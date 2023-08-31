#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charmed operator for the SD-Core's UDR service."""

import logging
from ipaddress import IPv4Address
from subprocess import check_output
from typing import Optional

from charms.data_platform_libs.v0.data_interfaces import DatabaseRequires  # type: ignore[import]
from charms.observability_libs.v1.kubernetes_service_patch import (  # type: ignore[import]  # noqa: E501
    KubernetesServicePatch,
)
from charms.sdcore_nrf.v0.fiveg_nrf import NRFRequires  # type: ignore[import]
from charms.tls_certificates_interface.v2.tls_certificates import (  # type: ignore[import]
    CertificateAvailableEvent,
    CertificateExpiringEvent,
    TLSCertificatesRequiresV2,
    generate_csr,
    generate_private_key,
)
from jinja2 import Environment, FileSystemLoader
from lightkube.models.core_v1 import ServicePort
from ops.charm import CharmBase, EventBase
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus, WaitingStatus
from ops.pebble import Layer, PathError

logger = logging.getLogger(__name__)

BASE_CONFIG_PATH = "/free5gc/config"
DEFAULT_DATABASE_NAME = "free5gc"
UDR_CONFIG_FILE_NAME = "udrcfg.yaml"
UDR_SBI_PORT = 29504
CERTS_DIR_PATH = "/support/TLS"  # Certificate paths are hardcoded in UDR code
PRIVATE_KEY_NAME = "udr.key"
CSR_NAME = "udr.csr"
CERTIFICATE_NAME = "udr.pem"
CERTIFICATE_COMMON_NAME = "udr.sdcore"


class UDROperatorCharm(CharmBase):
    """Charm the service."""

    def __init__(self, *args):
        super().__init__(*args)
        self._container_name = self._service_name = "udr"
        self._container = self.unit.get_container(self._container_name)
        self._nrf = NRFRequires(charm=self, relation_name="fiveg_nrf")
        self._database = DatabaseRequires(
            self, relation_name="database", database_name=DEFAULT_DATABASE_NAME
        )
        self._service_patcher = KubernetesServicePatch(
            charm=self,
            ports=[ServicePort(name="sbi", port=UDR_SBI_PORT)],
        )
        self._certificates = TLSCertificatesRequiresV2(self, "certificates")

        self.framework.observe(self.on.udr_pebble_ready, self._configure_udr)
        self.framework.observe(self.on.database_relation_joined, self._configure_udr)
        self.framework.observe(self._database.on.database_created, self._configure_udr)
        self.framework.observe(self.on.fiveg_nrf_relation_joined, self._configure_udr)
        self.framework.observe(self._nrf.on.nrf_available, self._configure_udr)
        self.framework.observe(self._nrf.on.nrf_broken, self._on_nrf_broken)
        self.framework.observe(
            self.on.certificates_relation_created, self._on_certificates_relation_created
        )
        self.framework.observe(
            self.on.certificates_relation_joined, self._on_certificates_relation_joined
        )
        self.framework.observe(
            self.on.certificates_relation_broken, self._on_certificates_relation_broken
        )
        self.framework.observe(
            self._certificates.on.certificate_available, self._on_certificate_available
        )
        self.framework.observe(
            self._certificates.on.certificate_expiring, self._on_certificate_expiring
        )

    def _configure_udr(self, event: EventBase) -> None:
        """Main callback function of the UDR operator.

        Handles config changes.
        Manages pebble layer and Juju unit status.

        Args:
            event: Juju event
        """
        for relation in ["database", "fiveg_nrf"]:
            if not self._relation_created(relation):
                self.unit.status = BlockedStatus(
                    f"Waiting for the `{relation}` relation to be created"
                )
                return
        if not self._database_is_available():
            self.unit.status = WaitingStatus("Waiting for the database to be available")
            return
        if not self._get_database_data():
            self.unit.status = WaitingStatus("Waiting for the database data to be available")
            event.defer()
            return
        if not self._nrf_is_available():
            self.unit.status = WaitingStatus("Waiting for the NRF to be available")
            return
        if not self._container.can_connect():
            self.unit.status = WaitingStatus("Waiting for the container to be ready")
            return
        if not self._storage_is_attached():
            self.unit.status = WaitingStatus("Waiting for the storage to be attached")
            event.defer()
            return
        if not _get_pod_ip():
            self.unit.status = WaitingStatus("Waiting for pod IP address to be available")
            event.defer()
            return
        self._generate_udr_config_file()
        self._configure_udr_service()
        self.unit.status = ActiveStatus()

    def _on_nrf_broken(self, event: EventBase) -> None:
        """Event handler for NRF relation broken.

        Args:
            event (NRFBrokenEvent): Juju event
        """
        self.unit.status = BlockedStatus("Waiting for fiveg_nrf relation")

    def _on_certificates_relation_created(self, event: EventBase) -> None:
        """Generates Private key."""
        if not self._container.can_connect():
            event.defer()
            return
        self._generate_private_key()

    def _on_certificates_relation_broken(self, event: EventBase) -> None:
        """Deletes TLS related artifacts and reconfigures workload."""
        if not self._container.can_connect():
            event.defer()
            return
        self._delete_private_key()
        self._delete_csr()
        self._delete_certificate()
        self._configure_udr(event)

    def _on_certificates_relation_joined(self, event: EventBase) -> None:
        """Generates CSR and requests new certificate."""
        if not self._container.can_connect():
            event.defer()
            return
        if not self._private_key_is_stored():
            event.defer()
            return
        self._request_new_certificate()

    def _on_certificate_available(self, event: CertificateAvailableEvent) -> None:
        """Pushes certificate to workload and configures workload."""
        if not self._container.can_connect():
            event.defer()
            return
        if not self._csr_is_stored():
            logger.warning("Certificate is available but no CSR is stored")
            return
        if event.certificate_signing_request != self._get_stored_csr():
            logger.debug("Stored CSR doesn't match one in certificate available event")
            return
        self._store_certificate(event.certificate)
        self._configure_udr(event)

    def _on_certificate_expiring(self, event: CertificateExpiringEvent):
        """Requests new certificate."""
        if not self._container.can_connect():
            event.defer()
            return
        if event.certificate != self._get_stored_certificate():
            logger.debug("Expiring certificate is not the one stored")
            return
        self._request_new_certificate()

    def _generate_private_key(self) -> None:
        """Generates and stores private key."""
        private_key = generate_private_key()
        self._store_private_key(private_key)

    def _request_new_certificate(self) -> None:
        """Generates and stores CSR, and uses it to request a new certificate."""
        private_key = self._get_stored_private_key()
        csr = generate_csr(
            private_key=private_key,
            subject=CERTIFICATE_COMMON_NAME,
            sans_dns=[CERTIFICATE_COMMON_NAME],
        )
        self._store_csr(csr)
        self._certificates.request_certificate_creation(certificate_signing_request=csr)

    def _delete_private_key(self):
        """Removes private key from workload."""
        if not self._private_key_is_stored():
            return
        self._container.remove_path(path=f"{CERTS_DIR_PATH}/{PRIVATE_KEY_NAME}")
        logger.info("Removed private key from workload")

    def _delete_csr(self):
        """Deletes CSR from workload."""
        if not self._csr_is_stored():
            return
        self._container.remove_path(path=f"{CERTS_DIR_PATH}/{CSR_NAME}")
        logger.info("Removed CSR from workload")

    def _delete_certificate(self):
        """Deletes certificate from workload."""
        if not self._certificate_is_stored():
            return
        self._container.remove_path(path=f"{CERTS_DIR_PATH}/{CERTIFICATE_NAME}")
        logger.info("Removed certificate from workload")

    def _private_key_is_stored(self) -> bool:
        """Returns whether private key is stored in workload."""
        return self._container.exists(path=f"{CERTS_DIR_PATH}/{PRIVATE_KEY_NAME}")

    def _csr_is_stored(self) -> bool:
        """Returns whether CSR is stored in workload."""
        return self._container.exists(path=f"{CERTS_DIR_PATH}/{CSR_NAME}")

    def _get_stored_certificate(self) -> str:
        """Returns stored certificate."""
        return str(self._container.pull(path=f"{CERTS_DIR_PATH}/{CERTIFICATE_NAME}").read())

    def _get_stored_csr(self) -> str:
        """Returns stored CSR."""
        return str(self._container.pull(path=f"{CERTS_DIR_PATH}/{CSR_NAME}").read())

    def _get_stored_private_key(self) -> bytes:
        """Returns stored private key."""
        return str(
            self._container.pull(path=f"{CERTS_DIR_PATH}/{PRIVATE_KEY_NAME}").read()
        ).encode()

    def _certificate_is_stored(self) -> bool:
        """Returns whether certificate is stored in workload."""
        return self._container.exists(path=f"{CERTS_DIR_PATH}/{CERTIFICATE_NAME}")

    def _store_certificate(self, certificate: str) -> None:
        """Stores certificate in workload."""
        self._container.push(path=f"{CERTS_DIR_PATH}/{CERTIFICATE_NAME}", source=certificate)
        logger.info("Pushed certificate pushed to workload")

    def _store_private_key(self, private_key: bytes) -> None:
        """Stores private key in workload."""
        self._container.push(
            path=f"{CERTS_DIR_PATH}/{PRIVATE_KEY_NAME}",
            source=private_key.decode(),
        )
        logger.info("Pushed private key to workload")

    def _store_csr(self, csr: bytes) -> None:
        """Stores CSR in workload."""
        self._container.push(path=f"{CERTS_DIR_PATH}/{CSR_NAME}", source=csr.decode().strip())
        logger.info("Pushed CSR to workload")

    def _generate_udr_config_file(self) -> None:
        """Handles creation of the UDR config file.

        Generates UDR config file based on a given template.
        Pushes UDR config file to the workload.
        Calls `_configure_udr_service` function to forcibly restart the UDR service in order
        to fetch new config.
        """
        content = self._render_config_file(
            udr_ip_address=_get_pod_ip(),  # type: ignore[arg-type]
            udr_sbi_port=UDR_SBI_PORT,
            default_database_name=DEFAULT_DATABASE_NAME,
            default_database_url=self._get_database_data()["uris"].split(",")[0],
            nrf_url=self._nrf.nrf_url,
            scheme="https" if self._certificate_is_stored() else "http",
        )
        if not self._config_file_content_matches(content=content):
            self._push_udr_config_file_to_workload(content=content)
            self._configure_udr_service(force_restart=True)

    def _configure_udr_service(self, force_restart: bool = False) -> None:
        """Manages UDR's pebble layer and service.

        Updates the pebble layer if the proposed config is different from the current one. If layer
        has been updated also restart the workload service.

        Args:
            force_restart (bool): Allows for forcibly restarting the service even if Pebble plan
                didn't change.
        """
        pebble_layer = self._pebble_layer
        plan = self._container.get_plan()
        if plan.services != pebble_layer.services or force_restart:
            self._container.add_layer(self._container_name, pebble_layer, combine=True)
            self._container.restart(self._service_name)
            logger.info(f"Restarted container {self._service_name}")

    @staticmethod
    def _render_config_file(
        *,
        udr_ip_address: str,
        udr_sbi_port: int,
        default_database_name: str,
        default_database_url: str,
        nrf_url: str,
        scheme: str,
    ) -> str:
        """Renders the config file content.

        Args:
            udr_ip_address (str): UDR IP address.
            udr_sbi_port (str): UDR SBI port.
            default_database_name (str): Database name.
            default_database_url (str): Database URL.
            nrf_url (str): NRF URL.
            scheme (str): SBI interface scheme ("http" or "https")

        Returns:
            str: Config file content.
        """
        jinja2_env = Environment(loader=FileSystemLoader("src/templates"))
        template = jinja2_env.get_template("udrcfg.yaml.j2")
        return template.render(
            udr_ip_address=udr_ip_address,
            udr_sbi_port=udr_sbi_port,
            default_database_name=default_database_name,
            default_database_url=default_database_url,
            nrf_url=nrf_url,
            scheme=scheme,
        )

    def _config_file_content_matches(self, content: str) -> bool:
        """Returns whether the config file content matches the provided content.

        Returns:
            bool: Whether the config file content matches
        """
        udr_config_file = f"{BASE_CONFIG_PATH}/{UDR_CONFIG_FILE_NAME}"
        try:
            existing_content = self._container.pull(path=udr_config_file)
            return existing_content.read() == content
        except PathError:
            return False

    def _push_udr_config_file_to_workload(self, content: str) -> None:
        """Pushes UDR's config file to the workload container.

        Args:
            content (str): Config file's content.
        """
        self._container.push(
            path=f"{BASE_CONFIG_PATH}/{UDR_CONFIG_FILE_NAME}", source=content, make_dirs=True
        )
        logger.info(f"Config file {UDR_CONFIG_FILE_NAME} pushed to workload.")

    def _get_database_data(self) -> dict:
        """Returns the database data.

        Returns:
            dict: The database data.
        """
        if not self._database_is_available():
            raise RuntimeError(f"Database `{DEFAULT_DATABASE_NAME}` is not available")
        return self._database.fetch_relation_data()[self._database.relations[0].id]

    def _nrf_is_available(self) -> bool:
        """Returns whether the NRF endpoint is available.

        Returns:
            bool: whether the NRF endpoint is available.
        """
        return bool(self._nrf.nrf_url)

    def _database_is_available(self) -> bool:
        """Returns whether database relation is available.

        Returns:
            bool: Whether database relation is available.
        """
        return bool(self._database.is_resource_created())

    @property
    def _pebble_layer(self) -> Layer:
        """Return a Pebble Layer .

        Returns:
            Layer: Pebble layer
        """
        return Layer(
            {
                "summary": "UDR pebble layer",
                "description": "UDR pebble layer",
                "services": {
                    self._service_name: {
                        "override": "replace",
                        "startup": "enabled",
                        "command": "/bin/udr "
                        f"-udrcfg {BASE_CONFIG_PATH}/{UDR_CONFIG_FILE_NAME}",
                        "environment": self._environment_variables,
                    }
                },
            }
        )

    @property
    def _environment_variables(self) -> dict:
        """Returns workload container environment variables.

        Returns:
            dict: environment variables
        """
        return {
            "GRPC_GO_LOG_VERBOSITY_LEVEL": "99",
            "GRPC_GO_LOG_SEVERITY_LEVEL": "info",
            "GRPC_TRACE": "all",
            "GRPC_VERBOSITY": "debug",
            "MANAGED_BY_CONFIG_POD": "true",
            "POD_IP": _get_pod_ip(),
        }

    def _relation_created(self, relation_name: str) -> bool:
        """Returns whether a given Juju relation was crated.

        Args:
            relation_name (str): Relation name

        Returns:
            bool: Whether the relation was created.
        """
        return bool(self.model.get_relation(relation_name))

    def _storage_is_attached(self) -> bool:
        """Returns whether storage is attached to the workload container.

        Returns:
            bool: Whether storage is attached.
        """
        return self._container.exists(path=BASE_CONFIG_PATH)


def _get_pod_ip() -> Optional[str]:
    """Returns the pod IP using juju client.

    Returns:
        str: The pod IP.
    """
    ip_address = check_output(["unit-get", "private-address"])
    return str(IPv4Address(ip_address.decode().strip())) if ip_address else None


if __name__ == "__main__":  # pragma: no cover
    main(UDROperatorCharm)

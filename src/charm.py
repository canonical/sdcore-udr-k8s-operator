#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charmed operator for the SD-Core's UDR service for K8s."""

import logging
from ipaddress import IPv4Address
from subprocess import CalledProcessError, check_output
from typing import Optional

from charms.data_platform_libs.v0.data_interfaces import DatabaseRequires  # type: ignore[import]
from charms.sdcore_nrf_k8s.v0.fiveg_nrf import NRFRequires  # type: ignore[import]
from charms.tls_certificates_interface.v3.tls_certificates import (  # type: ignore[import]
    CertificateExpiringEvent,
    TLSCertificatesRequiresV3,
    generate_csr,
    generate_private_key,
)
from jinja2 import Environment, FileSystemLoader
from ops import ActiveStatus, BlockedStatus, RelationBrokenEvent, WaitingStatus
from ops.charm import CharmBase, EventBase
from ops.main import main
from ops.pebble import Layer, PathError

logger = logging.getLogger(__name__)

BASE_CONFIG_PATH = "/free5gc/config"
COMMON_DATABASE_NAME = "free5gc"
AUTH_DATABASE_NAME = "authentication"
COMMON_DATABASE_RELATION_NAME = "common_database"
AUTH_DATABASE_RELATION_NAME = "auth_database"
NRF_RELATION_NAME = "fiveg_nrf"
TLS_RELATION_NAME = "certificates"
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
        self._nrf = NRFRequires(charm=self, relation_name=NRF_RELATION_NAME)
        self._common_database = DatabaseRequires(
            self, relation_name=COMMON_DATABASE_RELATION_NAME, database_name=COMMON_DATABASE_NAME
        )
        self._auth_database = DatabaseRequires(
            self, relation_name=AUTH_DATABASE_RELATION_NAME, database_name=AUTH_DATABASE_NAME
        )
        self.unit.set_ports(UDR_SBI_PORT)
        self._certificates = TLSCertificatesRequiresV3(self, TLS_RELATION_NAME)
        self.framework.observe(self.on.update_status, self._configure_udr)
        self.framework.observe(self.on.udr_pebble_ready, self._configure_udr)
        self.framework.observe(self.on.common_database_relation_joined, self._configure_udr)
        self.framework.observe(self.on.auth_database_relation_joined, self._configure_udr)
        self.framework.observe(
            self.on.common_database_relation_broken, self._on_common_database_relation_broken
        )
        self.framework.observe(
            self.on.auth_database_relation_broken, self._on_auth_database_relation_broken
        )
        self.framework.observe(self._common_database.on.database_created, self._configure_udr)
        self.framework.observe(self._auth_database.on.database_created, self._configure_udr)
        self.framework.observe(self.on.fiveg_nrf_relation_joined, self._configure_udr)
        self.framework.observe(self._nrf.on.nrf_available, self._configure_udr)
        self.framework.observe(self._nrf.on.nrf_broken, self._on_nrf_broken)
        self.framework.observe(self.on.certificates_relation_joined, self._configure_udr)
        self.framework.observe(
            self.on.certificates_relation_broken, self._on_certificates_relation_broken
        )
        self.framework.observe(self._certificates.on.certificate_available, self._configure_udr)
        self.framework.observe(
            self._certificates.on.certificate_expiring, self._on_certificate_expiring
        )

    def ready_to_configure(self) -> bool:
        """Returns whether the preconditions are met to proceed with configuration."""
        for relation in [
            COMMON_DATABASE_RELATION_NAME,
            AUTH_DATABASE_RELATION_NAME,
            NRF_RELATION_NAME,
            TLS_RELATION_NAME,
        ]:
            if not self._relation_created(relation):
                self.unit.status = BlockedStatus(
                    f"Waiting for the {relation} relation to be created"
                )
                return False
        if not self._common_database_is_available():
            self.unit.status = WaitingStatus("Waiting for the common database to be available")
            return False
        if not self._auth_database_is_available():
            self.unit.status = WaitingStatus(
                "Waiting for the authentication database to be available"
            )
            return False
        if not self._get_common_database_url():
            self.unit.status = WaitingStatus("Waiting for the common database url to be available")
            return False
        if not self._get_auth_database_url():
            self.unit.status = WaitingStatus("Waiting for the auth database url to be available")
            return False
        if not self._nrf_is_available():
            self.unit.status = WaitingStatus("Waiting for the NRF to be available")
            return False
        return True

    def _configure_udr(self, event: EventBase) -> None:
        """Main callback function of the UDR operator.

        Handles config changes.
        Manages pebble layer and Juju unit status.

        Args:
            event: Juju event
        """
        if not self.ready_to_configure():
            return
        if not self._container.can_connect():
            self.unit.status = WaitingStatus("Waiting for the container to be ready")
            return
        if not self._storage_is_attached():
            self.unit.status = WaitingStatus("Waiting for the storage to be attached")
            return
        if not _get_pod_ip():
            self.unit.status = WaitingStatus("Waiting for pod IP address to be available")
            return

        if not self._private_key_is_stored():
            self._generate_private_key()

        if not self._csr_is_stored():
            self._request_new_certificate()

        provider_certificate = self._get_current_provider_certificate()
        if not provider_certificate:
            self.unit.status = WaitingStatus("Waiting for certificates to be stored")
            return

        if certificate_update_required := self._is_certificate_update_required(
            provider_certificate
        ):
            self._store_certificate(certificate=provider_certificate)

        desired_config_file = self._generate_udr_config_file()
        if config_update_required := self._is_config_update_required(desired_config_file):
            self._push_udr_config_file_to_workload(content=desired_config_file)

        should_restart = config_update_required or certificate_update_required
        self._configure_pebble(restart=should_restart)
        self.unit.status = ActiveStatus()

    def _on_nrf_broken(self, event: RelationBrokenEvent) -> None:
        """Event handler for NRF relation broken.

        Args:
            event (NRFBrokenEvent): Juju event
        """
        self.unit.status = BlockedStatus("Waiting for fiveg_nrf relation")

    def _on_common_database_relation_broken(self, event: RelationBrokenEvent) -> None:
        """Event handler for common database relation broken.

        Args:
            event: Juju event
        """
        if not self.model.relations[COMMON_DATABASE_RELATION_NAME]:
            self.unit.status = BlockedStatus(
                f"Waiting for {COMMON_DATABASE_RELATION_NAME} relation"
            )

    def _on_auth_database_relation_broken(self, event: RelationBrokenEvent) -> None:
        """Event handler for auth database relation broken.

        Args:
            event: Juju event
        """
        if not self.model.relations[AUTH_DATABASE_RELATION_NAME]:
            self.unit.status = BlockedStatus(f"Waiting for {AUTH_DATABASE_RELATION_NAME} relation")

    def _on_certificates_relation_broken(self, event: RelationBrokenEvent) -> None:
        """Deletes TLS related artifacts and reconfigures workload."""
        if not self._container.can_connect():
            event.defer()
            return
        self._delete_private_key()
        self._delete_csr()
        self._delete_certificate()
        self.unit.status = BlockedStatus("Waiting for certificates relation")

    def _get_current_provider_certificate(self) -> str | None:
        """Compares the current certificate request to what is in the interface.

        Returns the current valid provider certificate if present
        """
        csr = self._get_stored_csr()
        for provider_certificate in self._certificates.get_assigned_certificates():
            if provider_certificate.csr == csr:
                return provider_certificate.certificate
        return None

    def _get_existing_certificate(self) -> str:
        """Returns the existing certificate if present else empty string."""
        return self._get_stored_certificate() if self._certificate_is_stored() else ""

    def _is_certificate_update_required(self, provider_certificate) -> bool:
        """Checks the provided certificate and existing certificate.

        Returns True if update is required.

        Args:
            provider_certificate: str
        Returns:
            True if update is required else False
        """
        return self._get_existing_certificate() != provider_certificate

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

    def _generate_udr_config_file(self) -> str:
        """Handles creation of the UDR config file based on a given template.

        Returns:
            content (str): desired config file content
        """
        return self._render_config_file(
            udr_ip_address=_get_pod_ip(),  # type: ignore[arg-type]
            udr_sbi_port=UDR_SBI_PORT,
            common_database_name=COMMON_DATABASE_NAME,
            common_database_url=self._get_common_database_url(),
            auth_database_name=AUTH_DATABASE_NAME,
            auth_database_url=self._get_auth_database_url(),
            nrf_url=self._nrf.nrf_url,
            scheme="https",
        )

    def _is_config_update_required(self, content: str) -> bool:
        """Decides whether config update is required by checking existence and config content.

        Args:
            content (str): desired config file content

        Returns:
            True if config update is required else False
        """
        if not self._config_file_is_written() or not self._config_file_content_matches(
            content=content
        ):
            return True
        return False

    def _configure_pebble(self, restart: bool = False) -> None:
        """Configure the Pebble layer.

        Args:
            restart (bool): Whether to restart the Pebble service. Defaults to False.
        """
        self._container.add_layer(self._container_name, self._pebble_layer, combine=True)
        if restart:
            self._container.restart(self._service_name)
            logger.info("Restarted container %s", self._service_name)
            return
        self._container.replan()

    @staticmethod
    def _render_config_file(
        *,
        udr_ip_address: str,
        udr_sbi_port: int,
        common_database_name: str,
        auth_database_name: str,
        common_database_url: str,
        auth_database_url: str,
        nrf_url: str,
        scheme: str,
    ) -> str:
        """Renders the config file content.

        Args:
            udr_ip_address (str): UDR IP address.
            udr_sbi_port (str): UDR SBI port.
            common_database_name (str): Commmon Database name.
            auth_database_name (str): Database name to store authentication keys.
            common_database_url (str): Common Database URL.
            auth_database_url (str): Authentication Database URL.
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
            common_database_name=common_database_name,
            common_database_url=common_database_url,
            auth_database_name=auth_database_name,
            auth_database_url=auth_database_url,
            nrf_url=nrf_url,
            scheme=scheme,
        )

    def _config_file_is_written(self) -> bool:
        """Returns whether the config file was written to the workload container.

        Returns:
            bool: Whether the config file was written.
        """
        return bool(self._container.exists(f"{BASE_CONFIG_PATH}/{UDR_CONFIG_FILE_NAME}"))

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

    def _get_common_database_url(self) -> str:
        """Returns the common database URL.

        Returns:
            str: The common database URL.
        """
        if not self._common_database_is_available():
            raise RuntimeError(f"Database `{COMMON_DATABASE_NAME}` is not available")
        uris = self._common_database.fetch_relation_data()[
            self._common_database.relations[0].id
        ].get("uris")
        if uris:
            return uris.split(",")[0]
        return ""

    def _get_auth_database_url(self) -> str:
        """Returns the authentication database URL.

        Returns:
            str: The authentication database URL.
        """
        if not self._auth_database_is_available():
            raise RuntimeError(f"Database `{AUTH_DATABASE_NAME}` is not available")
        uris = self._auth_database.fetch_relation_data()[self._auth_database.relations[0].id].get(
            "uris"
        )
        if uris:
            return uris.split(",")[0]
        return ""

    def _nrf_is_available(self) -> bool:
        """Returns whether the NRF endpoint is available.

        Returns:
            bool: whether the NRF endpoint is available.
        """
        return bool(self._nrf.nrf_url)

    def _common_database_is_available(self) -> bool:
        """Returns whether common database relation is available.

        Returns:
            bool: Whether common database relation is available.
        """
        return bool(self._common_database.is_resource_created())

    def _auth_database_is_available(self) -> bool:
        """Returns whether authentication database relation is available.

        Returns:
            bool: Whether authentication database relation is available.
        """
        return bool(self._auth_database.is_resource_created())

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
        return self._container.exists(path=BASE_CONFIG_PATH) and self._container.exists(
            path=CERTS_DIR_PATH
        )


def _get_pod_ip() -> Optional[str]:
    """Returns the pod IP using juju client.

    Returns:
        str: The pod IP.
    """
    try:
        ip_address = check_output(["unit-get", "private-address"])
        return str(IPv4Address(ip_address.decode().strip())) if ip_address else None
    except (CalledProcessError, ValueError):
        return None


if __name__ == "__main__":  # pragma: no cover
    main(UDROperatorCharm)

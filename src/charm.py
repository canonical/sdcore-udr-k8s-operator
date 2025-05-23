#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charmed operator for the SD-Core's UDR service for K8s."""

import logging
from ipaddress import IPv4Address
from subprocess import CalledProcessError, check_output
from typing import List, Optional, cast

from charms.data_platform_libs.v0.data_interfaces import DatabaseRequires
from charms.loki_k8s.v1.loki_push_api import LogForwarder
from charms.prometheus_k8s.v0.prometheus_scrape import (
    MetricsEndpointProvider,
)
from charms.sdcore_nms_k8s.v0.sdcore_config import (
    SdcoreConfigRequires,
)
from charms.sdcore_nrf_k8s.v0.fiveg_nrf import NRFRequires
from charms.tls_certificates_interface.v4.tls_certificates import (
    Certificate,
    CertificateRequestAttributes,
    PrivateKey,
    TLSCertificatesRequiresV4,
)
from jinja2 import Environment, FileSystemLoader
from ops import (
    ActiveStatus,
    BlockedStatus,
    CollectStatusEvent,
    ModelError,
    RelationBrokenEvent,
    WaitingStatus,
    main,
)
from ops.charm import CharmBase
from ops.framework import EventBase
from ops.pebble import Layer, PathError

logger = logging.getLogger(__name__)

PROMETHEUS_PORT = 8080
BASE_CONFIG_PATH = "/free5gc/config"
COMMON_DATABASE_NAME = "free5gc"
AUTH_DATABASE_NAME = "authentication"
COMMON_DATABASE_RELATION_NAME = "common_database"
AUTH_DATABASE_RELATION_NAME = "auth_database"
NRF_RELATION_NAME = "fiveg_nrf"
TLS_RELATION_NAME = "certificates"
UDR_CONFIG_FILE_NAME = "udrcfg.yaml"
UDR_SBI_PORT = 29504
CERTS_DIR_PATH = "/support/TLS"
PRIVATE_KEY_NAME = "udr.key"
CERTIFICATE_NAME = "udr.pem"
CERTIFICATE_COMMON_NAME = "udr.sdcore"
LOGGING_RELATION_NAME = "logging"
SDCORE_CONFIG_RELATION_NAME = "sdcore_config"
WORKLOAD_VERSION_FILE_NAME = "/etc/workload-version"


class UDROperatorCharm(CharmBase):
    """Charm the service."""

    def __init__(self, *args):
        super().__init__(*args)
        self.framework.observe(self.on.collect_unit_status, self._on_collect_unit_status)
        if not self.unit.is_leader():
            # NOTE: In cases where leader status is lost before the charm is
            # finished processing all teardown events, this prevents teardown
            # event code from running. Luckily, for this charm, none of the
            # teardown code is necessary to perform if we're removing the
            # charm.
            return
        self._container_name = self._service_name = "udr"
        self._container = self.unit.get_container(self._container_name)
        self._nrf = NRFRequires(charm=self, relation_name=NRF_RELATION_NAME)
        self._common_database = DatabaseRequires(
            self, relation_name=COMMON_DATABASE_RELATION_NAME, database_name=COMMON_DATABASE_NAME
        )
        self._auth_database = DatabaseRequires(
            self, relation_name=AUTH_DATABASE_RELATION_NAME, database_name=AUTH_DATABASE_NAME
        )
        self._webui_requires = SdcoreConfigRequires(
            charm=self, relation_name=SDCORE_CONFIG_RELATION_NAME
        )
        self._udr_metrics_endpoint = MetricsEndpointProvider(
            self,
            refresh_event=[self.on.update_status],
            jobs=[
                {
                    "static_configs": [{"targets": [f"*:{PROMETHEUS_PORT}"]}],
                }
            ],
        )
        self.unit.set_ports(PROMETHEUS_PORT, UDR_SBI_PORT)
        self._certificates = TLSCertificatesRequiresV4(
            charm=self,
            relationship_name=TLS_RELATION_NAME,
            certificate_requests=[self._get_certificate_request()],
        )
        self._logging = LogForwarder(charm=self, relation_name=LOGGING_RELATION_NAME)
        self.framework.observe(self.on.update_status, self._configure_udr)
        self.framework.observe(self.on.udr_pebble_ready, self._configure_udr)
        self.framework.observe(self.on.common_database_relation_joined, self._configure_udr)
        self.framework.observe(self.on.auth_database_relation_joined, self._configure_udr)
        self.framework.observe(self._common_database.on.database_created, self._configure_udr)
        self.framework.observe(self._auth_database.on.database_created, self._configure_udr)
        self.framework.observe(self.on.fiveg_nrf_relation_joined, self._configure_udr)
        self.framework.observe(self._nrf.on.nrf_available, self._configure_udr)
        self.framework.observe(self.on.certificates_relation_joined, self._configure_udr)
        self.framework.observe(
            self.on.certificates_relation_broken, self._on_certificates_relation_broken
        )
        self.framework.observe(self._certificates.on.certificate_available, self._configure_udr)
        self.framework.observe(self._webui_requires.on.webui_url_available, self._configure_udr)
        self.framework.observe(self.on.sdcore_config_relation_joined, self._configure_udr)

    def _configure_udr(self, event: EventBase) -> None:
        """Handle Juju events.

        This event handler is called for every event that affects the charm state
        (ex. configuration files, relation data). This method performs a couple of checks
        to make sure that the workload is ready to be started. Then, it configures the UDR
        workload and runs the Pebble services.

        Args:
            event (EventBase): Juju event
        """
        if not self.ready_to_configure():
            logger.info("The preconditions for the configuration are not met yet.")
            return

        if not self._container.can_connect():
            return

        if not self._storage_is_attached():
            return

        if not _get_pod_ip():
            return

        if not self._certificate_is_available():
            logger.info("The certificate is not available yet.")
            return

        certificate_update_required = self._check_and_update_certificate()

        desired_config_file = self._generate_udr_config_file()
        if config_update_required := self._is_config_update_required(desired_config_file):
            self._push_udr_config_file_to_workload(content=desired_config_file)

        should_restart = config_update_required or certificate_update_required
        self._configure_pebble(restart=should_restart)

    def _on_collect_unit_status(self, event: CollectStatusEvent):  # noqa C901
        """Check the unit status and set to Unit when CollectStatusEvent is fired.

        Args:
            event: CollectStatusEvent
        """
        if not self.unit.is_leader():
            # NOTE: In cases where leader status is lost before the charm is
            # finished processing all teardown events, this prevents teardown
            # event code from running. Luckily, for this charm, none of the
            # teardown code is necessary to perform if we're removing the
            # charm.
            event.add_status(BlockedStatus("Scaling is not implemented for this charm"))
            logger.info("Scaling is not implemented for this charm")
            return

        if invalid_configs := self._get_invalid_configs():
            event.add_status(
                BlockedStatus(f"The following configurations are not valid: {invalid_configs}")
            )
            logger.info("The following configurations are not valid: %s", invalid_configs)
            return

        if missing_relations := self._missing_relations():
            event.add_status(
                BlockedStatus(f"Waiting for {', '.join(missing_relations)} relation(s)")
            )
            logger.info("Waiting for %s  relation(s)", ", ".join(missing_relations))
            return

        if not self._common_database_is_available():
            event.add_status(WaitingStatus("Waiting for the common database to be available"))
            logger.info("Waiting for the common database to be available")
            return

        if not self._auth_database_is_available():
            event.add_status(
                WaitingStatus("Waiting for the authentication database to be available")
            )
            logger.info("Waiting for the authentication database to be available")
            return

        if not self._get_common_database_url():
            event.add_status(WaitingStatus("Waiting for the common database url to be available"))
            logger.info("Waiting for the common database url to be available")
            return

        if not self._get_auth_database_url():
            event.add_status(WaitingStatus("Waiting for the auth database url to be available"))
            logger.info("Waiting for the auth database url to be available")
            return

        if not self._nrf_is_available():
            event.add_status(WaitingStatus("Waiting for the NRF to be available"))
            logger.info("Waiting for the NRF to be available")
            return

        if not self._webui_url_is_available:
            event.add_status(WaitingStatus("Waiting for Webui URL to be available"))
            logger.info("Waiting for Webui URL to be available")
            return

        if not self._container.can_connect():
            event.add_status(WaitingStatus("Waiting for the container to be ready"))
            logger.info("Waiting for the container to be ready")
            return

        self.unit.set_workload_version(self._get_workload_version())

        if not self._storage_is_attached():
            event.add_status(WaitingStatus("Waiting for the storage to be attached"))
            logger.info("Waiting for the storage to be attached")
            return

        if not _get_pod_ip():
            event.add_status(WaitingStatus("Waiting for pod IP address to be available"))
            logger.info("Waiting for pod IP address to be available")
            return

        if not self._certificate_is_available():
            event.add_status(WaitingStatus("Waiting for certificates to be available"))
            logger.info("Waiting for certificates to be available")

        if not self._udr_service_is_running():
            event.add_status(WaitingStatus("Waiting for UDR service to start"))
            logger.info("Waiting for UDR service to start")
            return

        event.add_status(ActiveStatus())

    def ready_to_configure(self) -> bool:
        """Return whether the preconditions are met to proceed with the configuration.

        Returns:
            ready_to_configure: True if all conditions are met else False
        """
        if not self._container.can_connect():
            return False

        if self._get_invalid_configs():
            return False

        if self._missing_relations():
            return False

        if not self._common_database_is_available():
            return False

        if not self._auth_database_is_available():
            return False

        if not self._get_common_database_url():
            return False

        if not self._get_auth_database_url():
            return False

        if not self._nrf_is_available():
            return False

        if not self._webui_url_is_available:
            return False

        return True

    def _certificate_is_available(self) -> bool:
        cert, key = self._certificates.get_assigned_certificate(
            certificate_request=self._get_certificate_request()
        )
        return bool(cert and key)

    def _check_and_update_certificate(self) -> bool:
        """Check if the certificate or private key needs an update and perform the update.

        This method retrieves the currently assigned certificate and private key associated with
        the charm's TLS relation. It checks whether the certificate or private key has changed
        or needs to be updated. If an update is necessary, the new certificate or private key is
        stored.

        Returns:
            bool: True if either the certificate or the private key was updated, False otherwise.
        """
        provider_certificate, private_key = self._certificates.get_assigned_certificate(
            certificate_request=self._get_certificate_request()
        )
        if not provider_certificate or not private_key:
            logger.debug("Certificate or private key is not available")
            return False
        if certificate_update_required := self._is_certificate_update_required(
            provider_certificate.certificate
        ):
            self._store_certificate(certificate=provider_certificate.certificate)
        if private_key_update_required := self._is_private_key_update_required(private_key):
            self._store_private_key(private_key=private_key)
        return certificate_update_required or private_key_update_required

    @staticmethod
    def _get_certificate_request() -> CertificateRequestAttributes:
        return CertificateRequestAttributes(
            common_name=CERTIFICATE_COMMON_NAME,
            sans_dns=frozenset([CERTIFICATE_COMMON_NAME]),
        )

    def _missing_relations(self) -> List[str]:
        """Return list of missing relations.

        If all the relations are created, it returns an empty list.

        Returns:
            list: missing relation names.
        """
        missing_relations = []
        for relation in [
            COMMON_DATABASE_RELATION_NAME,
            AUTH_DATABASE_RELATION_NAME,
            NRF_RELATION_NAME,
            TLS_RELATION_NAME,
            SDCORE_CONFIG_RELATION_NAME,
        ]:
            if not self._relation_created(relation):
                missing_relations.append(relation)
        return missing_relations

    @property
    def _webui_url_is_available(self) -> bool:
        return bool(self._webui_requires.webui_url)

    def _udr_service_is_running(self) -> bool:
        """Check if the UDR service is running."""
        try:
            self._container.get_service(service_name=self._service_name)
        except ModelError:
            return False
        return True

    def _on_certificates_relation_broken(self, event: RelationBrokenEvent) -> None:
        """Delete TLS related artifacts and reconfigures workload."""
        if not self._container.can_connect():
            event.defer()
            return
        self._delete_private_key()
        self._delete_certificate()

    def _is_certificate_update_required(self, certificate: Certificate) -> bool:
        return self._get_existing_certificate() != certificate

    def _is_private_key_update_required(self, private_key: PrivateKey) -> bool:
        return self._get_existing_private_key() != private_key

    def _get_existing_certificate(self) -> Optional[Certificate]:
        return self._get_stored_certificate() if self._certificate_is_stored() else None

    def _get_existing_private_key(self) -> Optional[PrivateKey]:
        return self._get_stored_private_key() if self._private_key_is_stored() else None

    def _delete_private_key(self):
        """Remove private key from workload."""
        if not self._private_key_is_stored():
            return
        self._container.remove_path(path=f"{CERTS_DIR_PATH}/{PRIVATE_KEY_NAME}")
        logger.info("Removed private key from workload")

    def _delete_certificate(self):
        """Delete certificate from workload."""
        if not self._certificate_is_stored():
            return
        self._container.remove_path(path=f"{CERTS_DIR_PATH}/{CERTIFICATE_NAME}")
        logger.info("Removed certificate from workload")

    def _private_key_is_stored(self) -> bool:
        """Return whether private key is stored in workload."""
        return self._container.exists(path=f"{CERTS_DIR_PATH}/{PRIVATE_KEY_NAME}")

    def _get_stored_certificate(self) -> Certificate:
        cert_string = str(self._container.pull(path=f"{CERTS_DIR_PATH}/{CERTIFICATE_NAME}").read())
        return Certificate.from_string(cert_string)

    def _get_stored_private_key(self) -> PrivateKey:
        key_string = str(self._container.pull(path=f"{CERTS_DIR_PATH}/{PRIVATE_KEY_NAME}").read())
        return PrivateKey.from_string(key_string)

    def _certificate_is_stored(self) -> bool:
        """Return whether certificate is stored in workload."""
        return self._container.exists(path=f"{CERTS_DIR_PATH}/{CERTIFICATE_NAME}")

    def _store_certificate(self, certificate: Certificate) -> None:
        """Store certificate in workload."""
        self._container.push(path=f"{CERTS_DIR_PATH}/{CERTIFICATE_NAME}", source=str(certificate))
        logger.info("Pushed certificate to workload")

    def _store_private_key(self, private_key: PrivateKey) -> None:
        """Store private key in workload."""
        self._container.push(
            path=f"{CERTS_DIR_PATH}/{PRIVATE_KEY_NAME}",
            source=str(private_key),
        )
        logger.info("Pushed private key to workload")

    def _get_workload_version(self) -> str:
        """Return the workload version.

        Checks for the presence of /etc/workload-version file
        and if present, returns the contents of that file. If
        the file is not present, an empty string is returned.

        Returns:
            string: A human readable string representing the
            version of the workload
        """
        if self._container.exists(path=f"{WORKLOAD_VERSION_FILE_NAME}"):
            version_file_content = self._container.pull(
                path=f"{WORKLOAD_VERSION_FILE_NAME}"
            ).read()
            return version_file_content
        return ""

    def _get_invalid_configs(self) -> list[str]:
        """Return list of invalid configurations.

        Returns:
            list: List of strings matching config keys.
        """
        invalid_configs = []
        if not self._is_log_level_valid():
            invalid_configs.append("log-level")
        return invalid_configs

    def _get_log_level_config(self) -> Optional[str]:
        return cast(Optional[str], self.model.config.get("log-level"))

    def _is_log_level_valid(self) -> bool:
        log_level = self._get_log_level_config()
        return log_level in ["debug", "info", "warn", "error", "fatal", "panic"]

    def _generate_udr_config_file(self) -> str:
        """Handle creation of the UDR config file based on a given template.

        Returns:
            content (str): desired config file content
        """
        if not (pod_ip := _get_pod_ip()):
            return ""
        if not self._nrf.nrf_url:
            return ""
        if not self._webui_requires.webui_url:
            return ""
        if not (log_level := self._get_log_level_config()):
            return ""
        return self._render_config_file(
            udr_ip_address=pod_ip,
            udr_sbi_port=UDR_SBI_PORT,
            common_database_name=COMMON_DATABASE_NAME,
            common_database_url=self._get_common_database_url(),
            auth_database_name=AUTH_DATABASE_NAME,
            auth_database_url=self._get_auth_database_url(),
            nrf_url=self._nrf.nrf_url,
            scheme="https",
            webui_uri=self._webui_requires.webui_url,
            tls_pem=f"{CERTS_DIR_PATH}/{CERTIFICATE_NAME}",
            tls_key=f"{CERTS_DIR_PATH}/{PRIVATE_KEY_NAME}",
            log_level=log_level,
        )

    def _is_config_update_required(self, content: str) -> bool:
        """Decide whether config update is required by checking existence and config content.

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
        plan = self._container.get_plan()
        if plan.services != self._pebble_layer.services:
            self._container.add_layer(self._container_name, self._pebble_layer, combine=True)
            self._container.replan()
            logger.info("New layer added: %s", self._pebble_layer)
        if restart:
            self._container.restart(self._service_name)
            logger.info("Restarted container %s", self._service_name)
            return

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
        webui_uri: str,
        tls_pem: str,
        tls_key: str,
        log_level: str,
    ) -> str:
        """Render the config file content.

        Args:
            udr_ip_address (str): UDR IP address.
            udr_sbi_port (str): UDR SBI port.
            common_database_name (str): Common Database name.
            auth_database_name (str): Database name to store authentication keys.
            common_database_url (str): Common Database URL.
            auth_database_url (str): Authentication Database URL.
            nrf_url (str): NRF URL.
            scheme (str): SBI interface scheme ("http" or "https")
            webui_uri (str) : URL of the Webui
            tls_pem (str): TLS certificate file.
            tls_key (str): TLS key file.
            log_level (str): Log level for the AMF.

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
            webui_uri=webui_uri,
            tls_pem=tls_pem,
            tls_key=tls_key,
            log_level=log_level,
        )

    def _config_file_is_written(self) -> bool:
        """Return whether the config file was written to the workload container.

        Returns:
            bool: Whether the config file was written.
        """
        return bool(self._container.exists(f"{BASE_CONFIG_PATH}/{UDR_CONFIG_FILE_NAME}"))

    def _config_file_content_matches(self, content: str) -> bool:
        """Return whether the config file content matches the provided content.

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
        """Push UDR's config file to the workload container.

        Args:
            content (str): Config file's content.
        """
        self._container.push(
            path=f"{BASE_CONFIG_PATH}/{UDR_CONFIG_FILE_NAME}", source=content, make_dirs=True
        )
        logger.info(f"Config file {UDR_CONFIG_FILE_NAME} pushed to workload.")

    def _get_common_database_url(self) -> str:
        """Return the common database URL.

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
        """Return the authentication database URL.

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
        """Return whether the NRF endpoint is available.

        Returns:
            bool: whether the NRF endpoint is available.
        """
        return bool(self._nrf.nrf_url)

    def _common_database_is_available(self) -> bool:
        """Return whether common database relation is available.

        Returns:
            bool: Whether common database relation is available.
        """
        return bool(self._common_database.is_resource_created())

    def _auth_database_is_available(self) -> bool:
        """Return whether authentication database relation is available.

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
                        "command": "/bin/udr " f"-cfg {BASE_CONFIG_PATH}/{UDR_CONFIG_FILE_NAME}",
                        "environment": self._environment_variables,
                    }
                },
            }
        )

    @property
    def _environment_variables(self) -> dict:
        """Return workload container environment variables.

        Returns:
            dict: environment variables
        """
        return {
            "MANAGED_BY_CONFIG_POD": "true",
            "POD_IP": _get_pod_ip(),
        }

    def _relation_created(self, relation_name: str) -> bool:
        """Return whether a given Juju relation was created.

        Args:
            relation_name (str): Relation name

        Returns:
            bool: Whether the relation was created.
        """
        return bool(self.model.get_relation(relation_name))

    def _storage_is_attached(self) -> bool:
        """Return whether storage is attached to the workload container.

        Returns:
            bool: Whether storage is attached.
        """
        return self._container.exists(path=BASE_CONFIG_PATH) and self._container.exists(
            path=CERTS_DIR_PATH
        )


def _get_pod_ip() -> Optional[str]:
    """Return the pod IP using juju client.

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

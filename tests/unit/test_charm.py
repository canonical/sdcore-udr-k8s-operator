# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import unittest
from subprocess import CalledProcessError
from unittest.mock import Mock, PropertyMock, patch

import yaml
from charms.tls_certificates_interface.v3.tls_certificates import (  # type: ignore[import]
    ProviderCertificate,
)
from ops import ActiveStatus, BlockedStatus, WaitingStatus, testing

from charm import NRF_RELATION_NAME, TLS_RELATION_NAME, UDROperatorCharm

COMMON_DATABASE_RELATION_NAME = "common_database"
AUTH_DATABASE_RELATION_NAME = "auth_database"
POD_IP = b"1.2.3.4"
VALID_NRF_URL = "http://nrf:8081"
EXPECTED_CONFIG_FILE_PATH = "tests/unit/expected_udrcfg.yaml"
CERTIFICATES_LIB = (
    "charms.tls_certificates_interface.v3.tls_certificates.TLSCertificatesRequiresV3"
)
STORED_CERTIFICATE = "whatever certificate content"
STORED_CSR = b"whatever csr content"
STORED_PRIVATE_KEY = b"whatever key content"
TEST_PEBBLE_LAYER = {
    "services": {
        "udr": {
            "override": "replace",
            "startup": "enabled",
            "command": "/bin/udr -udrcfg /free5gc/config/udrcfg.yaml",
            "environment": {
                "GRPC_GO_LOG_VERBOSITY_LEVEL": "99",
                "GRPC_GO_LOG_SEVERITY_LEVEL": "info",
                "GRPC_TRACE": "all",
                "GRPC_VERBOSITY": "debug",
                "MANAGED_BY_CONFIG_POD": "true",
                "POD_IP": "1.2.3.4",
            },
        }
    }
}


class TestCharm(unittest.TestCase):
    def setUp(self):
        self.namespace = "whatever"
        self.maxDiff = None
        self.metadata = self._get_metadata()
        self.container_name = list(self.metadata["containers"].keys())[0]
        self.harness = testing.Harness(UDROperatorCharm)
        self.harness.set_model_name(name=self.namespace)
        self.addCleanup(self.harness.cleanup)
        self.harness.set_leader(is_leader=True)
        self.harness.begin()
        self._container = self.harness.model.unit.get_container("udr")

    @staticmethod
    def _get_metadata() -> dict:
        """Read `metadata.yaml` and returns it as a dictionary.

        Returns:
            dics: metadata.yaml as a dictionary.
        """
        with open("metadata.yaml", "r") as f:
            data = yaml.safe_load(f)
        return data

    @staticmethod
    def _read_file(path: str) -> str:
        """Read a file and returns as a string.

        Args:
            path (str): path to the file.

        Returns:
            str: content of the file.
        """
        with open(path, "r") as f:
            content = f.read()
        return content

    def _create_common_database_relation_and_populate_data(self) -> int:
        common_database_url = "1.9.11.4:1234"
        common_database_username = "banana"
        common_database_password = "pizza"
        common_database_relation_id = self.harness.add_relation(
            COMMON_DATABASE_RELATION_NAME, "mongodb"
        )
        self.harness.add_relation_unit(
            relation_id=common_database_relation_id, remote_unit_name="mongodb/0"
        )
        self.harness.update_relation_data(
            relation_id=common_database_relation_id,
            app_or_unit="mongodb",
            key_values={
                "username": common_database_username,
                "password": common_database_password,
                "uris": common_database_url,
            },
        )
        return common_database_relation_id

    def _create_auth_database_relation_and_populate_data(self) -> int:
        auth_database_url = "1.9.11.4:1234"
        auth_database_username = "apple"
        auth_database_password = "hamburger"
        auth_database_relation_id = self.harness.add_relation(
            AUTH_DATABASE_RELATION_NAME, "mongodb"
        )
        self.harness.add_relation_unit(
            relation_id=auth_database_relation_id, remote_unit_name="mongodb/0"
        )
        self.harness.update_relation_data(
            relation_id=auth_database_relation_id,
            app_or_unit="mongodb",
            key_values={
                "username": auth_database_username,
                "password": auth_database_password,
                "uris": auth_database_url,
            },
        )
        return auth_database_relation_id

    def _create_certificates_relation(self) -> int:
        """Create certificates relation.

        Returns:
            int: relation id.
        """
        relation_id = self.harness.add_relation(
            relation_name=TLS_RELATION_NAME, remote_app="tls-certificates-operator"
        )
        self.harness.add_relation_unit(
            relation_id=relation_id, remote_unit_name="tls-certificates-operator/0"
        )
        return relation_id

    def _create_nrf_relation(self) -> int:
        """Create NRF relation.

        Returns:
            int: relation id.
        """
        relation_id = self.harness.add_relation(
            relation_name=NRF_RELATION_NAME, remote_app="nrf-operator"
        )
        self.harness.add_relation_unit(relation_id=relation_id, remote_unit_name="nrf-operator/0")
        return relation_id

    def test_given_common_database_relation_not_created_when_pebble_ready_then_status_is_blocked(
        self,
    ):
        self._create_nrf_relation()
        self.harness.container_pebble_ready(self.container_name)
        self.harness.evaluate_status()
        self.assertEqual(
            self.harness.model.unit.status,
            BlockedStatus("Waiting for the common_database relation to be created"),
        )

    def test_given_auth_database_relation_not_created_when_pebble_ready_then_status_is_blocked(
        self,
    ):
        self._create_nrf_relation()
        self.harness.add_relation(
            relation_name=COMMON_DATABASE_RELATION_NAME, remote_app="mongodb"
        )
        self._create_certificates_relation()
        self.harness.container_pebble_ready(self.container_name)
        self.harness.evaluate_status()
        self.assertEqual(
            self.harness.model.unit.status,
            BlockedStatus("Waiting for the auth_database relation to be created"),
        )

    def test_given_fiveg_nrf_relation_not_created_when_pebble_ready_then_status_is_blocked(self):
        self.harness.add_relation(
            relation_name=COMMON_DATABASE_RELATION_NAME, remote_app="some_db_app"
        )
        self.harness.add_relation(
            relation_name=AUTH_DATABASE_RELATION_NAME, remote_app="some_db_app"
        )
        self.harness.container_pebble_ready(self.container_name)
        self.harness.evaluate_status()
        self.assertEqual(
            self.harness.model.unit.status,
            BlockedStatus("Waiting for the fiveg_nrf relation to be created"),
        )

    def test_given_certificates_relation_not_created_when_pebble_ready_then_status_is_blocked(
        self,
    ):
        self.harness.add_relation(
            relation_name=COMMON_DATABASE_RELATION_NAME, remote_app="some_db_app"
        )
        self.harness.add_relation(
            relation_name=AUTH_DATABASE_RELATION_NAME, remote_app="some_db_app"
        )
        self.harness.add_relation(relation_name=NRF_RELATION_NAME, remote_app="some_nrf_app")
        self.harness.container_pebble_ready(self.container_name)
        self.harness.evaluate_status()
        self.assertEqual(
            self.harness.model.unit.status,
            BlockedStatus("Waiting for the certificates relation to be created"),
        )

    @patch("charm.check_output")
    @patch("charms.sdcore_nrf_k8s.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    @patch("charms.data_platform_libs.v0.data_interfaces.DatabaseRequires.is_resource_created")
    def test_given_udr_charm_in_active_status_when_nrf_relation_breaks_then_status_is_blocked(
        self, patched_is_resource_created, patched_nrf_url, patched_check_output
    ):
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.add_storage(storage_name="config", attach=True)

        root = self.harness.get_filesystem_root(self.container_name)
        (root / "support/TLS/udr.pem").write_text(STORED_CERTIFICATE)

        patched_check_output.return_value = POD_IP
        patched_is_resource_created.return_value = True
        patched_nrf_url.return_value = VALID_NRF_URL

        nrf_relation_id = self._create_nrf_relation()
        self._create_certificates_relation()
        self._create_common_database_relation_and_populate_data()
        self._create_auth_database_relation_and_populate_data()
        self.harness.container_pebble_ready(self.container_name)

        self.harness.remove_relation(nrf_relation_id)
        self.harness.evaluate_status()
        self.assertEqual(
            self.harness.model.unit.status,
            BlockedStatus("Waiting for the fiveg_nrf relation to be created"),
        )

    @patch("charm.check_output")
    @patch("charms.sdcore_nrf_k8s.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    @patch("charms.data_platform_libs.v0.data_interfaces.DatabaseRequires.is_resource_created")
    def test_given_udr_charm_in_active_status_when_database_relation_breaks_then_status_is_blocked(
        self, patched_is_resource_created, patched_nrf_url, patched_check_output
    ):
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.add_storage(storage_name="config", attach=True)

        root = self.harness.get_filesystem_root(self.container_name)
        (root / "support/TLS/udr.pem").write_text(STORED_CERTIFICATE)

        patched_check_output.return_value = POD_IP
        patched_is_resource_created.return_value = True
        patched_nrf_url.return_value = VALID_NRF_URL

        self._create_certificates_relation()
        self._create_nrf_relation()
        self._create_auth_database_relation_and_populate_data()
        database_relation_id = self._create_common_database_relation_and_populate_data()
        self.harness.container_pebble_ready(self.container_name)

        self.harness.remove_relation(database_relation_id)
        self.harness.evaluate_status()
        self.assertEqual(
            self.harness.model.unit.status,
            BlockedStatus("Waiting for the common_database relation to be created"),
        )

    def test_given_relations_created_but_common_database_not_available_when_pebble_ready_then_status_is_waiting(  # noqa: E501
        self,
    ):
        self.harness.add_relation(
            relation_name=COMMON_DATABASE_RELATION_NAME, remote_app="some_db_app"
        )
        self.harness.add_relation(
            relation_name=AUTH_DATABASE_RELATION_NAME, remote_app="some_db_app"
        )
        self._create_nrf_relation()
        self._create_certificates_relation()
        self.harness.container_pebble_ready(self.container_name)
        self.harness.evaluate_status()
        self.assertEqual(
            self.harness.model.unit.status,
            WaitingStatus("Waiting for the common database to be available"),
        )

    @patch("charms.data_platform_libs.v0.data_interfaces.DatabaseRequires.is_resource_created")
    def test_given_common_database_url_not_available_when_pebble_ready_then_status_is_waiting(
        self, patched_is_resource_created
    ):
        patched_is_resource_created.return_value = True
        self.harness.add_relation(
            relation_name=COMMON_DATABASE_RELATION_NAME, remote_app="some_db_app"
        )
        self.harness.add_relation(
            relation_name=AUTH_DATABASE_RELATION_NAME, remote_app="some_db_app"
        )
        self._create_nrf_relation()
        self._create_certificates_relation()
        self.harness.container_pebble_ready(self.container_name)
        self.harness.evaluate_status()
        self.assertEqual(
            self.harness.model.unit.status,
            WaitingStatus("Waiting for the common database url to be available"),
        )

    @patch("charms.data_platform_libs.v0.data_interfaces.DatabaseRequires.is_resource_created")
    def test_given_nrf_data_not_available_when_pebble_ready_then_status_is_waiting(
        self, patched_is_resource_created
    ):
        patched_is_resource_created.return_value = True
        self.harness.add_relation(relation_name=NRF_RELATION_NAME, remote_app="some_nrf_app")
        self._create_common_database_relation_and_populate_data()
        self._create_auth_database_relation_and_populate_data()
        self._create_certificates_relation()
        self.harness.container_pebble_ready(self.container_name)
        self.harness.evaluate_status()
        self.assertEqual(
            self.harness.model.unit.status, WaitingStatus("Waiting for the NRF to be available")
        )

    @patch("charms.sdcore_nrf_k8s.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    @patch("charms.data_platform_libs.v0.data_interfaces.DatabaseRequires.is_resource_created")
    def test_given_relations_created_and_database_available_and_nrf_available_but_storage_not_attached_when_pebble_ready_then_then_status_is_waiting(  # noqa: E501
        self, patched_is_resource_created, patched_nrf_url
    ):
        patched_is_resource_created.return_value = True
        patched_nrf_url.return_value = VALID_NRF_URL
        self._create_nrf_relation()
        self._create_common_database_relation_and_populate_data()
        self._create_auth_database_relation_and_populate_data()
        self._create_certificates_relation()
        self.harness.container_pebble_ready(self.container_name)
        self.harness.evaluate_status()
        self.assertEqual(
            self.harness.model.unit.status, WaitingStatus("Waiting for the storage to be attached")
        )

    @patch("charm.check_output")
    @patch("charms.sdcore_nrf_k8s.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    @patch("charms.data_platform_libs.v0.data_interfaces.DatabaseRequires.is_resource_created")
    def test_given_relations_created_and_database_available_and_nrf_available_but_certificate_not_stored_when_pebble_ready_then_then_status_is_waiting(  # noqa: E501
        self,
        patched_is_resource_created,
        patched_nrf_url,
        patched_check_output,
    ):
        self.harness.add_storage(storage_name="config", attach=True)
        self.harness.add_storage(storage_name="certs", attach=True)

        patched_check_output.return_value = POD_IP
        patched_is_resource_created.return_value = True
        patched_nrf_url.return_value = VALID_NRF_URL

        self.harness.add_relation(relation_name=NRF_RELATION_NAME, remote_app="some_nrf_app")
        self._create_common_database_relation_and_populate_data()
        self._create_auth_database_relation_and_populate_data()
        self._create_certificates_relation()

        self.harness.container_pebble_ready(self.container_name)
        self.harness.evaluate_status()
        self.assertEqual(
            self.harness.model.unit.status, WaitingStatus("Waiting for certificates to be stored")
        )

    @patch("charms.sdcore_nrf_k8s.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    @patch(f"{CERTIFICATES_LIB}.get_assigned_certificates")
    @patch("charm.generate_csr")
    @patch("charm.check_output")
    @patch("charm.generate_private_key")
    @patch("charms.data_platform_libs.v0.data_interfaces.DatabaseRequires.is_resource_created")
    def test_given_udr_config_is_different_from_the_newly_generated_config_when_pebble_ready_then_new_config_file_is_pushed(  # noqa: E501
        self,
        patched_is_resource_created,
        patch_generate_private_key,
        patch_check_output,
        patch_generate_csr,
        patch_get_assigned_certificates,
        patched_nrf_url,
    ):
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.add_storage(storage_name="config", attach=True)
        root = self.harness.get_filesystem_root(self.container_name)

        patch_generate_private_key.return_value = STORED_PRIVATE_KEY
        patch_check_output.return_value = POD_IP
        patch_generate_csr.return_value = STORED_CSR
        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = STORED_CERTIFICATE
        provider_certificate.csr = STORED_CSR.decode()
        patch_get_assigned_certificates.return_value = [
            provider_certificate,
        ]
        patched_is_resource_created.return_value = True
        patched_nrf_url.return_value = VALID_NRF_URL

        (root / "support/TLS/udr.pem").write_text(STORED_CERTIFICATE)
        (root / "free5gc/config/udrcfg.yaml").write_text("Dummy content")

        self._create_nrf_relation()
        self._create_common_database_relation_and_populate_data()
        self._create_auth_database_relation_and_populate_data()
        self._create_certificates_relation()
        self.harness.container_pebble_ready(self.container_name)
        self.harness.evaluate_status()
        self.assertEqual(self.harness.model.unit.status, ActiveStatus(""))
        with open("tests/unit/resources/expected_udrcfg.yaml") as expected_config_file:
            expected_content = expected_config_file.read()
            self.assertEqual(
                (root / "free5gc/config/udrcfg.yaml").read_text(), expected_content.strip()
            )

    @patch("charm.check_output")
    @patch("charms.sdcore_nrf_k8s.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    @patch("charms.data_platform_libs.v0.data_interfaces.DatabaseRequires.is_resource_created")
    def test_given_udr_config_is_the_same_as_the_newly_generated_config_when_pebble_ready_then_new_config_file_is_not_pushed(  # noqa: E501
        self,
        patched_is_resource_created,
        patched_nrf_url,
        patched_check_output,
    ):
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.add_storage(storage_name="config", attach=True)

        root = self.harness.get_filesystem_root("udr")
        (root / "support/TLS/udr.pem").write_text(STORED_CERTIFICATE)
        (root / "free5gc/config/udrcfg.yaml").write_text(
            self._read_file("tests/unit/resources/expected_udrcfg.yaml")
        )
        config_modification_time = (root / "free5gc/config/udrcfg.yaml").stat().st_mtime

        patched_check_output.return_value = POD_IP
        patched_is_resource_created.return_value = True
        patched_nrf_url.return_value = VALID_NRF_URL
        self._create_nrf_relation()
        self._create_certificates_relation()
        self._create_common_database_relation_and_populate_data()
        self._create_auth_database_relation_and_populate_data()

        self.harness.container_pebble_ready(self.container_name)

        self.assertEqual(
            (root / "free5gc/config/udrcfg.yaml").stat().st_mtime, config_modification_time
        )

    @patch("ops.model.Container.restart")
    @patch("charms.sdcore_nrf_k8s.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    @patch(f"{CERTIFICATES_LIB}.get_assigned_certificates")
    @patch("charm.generate_csr")
    @patch("charm.check_output")
    @patch("charm.generate_private_key")
    @patch("charms.data_platform_libs.v0.data_interfaces.DatabaseRequires.is_resource_created")
    def test_given_udr_service_already_configured_and_udr_config_is_different_from_the_newly_generated_config_when_pebble_ready_then_udr_service_is_restarted(  # noqa: E501
        self,
        patched_is_resource_created,
        patch_generate_private_key,
        patch_check_output,
        patch_generate_csr,
        patch_get_assigned_certificates,
        patched_nrf_url,
        patch_restart,
    ):
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.add_storage(storage_name="config", attach=True)
        root = self.harness.get_filesystem_root(self.container_name)

        patch_generate_private_key.return_value = STORED_PRIVATE_KEY
        patch_check_output.return_value = POD_IP
        patch_generate_csr.return_value = STORED_CSR
        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = STORED_CERTIFICATE
        provider_certificate.csr = STORED_CSR.decode()
        patch_get_assigned_certificates.return_value = [
            provider_certificate,
        ]
        patched_is_resource_created.return_value = True
        patched_nrf_url.return_value = VALID_NRF_URL

        (root / "support/TLS/udr.pem").write_text(STORED_CERTIFICATE)
        (root / "free5gc/config/udrcfg.yaml").write_text("Dummy content")

        self._create_nrf_relation()
        self._create_common_database_relation_and_populate_data()
        self._create_auth_database_relation_and_populate_data()
        self._create_certificates_relation()
        self.harness.container_pebble_ready(self.container_name)
        self.harness.evaluate_status()
        self.assertEqual(self.harness.model.unit.status, ActiveStatus(""))

        patch_restart.assert_called_with(self.container_name)

    @patch("ops.model.Container.restart")
    @patch("charms.sdcore_nrf_k8s.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    @patch(f"{CERTIFICATES_LIB}.get_assigned_certificates")
    @patch("charm.generate_csr")
    @patch("charm.check_output")
    @patch("charm.generate_private_key")
    @patch("charms.data_platform_libs.v0.data_interfaces.DatabaseRequires.is_resource_created")
    def test_given_udr_service_already_configured_and_udr_config_is_the_same_as_the_newly_generated_config_when_pebble_ready_then_udr_service_is_not_restarted(  # noqa: E501
        self,
        patched_is_resource_created,
        patch_generate_private_key,
        patch_check_output,
        patch_generate_csr,
        patch_get_assigned_certificates,
        patched_nrf_url,
        patch_restart,
    ):
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.add_storage(storage_name="config", attach=True)
        root = self.harness.get_filesystem_root(self.container_name)

        patch_generate_private_key.return_value = STORED_PRIVATE_KEY
        patch_check_output.return_value = POD_IP
        patch_generate_csr.return_value = STORED_CSR
        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = STORED_CERTIFICATE
        provider_certificate.csr = STORED_CSR.decode()
        patch_get_assigned_certificates.return_value = [
            provider_certificate,
        ]
        patched_is_resource_created.return_value = True
        patched_nrf_url.return_value = VALID_NRF_URL

        (root / "support/TLS/udr.pem").write_text(STORED_CERTIFICATE)
        (root / "free5gc/config/udrcfg.yaml").write_text(
            self._read_file("tests/unit/resources/expected_udrcfg.yaml")
        )

        self._create_nrf_relation()
        self._create_common_database_relation_and_populate_data()
        self._create_auth_database_relation_and_populate_data()
        self._create_certificates_relation()
        self.harness.container_pebble_ready(self.container_name)
        self.harness.evaluate_status()
        self.assertEqual(self.harness.model.unit.status, ActiveStatus(""))

        patch_restart.assert_not_called()

    @patch("charms.sdcore_nrf_k8s.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    @patch(f"{CERTIFICATES_LIB}.get_assigned_certificates")
    @patch("charm.generate_csr")
    @patch("charm.check_output")
    @patch("charm.generate_private_key")
    @patch("charms.data_platform_libs.v0.data_interfaces.DatabaseRequires.is_resource_created")
    def test_given_udr_config_is_pushed_when_pebble_ready_then_udr_service_is_configured_in_the_pebble(  # noqa: E501
        self,
        patched_is_resource_created,
        patch_generate_private_key,
        patch_check_output,
        patch_generate_csr,
        patch_get_assigned_certificates,
        patched_nrf_url,
    ):
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.add_storage(storage_name="config", attach=True)

        root = self.harness.get_filesystem_root(self.container_name)

        patch_generate_private_key.return_value = STORED_PRIVATE_KEY
        patch_check_output.return_value = POD_IP
        patch_generate_csr.return_value = STORED_CSR
        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = STORED_CERTIFICATE
        provider_certificate.csr = STORED_CSR.decode()
        patch_get_assigned_certificates.return_value = [
            provider_certificate,
        ]
        patched_is_resource_created.return_value = True
        patched_nrf_url.return_value = VALID_NRF_URL

        certificate = "whatever certificate content"
        (root / "support/TLS/udr.pem").write_text(certificate)
        (root / "free5gc/config/udrcfg.yaml").write_text(
            self._read_file("tests/unit/resources/expected_udrcfg.yaml")
        )

        self._create_nrf_relation()
        self._create_common_database_relation_and_populate_data()
        self._create_auth_database_relation_and_populate_data()
        self._create_certificates_relation()
        self.harness.container_pebble_ready(self.container_name)
        self.harness.evaluate_status()
        self.assertEqual(self.harness.model.unit.status, ActiveStatus(""))

        updated_plan = self.harness.get_container_pebble_plan("udr").to_dict()
        self.assertEqual(TEST_PEBBLE_LAYER, updated_plan)

    @patch("charms.sdcore_nrf_k8s.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    @patch(f"{CERTIFICATES_LIB}.get_assigned_certificates")
    @patch("charm.generate_csr")
    @patch("charm.check_output")
    @patch("charm.generate_private_key")
    @patch("charms.data_platform_libs.v0.data_interfaces.DatabaseRequires.is_resource_created")
    def test_given_udr_config_is_pushed_when_pebble_ready_then_status_is_active(
        self,
        patched_is_resource_created,
        patch_generate_private_key,
        patch_check_output,
        patch_generate_csr,
        patch_get_assigned_certificates,
        patched_nrf_url,
    ):
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.add_storage(storage_name="config", attach=True)
        root = self.harness.get_filesystem_root(self.container_name)

        patch_generate_private_key.return_value = STORED_PRIVATE_KEY
        patch_check_output.return_value = POD_IP
        patch_generate_csr.return_value = STORED_CSR
        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = STORED_CERTIFICATE
        provider_certificate.csr = STORED_CSR.decode()
        patch_get_assigned_certificates.return_value = [
            provider_certificate,
        ]
        patched_is_resource_created.return_value = True
        patched_nrf_url.return_value = VALID_NRF_URL

        certificate = "whatever certificate content"
        (root / "support/TLS/udr.pem").write_text(certificate)
        self._create_nrf_relation()
        self._create_common_database_relation_and_populate_data()
        self._create_auth_database_relation_and_populate_data()
        self._create_certificates_relation()
        self.harness.container_pebble_ready(self.container_name)
        self.harness.evaluate_status()
        self.assertEqual(
            self.harness.model.unit.status,
            ActiveStatus(),
        )

    @patch("charms.sdcore_nrf_k8s.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    @patch(f"{CERTIFICATES_LIB}.get_assigned_certificates")
    @patch("charm.generate_csr")
    @patch("charm.check_output")
    @patch("charm.generate_private_key")
    @patch("charms.data_platform_libs.v0.data_interfaces.DatabaseRequires.is_resource_created")
    def test_given_ip_not_available_when_pebble_ready_then_status_is_waiting(
        self,
        patched_is_resource_created,
        patch_generate_private_key,
        patch_check_output,
        patch_generate_csr,
        patch_get_assigned_certificates,
        patched_nrf_url,
    ):
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.add_storage(storage_name="config", attach=True)
        root = self.harness.get_filesystem_root(self.container_name)

        patch_generate_private_key.return_value = STORED_PRIVATE_KEY
        patch_generate_csr.return_value = STORED_CSR
        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = STORED_CERTIFICATE
        provider_certificate.csr = STORED_CSR.decode()
        patch_get_assigned_certificates.return_value = [
            provider_certificate,
        ]
        patched_is_resource_created.return_value = True
        patched_nrf_url.return_value = VALID_NRF_URL

        certificate = "whatever certificate content"
        (root / "support/TLS/udr.pem").write_text(certificate)
        self._create_nrf_relation()
        self._create_common_database_relation_and_populate_data()
        self._create_auth_database_relation_and_populate_data()
        self._create_certificates_relation()
        self.harness.container_pebble_ready(self.container_name)
        self.harness.evaluate_status()
        self.assertEqual(
            self.harness.model.unit.status,
            WaitingStatus("Waiting for pod IP address to be available"),
        )

    @patch("charms.sdcore_nrf_k8s.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    @patch(f"{CERTIFICATES_LIB}.get_assigned_certificates")
    @patch("charm.generate_csr")
    @patch("charm.check_output")
    @patch("charm.generate_private_key")
    @patch("charms.data_platform_libs.v0.data_interfaces.DatabaseRequires.is_resource_created")
    def test_given_called_process_error_thrown_while_fetching_pod_ip_when_pebble_ready_then_status_is_waiting(  # noqa: E501
        self,
        patched_is_resource_created,
        patch_generate_private_key,
        patch_check_output,
        patch_generate_csr,
        patch_get_assigned_certificates,
        patched_nrf_url,
    ):
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.add_storage(storage_name="config", attach=True)
        root = self.harness.get_filesystem_root(self.container_name)

        patch_generate_private_key.return_value = STORED_PRIVATE_KEY
        patch_check_output.side_effect = CalledProcessError(cmd="", returncode=123)
        patch_generate_csr.return_value = STORED_CSR
        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = STORED_CERTIFICATE
        provider_certificate.csr = STORED_CSR.decode()
        patch_get_assigned_certificates.return_value = [
            provider_certificate,
        ]
        patched_is_resource_created.return_value = True
        patched_nrf_url.return_value = VALID_NRF_URL

        certificate = "whatever certificate content"
        (root / "support/TLS/udr.pem").write_text(certificate)
        self._create_nrf_relation()
        self._create_common_database_relation_and_populate_data()
        self._create_auth_database_relation_and_populate_data()
        self._create_certificates_relation()
        self.harness.container_pebble_ready(self.container_name)
        self.harness.evaluate_status()
        self.assertEqual(
            self.harness.model.unit.status,
            WaitingStatus("Waiting for pod IP address to be available"),
        )

    @patch("charms.sdcore_nrf_k8s.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    @patch("charm.generate_csr")
    @patch("charm.generate_private_key")
    @patch("charm.check_output")
    def test_given_can_connect_when_on_certificates_relation_created_then_private_key_is_generated(
        self, patch_check_output, patch_generate_private_key, patch_generate_csr, patched_nrf_url
    ):
        self.harness.add_storage(storage_name="config", attach=True)
        self.harness.add_storage(storage_name="certs", attach=True)
        root = self.harness.get_filesystem_root(self.container_name)

        patch_generate_private_key.return_value = STORED_PRIVATE_KEY
        patch_check_output.return_value = POD_IP
        patch_generate_csr.return_value = STORED_CSR
        patched_nrf_url.return_value = VALID_NRF_URL
        self._create_nrf_relation()
        self._create_common_database_relation_and_populate_data()
        self._create_auth_database_relation_and_populate_data()
        self._create_certificates_relation()
        self.harness.set_can_connect(container=self.container_name, val=True)
        self.harness.container_pebble_ready(self.container_name)

        self.assertEqual((root / "support/TLS/udr.key").read_text(), STORED_PRIVATE_KEY.decode())

    def test_given_certificates_are_stored_when_on_certificates_relation_broken_then_certificates_are_removed(  # noqa: E501
        self,
    ):
        self.harness.add_storage(storage_name="certs", attach=True)
        root = self.harness.get_filesystem_root("udr")
        (root / "support/TLS/udr.key").write_text(STORED_PRIVATE_KEY.decode())
        (root / "support/TLS/udr.csr").write_text(STORED_CSR.decode())
        (root / "support/TLS/udr.pem").write_text(STORED_CERTIFICATE)
        self.harness.set_can_connect(container=self.container_name, val=True)

        self.harness.charm._on_certificates_relation_broken(event=Mock)
        with self.assertRaises(FileNotFoundError):
            (root / "support/TLS/udr.key").read_text()
        with self.assertRaises(FileNotFoundError):
            (root / "support/TLS/udr.pem").read_text()
        with self.assertRaises(FileNotFoundError):
            (root / "support/TLS/udr.csr").read_text()

    @patch("charms.sdcore_nrf_k8s.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    @patch("charm.check_output")
    @patch("charm.generate_csr")
    def test_given_private_key_exists_when_on_certificates_relation_joined_then_csr_is_generated(
        self, patch_generate_csr, patch_check_output, patch_nrf_url
    ):
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.add_storage(storage_name="config", attach=True)

        root = self.harness.get_filesystem_root(self.container_name)

        (root / "support/TLS/udr.key").write_text(STORED_PRIVATE_KEY.decode())

        patch_generate_csr.return_value = STORED_CSR
        patch_check_output.return_value = POD_IP
        patch_nrf_url.return_value = VALID_NRF_URL
        self.harness.set_can_connect(container=self.container_name, val=True)
        self._create_common_database_relation_and_populate_data()
        self._create_nrf_relation()
        self._create_auth_database_relation_and_populate_data()
        self._create_certificates_relation()
        self.harness.set_can_connect(container=self.container_name, val=True)

        self.harness.container_pebble_ready(container_name=self.container_name)

        self.assertEqual((root / "support/TLS/udr.csr").read_text(), STORED_CSR.decode())

    @patch("charms.sdcore_nrf_k8s.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    @patch("charm.check_output")
    @patch(f"{CERTIFICATES_LIB}.request_certificate_creation")
    @patch("charm.generate_csr")
    def test_given_private_key_exists_and_cert_not_yet_requested_when_on_certificates_relation_joined_then_cert_is_requested(  # noqa: E501
        self,
        patch_generate_csr,
        patch_request_certificate_creation,
        patch_check_output,
        patch_nrf_url,
    ):
        self.harness.add_storage(storage_name="config", attach=True)
        self.harness.add_storage(storage_name="certs", attach=True)
        root = self.harness.get_filesystem_root(self.container_name)

        (root / "support/TLS/udr.key").write_text(STORED_PRIVATE_KEY.decode())
        patch_generate_csr.return_value = STORED_CSR
        patch_check_output.return_value = POD_IP
        patch_nrf_url.return_value = VALID_NRF_URL
        self.harness.set_can_connect(container=self.container_name, val=True)
        self._create_common_database_relation_and_populate_data()
        self._create_nrf_relation()
        self._create_auth_database_relation_and_populate_data()
        self._create_certificates_relation()
        patch_request_certificate_creation.assert_called_with(
            certificate_signing_request=STORED_CSR
        )

    @patch("charms.sdcore_nrf_k8s.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    @patch("charm.check_output")
    @patch(f"{CERTIFICATES_LIB}.request_certificate_creation")
    def test_given_cert_already_stored_when_on_certificates_relation_joined_then_cert_is_not_requested(  # noqa: E501
        self, patch_request_certificate_creation, patch_check_output, patch_nrf_url
    ):
        self.harness.add_storage(storage_name="config", attach=True)
        self.harness.add_storage(storage_name="certs", attach=True)
        root = self.harness.get_filesystem_root(self.container_name)

        (root / "support/TLS/udr.key").write_text(STORED_PRIVATE_KEY.decode())
        (root / "support/TLS/udr.csr").write_text(STORED_CSR.decode())
        (root / "support/TLS/udr.pem").write_text(STORED_CERTIFICATE)

        self.harness.set_can_connect(container=self.container_name, val=True)
        patch_check_output.return_value = POD_IP
        patch_nrf_url.return_value = VALID_NRF_URL
        self._create_common_database_relation_and_populate_data()
        self._create_nrf_relation()
        self._create_auth_database_relation_and_populate_data()
        self.harness.set_can_connect(container=self.container_name, val=True)
        self.harness.container_pebble_ready(container_name=self.container_name)
        patch_request_certificate_creation.assert_not_called()

    @patch("charm.generate_csr")
    @patch("charm.generate_private_key")
    @patch("charms.sdcore_nrf_k8s.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    @patch("charm.check_output")
    @patch(f"{CERTIFICATES_LIB}.get_assigned_certificates")
    def test_given_csr_matches_stored_one_when_certificate_available_then_certificate_is_pushed(
        self,
        patch_get_assigned_certificates,
        patch_check_output,
        patch_nrf_url,
        patch_generate_private_key,
        patch_generate_csr,
    ):
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.add_storage(storage_name="config", attach=True)
        root = self.harness.get_filesystem_root(self.container_name)

        patch_generate_private_key.return_value = STORED_PRIVATE_KEY
        patch_check_output.return_value = POD_IP
        patch_generate_csr.return_value = STORED_CSR
        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = STORED_CERTIFICATE
        provider_certificate.csr = STORED_CSR.decode()
        patch_get_assigned_certificates.return_value = [
            provider_certificate,
        ]
        patch_check_output.return_value = POD_IP
        (root / "support/TLS/udr.csr").write_text(STORED_CSR.decode())
        self._create_common_database_relation_and_populate_data()
        self._create_auth_database_relation_and_populate_data()
        self._create_nrf_relation()
        self._create_certificates_relation()
        self.harness.set_can_connect(container=self.container_name, val=True)
        self.harness.container_pebble_ready(container_name=self.container_name)
        self.assertEqual((root / "support/TLS/udr.pem").read_text(), STORED_CERTIFICATE)

    @patch("charm.generate_csr")
    @patch("charm.generate_private_key")
    @patch("charm.check_output")
    @patch(f"{CERTIFICATES_LIB}.get_assigned_certificates")
    def test_given_csr_doesnt_match_stored_one_when_certificate_available_then_certificate_is_not_pushed(  # noqa: E501
        self,
        patch_get_assigned_certificates,
        patch_check_output,
        patch_generate_private_key,
        patch_generate_csr,
    ):
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.add_storage(storage_name="config", attach=True)
        root = self.harness.get_filesystem_root(self.container_name)

        patch_generate_private_key.return_value = STORED_PRIVATE_KEY
        patch_check_output.return_value = POD_IP
        csr = b"Different csr content"
        patch_generate_csr.return_value = csr
        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = STORED_CERTIFICATE
        provider_certificate.csr = STORED_CSR.decode()
        patch_get_assigned_certificates.return_value = [
            provider_certificate,
        ]
        patch_check_output.return_value = POD_IP
        (root / "support/TLS/udr.csr").write_text(csr.decode())
        self._create_common_database_relation_and_populate_data()
        self._create_auth_database_relation_and_populate_data()
        self._create_nrf_relation()
        self._create_certificates_relation()
        self.harness.set_can_connect(container=self.container_name, val=True)
        self.harness.container_pebble_ready(container_name=self.container_name)

        with self.assertRaises(FileNotFoundError):
            (root / "support/TLS/udr.pem").read_text()

    @patch(f"{CERTIFICATES_LIB}.request_certificate_creation")
    @patch("charm.generate_csr")
    def test_given_certificate_does_not_match_stored_one_when_certificate_expiring_then_certificate_is_not_requested(  # noqa: E501
        self, patch_generate_csr, patch_request_certificate_creation
    ):
        self.harness.add_storage("certs", attach=True)
        root = self.harness.get_filesystem_root(self.container_name)
        (root / "support/TLS/udr.pem").write_text(STORED_CERTIFICATE)
        event = Mock()
        event.certificate = "Relation certificate content (different from stored)"
        patch_generate_csr.return_value = STORED_CSR
        self.harness.set_can_connect(container=self.container_name, val=True)

        self.harness.charm._on_certificate_expiring(event=event)

        patch_request_certificate_creation.assert_not_called()

    @patch(f"{CERTIFICATES_LIB}.request_certificate_creation")
    @patch("charm.generate_csr")
    def test_given_certificate_matches_stored_one_when_certificate_expiring_then_certificate_is_requested(  # noqa: E501
        self, patch_generate_csr, patch_request_certificate_creation
    ):
        self.harness.add_storage("certs", attach=True)
        root = self.harness.get_filesystem_root("udr")
        (root / "support/TLS/udr.key").write_text(STORED_PRIVATE_KEY.decode())
        (root / "support/TLS/udr.pem").write_text(STORED_CERTIFICATE)
        event = Mock()
        event.certificate = STORED_CERTIFICATE
        patch_generate_csr.return_value = STORED_CSR
        self.harness.set_can_connect(container=self.container_name, val=True)

        self.harness.charm._on_certificate_expiring(event=event)

        patch_request_certificate_creation.assert_called_with(
            certificate_signing_request=STORED_CSR
        )

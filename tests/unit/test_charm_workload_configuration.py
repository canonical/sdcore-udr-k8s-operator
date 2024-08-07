# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

from unittest.mock import Mock

from charms.tls_certificates_interface.v3.tls_certificates import (
    ProviderCertificate,
)
from ops import ActiveStatus

from tests.unit.fixtures import UDRUnitTestFixtures

CONTAINER_NAME = "udr"
TEST_POD_IP = b"1.2.3.4"
TEST_CSR = b"whatever csr"
TEST_PRIVATE_KEY = b"whatever private key"
TEST_CERTIFICATE = "whatever certificate"
EXPECTED_CONFIG_FILE_PATH = "tests/unit/expected_udrcfg.yaml"
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


class TestCharmWorkloadConfiguration(UDRUnitTestFixtures):
    def test_given_udr_config_is_different_from_the_newly_generated_config_when_pebble_ready_then_new_config_file_is_pushed(  # noqa: E501
        self,
        add_storage,
        create_auth_database_relation_and_populate_data,
        create_common_database_relation_and_populate_data,
        create_nrf_relation_and_set_nrf_url,
        create_webui_relation_and_set_webui_url,
        certificates_relation_id,
    ):
        self.harness.set_can_connect(container=CONTAINER_NAME, val=True)
        self.mock_check_output.return_value = TEST_POD_IP
        root = self.harness.get_filesystem_root(CONTAINER_NAME)
        (root / "support/TLS/udr.csr").write_text(TEST_CSR.decode())
        (root / "support/TLS/udr.key").write_text(TEST_PRIVATE_KEY.decode())
        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = TEST_CERTIFICATE
        provider_certificate.csr = TEST_CSR.decode()
        self.mock_get_assigned_certificates.return_value = [
            provider_certificate,
        ]
        (root / "free5gc/config/udrcfg.yaml").write_text("Dummy content")

        self.harness.container_pebble_ready(CONTAINER_NAME)

        self.harness.evaluate_status()
        assert self.harness.model.unit.status == ActiveStatus("")
        with open("tests/unit/resources/expected_udrcfg.yaml") as expected_config_file:
            expected_content = expected_config_file.read()
            assert (root / "free5gc/config/udrcfg.yaml").read_text() == expected_content.strip()

    def test_given_udr_config_is_the_same_as_the_newly_generated_config_when_pebble_ready_then_new_config_file_is_not_pushed(  # noqa: E501
        self,
        add_storage,
        create_auth_database_relation_and_populate_data,
        create_common_database_relation_and_populate_data,
        create_nrf_relation_and_set_nrf_url,
        create_webui_relation_and_set_webui_url,
        certificates_relation_id,
    ):
        self.harness.set_can_connect(container=CONTAINER_NAME, val=True)
        self.mock_check_output.return_value = TEST_POD_IP
        root = self.harness.get_filesystem_root(CONTAINER_NAME)
        (root / "support/TLS/udr.csr").write_text(TEST_CSR.decode())
        (root / "support/TLS/udr.key").write_text(TEST_PRIVATE_KEY.decode())
        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = TEST_CERTIFICATE
        provider_certificate.csr = TEST_CSR.decode()
        self.mock_get_assigned_certificates.return_value = [
            provider_certificate,
        ]
        (root / "free5gc/config/udrcfg.yaml").write_text(
            _read_file("tests/unit/resources/expected_udrcfg.yaml")
        )
        config_modification_time = (root / "free5gc/config/udrcfg.yaml").stat().st_mtime

        self.harness.container_pebble_ready(CONTAINER_NAME)

        assert (root / "free5gc/config/udrcfg.yaml").stat().st_mtime == config_modification_time

    def test_given_udr_service_already_configured_and_udr_config_is_different_from_the_newly_generated_config_when_pebble_ready_then_udr_service_is_restarted(  # noqa: E501
        self,
        add_storage,
        create_auth_database_relation_and_populate_data,
        create_common_database_relation_and_populate_data,
        create_nrf_relation_and_set_nrf_url,
        create_webui_relation_and_set_webui_url,
        certificates_relation_id,
    ):
        self.harness.set_can_connect(container=CONTAINER_NAME, val=True)
        self.mock_check_output.return_value = TEST_POD_IP
        root = self.harness.get_filesystem_root(CONTAINER_NAME)
        (root / "support/TLS/udr.csr").write_text(TEST_CSR.decode())
        (root / "support/TLS/udr.key").write_text(TEST_PRIVATE_KEY.decode())
        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = TEST_CERTIFICATE
        provider_certificate.csr = TEST_CSR.decode()
        self.mock_get_assigned_certificates.return_value = [
            provider_certificate,
        ]
        (root / "free5gc/config/udrcfg.yaml").write_text("Dummy content")

        self.harness.container_pebble_ready(CONTAINER_NAME)

        self.mock_restart.assert_called_with(CONTAINER_NAME)

    def test_given_udr_service_already_configured_and_webui_url_is_different_from_the_newly_generated_config_when_webui_url_available_then_udr_service_is_restarted(  # noqa: E501
        self,
        add_storage,
        create_auth_database_relation_and_populate_data,
        create_common_database_relation_and_populate_data,
        create_nrf_relation_and_set_nrf_url,
        create_webui_relation_and_set_webui_url,
        webui_relation_id,
        certificates_relation_id,
    ):
        self.harness.set_can_connect(container=CONTAINER_NAME, val=True)
        self.mock_check_output.return_value = TEST_POD_IP
        root = self.harness.get_filesystem_root(CONTAINER_NAME)
        (root / "support/TLS/udr.csr").write_text(TEST_CSR.decode())
        (root / "support/TLS/udr.key").write_text(TEST_PRIVATE_KEY.decode())
        (root / "support/TLS/udr.pem").write_text(TEST_CERTIFICATE)
        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = TEST_CERTIFICATE
        provider_certificate.csr = TEST_CSR.decode()
        self.mock_get_assigned_certificates.return_value = [
            provider_certificate,
        ]
        (root / "free5gc/config/udrcfg.yaml").write_text(
            _read_file("tests/unit/resources/expected_udrcfg.yaml")
        )

        self.harness.update_relation_data(
            relation_id=webui_relation_id,
            app_or_unit="whatever-webui",
            key_values={"webui_url": "something new"},
        )

        self.mock_restart.assert_called_with(CONTAINER_NAME)

    def test_given_udr_service_already_configured_and_udr_config_is_the_same_as_the_newly_generated_config_when_pebble_ready_then_udr_service_is_not_restarted(  # noqa: E501
        self,
        add_storage,
        create_auth_database_relation_and_populate_data,
        create_common_database_relation_and_populate_data,
        create_nrf_relation_and_set_nrf_url,
        create_webui_relation_and_set_webui_url,
        certificates_relation_id,
    ):
        self.harness.set_can_connect(container=CONTAINER_NAME, val=True)
        self.mock_check_output.return_value = TEST_POD_IP
        root = self.harness.get_filesystem_root(CONTAINER_NAME)
        (root / "support/TLS/udr.csr").write_text(TEST_CSR.decode())
        (root / "support/TLS/udr.key").write_text(TEST_PRIVATE_KEY.decode())
        (root / "support/TLS/udr.pem").write_text(TEST_CERTIFICATE)
        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = TEST_CERTIFICATE
        provider_certificate.csr = TEST_CSR.decode()
        self.mock_get_assigned_certificates.return_value = [
            provider_certificate,
        ]
        (root / "free5gc/config/udrcfg.yaml").write_text(
            _read_file("tests/unit/resources/expected_udrcfg.yaml")
        )

        self.harness.container_pebble_ready(CONTAINER_NAME)

        self.mock_restart.assert_not_called()

    def test_given_udr_config_is_pushed_when_pebble_ready_then_udr_service_is_configured_in_the_pebble(  # noqa: E501
        self,
        add_storage,
        create_auth_database_relation_and_populate_data,
        create_common_database_relation_and_populate_data,
        create_nrf_relation_and_set_nrf_url,
        create_webui_relation_and_set_webui_url,
        certificates_relation_id,
    ):
        self.harness.set_can_connect(container=CONTAINER_NAME, val=True)
        self.mock_check_output.return_value = TEST_POD_IP
        root = self.harness.get_filesystem_root(CONTAINER_NAME)
        (root / "support/TLS/udr.csr").write_text(TEST_CSR.decode())
        (root / "support/TLS/udr.key").write_text(TEST_PRIVATE_KEY.decode())
        (root / "support/TLS/udr.pem").write_text(TEST_CERTIFICATE)
        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = TEST_CERTIFICATE
        provider_certificate.csr = TEST_CSR.decode()
        self.mock_get_assigned_certificates.return_value = [
            provider_certificate,
        ]
        (root / "free5gc/config/udrcfg.yaml").write_text(
            _read_file("tests/unit/resources/expected_udrcfg.yaml")
        )

        self.harness.container_pebble_ready(CONTAINER_NAME)

        updated_plan = self.harness.get_container_pebble_plan("udr").to_dict()
        assert TEST_PEBBLE_LAYER == updated_plan


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

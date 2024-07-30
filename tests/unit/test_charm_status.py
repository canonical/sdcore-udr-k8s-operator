# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import os
from subprocess import CalledProcessError
from unittest.mock import Mock

from fixtures import UDRUnitTestFixtures
from ops import ActiveStatus, BlockedStatus, WaitingStatus

from lib.charms.tls_certificates_interface.v3.tls_certificates import ProviderCertificate

CONTAINER_NAME = "udr"
TEST_POD_IP = b"1.2.3.4"
TEST_CSR = b"whatever csr"
TEST_PRIVATE_KEY = b"whatever private key"
TEST_CERTIFICATE = "whatever certificate"


class TestCharmStatus(UDRUnitTestFixtures):
    def test_given_common_database_relation_not_created_when_pebble_ready_then_status_is_blocked(
        self,
        auth_database_relation_id,
        certificates_relation_id,
        nrf_relation_id,
        nms_relation_id,
    ):
        self.harness.container_pebble_ready(CONTAINER_NAME)
        self.harness.evaluate_status()

        assert self.harness.model.unit.status == BlockedStatus(
            "Waiting for common_database relation(s)"
        )

    def test_given_auth_database_relation_not_created_when_pebble_ready_then_status_is_blocked(
        self,
        common_database_relation_id,
        certificates_relation_id,
        nrf_relation_id,
        nms_relation_id,
    ):
        self.harness.container_pebble_ready(CONTAINER_NAME)
        self.harness.evaluate_status()

        assert self.harness.model.unit.status == BlockedStatus(
            "Waiting for auth_database relation(s)"
        )

    def test_given_fiveg_nrf_relation_not_created_when_pebble_ready_then_status_is_blocked(
        self,
        auth_database_relation_id,
        common_database_relation_id,
        certificates_relation_id,
        nms_relation_id,
    ):
        self.harness.container_pebble_ready(CONTAINER_NAME)
        self.harness.evaluate_status()

        assert self.harness.model.unit.status == BlockedStatus("Waiting for fiveg_nrf relation(s)")

    def test_given_certificates_relation_not_created_when_pebble_ready_then_status_is_blocked(
        self,
        auth_database_relation_id,
        common_database_relation_id,
        nrf_relation_id,
        nms_relation_id,
    ):
        self.harness.container_pebble_ready(CONTAINER_NAME)
        self.harness.evaluate_status()

        assert self.harness.model.unit.status == BlockedStatus(
            "Waiting for certificates relation(s)"
        )

    def test_given_sdcore_config_relation_not_created_when_pebble_ready_then_status_is_blocked(
        self,
        auth_database_relation_id,
        common_database_relation_id,
        certificates_relation_id,
        nrf_relation_id,
    ):
        self.harness.container_pebble_ready(CONTAINER_NAME)
        self.harness.evaluate_status()

        assert self.harness.model.unit.status == BlockedStatus(
            "Waiting for sdcore-config relation(s)"
        )

    def test_given_relations_created_and_database_available_nrf_available_and_webui_available_but_storage_not_attached_when_pebble_ready_then_then_status_is_waiting(  # noqa: E501
        self,
        create_auth_database_relation_and_populate_data,
        create_common_database_relation_and_populate_data,
        create_nrf_relation_and_set_nrf_url,
        create_nms_relation_and_set_webui_url,
        certificates_relation_id,
    ):
        self.harness.container_pebble_ready(CONTAINER_NAME)
        self.harness.evaluate_status()

        assert self.harness.model.unit.status == WaitingStatus(
            "Waiting for the storage to be attached"
        )

    def test_given_udr_charm_in_active_status_when_nrf_relation_breaks_then_status_is_blocked(
        self,
        add_storage,
        create_auth_database_relation_and_populate_data,
        create_common_database_relation_and_populate_data,
        create_nrf_relation_and_set_nrf_url,
        create_nms_relation_and_set_webui_url,
        nrf_relation_id,
        certificates_relation_id,
    ):
        self.mock_check_output.return_value = TEST_POD_IP
        self.mock_generate_private_key.return_value = TEST_PRIVATE_KEY
        self.harness.set_can_connect(container=CONTAINER_NAME, val=True)
        root = self.harness.get_filesystem_root(CONTAINER_NAME)
        (root / "support/TLS/udr.csr").write_text(TEST_CSR.decode())
        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = TEST_CERTIFICATE
        provider_certificate.csr = TEST_CSR.decode()
        self.mock_get_assigned_certificates.return_value = [
            provider_certificate,
        ]
        self.harness.evaluate_status()
        assert self.harness.model.unit.status == ActiveStatus()

        self.harness.remove_relation(nrf_relation_id)

        self.harness.evaluate_status()
        assert self.harness.model.unit.status == BlockedStatus("Waiting for fiveg_nrf relation(s)")

    def test_given_udr_charm_in_active_status_when_database_relation_breaks_then_status_is_blocked(
        self,
        add_storage,
        create_auth_database_relation_and_populate_data,
        create_common_database_relation_and_populate_data,
        create_nrf_relation_and_set_nrf_url,
        create_nms_relation_and_set_webui_url,
        common_database_relation_id,
        certificates_relation_id,
    ):
        self.mock_check_output.return_value = TEST_POD_IP
        self.mock_generate_private_key.return_value = TEST_PRIVATE_KEY
        self.harness.set_can_connect(container=CONTAINER_NAME, val=True)
        root = self.harness.get_filesystem_root(CONTAINER_NAME)
        (root / "support/TLS/udr.csr").write_text(TEST_CSR.decode())
        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = TEST_CERTIFICATE
        provider_certificate.csr = TEST_CSR.decode()
        self.mock_get_assigned_certificates.return_value = [
            provider_certificate,
        ]
        self.harness.evaluate_status()
        assert self.harness.model.unit.status == ActiveStatus()

        self.harness.remove_relation(common_database_relation_id)

        self.harness.evaluate_status()
        assert self.harness.model.unit.status == BlockedStatus(
            "Waiting for common_database relation(s)"
        )

    def test_given_udr_charm_in_active_status_when_sdcore_config_relation_breaks_then_status_is_blocked(  # noqa: E501
        self,
        add_storage,
        create_auth_database_relation_and_populate_data,
        create_common_database_relation_and_populate_data,
        create_nrf_relation_and_set_nrf_url,
        create_nms_relation_and_set_webui_url,
        nms_relation_id,
        certificates_relation_id,
    ):
        self.mock_check_output.return_value = TEST_POD_IP
        self.mock_generate_private_key.return_value = TEST_PRIVATE_KEY
        self.harness.set_can_connect(container=CONTAINER_NAME, val=True)
        root = self.harness.get_filesystem_root(CONTAINER_NAME)
        (root / "support/TLS/udr.csr").write_text(TEST_CSR.decode())
        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = TEST_CERTIFICATE
        provider_certificate.csr = TEST_CSR.decode()
        self.mock_get_assigned_certificates.return_value = [
            provider_certificate,
        ]
        self.harness.evaluate_status()
        assert self.harness.model.unit.status == ActiveStatus()

        self.harness.remove_relation(nms_relation_id)

        self.harness.evaluate_status()
        assert self.harness.model.unit.status == BlockedStatus(
            "Waiting for sdcore-config relation(s)"
        )

    def test_given_relations_created_but_common_database_not_available_when_pebble_ready_then_status_is_waiting(  # noqa: E501
        self,
        create_auth_database_relation_and_populate_data,
        common_database_relation_id,
        nrf_relation_id,
        certificates_relation_id,
        nms_relation_id,
    ):
        self.mock_resource_created.return_value = False

        self.harness.container_pebble_ready(CONTAINER_NAME)

        self.harness.evaluate_status()
        assert self.harness.model.unit.status == WaitingStatus(
            "Waiting for the common database to be available"
        )

    def test_given_common_database_url_not_available_when_pebble_ready_then_status_is_waiting(
        self,
        create_auth_database_relation_and_populate_data,
        common_database_relation_id,
        nrf_relation_id,
        certificates_relation_id,
        nms_relation_id,
    ):
        self.mock_resource_created.return_value = True

        self.harness.container_pebble_ready(CONTAINER_NAME)

        self.harness.evaluate_status()
        assert self.harness.model.unit.status == WaitingStatus(
            "Waiting for the common database url to be available"
        )

    def test_given_nrf_data_not_available_when_pebble_ready_then_status_is_waiting(
        self,
        create_auth_database_relation_and_populate_data,
        create_common_database_relation_and_populate_data,
        nrf_relation_id,
        certificates_relation_id,
        nms_relation_id,
    ):
        self.harness.container_pebble_ready(CONTAINER_NAME)

        self.harness.evaluate_status()
        assert self.harness.model.unit.status == WaitingStatus(
            "Waiting for the NRF to be available"
        )

    def test_given_webui_url_not_available_when_pebble_ready_then_status_is_waiting(
        self,
        create_auth_database_relation_and_populate_data,
        create_common_database_relation_and_populate_data,
        create_nrf_relation_and_set_nrf_url,
        certificates_relation_id,
        nms_relation_id,
    ):
        self.harness.container_pebble_ready(CONTAINER_NAME)

        self.harness.evaluate_status()
        assert self.harness.model.unit.status == WaitingStatus(
            "Waiting for Webui URL to be available"
        )

    def test_given_relations_created_and_database_available_and_nrf_available_and_webui_available_but_certificate_not_stored_when_pebble_ready_then_then_status_is_waiting(  # noqa: E501
        self,
        add_storage,
        create_auth_database_relation_and_populate_data,
        create_common_database_relation_and_populate_data,
        create_nrf_relation_and_set_nrf_url,
        create_nms_relation_and_set_webui_url,
        certificates_relation_id,
    ):
        self.mock_check_output.return_value = TEST_POD_IP
        self.mock_generate_private_key.return_value = TEST_PRIVATE_KEY
        self.mock_generate_csr.return_value = TEST_CSR

        self.harness.container_pebble_ready(CONTAINER_NAME)

        self.harness.evaluate_status()
        assert self.harness.model.unit.status == WaitingStatus(
            "Waiting for certificates to be stored"
        )

    def test_given_udr_is_ready_to_be_configured_when_pebble_ready_then_status_is_active(
        self,
        add_storage,
        create_auth_database_relation_and_populate_data,
        create_common_database_relation_and_populate_data,
        create_nrf_relation_and_set_nrf_url,
        create_nms_relation_and_set_webui_url,
        certificates_relation_id,
    ):
        self.mock_check_output.return_value = TEST_POD_IP
        self.mock_generate_private_key.return_value = TEST_PRIVATE_KEY
        self.harness.set_can_connect(container=CONTAINER_NAME, val=True)
        root = self.harness.get_filesystem_root(CONTAINER_NAME)
        (root / "support/TLS/udr.csr").write_text(TEST_CSR.decode())
        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = TEST_CERTIFICATE
        provider_certificate.csr = TEST_CSR.decode()
        self.mock_get_assigned_certificates.return_value = [
            provider_certificate,
        ]

        self.harness.container_pebble_ready(CONTAINER_NAME)

        self.harness.evaluate_status()
        assert self.harness.model.unit.status == ActiveStatus()

    def test_given_ip_not_available_when_pebble_ready_then_status_is_waiting(
        self,
        add_storage,
        create_auth_database_relation_and_populate_data,
        create_common_database_relation_and_populate_data,
        create_nrf_relation_and_set_nrf_url,
        create_nms_relation_and_set_webui_url,
        certificates_relation_id,
    ):
        self.harness.container_pebble_ready(CONTAINER_NAME)

        self.harness.evaluate_status()
        assert self.harness.model.unit.status == WaitingStatus(
            "Waiting for pod IP address to be available"
        )

    def test_given_called_process_error_thrown_while_fetching_pod_ip_when_pebble_ready_then_status_is_waiting(  # noqa: E501
        self,
        add_storage,
        create_auth_database_relation_and_populate_data,
        create_common_database_relation_and_populate_data,
        create_nrf_relation_and_set_nrf_url,
        create_nms_relation_and_set_webui_url,
        certificates_relation_id,
    ):
        self.mock_check_output.side_effect = CalledProcessError(cmd="", returncode=123)

        self.harness.container_pebble_ready(CONTAINER_NAME)

        self.harness.evaluate_status()
        assert self.harness.model.unit.status == WaitingStatus(
            "Waiting for pod IP address to be available"
        )

    def test_given_no_workload_version_file_when_container_can_connect_then_workload_version_not_set(  # noqa: E501
        self,
        create_auth_database_relation_and_populate_data,
        create_common_database_relation_and_populate_data,
        create_nrf_relation_and_set_nrf_url,
        create_nms_relation_and_set_webui_url,
        nrf_relation_id,
        certificates_relation_id,
    ):
        self.harness.container_pebble_ready(container_name=CONTAINER_NAME)
        self.harness.evaluate_status()
        version = self.harness.get_workload_version()
        assert version == ""

    def test_given_workload_version_file_when_container_can_connect_then_workload_version_set(
        self,
        create_auth_database_relation_and_populate_data,
        create_common_database_relation_and_populate_data,
        create_nrf_relation_and_set_nrf_url,
        create_nms_relation_and_set_webui_url,
        nrf_relation_id,
        certificates_relation_id,
    ):
        expected_version = "1.2.3"
        root = self.harness.get_filesystem_root(CONTAINER_NAME)
        os.mkdir(f"{root}/etc")
        (root / "etc/workload-version").write_text(expected_version)
        self.harness.container_pebble_ready(container_name=CONTAINER_NAME)
        self.harness.evaluate_status()
        version = self.harness.get_workload_version()
        assert version == expected_version

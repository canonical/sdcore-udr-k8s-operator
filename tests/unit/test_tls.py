# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

from unittest.mock import Mock

import pytest
from ops import ActiveStatus

from lib.charms.tls_certificates_interface.v3.tls_certificates import ProviderCertificate
from tests.unit.fixtures import UDRUnitTestFixtures

CONTAINER_NAME = "udr"
TEST_POD_IP = b"1.2.3.4"
TEST_CSR = b"whatever csr"
TEST_PRIVATE_KEY = b"whatever private key"
TEST_CERTIFICATE = "whatever certificate"


class TestTLS(UDRUnitTestFixtures):
    def test_given_can_connect_when_on_update_status_then_private_key_is_generated(
        self,
        add_storage,
        create_auth_database_relation_and_populate_data,
        create_common_database_relation_and_populate_data,
        create_nrf_relation_and_set_nrf_url,
        create_nms_relation_and_set_webui_url,
        certificates_relation_id,
    ):
        self.harness.set_can_connect(container=CONTAINER_NAME, val=True)
        self.mock_check_output.return_value = TEST_POD_IP
        self.mock_generate_private_key.return_value = TEST_PRIVATE_KEY
        self.mock_generate_csr.return_value = TEST_CSR
        root = self.harness.get_filesystem_root(CONTAINER_NAME)

        self.harness.charm.on.update_status.emit()

        assert (root / "support/TLS/udr.key").read_text() == TEST_PRIVATE_KEY.decode()

    def test_given_certificates_are_stored_when_on_certificates_relation_broken_then_certificates_are_removed(  # noqa: E501
        self,
        add_storage,
        create_auth_database_relation_and_populate_data,
        create_common_database_relation_and_populate_data,
        create_nrf_relation_and_set_nrf_url,
        create_nms_relation_and_set_webui_url,
        certificates_relation_id,
    ):
        self.harness.set_can_connect(container=CONTAINER_NAME, val=True)
        self.mock_check_output.return_value = TEST_POD_IP
        self.mock_generate_private_key.return_value = TEST_PRIVATE_KEY
        self.mock_generate_csr.return_value = TEST_CSR
        self.mock_get_assigned_certificates.return_value = TEST_CERTIFICATE
        root = self.harness.get_filesystem_root(CONTAINER_NAME)
        self.harness.evaluate_status()
        assert self.harness.model.unit.status == ActiveStatus()

        self.harness.charm._on_certificates_relation_broken(event=Mock)

        with pytest.raises(FileNotFoundError):
            (root / "support/TLS/udr.key").read_text()
        with pytest.raises(FileNotFoundError):
            (root / "support/TLS/udr.pem").read_text()
        with pytest.raises(FileNotFoundError):
            (root / "support/TLS/udr.csr").read_text()

    def test_given_private_key_exists_when_on_certificates_relation_joined_then_csr_is_generated(
        self,
        add_storage,
        create_auth_database_relation_and_populate_data,
        create_common_database_relation_and_populate_data,
        create_nrf_relation_and_set_nrf_url,
        create_nms_relation_and_set_webui_url,
        certificates_relation_id,
    ):
        self.harness.set_can_connect(container=CONTAINER_NAME, val=True)
        self.mock_check_output.return_value = TEST_POD_IP
        self.mock_generate_private_key.return_value = TEST_PRIVATE_KEY
        self.mock_generate_csr.return_value = TEST_CSR
        root = self.harness.get_filesystem_root(CONTAINER_NAME)

        relation = Mock()
        relation.name = "certificates"
        relation.id = certificates_relation_id
        self.harness.charm.on.certificates_relation_joined.emit(relation=relation)

        assert (root / "support/TLS/udr.csr").read_text() == TEST_CSR.decode()

    def test_given_private_key_exists_and_cert_not_yet_requested_when_on_certificates_relation_joined_then_cert_is_requested(  # noqa: E501
        self,
        add_storage,
        create_auth_database_relation_and_populate_data,
        create_common_database_relation_and_populate_data,
        create_nrf_relation_and_set_nrf_url,
        create_nms_relation_and_set_webui_url,
        certificates_relation_id,
    ):
        self.harness.set_can_connect(container=CONTAINER_NAME, val=True)
        self.mock_check_output.return_value = TEST_POD_IP
        self.mock_generate_private_key.return_value = TEST_PRIVATE_KEY
        self.mock_generate_csr.return_value = TEST_CSR

        relation = Mock()
        relation.name = "certificates"
        relation.id = certificates_relation_id
        self.harness.charm.on.certificates_relation_joined.emit(relation=relation)

        self.mock_request_certificate_creation.assert_called_with(
            certificate_signing_request=TEST_CSR
        )

    def test_given_cert_already_stored_when_on_certificates_relation_joined_then_cert_is_not_requested(  # noqa: E501
        self,
        add_storage,
        create_auth_database_relation_and_populate_data,
        create_common_database_relation_and_populate_data,
        create_nrf_relation_and_set_nrf_url,
        create_nms_relation_and_set_webui_url,
        certificates_relation_id,
    ):
        self.harness.set_can_connect(container=CONTAINER_NAME, val=True)
        self.mock_check_output.return_value = TEST_POD_IP
        root = self.harness.get_filesystem_root(CONTAINER_NAME)
        (root / "support/TLS/udr.csr").write_text(TEST_CSR.decode())
        (root / "support/TLS/udr.key").write_text(TEST_PRIVATE_KEY.decode())
        (root / "support/TLS/udr.pem").write_text(TEST_CERTIFICATE)

        relation = Mock()
        relation.name = "certificates"
        relation.id = certificates_relation_id
        self.harness.charm.on.certificates_relation_joined.emit(relation=relation)

        self.mock_request_certificate_creation.assert_not_called()

    def test_given_csr_matches_stored_one_when_pebble_ready_then_certificate_is_pushed(
        self,
        add_storage,
        create_auth_database_relation_and_populate_data,
        create_common_database_relation_and_populate_data,
        create_nrf_relation_and_set_nrf_url,
        create_nms_relation_and_set_webui_url,
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

        self.harness.container_pebble_ready(CONTAINER_NAME)

        assert (root / "support/TLS/udr.pem").read_text() == TEST_CERTIFICATE

    def test_given_csr_doesnt_match_stored_one_when_certificate_available_then_certificate_is_not_pushed(  # noqa: E501
        self,
        add_storage,
        create_auth_database_relation_and_populate_data,
        create_common_database_relation_and_populate_data,
        create_nrf_relation_and_set_nrf_url,
        create_nms_relation_and_set_webui_url,
        certificates_relation_id,
    ):
        self.harness.set_can_connect(container=CONTAINER_NAME, val=True)
        self.mock_check_output.return_value = TEST_POD_IP
        root = self.harness.get_filesystem_root(CONTAINER_NAME)
        (root / "support/TLS/udr.csr").write_text(TEST_CSR.decode())
        (root / "support/TLS/udr.key").write_text(TEST_PRIVATE_KEY.decode())
        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = TEST_CERTIFICATE
        provider_certificate.csr = "different csr"
        self.mock_get_assigned_certificates.return_value = [
            provider_certificate,
        ]

        self.harness.container_pebble_ready(CONTAINER_NAME)

        with pytest.raises(FileNotFoundError):
            (root / "support/TLS/udr.pem").read_text()

    def test_given_certificate_does_not_match_stored_one_when_certificate_expiring_then_certificate_is_not_requested(  # noqa: E501
        self,
        add_storage,
        create_auth_database_relation_and_populate_data,
        create_common_database_relation_and_populate_data,
        create_nrf_relation_and_set_nrf_url,
        create_nms_relation_and_set_webui_url,
        certificates_relation_id,
    ):
        self.harness.set_can_connect(container=CONTAINER_NAME, val=True)
        self.mock_check_output.return_value = TEST_POD_IP
        root = self.harness.get_filesystem_root(CONTAINER_NAME)
        self.mock_generate_private_key.return_value = TEST_PRIVATE_KEY
        self.mock_generate_csr.return_value = TEST_CSR
        (root / "support/TLS/udr.pem").write_text(TEST_CERTIFICATE)

        event = Mock()
        event.certificate = "Relation certificate content (different from stored)"

        self.harness.charm._on_certificate_expiring(event=event)

        self.mock_request_certificate_creation.assert_not_called()

    def test_given_certificate_matches_stored_one_when_certificate_expiring_then_certificate_is_requested(  # noqa: E501
        self,
        add_storage,
        create_auth_database_relation_and_populate_data,
        create_common_database_relation_and_populate_data,
        create_nrf_relation_and_set_nrf_url,
        create_nms_relation_and_set_webui_url,
        certificates_relation_id,
    ):
        self.harness.set_can_connect(container=CONTAINER_NAME, val=True)
        self.mock_check_output.return_value = TEST_POD_IP
        root = self.harness.get_filesystem_root(CONTAINER_NAME)
        (root / "support/TLS/udr.key").write_text(TEST_PRIVATE_KEY.decode())
        self.mock_generate_csr.return_value = TEST_CSR
        (root / "support/TLS/udr.pem").write_text(TEST_CERTIFICATE)

        event = Mock()
        event.certificate = TEST_CERTIFICATE

        self.harness.charm._on_certificate_expiring(event=event)

        self.mock_request_certificate_creation.assert_called_with(
            certificate_signing_request=TEST_CSR
        )

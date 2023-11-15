# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import unittest
from io import StringIO
from unittest.mock import Mock, PropertyMock, patch

from ops import testing
from ops.model import ActiveStatus, BlockedStatus, WaitingStatus

from charm import UDROperatorCharm

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
    @patch("charm.KubernetesServicePatch", lambda charm, ports: None)
    def setUp(self):
        self.namespace = "whatever"
        self.harness = testing.Harness(UDROperatorCharm)
        self.harness.set_model_name(name=self.namespace)
        self.addCleanup(self.harness.cleanup)
        self.harness.set_leader(is_leader=True)
        self.harness.begin()
        self._container = self.harness.model.unit.get_container("udr")

    def _database_is_available(self):
        database_relation_id = self.harness.add_relation("database", "mongodb")
        self.harness.add_relation_unit(
            relation_id=database_relation_id, remote_unit_name="mongodb/0"
        )
        self.harness.update_relation_data(
            relation_id=database_relation_id,
            app_or_unit="mongodb",
            key_values={
                "username": "dummy",
                "password": "dummy",
                "uris": "http://dummy",
            },
        )

    def test_given_database_relation_not_created_when_pebble_ready_then_status_is_blocked(self):
        self.harness.add_relation(relation_name="fiveg_nrf", remote_app="some_nrf_app")
        self.harness.container_pebble_ready("udr")
        self.assertEqual(
            self.harness.model.unit.status,
            BlockedStatus("Waiting for the `database` relation to be created"),
        )

    def test_given_fiveg_nrf_relation_not_created_when_pebble_ready_then_status_is_blocked(self):
        self.harness.add_relation(relation_name="database", remote_app="some_db_app")
        self.harness.container_pebble_ready("udr")
        self.assertEqual(
            self.harness.model.unit.status,
            BlockedStatus("Waiting for the `fiveg_nrf` relation to be created"),
        )

    def test_given_certificates_relation_not_created_when_pebble_ready_then_status_is_blocked(
        self,
    ):
        self.harness.add_relation(relation_name="database", remote_app="some_db_app")
        self.harness.add_relation(relation_name="fiveg_nrf", remote_app="some_nrf_app")
        self.harness.container_pebble_ready("udr")
        self.assertEqual(
            self.harness.model.unit.status,
            BlockedStatus("Waiting for the `certificates` relation to be created"),
        )

    @patch("charm.check_output")
    @patch("ops.model.Container.exists")
    @patch("charms.sdcore_nrf.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    @patch("charms.data_platform_libs.v0.data_interfaces.DatabaseRequires.is_resource_created")
    def test_given_udr_charm_in_active_status_when_nrf_relation_breaks_then_status_is_blocked(
        self, patched_is_resource_created, patched_nrf_url, patched_exists, patched_check_output
    ):
        patched_exists.return_value = True
        patched_check_output.return_value = "1.2.3.4".encode()
        patched_is_resource_created.return_value = True
        patched_nrf_url.return_value = "http://nrf:8081"
        nrf_relation_id = self.harness.add_relation(
            relation_name="fiveg_nrf", remote_app="some_nrf_app"
        )
        self._database_is_available()
        self.harness.container_pebble_ready("udr")

        self.harness.remove_relation(nrf_relation_id)

        self.assertEqual(
            self.harness.model.unit.status,
            BlockedStatus("Waiting for fiveg_nrf relation"),
        )

    def test_given_relations_created_but_database_not_available_when_pebble_ready_then_status_is_waiting(  # noqa: E501
        self,
    ):
        self.harness.add_relation(relation_name="database", remote_app="some_db_app")
        self.harness.add_relation(relation_name="fiveg_nrf", remote_app="some_nrf_app")
        self.harness.add_relation(
            relation_name="certificates", remote_app="tls-certificates-operator"
        )
        self.harness.container_pebble_ready("udr")
        self.assertEqual(
            self.harness.model.unit.status,
            WaitingStatus("Waiting for the database to be available"),
        )

    @patch("charms.data_platform_libs.v0.data_interfaces.DatabaseRequires.is_resource_created")
    def test_give_database_info_not_available_when_pebble_ready_then_status_is_waiting(
        self, patched_is_resource_created
    ):
        patched_is_resource_created.return_value = True
        self.harness.add_relation(relation_name="database", remote_app="some_db_app")
        self.harness.add_relation(relation_name="fiveg_nrf", remote_app="some_nrf_app")
        self.harness.add_relation(
            relation_name="certificates", remote_app="tls-certificates-operator"
        )
        self.harness.container_pebble_ready("udr")
        self.assertEqual(
            self.harness.model.unit.status,
            WaitingStatus("Waiting for the database data to be available"),
        )

    @patch("charms.data_platform_libs.v0.data_interfaces.DatabaseRequires.is_resource_created")
    def test_given_nrf_data_not_available_when_pebble_ready_then_status_is_waiting(
        self, patched_is_resource_created
    ):
        patched_is_resource_created.return_value = True
        self.harness.add_relation(relation_name="fiveg_nrf", remote_app="some_nrf_app")
        self._database_is_available()
        self.harness.add_relation(
            relation_name="certificates", remote_app="tls-certificates-operator"
        )
        self.harness.container_pebble_ready("udr")
        self.assertEqual(
            self.harness.model.unit.status, WaitingStatus("Waiting for the NRF to be available")
        )

    @patch("charms.sdcore_nrf.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    @patch("charms.data_platform_libs.v0.data_interfaces.DatabaseRequires.is_resource_created")
    def test_given_relations_created_and_database_available_and_nrf_available_but_storage_not_attached_when_pebble_ready_then_then_status_is_waiting(  # noqa: E501
        self, patched_is_resource_created, patched_nrf_url
    ):
        patched_is_resource_created.return_value = True
        patched_nrf_url.return_value = "http://nrf:8081"
        self.harness.add_relation(relation_name="fiveg_nrf", remote_app="some_nrf_app")
        self._database_is_available()
        self.harness.add_relation(
            relation_name="certificates", remote_app="tls-certificates-operator"
        )
        self.harness.container_pebble_ready("udr")
        self.assertEqual(
            self.harness.model.unit.status, WaitingStatus("Waiting for the storage to be attached")
        )

    @patch("charm.check_output")
    @patch("ops.Container.push")
    @patch("charms.sdcore_nrf.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    @patch("charms.data_platform_libs.v0.data_interfaces.DatabaseRequires.is_resource_created")
    def test_given_relations_created_and_database_available_and_nrf_available_but_certificate_not_stored_when_pebble_ready_then_then_status_is_waiting(  # noqa: E501
        self,
        patched_is_resource_created,
        patched_nrf_url,
        _,
        patched_check_output,
    ):
        patched_check_output.return_value = "1.2.3.4".encode()
        patched_is_resource_created.return_value = True
        self.harness.charm._storage_is_attached = Mock(return_value=True)
        patched_nrf_url.return_value = "http://nrf:8081"
        self.harness.add_relation(relation_name="fiveg_nrf", remote_app="some_nrf_app")
        self._database_is_available()
        self.harness.add_relation(
            relation_name="certificates", remote_app="tls-certificates-operator"
        )
        self.harness.container_pebble_ready("udr")
        self.assertEqual(
            self.harness.model.unit.status, WaitingStatus("Waiting for certificates to be stored")
        )

    @patch("ops.model.Container.push")
    @patch("charm.check_output")
    @patch("ops.model.Container.exists")
    @patch("charms.sdcore_nrf.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    @patch("charms.data_platform_libs.v0.data_interfaces.DatabaseRequires.is_resource_created")
    def test_given_udr_operator_ready_to_be_configured_when_pebble_ready_then_config_file_is_rendered_and_pushed(  # noqa: E501
        self,
        patched_is_resource_created,
        patched_nrf_url,
        patched_exists,
        patched_check_output,
        patched_push,
    ):
        patched_exists.side_effect = [True, True, True, False]
        patched_check_output.return_value = "1.2.3.4".encode()
        patched_is_resource_created.return_value = True
        patched_nrf_url.return_value = "http://nrf:8081"
        self.harness.add_relation(relation_name="fiveg_nrf", remote_app="some_nrf_app")
        self._database_is_available()
        self.harness.add_relation(
            relation_name="certificates", remote_app="tls-certificates-operator"
        )

        self.harness.container_pebble_ready("udr")

        with open("tests/unit/resources/expected_udrcfg.yaml") as expected_config_file:
            expected_content = expected_config_file.read()
            patched_push.assert_called_with(
                path="/free5gc/config/udrcfg.yaml",
                source=expected_content,
                make_dirs=True,
            )

    @patch("ops.model.Container.push")
    @patch("ops.model.Container.pull")
    @patch("charm.check_output")
    @patch("ops.model.Container.exists")
    @patch("charms.sdcore_nrf.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    @patch("charms.data_platform_libs.v0.data_interfaces.DatabaseRequires.is_resource_created")
    def test_given_udr_config_is_different_from_the_newly_generated_config_when_pebble_ready_then_new_config_file_is_pushed(  # noqa: E501
        self,
        patched_is_resource_created,
        patched_nrf_url,
        patched_exists,
        patched_check_output,
        patched_pull,
        patched_push,
    ):
        patched_exists.side_effect = [True, True, True, False]
        patched_check_output.return_value = "1.2.3.4".encode()
        patched_pull.return_value = StringIO("Dummy content")
        patched_is_resource_created.return_value = True
        patched_nrf_url.return_value = "http://nrf:8081"
        self.harness.add_relation(relation_name="fiveg_nrf", remote_app="some_nrf_app")
        self._database_is_available()
        self.harness.add_relation(
            relation_name="certificates", remote_app="tls-certificates-operator"
        )

        self.harness.container_pebble_ready("udr")

        with open("tests/unit/resources/expected_udrcfg.yaml") as expected_config_file:
            expected_content = expected_config_file.read()
            patched_push.assert_called_with(
                path="/free5gc/config/udrcfg.yaml",
                source=expected_content,
                make_dirs=True,
            )

    @patch("ops.model.Container.push")
    @patch("ops.model.Container.pull")
    @patch("charm.check_output")
    @patch("ops.model.Container.exists")
    @patch("charms.sdcore_nrf.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    @patch("charms.data_platform_libs.v0.data_interfaces.DatabaseRequires.is_resource_created")
    def test_given_udr_config_is_the_same_as_the_newly_generated_config_when_pebble_ready_then_new_config_file_is_not_pushed(  # noqa: E501
        self,
        patched_is_resource_created,
        patched_nrf_url,
        patched_exists,
        patched_check_output,
        patched_pull,
        patched_push,
    ):
        patched_exists.side_effect = [True, False]
        patched_check_output.return_value = "1.2.3.4".encode()
        patched_is_resource_created.return_value = True
        patched_nrf_url.return_value = "http://nrf:8081"
        self.harness.add_relation(relation_name="fiveg_nrf", remote_app="some_nrf_app")
        self._database_is_available()

        with open("tests/unit/resources/expected_udrcfg.yaml") as expected_config_file:
            expected_content = expected_config_file.read()
            patched_pull.return_value = StringIO(expected_content)
            self.harness.container_pebble_ready("udr")

        patched_push.assert_not_called()

    @patch("ops.model.Container.restart")
    @patch("ops.model.Container.pull")
    @patch("charm.check_output")
    @patch("ops.model.Container.exists")
    @patch("charms.sdcore_nrf.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    @patch("charms.data_platform_libs.v0.data_interfaces.DatabaseRequires.is_resource_created")
    def test_given_udr_service_already_configured_and_udr_config_is_different_from_the_newly_generated_config_when_pebble_ready_then_udr_service_is_restarted(  # noqa: E501
        self,
        patched_is_resource_created,
        patched_nrf_url,
        patched_exists,
        patched_check_output,
        patched_pull,
        patched_restart,
    ):
        patched_exists.return_value = True
        patched_check_output.return_value = "1.2.3.4".encode()
        patched_pull.return_value = StringIO("Dummy content")
        patched_is_resource_created.return_value = True
        patched_nrf_url.return_value = "http://nrf:8081"
        self.harness.add_relation(relation_name="fiveg_nrf", remote_app="some_nrf_app")
        self._database_is_available()
        self.harness.add_relation(
            relation_name="certificates", remote_app="tls-certificates-operator"
        )
        self.harness.set_can_connect(container="udr", val=True)
        self._container.add_layer("udr", TEST_PEBBLE_LAYER, combine=True)

        self.harness.container_pebble_ready("udr")

        patched_restart.assert_called_once_with("udr")

    @patch("ops.model.Container.restart")
    @patch("ops.model.Container.pull")
    @patch("charm.check_output")
    @patch("ops.model.Container.exists")
    @patch("charms.sdcore_nrf.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    @patch("charms.data_platform_libs.v0.data_interfaces.DatabaseRequires.is_resource_created")
    def test_given_udr_service_already_configured_and_udr_config_is_the_same_as_the_newly_generated_config_when_pebble_ready_then_udr_service_is_not_restarted(  # noqa: E501
        self,
        patched_is_resource_created,
        patched_nrf_url,
        patched_exists,
        patched_check_output,
        patched_pull,
        patched_restart,
    ):
        patched_exists.side_effect = [True, False]
        patched_check_output.return_value = "1.2.3.4".encode()
        patched_is_resource_created.return_value = True
        patched_nrf_url.return_value = "http://nrf:8081"
        self.harness.add_relation(relation_name="fiveg_nrf", remote_app="some_nrf_app")
        self._database_is_available()

        with open("tests/unit/resources/expected_udrcfg.yaml") as expected_config_file:
            expected_content = expected_config_file.read()
            patched_pull.return_value = StringIO(expected_content)
            self.harness.set_can_connect(container="udr", val=True)
            self._container.add_layer("udr", TEST_PEBBLE_LAYER, combine=True)
            self.harness.container_pebble_ready("udr")

        patched_restart.assert_not_called()

    @patch("charm.check_output")
    @patch("ops.model.Container.exists")
    @patch("charms.sdcore_nrf.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    @patch("charms.data_platform_libs.v0.data_interfaces.DatabaseRequires.is_resource_created")
    def test_given_udr_config_is_pushed_when_pebble_ready_then_udr_service_is_configured_in_the_pebble(  # noqa: E501
        self,
        patched_is_resource_created,
        patched_nrf_url,
        patched_exists,
        patched_check_output,
    ):
        patched_exists.return_value = True
        patched_check_output.return_value = "1.2.3.4".encode()
        patched_is_resource_created.return_value = True
        patched_nrf_url.return_value = "http://nrf:8081"
        self.harness.add_relation(relation_name="fiveg_nrf", remote_app="some_nrf_app")
        self._database_is_available()
        self.harness.add_relation(
            relation_name="certificates", remote_app="tls-certificates-operator"
        )

        self.harness.container_pebble_ready("udr")

        updated_plan = self.harness.get_container_pebble_plan("udr").to_dict()
        self.assertEqual(TEST_PEBBLE_LAYER, updated_plan)

    @patch("ops.model.Container.restart")
    @patch("charm.check_output")
    @patch("ops.model.Container.exists")
    @patch("charms.sdcore_nrf.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    @patch("charms.data_platform_libs.v0.data_interfaces.DatabaseRequires.is_resource_created")
    def test_given_udr_config_is_pushed_when_pebble_ready_then_udr_service_is_restarted(
        self,
        patched_is_resource_created,
        patched_nrf_url,
        patched_exists,
        patched_check_output,
        patched_restart,
    ):
        patched_exists.return_value = True
        patched_check_output.return_value = "1.2.3.4".encode()
        patched_is_resource_created.return_value = True
        patched_nrf_url.return_value = "http://nrf:8081"
        self.harness.add_relation(relation_name="fiveg_nrf", remote_app="some_nrf_app")
        self._database_is_available()
        self.harness.add_relation(
            relation_name="certificates", remote_app="tls-certificates-operator"
        )
        self.harness.container_pebble_ready("udr")
        patched_restart.assert_called_once_with("udr")

    @patch("charm.check_output")
    @patch("ops.model.Container.exists")
    @patch("charms.sdcore_nrf.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    @patch("charms.data_platform_libs.v0.data_interfaces.DatabaseRequires.is_resource_created")
    def test_given_udr_config_is_pushed_when_pebble_ready_then_status_is_active(
        self,
        patched_is_resource_created,
        patched_nrf_url,
        patched_exists,
        patched_check_output,
    ):
        patched_exists.return_value = True
        patched_check_output.return_value = "1.2.3.4".encode()
        patched_is_resource_created.return_value = True
        patched_nrf_url.return_value = "http://nrf:8081"
        self.harness.add_relation(relation_name="fiveg_nrf", remote_app="some_nrf_app")
        self._database_is_available()
        self.harness.add_relation(
            relation_name="certificates", remote_app="tls-certificates-operator"
        )
        self.harness.container_pebble_ready("udr")
        self.assertEqual(
            self.harness.model.unit.status,
            ActiveStatus(),
        )

    @patch("charm.check_output")
    @patch("ops.model.Container.exists")
    @patch("charms.sdcore_nrf.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    @patch("charms.data_platform_libs.v0.data_interfaces.DatabaseRequires.is_resource_created")
    def test_given_ip_not_available_when_pebble_ready_then_status_is_waiting(
        self,
        patched_is_resource_created,
        patched_nrf_url,
        patched_exists,
        patched_check_output,
    ):
        patched_exists.return_value = True
        patched_check_output.return_value = "".encode()
        patched_is_resource_created.return_value = True
        patched_nrf_url.return_value = "http://nrf:8081"
        self.harness.add_relation(relation_name="fiveg_nrf", remote_app="some_nrf_app")
        self._database_is_available()
        self.harness.add_relation(
            relation_name="certificates", remote_app="tls-certificates-operator"
        )

        self.harness.container_pebble_ready("udr")

        self.assertEqual(
            self.harness.model.unit.status,
            WaitingStatus("Waiting for pod IP address to be available"),
        )

    @patch("charm.generate_private_key")
    @patch("ops.model.Container.push")
    def test_given_can_connect_when_on_certificates_relation_created_then_private_key_is_generated(
        self, patch_push, patch_generate_private_key
    ):
        private_key = b"whatever key content"
        self.harness.set_can_connect(container="udr", val=True)
        patch_generate_private_key.return_value = private_key

        self.harness.charm._on_certificates_relation_created(event=Mock)

        patch_push.assert_called_with(path="/support/TLS/udr.key", source=private_key.decode())

    @patch("ops.model.Container.remove_path")
    @patch("ops.model.Container.exists")
    def test_given_certificates_are_stored_when_on_certificates_relation_broken_then_certificates_are_removed(  # noqa: E501
        self, patch_exists, patch_remove_path
    ):
        patch_exists.return_value = True
        self.harness.set_can_connect(container="udr", val=True)

        self.harness.charm._on_certificates_relation_broken(event=Mock)

        patch_remove_path.assert_any_call(path="/support/TLS/udr.pem")
        patch_remove_path.assert_any_call(path="/support/TLS/udr.key")
        patch_remove_path.assert_any_call(path="/support/TLS/udr.csr")

    @patch(
        "charms.tls_certificates_interface.v2.tls_certificates.TLSCertificatesRequiresV2.request_certificate_creation",  # noqa: E501
        new=Mock,
    )
    @patch("ops.model.Container.push")
    @patch("charm.generate_csr")
    @patch("ops.model.Container.pull")
    @patch("ops.model.Container.exists")
    def test_given_private_key_exists_when_on_certificates_relation_joined_then_csr_is_generated(
        self, patch_exists, patch_pull, patch_generate_csr, patch_push
    ):
        csr = b"whatever csr content"
        patch_generate_csr.return_value = csr
        patch_pull.return_value = StringIO("private key content")
        patch_exists.side_effect = [True, False]
        self.harness.set_can_connect(container="udr", val=True)

        self.harness.charm._on_certificates_relation_joined(event=Mock)

        patch_push.assert_called_with(path="/support/TLS/udr.csr", source=csr.decode())

    @patch(
        "charms.tls_certificates_interface.v2.tls_certificates.TLSCertificatesRequiresV2.request_certificate_creation",  # noqa: E501
    )
    @patch("ops.model.Container.push", new=Mock)
    @patch("charm.generate_csr")
    @patch("ops.model.Container.pull")
    @patch("ops.model.Container.exists")
    def test_given_private_key_exists_and_cert_not_yet_requested_when_on_certificates_relation_joined_then_cert_is_requested(  # noqa: E501
        self,
        patch_exists,
        patch_pull,
        patch_generate_csr,
        patch_request_certificate_creation,
    ):
        csr = b"whatever csr content"
        patch_generate_csr.return_value = csr
        patch_pull.return_value = StringIO("private key content")
        patch_exists.side_effect = [True, False]
        self.harness.set_can_connect(container="udr", val=True)

        self.harness.charm._on_certificates_relation_joined(event=Mock)

        patch_request_certificate_creation.assert_called_with(certificate_signing_request=csr)

    @patch(
        "charms.tls_certificates_interface.v2.tls_certificates.TLSCertificatesRequiresV2.request_certificate_creation",  # noqa: E501
    )
    @patch("ops.model.Container.push", new=Mock)
    @patch("ops.model.Container.pull")
    @patch("ops.model.Container.exists")
    def test_given_cert_already_stored_when_on_certificates_relation_joined_then_cert_is_not_requested(  # noqa: E501
        self,
        patch_exists,
        patch_pull,
        patch_request_certificate_creation,
    ):
        patch_pull.return_value = StringIO("private key content")
        patch_exists.return_value = True
        self.harness.set_can_connect(container="udr", val=True)

        self.harness.charm._on_certificates_relation_joined(event=Mock)

        patch_request_certificate_creation.assert_not_called

    @patch("ops.model.Container.pull")
    @patch("ops.model.Container.exists")
    @patch("ops.model.Container.push")
    def test_given_csr_matches_stored_one_when_certificate_available_then_certificate_is_pushed(
        self,
        patch_push,
        patch_exists,
        patch_pull,
    ):
        csr = "Whatever CSR content"
        patch_pull.return_value = StringIO(csr)
        patch_exists.return_value = True
        certificate = "Whatever certificate content"
        event = Mock()
        event.certificate = certificate
        event.certificate_signing_request = csr
        self.harness.set_can_connect(container="udr", val=True)

        self.harness.charm._on_certificate_available(event=event)

        patch_push.assert_called_with(path="/support/TLS/udr.pem", source=certificate)

    @patch("ops.model.Container.pull")
    @patch("ops.model.Container.exists")
    @patch("ops.model.Container.push")
    def test_given_csr_doesnt_match_stored_one_when_certificate_available_then_certificate_is_not_pushed(  # noqa: E501
        self,
        patch_push,
        patch_exists,
        patch_pull,
    ):
        patch_pull.return_value = StringIO("Stored CSR content")
        patch_exists.return_value = True
        certificate = "Whatever certificate content"
        event = Mock()
        event.certificate = certificate
        event.certificate_signing_request = "Relation CSR content (different from stored one)"
        self.harness.set_can_connect(container="udr", val=True)

        self.harness.charm._on_certificate_available(event=event)

        patch_push.assert_not_called()

    @patch(
        "charms.tls_certificates_interface.v2.tls_certificates.TLSCertificatesRequiresV2.request_certificate_creation",  # noqa: E501
    )
    @patch("ops.model.Container.push", new=Mock)
    @patch("charm.generate_csr")
    @patch("ops.model.Container.pull")
    def test_given_certificate_does_not_match_stored_one_when_certificate_expiring_then_certificate_is_not_requested(  # noqa: E501
        self, patch_pull, patch_generate_csr, patch_request_certificate_creation
    ):
        event = Mock()
        patch_pull.return_value = StringIO("Stored certificate content")
        event.certificate = "Relation certificate content (different from stored)"
        csr = b"whatever csr content"
        patch_generate_csr.return_value = csr
        self.harness.set_can_connect(container="udr", val=True)

        self.harness.charm._on_certificate_expiring(event=event)

        patch_request_certificate_creation.assert_not_called()

    @patch(
        "charms.tls_certificates_interface.v2.tls_certificates.TLSCertificatesRequiresV2.request_certificate_creation",  # noqa: E501
    )
    @patch("ops.model.Container.push", new=Mock)
    @patch("charm.generate_csr")
    @patch("ops.model.Container.pull")
    def test_given_certificate_matches_stored_one_when_certificate_expiring_then_certificate_is_requested(  # noqa: E501
        self, patch_pull, patch_generate_csr, patch_request_certificate_creation
    ):
        certificate = "whatever certificate content"
        event = Mock()
        event.certificate = certificate
        patch_pull.return_value = StringIO(certificate)
        csr = b"whatever csr content"
        patch_generate_csr.return_value = csr
        self.harness.set_can_connect(container="udr", val=True)

        self.harness.charm._on_certificate_expiring(event=event)

        patch_request_certificate_creation.assert_called_with(certificate_signing_request=csr)

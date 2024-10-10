# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.


import tempfile

from ops import testing
from ops.model import ActiveStatus, BlockedStatus, WaitingStatus
from ops.pebble import Layer, ServiceStatus

from tests.unit.certificates_helpers import example_cert_and_key
from tests.unit.fixtures import UDRUnitTestFixtures


class TestCharmCollectStatus(UDRUnitTestFixtures):
    def test_given_not_leader_when_collect_unit_status_then_status_is_blocked(self):
        state_in = testing.State(
            leader=False,
        )

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == BlockedStatus("Scaling is not implemented for this charm")

    def test_given_relations_not_created_when_collect_unit_status_then_status_is_blocked(self):
        container = testing.Container(
            name="udr",
            can_connect=True,
        )
        state_in = testing.State(
            containers=[container],
            leader=True,
        )

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == BlockedStatus(
            "Waiting for common_database, auth_database, fiveg_nrf, certificates, sdcore_config relation(s)"  # noqa: E501
        )

    def test_given_nms_relation_not_created_when_collect_unit_status_then_status_is_blocked(
        self,
    ):
        certificates_relation = testing.Relation(
            endpoint="certificates",
            interface="tls-certificates",
        )
        container = testing.Container(
            name="udr",
            can_connect=True,
        )
        state_in = testing.State(
            containers=[container],
            relations=[certificates_relation],
            leader=True,
        )

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == BlockedStatus(
            "Waiting for common_database, auth_database, fiveg_nrf, sdcore_config relation(s)"
        )

    def test_given_database_relations_not_created_when_collect_unit_status_then_status_is_blocked(
        self,
    ):
        certificates_relation = testing.Relation(
            endpoint="certificates",
            interface="tls-certificates",
        )
        nms_relation = testing.Relation(
            endpoint="sdcore_config",
            interface="sdcore_config",
        )
        nrf_relation = testing.Relation(
            endpoint="fiveg_nrf",
            interface="fiveg_nrf",
        )
        container = testing.Container(
            name="udr",
            can_connect=True,
        )
        state_in = testing.State(
            containers=[container],
            relations=[certificates_relation, nms_relation, nrf_relation],
            leader=True,
        )
        self.mock_nrf_url.return_value = None
        self.mock_sdcore_config_webui_url.return_value = None

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == BlockedStatus(
            "Waiting for common_database, auth_database relation(s)"
        )

    def test_given_database_not_available_when_collect_unit_status_then_status_is_waiting(
        self,
    ):
        certificates_relation = testing.Relation(
            endpoint="certificates",
            interface="tls-certificates",
        )
        nms_relation = testing.Relation(
            endpoint="sdcore_config",
            interface="sdcore_config",
        )
        nrf_relation = testing.Relation(
            endpoint="fiveg_nrf",
            interface="fiveg_nrf",
        )
        common_database = testing.Relation(
            endpoint="common_database",
            interface="mongodb_client",
        )
        auth_database = testing.Relation(
            endpoint="auth_database",
            interface="mongodb_client",
        )
        container = testing.Container(
            name="udr",
            can_connect=True,
        )
        state_in = testing.State(
            containers=[container],
            relations=[
                certificates_relation,
                nms_relation,
                nrf_relation,
                common_database,
                auth_database,
            ],
            leader=True,
        )
        self.mock_nrf_url.return_value = None
        self.mock_sdcore_config_webui_url.return_value = None
        self.mock_db_is_resource_created.return_value = False

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == WaitingStatus(
            "Waiting for the common database to be available"
        )

    def test_given_nrf_data_not_available_when_collect_unit_status_then_status_is_waiting(
        self,
    ):
        certificates_relation = testing.Relation(
            endpoint="certificates",
            interface="tls-certificates",
        )
        nms_relation = testing.Relation(
            endpoint="sdcore_config",
            interface="sdcore_config",
        )
        nrf_relation = testing.Relation(
            endpoint="fiveg_nrf",
            interface="fiveg_nrf",
        )
        common_database = testing.Relation(
            endpoint="common_database",
            interface="mongodb_client",
        )
        auth_database = testing.Relation(
            endpoint="auth_database",
            interface="mongodb_client",
        )
        container = testing.Container(
            name="udr",
            can_connect=True,
        )
        state_in = testing.State(
            containers=[container],
            relations=[
                certificates_relation,
                nms_relation,
                nrf_relation,
                common_database,
                auth_database,
            ],
            leader=True,
        )
        self.mock_nrf_url.return_value = None
        self.mock_sdcore_config_webui_url.return_value = None
        self.mock_db_is_resource_created.return_value = True

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == WaitingStatus("Waiting for the NRF to be available")

    def test_given_webui_url_not_available_when_collect_unit_status_then_status_is_waiting(
        self,
    ):
        certificates_relation = testing.Relation(
            endpoint="certificates",
            interface="tls-certificates",
        )
        nms_relation = testing.Relation(
            endpoint="sdcore_config",
            interface="sdcore_config",
        )
        nrf_relation = testing.Relation(
            endpoint="fiveg_nrf",
            interface="fiveg_nrf",
        )
        common_database = testing.Relation(
            endpoint="common_database",
            interface="mongodb_client",
        )
        auth_database = testing.Relation(
            endpoint="auth_database",
            interface="mongodb_client",
        )
        container = testing.Container(
            name="udr",
            can_connect=True,
        )
        state_in = testing.State(
            containers=[container],
            relations=[
                certificates_relation,
                nms_relation,
                nrf_relation,
                common_database,
                auth_database,
            ],
            leader=True,
        )
        self.mock_nrf_url.return_value = "https://nrf-example.com:1234"
        self.mock_sdcore_config_webui_url.return_value = None
        self.mock_db_is_resource_created.return_value = True

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == WaitingStatus("Waiting for Webui URL to be available")

    def test_given_cant_connect_to_container_when_collect_unit_status_then_status_is_waiting(
        self,
    ):
        certificates_relation = testing.Relation(
            endpoint="certificates",
            interface="tls-certificates",
        )
        nms_relation = testing.Relation(
            endpoint="sdcore_config",
            interface="sdcore_config",
        )
        nrf_relation = testing.Relation(
            endpoint="fiveg_nrf",
            interface="fiveg_nrf",
        )
        common_database = testing.Relation(
            endpoint="common_database",
            interface="mongodb_client",
        )
        auth_database = testing.Relation(
            endpoint="auth_database",
            interface="mongodb_client",
        )
        container = testing.Container(
            name="udr",
            can_connect=False,
        )
        state_in = testing.State(
            containers=[container],
            relations=[
                certificates_relation,
                nms_relation,
                nrf_relation,
                common_database,
                auth_database,
            ],
            leader=True,
        )
        self.mock_nrf_url.return_value = "https://nrf-example.com:1234"
        self.mock_sdcore_config_webui_url.return_value = "some-webui:7890"
        self.mock_db_is_resource_created.return_value = True

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == WaitingStatus("Waiting for the container to be ready")

    def test_given_storage_not_attached_when_collect_unit_status_then_status_is_waiting(
        self,
    ):
        certificates_relation = testing.Relation(
            endpoint="certificates",
            interface="tls-certificates",
        )
        nms_relation = testing.Relation(
            endpoint="sdcore_config",
            interface="sdcore_config",
        )
        nrf_relation = testing.Relation(
            endpoint="fiveg_nrf",
            interface="fiveg_nrf",
        )
        common_database = testing.Relation(
            endpoint="common_database",
            interface="mongodb_client",
        )
        auth_database = testing.Relation(
            endpoint="auth_database",
            interface="mongodb_client",
        )
        container = testing.Container(
            name="udr",
            can_connect=True,
        )
        state_in = testing.State(
            containers=[container],
            relations=[
                certificates_relation,
                nms_relation,
                nrf_relation,
                common_database,
                auth_database,
            ],
            leader=True,
        )
        self.mock_nrf_url.return_value = "https://nrf-example.com:1234"
        self.mock_sdcore_config_webui_url.return_value = "some-webui:7890"
        self.mock_db_is_resource_created.return_value = True

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == WaitingStatus("Waiting for the storage to be attached")

    def test_given_pod_address_unavailable_when_collect_unit_status_then_status_is_waiting(
        self,
    ):
        with tempfile.TemporaryDirectory() as temp_dir:
            certificates_relation = testing.Relation(
                endpoint="certificates",
                interface="tls-certificates",
            )
            nrf_relation = testing.Relation(
                endpoint="fiveg_nrf",
                interface="fiveg_nrf",
            )
            nms_relation = testing.Relation(
                endpoint="sdcore_config",
                interface="sdcore_config",
            )
            common_database = testing.Relation(
                endpoint="common_database",
                interface="mongodb_client",
            )
            auth_database = testing.Relation(
                endpoint="auth_database",
                interface="mongodb_client",
            )
            config_mount = testing.Mount(
                location="/free5gc/config/",
                source=temp_dir,
            )
            certs_mount = testing.Mount(
                location="/support/TLS/",
                source=temp_dir,
            )
            container = testing.Container(
                name="udr",
                can_connect=True,
                mounts={"config": config_mount, "certs": certs_mount},
            )
            state_in = testing.State(
                containers=[container],
                relations=[
                    certificates_relation,
                    nrf_relation,
                    nms_relation,
                    common_database,
                    auth_database,
                ],
                leader=True,
            )
            self.mock_nrf_url.return_value = "https://nrf.url"
            self.mock_sdcore_config_webui_url.return_value = "http://webui.url"
            self.mock_check_output.return_value = b""

            state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

            assert state_out.unit_status == WaitingStatus(
                "Waiting for pod IP address to be available"
            )

    def test_given_certificate_not_stored_when_collect_unit_status_then_status_is_waiting(
        self,
    ):
        with tempfile.TemporaryDirectory() as temp_dir:
            certificates_relation = testing.Relation(
                endpoint="certificates",
                interface="tls-certificates",
            )
            nrf_relation = testing.Relation(
                endpoint="fiveg_nrf",
                interface="fiveg_nrf",
            )
            nms_relation = testing.Relation(
                endpoint="sdcore_config",
                interface="sdcore_config",
            )
            common_database = testing.Relation(
                endpoint="common_database",
                interface="mongodb_client",
            )
            auth_database = testing.Relation(
                endpoint="auth_database",
                interface="mongodb_client",
            )
            config_mount = testing.Mount(
                location="/free5gc/config/",
                source=temp_dir,
            )
            certs_mount = testing.Mount(
                location="/support/TLS/",
                source=temp_dir,
            )
            container = testing.Container(
                name="udr",
                can_connect=True,
                mounts={"config": config_mount, "certs": certs_mount},
            )
            state_in = testing.State(
                containers=[container],
                relations=[
                    certificates_relation,
                    nrf_relation,
                    nms_relation,
                    common_database,
                    auth_database,
                ],
                leader=True,
            )
            self.mock_nrf_url.return_value = "https://nrf.url"
            self.mock_sdcore_config_webui_url.return_value = "http://webui.url"
            self.mock_check_output.return_value = b"1.2.3.4"
            self.mock_get_assigned_certificate.return_value = (None, None)

            state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

            assert state_out.unit_status == WaitingStatus(
                "Waiting for certificates to be available"
            )

    def test_given_udr_service_not_running_when_collect_unit_status_then_status_is_waiting(
        self,
    ):
        with tempfile.TemporaryDirectory() as temp_dir:
            certificates_relation = testing.Relation(
                endpoint="certificates",
                interface="tls-certificates",
            )
            nrf_relation = testing.Relation(
                endpoint="fiveg_nrf",
                interface="fiveg_nrf",
            )
            nms_relation = testing.Relation(
                endpoint="sdcore_config",
                interface="sdcore_config",
            )
            common_database = testing.Relation(
                endpoint="common_database",
                interface="mongodb_client",
            )
            auth_database = testing.Relation(
                endpoint="auth_database",
                interface="mongodb_client",
            )
            config_mount = testing.Mount(
                location="/free5gc/config/",
                source=temp_dir,
            )
            certs_mount = testing.Mount(
                location="/support/TLS/",
                source=temp_dir,
            )
            container = testing.Container(
                name="udr",
                can_connect=True,
                mounts={"config": config_mount, "certs": certs_mount},
            )
            state_in = testing.State(
                containers=[container],
                relations=[
                    certificates_relation,
                    nrf_relation,
                    nms_relation,
                    common_database,
                    auth_database,
                ],
                leader=True,
            )
            self.mock_nrf_url.return_value = "https://nrf.url"
            self.mock_sdcore_config_webui_url.return_value = "http://webui.url"
            self.mock_check_output.return_value = b"1.2.3.4"
            provider_certificate, private_key = example_cert_and_key(
                relation_id=certificates_relation.id
            )
            self.mock_get_assigned_certificate.return_value = (provider_certificate, private_key)

            state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

            assert state_out.unit_status == WaitingStatus("Waiting for UDR service to start")

    def test_given_pebble_service_running_when_collect_unit_status_then_status_is_active(
        self,
    ):
        with tempfile.TemporaryDirectory() as temp_dir:
            certificates_relation = testing.Relation(
                endpoint="certificates",
                interface="tls-certificates",
            )
            nrf_relation = testing.Relation(
                endpoint="fiveg_nrf",
                interface="fiveg_nrf",
            )
            nms_relation = testing.Relation(
                endpoint="sdcore_config",
                interface="sdcore_config",
            )
            common_database = testing.Relation(
                endpoint="common_database",
                interface="mongodb_client",
            )
            auth_database = testing.Relation(
                endpoint="auth_database",
                interface="mongodb_client",
            )
            config_mount = testing.Mount(
                location="/free5gc/config/",
                source=temp_dir,
            )
            certs_mount = testing.Mount(
                location="/support/TLS/",
                source=temp_dir,
            )
            container = testing.Container(
                name="udr",
                can_connect=True,
                mounts={"config": config_mount, "certs": certs_mount},
                layers={"udr": Layer({"services": {"udr": {}}})},
                service_statuses={"udr": ServiceStatus.ACTIVE},
            )
            state_in = testing.State(
                containers=[container],
                relations=[
                    certificates_relation,
                    nrf_relation,
                    nms_relation,
                    common_database,
                    auth_database,
                ],
                leader=True,
            )
            self.mock_nrf_url.return_value = "https://nrf.url"
            self.mock_sdcore_config_webui_url.return_value = "http://webui.url"
            self.mock_check_output.return_value = b"1.2.3.4"
            provider_certificate, private_key = example_cert_and_key(
                relation_id=certificates_relation.id
            )
            self.mock_get_assigned_certificate.return_value = (provider_certificate, private_key)

            state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

            assert state_out.unit_status == ActiveStatus()

    def test_given_no_workload_version_file_when_collect_unit_status_then_workload_version_not_set(
        self,
    ):
        with tempfile.TemporaryDirectory() as tempdir:
            nrf_relation = testing.Relation(endpoint="fiveg_nrf", interface="fiveg_nrf")
            certificates_relation = testing.Relation(
                endpoint="certificates", interface="tls-certificates"
            )
            sdcore_config_relation = testing.Relation(
                endpoint="sdcore_config", interface="sdcore_config"
            )
            common_database = testing.Relation(
                endpoint="common_database",
                interface="mongodb_client",
            )
            auth_database = testing.Relation(
                endpoint="auth_database",
                interface="mongodb_client",
            )
            workload_version_mount = testing.Mount(
                location="/etc",
                source=tempdir,
            )
            container = testing.Container(
                name="udr", can_connect=True, mounts={"workload-version": workload_version_mount}
            )
            state_in = testing.State(
                leader=True,
                containers=[container],
                relations=[
                    nrf_relation,
                    certificates_relation,
                    sdcore_config_relation,
                    common_database,
                    auth_database,
                ],
            )

            state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

            assert state_out.workload_version == ""

    def test_given_workload_version_file_when_collect_unit_status_then_workload_version_set(
        self,
    ):
        with tempfile.TemporaryDirectory() as tempdir:
            nrf_relation = testing.Relation(endpoint="fiveg_nrf", interface="fiveg_nrf")
            certificates_relation = testing.Relation(
                endpoint="certificates", interface="tls-certificates"
            )
            sdcore_config_relation = testing.Relation(
                endpoint="sdcore_config", interface="sdcore_config"
            )
            common_database = testing.Relation(
                endpoint="common_database",
                interface="mongodb_client",
            )
            auth_database = testing.Relation(
                endpoint="auth_database",
                interface="mongodb_client",
            )
            workload_version_mount = testing.Mount(
                location="/etc",
                source=tempdir,
            )
            expected_version = "1.2.3"
            with open(f"{tempdir}/workload-version", "w") as f:
                f.write(expected_version)
            container = testing.Container(
                name="udr", can_connect=True, mounts={"workload-version": workload_version_mount}
            )
            state_in = testing.State(
                leader=True,
                containers=[container],
                relations=[
                    nrf_relation,
                    certificates_relation,
                    sdcore_config_relation,
                    common_database,
                    auth_database,
                ],
            )

            state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

            assert state_out.workload_version == expected_version

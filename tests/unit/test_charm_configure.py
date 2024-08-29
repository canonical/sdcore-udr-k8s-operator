# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.


import os
import tempfile

import scenario
from ops.pebble import Layer

from tests.unit.certificates_helpers import example_cert_and_key
from tests.unit.fixtures import UDRUnitTestFixtures


class TestCharmConfigure(UDRUnitTestFixtures):
    def test_given_workload_ready_when_configure_then_config_file_is_rendered_and_pushed(  # noqa: E501
        self,
    ):
        with tempfile.TemporaryDirectory() as temp_dir:
            certificates_relation = scenario.Relation(
                endpoint="certificates",
                interface="tls-certificates",
            )
            nrf_relation = scenario.Relation(
                endpoint="fiveg_nrf",
                interface="fiveg_nrf",
            )
            nms_relation = scenario.Relation(
                endpoint="sdcore_config",
                interface="sdcore_config",
            )
            common_database = scenario.Relation(
                endpoint="common_database",
                interface="mongodb_client",
            )
            auth_database = scenario.Relation(
                endpoint="auth_database",
                interface="mongodb_client",
            )
            config_mount = scenario.Mount(
                location="/free5gc/config/",
                src=temp_dir,
            )
            certs_mount = scenario.Mount(
                location="/support/TLS",
                src=temp_dir,
            )
            container = scenario.Container(
                name="udr",
                can_connect=True,
                mounts={"config": config_mount, "certs": certs_mount},
            )
            state_in = scenario.State(
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
            self.mock_db_fetch_relation_data.return_value = {
                common_database.relation_id: {"uris": "http://dummy"},
                auth_database.relation_id: {"uris": "http://dummy"},
            }
            self.mock_nrf_url.return_value = "https://nrf-example.com:1234"
            self.mock_sdcore_config_webui_url.return_value = "some-webui:7890"
            self.mock_check_output.return_value = b"1.2.3.4"
            provider_certificate, private_key = example_cert_and_key(
                relation_id=certificates_relation.relation_id
            )
            self.mock_get_assigned_certificate.return_value = (provider_certificate, private_key)

            self.ctx.run(container.pebble_ready_event, state_in)

            with open(f"{temp_dir}/udrcfg.yaml", "r") as config_file:
                actual_config = config_file.read()

            with open("tests/unit/resources/expected_udrcfg.yaml", "r") as expected_config_file:
                expected_config = expected_config_file.read()

            assert actual_config.strip() == expected_config.strip()

    def test_given_content_of_config_file_not_changed_when_pebble_ready_then_config_file_is_not_pushed(  # noqa: E501
        self,
    ):
        with tempfile.TemporaryDirectory() as temp_dir:
            certificates_relation = scenario.Relation(
                endpoint="certificates",
                interface="tls-certificates",
            )
            nrf_relation = scenario.Relation(
                endpoint="fiveg_nrf",
                interface="fiveg_nrf",
            )
            nms_relation = scenario.Relation(
                endpoint="sdcore_config",
                interface="sdcore_config",
            )
            common_database = scenario.Relation(
                endpoint="common_database",
                interface="mongodb_client",
            )
            auth_database = scenario.Relation(
                endpoint="auth_database",
                interface="mongodb_client",
            )
            config_mount = scenario.Mount(
                location="/free5gc/config/",
                src=temp_dir,
            )
            certs_mount = scenario.Mount(
                location="/support/TLS",
                src=temp_dir,
            )
            container = scenario.Container(
                name="udr",
                can_connect=True,
                mounts={"config": config_mount, "certs": certs_mount},
            )
            state_in = scenario.State(
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
            self.mock_nrf_url.return_value = "https://nrf-example.com:1234"
            self.mock_sdcore_config_webui_url.return_value = "some-webui:7890"
            self.mock_check_output.return_value = b"1.2.3.4"
            provider_certificate, private_key = example_cert_and_key(
                relation_id=certificates_relation.relation_id
            )
            self.mock_get_assigned_certificate.return_value = (provider_certificate, private_key)
            self.mock_db_fetch_relation_data.return_value = {
                common_database.relation_id: {"uris": "http://dummy"},
                auth_database.relation_id: {"uris": "http://dummy"},
            }
            with open("tests/unit/resources/expected_udrcfg.yaml", "r") as expected_config_file:
                expected_config = expected_config_file.read()
            with open(f"{temp_dir}/udrcfg.yaml", "w") as config_file:
                config_file.write(expected_config.strip())
            config_modification_time = os.stat(temp_dir + "/udrcfg.yaml").st_mtime

            self.ctx.run(container.pebble_ready_event, state_in)

            with open(f"{temp_dir}/udrcfg.yaml", "r") as config_file:
                actual_config = config_file.read()

            with open("tests/unit/resources/expected_udrcfg.yaml", "r") as expected_config_file:
                expected_config = expected_config_file.read()

            assert actual_config.strip() == expected_config.strip()
            assert os.stat(temp_dir + "/udrcfg.yaml").st_mtime == config_modification_time

    def test_given_given_workload_ready_when_configure_then_pebble_plan_is_applied(  # noqa: E501
        self,
    ):
        with tempfile.TemporaryDirectory() as temp_dir:
            certificates_relation = scenario.Relation(
                endpoint="certificates",
                interface="tls-certificates",
            )
            nrf_relation = scenario.Relation(
                endpoint="fiveg_nrf",
                interface="fiveg_nrf",
            )
            nms_relation = scenario.Relation(
                endpoint="sdcore_config",
                interface="sdcore_config",
            )
            common_database = scenario.Relation(
                endpoint="common_database",
                interface="mongodb_client",
            )
            auth_database = scenario.Relation(
                endpoint="auth_database",
                interface="mongodb_client",
            )
            config_mount = scenario.Mount(
                location="/free5gc/config/",
                src=temp_dir,
            )
            certs_mount = scenario.Mount(
                location="/support/TLS",
                src=temp_dir,
            )
            container = scenario.Container(
                name="udr",
                can_connect=True,
                mounts={"config": config_mount, "certs": certs_mount},
            )
            state_in = scenario.State(
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
            self.mock_nrf_url.return_value = "https://nrf-example.com:1234"
            self.mock_sdcore_config_webui_url.return_value = "some-webui:7890"
            self.mock_check_output.return_value = b"1.2.3.4"
            provider_certificate, private_key = example_cert_and_key(
                relation_id=certificates_relation.relation_id
            )
            self.mock_get_assigned_certificate.return_value = (provider_certificate, private_key)
            self.mock_db_fetch_relation_data.return_value = {
                common_database.relation_id: {"uris": "http://dummy"},
                auth_database.relation_id: {"uris": "http://dummy"},
            }

            state_out = self.ctx.run(container.pebble_ready_event, state_in)

            assert state_out.containers[0].layers == {
                "udr": Layer(
                    {
                        "summary": "UDR pebble layer",
                        "description": "UDR pebble layer",
                        "services": {
                            "udr": {
                                "startup": "enabled",
                                "override": "replace",
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
                        },
                    }
                )
            }

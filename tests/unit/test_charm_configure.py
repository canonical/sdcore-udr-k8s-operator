# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.


import datetime
import os
import tempfile

import scenario
from charms.tls_certificates_interface.v3.tls_certificates import (
    ProviderCertificate,
)
from ops.pebble import Layer

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
            self.mock_generate_private_key.return_value = b"private key"
            self.mock_generate_csr.return_value = b"whatever csr"
            self.mock_get_assigned_certificates.return_value = [
                ProviderCertificate(
                    relation_id=certificates_relation.relation_id,
                    application_name="udr",
                    csr="whatever csr",
                    certificate="whatever cert",
                    ca="whatever ca",
                    chain=["whatever ca", "whatever cert"],
                    revoked=False,
                    expiry_time=datetime.datetime.now(),
                )
            ]
            with open(f"{temp_dir}/udr.csr", "w") as f:
                f.write("whatever csr")

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
            self.mock_generate_private_key.return_value = b"private key"
            self.mock_generate_csr.return_value = b"whatever csr"
            self.mock_get_assigned_certificates.return_value = [
                ProviderCertificate(
                    relation_id=certificates_relation.relation_id,
                    application_name="udr",
                    csr="whatever csr",
                    certificate="whatever cert",
                    ca="whatever ca",
                    chain=["whatever ca", "whatever cert"],
                    revoked=False,
                    expiry_time=datetime.datetime.now(),
                )
            ]
            self.mock_db_fetch_relation_data.return_value = {
                common_database.relation_id: {"uris": "http://dummy"},
                auth_database.relation_id: {"uris": "http://dummy"},
            }
            with open(f"{temp_dir}/nrf.csr", "w") as f:
                f.write("whatever csr")
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
            self.mock_generate_private_key.return_value = b"private key"
            self.mock_generate_csr.return_value = b"whatever csr"
            self.mock_get_assigned_certificates.return_value = [
                ProviderCertificate(
                    relation_id=certificates_relation.relation_id,
                    application_name="udr",
                    csr="whatever csr",
                    certificate="whatever cert",
                    ca="whatever ca",
                    chain=["whatever ca", "whatever cert"],
                    revoked=False,
                    expiry_time=datetime.datetime.now(),
                )
            ]
            self.mock_db_fetch_relation_data.return_value = {
                common_database.relation_id: {"uris": "http://dummy"},
                auth_database.relation_id: {"uris": "http://dummy"},
            }
            with open(f"{temp_dir}/udr.csr", "w") as f:
                f.write("whatever csr")

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

    def test_given_can_connect_when_configure_then_private_key_is_generated(
        self,
    ):
        with tempfile.TemporaryDirectory() as tempdir:
            nrf_relation = scenario.Relation(endpoint="fiveg_nrf", interface="fiveg_nrf")
            certificates_relation = scenario.Relation(
                endpoint="certificates", interface="tls-certificates"
            )
            sdcore_config_relation = scenario.Relation(
                endpoint="sdcore_config", interface="sdcore_config"
            )
            common_database = scenario.Relation(
                endpoint="common_database",
                interface="mongodb_client",
            )
            auth_database = scenario.Relation(
                endpoint="auth_database",
                interface="mongodb_client",
            )
            certs_mount = scenario.Mount(
                location="/support/TLS",
                src=tempdir,
            )
            config_mount = scenario.Mount(
                location="/free5gc/config",
                src=tempdir,
            )
            container = scenario.Container(
                name="udr",
                can_connect=True,
                mounts={"certs": certs_mount, "config": config_mount},
            )
            state_in = scenario.State(
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
            self.mock_get_assigned_certificates.return_value = [
                ProviderCertificate(
                    relation_id=certificates_relation.relation_id,
                    application_name="udr",
                    csr="whatever csr",
                    certificate="whatever cert",
                    ca="whatever ca",
                    chain=["whatever ca", "whatever cert"],
                    revoked=False,
                    expiry_time=datetime.datetime.now(),
                )
            ]
            self.mock_check_output.return_value = b"1.2.3.4"
            self.mock_generate_private_key.return_value = b"private key"
            self.mock_generate_csr.return_value = b"whatever csr"

            self.ctx.run(container.pebble_ready_event, state_in)

            with open(tempdir + "/udr.key", "r") as f:
                assert f.read() == "private key"

# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

from typing import Generator
from unittest.mock import patch

import pytest
from charm import (
    AUTH_DATABASE_RELATION_NAME,
    COMMON_DATABASE_RELATION_NAME,
    NRF_RELATION_NAME,
    SDCORE_CONFIG_RELATION_NAME,
    TLS_RELATION_NAME,
    UDROperatorCharm,
)
from ops import testing

NAMESPACE = "whatever"
TEST_NRF_URL = "https://nrf-example.com:1234"
TEST_WEBUI_URL = "some-webui:7890"
TEST_DB_APPLICATION_NAME = "whatever-db"


class UDRUnitTestFixtures:
    patcher_check_output = patch("charm.check_output")
    patcher_generate_csr = patch("charm.generate_csr")
    patcher_generate_private_key = patch("charm.generate_private_key")
    patcher_get_service = patch("ops.model.Container.get_service")
    patcher_get_assigned_certificates = patch("charms.tls_certificates_interface.v3.tls_certificates.TLSCertificatesRequiresV3.get_assigned_certificates")  # noqa: E501
    patcher_request_certificate_creation = patch("charms.tls_certificates_interface.v3.tls_certificates.TLSCertificatesRequiresV3.request_certificate_creation")  # noqa: E501
    patcher_restart = patch("ops.model.Container.restart")
    patcher_resource_created = patch("charms.data_platform_libs.v0.data_interfaces.DatabaseRequires.is_resource_created")  # noqa: E501

    @pytest.fixture()
    def setup(self):
        self.mock_check_output = UDRUnitTestFixtures.patcher_check_output.start()
        self.mock_generate_csr = UDRUnitTestFixtures.patcher_generate_csr.start()
        self.mock_generate_private_key = UDRUnitTestFixtures.patcher_generate_private_key.start()
        self.mock_get_service = UDRUnitTestFixtures.patcher_get_service.start()
        self.mock_get_assigned_certificates = UDRUnitTestFixtures.patcher_get_assigned_certificates.start()  # noqa: E501
        self.mock_request_certificate_creation = UDRUnitTestFixtures.patcher_request_certificate_creation.start()  # noqa: E501
        self.mock_restart = UDRUnitTestFixtures.patcher_restart.start()
        self.mock_resource_created = UDRUnitTestFixtures.patcher_resource_created.start()

    @staticmethod
    def teardown() -> None:
        patch.stopall()

    @pytest.fixture(autouse=True)
    def create_harness(self, setup, request):
        self.harness = testing.Harness(UDROperatorCharm)
        self.harness.set_model_name(name=NAMESPACE)
        self.harness.set_leader(is_leader=True)
        self.harness.begin()
        yield self.harness
        self.harness.cleanup()
        request.addfinalizer(self.teardown)

    @pytest.fixture()
    def add_storage(self):
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.add_storage(storage_name="config", attach=True)

    @pytest.fixture()
    def create_nrf_relation_and_set_nrf_url(self, nrf_relation_id):
        self.harness.add_relation_unit(
            relation_id=nrf_relation_id, remote_unit_name="whatever-nrf/0"
        )
        self.harness.update_relation_data(
            relation_id=nrf_relation_id,
            app_or_unit="whatever-nrf",
            key_values={"url": TEST_NRF_URL},
        )

    @pytest.fixture()
    def nrf_relation_id(self) -> Generator[int, None, None]:
        yield self.harness.add_relation(
            relation_name=NRF_RELATION_NAME,
            remote_app="whatever-nrf",
        )

    @pytest.fixture()
    def create_nms_relation_and_set_webui_url(self, nms_relation_id):
        self.harness.add_relation_unit(
            relation_id=nms_relation_id, remote_unit_name="whatever-nms/0"
        )
        self.harness.update_relation_data(
            relation_id=nms_relation_id,
            app_or_unit="whatever-nms",
            key_values={"webui_url": TEST_WEBUI_URL},
        )

    @pytest.fixture()
    def nms_relation_id(self) -> Generator[int, None, None]:
        yield self.harness.add_relation(
            relation_name=SDCORE_CONFIG_RELATION_NAME,
            remote_app="whatever-nms",
        )

    @pytest.fixture()
    def create_auth_database_relation_and_populate_data(self, auth_database_relation_id):
        self.harness.add_relation_unit(
            relation_id=auth_database_relation_id, remote_unit_name=f"{TEST_DB_APPLICATION_NAME}/0"
        )
        self.harness.update_relation_data(
            relation_id=auth_database_relation_id,
            app_or_unit=TEST_DB_APPLICATION_NAME,
            key_values={
                "username": "dummy",
                "password": "dummy",
                "uris": "http://dummy",
            },
        )

    @pytest.fixture()
    def auth_database_relation_id(self) -> Generator[int, None, None]:
        yield self.harness.add_relation(
            relation_name=AUTH_DATABASE_RELATION_NAME,
            remote_app=TEST_DB_APPLICATION_NAME,
        )

    @pytest.fixture()
    def create_common_database_relation_and_populate_data(self, common_database_relation_id):
        self.harness.add_relation_unit(
            relation_id=common_database_relation_id,
            remote_unit_name=f"{TEST_DB_APPLICATION_NAME}/0",
        )
        self.harness.update_relation_data(
            relation_id=common_database_relation_id,
            app_or_unit=TEST_DB_APPLICATION_NAME,
            key_values={
                "username": "dummy",
                "password": "dummy",
                "uris": "http://dummy",
            },
        )

    @pytest.fixture()
    def common_database_relation_id(self) -> Generator[int, None, None]:
        yield self.harness.add_relation(
            relation_name=COMMON_DATABASE_RELATION_NAME,
            remote_app=TEST_DB_APPLICATION_NAME,
        )

    @pytest.fixture()
    def certificates_relation_id(self) -> Generator[int, None, None]:
        yield self.harness.add_relation(
            relation_name=TLS_RELATION_NAME,
            remote_app="whatever-tls",
        )

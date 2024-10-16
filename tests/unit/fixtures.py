# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

from unittest.mock import PropertyMock, patch

import pytest
from ops import testing

from charm import UDROperatorCharm


class UDRUnitTestFixtures:
    patcher_sdcore_config_webui_url = patch(
        "charms.sdcore_nms_k8s.v0.sdcore_config.SdcoreConfigRequires.webui_url",
        new_callable=PropertyMock,
    )
    patcher_get_assigned_certificate = patch(
        "charms.tls_certificates_interface.v4.tls_certificates.TLSCertificatesRequiresV4.get_assigned_certificate"
    )
    patcher_nrf_url = patch("charm.NRFRequires.nrf_url", new_callable=PropertyMock)
    patcher_check_output = patch("charm.check_output")
    patcher_db_is_resource_created = patch(
        "charms.data_platform_libs.v0.data_interfaces.DatabaseRequires.is_resource_created"
    )
    patcher_db_fetch_relation_data = patch(
        "charms.data_platform_libs.v0.data_interfaces.DatabaseRequires.fetch_relation_data"
    )

    @pytest.fixture(autouse=True)
    def setup(self, request):
        self.mock_sdcore_config_webui_url = (
            UDRUnitTestFixtures.patcher_sdcore_config_webui_url.start()
        )
        self.mock_get_assigned_certificate = (
            UDRUnitTestFixtures.patcher_get_assigned_certificate.start()
        )
        self.mock_nrf_url = UDRUnitTestFixtures.patcher_nrf_url.start()
        self.mock_check_output = UDRUnitTestFixtures.patcher_check_output.start()
        self.mock_db_is_resource_created = (
            UDRUnitTestFixtures.patcher_db_is_resource_created.start()
        )
        self.mock_db_fetch_relation_data = (
            UDRUnitTestFixtures.patcher_db_fetch_relation_data.start()
        )
        yield
        request.addfinalizer(self.teardown)

    @staticmethod
    def teardown() -> None:
        patch.stopall()

    @pytest.fixture(autouse=True)
    def context(self):
        self.ctx = testing.Context(
            charm_type=UDROperatorCharm,
        )

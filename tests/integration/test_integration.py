#!/usr/bin/env python3
# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
from pathlib import Path

import pytest
import yaml
from pytest_operator.plugin import OpsTest

logger = logging.getLogger(__name__)

METADATA = yaml.safe_load(Path("./charmcraft.yaml").read_text())
APPLICATION_NAME = METADATA["name"]

DATABASE_CHARM_NAME = "mongodb-k8s"
DATABASE_CHARM_CHANNEL = "6/stable"
NRF_CHARM_NAME = "sdcore-nrf-k8s"
NRF_CHARM_CHANNEL = "1.6/edge"
NMS_CHARM_NAME = "sdcore-nms-k8s"
NMS_CHARM_CHANNEL = "1.6/edge"
TLS_CHARM_NAME = "self-signed-certificates"
TLS_CHARM_CHANNEL = "latest/stable"
GRAFANA_AGENT_CHARM_NAME = "grafana-agent-k8s"
GRAFANA_AGENT_CHARM_CHANNEL = "1/stable"
COMMON_DATABASE_RELATION_NAME = "common_database"
AUTH_DATABASE_RELATION_NAME = "auth_database"
NRF_RELATION_NAME = "fiveg_nrf"
TLS_RELATION_NAME = "certificates"
SDCORE_CHARMS_BASE = "ubuntu@24.04"


class TestUDROperatorCharm:
    @pytest.fixture(scope="module")
    @pytest.mark.abort_on_fail
    async def deploy(self, ops_test: OpsTest, request):
        charm = Path(request.config.getoption("--charm_path")).resolve()
        resources = {"udr-image": METADATA["resources"]["udr-image"]["upstream-source"]}
        assert ops_test.model
        await ops_test.model.set_config({"update-status-hook-interval": "5s"})
        await self._deploy_mongodb(ops_test)
        await self._deploy_tls_provider(ops_test)
        await self._deploy_grafana_agent(ops_test)
        await self._deploy_nms(ops_test)
        await self._deploy_nrf(ops_test)
        await ops_test.model.deploy(
            charm,
            resources=resources,
            application_name=APPLICATION_NAME,
            trust=True,
        )

    @pytest.mark.abort_on_fail
    async def test_wait_for_blocked_status(self, ops_test: OpsTest, deploy):
        assert ops_test.model
        await ops_test.model.wait_for_idle(apps=[APPLICATION_NAME], status="blocked", timeout=300)

    @pytest.mark.abort_on_fail
    async def test_relate_and_wait_for_idle(self, ops_test: OpsTest, deploy):
        assert ops_test.model
        await ops_test.model.integrate(
            relation1=f"{APPLICATION_NAME}:{COMMON_DATABASE_RELATION_NAME}",
            relation2=DATABASE_CHARM_NAME,
        )
        await ops_test.model.integrate(
            relation1=f"{APPLICATION_NAME}:{AUTH_DATABASE_RELATION_NAME}",
            relation2=DATABASE_CHARM_NAME,
        )
        await ops_test.model.integrate(
            relation1=f"{APPLICATION_NAME}:{NRF_RELATION_NAME}", relation2=NRF_CHARM_NAME
        )
        await ops_test.model.integrate(
            relation1=f"{APPLICATION_NAME}:{TLS_RELATION_NAME}",
            relation2=f"{TLS_CHARM_NAME}:certificates",
        )
        await ops_test.model.integrate(
            relation1=f"{APPLICATION_NAME}:sdcore_config",
            relation2=f"{NMS_CHARM_NAME}:sdcore_config",
        )
        await ops_test.model.integrate(
            relation1=f"{APPLICATION_NAME}:logging",
            relation2=f"{GRAFANA_AGENT_CHARM_NAME}:logging-provider",
        )
        await ops_test.model.integrate(
            relation1=f"{APPLICATION_NAME}:metrics-endpoint",
            relation2=f"{GRAFANA_AGENT_CHARM_NAME}:metrics-endpoint",
        )
        await ops_test.model.wait_for_idle(apps=[APPLICATION_NAME], status="active", timeout=300)

    @pytest.mark.abort_on_fail
    async def test_remove_nrf_and_wait_for_blocked_status(self, ops_test: OpsTest, deploy):
        assert ops_test.model
        await ops_test.model.remove_application(NRF_CHARM_NAME, block_until_done=True)
        await ops_test.model.wait_for_idle(apps=[APPLICATION_NAME], status="blocked", timeout=60)

    @pytest.mark.abort_on_fail
    async def test_restore_nrf_and_wait_for_active_status(self, ops_test: OpsTest, deploy):
        assert ops_test.model
        await self._deploy_nrf(ops_test)
        await ops_test.model.integrate(relation1=APPLICATION_NAME, relation2=NRF_CHARM_NAME)
        await ops_test.model.wait_for_idle(apps=[APPLICATION_NAME], status="active", timeout=300)

    @pytest.mark.abort_on_fail
    async def test_remove_nms_and_wait_for_blocked_status(self, ops_test: OpsTest, deploy):
        assert ops_test.model
        await ops_test.model.remove_application(NMS_CHARM_NAME, block_until_done=True)
        await ops_test.model.wait_for_idle(apps=[APPLICATION_NAME], status="blocked", timeout=60)

    @pytest.mark.abort_on_fail
    async def test_restore_nms_and_wait_for_active_status(self, ops_test: OpsTest, deploy):
        assert ops_test.model
        await self._deploy_nms(ops_test)
        await ops_test.model.integrate(
            relation1=f"{APPLICATION_NAME}:sdcore_config",
            relation2=f"{NMS_CHARM_NAME}:sdcore_config",
        )
        await ops_test.model.wait_for_idle(apps=[APPLICATION_NAME], status="active", timeout=300)

    @pytest.mark.abort_on_fail
    async def test_remove_tls_and_wait_for_blocked_status(self, ops_test: OpsTest, deploy):
        assert ops_test.model
        await ops_test.model.remove_application(TLS_CHARM_NAME, block_until_done=True)
        await ops_test.model.wait_for_idle(apps=[APPLICATION_NAME], status="blocked", timeout=60)

    @pytest.mark.abort_on_fail
    async def test_restore_tls_and_wait_for_active_status(self, ops_test: OpsTest, deploy):
        assert ops_test.model
        await self._deploy_tls_provider(ops_test)
        await ops_test.model.integrate(relation1=APPLICATION_NAME, relation2=TLS_CHARM_NAME)
        await ops_test.model.integrate(relation1=NMS_CHARM_NAME, relation2=TLS_CHARM_NAME)
        await ops_test.model.integrate(relation1=NRF_CHARM_NAME, relation2=TLS_CHARM_NAME)
        await ops_test.model.wait_for_idle(apps=[APPLICATION_NAME], status="active", timeout=300)


    @pytest.mark.abort_on_fail
    async def test_remove_database_and_wait_for_blocked_status(self, ops_test: OpsTest, deploy):
        assert ops_test.model
        await ops_test.model.remove_application(DATABASE_CHARM_NAME, block_until_done=True)
        await ops_test.model.wait_for_idle(apps=[APPLICATION_NAME], status="blocked", timeout=60)


    @pytest.mark.abort_on_fail
    async def test_restore_database_and_wait_for_active_status(self, ops_test: OpsTest, deploy):
        assert ops_test.model
        await self._deploy_mongodb(ops_test)
        await ops_test.model.integrate(
            relation1=f"{APPLICATION_NAME}:{COMMON_DATABASE_RELATION_NAME}",
            relation2=DATABASE_CHARM_NAME,
        )
        await ops_test.model.integrate(
            relation1=f"{APPLICATION_NAME}:{AUTH_DATABASE_RELATION_NAME}",
            relation2=DATABASE_CHARM_NAME,
        )
        await ops_test.model.wait_for_idle(apps=[APPLICATION_NAME], status="active", timeout=300)

    @staticmethod
    async def _deploy_mongodb(ops_test: OpsTest):
        assert ops_test.model
        await ops_test.model.deploy(
            DATABASE_CHARM_NAME,
            application_name=DATABASE_CHARM_NAME,
            channel=DATABASE_CHARM_CHANNEL,
            trust=True,
        )

    @staticmethod
    async def _deploy_tls_provider(ops_test: OpsTest):
        assert ops_test.model
        await ops_test.model.deploy(
            TLS_CHARM_NAME,
            application_name=TLS_CHARM_NAME,
            channel=TLS_CHARM_CHANNEL,
        )

    @staticmethod
    async def _deploy_grafana_agent(ops_test: OpsTest):
        assert ops_test.model
        await ops_test.model.deploy(
            GRAFANA_AGENT_CHARM_NAME,
            application_name=GRAFANA_AGENT_CHARM_NAME,
            channel=GRAFANA_AGENT_CHARM_CHANNEL,
        )

    @staticmethod
    async def _deploy_nrf(ops_test: OpsTest):
        assert ops_test.model
        await ops_test.model.deploy(
            NRF_CHARM_NAME,
            application_name=NRF_CHARM_NAME,
            channel=NRF_CHARM_CHANNEL,
            trust=True,
            base=SDCORE_CHARMS_BASE,
        )
        await ops_test.model.integrate(relation1=NRF_CHARM_NAME, relation2=DATABASE_CHARM_NAME)
        await ops_test.model.integrate(relation1=NRF_CHARM_NAME, relation2=TLS_CHARM_NAME)
        await ops_test.model.integrate(relation1=NRF_CHARM_NAME, relation2=NMS_CHARM_NAME)

    @staticmethod
    async def _deploy_nms(ops_test: OpsTest):
        assert ops_test.model
        await ops_test.model.deploy(
            NMS_CHARM_NAME,
            application_name=NMS_CHARM_NAME,
            channel=NMS_CHARM_CHANNEL,
            base=SDCORE_CHARMS_BASE,
        )
        await ops_test.model.integrate(
            relation1=f"{NMS_CHARM_NAME}:common_database", relation2=DATABASE_CHARM_NAME
        )
        await ops_test.model.integrate(
            relation1=f"{NMS_CHARM_NAME}:auth_database", relation2=DATABASE_CHARM_NAME
        )
        await ops_test.model.integrate(
            relation1=f"{NMS_CHARM_NAME}:webui_database", relation2=DATABASE_CHARM_NAME
        )
        await ops_test.model.integrate(relation1=NMS_CHARM_NAME, relation2=TLS_CHARM_NAME)

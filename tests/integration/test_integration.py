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
DATABASE_CHARM_CHANNEL = "6/beta"
NRF_CHARM_NAME = "sdcore-nrf-k8s"
NRF_CHARM_CHANNEL = "1.5/edge"
WEBUI_CHARM_NAME = "sdcore-webui-k8s"
WEBUI_CHARM_CHANNEL = "1.5/edge"
TLS_CHARM_NAME = "self-signed-certificates"
TLS_CHARM_CHANNEL = "latest/stable"
GRAFANA_AGENT_CHARM_NAME = "grafana-agent-k8s"
GRAFANA_AGENT_CHARM_CHANNEL = "latest/stable"
COMMON_DATABASE_RELATION_NAME = "common_database"
AUTH_DATABASE_RELATION_NAME = "auth_database"
NRF_RELATION_NAME = "fiveg_nrf"
TLS_RELATION_NAME = "certificates"


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
        await self._deploy_webui(ops_test)
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
            relation1=f"{APPLICATION_NAME}:logging", relation2=GRAFANA_AGENT_CHARM_NAME
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
    async def test_remove_tls_and_wait_for_blocked_status(self, ops_test: OpsTest, deploy):
        assert ops_test.model
        await ops_test.model.remove_application(TLS_CHARM_NAME, block_until_done=True)
        await ops_test.model.wait_for_idle(apps=[APPLICATION_NAME], status="blocked", timeout=60)

    @pytest.mark.abort_on_fail
    async def test_restore_tls_and_wait_for_active_status(self, ops_test: OpsTest, deploy):
        assert ops_test.model
        await self._deploy_tls_provider(ops_test)
        await ops_test.model.integrate(
            relation1=APPLICATION_NAME, relation2=TLS_CHARM_NAME
        )
        await ops_test.model.wait_for_idle(apps=[APPLICATION_NAME], status="active", timeout=300)

    @pytest.mark.skip(
        reason="Bug in MongoDB: https://github.com/canonical/mongodb-k8s-operator/issues/218"
    )
    @pytest.mark.abort_on_fail
    async def test_remove_database_and_wait_for_blocked_status(self, ops_test: OpsTest, deploy):
        assert ops_test.model
        await ops_test.model.remove_application(DATABASE_CHARM_NAME, block_until_done=True)
        await ops_test.model.wait_for_idle(apps=[APPLICATION_NAME], status="blocked", timeout=60)

    @pytest.mark.skip(
        reason="Bug in MongoDB: https://github.com/canonical/mongodb-k8s-operator/issues/218"
    )
    @pytest.mark.abort_on_fail
    async def test_restore_database_and_wait_for_active_status(self, ops_test: OpsTest, deploy):
        assert ops_test.model
        await self._deploy_mongodb(ops_test)
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
        )
        await ops_test.model.integrate(relation1=NRF_CHARM_NAME, relation2=DATABASE_CHARM_NAME)
        await ops_test.model.integrate(relation1=NRF_CHARM_NAME, relation2=TLS_CHARM_NAME)
        await ops_test.model.integrate(relation1=NRF_CHARM_NAME, relation2=WEBUI_CHARM_NAME)

    @staticmethod
    async def _deploy_webui(ops_test: OpsTest):
        assert ops_test.model
        await ops_test.model.deploy(
            WEBUI_CHARM_NAME,
            application_name=WEBUI_CHARM_NAME,
            channel=WEBUI_CHARM_CHANNEL,
        )
        await ops_test.model.integrate(
            relation1=f"{WEBUI_CHARM_NAME}:common_database", relation2=f"{DATABASE_CHARM_NAME}"
        )
        await ops_test.model.integrate(
            relation1=f"{WEBUI_CHARM_NAME}:auth_database", relation2=f"{DATABASE_CHARM_NAME}"
        )

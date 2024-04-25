#!/usr/bin/env python3
# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
from pathlib import Path

import pytest
import yaml
from pytest_operator.plugin import OpsTest

logger = logging.getLogger(__name__)

METADATA = yaml.safe_load(Path("./metadata.yaml").read_text())
APPLICATION_NAME = METADATA["name"]

DB_APPLICATION_NAME = "mongodb-k8s"
DB_APPLICATION_CHANNEL = "6/beta"
NRF_APPLICATION_NAME = "sdcore-nrf-k8s"
NRF_APPLICATION_CHANNEL = "1.4/edge"
TLS_PROVIDER_CHARM_NAME = "self-signed-certificates"
TLS_PROVIDER_CHARM_CHANNEL = "latest/stable"
COMMON_DATABASE_RELATION_NAME = "common_database"
AUTH_DATABASE_RELATION_NAME = "auth_database"
NRF_RELATION_NAME = "fiveg_nrf"
TLS_RELATION_NAME = "certificates"
GRAFANA_AGENT_APP_NAME = "grafana-agent-k8s"
GRAFANA_AGENT_APP_CHANNEL = "latest/stable"


class TestUDROperatorCharm:
    @pytest.fixture(scope="module")
    @pytest.mark.abort_on_fail
    async def setup(self, ops_test: OpsTest):
        assert ops_test.model
        await ops_test.model.set_config({"update-status-hook-interval": "5s"})
        await self._deploy_mongodb(ops_test)
        await self._deploy_tls_provider(ops_test)
        await self._deploy_sdcore_nrf_operator(ops_test)
        await self._deploy_grafana_agent(ops_test)
        await ops_test.model.integrate(
            relation1=DB_APPLICATION_NAME, relation2=NRF_APPLICATION_NAME
        )
        await ops_test.model.integrate(
            relation1=TLS_PROVIDER_CHARM_NAME, relation2=NRF_APPLICATION_NAME
        )

    @pytest.fixture(scope="module")
    @pytest.mark.abort_on_fail
    async def build_and_deploy_charm(self, ops_test: OpsTest):
        charm = await ops_test.build_charm(".")
        resources = {"udr-image": METADATA["resources"]["udr-image"]["upstream-source"]}
        assert ops_test.model
        await ops_test.model.deploy(
            charm,
            resources=resources,
            application_name=APPLICATION_NAME,
            trust=True,
        )

    @staticmethod
    async def _deploy_mongodb(ops_test: OpsTest):
        assert ops_test.model
        await ops_test.model.deploy(
            DB_APPLICATION_NAME,
            application_name=DB_APPLICATION_NAME,
            channel=DB_APPLICATION_CHANNEL,
            trust=True,
        )

    @staticmethod
    async def _deploy_tls_provider(ops_test: OpsTest):
        assert ops_test.model
        await ops_test.model.deploy(
            TLS_PROVIDER_CHARM_NAME,
            application_name=TLS_PROVIDER_CHARM_NAME,
            channel=TLS_PROVIDER_CHARM_CHANNEL,
        )

    @staticmethod
    async def _deploy_grafana_agent(ops_test: OpsTest):
        assert ops_test.model
        await ops_test.model.deploy(
            GRAFANA_AGENT_APP_NAME,
            application_name=GRAFANA_AGENT_APP_NAME,
            channel=GRAFANA_AGENT_APP_CHANNEL,
        )

    @staticmethod
    async def _deploy_sdcore_nrf_operator(ops_test: OpsTest):
        assert ops_test.model
        await ops_test.model.deploy(
            NRF_APPLICATION_NAME,
            application_name=NRF_APPLICATION_NAME,
            channel=NRF_APPLICATION_CHANNEL,
            trust=True,
        )

    @pytest.mark.abort_on_fail
    async def test_wait_for_blocked_status(self, ops_test: OpsTest, setup, build_and_deploy_charm):
        assert ops_test.model
        await ops_test.model.wait_for_idle(apps=[APPLICATION_NAME], status="blocked", timeout=1000)

    @pytest.mark.abort_on_fail
    async def test_relate_and_wait_for_idle(
        self, ops_test: OpsTest, setup, build_and_deploy_charm
    ):
        assert ops_test.model
        await ops_test.model.integrate(
            relation1=f"{APPLICATION_NAME}:{COMMON_DATABASE_RELATION_NAME}",
            relation2=DB_APPLICATION_NAME,
        )
        await ops_test.model.integrate(
            relation1=f"{APPLICATION_NAME}:{AUTH_DATABASE_RELATION_NAME}",
            relation2=DB_APPLICATION_NAME,
        )
        await ops_test.model.integrate(
            relation1=f"{APPLICATION_NAME}:{NRF_RELATION_NAME}", relation2=NRF_APPLICATION_NAME
        )
        await ops_test.model.integrate(
            relation1=f"{APPLICATION_NAME}:{TLS_RELATION_NAME}",
            relation2=f"{TLS_PROVIDER_CHARM_NAME}:certificates",
        )
        await ops_test.model.integrate(
            relation1=f"{APPLICATION_NAME}:logging", relation2=GRAFANA_AGENT_APP_NAME
        )
        await ops_test.model.wait_for_idle(apps=[APPLICATION_NAME], status="active", timeout=1000)

    @pytest.mark.abort_on_fail
    async def test_remove_nrf_and_wait_for_blocked_status(
        self, ops_test: OpsTest, setup, build_and_deploy_charm
    ):
        assert ops_test.model
        await ops_test.model.remove_application(NRF_APPLICATION_NAME, block_until_done=True)
        await ops_test.model.wait_for_idle(apps=[APPLICATION_NAME], status="blocked", timeout=60)

    @pytest.mark.abort_on_fail
    async def test_restore_nrf_and_wait_for_active_status(
        self, ops_test: OpsTest, setup, build_and_deploy_charm
    ):
        assert ops_test.model
        await self._deploy_sdcore_nrf_operator(ops_test)
        await ops_test.model.integrate(
            relation1=f"{NRF_APPLICATION_NAME}:database", relation2=DB_APPLICATION_NAME
        )
        await ops_test.model.integrate(relation1=APPLICATION_NAME, relation2=NRF_APPLICATION_NAME)
        await ops_test.model.integrate(
            relation1=TLS_PROVIDER_CHARM_NAME, relation2=NRF_APPLICATION_NAME
        )
        await ops_test.model.wait_for_idle(apps=[APPLICATION_NAME], status="active", timeout=300)

    @pytest.mark.abort_on_fail
    async def test_remove_tls_and_wait_for_blocked_status(
        self, ops_test: OpsTest, build_and_deploy_charm
    ):
        assert ops_test.model
        await ops_test.model.remove_application(TLS_PROVIDER_CHARM_NAME, block_until_done=True)
        await ops_test.model.wait_for_idle(apps=[APPLICATION_NAME], status="blocked", timeout=60)

    @pytest.mark.abort_on_fail
    async def test_restore_tls_and_wait_for_active_status(
        self, ops_test: OpsTest, build_and_deploy_charm
    ):
        assert ops_test.model
        await self._deploy_tls_provider(ops_test)
        await ops_test.model.integrate(
            relation1=APPLICATION_NAME, relation2=TLS_PROVIDER_CHARM_NAME
        )
        await ops_test.model.wait_for_idle(apps=[APPLICATION_NAME], status="active", timeout=1000)

    @pytest.mark.skip(
        reason="Bug in MongoDB: https://github.com/canonical/mongodb-k8s-operator/issues/218"
    )
    @pytest.mark.abort_on_fail
    async def test_remove_database_and_wait_for_blocked_status(
        self, ops_test: OpsTest, build_and_deploy_charm
    ):
        assert ops_test.model
        await ops_test.model.remove_application(DB_APPLICATION_NAME, block_until_done=True)
        await ops_test.model.wait_for_idle(apps=[APPLICATION_NAME], status="blocked", timeout=60)

    @pytest.mark.skip(
        reason="Bug in MongoDB: https://github.com/canonical/mongodb-k8s-operator/issues/218"
    )
    @pytest.mark.abort_on_fail
    async def test_restore_database_and_wait_for_active_status(
        self, ops_test: OpsTest, build_and_deploy_charm
    ):
        assert ops_test.model
        await self._deploy_mongodb(ops_test)
        await ops_test.model.integrate(
            relation1=f"{NRF_APPLICATION_NAME}:{COMMON_DATABASE_RELATION_NAME}",
            relation2=DB_APPLICATION_NAME,
        )
        await ops_test.model.integrate(
            relation1=f"{NRF_APPLICATION_NAME}:{AUTH_DATABASE_RELATION_NAME}",
            relation2=DB_APPLICATION_NAME,
        )
        await ops_test.model.wait_for_idle(apps=[APPLICATION_NAME], status="active", timeout=1000)

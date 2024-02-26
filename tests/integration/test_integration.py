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
NRF_APPLICATION_NAME = "sdcore-nrf-k8s"
TLS_PROVIDER_CHARM_NAME = "self-signed-certificates"
COMMON_DATABASE_RELATION_NAME = "common_database"
AUTH_DATABASE_RELATION_NAME = "auth_database"
NRF_RELATION_NAME = "fiveg_nrf"
TLS_RELATION_NAME = "certificates"


class TestUDROperatorCharm:
    @pytest.fixture(scope="module")
    @pytest.mark.abort_on_fail
    async def setup(self, ops_test: OpsTest):
        await ops_test.model.set_config({"update-status-hook-interval": "5s"})  # type: ignore[union-attr]  # noqa: E501
        await self._deploy_mongodb(ops_test)
        await self._deploy_tls_provider(ops_test)
        await self._deploy_sdcore_nrf_operator(ops_test)

    @pytest.fixture(scope="module")
    @pytest.mark.abort_on_fail
    async def build_and_deploy_charm(self, ops_test: OpsTest):
        charm = await ops_test.build_charm(".")
        resources = {"udr-image": METADATA["resources"]["udr-image"]["upstream-source"]}
        await ops_test.model.deploy(  # type: ignore[union-attr]
            charm,
            resources=resources,
            application_name=APPLICATION_NAME,
            trust=True,
        )

    @staticmethod
    async def _deploy_mongodb(ops_test: OpsTest):
        await ops_test.model.deploy(  # type: ignore[union-attr]
            DB_APPLICATION_NAME,
            application_name=DB_APPLICATION_NAME,
            channel="6/beta",
            trust=True,
        )

    @staticmethod
    async def _deploy_tls_provider(ops_test: OpsTest):
        await ops_test.model.deploy(  # type: ignore[union-attr]
            TLS_PROVIDER_CHARM_NAME,
            application_name=TLS_PROVIDER_CHARM_NAME,
            channel="beta",
        )

    @staticmethod
    async def _deploy_sdcore_nrf_operator(ops_test: OpsTest):
        await ops_test.model.deploy(  # type: ignore[union-attr]
            NRF_APPLICATION_NAME,
            application_name=NRF_APPLICATION_NAME,
            channel="edge",
            trust=True,
        )
        await ops_test.model.integrate(  # type: ignore[union-attr]
            relation1=DB_APPLICATION_NAME, relation2=NRF_APPLICATION_NAME
        )
        await ops_test.model.integrate(  # type: ignore[union-attr]
            relation1=TLS_PROVIDER_CHARM_NAME, relation2=NRF_APPLICATION_NAME
        )

    @pytest.mark.abort_on_fail
    async def test_wait_for_blocked_status(self, ops_test: OpsTest, setup, build_and_deploy_charm):
        await ops_test.model.wait_for_idle(apps=[APPLICATION_NAME], status="blocked", timeout=1000)  # type: ignore[union-attr]  # noqa: E501

    @pytest.mark.abort_on_fail
    async def test_relate_and_wait_for_idle(
        self, ops_test: OpsTest, setup, build_and_deploy_charm
    ):
        await ops_test.model.integrate(  # type: ignore[union-attr]
            relation1=f"{APPLICATION_NAME}:{COMMON_DATABASE_RELATION_NAME}",
            relation2=DB_APPLICATION_NAME,
        )
        await ops_test.model.integrate(  # type: ignore[union-attr]
            relation1=f"{APPLICATION_NAME}:{AUTH_DATABASE_RELATION_NAME}",
            relation2=DB_APPLICATION_NAME,
        )
        await ops_test.model.integrate(  # type: ignore[union-attr]
            relation1=f"{APPLICATION_NAME}:{NRF_RELATION_NAME}", relation2=NRF_APPLICATION_NAME
        )
        await ops_test.model.integrate(  # type: ignore[union-attr]
            relation1=f"{APPLICATION_NAME}:{TLS_RELATION_NAME}",
            relation2=f"{TLS_PROVIDER_CHARM_NAME}:certificates",
        )
        await ops_test.model.wait_for_idle(apps=[APPLICATION_NAME], status="active", timeout=1000)  # type: ignore[union-attr]  # noqa: E501

    @pytest.mark.abort_on_fail
    async def test_remove_nrf_and_wait_for_blocked_status(
        self, ops_test: OpsTest, setup, build_and_deploy_charm
    ):
        await ops_test.model.remove_application(NRF_APPLICATION_NAME, block_until_done=True)  # type: ignore[union-attr]  # noqa: E501
        await ops_test.model.wait_for_idle(apps=[APPLICATION_NAME], status="blocked", timeout=60)  # type: ignore[union-attr]  # noqa: E501

    @pytest.mark.abort_on_fail
    async def test_restore_nrf_and_wait_for_active_status(
        self, ops_test: OpsTest, setup, build_and_deploy_charm
    ):
        await ops_test.model.deploy(  # type: ignore[union-attr]
            NRF_APPLICATION_NAME,
            application_name=NRF_APPLICATION_NAME,
            channel="edge",
            trust=True,
        )
        await ops_test.model.integrate(  # type: ignore[union-attr]
            relation1=f"{NRF_APPLICATION_NAME}:database", relation2=DB_APPLICATION_NAME
        )
        await ops_test.model.integrate(relation1=APPLICATION_NAME, relation2=NRF_APPLICATION_NAME)  # type: ignore[union-attr]  # noqa: E501
        await ops_test.model.integrate(relation1=TLS_PROVIDER_CHARM_NAME, relation2=NRF_APPLICATION_NAME)  # type: ignore[union-attr]  # noqa: E501
        await ops_test.model.wait_for_idle(apps=[APPLICATION_NAME], status="active", timeout=300)  # type: ignore[union-attr]  # noqa: E501

    @pytest.mark.abort_on_fail
    async def test_remove_tls_and_wait_for_blocked_status(
        self, ops_test: OpsTest, build_and_deploy_charm
    ):
        await ops_test.model.remove_application(TLS_PROVIDER_CHARM_NAME, block_until_done=True)  # type: ignore[union-attr]  # noqa: E501
        await ops_test.model.wait_for_idle(apps=[APPLICATION_NAME], status="blocked", timeout=60)  # type: ignore[union-attr]  # noqa: E501

    @pytest.mark.abort_on_fail
    async def test_restore_tls_and_wait_for_active_status(
        self, ops_test: OpsTest, build_and_deploy_charm
    ):
        await ops_test.model.deploy(  # type: ignore[union-attr]
            TLS_PROVIDER_CHARM_NAME,
            application_name=TLS_PROVIDER_CHARM_NAME,
            channel="beta",
            trust=True,
        )
        await ops_test.model.integrate(  # type: ignore[union-attr]
            relation1=APPLICATION_NAME, relation2=TLS_PROVIDER_CHARM_NAME
        )
        await ops_test.model.wait_for_idle(apps=[APPLICATION_NAME], status="active", timeout=1000)  # type: ignore[union-attr]  # noqa: E501


@pytest.mark.skip(
    reason="Bug in MongoDB: https://github.com/canonical/mongodb-k8s-operator/issues/218"
)
@pytest.mark.abort_on_fail
async def test_remove_database_and_wait_for_blocked_status(ops_test: OpsTest, build_and_deploy):
    assert ops_test.model
    await ops_test.model.remove_application(DB_APPLICATION_NAME, block_until_done=True)
    await ops_test.model.wait_for_idle(apps=[APPLICATION_NAME], status="blocked", timeout=60)


@pytest.mark.skip(
    reason="Bug in MongoDB: https://github.com/canonical/mongodb-k8s-operator/issues/218"
)
@pytest.mark.abort_on_fail
async def test_restore_database_and_wait_for_active_status(ops_test: OpsTest, build_and_deploy):
    assert ops_test.model
    await ops_test.model.deploy(
        DB_APPLICATION_NAME,
        application_name=DB_APPLICATION_NAME,
        channel="5/edge",
        trust=True,
    )
    await ops_test.model.integrate(
        relation1=f"{NRF_APPLICATION_NAME}:{COMMON_DATABASE_RELATION_NAME}",
        relation2=DB_APPLICATION_NAME,
    )
    await ops_test.model.integrate(
        relation1=f"{NRF_APPLICATION_NAME}:{AUTH_DATABASE_RELATION_NAME}",
        relation2=DB_APPLICATION_NAME,
    )
    await ops_test.model.wait_for_idle(apps=[APPLICATION_NAME], status="active", timeout=1000)

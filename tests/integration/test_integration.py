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
NRF_APPLICATION_NAME = "sdcore-nrf"
TLS_PROVIDER_CHARM_NAME = "self-signed-certificates"


class TestUDROperatorCharm:
    @pytest.fixture(scope="module")
    @pytest.mark.abort_on_fail
    async def setup(self, ops_test: OpsTest):
        await ops_test.model.set_config({"update-status-hook-interval": "5s"})
        await self._deploy_mongodb(ops_test)
        await self._deploy_sdcore_nrf_operator(ops_test)
        await self._deploy_tls_provider(ops_test)

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
            channel="5/edge",
            trust=True,
        )

    @staticmethod
    async def _deploy_tls_provider(ops_test: OpsTest):
        await ops_test.model.deploy(  # type: ignore[union-attr]
            TLS_PROVIDER_CHARM_NAME,
            application_name=TLS_PROVIDER_CHARM_NAME,
            channel="edge",
        )

    @staticmethod
    async def _deploy_sdcore_nrf_operator(ops_test: OpsTest):
        await ops_test.model.deploy(  # type: ignore[union-attr]
            NRF_APPLICATION_NAME,
            application_name=NRF_APPLICATION_NAME,
            channel="edge",
            trust=True,
        )
        await ops_test.model.add_relation(  # type: ignore[union-attr]
            relation1=DB_APPLICATION_NAME, relation2=NRF_APPLICATION_NAME
        )

    @pytest.mark.abort_on_fail
    async def test_wait_for_blocked_status(self, ops_test: OpsTest, setup, build_and_deploy_charm):
        await ops_test.model.wait_for_idle(apps=[APPLICATION_NAME], status="blocked", timeout=1000)  # type: ignore[union-attr]  # noqa: E501

    @pytest.mark.abort_on_fail
    async def test_relate_and_wait_for_idle(
        self, ops_test: OpsTest, setup, build_and_deploy_charm
    ):
        await ops_test.model.add_relation(  # type: ignore[union-attr]
            relation1=f"{APPLICATION_NAME}:database", relation2=DB_APPLICATION_NAME
        )
        await ops_test.model.add_relation(  # type: ignore[union-attr]
            relation1=f"{APPLICATION_NAME}:fiveg_nrf", relation2=NRF_APPLICATION_NAME
        )
        await ops_test.model.add_relation(  # type: ignore[union-attr]
            relation1=f"{APPLICATION_NAME}:certificates",
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
        await ops_test.model.add_relation(  # type: ignore[union-attr]
            relation1=f"{NRF_APPLICATION_NAME}:database", relation2=DB_APPLICATION_NAME
        )
        await ops_test.model.add_relation(relation1=APPLICATION_NAME, relation2=NRF_APPLICATION_NAME)  # type: ignore[union-attr]  # noqa: E501
        await ops_test.model.wait_for_idle(apps=[APPLICATION_NAME], status="active", timeout=300)  # type: ignore[union-attr]  # noqa: E501

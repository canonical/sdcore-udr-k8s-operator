#!/usr/bin/env python3
# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
from pathlib import Path

import pytest
import yaml

logger = logging.getLogger(__name__)

METADATA = yaml.safe_load(Path("./metadata.yaml").read_text())
APPLICATION_NAME = METADATA["name"]

DB_APPLICATION_NAME = "mongodb-k8s"
NRF_APPLICATION_NAME = "sdcore-nrf"


class TestUDROperatorCharm:
    @pytest.fixture(scope="module")
    @pytest.mark.abort_on_fail
    async def setup(self, ops_test):
        await self._deploy_mongodb(ops_test)
        await self._deploy_sdcore_nrf_operator(ops_test)

    @pytest.fixture(scope="module")
    @pytest.mark.abort_on_fail
    async def build_and_deploy_charm(self, ops_test):
        charm = await ops_test.build_charm(".")
        resources = {
            f"{APPLICATION_NAME}-image": METADATA["resources"][f"{APPLICATION_NAME}-image"][
                "upstream-source"
            ],
        }
        await ops_test.model.deploy(
            charm,
            resources=resources,
            application_name=APPLICATION_NAME,
            trust=True,
        )

    async def test_wait_for_blocked_status(self, ops_test, setup, build_and_deploy_charm):
        await ops_test.model.wait_for_idle(apps=[APPLICATION_NAME], status="blocked", timeout=1000)

    async def test_relate_and_wait_for_idle(self, ops_test, setup, build_and_deploy_charm):
        await ops_test.model.add_relation(
            relation1=f"{APPLICATION_NAME}:database", relation2=DB_APPLICATION_NAME
        )
        await ops_test.model.add_relation(
            relation1=f"{APPLICATION_NAME}:fivef_nrf", relation2=NRF_APPLICATION_NAME
        )
        await ops_test.model.wait_for_idle(apps=[APPLICATION_NAME], status="active", timeout=1000)

    @staticmethod
    async def _deploy_mongodb(ops_test):
        await ops_test.model.deploy(
            DB_APPLICATION_NAME,
            application_name=DB_APPLICATION_NAME,
            channel="5/edge",
            trust=True,
        )

    @staticmethod
    async def _deploy_sdcore_nrf_operator(ops_test):
        await ops_test.model.deploy(
            NRF_APPLICATION_NAME,
            application_name=NRF_APPLICATION_NAME,
            channel="edge",
            trust=True,
        )
        await ops_test.model.add_relation(
            relation1=DB_APPLICATION_NAME, relation2=NRF_APPLICATION_NAME
        )

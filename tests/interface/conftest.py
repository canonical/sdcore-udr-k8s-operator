import tempfile

import pytest
import scenario
from charm import UDROperatorCharm
from interface_tester import InterfaceTester
from ops.pebble import Layer, ServiceStatus


@pytest.fixture
def interface_tester(interface_tester: InterfaceTester):
    with tempfile.TemporaryDirectory() as tempdir:
        config_mount = scenario.Mount(
            location="/etc/udr/",
            src=tempdir,
        )
        certs_mount = scenario.Mount(
            location="/support/TLS/",
            src=tempdir,
        )
        container = scenario.Container(
            name="udr",
            can_connect=True,
            layers={"udr": Layer({"services": {"udr": {}}})},
            service_status={
                "udr": ServiceStatus.ACTIVE,
            },
            mounts={
                "config": config_mount,
                "certs": certs_mount,
            },
        )
        interface_tester.configure(
            charm_type=UDROperatorCharm,
            state_template=scenario.State(
                leader=True,
                containers=[container],
            ),
        )
        yield interface_tester

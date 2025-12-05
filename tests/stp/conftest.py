"""
Conftest for STP (Spanning Tree Protocol) tests

This module provides common fixtures for PVST, RPVST, and MSTP testing.
"""

import pytest
import logging

logger = logging.getLogger(__name__)


def pytest_addoption(parser):
    """Add STP-specific command line options"""
    parser.addoption(
        "--vlan_config",
        action="store",
        default="two_vlan_a",
        choices=["one_vlan_a", "two_vlan_a", "four_vlan_a"],
        help="VLAN configuration to use for STP tests"
    )
    parser.addoption(
        "--stp_mode",
        action="store",
        default="pvst",
        choices=["pvst", "rpvst", "mstp"],
        help="STP mode to test"
    )


@pytest.fixture(scope="module")
def vlan_config(request):
    """Get the VLAN configuration from command line"""
    return request.config.getoption("--vlan_config")


@pytest.fixture(scope="module")
def stp_mode(request):
    """Get the STP mode from command line"""
    return request.config.getoption("--stp_mode")


@pytest.fixture(scope="module")
def stp_params(vlan_config, stp_mode):
    """Provide STP test parameters based on configuration"""
    params = {
        "vlan_config": vlan_config,
        "stp_mode": stp_mode,
        "convergence_timeout": 60,
        "default_priority": 32768,
        "default_hello_time": 2,
        "default_forward_delay": 15,
        "default_max_age": 20
    }

    if vlan_config == "two_vlan_a":
        params["vlans"] = [
            {"name": "Vlan100", "id": 100},
            {"name": "Vlan200", "id": 200}
        ]
    elif vlan_config == "four_vlan_a":
        params["vlans"] = [
            {"name": "Vlan1000", "id": 1000},
            {"name": "Vlan2000", "id": 2000},
            {"name": "Vlan3000", "id": 3000},
            {"name": "Vlan4000", "id": 4000}
        ]
    else:
        params["vlans"] = [
            {"name": "Vlan1000", "id": 1000}
        ]

    return params

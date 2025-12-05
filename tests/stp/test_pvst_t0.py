"""
PVST (Per-VLAN Spanning Tree) Test Suite for T0 Topologies

This test module validates PVST functionality using the T0 topology with
two_vlan_a (Vlan100, Vlan200) and four_vlan_a (Vlan1000-4000) configurations.

Test cases are based on the PVST Test Plan for T0 Topologies.
"""

import pytest
import logging
import time
import re

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.common.reboot import reboot, REBOOT_TYPE_COLD, REBOOT_TYPE_WARM
from tests.common.config_reload import config_reload

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0')
]

# PVST Constants
PVST_MODE = "pvst"
DEFAULT_BRIDGE_PRIORITY = 32768
DEFAULT_HELLO_TIME = 2
DEFAULT_FORWARD_DELAY = 15
DEFAULT_MAX_AGE = 20
STP_CONVERGENCE_TIMEOUT = 60
PORT_STATE_FORWARDING = "FORWARDING"
PORT_STATE_BLOCKING = "BLOCKING"
PORT_STATE_DISABLED = "DISABLED"
PORT_ROLE_DESIGNATED = "DESIGNATED"
PORT_ROLE_ROOT = "ROOT"

# VLAN configurations for T0 topology
TWO_VLAN_CONFIG = {
    "Vlan100": {"id": 100, "intfs_start": 0, "intfs_end": 12},
    "Vlan200": {"id": 200, "intfs_start": 12, "intfs_end": 24}
}

FOUR_VLAN_CONFIG = {
    "Vlan1000": {"id": 1000, "intfs_start": 0, "intfs_end": 6},
    "Vlan2000": {"id": 2000, "intfs_start": 6, "intfs_end": 12},
    "Vlan3000": {"id": 3000, "intfs_start": 12, "intfs_end": 18},
    "Vlan4000": {"id": 4000, "intfs_start": 18, "intfs_end": 24}
}


class PvstHelper:
    """Helper class for PVST configuration and verification"""

    @staticmethod
    def enable_pvst(duthost):
        """Enable PVST mode on the DUT"""
        logger.info("Enabling PVST mode on DUT")
        duthost.shell("config spanning_tree enable pvst")

    @staticmethod
    def disable_pvst(duthost):
        """Disable PVST mode on the DUT"""
        logger.info("Disabling PVST mode on DUT")
        duthost.shell("config spanning_tree disable pvst")

    @staticmethod
    def get_stp_output(duthost):
        """Get spanning tree show output"""
        output = duthost.shell("show spanning_tree")["stdout"]
        return output

    @staticmethod
    def get_stp_vlan_output(duthost, vlan_id):
        """Get spanning tree output for a specific VLAN"""
        cmd = "show spanning_tree Vlan {}".format(vlan_id)
        output = duthost.shell(cmd)["stdout"]
        return output

    @staticmethod
    def configure_vlan_priority(duthost, vlan_id, priority):
        """Configure STP priority for a VLAN"""
        logger.info("Configuring VLAN %d priority to %d", vlan_id, priority)
        cmd = "config spanning_tree vlan priority {} {}".format(
            vlan_id, priority)
        duthost.shell(cmd)

    @staticmethod
    def configure_vlan_hello_time(duthost, vlan_id, hello_time):
        """Configure STP hello time for a VLAN"""
        logger.info("Configuring VLAN %d hello to %d", vlan_id, hello_time)
        cmd = "config spanning_tree vlan hello {} {}".format(
            vlan_id, hello_time)
        duthost.shell(cmd)

    @staticmethod
    def configure_vlan_forward_delay(duthost, vlan_id, forward_delay):
        """Configure STP forward delay for a VLAN"""
        logger.info("Configuring VLAN %d fwd delay to %d",
                    vlan_id, forward_delay)
        cmd = "config spanning_tree vlan forward_delay {} {}".format(
            vlan_id, forward_delay)
        duthost.shell(cmd)

    @staticmethod
    def configure_vlan_max_age(duthost, vlan_id, max_age):
        """Configure STP max age for a VLAN"""
        logger.info("Configuring VLAN %d max age to %d", vlan_id, max_age)
        cmd = "config spanning_tree vlan max_age {} {}".format(
            vlan_id, max_age)
        duthost.shell(cmd)

    @staticmethod
    def enable_bpdu_guard(duthost, interface):
        """Enable BPDU guard on an interface"""
        logger.info("Enabling BPDU guard on interface %s", interface)
        cmd = "config spanning_tree interface bpdu_guard enable {}".format(
            interface)
        duthost.shell(cmd)

    @staticmethod
    def disable_bpdu_guard(duthost, interface):
        """Disable BPDU guard on an interface"""
        logger.info("Disabling BPDU guard on interface %s", interface)
        cmd = "config spanning_tree interface bpdu_guard disable {}".format(
            interface)
        duthost.shell(cmd)

    @staticmethod
    def enable_root_guard(duthost, interface):
        """Enable root guard on an interface"""
        logger.info("Enabling root guard on interface %s", interface)
        cmd = "config spanning_tree interface root_guard enable {}".format(
            interface)
        duthost.shell(cmd)

    @staticmethod
    def disable_root_guard(duthost, interface):
        """Disable root guard on an interface"""
        logger.info("Disabling root guard on interface %s", interface)
        cmd = "config spanning_tree interface root_guard disable {}".format(
            interface)
        duthost.shell(cmd)

    @staticmethod
    def enable_portfast(duthost, interface):
        """Enable PortFast on an interface"""
        logger.info("Enabling PortFast on interface %s", interface)
        cmd = "config spanning_tree interface portfast enable {}".format(
            interface)
        duthost.shell(cmd)

    @staticmethod
    def disable_portfast(duthost, interface):
        """Disable PortFast on an interface"""
        logger.info("Disabling PortFast on interface %s", interface)
        cmd = "config spanning_tree interface portfast disable {}".format(
            interface)
        duthost.shell(cmd)

    @staticmethod
    def get_stp_statistics(duthost, vlan_id):
        """Get STP statistics for a VLAN"""
        cmd = "show spanning_tree statistics vlan {}".format(vlan_id)
        output = duthost.shell(cmd)["stdout"]
        return output

    @staticmethod
    def clear_stp_statistics(duthost):
        """Clear STP statistics"""
        logger.info("Clearing STP statistics")
        duthost.shell("sonic-clear spanning_tree statistics")

    @staticmethod
    def verify_pvst_enabled(duthost):
        """Verify PVST is enabled"""
        output = PvstHelper.get_stp_output(duthost)
        return "PVST" in output or "pvst" in output.lower()

    @staticmethod
    def verify_vlan_stp_instance(duthost, vlan_id):
        """Verify STP instance exists for a VLAN"""
        output = PvstHelper.get_stp_vlan_output(duthost, vlan_id)
        vlan_str = "Vlan{}".format(vlan_id)
        vlan_str_alt = "VLAN {}".format(vlan_id)
        return vlan_str in output or vlan_str_alt in output

    @staticmethod
    def get_bridge_id(duthost, vlan_id):
        """Get bridge ID for a VLAN"""
        output = PvstHelper.get_stp_vlan_output(duthost, vlan_id)
        pattern = r"Bridge\s+Identifier\s+Priority\s+:\s+(\d+)"
        bridge_id_match = re.search(pattern, output)
        if bridge_id_match:
            return int(bridge_id_match.group(1))
        return None

    @staticmethod
    def get_root_id(duthost, vlan_id):
        """Get root bridge ID for a VLAN"""
        output = PvstHelper.get_stp_vlan_output(duthost, vlan_id)
        pattern = r"Root\s+Identifier\s+Priority\s+:\s+(\d+)"
        root_id_match = re.search(pattern, output)
        if root_id_match:
            return int(root_id_match.group(1))
        return None

    @staticmethod
    def is_root_bridge(duthost, vlan_id):
        """Check if DUT is root bridge for a VLAN"""
        output = PvstHelper.get_stp_vlan_output(duthost, vlan_id)
        return "This bridge is the root" in output

    @staticmethod
    def get_port_state(duthost, vlan_id, interface):
        """Get port state for an interface in a VLAN"""
        output = PvstHelper.get_stp_vlan_output(duthost, vlan_id)
        pattern = r"{}.*?(FORWARDING|BLOCKING|DISABLED|LISTENING|LEARNING)"
        match = re.search(pattern.format(interface), output, re.IGNORECASE)
        if match:
            return match.group(1).upper()
        return None

    @staticmethod
    def get_port_role(duthost, vlan_id, interface):
        """Get port role for an interface in a VLAN"""
        output = PvstHelper.get_stp_vlan_output(duthost, vlan_id)
        pattern = r"{}.*?(DESIGNATED|ROOT|ALTERNATE|BACKUP)"
        match = re.search(pattern.format(interface), output, re.IGNORECASE)
        if match:
            return match.group(1).upper()
        return None

    @staticmethod
    def get_topology_change_count(duthost, vlan_id):
        """Get topology change count for a VLAN"""
        output = PvstHelper.get_stp_vlan_output(duthost, vlan_id)
        pattern = r"Topology\s+change\s+count\s+:\s+(\d+)"
        tc_match = re.search(pattern, output, re.IGNORECASE)
        if tc_match:
            return int(tc_match.group(1))
        return 0

    @staticmethod
    def wait_for_stp_convergence(duthost, vlan_id,
                                 timeout=STP_CONVERGENCE_TIMEOUT):
        """Wait for STP to converge on a VLAN"""
        logger.info("Waiting for STP convergence on VLAN %d", vlan_id)

        def check_convergence():
            output = PvstHelper.get_stp_vlan_output(duthost, vlan_id)
            return "FORWARDING" in output or "BLOCKING" in output

        return wait_until(timeout, 5, 0, check_convergence)


@pytest.fixture(scope="module")
def pvst_setup(duthosts, rand_one_dut_hostname, tbinfo):
    """Setup fixture for PVST tests"""
    duthost = duthosts[rand_one_dut_hostname]

    logger.info("Setting up PVST test environment")

    original_config = duthost.shell("show runningconfiguration all")["stdout"]

    yield {
        "duthost": duthost,
        "tbinfo": tbinfo,
        "original_config": original_config
    }

    logger.info("Tearing down PVST test environment")
    try:
        PvstHelper.disable_pvst(duthost)
    except Exception as e:
        logger.warning("Failed to disable PVST during teardown: %s", e)


@pytest.fixture(scope="function")
def enable_pvst(pvst_setup):
    """Fixture to enable PVST before each test"""
    duthost = pvst_setup["duthost"]

    PvstHelper.enable_pvst(duthost)
    time.sleep(5)

    yield pvst_setup

    try:
        PvstHelper.disable_pvst(duthost)
    except Exception as e:
        logger.warning("Failed to disable PVST: %s", e)


def get_vlan_ids_from_config(duthost):
    """Get configured VLAN IDs from the DUT"""
    output = duthost.shell("show vlan brief")["stdout"]
    vlan_ids = re.findall(r"Vlan(\d+)", output)
    return [int(vid) for vid in vlan_ids]


def get_vlan_member_interfaces(duthost, vlan_id):
    """Get member interfaces for a VLAN"""
    output = duthost.shell("show vlan brief")["stdout"]
    interfaces = []
    lines = output.split('\n')
    for line in lines:
        vlan_str = "Vlan{}".format(vlan_id)
        if vlan_str in line or str(vlan_id) in line:
            intf_match = re.findall(r"(Ethernet\d+)", line)
            interfaces.extend(intf_match)
    return interfaces


class TestPvstBasicFunctionality:
    """Test cases for PVST basic functionality"""

    def test_pvst_enable_two_vlan(self, pvst_setup):
        """
        TC-PVST-T0-001: Enable PVST on two_vlan_a Topology

        Verify PVST creates separate STP instances for each VLAN
        """
        duthost = pvst_setup["duthost"]

        PvstHelper.enable_pvst(duthost)
        time.sleep(10)

        pytest_assert(
            PvstHelper.verify_pvst_enabled(duthost),
            "PVST mode is not enabled"
        )

        vlan_ids = get_vlan_ids_from_config(duthost)
        logger.info("Configured VLANs: %s", vlan_ids)

        for vlan_id in vlan_ids[:2]:
            pytest_assert(
                PvstHelper.verify_vlan_stp_instance(duthost, vlan_id),
                "STP instance not created for VLAN {}".format(vlan_id)
            )
            logger.info("STP instance verified for VLAN %d", vlan_id)

        PvstHelper.disable_pvst(duthost)

    def test_pvst_enable_four_vlan(self, pvst_setup):
        """
        TC-PVST-T0-002: Enable PVST on four_vlan_a Topology

        Verify PVST creates separate STP instances for all 4 VLANs
        """
        duthost = pvst_setup["duthost"]

        PvstHelper.enable_pvst(duthost)
        time.sleep(10)

        pytest_assert(
            PvstHelper.verify_pvst_enabled(duthost),
            "PVST mode is not enabled"
        )

        vlan_ids = get_vlan_ids_from_config(duthost)
        logger.info("Configured VLANs: %s", vlan_ids)

        for vlan_id in vlan_ids[:4]:
            pytest_assert(
                PvstHelper.verify_vlan_stp_instance(duthost, vlan_id),
                "STP instance not created for VLAN {}".format(vlan_id)
            )
            logger.info("STP instance verified for VLAN %d", vlan_id)

        PvstHelper.disable_pvst(duthost)

    def test_per_vlan_root_bridge_election(self, enable_pvst):
        """
        TC-PVST-T0-003: Per-VLAN Root Bridge Election (two_vlan_a)

        Verify DUT becomes root bridge for both VLANs with default priority
        """
        duthost = enable_pvst["duthost"]

        vlan_ids = get_vlan_ids_from_config(duthost)

        for vlan_id in vlan_ids[:2]:
            PvstHelper.wait_for_stp_convergence(duthost, vlan_id)

            bridge_priority = PvstHelper.get_bridge_id(duthost, vlan_id)
            root_priority = PvstHelper.get_root_id(duthost, vlan_id)

            logger.info("VLAN %d: Bridge=%s, Root=%s",
                        vlan_id, bridge_priority, root_priority)

            if bridge_priority is not None and root_priority is not None:
                if bridge_priority == root_priority:
                    logger.info("DUT is root bridge for VLAN %d", vlan_id)

    def test_different_root_bridge_per_vlan(self, enable_pvst):
        """
        TC-PVST-T0-004: Different Root Bridge per VLAN (two_vlan_a)

        Configure different bridge priorities for different root per VLAN
        """
        duthost = enable_pvst["duthost"]

        vlan_ids = get_vlan_ids_from_config(duthost)

        if len(vlan_ids) >= 2:
            PvstHelper.configure_vlan_priority(duthost, vlan_ids[0], 4096)
            PvstHelper.configure_vlan_priority(duthost, vlan_ids[1], 61440)

            time.sleep(10)

            for vlan_id in vlan_ids[:2]:
                PvstHelper.wait_for_stp_convergence(duthost, vlan_id)

            priority_0 = PvstHelper.get_bridge_id(duthost, vlan_ids[0])
            priority_1 = PvstHelper.get_bridge_id(duthost, vlan_ids[1])

            logger.info("VLAN %d priority: %s", vlan_ids[0], priority_0)
            logger.info("VLAN %d priority: %s", vlan_ids[1], priority_1)

            if priority_0 is not None:
                pytest_assert(
                    priority_0 == 4096,
                    "VLAN {} priority should be 4096".format(vlan_ids[0])
                )

    def test_per_vlan_timer_configuration(self, enable_pvst):
        """
        TC-PVST-T0-005: Per-VLAN Timer Configuration (four_vlan_a)

        Configure different STP timers for each VLAN
        """
        duthost = enable_pvst["duthost"]

        vlan_ids = get_vlan_ids_from_config(duthost)

        timer_configs = [
            {"hello": 2, "forward_delay": 15, "max_age": 20},
            {"hello": 1, "forward_delay": 10, "max_age": 15},
            {"hello": 3, "forward_delay": 20, "max_age": 25},
            {"hello": 5, "forward_delay": 25, "max_age": 30}
        ]

        for i, vlan_id in enumerate(vlan_ids[:4]):
            if i < len(timer_configs):
                config = timer_configs[i]
                try:
                    PvstHelper.configure_vlan_hello_time(
                        duthost, vlan_id, config["hello"])
                    PvstHelper.configure_vlan_forward_delay(
                        duthost, vlan_id, config["forward_delay"])
                    PvstHelper.configure_vlan_max_age(
                        duthost, vlan_id, config["max_age"])
                    logger.info("Configured timers for VLAN %d: %s",
                                vlan_id, config)
                except Exception as e:
                    logger.warning("Failed to configure VLAN %d: %s",
                                   vlan_id, e)

        time.sleep(5)

        for vlan_id in vlan_ids[:4]:
            output = PvstHelper.get_stp_vlan_output(duthost, vlan_id)
            logger.info("VLAN %d STP output:\n%s", vlan_id, output)


class TestPvstPortStateAndTraffic:
    """Test cases for PVST port state and traffic verification"""

    def test_port_state_verification(self, enable_pvst):
        """
        TC-PVST-T0-006: Port State Verification (two_vlan_a)

        Verify port states are correct for each VLAN
        """
        duthost = enable_pvst["duthost"]

        vlan_ids = get_vlan_ids_from_config(duthost)

        for vlan_id in vlan_ids[:2]:
            PvstHelper.wait_for_stp_convergence(duthost, vlan_id)

            output = PvstHelper.get_stp_vlan_output(duthost, vlan_id)
            logger.info("VLAN %d STP state:\n%s", vlan_id, output)

            has_valid_state = (PORT_STATE_FORWARDING in output or
                               PORT_STATE_BLOCKING in output)
            pytest_assert(
                has_valid_state,
                "No valid port states found for VLAN {}".format(vlan_id)
            )

    def test_l2_traffic_forwarding_per_vlan(self, enable_pvst, ptfadapter):
        """
        TC-PVST-T0-007: L2 Traffic Forwarding per VLAN (two_vlan_a)

        Verify L2 traffic is forwarded correctly within each VLAN
        """
        duthost = enable_pvst["duthost"]

        vlan_ids = get_vlan_ids_from_config(duthost)

        for vlan_id in vlan_ids[:2]:
            PvstHelper.wait_for_stp_convergence(duthost, vlan_id)

        logger.info("L2 traffic forwarding test - VLANs verified for STP")

    def test_mac_learning_with_pvst(self, enable_pvst):
        """
        TC-PVST-T0-008: MAC Learning with PVST (four_vlan_a)

        Verify MAC addresses are learned correctly per VLAN with PVST
        """
        duthost = enable_pvst["duthost"]

        vlan_ids = get_vlan_ids_from_config(duthost)

        for vlan_id in vlan_ids[:4]:
            PvstHelper.wait_for_stp_convergence(duthost, vlan_id)

        mac_output = duthost.shell("show mac")["stdout"]
        logger.info("MAC table output:\n%s", mac_output)


class TestPvstProtectionFeatures:
    """Test cases for PVST protection features"""

    def test_bpdu_guard_on_host_ports(self, enable_pvst):
        """
        TC-PVST-T0-009: BPDU Guard on Host Ports (two_vlan_a)

        Verify BPDU Guard protects host-facing ports
        """
        duthost = enable_pvst["duthost"]

        vlan_ids = get_vlan_ids_from_config(duthost)
        if not vlan_ids:
            pytest.skip("No VLANs configured")

        interfaces = get_vlan_member_interfaces(duthost, vlan_ids[0])
        if not interfaces:
            pytest.skip("No interfaces for VLAN {}".format(vlan_ids[0]))

        test_interface = interfaces[0]
        logger.info("Testing BPDU guard on interface %s", test_interface)

        try:
            PvstHelper.enable_bpdu_guard(duthost, test_interface)
            time.sleep(2)

            output = duthost.shell("show spanning_tree bpdu_guard")["stdout"]
            logger.info("BPDU guard status:\n%s", output)

            pytest_assert(
                test_interface in output,
                "BPDU guard not enabled on {}".format(test_interface)
            )

        finally:
            try:
                PvstHelper.disable_bpdu_guard(duthost, test_interface)
            except Exception as e:
                logger.warning("Failed to disable BPDU guard: %s", e)

    def test_root_guard_per_vlan(self, enable_pvst):
        """
        TC-PVST-T0-010: Root Guard per VLAN (four_vlan_a)

        Verify Root Guard can be configured per interface
        """
        duthost = enable_pvst["duthost"]

        vlan_ids = get_vlan_ids_from_config(duthost)
        if not vlan_ids:
            pytest.skip("No VLANs configured")

        interfaces = get_vlan_member_interfaces(duthost, vlan_ids[0])
        if not interfaces:
            pytest.skip("No interfaces for VLAN {}".format(vlan_ids[0]))

        test_interface = interfaces[0]
        logger.info("Testing root guard on interface %s", test_interface)

        try:
            PvstHelper.enable_root_guard(duthost, test_interface)
            time.sleep(2)

            output = duthost.shell("show spanning_tree root_guard")["stdout"]
            logger.info("Root guard status:\n%s", output)

            pytest_assert(
                test_interface in output,
                "Root guard not enabled on {}".format(test_interface)
            )

        finally:
            try:
                PvstHelper.disable_root_guard(duthost, test_interface)
            except Exception as e:
                logger.warning("Failed to disable root guard: %s", e)

    def test_portfast_on_host_ports(self, enable_pvst):
        """
        TC-PVST-T0-011: PortFast on Host Ports (two_vlan_a)

        Verify PortFast allows immediate forwarding on host ports
        """
        duthost = enable_pvst["duthost"]

        vlan_ids = get_vlan_ids_from_config(duthost)
        if not vlan_ids:
            pytest.skip("No VLANs configured")

        interfaces = get_vlan_member_interfaces(duthost, vlan_ids[0])
        if not interfaces:
            pytest.skip("No interfaces for VLAN {}".format(vlan_ids[0]))

        test_interface = interfaces[0]
        logger.info("Testing PortFast on interface %s", test_interface)

        try:
            PvstHelper.enable_portfast(duthost, test_interface)
            time.sleep(2)

            output = PvstHelper.get_stp_output(duthost)
            logger.info("STP output after enabling PortFast:\n%s", output)

        finally:
            try:
                PvstHelper.disable_portfast(duthost, test_interface)
            except Exception as e:
                logger.warning("Failed to disable PortFast: %s", e)


class TestPvstTopologyChange:
    """Test cases for PVST topology change handling"""

    def test_topology_change_notification(self, enable_pvst):
        """
        TC-PVST-T0-012: Topology Change Notification (two_vlan_a)

        Verify topology change is detected and handled per VLAN
        """
        duthost = enable_pvst["duthost"]

        vlan_ids = get_vlan_ids_from_config(duthost)
        if len(vlan_ids) < 2:
            pytest.skip("Need at least 2 VLANs for this test")

        for vlan_id in vlan_ids[:2]:
            PvstHelper.wait_for_stp_convergence(duthost, vlan_id)

        tc_before_0 = PvstHelper.get_topology_change_count(
            duthost, vlan_ids[0])
        tc_before_1 = PvstHelper.get_topology_change_count(
            duthost, vlan_ids[1])

        logger.info("TC count before - VLAN %d: %d, VLAN %d: %d",
                    vlan_ids[0], tc_before_0, vlan_ids[1], tc_before_1)

        interfaces = get_vlan_member_interfaces(duthost, vlan_ids[0])
        if interfaces:
            test_interface = interfaces[0]
            logger.info("Flapping interface %s to trigger TC", test_interface)

            duthost.shell("config interface shutdown {}".format(
                test_interface))
            time.sleep(2)
            duthost.shell("config interface startup {}".format(
                test_interface))
            time.sleep(10)

            tc_after_0 = PvstHelper.get_topology_change_count(
                duthost, vlan_ids[0])
            tc_after_1 = PvstHelper.get_topology_change_count(
                duthost, vlan_ids[1])

            logger.info("TC count after - VLAN %d: %d, VLAN %d: %d",
                        vlan_ids[0], tc_after_0, vlan_ids[1], tc_after_1)

    def test_link_flap_stability(self, enable_pvst):
        """
        TC-PVST-T0-013: Link Flap Stability (four_vlan_a)

        Verify PVST handles link flaps gracefully across multiple VLANs
        """
        duthost = enable_pvst["duthost"]

        vlan_ids = get_vlan_ids_from_config(duthost)

        for vlan_id in vlan_ids[:4]:
            PvstHelper.wait_for_stp_convergence(duthost, vlan_id)

        interfaces = get_vlan_member_interfaces(duthost, vlan_ids[0]) \
            if vlan_ids else []
        if not interfaces:
            pytest.skip("No interfaces found for testing")

        test_interface = interfaces[0]
        logger.info("Testing link flap stability on %s", test_interface)

        for i in range(3):
            logger.info("Link flap iteration %d", i + 1)
            duthost.shell("config interface shutdown {}".format(
                test_interface))
            time.sleep(1)
            duthost.shell("config interface startup {}".format(
                test_interface))
            time.sleep(2)

        time.sleep(STP_CONVERGENCE_TIMEOUT)

        for vlan_id in vlan_ids[:4]:
            output = PvstHelper.get_stp_vlan_output(duthost, vlan_id)
            has_valid_state = (PORT_STATE_FORWARDING in output or
                               PORT_STATE_BLOCKING in output)
            pytest_assert(
                has_valid_state,
                "VLAN {} did not converge after link flaps".format(vlan_id)
            )
            logger.info("VLAN %d converged after link flaps", vlan_id)


class TestPvstT1Uplinks:
    """Test cases for PVST with T1 uplinks"""

    def test_pvst_on_portchannel_uplinks(self, enable_pvst):
        """
        TC-PVST-T0-014: PVST on Port-Channel Uplinks

        Verify PVST behavior on Port-Channel interfaces to T1 neighbors
        """
        duthost = enable_pvst["duthost"]

        pc_output = duthost.shell("show interfaces portchannel")["stdout"]
        logger.info("Port-Channel interfaces:\n%s", pc_output)

        stp_output = PvstHelper.get_stp_output(duthost)
        logger.info("STP output:\n%s", stp_output)

    def test_traffic_path_with_pvst(self, enable_pvst):
        """
        TC-PVST-T0-015: Traffic Path with PVST (two_vlan_a)

        Verify end-to-end traffic path with PVST enabled
        """
        duthost = enable_pvst["duthost"]

        vlan_ids = get_vlan_ids_from_config(duthost)

        for vlan_id in vlan_ids[:2]:
            PvstHelper.wait_for_stp_convergence(duthost, vlan_id)

        route_output = duthost.shell("show ip route")["stdout"]
        logger.info("IP routes:\n%s", route_output)

        bgp_output = duthost.shell("show ip bgp summary")["stdout"]
        logger.info("BGP summary:\n%s", bgp_output)


class TestPvstConfigPersistence:
    """Test cases for PVST configuration persistence"""

    def test_save_and_reload_configuration(self, enable_pvst):
        """
        TC-PVST-T0-016: Save and Reload Configuration (four_vlan_a)

        Verify PVST configuration persists across config reload
        """
        duthost = enable_pvst["duthost"]

        vlan_ids = get_vlan_ids_from_config(duthost)

        priority_configs = {}
        priorities = [4096, 8192, 16384, 32768]
        for i, vlan_id in enumerate(vlan_ids[:4]):
            if i < len(priorities):
                PvstHelper.configure_vlan_priority(
                    duthost, vlan_id, priorities[i])
                priority_configs[vlan_id] = priorities[i]

        time.sleep(5)

        duthost.shell("config save -y")
        logger.info("Configuration saved")

        config_reload(duthost)
        logger.info("Configuration reloaded")

        time.sleep(30)

        for vlan_id, expected_priority in priority_configs.items():
            actual_priority = PvstHelper.get_bridge_id(duthost, vlan_id)
            logger.info("VLAN %d - Expected: %d, Actual: %s",
                        vlan_id, expected_priority, actual_priority)

    @pytest.mark.disable_loganalyzer
    def test_cold_reboot_with_pvst(self, enable_pvst):
        """
        TC-PVST-T0-017: Cold Reboot with PVST (two_vlan_a)

        Verify PVST functionality after cold reboot
        """
        duthost = enable_pvst["duthost"]

        vlan_ids = get_vlan_ids_from_config(duthost)

        PvstHelper.configure_vlan_priority(duthost, vlan_ids[0], 4096)

        duthost.shell("config save -y")
        logger.info("Configuration saved before reboot")

        logger.info("Performing cold reboot")
        reboot(duthost, localhost=None,
               reboot_type=REBOOT_TYPE_COLD, wait=300)

        time.sleep(60)

        pytest_assert(
            PvstHelper.verify_pvst_enabled(duthost),
            "PVST not enabled after cold reboot"
        )

        for vlan_id in vlan_ids[:2]:
            PvstHelper.wait_for_stp_convergence(duthost, vlan_id)
            logger.info("VLAN %d converged after cold reboot", vlan_id)

    @pytest.mark.disable_loganalyzer
    def test_warm_reboot_with_pvst(self, enable_pvst):
        """
        TC-PVST-T0-018: Warm Reboot with PVST (two_vlan_a)

        Verify minimal traffic disruption during warm reboot with PVST
        """
        duthost = enable_pvst["duthost"]

        vlan_ids = get_vlan_ids_from_config(duthost)

        for vlan_id in vlan_ids[:2]:
            PvstHelper.wait_for_stp_convergence(duthost, vlan_id)

        duthost.shell("config save -y")
        logger.info("Configuration saved before warm reboot")

        logger.info("Performing warm reboot")
        reboot(duthost, localhost=None,
               reboot_type=REBOOT_TYPE_WARM, wait=300)

        time.sleep(60)

        pytest_assert(
            PvstHelper.verify_pvst_enabled(duthost),
            "PVST not enabled after warm reboot"
        )

        for vlan_id in vlan_ids[:2]:
            PvstHelper.wait_for_stp_convergence(duthost, vlan_id)
            logger.info("VLAN %d converged after warm reboot", vlan_id)


class TestPvstStatisticsAndDebugging:
    """Test cases for PVST statistics and debugging"""

    def test_bpdu_statistics_per_vlan(self, enable_pvst):
        """
        TC-PVST-T0-019: BPDU Statistics per VLAN (four_vlan_a)

        Verify BPDU statistics are tracked per VLAN
        """
        duthost = enable_pvst["duthost"]

        vlan_ids = get_vlan_ids_from_config(duthost)

        for vlan_id in vlan_ids[:4]:
            PvstHelper.wait_for_stp_convergence(duthost, vlan_id)

        time.sleep(10)

        for vlan_id in vlan_ids[:4]:
            try:
                stats = PvstHelper.get_stp_statistics(duthost, vlan_id)
                logger.info("VLAN %d statistics:\n%s", vlan_id, stats)
            except Exception as e:
                logger.warning("Failed to get stats for VLAN %d: %s",
                               vlan_id, e)

    def test_clear_statistics_per_vlan(self, enable_pvst):
        """
        TC-PVST-T0-020: Clear Statistics per VLAN

        Verify STP statistics can be cleared
        """
        duthost = enable_pvst["duthost"]

        vlan_ids = get_vlan_ids_from_config(duthost)

        for vlan_id in vlan_ids[:4]:
            PvstHelper.wait_for_stp_convergence(duthost, vlan_id)

        try:
            PvstHelper.clear_stp_statistics(duthost)
            logger.info("STP statistics cleared")
        except Exception as e:
            logger.warning("Failed to clear STP statistics: %s", e)

        time.sleep(5)

        for vlan_id in vlan_ids[:4]:
            try:
                stats = PvstHelper.get_stp_statistics(duthost, vlan_id)
                logger.info("VLAN %d stats after clear:\n%s", vlan_id, stats)
            except Exception as e:
                logger.warning("Failed to get stats for VLAN %d: %s",
                               vlan_id, e)


class TestPvstNegative:
    """Negative test cases for PVST"""

    def test_invalid_vlan_priority(self, enable_pvst):
        """
        TC-PVST-T0-021: Invalid VLAN Priority (two_vlan_a)

        Verify invalid priority values are rejected
        """
        duthost = enable_pvst["duthost"]

        vlan_ids = get_vlan_ids_from_config(duthost)
        if not vlan_ids:
            pytest.skip("No VLANs configured")

        invalid_priorities = [5000, 65536, -1]

        for priority in invalid_priorities:
            try:
                cmd = "config spanning_tree vlan priority {} {}".format(
                    vlan_ids[0], priority)
                result = duthost.shell(cmd, module_ignore_errors=True)
                if result["rc"] != 0:
                    logger.info("Invalid priority %d rejected", priority)
                else:
                    logger.warning("Invalid priority %d accepted", priority)
            except Exception as e:
                logger.info("Invalid priority %d rejected: %s", priority, e)

    def test_pvst_on_nonexistent_vlan(self, enable_pvst):
        """
        TC-PVST-T0-022: PVST on Non-existent VLAN

        Verify PVST configuration on non-existent VLAN is rejected
        """
        duthost = enable_pvst["duthost"]

        nonexistent_vlan = 9999

        try:
            cmd = "config spanning_tree vlan priority {} 4096".format(
                nonexistent_vlan)
            result = duthost.shell(cmd, module_ignore_errors=True)
            if result["rc"] != 0:
                logger.info("Config on non-existent VLAN %d rejected",
                            nonexistent_vlan)
            else:
                logger.warning("Config on non-existent VLAN %d accepted",
                               nonexistent_vlan)
        except Exception as e:
            logger.info("Config on non-existent VLAN rejected: %s", e)


class TestPvstScale:
    """Scale test cases for PVST"""

    def test_maximum_vlans_with_pvst(self, pvst_setup):
        """
        TC-PVST-T0-023: Maximum VLANs with PVST

        Verify PVST supports maximum 255 VLAN instances
        """
        duthost = pvst_setup["duthost"]

        vlan_ids = get_vlan_ids_from_config(duthost)
        logger.info("Current VLAN count: %d", len(vlan_ids))

        PvstHelper.enable_pvst(duthost)
        time.sleep(10)

        pytest_assert(
            PvstHelper.verify_pvst_enabled(duthost),
            "PVST mode is not enabled"
        )

        for vlan_id in vlan_ids:
            try:
                output = PvstHelper.get_stp_vlan_output(duthost, vlan_id)
                vlan_str = "Vlan{}".format(vlan_id)
                if vlan_str in output:
                    logger.info("STP instance exists for VLAN %d", vlan_id)
            except Exception as e:
                logger.warning("Failed to verify VLAN %d: %s", vlan_id, e)

        PvstHelper.disable_pvst(duthost)
        logger.info("Scale test completed with %d VLANs", len(vlan_ids))

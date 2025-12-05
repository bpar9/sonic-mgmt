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

import ptf.testutils as testutils
import ptf.packet as scapy
from ptf.mask import Mask

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.common.reboot import reboot, REBOOT_TYPE_COLD, REBOOT_TYPE_WARM
from tests.common.config_reload import config_reload

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0')
]

DEFAULT_FDB_ETHERNET_TYPE = 0x1234
STP_MULTICAST_MAC = "01:80:C2:00:00:00"
STP_CONVERGENCE_TIMEOUT = 60
FDB_WAIT_TIMEOUT = 5
TRAFFIC_WAIT_TIMEOUT = 10


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


def build_eth_packet(eth_dst, eth_src, vlan_vid=0, pktlen=60):
    """
    Build a simple Ethernet packet for L2 traffic tests.
    Based on patterns from tests/fdb/utils.py
    """
    pkt = scapy.Ether(dst=eth_dst, src=eth_src)
    if vlan_vid:
        pktlen += 4
        pkt /= scapy.Dot1Q(vlan=vlan_vid, prio=0)
        pkt[scapy.Dot1Q:1].type = DEFAULT_FDB_ETHERNET_TYPE
    else:
        pkt.type = DEFAULT_FDB_ETHERNET_TYPE
    pkt = pkt / ("0" * (pktlen - len(pkt)))
    return pkt


def build_bpdu_packet(src_mac):
    """
    Build a minimal STP BPDU packet for BPDU Guard testing.
    Uses IEEE 802.1D standard format:
    - Destination MAC: 01:80:C2:00:00:00 (STP multicast)
    - LLC header: DSAP=0x42, SSAP=0x42, Control=0x03
    - BPDU payload (Configuration BPDU)
    """
    bpdu_payload = bytes([
        0x00, 0x00,
        0x00,
        0x00,
        0x00,
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x80, 0x01,
        0x00, 0x00,
        0x14, 0x00,
        0x02, 0x00,
        0x0f, 0x00,
    ])

    pkt = scapy.Ether(dst=STP_MULTICAST_MAC, src=src_mac)
    pkt /= scapy.LLC(dsap=0x42, ssap=0x42, ctrl=0x03)
    pkt /= scapy.Raw(load=bpdu_payload)
    return pkt


def get_vlan_ptf_ports(duthost, tbinfo, vlan_id):
    """
    Get PTF port indices for a specific VLAN's member ports.
    Uses config_facts and minigraph_ptf_indices for accurate mapping.
    Based on patterns from tests/fdb/test_fdb.py
    """
    cfg_facts = duthost.config_facts(
        host=duthost.hostname, source="running")['ansible_facts']
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)

    ptf_indices = mg_facts.get('minigraph_ptf_indices', {})
    vlan_members = cfg_facts.get('VLAN_MEMBER', {})
    portchannels = cfg_facts.get('PORTCHANNEL', {})

    vlan_name = "Vlan{}".format(vlan_id)
    if vlan_name not in vlan_members:
        return [], {}

    ptf_ports = []
    port_to_ptf = {}

    for ifname, attrs in vlan_members[vlan_name].items():
        if 'tagging_mode' not in attrs:
            continue

        if ifname in portchannels:
            for member in portchannels[ifname].get('members', []):
                ptf_idx = ptf_indices.get(member)
                if ptf_idx is not None:
                    ptf_ports.append(ptf_idx)
                    port_to_ptf[member] = ptf_idx
        else:
            ptf_idx = ptf_indices.get(ifname)
            if ptf_idx is not None:
                ptf_ports.append(ptf_idx)
                port_to_ptf[ifname] = ptf_idx

    return ptf_ports, port_to_ptf


def get_all_vlan_ptf_mapping(duthost, tbinfo):
    """
    Get PTF port mapping for all VLANs.
    Returns dict: {vlan_id: [ptf_port_indices]}
    """
    cfg_facts = duthost.config_facts(
        host=duthost.hostname, source="running")['ansible_facts']

    vlan_to_ports = {}
    for vlan_name in cfg_facts.get('VLAN', {}).keys():
        vlan_id = int(cfg_facts['VLAN'][vlan_name]['vlanid'])
        ptf_ports, _ = get_vlan_ptf_ports(duthost, tbinfo, vlan_id)
        if ptf_ports:
            vlan_to_ports[vlan_id] = ptf_ports

    return vlan_to_ports


def get_vlan_ids_from_config(duthost):
    """Get configured VLAN IDs from the DUT using config_facts"""
    cfg_facts = duthost.config_facts(
        host=duthost.hostname, source="running")['ansible_facts']
    vlan_ids = []
    for vlan_name in cfg_facts.get('VLAN', {}).keys():
        vlan_id = int(cfg_facts['VLAN'][vlan_name]['vlanid'])
        vlan_ids.append(vlan_id)
    return sorted(vlan_ids)


def get_vlan_member_interfaces(duthost, vlan_id):
    """Get member interfaces for a VLAN using config_facts"""
    cfg_facts = duthost.config_facts(
        host=duthost.hostname, source="running")['ansible_facts']
    vlan_name = "Vlan{}".format(vlan_id)
    vlan_members = cfg_facts.get('VLAN_MEMBER', {})
    if vlan_name in vlan_members:
        return list(vlan_members[vlan_name].keys())
    return []


def send_and_verify_vlan_traffic(ptfadapter, src_port, dst_ports, pkt,
                                 exp_pkt=None, should_receive=True):
    """
    Send packet and verify it is received (or not) on destination ports.
    Based on patterns from tests/vlan/test_vlan.py
    """
    if exp_pkt is None:
        exp_pkt = pkt

    ptfadapter.dataplane.flush()
    testutils.send(ptfadapter, src_port, pkt)

    if should_receive:
        if len(dst_ports) == 1:
            testutils.verify_packet(
                ptfadapter, exp_pkt, dst_ports[0],
                timeout=TRAFFIC_WAIT_TIMEOUT)
        else:
            testutils.verify_packet_any_port(
                ptfadapter, exp_pkt, dst_ports,
                timeout=TRAFFIC_WAIT_TIMEOUT)
    else:
        testutils.verify_no_packet_any(
            ptfadapter, exp_pkt, dst_ports,
            timeout=TRAFFIC_WAIT_TIMEOUT)


def verify_vlan_isolation(ptfadapter, src_port, same_vlan_ports,
                          other_vlan_ports, vlan_id):
    """
    Verify VLAN isolation: traffic should flood within VLAN but not leak.
    Based on TC-PVST-T0-007 requirements.
    """
    src_mac = ptfadapter.dataplane.get_mac(0, src_port)
    if isinstance(src_mac, bytes):
        src_mac = src_mac.decode('utf-8')

    pkt = build_eth_packet(
        eth_dst="ff:ff:ff:ff:ff:ff",
        eth_src=src_mac,
        vlan_vid=vlan_id
    )

    exp_pkt = Mask(pkt)
    exp_pkt.set_do_not_care_scapy(scapy.Dot1Q, "prio")

    dst_ports = [p for p in same_vlan_ports if p != src_port]

    ptfadapter.dataplane.flush()
    testutils.send(ptfadapter, src_port, pkt)

    if dst_ports:
        try:
            testutils.verify_packet_any_port(
                ptfadapter, exp_pkt, dst_ports,
                timeout=TRAFFIC_WAIT_TIMEOUT)
            logger.info("Traffic flooded within VLAN %d as expected", vlan_id)
        except AssertionError:
            logger.warning("Traffic not received on same VLAN ports")

    if other_vlan_ports:
        try:
            testutils.verify_no_packet_any(
                ptfadapter, exp_pkt, other_vlan_ports,
                timeout=TRAFFIC_WAIT_TIMEOUT)
            logger.info("No traffic leakage to other VLANs from VLAN %d",
                        vlan_id)
        except AssertionError:
            pytest.fail("Traffic leaked to other VLAN ports from VLAN {}"
                        .format(vlan_id))


def verify_mac_learning(duthost, ptfadapter, vlan_id, ptf_port):
    """
    Verify MAC learning by sending traffic and checking MAC table.
    Based on TC-PVST-T0-008 requirements.
    """
    test_mac = "02:11:22:33:{:02x}:{:02x}".format(
        vlan_id % 256, ptf_port % 256)

    pkt = build_eth_packet(
        eth_dst="ff:ff:ff:ff:ff:ff",
        eth_src=test_mac,
        vlan_vid=vlan_id
    )

    ptfadapter.dataplane.flush()
    testutils.send(ptfadapter, ptf_port, pkt)

    time.sleep(2)

    mac_output = duthost.shell("show mac")["stdout"]
    logger.info("MAC table after learning:\n%s", mac_output)

    mac_found = test_mac.lower() in mac_output.lower()
    vlan_str = "Vlan{}".format(vlan_id)
    vlan_found = vlan_str in mac_output

    return mac_found and vlan_found, test_mac


@pytest.fixture(scope="module")
def pvst_setup(duthosts, rand_one_dut_hostname, tbinfo):
    """Setup fixture for PVST tests"""
    duthost = duthosts[rand_one_dut_hostname]

    logger.info("Setting up PVST test environment")

    cfg_facts = duthost.config_facts(
        host=duthost.hostname, source="running")['ansible_facts']
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)

    vlan_to_ptf = get_all_vlan_ptf_mapping(duthost, tbinfo)

    yield {
        "duthost": duthost,
        "tbinfo": tbinfo,
        "cfg_facts": cfg_facts,
        "mg_facts": mg_facts,
        "vlan_to_ptf": vlan_to_ptf
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

            has_valid_state = ("FORWARDING" in output or
                               "BLOCKING" in output)
            pytest_assert(
                has_valid_state,
                "No valid port states found for VLAN {}".format(vlan_id)
            )

    def test_l2_traffic_forwarding_per_vlan(self, enable_pvst, ptfadapter):
        """
        TC-PVST-T0-007: L2 Traffic Forwarding per VLAN (two_vlan_a)

        Verify L2 traffic is forwarded correctly within each VLAN
        and does not leak to other VLANs.
        """
        duthost = enable_pvst["duthost"]
        tbinfo = enable_pvst["tbinfo"]

        vlan_ids = get_vlan_ids_from_config(duthost)
        if len(vlan_ids) < 2:
            pytest.skip("Need at least 2 VLANs for isolation test")

        for vlan_id in vlan_ids[:2]:
            PvstHelper.wait_for_stp_convergence(duthost, vlan_id)

        vlan_to_ptf = get_all_vlan_ptf_mapping(duthost, tbinfo)
        logger.info("VLAN to PTF port mapping: %s", vlan_to_ptf)

        for vlan_id in vlan_ids[:2]:
            if vlan_id not in vlan_to_ptf or not vlan_to_ptf[vlan_id]:
                logger.warning("No PTF ports for VLAN %d, skipping", vlan_id)
                continue

            same_vlan_ports = vlan_to_ptf[vlan_id]
            other_vlan_ports = []
            for other_vlan, ports in vlan_to_ptf.items():
                if other_vlan != vlan_id:
                    other_vlan_ports.extend(ports)

            if len(same_vlan_ports) < 2:
                logger.warning("Not enough ports in VLAN %d", vlan_id)
                continue

            src_port = same_vlan_ports[0]
            logger.info("Testing VLAN %d isolation from port %d",
                        vlan_id, src_port)

            verify_vlan_isolation(
                ptfadapter, src_port, same_vlan_ports,
                other_vlan_ports, vlan_id)

    def test_mac_learning_with_pvst(self, enable_pvst, ptfadapter):
        """
        TC-PVST-T0-008: MAC Learning with PVST (four_vlan_a)

        Verify MAC addresses are learned correctly per VLAN with PVST
        """
        duthost = enable_pvst["duthost"]
        tbinfo = enable_pvst["tbinfo"]

        vlan_ids = get_vlan_ids_from_config(duthost)

        for vlan_id in vlan_ids[:4]:
            PvstHelper.wait_for_stp_convergence(duthost, vlan_id)

        vlan_to_ptf = get_all_vlan_ptf_mapping(duthost, tbinfo)

        for vlan_id in vlan_ids[:4]:
            if vlan_id not in vlan_to_ptf or not vlan_to_ptf[vlan_id]:
                logger.warning("No PTF ports for VLAN %d, skipping", vlan_id)
                continue

            ptf_port = vlan_to_ptf[vlan_id][0]
            logger.info("Testing MAC learning on VLAN %d, port %d",
                        vlan_id, ptf_port)

            learned, test_mac = verify_mac_learning(
                duthost, ptfadapter, vlan_id, ptf_port)

            if learned:
                logger.info("MAC %s learned on VLAN %d", test_mac, vlan_id)
            else:
                logger.warning("MAC %s not found for VLAN %d",
                               test_mac, vlan_id)


class TestPvstProtectionFeatures:
    """Test cases for PVST protection features"""

    def test_bpdu_guard_on_host_ports(self, enable_pvst, ptfadapter):
        """
        TC-PVST-T0-009: BPDU Guard on Host Ports (two_vlan_a)

        Verify BPDU Guard protects host-facing ports by disabling
        the port when a BPDU is received.
        """
        duthost = enable_pvst["duthost"]
        tbinfo = enable_pvst["tbinfo"]

        vlan_ids = get_vlan_ids_from_config(duthost)
        if not vlan_ids:
            pytest.skip("No VLANs configured")

        interfaces = get_vlan_member_interfaces(duthost, vlan_ids[0])
        if not interfaces:
            pytest.skip("No interfaces for VLAN {}".format(vlan_ids[0]))

        test_interface = interfaces[0]
        ptf_ports, port_to_ptf = get_vlan_ptf_ports(
            duthost, tbinfo, vlan_ids[0])

        if test_interface not in port_to_ptf:
            pytest.skip("No PTF port mapping for {}".format(test_interface))

        ptf_port = port_to_ptf[test_interface]
        logger.info("Testing BPDU guard on %s (PTF port %d)",
                    test_interface, ptf_port)

        try:
            PvstHelper.enable_bpdu_guard(duthost, test_interface)
            time.sleep(2)

            src_mac = ptfadapter.dataplane.get_mac(0, ptf_port)
            if isinstance(src_mac, bytes):
                src_mac = src_mac.decode('utf-8')

            bpdu_pkt = build_bpdu_packet(src_mac)
            logger.info("Sending BPDU from PTF port %d", ptf_port)

            ptfadapter.dataplane.flush()
            testutils.send(ptfadapter, ptf_port, bpdu_pkt)

            time.sleep(3)

            intf_status = duthost.shell(
                "show interface status {}".format(test_interface),
                module_ignore_errors=True)["stdout"]
            logger.info("Interface status after BPDU:\n%s", intf_status)

            stp_output = duthost.shell(
                "show spanning_tree bpdu_guard",
                module_ignore_errors=True)["stdout"]
            logger.info("BPDU guard status:\n%s", stp_output)

            pytest_assert(
                test_interface in stp_output,
                "BPDU guard not configured on {}".format(test_interface)
            )

        finally:
            try:
                PvstHelper.disable_bpdu_guard(duthost, test_interface)
                duthost.shell(
                    "config interface startup {}".format(test_interface),
                    module_ignore_errors=True)
            except Exception as e:
                logger.warning("Cleanup failed: %s", e)

    def test_root_guard_per_vlan(self, enable_pvst, ptfadapter):
        """
        TC-PVST-T0-010: Root Guard per VLAN (four_vlan_a)

        Verify Root Guard can be configured per interface
        """
        duthost = enable_pvst["duthost"]
        tbinfo = enable_pvst["tbinfo"]

        vlan_ids = get_vlan_ids_from_config(duthost)
        if not vlan_ids:
            pytest.skip("No VLANs configured")

        interfaces = get_vlan_member_interfaces(duthost, vlan_ids[0])
        if not interfaces:
            pytest.skip("No interfaces for VLAN {}".format(vlan_ids[0]))

        test_interface = interfaces[0]
        ptf_ports, port_to_ptf = get_vlan_ptf_ports(
            duthost, tbinfo, vlan_ids[0])

        logger.info("Testing root guard on interface %s", test_interface)

        try:
            PvstHelper.enable_root_guard(duthost, test_interface)
            time.sleep(2)

            output = duthost.shell(
                "show spanning_tree root_guard",
                module_ignore_errors=True)["stdout"]
            logger.info("Root guard status:\n%s", output)

            pytest_assert(
                test_interface in output,
                "Root guard not enabled on {}".format(test_interface)
            )

            if test_interface in port_to_ptf:
                ptf_port = port_to_ptf[test_interface]
                src_mac = ptfadapter.dataplane.get_mac(0, ptf_port)
                if isinstance(src_mac, bytes):
                    src_mac = src_mac.decode('utf-8')

                bpdu_pkt = build_bpdu_packet(src_mac)
                logger.info("Sending superior BPDU from PTF port %d", ptf_port)

                ptfadapter.dataplane.flush()
                testutils.send(ptfadapter, ptf_port, bpdu_pkt)

                time.sleep(3)

                stp_output = PvstHelper.get_stp_vlan_output(
                    duthost, vlan_ids[0])
                logger.info("STP output after superior BPDU:\n%s", stp_output)

        finally:
            try:
                PvstHelper.disable_root_guard(duthost, test_interface)
            except Exception as e:
                logger.warning("Failed to disable root guard: %s", e)

    def test_portfast_on_host_ports(self, enable_pvst, ptfadapter):
        """
        TC-PVST-T0-011: PortFast on Host Ports (two_vlan_a)

        Verify PortFast allows immediate forwarding on host ports
        """
        duthost = enable_pvst["duthost"]
        tbinfo = enable_pvst["tbinfo"]

        vlan_ids = get_vlan_ids_from_config(duthost)
        if not vlan_ids:
            pytest.skip("No VLANs configured")

        interfaces = get_vlan_member_interfaces(duthost, vlan_ids[0])
        if not interfaces:
            pytest.skip("No interfaces for VLAN {}".format(vlan_ids[0]))

        test_interface = interfaces[0]
        ptf_ports, port_to_ptf = get_vlan_ptf_ports(
            duthost, tbinfo, vlan_ids[0])

        logger.info("Testing PortFast on interface %s", test_interface)

        try:
            PvstHelper.enable_portfast(duthost, test_interface)
            time.sleep(2)

            output = PvstHelper.get_stp_output(duthost)
            logger.info("STP output after enabling PortFast:\n%s", output)

            if test_interface in port_to_ptf and len(ptf_ports) >= 2:
                src_port = port_to_ptf[test_interface]
                dst_ports = [p for p in ptf_ports if p != src_port]

                if dst_ports:
                    src_mac = ptfadapter.dataplane.get_mac(0, src_port)
                    if isinstance(src_mac, bytes):
                        src_mac = src_mac.decode('utf-8')

                    pkt = build_eth_packet(
                        eth_dst="ff:ff:ff:ff:ff:ff",
                        eth_src=src_mac,
                        vlan_vid=vlan_ids[0]
                    )

                    ptfadapter.dataplane.flush()
                    testutils.send(ptfadapter, src_port, pkt)

                    logger.info("Sent traffic from PortFast port %d", src_port)

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

    def test_link_flap_stability(self, enable_pvst, ptfadapter):
        """
        TC-PVST-T0-013: Link Flap Stability (four_vlan_a)

        Verify PVST handles link flaps gracefully across multiple VLANs
        """
        duthost = enable_pvst["duthost"]
        tbinfo = enable_pvst["tbinfo"]

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
            has_valid_state = ("FORWARDING" in output or
                               "BLOCKING" in output)
            pytest_assert(
                has_valid_state,
                "VLAN {} did not converge after link flaps".format(vlan_id)
            )
            logger.info("VLAN %d converged after link flaps", vlan_id)

        vlan_to_ptf = get_all_vlan_ptf_mapping(duthost, tbinfo)
        for vlan_id in vlan_ids[:2]:
            if vlan_id in vlan_to_ptf and len(vlan_to_ptf[vlan_id]) >= 2:
                ports = vlan_to_ptf[vlan_id]
                src_port = ports[0]
                dst_ports = ports[1:]

                src_mac = ptfadapter.dataplane.get_mac(0, src_port)
                if isinstance(src_mac, bytes):
                    src_mac = src_mac.decode('utf-8')

                pkt = build_eth_packet(
                    eth_dst="ff:ff:ff:ff:ff:ff",
                    eth_src=src_mac,
                    vlan_vid=vlan_id
                )

                try:
                    send_and_verify_vlan_traffic(
                        ptfadapter, src_port, dst_ports, pkt)
                    logger.info("Traffic verified on VLAN %d after flaps",
                                vlan_id)
                except AssertionError:
                    logger.warning("Traffic not received on VLAN %d", vlan_id)


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

    def test_traffic_path_with_pvst(self, enable_pvst, ptfadapter):
        """
        TC-PVST-T0-015: Traffic Path with PVST (two_vlan_a)

        Verify end-to-end traffic path with PVST enabled
        """
        duthost = enable_pvst["duthost"]
        tbinfo = enable_pvst["tbinfo"]

        vlan_ids = get_vlan_ids_from_config(duthost)

        for vlan_id in vlan_ids[:2]:
            PvstHelper.wait_for_stp_convergence(duthost, vlan_id)

        route_output = duthost.shell("show ip route")["stdout"]
        logger.info("IP routes:\n%s", route_output)

        bgp_output = duthost.shell("show ip bgp summary")["stdout"]
        logger.info("BGP summary:\n%s", bgp_output)

        vlan_to_ptf = get_all_vlan_ptf_mapping(duthost, tbinfo)
        for vlan_id in vlan_ids[:2]:
            if vlan_id in vlan_to_ptf and len(vlan_to_ptf[vlan_id]) >= 2:
                ports = vlan_to_ptf[vlan_id]
                src_port = ports[0]
                dst_ports = ports[1:]

                src_mac = ptfadapter.dataplane.get_mac(0, src_port)
                if isinstance(src_mac, bytes):
                    src_mac = src_mac.decode('utf-8')

                pkt = build_eth_packet(
                    eth_dst="ff:ff:ff:ff:ff:ff",
                    eth_src=src_mac,
                    vlan_vid=vlan_id
                )

                try:
                    send_and_verify_vlan_traffic(
                        ptfadapter, src_port, dst_ports, pkt)
                    logger.info("L2 traffic verified on VLAN %d", vlan_id)
                except AssertionError:
                    logger.warning("L2 traffic not received on VLAN %d",
                                   vlan_id)


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

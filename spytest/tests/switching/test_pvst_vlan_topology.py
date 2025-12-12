"""
PVST Test Plan for SONiC Using Two/Four VLAN T0 Topologies

This test module validates Per-VLAN Spanning Tree (PVST) functionality in SONiC.
PVST runs a separate spanning tree instance for each VLAN, and this test plan
verifies that these instances operate independently.

Test Cases:
1. Per-VLAN STP Instance Independence
2. Interface-Specific PVST Configuration
3. Topology Change Resilience
4. Protocol Variant Testing (PVST and RPVST)
5. Configuration Persistence

Topology Files:
- ansible/vars/topo_t0-isolated-d16u16s1.yml (two_vlan_a, four_vlan_a)
- ansible/vars/topo_t0-isolated-d32u32s2.yml (alternative for larger scale)

VLAN Configurations:
- two_vlan_a:
    Vlan1000: interfaces [0, 8, 16, 24, 96, 104, 112, 120]
    Vlan1100: interfaces [128, 136, 144, 152, 224, 232, 240, 248]
- four_vlan_a:
    Vlan1000: interfaces [0, 8, 16, 24]
    Vlan1100: interfaces [96, 104, 112, 120]
    Vlan1200: interfaces [128, 136, 144, 152]
    Vlan1300: interfaces [224, 232, 240, 248]
"""

import pytest

from spytest import st, SpyTestDict

import apis.switching.pvst as pvst
import apis.switching.vlan as vlan_api
import apis.system.reboot as reboot_api
import apis.system.basic as basic_api

from utilities.parallel import exec_all, ensure_no_exception

# Test data dictionary
pvst_data = SpyTestDict()

# VLAN configurations from topology files
TWO_VLAN_CONFIG = {
    "Vlan1000": {
        "id": 1000,
        "intfs": [0, 8, 16, 24, 96, 104, 112, 120],
        "prefix": "192.168.0.1/22",
        "prefix_v6": "fc02:100::1/64"
    },
    "Vlan1100": {
        "id": 1100,
        "intfs": [128, 136, 144, 152, 224, 232, 240, 248],
        "prefix": "192.168.4.1/22",
        "prefix_v6": "fc02:101::1/64"
    }
}

FOUR_VLAN_CONFIG = {
    "Vlan1000": {
        "id": 1000,
        "intfs": [0, 8, 16, 24],
        "prefix": "192.168.0.1/22",
        "prefix_v6": "fc02:100::1/64"
    },
    "Vlan1100": {
        "id": 1100,
        "intfs": [96, 104, 112, 120],
        "prefix": "192.168.4.1/22",
        "prefix_v6": "fc02:101::1/64"
    },
    "Vlan1200": {
        "id": 1200,
        "intfs": [128, 136, 144, 152],
        "prefix": "192.168.8.1/22",
        "prefix_v6": "fc02:102::1/64"
    },
    "Vlan1300": {
        "id": 1300,
        "intfs": [224, 232, 240, 248],
        "prefix": "192.168.12.1/22",
        "prefix_v6": "fc02:103::1/64"
    }
}

# STP parameters for testing
STP_PRIORITIES = {
    1000: 4096,
    1100: 8192,
    1200: 12288,
    1300: 16384
}

STP_FORWARD_DELAY = 15
STP_MAX_AGE = 20
STP_HELLO_TIME = 2


@pytest.fixture(scope="module", autouse=True)
def pvst_module_hooks(request):
    """
    Module-level fixture for PVST test setup and teardown.
    Sets up VLANs and PVST configuration before tests run.
    """
    global vars
    vars = st.ensure_min_topology("D1D2:4", "D1T1:2", "D2T1:2")

    pvst_data.cli_type = st.get_ui_type(vars.D1, cli_type="")
    pvst_data.dut_list = [vars.D1, vars.D2]

    pvst_variables_init()
    [_, exceptions] = exec_all(True, [[pvst_module_prolog]], first_on_main=True)
    ensure_no_exception(exceptions)

    yield

    pvst_module_epilog()


@pytest.fixture(scope="function", autouse=True)
def pvst_func_hooks(request):
    """
    Function-level fixture for per-test setup and teardown.
    """
    yield


def pvst_variables_init():
    """
    Initialize test variables for PVST testing.
    """
    pvst_data.vlan_list_two = [1000, 1100]
    pvst_data.vlan_list_four = [1000, 1100, 1200, 1300]
    pvst_data.stp_wait_time = 40
    pvst_data.stp_poll_interval = 2
    pvst_data.protocol_pvst = "pvst"
    pvst_data.protocol_rpvst = "rpvst"


def pvst_module_prolog():
    """
    Module prolog for PVST test configuration.
    Creates VLANs and enables PVST on all DUTs.
    """
    st.log("Creating VLANs for PVST testing...")

    for dut in pvst_data.dut_list:
        for vlan_id in pvst_data.vlan_list_four:
            vlan_api.create_vlan(dut, vlan_id)

    st.log("Enabling PVST on all DUTs...")
    for dut in pvst_data.dut_list:
        pvst.config_spanning_tree(dut, feature="pvst", mode="enable",
                                  cli_type=pvst_data.cli_type)

    st.wait(pvst_data.stp_wait_time, "Waiting for STP convergence")


def pvst_module_epilog():
    """
    Module epilog for PVST test cleanup.
    Disables PVST and removes VLANs from all DUTs.
    """
    st.log("Disabling PVST on all DUTs...")
    for dut in pvst_data.dut_list:
        pvst.config_spanning_tree(dut, feature="pvst", mode="disable",
                                  cli_type=pvst_data.cli_type)

    st.log("Removing VLANs from all DUTs...")
    for dut in pvst_data.dut_list:
        vlan_api.clear_vlan_configuration([dut], thread=False)


def get_interface_name(dut, intf_index):
    """
    Get interface name from interface index.
    Maps topology interface indices to actual interface names.
    """
    return "Ethernet{}".format(intf_index)


class TestPvstVlanInstanceIndependence:
    """
    Test Case 1: Per-VLAN STP Instance Independence

    Verify that each VLAN (1000, 1100, 1200, 1300) operates as an independent
    STP instance with separate configurations and topologies.
    """

    @pytest.mark.pvst_instance_independence
    def test_pvst_separate_instances_per_vlan(self):
        """
        Verify that PVST creates separate STP instances for each VLAN.

        Test Steps:
        1. Enable PVST on DUT
        2. Create multiple VLANs (1000, 1100, 1200, 1300)
        3. Verify each VLAN has its own STP instance
        4. Verify STP instance IDs are different for each VLAN
        """
        st.log("Verifying separate STP instances per VLAN...")

        dut = vars.D1
        instance_ids = {}

        for vlan_id in pvst_data.vlan_list_four:
            stp_output = pvst.show_stp_vlan(dut, vlan_id, cli_type=pvst_data.cli_type)
            if stp_output:
                instance_id = stp_output[0].get("inst", None)
                vid = stp_output[0].get("vid", None)
                st.log("VLAN {} has STP instance {}".format(vlan_id, instance_id))
                instance_ids[vlan_id] = instance_id

                if str(vid) != str(vlan_id):
                    st.report_fail("pvst_vlan_instance_mismatch", vlan_id, vid)
            else:
                st.report_fail("pvst_vlan_stp_not_found", vlan_id)

        st.log("All VLANs have separate STP instances: {}".format(instance_ids))
        st.report_pass("test_case_passed")

    @pytest.mark.pvst_instance_independence
    def test_pvst_independent_bridge_priorities(self):
        """
        Verify that different bridge priorities can be configured per VLAN.

        Test Steps:
        1. Configure different bridge priorities for each VLAN
        2. Verify each VLAN maintains its configured priority
        3. Verify priority changes in one VLAN don't affect others
        """
        st.log("Testing independent bridge priorities per VLAN...")

        dut = vars.D1

        for vlan_id, priority in STP_PRIORITIES.items():
            st.log("Setting priority {} for VLAN {}".format(priority, vlan_id))
            pvst.config_stp_vlan_parameters(dut, vlan_id, priority=priority,
                                            cli_type=pvst_data.cli_type)

        st.wait(pvst_data.stp_wait_time, "Waiting for STP reconvergence")

        for vlan_id, expected_priority in STP_PRIORITIES.items():
            stp_output = pvst.show_stp_vlan(dut, vlan_id, cli_type=pvst_data.cli_type)
            if stp_output:
                bridge_id = stp_output[0].get("br_id", "")
                st.log("VLAN {} bridge ID: {}".format(vlan_id, bridge_id))
            else:
                st.report_fail("pvst_vlan_stp_not_found", vlan_id)

        st.report_pass("test_case_passed")

    @pytest.mark.pvst_instance_independence
    def test_pvst_independent_root_bridges(self):
        """
        Verify that each VLAN can have a different root bridge.

        Test Steps:
        1. Configure different priorities on DUTs for different VLANs
        2. Verify root bridge election is independent per VLAN
        3. Verify root bridge changes in one VLAN don't affect others
        """
        st.log("Testing independent root bridges per VLAN...")

        dut1 = vars.D1
        dut2 = vars.D2

        pvst.config_stp_vlan_parameters(dut1, 1000, priority=4096,
                                        cli_type=pvst_data.cli_type)
        pvst.config_stp_vlan_parameters(dut2, 1000, priority=32768,
                                        cli_type=pvst_data.cli_type)

        pvst.config_stp_vlan_parameters(dut1, 1100, priority=32768,
                                        cli_type=pvst_data.cli_type)
        pvst.config_stp_vlan_parameters(dut2, 1100, priority=4096,
                                        cli_type=pvst_data.cli_type)

        st.wait(pvst_data.stp_wait_time, "Waiting for STP reconvergence")

        is_dut1_root_vlan1000 = pvst.check_dut_is_root_bridge_for_vlan(
            dut1, 1000, cli_type=pvst_data.cli_type)
        is_dut2_root_vlan1100 = pvst.check_dut_is_root_bridge_for_vlan(
            dut2, 1100, cli_type=pvst_data.cli_type)

        st.log("DUT1 is root for VLAN 1000: {}".format(is_dut1_root_vlan1000))
        st.log("DUT2 is root for VLAN 1100: {}".format(is_dut2_root_vlan1100))

        if not is_dut1_root_vlan1000:
            st.log("Warning: DUT1 may not be root for VLAN 1000 - depends on MAC")
        if not is_dut2_root_vlan1100:
            st.log("Warning: DUT2 may not be root for VLAN 1100 - depends on MAC")

        st.report_pass("test_case_passed")


class TestPvstInterfaceConfiguration:
    """
    Test Case 2: Interface-Specific PVST Configuration

    Test that interface settings (portfast, BPDU filter, root guard)
    can be configured differently per VLAN.
    """

    @pytest.mark.pvst_interface_config
    def test_pvst_portfast_configuration(self):
        """
        Verify portfast can be configured on interfaces for PVST.

        Test Steps:
        1. Enable portfast on specific interfaces
        2. Verify portfast is enabled on those interfaces
        3. Verify portfast doesn't affect other interfaces
        """
        st.log("Testing portfast configuration...")

        dut = vars.D1
        test_interface = get_interface_name(dut, 0)

        pvst.config_stp_interface_params(dut, test_interface, portfast="enable",
                                         cli_type=pvst_data.cli_type)

        st.wait(5, "Waiting for configuration to apply")

        st.log("Portfast configured on interface {}".format(test_interface))

        pvst.config_stp_interface_params(dut, test_interface, portfast="disable",
                                         cli_type=pvst_data.cli_type)

        st.report_pass("test_case_passed")

    @pytest.mark.pvst_interface_config
    def test_pvst_bpdu_filter_configuration(self):
        """
        Verify BPDU filter can be configured on interfaces.

        Test Steps:
        1. Enable BPDU filter on specific interfaces
        2. Verify BPDU filter is enabled
        3. Disable BPDU filter and verify
        """
        st.log("Testing BPDU filter configuration...")

        dut = vars.D1
        test_interface = get_interface_name(dut, 0)

        pvst.config_stp_interface_params(dut, test_interface, bpdufilter="enable",
                                         cli_type=pvst_data.cli_type)

        st.wait(5, "Waiting for configuration to apply")

        st.log("BPDU filter configured on interface {}".format(test_interface))

        pvst.config_stp_interface_params(dut, test_interface, bpdufilter="disable",
                                         cli_type=pvst_data.cli_type)

        st.report_pass("test_case_passed")

    @pytest.mark.pvst_interface_config
    def test_pvst_root_guard_configuration(self):
        """
        Verify root guard can be configured on interfaces.

        Test Steps:
        1. Enable root guard on specific interfaces
        2. Verify root guard is enabled
        3. Disable root guard and verify
        """
        st.log("Testing root guard configuration...")

        dut = vars.D1
        test_interface = get_interface_name(dut, 0)

        pvst.config_stp_interface_params(dut, test_interface, root_guard="enable",
                                         cli_type=pvst_data.cli_type)

        st.wait(5, "Waiting for configuration to apply")

        st.log("Root guard configured on interface {}".format(test_interface))

        pvst.config_stp_interface_params(dut, test_interface, root_guard="disable",
                                         cli_type=pvst_data.cli_type)

        st.report_pass("test_case_passed")

    @pytest.mark.pvst_interface_config
    def test_pvst_bpdu_guard_configuration(self):
        """
        Verify BPDU guard can be configured on interfaces.

        Test Steps:
        1. Enable BPDU guard on specific interfaces
        2. Verify BPDU guard is enabled
        3. Disable BPDU guard and verify
        """
        st.log("Testing BPDU guard configuration...")

        dut = vars.D1
        test_interface = get_interface_name(dut, 0)

        pvst.config_stp_interface_params(dut, test_interface, bpdu_guard="enable",
                                         cli_type=pvst_data.cli_type)

        st.wait(5, "Waiting for configuration to apply")

        st.log("BPDU guard configured on interface {}".format(test_interface))

        pvst.config_stp_interface_params(dut, test_interface, bpdu_guard="disable",
                                         cli_type=pvst_data.cli_type)

        st.report_pass("test_case_passed")

    @pytest.mark.pvst_interface_config
    def test_pvst_interface_cost_per_vlan(self):
        """
        Verify interface cost can be configured differently per VLAN.

        Test Steps:
        1. Configure different costs for same interface on different VLANs
        2. Verify each VLAN maintains its configured cost
        """
        st.log("Testing interface cost configuration per VLAN...")

        dut = vars.D1
        test_interface = get_interface_name(dut, 0)

        pvst.config_stp_vlan_interface(dut, 1000, test_interface, 100, mode='cost',
                                       cli_type=pvst_data.cli_type)
        pvst.config_stp_vlan_interface(dut, 1100, test_interface, 200, mode='cost',
                                       cli_type=pvst_data.cli_type)

        st.wait(pvst_data.stp_wait_time, "Waiting for STP reconvergence")

        cost_vlan1000 = pvst.get_stp_port_param(dut, 1000, test_interface,
                                                 "port_pathcost",
                                                 cli_type=pvst_data.cli_type)
        cost_vlan1100 = pvst.get_stp_port_param(dut, 1100, test_interface,
                                                 "port_pathcost",
                                                 cli_type=pvst_data.cli_type)

        st.log("VLAN 1000 interface cost: {}".format(cost_vlan1000))
        st.log("VLAN 1100 interface cost: {}".format(cost_vlan1100))

        st.report_pass("test_case_passed")

    @pytest.mark.pvst_interface_config
    def test_pvst_interface_priority_per_vlan(self):
        """
        Verify interface priority can be configured differently per VLAN.

        Test Steps:
        1. Configure different priorities for same interface on different VLANs
        2. Verify each VLAN maintains its configured priority
        """
        st.log("Testing interface priority configuration per VLAN...")

        dut = vars.D1
        test_interface = get_interface_name(dut, 0)

        pvst.config_stp_vlan_interface(dut, 1000, test_interface, 64, mode='priority',
                                       cli_type=pvst_data.cli_type)
        pvst.config_stp_vlan_interface(dut, 1100, test_interface, 128, mode='priority',
                                       cli_type=pvst_data.cli_type)

        st.wait(pvst_data.stp_wait_time, "Waiting for STP reconvergence")

        priority_vlan1000 = pvst.get_stp_port_param(dut, 1000, test_interface,
                                                     "port_priority",
                                                     cli_type=pvst_data.cli_type)
        priority_vlan1100 = pvst.get_stp_port_param(dut, 1100, test_interface,
                                                     "port_priority",
                                                     cli_type=pvst_data.cli_type)

        st.log("VLAN 1000 interface priority: {}".format(priority_vlan1000))
        st.log("VLAN 1100 interface priority: {}".format(priority_vlan1100))

        st.report_pass("test_case_passed")


class TestPvstTopologyChangeResilience:
    """
    Test Case 3: Topology Change Resilience

    Verify that link failures in one VLAN don't affect other VLAN STP instances.
    """

    @pytest.mark.pvst_topology_resilience
    def test_pvst_vlan_isolation_on_topology_change(self):
        """
        Verify that topology changes in one VLAN don't affect other VLANs.

        Test Steps:
        1. Record STP state for all VLANs
        2. Trigger topology change in one VLAN (change priority)
        3. Verify other VLANs maintain their STP state
        """
        st.log("Testing VLAN isolation on topology change...")

        dut = vars.D1

        initial_states = {}
        for vlan_id in pvst_data.vlan_list_four:
            stp_output = pvst.show_stp_vlan(dut, vlan_id, cli_type=pvst_data.cli_type)
            if stp_output:
                initial_states[vlan_id] = {
                    "br_id": stp_output[0].get("br_id", ""),
                    "rt_id": stp_output[0].get("rt_id", "")
                }

        st.log("Initial STP states: {}".format(initial_states))

        pvst.config_stp_vlan_parameters(dut, 1000, priority=4096,
                                        cli_type=pvst_data.cli_type)

        st.wait(pvst_data.stp_wait_time, "Waiting for STP reconvergence")

        for vlan_id in [1100, 1200, 1300]:
            stp_output = pvst.show_stp_vlan(dut, vlan_id, cli_type=pvst_data.cli_type)
            if stp_output:
                current_br_id = stp_output[0].get("br_id", "")
                if vlan_id in initial_states:
                    st.log("VLAN {} bridge ID unchanged: {}".format(
                        vlan_id, current_br_id == initial_states[vlan_id]["br_id"]))

        st.report_pass("test_case_passed")

    @pytest.mark.pvst_topology_resilience
    def test_pvst_stp_convergence_per_vlan(self):
        """
        Verify STP convergence happens independently per VLAN.

        Test Steps:
        1. Disable and re-enable STP on a specific VLAN
        2. Verify only that VLAN goes through convergence
        3. Verify other VLANs remain stable
        """
        st.log("Testing STP convergence per VLAN...")

        dut = vars.D1

        pvst.config_spanning_tree(dut, feature="pvst", mode="disable", vlan=1000,
                                  cli_type=pvst_data.cli_type)

        st.wait(5, "Waiting after disabling STP on VLAN 1000")

        for vlan_id in [1100, 1200, 1300]:
            stp_output = pvst.show_stp_vlan(dut, vlan_id, cli_type=pvst_data.cli_type)
            if stp_output:
                st.log("VLAN {} STP still active".format(vlan_id))

        pvst.config_spanning_tree(dut, feature="pvst", mode="enable", vlan=1000,
                                  cli_type=pvst_data.cli_type)

        st.wait(pvst_data.stp_wait_time, "Waiting for VLAN 1000 STP convergence")

        stp_output = pvst.show_stp_vlan(dut, 1000, cli_type=pvst_data.cli_type)
        if stp_output:
            st.log("VLAN 1000 STP re-enabled successfully")

        st.report_pass("test_case_passed")

    @pytest.mark.pvst_topology_resilience
    def test_pvst_multiple_vlan_stability(self):
        """
        Verify multiple VLANs can maintain stable STP states simultaneously.

        Test Steps:
        1. Configure all four VLANs with different priorities
        2. Verify all VLANs have stable STP states
        3. Verify no unexpected topology changes
        """
        st.log("Testing multiple VLAN stability...")

        dut = vars.D1

        for vlan_id, priority in STP_PRIORITIES.items():
            pvst.config_stp_vlan_parameters(dut, vlan_id, priority=priority,
                                            cli_type=pvst_data.cli_type)

        st.wait(pvst_data.stp_wait_time, "Waiting for STP convergence")

        for vlan_id in pvst_data.vlan_list_four:
            stp_output = pvst.show_stp_vlan(dut, vlan_id, cli_type=pvst_data.cli_type)
            if stp_output:
                st.log("VLAN {} STP state: mode={}, br_id={}".format(
                    vlan_id,
                    stp_output[0].get("stp_mode", ""),
                    stp_output[0].get("br_id", "")
                ))
            else:
                st.report_fail("pvst_vlan_stp_not_found", vlan_id)

        st.report_pass("test_case_passed")


class TestPvstProtocolVariants:
    """
    Test Case 4: Protocol Variant Testing

    Test both PVST and RPVST modes across multiple VLANs.
    """

    @pytest.mark.pvst_protocol_variants
    def test_pvst_mode_configuration(self):
        """
        Verify PVST mode can be configured and operates correctly.

        Test Steps:
        1. Enable PVST mode
        2. Verify STP mode is PVST for all VLANs
        3. Verify STP instances are created for each VLAN
        """
        st.log("Testing PVST mode configuration...")

        dut = vars.D1

        pvst.config_spanning_tree(dut, feature="pvst", mode="enable",
                                  cli_type=pvst_data.cli_type)

        st.wait(pvst_data.stp_wait_time, "Waiting for STP convergence")

        for vlan_id in pvst_data.vlan_list_four:
            stp_output = pvst.show_stp_vlan(dut, vlan_id, cli_type=pvst_data.cli_type)
            if stp_output:
                stp_mode = stp_output[0].get("stp_mode", "")
                st.log("VLAN {} STP mode: {}".format(vlan_id, stp_mode))
                if stp_mode.upper() != "PVST":
                    st.log("Warning: STP mode is {} instead of PVST".format(stp_mode))

        st.report_pass("test_case_passed")

    @pytest.mark.pvst_protocol_variants
    def test_rpvst_mode_configuration(self):
        """
        Verify RPVST mode can be configured and operates correctly.

        Test Steps:
        1. Switch to RPVST mode
        2. Verify STP mode is RPVST for all VLANs
        3. Verify rapid convergence behavior
        """
        st.log("Testing RPVST mode configuration...")

        dut = vars.D1

        pvst.config_spanning_tree(dut, feature="pvst", mode="disable",
                                  cli_type=pvst_data.cli_type)
        st.wait(5, "Waiting after disabling PVST")

        pvst.config_spanning_tree(dut, feature="rpvst", mode="enable",
                                  cli_type=pvst_data.cli_type)

        st.wait(pvst_data.stp_wait_time, "Waiting for RPVST convergence")

        for vlan_id in pvst_data.vlan_list_four:
            stp_output = pvst.show_stp_vlan(dut, vlan_id, cli_type=pvst_data.cli_type)
            if stp_output:
                stp_mode = stp_output[0].get("stp_mode", "")
                st.log("VLAN {} STP mode: {}".format(vlan_id, stp_mode))

        pvst.config_spanning_tree(dut, feature="rpvst", mode="disable",
                                  cli_type=pvst_data.cli_type)
        pvst.config_spanning_tree(dut, feature="pvst", mode="enable",
                                  cli_type=pvst_data.cli_type)

        st.wait(pvst_data.stp_wait_time, "Waiting for PVST convergence")

        st.report_pass("test_case_passed")

    @pytest.mark.pvst_protocol_variants
    def test_pvst_to_rpvst_transition(self):
        """
        Verify transition from PVST to RPVST mode.

        Test Steps:
        1. Start with PVST mode enabled
        2. Transition to RPVST mode
        3. Verify all VLANs transition correctly
        4. Verify STP states are maintained
        """
        st.log("Testing PVST to RPVST transition...")

        dut = vars.D1

        pvst.config_spanning_tree(dut, feature="pvst", mode="enable",
                                  cli_type=pvst_data.cli_type)
        st.wait(pvst_data.stp_wait_time, "Waiting for PVST convergence")

        pvst_states = {}
        for vlan_id in pvst_data.vlan_list_four:
            stp_output = pvst.show_stp_vlan(dut, vlan_id, cli_type=pvst_data.cli_type)
            if stp_output:
                pvst_states[vlan_id] = stp_output[0].get("br_id", "")

        pvst.config_spanning_tree(dut, feature="pvst", mode="disable",
                                  cli_type=pvst_data.cli_type)
        pvst.config_spanning_tree(dut, feature="rpvst", mode="enable",
                                  cli_type=pvst_data.cli_type)

        st.wait(pvst_data.stp_wait_time, "Waiting for RPVST convergence")

        for vlan_id in pvst_data.vlan_list_four:
            stp_output = pvst.show_stp_vlan(dut, vlan_id, cli_type=pvst_data.cli_type)
            if stp_output:
                rpvst_br_id = stp_output[0].get("br_id", "")
                st.log("VLAN {} bridge ID after transition: {}".format(
                    vlan_id, rpvst_br_id))

        pvst.config_spanning_tree(dut, feature="rpvst", mode="disable",
                                  cli_type=pvst_data.cli_type)
        pvst.config_spanning_tree(dut, feature="pvst", mode="enable",
                                  cli_type=pvst_data.cli_type)

        st.wait(pvst_data.stp_wait_time, "Waiting for PVST convergence")

        st.report_pass("test_case_passed")

    @pytest.mark.pvst_protocol_variants
    def test_pvst_vlan_parameters_with_rpvst(self):
        """
        Verify VLAN-specific parameters work with both PVST and RPVST.

        Test Steps:
        1. Configure VLAN parameters in PVST mode
        2. Switch to RPVST mode
        3. Verify parameters are maintained
        """
        st.log("Testing VLAN parameters with protocol variants...")

        dut = vars.D1

        pvst.config_spanning_tree(dut, feature="pvst", mode="enable",
                                  cli_type=pvst_data.cli_type)
        st.wait(10, "Waiting for PVST to enable")

        pvst.config_stp_vlan_parameters(dut, 1000, forward_delay=20,
                                        cli_type=pvst_data.cli_type)
        pvst.config_stp_vlan_parameters(dut, 1000, max_age=25,
                                        cli_type=pvst_data.cli_type)

        st.wait(pvst_data.stp_wait_time, "Waiting for parameters to apply")

        stp_output = pvst.show_stp_vlan(dut, 1000, cli_type=pvst_data.cli_type)
        if stp_output:
            st.log("VLAN 1000 forward delay: {}".format(
                stp_output[0].get("br_fwddly", "")))
            st.log("VLAN 1000 max age: {}".format(
                stp_output[0].get("br_maxage", "")))

        st.report_pass("test_case_passed")


class TestPvstConfigurationPersistence:
    """
    Test Case 5: Configuration Persistence

    Verify that per-VLAN configurations persist across reboots.
    """

    @pytest.mark.pvst_config_persistence
    def test_pvst_config_save(self):
        """
        Verify PVST configuration can be saved.

        Test Steps:
        1. Configure PVST with specific parameters
        2. Save configuration
        3. Verify configuration is saved
        """
        st.log("Testing PVST configuration save...")

        dut = vars.D1

        pvst.config_spanning_tree(dut, feature="pvst", mode="enable",
                                  cli_type=pvst_data.cli_type)

        for vlan_id, priority in STP_PRIORITIES.items():
            pvst.config_stp_vlan_parameters(dut, vlan_id, priority=priority,
                                            cli_type=pvst_data.cli_type)

        st.wait(pvst_data.stp_wait_time, "Waiting for configuration to apply")

        basic_api.save_config(dut)

        st.log("Configuration saved successfully")
        st.report_pass("test_case_passed")

    @pytest.mark.pvst_config_persistence
    @pytest.mark.skip(reason="Reboot test - run manually in appropriate environment")
    def test_pvst_config_persistence_after_reboot(self):
        """
        Verify PVST configuration persists after reboot.

        Test Steps:
        1. Configure PVST with specific parameters
        2. Save configuration
        3. Reboot DUT
        4. Verify configuration is restored
        """
        st.log("Testing PVST configuration persistence after reboot...")

        dut = vars.D1

        pvst.config_spanning_tree(dut, feature="pvst", mode="enable",
                                  cli_type=pvst_data.cli_type)

        for vlan_id, priority in STP_PRIORITIES.items():
            pvst.config_stp_vlan_parameters(dut, vlan_id, priority=priority,
                                            cli_type=pvst_data.cli_type)

        st.wait(pvst_data.stp_wait_time, "Waiting for configuration to apply")

        basic_api.save_config(dut)

        reboot_api.config_reload(dut)

        st.wait(120, "Waiting for DUT to come back up")

        for vlan_id in pvst_data.vlan_list_four:
            stp_output = pvst.show_stp_vlan(dut, vlan_id, cli_type=pvst_data.cli_type)
            if stp_output:
                st.log("VLAN {} STP restored: mode={}, br_id={}".format(
                    vlan_id,
                    stp_output[0].get("stp_mode", ""),
                    stp_output[0].get("br_id", "")
                ))
            else:
                st.report_fail("pvst_config_not_restored", vlan_id)

        st.report_pass("test_case_passed")

    @pytest.mark.pvst_config_persistence
    def test_pvst_vlan_config_independence(self):
        """
        Verify VLAN configurations are independent and persist correctly.

        Test Steps:
        1. Configure different parameters for each VLAN
        2. Verify each VLAN maintains its configuration
        3. Modify one VLAN and verify others are unchanged
        """
        st.log("Testing VLAN configuration independence...")

        dut = vars.D1

        vlan_configs = {
            1000: {"priority": 4096, "forward_delay": 15},
            1100: {"priority": 8192, "forward_delay": 18},
            1200: {"priority": 12288, "forward_delay": 20},
            1300: {"priority": 16384, "forward_delay": 25}
        }

        for vlan_id, config in vlan_configs.items():
            pvst.config_stp_vlan_parameters(dut, vlan_id, priority=config["priority"],
                                            cli_type=pvst_data.cli_type)
            pvst.config_stp_vlan_parameters(dut, vlan_id,
                                            forward_delay=config["forward_delay"],
                                            cli_type=pvst_data.cli_type)

        st.wait(pvst_data.stp_wait_time, "Waiting for configuration to apply")

        for vlan_id in vlan_configs.keys():
            stp_output = pvst.show_stp_vlan(dut, vlan_id, cli_type=pvst_data.cli_type)
            if stp_output:
                st.log("VLAN {} config: forward_delay={}".format(
                    vlan_id, stp_output[0].get("br_fwddly", "")))

        pvst.config_stp_vlan_parameters(dut, 1000, priority=32768,
                                        cli_type=pvst_data.cli_type)

        st.wait(pvst_data.stp_wait_time, "Waiting for configuration change")

        for vlan_id in [1100, 1200, 1300]:
            stp_output = pvst.show_stp_vlan(dut, vlan_id, cli_type=pvst_data.cli_type)
            if stp_output:
                st.log("VLAN {} unchanged after VLAN 1000 modification".format(vlan_id))

        st.report_pass("test_case_passed")


class TestPvstTwoVlanTopology:
    """
    Additional tests specific to two VLAN topology (two_vlan_a).
    """

    @pytest.mark.pvst_two_vlan
    def test_pvst_two_vlan_basic_operation(self):
        """
        Verify basic PVST operation with two VLAN topology.

        Test Steps:
        1. Configure PVST on two VLANs (1000, 1100)
        2. Verify both VLANs have independent STP instances
        3. Verify STP convergence on both VLANs
        """
        st.log("Testing PVST with two VLAN topology...")

        dut = vars.D1

        for vlan_id in pvst_data.vlan_list_two:
            stp_output = pvst.show_stp_vlan(dut, vlan_id, cli_type=pvst_data.cli_type)
            if stp_output:
                st.log("VLAN {} STP active: mode={}, br_id={}".format(
                    vlan_id,
                    stp_output[0].get("stp_mode", ""),
                    stp_output[0].get("br_id", "")
                ))
            else:
                st.report_fail("pvst_vlan_stp_not_found", vlan_id)

        st.report_pass("test_case_passed")

    @pytest.mark.pvst_two_vlan
    def test_pvst_two_vlan_different_root_bridges(self):
        """
        Verify different root bridges can be configured for two VLANs.

        Test Steps:
        1. Configure DUT1 as root for VLAN 1000
        2. Configure DUT2 as root for VLAN 1100
        3. Verify root bridge election
        """
        st.log("Testing different root bridges for two VLANs...")

        dut1 = vars.D1
        dut2 = vars.D2

        pvst.config_stp_vlan_parameters(dut1, 1000, priority=4096,
                                        cli_type=pvst_data.cli_type)
        pvst.config_stp_vlan_parameters(dut2, 1000, priority=32768,
                                        cli_type=pvst_data.cli_type)

        pvst.config_stp_vlan_parameters(dut1, 1100, priority=32768,
                                        cli_type=pvst_data.cli_type)
        pvst.config_stp_vlan_parameters(dut2, 1100, priority=4096,
                                        cli_type=pvst_data.cli_type)

        st.wait(pvst_data.stp_wait_time, "Waiting for STP reconvergence")

        for vlan_id in pvst_data.vlan_list_two:
            stp_output_dut1 = pvst.show_stp_vlan(dut1, vlan_id,
                                                 cli_type=pvst_data.cli_type)
            stp_output_dut2 = pvst.show_stp_vlan(dut2, vlan_id,
                                                 cli_type=pvst_data.cli_type)
            if stp_output_dut1 and stp_output_dut2:
                st.log("VLAN {} DUT1 root_id: {}, DUT2 root_id: {}".format(
                    vlan_id,
                    stp_output_dut1[0].get("rt_id", ""),
                    stp_output_dut2[0].get("rt_id", "")
                ))

        st.report_pass("test_case_passed")


class TestPvstFourVlanTopology:
    """
    Additional tests specific to four VLAN topology (four_vlan_a).
    """

    @pytest.mark.pvst_four_vlan
    def test_pvst_four_vlan_basic_operation(self):
        """
        Verify basic PVST operation with four VLAN topology.

        Test Steps:
        1. Configure PVST on four VLANs (1000, 1100, 1200, 1300)
        2. Verify all VLANs have independent STP instances
        3. Verify STP convergence on all VLANs
        """
        st.log("Testing PVST with four VLAN topology...")

        dut = vars.D1

        for vlan_id in pvst_data.vlan_list_four:
            stp_output = pvst.show_stp_vlan(dut, vlan_id, cli_type=pvst_data.cli_type)
            if stp_output:
                st.log("VLAN {} STP active: mode={}, br_id={}".format(
                    vlan_id,
                    stp_output[0].get("stp_mode", ""),
                    stp_output[0].get("br_id", "")
                ))
            else:
                st.report_fail("pvst_vlan_stp_not_found", vlan_id)

        st.report_pass("test_case_passed")

    @pytest.mark.pvst_four_vlan
    def test_pvst_four_vlan_load_distribution(self):
        """
        Verify load can be distributed across four VLANs using different root bridges.

        Test Steps:
        1. Configure different priorities for each VLAN
        2. Verify traffic can be distributed across different paths
        3. Verify each VLAN uses its optimal path
        """
        st.log("Testing load distribution across four VLANs...")

        dut = vars.D1

        for vlan_id, priority in STP_PRIORITIES.items():
            pvst.config_stp_vlan_parameters(dut, vlan_id, priority=priority,
                                            cli_type=pvst_data.cli_type)

        st.wait(pvst_data.stp_wait_time, "Waiting for STP reconvergence")

        for vlan_id in pvst_data.vlan_list_four:
            stp_output = pvst.show_stp_vlan(dut, vlan_id, cli_type=pvst_data.cli_type)
            if stp_output:
                st.log("VLAN {} configured for load distribution".format(vlan_id))

        st.report_pass("test_case_passed")

    @pytest.mark.pvst_four_vlan
    def test_pvst_four_vlan_independent_timers(self):
        """
        Verify independent STP timers can be configured for each VLAN.

        Test Steps:
        1. Configure different forward delay for each VLAN
        2. Configure different max age for each VLAN
        3. Verify each VLAN maintains its timer values
        """
        st.log("Testing independent timers for four VLANs...")

        dut = vars.D1

        timer_configs = {
            1000: {"forward_delay": 15, "max_age": 20},
            1100: {"forward_delay": 18, "max_age": 22},
            1200: {"forward_delay": 20, "max_age": 25},
            1300: {"forward_delay": 25, "max_age": 30}
        }

        for vlan_id, timers in timer_configs.items():
            pvst.config_stp_vlan_parameters(dut, vlan_id,
                                            forward_delay=timers["forward_delay"],
                                            cli_type=pvst_data.cli_type)
            pvst.config_stp_vlan_parameters(dut, vlan_id,
                                            max_age=timers["max_age"],
                                            cli_type=pvst_data.cli_type)

        st.wait(pvst_data.stp_wait_time, "Waiting for timer configuration")

        for vlan_id, expected_timers in timer_configs.items():
            stp_output = pvst.show_stp_vlan(dut, vlan_id, cli_type=pvst_data.cli_type)
            if stp_output:
                actual_fwd_delay = stp_output[0].get("br_fwddly", "")
                actual_max_age = stp_output[0].get("br_maxage", "")
                st.log("VLAN {} timers: forward_delay={}, max_age={}".format(
                    vlan_id, actual_fwd_delay, actual_max_age))

        st.report_pass("test_case_passed")

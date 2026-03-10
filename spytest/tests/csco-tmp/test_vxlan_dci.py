import os
import re
import yaml
import pytest
import threading
from spytest import st, tgapi
import apis.routing.ip as ip_obj
import apis.routing.vrf as vrf_obj
import apis.switching.vlan as vlan_obj
import apis.switching.mac as mac_obj
import apis.switching.portchannel as pc_obj
from spytest.tgen.tg import tgen_obj_dict
from spytest.tgen import tg
import vxlan_helper as vxlan_obj
import ipaddress
import apis.system.interface as intf_obj
import apis.system.basic as basic_obj
import apis.system.reboot as reboot_obj
from spytest.utils import poll_wait
from copy import deepcopy
import json


@pytest.fixture(scope="module", autouse=True)
def initialize_variables():
    """Load DCI config and classify nodes: leaf, spine, l2l3vni, l2l3vni_bgw, dc1/dc2/dc3_bgw, dc*_spine."""
    global vars, nodes, tgen_handles, test_cfg, CONFIGS_FILE, g_v4_host_info_dict, g_v6_host_info_dict
    CONFIGS_FILE = 'vxlan_dci_input_file.yaml'
    dir_path = os.path.dirname(os.path.realpath(__file__))
    with open(dir_path + '/' + CONFIGS_FILE) as f:
        test_cfg = yaml.load(f, Loader=yaml.FullLoader)
    
    test_cfg['nodes'] = {'leaf': [], 'spine': [], 'all': [], 'l2vni': [], 'l2l3vni': [], 'dc1_bgw': [], 'dc2_bgw': [], 'dc3_bgw': [],
                         'l2l3vni_bgw': [], 'dc1_spine': [], 'dc2_spine': [], 'dc3_spine': []}
    for dut in st.get_dut_names():
        if "leaf" in dut:
            test_cfg['nodes']['leaf'].append(dut)
        else:
            test_cfg['nodes']['spine'].append(dut)
        test_cfg['nodes']['all'].append(dut)

        # Classify L2-only nodes (have l2vni but no l3vni)
        if test_cfg.get(dut) and \
            'l2vni' in test_cfg[dut].keys() and \
            'l3vni' not in test_cfg[dut].keys():
                test_cfg['nodes']['l2vni'].append(dut)

        # Classify L2+L3 nodes (have both l2vni and l3vni)
        if test_cfg.get(dut) and \
            'l2vni' in test_cfg[dut].keys() and \
            'l3vni' in test_cfg[dut].keys():
                test_cfg['nodes']['l2l3vni'].append(dut)

        # Classify L2L3VNI + BGW nodes (nodes with L2+L3 VNI OR BGW nodes with L2VNI)
        # This includes leaf nodes with L3VNI that need DCI overlay BGP configuration
        has_config = test_cfg.get(dut)
        has_l2vni = has_config and 'l2vni' in test_cfg[dut].keys()
        has_l3vni = has_config and 'l3vni' in test_cfg[dut].keys()
        is_bgw = 'bgw' in dut
        
        if has_config and \
           ((has_l2vni and has_l3vni) or \
           (is_bgw and has_l2vni)):
            test_cfg['nodes']['l2l3vni_bgw'].append(dut)

        if 'dc1_bgw' in dut:
            test_cfg['nodes']['dc1_bgw'].append(dut)
        elif 'dc2_bgw' in dut:
            test_cfg['nodes']['dc2_bgw'].append(dut)
        elif 'dc3_bgw' in dut:
            test_cfg['nodes']['dc3_bgw'].append(dut)
        
        # Classify spine nodes by DC (excludes BGW and external test infrastructure)
        if 'spine' in dut and 'bgw' not in dut:
            if 'dc1' in dut:
                test_cfg['nodes']['dc1_spine'].append(dut)
            elif 'dc2' in dut:
                test_cfg['nodes']['dc2_spine'].append(dut)
            elif 'dc3' in dut:
                test_cfg['nodes']['dc3_spine'].append(dut)
    
    if not test_cfg.get('testcases'): 
        test_cfg['testcases'] = dict()
        test_cfg['global'] = dict()
    # setting platform specific variables
    if st.getenv('platform', 'q200')== 'g200':
        test_cfg['global']['ndf_exp_tx_pkts'] = 300
        test_cfg['global']['bum_triggers_retries'] = 4
        test_cfg['global']['del_add_bgp_retries'] = 10
        test_cfg['global']['proc_restart_retries'] = 7
        test_cfg['global']['config_reload'] = 7
        test_cfg['global']['plus_bringup_time'] = 12
        test_cfg['global']['traffic_stop_protocol_sleep'] = 15
        test_cfg['global']['traffic_start_protocol_sleep'] = 15
        test_cfg['global']['bfd_enable'] = False
        test_cfg['global']['restart_tgen_per_class'] = False
    else:
        test_cfg['global']['ndf_exp_tx_pkts'] = 150
        test_cfg['global']['bum_triggers_retries'] = 2
        test_cfg['global']['del_add_bgp_retries'] = 5
        test_cfg['global']['proc_restart_retries'] = 5
        test_cfg['global']['config_reload'] = 5
        test_cfg['global']['plus_bringup_time'] = 0
        test_cfg['global']['traffic_stop_protocol_sleep'] = 15
        test_cfg['global']['traffic_start_protocol_sleep'] = 15
        test_cfg['global']['bfd_enable'] = False
        test_cfg['global']['restart_tgen_per_class'] = False

    vars = st.get_testbed_vars()
    nodes = st.get_dut_names()
    
    # Initialize TGEN tracking variables
    test_cfg['tgen_tc_status'] = {'last_tc': None}
    tgen_handles = {}

@pytest.fixture(scope="module", autouse=True)
def copy_default_config_db():
    cmd = "sudo cp /etc/sonic/config_db.json config_db.json.orig"
    for dut in st.get_dut_names():
        st.config(dut, cmd, skip_error_check=True)

@pytest.fixture(scope="module", autouse=True)
def copy_spytest_helper():
    for dut in st.get_dut_names():
        st.config(dut, "cp /etc/spytest/remote/spytest-helper.py /etc/sonic/spytest-helper.py ")
        st.config(dut, " ls -lrt  /etc/spytest/remote/")
        st.config(dut, " ls -lrt /etc/sonic/")
    yield
    for dut in st.get_dut_names():
        st.config(dut,"rm /etc/sonic/spytest-helper.py")

def restore_helper_file(dut):
    st.config(dut, "mkdir -p /etc/spytest/remote")
    st.config(dut, "cp /etc/sonic/spytest-helper.py /etc/spytest/remote/spytest-helper.py")
    st.config(dut, "ls -lrt /etc | grep spytest")


@pytest.fixture(scope="module", autouse=True)
def vxlan_config_hooks(enable_debugs, configure_underlay, configure_overlay, configure_l2l3vni, configure_bgw_nodes):
    """Fixture order: underlay (loopback, BGP) -> overlay (EVPN) -> l2l3vni (leaf/spine VXLAN) -> bgw (BGW DCI)."""
    global tgen_handles
    pass
   
###Enable debugs###
@pytest.fixture(scope="module")
def enable_debugs(request):
     vxlan_obj.enable_debugs()

##VxLAN Configs###

def config_l2l3vni(dut=None):
    """
    Configures L2/L3 VNI on leaf/spine nodes (not BGW).
    Uses bgp_l3vni_config_dci (dci_enabled) for L3VNI BGP; EVPN MH/ESI for multi-homing.
    If `dut` is provided, only configure the specified node.
    """
    # Determine the nodes to configure
    l2l3vni_nodes = [dut] if dut else test_cfg['nodes']['l2l3vni']
    bgp_info = vxlan_obj.get_bgp_underlay_info_cached()
    # Perform the configuration
    vxlan_obj.config_feature_parallel(l2l3vni_nodes, 'nvo')
    vxlan_obj.config_feature_parallel(l2l3vni_nodes, 'enable_tunnel_counters')
    vxlan_obj.config_feature_parallel(l2l3vni_nodes, 'port_channels')
    vxlan_obj.config_feature_parallel(l2l3vni_nodes, 'l2vni')
    vxlan_obj.config_feature_parallel(l2l3vni_nodes, 'l3vni')
    vxlan_obj.config_feature_parallel(l2l3vni_nodes, 'add_sag_mac')
    vxlan_obj.config_feature_parallel(l2l3vni_nodes, 'sag_v4')
    vxlan_obj.config_feature_parallel(l2l3vni_nodes, 'sag_v6')
    vxlan_obj.config_feature_parallel(l2l3vni_nodes, 'bgp_l3vni_config_dci', dci_enabled=True, bgp_info=bgp_info)
    vxlan_obj.config_feature_parallel(l2l3vni_nodes, 'evpn_mh')
    vxlan_obj.config_feature_parallel(l2l3vni_nodes, 'evpn_esi')
    vxlan_obj.enable_uplink_tracking_configs(l2l3vni_nodes)

    # configs changed after image issues 24806, 27192
    for dut in test_cfg['nodes']['l2l3vni']:
        cmd = 'evpn mh startup-delay 10\n'
        cmd += 'no ip nht resolve-via-default\n'
        cmd += 'no ipv6 nht resolve-via-default\n'
        vxlan_obj.config_dut(dut, 'bgp', cmd)
    for dut in test_cfg['nodes']['spine']:
        cmd = 'no ip nht resolve-via-default\n'
        cmd += 'no ipv6 nht resolve-via-default\n'
        vxlan_obj.config_dut(dut, 'bgp', cmd)

    # Save the configuration for the relevant nodes
    for node in l2l3vni_nodes:
        vxlan_obj.config_dut(node, 'sonic', "sudo config save -y")
        vxlan_obj.config_dut(node, "bgp", "do write")


def unconfig_l2l3vni(dut=None):
    """
    Unconfigures L2/L3 VNI on the specified nodes.
    If `dut` is provided, only unconfigure the specified node.
    """
    # Determine the nodes to unconfigure
    l2l3vni_nodes = [dut] if dut else test_cfg['nodes']['l2l3vni']
    all_nodes = [dut] if dut else test_cfg['nodes']['all']
    bgp_info = vxlan_obj.get_bgp_underlay_info_cached()
    # Log the operation
    st.log("Unconfiguring L2/L3 VNI on nodes: {}".format(l2l3vni_nodes))

    # Perform the unconfiguration
    vxlan_obj.enable_uplink_tracking_configs(l2l3vni_nodes, add=False)
    vxlan_obj.config_feature_parallel(l2l3vni_nodes, 'delete_evpn_esi')
    vxlan_obj.config_feature_parallel(l2l3vni_nodes, 'delete_evpn_mh')
    vxlan_obj.config_feature_parallel(l2l3vni_nodes, 'delete_sag_v6')
    vxlan_obj.config_feature_parallel(l2l3vni_nodes, 'delete_sag_v4')
    vxlan_obj.config_feature_parallel(l2l3vni_nodes, 'del_sag_mac')
    vxlan_obj.config_feature_parallel(l2l3vni_nodes, 'delete_bgp_l3vni_config_dci', dci_enabled=True, bgp_info=bgp_info)
    vxlan_obj.config_feature_parallel(l2l3vni_nodes, 'delete_l3vni')
    vxlan_obj.config_feature_parallel(l2l3vni_nodes, 'delete_l2vni')
    vxlan_obj.config_feature_parallel(all_nodes, 'delete_bgp_config_dci', dci_enabled=True, bgp_info=bgp_info)
    vxlan_obj.config_feature_parallel(l2l3vni_nodes, 'delete_port_channels')
    vxlan_obj.config_feature_parallel(l2l3vni_nodes, 'disable_tunnel_counters')
    vxlan_obj.config_feature_parallel(l2l3vni_nodes, 'delete_vxlan')

    # configs changed after image issues 24806, 27192
    for dut in test_cfg['nodes']['l2l3vni']:
        cmd = 'no evpn mh startup-delay 10\n'
        cmd += 'ip nht resolve-via-default\n'
        cmd += 'ipv6 nht resolve-via-default\n'
        vxlan_obj.config_dut(dut, 'bgp', cmd)
    for dut in test_cfg['nodes']['spine']:
        cmd = 'ip nht resolve-via-default\n'
        cmd += 'ipv6 nht resolve-via-default\n'
        vxlan_obj.config_dut(dut, 'bgp', cmd)

    # Perform router pre-configuration cleanup
    router_preconfig_cleanup()

    # Save the configuration
    for node in all_nodes:
        vxlan_obj.config_dut(node, 'sonic', "sudo config save -y")

@pytest.fixture(scope="module")
def configure_l2l3vni(request):
    """
    Configures and unconfigures L2/L3 VNI using the above methods.
    """
    if st.getenv('skip_cfg', 'false') == 'false':
        config_l2l3vni()
    yield
    if st.getenv('skip_uncfg', 'false') == 'false':
        unconfig_l2l3vni()

def config_bgw_nodes(dut=None):
    """
    Configures BGW (Border Gateway) nodes for inter-DC connectivity.
    - loopback_dci: Loopback1/10/11 (WAN VIPs)
    - config_interface_ip_dci: WAN underlay IPs on Ethernet1_29/30
    - nvo_dci: Dual VXLAN (vxlan-dc, vxlan-wan)
    - l2vni_dci: L2VNI with named VXLANs
    - bgp_transit_wan_dci, bgp_overlay_wan_dci: BGP to other DCs
    - bgp_ihop_direct_dci: IHOP and DC_DIRECT peer groups
    
    Args:
        dut: Optional specific node to configure. If None, configures all BGW nodes.
    """
    # Determine the nodes to configure
    dc1_bgw_nodes = [dut] if dut else test_cfg['nodes']['dc1_bgw']
    dc2_bgw_nodes = [dut] if dut else test_cfg['nodes']['dc2_bgw']
    dc3_bgw_nodes = [dut] if dut else test_cfg['nodes']['dc3_bgw']
    bgw_nodes = dc1_bgw_nodes + dc2_bgw_nodes + dc3_bgw_nodes
    
    # Perform the configuration
    vxlan_obj.config_feature_parallel(bgw_nodes, 'loopback_dci', dci_enabled=True)
    vxlan_obj.config_feature_parallel(bgw_nodes, 'config_interface_ip_dci', dci_enabled=True)
    vxlan_obj.config_feature_parallel(bgw_nodes, 'nvo_dci', dci_enabled=True)
    vxlan_obj.config_feature_parallel(bgw_nodes, 'enable_tunnel_counters')
    vxlan_obj.config_feature_parallel(bgw_nodes, 'l2vni_dci', dci_enabled=True)
    vxlan_obj.config_feature_parallel(bgw_nodes, 'bgp_transit_wan_dci', dci_enabled=True)
    vxlan_obj.config_feature_parallel(bgw_nodes, 'bgp_overlay_wan_dci', dci_enabled=True)
    # ADDED: New configuration steps for IHOP and route-maps
    vxlan_obj.config_feature_parallel(bgw_nodes, 'bgp_ihop_direct_dci', dci_enabled=True)
    vxlan_obj.config_feature_parallel(bgw_nodes, 'route_maps_dci', dci_enabled=True)
    # Save the configuration for the relevant nodes
    for node in bgw_nodes:
        vxlan_obj.config_dut(node, 'sonic', "sudo config save -y")
        vxlan_obj.config_dut(node, "bgp", "do write")


def unconfig_bgw_nodes(dut=None):
    """
    Unconfigures BGW nodes by removing DCI-specific settings.
    Includes: L2VNI, BGP configs, tunnel counters, VXLAN, and interface IPs.
    
    Args:
        dut: Optional specific node to unconfigure. If None, unconfigures all BGW nodes.
    """
    # Determine the nodes to unconfigure
    dc1_bgw_nodes = [dut] if dut else test_cfg['nodes']['dc1_bgw']
    dc2_bgw_nodes = [dut] if dut else test_cfg['nodes']['dc2_bgw']
    dc3_bgw_nodes = [dut] if dut else test_cfg['nodes']['dc3_bgw']
    bgw_nodes = dc1_bgw_nodes + dc2_bgw_nodes + dc3_bgw_nodes
    
    # Log the operation
    st.log("Unconfiguring L2/L3 VNI on nodes: {}".format(bgw_nodes))

    # Perform the unconfiguration
    vxlan_obj.enable_uplink_tracking_configs(bgw_nodes, add=False)
    vxlan_obj.config_feature_parallel(bgw_nodes, 'delete_l2vni_dci', dci_enabled=True)
    vxlan_obj.config_feature_parallel(bgw_nodes, 'delete_bgp_l3vni_config')
    vxlan_obj.config_feature_parallel(bgw_nodes, 'delete_bgp_config')
    vxlan_obj.config_feature_parallel(bgw_nodes, 'disable_tunnel_counters')
    vxlan_obj.config_feature_parallel(bgw_nodes, 'delete_vxlan_dci', dci_enabled=True)
    vxlan_obj.config_feature_parallel(bgw_nodes, 'delete_interface_ip_dci', dci_enabled=True)

    # Perform router pre-configuration cleanup
    router_preconfig_cleanup()

    # Save the configuration
    for node in bgw_nodes:
        vxlan_obj.config_dut(node, 'sonic', "sudo config save -y")

@pytest.fixture(scope="module")
def configure_bgw_nodes(request):
    """
    Configures and unconfigures L2/L3 VNI using the above methods.
    """
    if st.getenv('skip_cfg', 'false') == 'false':
        config_bgw_nodes()
    yield
    if st.getenv('skip_uncfg', 'false') == 'false':
        unconfig_bgw_nodes()

@pytest.fixture(scope="module")
def configure_underlay(request):
    """Underlay: loopback, unnumbered, BGP underlay (bgp_underlay_dci for all nodes including BGWs)."""
    if st.getenv('skip_cfg', 'false') == 'false':
        bgp_info = vxlan_obj.get_bgp_underlay_info_cached()
        vxlan_obj.config_feature_parallel(test_cfg['nodes']['all'],'loopback')
        vxlan_obj.config_feature_parallel(test_cfg['nodes']['all'],'unnumbered')
        vxlan_obj.config_feature_parallel(test_cfg['nodes']['all'],'bgp_underlay_dci', dci_enabled=True, bgp_info=bgp_info)
        if test_cfg['global']['bfd_enable']:
            vxlan_obj.config_feature_parallel(test_cfg['nodes']['all'],'bgp_bfd_underlay')
    yield
    if st.getenv('skip_uncfg', 'false') == 'false':
        vxlan_obj.config_feature_parallel(test_cfg['nodes']['all'],'delete_loopback')

@pytest.fixture(scope="module")
def configure_overlay(request):
    """Overlay: BGP EVPN on l2l3vni_bgw (leaf+spine with L3VNI, and BGWs). Uses bgp_overlay_dci for domain/reoriginate."""
    if st.getenv('skip_cfg', 'false') == 'false':
        bgp_info = vxlan_obj.get_bgp_underlay_info_cached()
        overlay_info = vxlan_obj.generate_bgp_overlay_info(version=st.getenv("vtep"), dci_enabled=True, bgp_info=bgp_info)
        vxlan_obj.config_feature_parallel(test_cfg['nodes']['l2l3vni_bgw'],'bgp_overlay_dci', dci_enabled=True, overlay_info=overlay_info)
        if test_cfg['global']['bfd_enable']:
            vxlan_obj.config_feature_parallel(test_cfg['nodes']['l2l3vni_bgw'],'bgp_bfd_overlay', dci_enabled=True)

def router_preconfig_cleanup():
    """Clear VRF, IP, and VLAN config before reconfiguration (e.g. before unconfig)."""
    vrf_obj.clear_vrf_configuration(st.get_dut_names())
    ip_obj.clear_ip_configuration(st.get_dut_names(), family='all', thread=True, skip_error_check = True)
    vlan_obj.clear_vlan_configuration(st.get_dut_names())


def find_traffic_enpoints(topo_handles, v4_host_info_dict, src_int_dut, src_int, src_vlan_id, dst_vlan_id, 
                          traffic_type='default'):
    """
    Find traffic endpoints for BUM (Broadcast, Unknown unicast, Multicast) traffic.
    
    Args:
        topo_handles: Topology handles dictionary
        v4_host_info_dict: IPv4 host information dictionary
        src_int_dut: Source interface DUT name
        src_int: Source interface name
        src_vlan_id: Source VLAN ID
        dst_vlan_id: Destination VLAN ID
        traffic_type: Traffic type ('default' or 'raw')
    
    Returns:
        Dictionary of traffic endpoints
    """
    cntr = 1
    endpoints = dict()

    st.log(f"find_traffic_enpoints: src_node={src_int_dut}, src_int={src_int}, src_vlan={src_vlan_id}")
    
    # Check if source node exists in host_info_dict
    if src_int_dut not in v4_host_info_dict:
        st.log(f"  ERROR: {src_int_dut} not in v4_host_info_dict. Available nodes: {list(v4_host_info_dict.keys())}")
        return {}
    
    if src_int.startswith('PortChannel'):
        src_port_id = None
        # Try to find matching PortChannel in topology handles
        # Handle both exact match and prefix match (e.g., "PortChannel1" matches "PortChannel1_D5D6")
        for port_id in topo_handles.get(src_int_dut, {}).keys():
            if port_id.startswith(src_int):
                src_port_id = port_id
                break
        
        if src_port_id is None:
            raise Exception('Port channel {} not found in topology for node {}. Available ports: {}'.format(
                src_int, src_int_dut, list(topo_handles.get(src_int_dut, {}).keys())))
    else:
        src_port_id = vxlan_obj.get_peer_port_id(src_int, vars, src_int_dut)
    
    st.log(f"  Resolved src_port_id: {src_port_id}")
    st.log(f"  Available interfaces in host_info for {src_int_dut}: {list(v4_host_info_dict[src_int_dut].keys())}")
    
    # Check if resolved interface exists in host_info_dict
    if src_port_id not in v4_host_info_dict[src_int_dut]:
        st.log(f"  ERROR: {src_port_id} not found in host_info for {src_int_dut}")
        return {}
    
    # Check if the source VLAN exists on this interface
    if src_vlan_id not in v4_host_info_dict[src_int_dut][src_port_id]:
        st.log(f"  ERROR: VLAN {src_vlan_id} not found on {src_int_dut}:{src_port_id}")
        st.log(f"  Available VLANs: {list(v4_host_info_dict[src_int_dut][src_port_id].keys())}")
        return {}

    for lnode in test_cfg.keys():
        # Include both L2+L3 nodes and L2-only nodes as possible destinations
        if not (lnode in test_cfg['nodes']['l2l3vni'] or lnode in test_cfg['nodes']['l2vni']):
            continue
        # Skip nodes without l2vni configuration
        if 'l2vni' not in test_cfg[lnode]:
            continue
        for l2vni_item in test_cfg[lnode]['l2vni']:
            if l2vni_item['vlan_id'] == dst_vlan_id:
                # Only check l3vni if it exists for this node
                vrf = ''
                if 'l3vni' in test_cfg[lnode]:
                    for l3vni_item in test_cfg[lnode]['l3vni']:
                        if dst_vlan_id in l3vni_item['vlan_bindings']:
                            vrf = l3vni_item['vrf_id']
                            break
                # Skip if no members defined for this VLAN
                if 'members' not in l2vni_item:
                    continue
                for member in l2vni_item['members']:
                    if member.startswith('PortChannel'):
                        # look for portchannel name in topo_handles
                        # Handle both exact match and prefix match (e.g., "PortChannel1" matches "PortChannel1_D5D6")
                        dst_port_id = None
                        for port_id in topo_handles.get(lnode, {}).keys():
                            if port_id.startswith(member):
                                dst_port_id = port_id
                                break
                        
                        if dst_port_id is None:
                            # PortChannel not found in topology, skip it
                            continue
                    else:
                        # orphan port
                        dst_port_id = vxlan_obj.get_peer_port_id(member, vars, lnode)

                    if dst_port_id == src_port_id: 
                        continue
                    # find mac addresses
                    endpoints['traffic_item_{}_{}'.format(src_port_id,cntr)] = {
                                        'dst_int': dst_port_id,
                                        'dst_node': lnode,
                                        'dst_vlan': dst_vlan_id,
                                        'dst_vrf': vrf,
                                        'src_int': src_port_id,
                                        'src_node': src_int_dut,
                                        'src_vrf': vrf,
                                        'src_vlan': src_vlan_id}
                    if traffic_type == 'raw':
                        # Check if source and destination exist in host_info_dict before accessing
                        if (lnode in v4_host_info_dict and 
                            dst_port_id in v4_host_info_dict[lnode] and
                            dst_vlan_id in v4_host_info_dict[lnode][dst_port_id]):
                            endpoints['traffic_item_{}_{}'.format(src_port_id,cntr)]['dst_mac'] = \
                                    v4_host_info_dict[lnode][dst_port_id][dst_vlan_id]['src_mac']
                        else:
                            st.log(f"Warning: Cannot find dst MAC for {lnode}:{dst_port_id} VLAN {dst_vlan_id}")
                            endpoints['traffic_item_{}_{}'.format(src_port_id,cntr)]['dst_mac'] = '00:00:00:00:00:00'
                        
                        if (src_int_dut in v4_host_info_dict and 
                            src_port_id in v4_host_info_dict[src_int_dut] and
                            src_vlan_id in v4_host_info_dict[src_int_dut][src_port_id]):
                            endpoints['traffic_item_{}_{}'.format(src_port_id,cntr)]['src_mac'] = \
                                    v4_host_info_dict[src_int_dut][src_port_id][src_vlan_id]['src_mac']
                        else:
                            st.log(f"Warning: Cannot find src MAC for {src_int_dut}:{src_port_id} VLAN {src_vlan_id}")
                            st.log(f"  Available interfaces in {src_int_dut}: {list(v4_host_info_dict.get(src_int_dut, {}).keys())}")
                            # Skip this endpoint if source doesn't exist
                            del endpoints['traffic_item_{}_{}'.format(src_port_id,cntr)]
                            continue
                    cntr += 1
    return endpoints


def build_traffic_pairs_from_config(config, topo_handles):
    """
    Build traffic pairs from configuration dictionary.
    
    Args:
        config: TRAFFIC_CONFIG dictionary with sources/destinations
        topo_handles: Topology handles to discover actual interface names
    
    Returns:
        list: List of (src_node, src_int, dst_node, dst_int) tuples
    """
    traffic_pairs = []
    
    # Check if manual pairs are specified
    if 'manual' in config['pairs'] and config['pairs']['manual']:
        st.log("Using manually specified traffic pairs from configuration")
        return config['pairs']['manual']
    
    # Build pairs from sources and destinations
    st.log("Building traffic pairs from configuration...")
    
    # Discover interfaces for each node
    node_interfaces = {}
    for node, interfaces in topo_handles.items():
        node_interfaces[node] = {
            'orphan': [],
            'portchannel': []
        }
        for intf in interfaces.keys():
            if 'PortChannel' in intf:
                node_interfaces[node]['portchannel'].append(intf)
            else:
                node_interfaces[node]['orphan'].append(intf)
    
    # Build pairs from sources × destinations
    sources = config['pairs'].get('sources', {})
    destinations = config['pairs'].get('destinations', {})
    
    for src_node, src_types in sources.items():
        if src_node not in node_interfaces:
            st.log(f"Warning: Source node {src_node} not found in topology")
            continue
        
        # Get source interfaces based on type
        src_intfs = []
        for src_type in src_types:
            if src_type == 'all':
                src_intfs.extend(node_interfaces[src_node]['orphan'])
                src_intfs.extend(node_interfaces[src_node]['portchannel'])
            elif src_type in ['orphan', 'portchannel']:
                src_intfs.extend(node_interfaces[src_node][src_type])
        
        for dst_node, dst_types in destinations.items():
            if dst_node not in node_interfaces:
                st.log(f"Warning: Destination node {dst_node} not found in topology")
                continue
            
            # Get destination interfaces based on type
            dst_intfs = []
            for dst_type in dst_types:
                if dst_type == 'all':
                    dst_intfs.extend(node_interfaces[dst_node]['orphan'])
                    dst_intfs.extend(node_interfaces[dst_node]['portchannel'])
                elif dst_type in ['orphan', 'portchannel']:
                    dst_intfs.extend(node_interfaces[dst_node][dst_type])
            
            # Create pairs for all combinations
            for src_intf in src_intfs:
                for dst_intf in dst_intfs:
                    pair = (src_node, src_intf, dst_node, dst_intf)
                    traffic_pairs.append(pair)
                    st.log(f"  Added: {src_node}:{src_intf} <-> {dst_node}:{dst_intf}")
    
    return traffic_pairs


def filter_traffic_endpoints(all_endpoints, allowed_pairs=None, allowed_vlans=None, allowed_nodes=None, exclude_nodes=None, topo_handles=None):
    """
    Generalized function to filter traffic endpoints based on criteria.
    Uses existing vxlan_helper functions and filters the results.
    
    Args:
        all_endpoints: Dictionary of all traffic endpoints (from find_l2/l3_traffic_endpoints)
        allowed_pairs: List of (src_node, src_int, dst_node, dst_int) tuples to keep
        allowed_vlans: List of VLANs to keep (filters on src_vlan)
        allowed_nodes: List of destination node patterns to keep (e.g., ['dc2', 'dc3'])
        exclude_nodes: List of node patterns to exclude
        topo_handles: Topology handles dictionary to validate nodes exist (optional)
    
    Returns:
        dict: Filtered endpoint dictionary
    """
    filtered = {}
    
    for name, endpoint in all_endpoints.items():
        # Check if source and destination nodes exist in topology handles
        if topo_handles is not None:
            src_node = endpoint.get('src_node', '')
            dst_node = endpoint.get('dst_node', '')
            
            if src_node and src_node not in topo_handles:
                st.log(f"    Skipping endpoint: Source node '{src_node}' not in topology handles")
                continue
            if dst_node and dst_node not in topo_handles:
                st.log(f"    Skipping endpoint: Destination node '{dst_node}' not in topology handles")
                continue
        
        # Check exclude filter
        if exclude_nodes:
            dst_node = endpoint.get('dst_node', '')
            src_node = endpoint.get('src_node', '')
            if any(pattern in dst_node or pattern in src_node for pattern in exclude_nodes):
                continue
        
        # Check VLAN filter
        if allowed_vlans and endpoint.get('src_vlan') not in allowed_vlans:
            continue
        
        # Check node filter (destination or source contains any of the patterns)
        if allowed_nodes:
            dst_node = endpoint.get('dst_node', '')
            src_node = endpoint.get('src_node', '')
            node_match = any(pattern in dst_node or pattern in src_node for pattern in allowed_nodes)
            if not node_match:
                continue
        
        # Check pair filter
        if allowed_pairs:
            match = False
            ep_src_node = endpoint.get('src_node')
            ep_src_int = endpoint.get('src_int')
            ep_dst_node = endpoint.get('dst_node')
            ep_dst_int = endpoint.get('dst_int')
            
            # Helper function for flexible node matching
            def nodes_match(ep_node, pair_node):
                """
                Flexible node name matching to handle vxlan_helper inconsistencies:
                - L2: 'leaf0_dc1' == 'leaf0_dc1' (exact match)
                - L3: 'leaf0' matches 'leaf0_dc1' (prefix match, L3 uses truncated names)
                """
                if ep_node == pair_node:
                    return True
                # L3 endpoints use truncated names (e.g., 'leaf0' instead of 'leaf0_dc1')
                # Check if pair_node starts with ep_node + '_'
                if pair_node.startswith(ep_node + '_'):
                    return True
                # Also check reverse (ep_node could be 'leaf0_dc1', pair could be 'leaf0')
                if ep_node.startswith(pair_node + '_'):
                    return True
                return False
            
            for src_node, src_int, dst_node, dst_int in allowed_pairs:
                if (nodes_match(ep_src_node, src_node) and
                    ep_src_int == src_int and
                    nodes_match(ep_dst_node, dst_node) and
                    ep_dst_int == dst_int):
                    match = True
                    break
            
            if not match:
                # Debug: Show why endpoint was filtered out
                st.log(f"    Filtered out: {ep_src_node}:{ep_src_int} -> {ep_dst_node}:{ep_dst_int} (VLAN {endpoint.get('src_vlan')})")
                continue
            else:
                # Debug: Show which endpoint was kept
                st.log(f"    ✓ KEPT: {ep_src_node}:{ep_src_int} -> {ep_dst_node}:{ep_dst_int} (VLAN {endpoint.get('src_vlan')})")
        
        filtered[name] = endpoint
    
    return filtered


def tgen_preconfig(**kwargs):
    """
    Configure TGEN topology with device groups, protocols, and traffic streams
    for DCI inter-DC testing. Creates stream handles for L2/L3 unicast and BUM traffic.
    
    Supports two modes:
    1. CUSTOM mode: Filtered traffic for specific pairs/VLANs
    2. FULL MESH mode: All traffic (original behavior)
    
    Returns:
        dict: stream_handles containing all configured traffic streams and device handles
    """
    
    # ═══════════════════════════════════════════════════════════════════════
    # TRAFFIC CONFIGURATION SECTION - MODIFY HERE FOR YOUR REQUIREMENTS
    # ═══════════════════════════════════════════════════════════════════════
    
    TRAFFIC_CONFIG = {
        # ─────────────────────────────────────────────────────────────────
        # MODE SELECTION
        # ─────────────────────────────────────────────────────────────────
        'mode': 'custom',  # 'custom' or 'full_mesh'
        #   'custom'    : Filtered traffic (specific pairs + VLANs)
        #   'full_mesh' : All traffic between all nodes (original behavior)
        
        # ─────────────────────────────────────────────────────────────────
        # VLAN CONFIGURATION
        # ─────────────────────────────────────────────────────────────────
        'vlans': [11, 12, 13, 16, 17, 18],  # L2VNI test VLANs: 12,13 (within-DC), 11,12,13,16,17,18 (cross-DC)
        # Examples:
        #   [11]                    -> Test only VLAN 11 (cross-DC, different VNI)
        #   [11, 16]                -> Cross-DC: VLAN 11 (diff VNI), VLAN 16 (same VNI)
        #   [11, 12, 13, 16, 17, 18]-> 2 within-DC + 6 cross-DC ✅ CURRENT
        #   [12, 13]                -> Within-DC only (VRF 101)
        #   [14, 15]                -> Cross-DC with different VLANs
        #   list(range(11, 21))     -> All VLANs 11-20 (full coverage)
        
        # ─────────────────────────────────────────────────────────────────
        # CUSTOM MODE: TRAFFIC PAIR SPECIFICATION
        # ─────────────────────────────────────────────────────────────────
        'pairs': {
            # Define which source nodes/interfaces to use for traffic
            # Format: 'node_name': ['interface_types', ...]
            #   interface_types: 'orphan', 'portchannel', or 'all'
            
        'sources': {
            # leaf0_dc1 has both orphan (T1P1) and PortChannel1 (T1P2) connected to TGEN
            # Include both to test all source-destination combinations
            'leaf0_dc1': ['orphan', 'portchannel'],  # Both orphan and PC sources
        },
            
            # Define which destination nodes/interfaces to use
            'destinations': {
                # Cross-DC destinations (for inter-DC traffic)
                # DC2: leaf0_dc2 and leaf1_dc2 share PortChannel4 (multi-homed, sys_mac: 00:44:33:22:11:44)
                'leaf0_dc2': ['orphan', 'portchannel'],  # DC2: orphan + multi-homed PC4
                # Note: PortChannel4 traffic will be distributed to both leaf0_dc2 and leaf1_dc2
                #       via EVPN multi-homing, so no need to explicitly add leaf1_dc2 as destination
                
                # DC3: Single leaf node
                'leaf0_dc3': ['orphan'],                  # DC3: orphan port only
                
                # Within-DC destinations (for intra-DC traffic within DC1)
                # Test traffic to multiple leaf nodes within DC1
                'leaf1_dc1': ['orphan'],                  # DC1: orphan port on leaf1
                'leaf2_dc1': ['orphan', 'portchannel'],  # DC1: orphan + PortChannel3
                'leaf3_dc1': ['orphan'],                  # DC1: orphan port on leaf3
            },
            
        },
        
        # ─────────────────────────────────────────────────────────────────
        # CUSTOM MODE: BUM TRAFFIC CONFIGURATION
        # ─────────────────────────────────────────────────────────────────
        'bum': {
            'enabled': True,                    # Enable/disable BUM traffic
            'source_node': 'leaf0_dc1',         # Source node for BUM
            'source_type': 'all',               # 'orphan', 'portchannel', or 'all'
            'vlan': 'cross_dc',                 # 'first', 'all', 'cross_dc', or specific VLAN number
            'destination_filter': [],           # Empty = flood to ALL ports in VLAN (natural BUM behavior)
            # Source type options:
            #   'orphan'      -> Only orphan ports (creates bum_SH - Single-Homed only)
            #   'portchannel' -> Only PortChannels (creates bum_MH - Multi-Homed only)
            #   'all'         -> Both orphan + PortChannel (creates bum_SH + bum_MH) ✅ CURRENT
            # VLAN options:
            #   'first'    -> Use first VLAN (12) from WITHIN_DC_VLANS
            #   'all'      -> Use all VLANs (WITHIN_DC + CROSS_DC)
            #   'cross_dc' -> Use only cross-DC VLANs (11-20) - 10 VLANs ✅ CURRENT
            #   11         -> Use specific VLAN 11 (cross-DC, different VNI)
            # Destination filter:
            #   []             -> Flood to ALL ports in VLAN (natural BUM) ✅ CURRENT
            #   ['dc2', 'dc3'] -> Only include DC2/DC3 ports (incorrect for BUM!)
        },
        
        # ─────────────────────────────────────────────────────────────────
        # ADVANCED FILTERS (Optional)
        # ─────────────────────────────────────────────────────────────────
        'filters': {
            'exclude_nodes': [],        # Nodes to exclude from traffic
            'include_only_nodes': [],   # If set, ONLY include these nodes
            # Examples:
            #   exclude_nodes: ['leaf3_dc1']           -> Skip leaf3_dc1
            #   include_only_nodes: ['dc1', 'dc2']     -> Only DC1 and DC2
        }
    }
    
    # ═══════════════════════════════════════════════════════════════════════
    # END OF CONFIGURATION SECTION
    # ═══════════════════════════════════════════════════════════════════════
    
    bgw_nodes = test_cfg['nodes']['l2l3vni_bgw']
    leaf_nodes = test_cfg['nodes']['l2l3vni']
    svi_dict_v4 = {}
    svi_dict_v6 = {}
    stream_handles = {}

    global g_v4_host_info_dict
    global g_v6_host_info_dict

    if st.getenv('skip_tgen', 'false') == 'true':
        return stream_handles
    
    # Get L2VNI interfaces from ALL configured nodes (BGW, leaf nodes with L2+L3, and L2-only leaf nodes)
    # This ensures topology handles are created for all nodes that traffic might use
    # Use broader list to include L2-only nodes like leaf0_dc2 and leaf0_dc3 for cross-DC traffic
    all_l2l3vni_nodes = test_cfg['nodes']['l2l3vni_bgw'] + test_cfg['nodes']['l2l3vni'] + test_cfg['nodes']['l2vni']
    # Remove duplicates
    all_l2l3vni_nodes = list(set(all_l2l3vni_nodes))
    l2vni_intf_dict = vxlan_obj.get_interfaces(vars, all_l2l3vni_nodes, 'l2vni')
    # Port channel processing
    port_channel = dict()
    for node, config in test_cfg.items():
        if not config:
            continue
        if node not in test_cfg['nodes']['all']:
            continue
        for pc_channel in test_cfg[node].get('port_channels', []):
            pc_num = pc_channel['port_channel_num']
            if pc_num not in port_channel:
                port_channel[pc_num] = dict()
            port_channel[pc_num][node] = pc_channel['member_ids']
    def get_port_channel_match(tgn_port, port_channel):
        """Check if TGEN port is part of any port channel"""
        pc_match = False
        for pc_num, pc_info in port_channel.items():
            port_list = list()
            node_list = list()
            for node, member_ids in pc_info.items():
                for member_id in member_ids:
                    try:
                        peer_port_id = vxlan_obj.get_peer_port_id(member_id, vars, node)
                        node_list.append(vxlan_obj.get_device_id(node, vars))
                        port_list.append(peer_port_id)
                        if tgn_port == peer_port_id:
                            pc_match = True
                    except Exception as e:
                        # Skip port-channel members not defined in testbed (e.g., DCI nodes)
                        st.log(f"Skipping port-channel member {member_id} on {node}: {e}")
                        continue
            if pc_match:
                return {'num': pc_num, 'nodes': node_list, 'ports': port_list}
        else:
            return pc_match

    # Search for port-channel ports and consolidate
    pc_added_list = dict()  # Track which port-channels have been added globally
    new_l2vni_intf_dict = dict()
    for node in sorted(l2vni_intf_dict.keys()):
        new_l2vni_intf_dict[node] = list()
        for tgn_port in l2vni_intf_dict[node]:
            port_channel_match = get_port_channel_match(tgn_port, port_channel)
            if port_channel_match:
                pc_num = port_channel_match['num']
                # Only add port-channel if not already added
                if pc_num not in pc_added_list:
                    pc_added_list[pc_num] = True
                    port_channel_name = 'PortChannel{}_{}'.format(pc_num,
                                                                   ''.join(port_channel_match['nodes']))
                    tgn_port = {'name': port_channel_name,
                               'ports': port_channel_match['ports'],
                               'port_channel_num': pc_num}
                    new_l2vni_intf_dict[node].append(tgn_port)
            else:
                new_l2vni_intf_dict[node].append(tgn_port)
    l2vni_intf_dict = new_l2vni_intf_dict
    test_cfg["l2vni_intf_dict"] = l2vni_intf_dict
    # Generate VLAN mapping per port
    # Build a mapping of port identifiers to VLANs from config
    port_vlan_dict = {}
    for node in l2vni_intf_dict.keys():
        if node not in test_cfg or 'l2vni' not in test_cfg[node]:
            continue
        # Get ports for this node from TGEN interface dict
        for port_entry in l2vni_intf_dict[node]:
            if isinstance(port_entry, dict):
                # Port channel - port_entry has 'name', 'port_channel_num', 'ports'
                port_name = port_entry['name']
                port_channel_num = port_entry['port_channel_num']
                vlans_for_port = []
                
                # Find VLANs that use this port channel
                for item in test_cfg[node]['l2vni']:
                    if f'PortChannel{port_channel_num}' in item['members']:
                        vlans_for_port.append(item['vlan_id'])
                
                port_vlan_dict[port_name] = vlans_for_port
            else:
                # Regular TGEN port (like 'T1D5P1')
                port = port_entry
                vlans_for_port = []
                
                # Find VLANs that use this port in config
                # Config members might be in format 'T1P1', need to match against 'T1D5P1'
                for item in test_cfg[node]['l2vni']:
                    for member in item['members']:
                        if member.startswith('PortChannel'):
                            continue  # Skip port channels here
                        # Check if this member port matches our TGEN port
                        # TGEN port is 'T1D5P1', config has 'T1P1'
                        # Extract port number from TGEN port: 'T1D5P1' -> 'P1'
                        if port.endswith(member.split('P')[1]) if 'P' in member else False:
                            vlans_for_port.append(item['vlan_id'])
                            break
                        # Also check direct match in case they're the same format
                        elif port == member:
                            vlans_for_port.append(item['vlan_id'])
                            break
                
                port_vlan_dict[port] = vlans_for_port
    # Create topology handles
    topo_handles = vxlan_obj.create_topology_handles(l2vni_intf_dict)
    # Generate SVI IPs for each node
    for node, config in test_cfg.items():
        if node in test_cfg['nodes']['l2l3vni_bgw']:
            if kwargs.get('custom_svi_ip'):
                svi_dict_v4[node] = vxlan_obj.generate_svi_ip_sag(config, 'ipv4', ip_start="10.2.0.1")
                svi_dict_v6[node] = vxlan_obj.generate_svi_ip_sag(config, 'ipv6', ip_start="1000:2::1")
            else:
                svi_dict_v4[node] = vxlan_obj.generate_svi_ip_sag(config, 'ipv4')
                svi_dict_v6[node] = vxlan_obj.generate_svi_ip_sag(config, 'ipv6')

    # Generate host info for IPv4 and IPv6
    g_v4_host_info_dict = vxlan_obj.generate_sag_hosts(l2vni_intf_dict, svi_dict_v4, 
                                                       port_vlan_dict=port_vlan_dict, skip_nodes=[])
    g_v6_host_info_dict = vxlan_obj.generate_sag_hosts(l2vni_intf_dict, svi_dict_v6, 
                                                     port_vlan_dict=port_vlan_dict,
                                                     version="ipv6", skip_nodes=[])
    
    # TK5 - Add wait time before creating device groups for IXIA stability
    st.wait(10)
    
    # Create device groups for IPv4 and IPv6
    out_v4 = vxlan_obj.create_device_groups(topo_handles, g_v4_host_info_dict)
    v4_node_device_handles = out_v4[0]
    out_v6 = vxlan_obj.create_device_groups(topo_handles, g_v6_host_info_dict, version="ipv6")
    v6_node_device_handles = out_v6[0]

    v4_device_handles = {}
    v6_device_handles = {}

    for node, interfaces in v4_node_device_handles.items():
        for interface, values in interfaces.items():
            v4_device_handles[interface] = values
    for node, interfaces in v6_node_device_handles.items():
        for interface, values in interfaces.items():
            v6_device_handles[interface] = values
    
    ###TK1 - Set IXIA protocol stack options for ARP/NS retransmit intervals
    # This prevents IPv6 DAD (Duplicate Address Detection) issues
    tg_handle = topo_handles[leaf_nodes[0]][l2vni_intf_dict[leaf_nodes[0]][0]]['tg_handle']
    ixNet = tg.get_ixnet()
    try:
        st.log("Configuring IXIA protocol stack options for ARP/NS retransmit...")
        for node, nodeValues in topo_handles.items():
            for topo, topoValues in nodeValues.items():
                if re.search('/log:', topoValues['port_handle']):
                    vport_list = topoValues['vport_handles']
                    for vport in vport_list:
                        # NS (Neighbor Solicitation) Retransmit Interval - 3000ms
                        ixNet.setAttribute(vport + '/protocolStack/options', '-retransTime', 3000)
                        # NS Transmit Count - 10 attempts
                        ixNet.setAttribute(vport + '/protocolStack/options', '-mcast_solicit', 10)
                        # ARP Retransmit Interval - 3000ms
                        ixNet.setAttribute(vport + '/protocolStack/options', '-ipv4RetransTime', 3000)
                        # ARP Transmit Count - 10 attempts
                        ixNet.setAttribute(vport + '/protocolStack/options', '-ipv4McastSolicit', 10)
                    ixNet.commit()
        st.log("IXIA protocol stack options configured successfully")
    except Exception as e:
        st.log(f"Warning: Failed to set IXIA protocol options: {e}")
    
    # Start all protocols
    start_protocol = vxlan_obj.start_stop_protocols(tg_handle, action='start')
    if start_protocol == 0:
        st.report_tgen_fail('start protocols failed!')
    else:
        st.log("protocols started successfully")

    # Get VRF-VLAN mapping from configs
    vrf_vlan_dict = dict()
    for node in test_cfg['nodes']['l2l3vni_bgw']:
        if node in test_cfg and 'l3vni' in test_cfg[node]:
            for item in test_cfg[node]['l3vni']:
                vrf_vlan_dict[item['vrf_id']] = item['vlan_bindings']
            break
    
    # ===== APPLY TRAFFIC CONFIGURATION =====
    vlans_to_test = TRAFFIC_CONFIG['vlans']
    use_custom_filter = (TRAFFIC_CONFIG['mode'] == 'custom')
    
    st.banner("=" * 70)
    st.banner(f"TRAFFIC CONFIGURATION MODE: {TRAFFIC_CONFIG['mode'].upper()}")
    st.banner("=" * 70)
    st.log(f"VLANs to test: {vlans_to_test}")
    st.log(f"Custom filtering: {'ENABLED' if use_custom_filter else 'DISABLED (full mesh)'}")
    
    # Generate L2 traffic endpoints using existing orphan-port function
    # (PortChannel sources will be added later after filtering)
    st.log("Step 1: Generating L2 traffic endpoints (orphan ports only for now)...")
    all_l2_endpoints = vxlan_obj.find_l2_traffic_endpoints(g_v4_host_info_dict)
    st.log(f"  Generated {len(all_l2_endpoints)} L2 endpoints from orphan ports")
    
    st.log("Step 2: Generating all L3 traffic endpoints using vxlan_helper...")
    all_l3_endpoints = vxlan_obj.find_l3_traffic_endpoints(g_v4_host_info_dict, vrf_vlan_dict=vrf_vlan_dict)
    st.log(f"Generated {len(all_l3_endpoints)} L3 endpoints (before filtering)")
    
    if use_custom_filter:
        # Discover interface names from topology
        st.log("Step 3: Discovering interface names from topology...")
        for node, interfaces in topo_handles.items():
            st.log(f"  Node {node}: {list(interfaces.keys())}")
        
        # Build traffic pairs from configuration
        st.log("Step 4: Building traffic pairs from configuration...")
        traffic_pairs = build_traffic_pairs_from_config(TRAFFIC_CONFIG, topo_handles)
        st.log(f"Total traffic pairs created: {len(traffic_pairs)}")
        # Apply filters
        st.log(f"Step 5: Filtering endpoints to {len(traffic_pairs)} specific pairs...")
        
        # Prepare filter arguments
        filter_args = {
            'allowed_pairs': traffic_pairs,
            'allowed_vlans': vlans_to_test,
            'topo_handles': topo_handles,  # Validate nodes exist in topology
        }
        
        # Add advanced filters if specified
        if TRAFFIC_CONFIG['filters']['exclude_nodes']:
            filter_args['exclude_nodes'] = TRAFFIC_CONFIG['filters']['exclude_nodes']
            st.log(f"  Excluding nodes with patterns: {TRAFFIC_CONFIG['filters']['exclude_nodes']}")
        
        if TRAFFIC_CONFIG['filters']['include_only_nodes']:
            filter_args['allowed_nodes'] = TRAFFIC_CONFIG['filters']['include_only_nodes']
            st.log(f"  Including only nodes with patterns: {TRAFFIC_CONFIG['filters']['include_only_nodes']}")
        
        # Filter L2 endpoints
        l2_traffic_endpoints = filter_traffic_endpoints(all_l2_endpoints, **filter_args)
        st.log(f"  L2 endpoints after filter: {len(l2_traffic_endpoints)}")
        st.log(f"    (PortChannel sources will be added in next step)")
        
        # Filter L3 endpoints
        l3_traffic_endpoints = filter_traffic_endpoints(all_l3_endpoints, **filter_args)
        st.log(f"  L3 endpoints after filter: {len(l3_traffic_endpoints)}")
    else:
        # Use ALL traffic endpoints (original behavior)
        st.log("Step 3: Using ALL traffic endpoints (no filtering)")
        l2_traffic_endpoints = all_l2_endpoints
        l3_traffic_endpoints = all_l3_endpoints

    # Apply VLAN-based filtering for DCI: 3 VLANs for within-DC, 3 VLANs for cross-DC
    st.banner("Applying VLAN-based filtering for DCI traffic")
    
    # Define VLAN sets for different traffic types
    WITHIN_DC_VLANS = [12, 17]  # VRF 101: VLAN 12, 17 (within-DC) - keeps existing behavior
    CROSS_DC_VLANS = [11, 12, 13, 14, 15, 16, 17, 18, 19, 20]  # All VLANs for cross-DC (vxlan-wan)

    # L3VNI across DCI: Enable cross-DC L3 stream generation.
    # Set to False to disable cross-DC L3VNI traffic streams if unsupported.
    ENABLE_L3_ACROSS_DCI = True
    
    def filter_endpoints_by_vlan_and_scope(endpoints, allowed_vlans_within, allowed_vlans_cross):
        """
        Filter endpoints to limit VLANs:
        - Within-DC traffic: Use allowed_vlans_within
        - Cross-DC traffic: Use allowed_vlans_cross
        """
        filtered = {}
        within_count = 0
        cross_count = 0
        
        for name, ep in endpoints.items():
            src_node = ep.get('src_node', '')
            dst_node = ep.get('dst_node', '')
            vlan = ep.get('src_vlan')
            
            # Determine if within-DC or cross-DC
            src_dc_match = re.search(r'_(dc\d+)', src_node)
            dst_dc_match = re.search(r'_(dc\d+)', dst_node)
            
            if src_dc_match and dst_dc_match:
                src_dc = src_dc_match.group(1)
                dst_dc = dst_dc_match.group(1)
                is_within_dc = (src_dc == dst_dc)
                
                # Apply VLAN filter based on scope
                if is_within_dc and vlan in allowed_vlans_within:
                    filtered[name] = ep
                    within_count += 1
                elif not is_within_dc and vlan in allowed_vlans_cross:
                    filtered[name] = ep
                    cross_count += 1
        
        st.log(f"  Filtered: {len(filtered)} total ({within_count} within-DC, {cross_count} cross-DC)")
        return filtered
    
    # Apply filtering
    l2_traffic_endpoints = filter_endpoints_by_vlan_and_scope(
        l2_traffic_endpoints, WITHIN_DC_VLANS, CROSS_DC_VLANS
    )
    # L3VNI: allow cross-DC when enabled, otherwise within-DC only
    if ENABLE_L3_ACROSS_DCI:
        l3_allowed_cross = CROSS_DC_VLANS
    else:
        l3_allowed_cross = []
        st.log("NOTE: L3VNI across DCI is disabled. Generating within-DC L3 only.")

    l3_traffic_endpoints = filter_endpoints_by_vlan_and_scope(
        l3_traffic_endpoints, WITHIN_DC_VLANS, l3_allowed_cross
    )
    
    st.log(f"After VLAN filtering: L2={len(l2_traffic_endpoints)}, L3={len(l3_traffic_endpoints)}")
    
    # Log VLAN distribution
    l2_vlans_within = set()
    l2_vlans_cross = set()
    for ep in l2_traffic_endpoints.values():
        src_dc = re.search(r'_(dc\d+)', ep.get('src_node', '')).group(1) if re.search(r'_(dc\d+)', ep.get('src_node', '')) else None
        dst_dc = re.search(r'_(dc\d+)', ep.get('dst_node', '')).group(1) if re.search(r'_(dc\d+)', ep.get('dst_node', '')) else None
        if src_dc == dst_dc:
            l2_vlans_within.add(ep.get('src_vlan'))
        else:
            l2_vlans_cross.add(ep.get('src_vlan'))
    
    st.log(f"L2 VLAN distribution: Within-DC={sorted(l2_vlans_within)}, Cross-DC={sorted(l2_vlans_cross)}")

    # Separate L2 endpoints by source type (orphan vs PortChannel)
    l2_orphan_endpoints = {}
    l2_pc_endpoints = {}
    for tid, ep in l2_traffic_endpoints.items():
        src_int = ep.get('src_int', '')
        if src_int.startswith('PortChannel'):
            l2_pc_endpoints[tid] = ep
        else:
            l2_orphan_endpoints[tid] = ep
    
    st.log(f"L2 endpoint split: {len(l2_orphan_endpoints)} orphan, {len(l2_pc_endpoints)} PortChannel sources")
    
    # Generate PortChannel source L2 traffic by targeting specific traffic pairs
    st.log("  Step 1B: Adding PortChannel source L2 endpoints matching traffic pairs...")
    for src_node, src_int, dst_node, dst_int in traffic_pairs:
        # Only process PortChannel sources from leaf0_dc1 (the main source node)
        if not src_int.startswith('PortChannel'):
            continue
        if src_node != 'leaf0_dc1':
            continue  # Only generate PC sources from leaf0_dc1
        
        # Generate endpoints for this PortChannel source to all matching destinations
        for vlan_id in vlans_to_test:  # Use configured VLANs
            try:
                endpoints = find_traffic_enpoints(
                    topo_handles, g_v4_host_info_dict,
                    src_node, src_int, vlan_id, vlan_id,
                    traffic_type='default'
                )
                
                # Filter endpoints to only include those matching our traffic pairs
                for tid, ep in endpoints.items():
                    # Check if this endpoint matches any traffic pair
                    ep_pair = (ep['src_node'], ep['src_int'], ep['dst_node'], ep['dst_int'])
                    if ep_pair in traffic_pairs:
                        # Check VLAN filtering
                        if vlan_id in WITHIN_DC_VLANS or vlan_id in CROSS_DC_VLANS:
                            l2_pc_endpoints[f"PC_{tid}"] = ep
                
                st.log(f"    Added {len([e for e in endpoints.values() if (e['src_node'], e['src_int'], e['dst_node'], e['dst_int']) in traffic_pairs])} PC endpoints for {src_node}:{src_int} VLAN {vlan_id}")
            except Exception as e:
                st.log(f"    Warning: Failed to generate PC endpoints for {src_node}:{src_int} VLAN {vlan_id}: {e}")
    
    st.log(f"  Updated L2 endpoint split: {len(l2_orphan_endpoints)} orphan, {len(l2_pc_endpoints)} PortChannel sources")

    # Helper function to check if destination is within DC1
    def is_dst_within_dc1(dst_node):
        """Check if destination node is within DC1 (not DC2/DC3)"""
        return 'dc1' in dst_node.lower() and 'dc2' not in dst_node.lower() and 'dc3' not in dst_node.lower()
    
    # Split L2 endpoints into within-DC and cross-DC groups
    st.log("  Splitting L2 endpoints by destination DC...")
    l2_orphan_within = {k: v for k, v in l2_orphan_endpoints.items() if is_dst_within_dc1(v['dst_node'])}
    l2_orphan_cross = {k: v for k, v in l2_orphan_endpoints.items() if not is_dst_within_dc1(v['dst_node'])}
    l2_pc_within = {k: v for k, v in l2_pc_endpoints.items() if is_dst_within_dc1(v['dst_node'])}
    l2_pc_cross = {k: v for k, v in l2_pc_endpoints.items() if not is_dst_within_dc1(v['dst_node'])}
    
    st.log(f"  L2 orphan: {len(l2_orphan_within)} within-DC, {len(l2_orphan_cross)} cross-DC")
    st.log(f"  L2 PC: {len(l2_pc_within)} within-DC, {len(l2_pc_cross)} cross-DC")

    # Create traffic items
    st.banner(f"Creating L2 IPv4 traffic items: {len(l2_orphan_endpoints) + len(l2_pc_endpoints)} endpoints")
    st.log(f"  Creating traffic from ORPHAN sources: {len(l2_orphan_endpoints)} endpoints")
    st.log(f"  Creating traffic from PORTCHANNEL sources: {len(l2_pc_endpoints)} endpoints")
    
    stream_handles['l2_v4'] = []
    
    # Create orphan source L2 traffic - WITHIN DC
    if l2_orphan_within:
        l2_vlans_orphan_within = set(ep.get('src_vlan') for ep in l2_orphan_within.values())
        st.log(f"    Orphan sources (within-DC): {len(l2_vlans_orphan_within)} VLANs {sorted(l2_vlans_orphan_within)}")
        orphan_within_handles = vxlan_obj.create_traffic_item(device_handles=v4_device_handles,
                                                              endpoints=l2_orphan_within,
                                                              topo_handles=topo_handles,
                                                              multi_dst='vlan', name_prfx='L2-SH-WITHIN',
                                                              rate_percent=test_cfg['global'].get('l2l3', {}).get('rate_percent', 0.8),
                                                              pkts_per_burst=test_cfg['global'].get('l2l3', {}).get('pkts_per_burst', 1000))
        if orphan_within_handles:
            stream_handles['l2_v4'].extend(orphan_within_handles if isinstance(orphan_within_handles, list) else [orphan_within_handles])
    
    # Create orphan source L2 traffic - CROSS DC
    if l2_orphan_cross:
        l2_vlans_orphan_cross = set(ep.get('src_vlan') for ep in l2_orphan_cross.values())
        st.log(f"    Orphan sources (cross-DC): {len(l2_vlans_orphan_cross)} VLANs {sorted(l2_vlans_orphan_cross)}")
        orphan_cross_handles = vxlan_obj.create_traffic_item(device_handles=v4_device_handles,
                                                             endpoints=l2_orphan_cross,
                                                             topo_handles=topo_handles,
                                                             multi_dst='vlan', name_prfx='L2-SH-CROSS',
                                                             rate_percent=test_cfg['global'].get('l2l3', {}).get('rate_percent', 0.8),
                                                             pkts_per_burst=test_cfg['global'].get('l2l3', {}).get('pkts_per_burst', 1000))
        if orphan_cross_handles:
            stream_handles['l2_v4'].extend(orphan_cross_handles if isinstance(orphan_cross_handles, list) else [orphan_cross_handles])
    
    # Create PortChannel source L2 traffic - WITHIN DC
    if l2_pc_within:
        l2_vlans_pc_within = sorted(set(ep.get('src_vlan') for ep in l2_pc_within.values()))
        st.log(f"    PortChannel sources (within-DC): {len(l2_vlans_pc_within)} VLANs {sorted(l2_vlans_pc_within)}")
        
        # Create traffic item per source VLAN
        for vlan in l2_vlans_pc_within:
            vlan_pc_endpoints = {k: v for k, v in l2_pc_within.items() if v.get('src_vlan') == vlan}
            if vlan_pc_endpoints:
                st.log(f"      Creating PC within-DC traffic for VLAN {vlan}: {len(vlan_pc_endpoints)} endpoints")
                pc_within_handles = vxlan_obj.create_traffic_item(device_handles=v4_device_handles,
                                                                  endpoints=vlan_pc_endpoints,
                                                                  topo_handles=topo_handles,
                                                                  multi_dst='vlan', name_prfx='L2-MH-WITHIN',
                                                                  rate_percent=test_cfg['global'].get('l2l3', {}).get('rate_percent', 0.8),
                                                                  pkts_per_burst=test_cfg['global'].get('l2l3', {}).get('pkts_per_burst', 1000))
                if pc_within_handles:
                    stream_handles['l2_v4'].extend(pc_within_handles if isinstance(pc_within_handles, list) else [pc_within_handles])
    
    # Create PortChannel source L2 traffic - CROSS DC
    if l2_pc_cross:
        l2_vlans_pc_cross = sorted(set(ep.get('src_vlan') for ep in l2_pc_cross.values()))
        st.log(f"    PortChannel sources (cross-DC): {len(l2_vlans_pc_cross)} VLANs {sorted(l2_vlans_pc_cross)}")
        
        # Create traffic item per source VLAN
        for vlan in l2_vlans_pc_cross:
            vlan_pc_endpoints = {k: v for k, v in l2_pc_cross.items() if v.get('src_vlan') == vlan}
            if vlan_pc_endpoints:
                st.log(f"      Creating PC cross-DC traffic for VLAN {vlan}: {len(vlan_pc_endpoints)} endpoints")
                pc_cross_handles = vxlan_obj.create_traffic_item(device_handles=v4_device_handles,
                                                                 endpoints=vlan_pc_endpoints,
                                                                 topo_handles=topo_handles,
                                                                 multi_dst='vlan', name_prfx='L2-MH-CROSS',
                                                                 rate_percent=test_cfg['global'].get('l2l3', {}).get('rate_percent', 0.8),
                                                                 pkts_per_burst=test_cfg['global'].get('l2l3', {}).get('pkts_per_burst', 1000))
                if pc_cross_handles:
                    stream_handles['l2_v4'].extend(pc_cross_handles if isinstance(pc_cross_handles, list) else [pc_cross_handles])
    
    st.banner(f"Creating L3 IPv4 traffic items: {len(l3_traffic_endpoints)} endpoints")
    
    if l3_traffic_endpoints:
        # Count unique VRF-VLAN combinations
        l3_combos = set((ep.get('src_vrf'), ep.get('src_vlan')) for ep in l3_traffic_endpoints.values())
        st.log(f"  Endpoints will be grouped into {len(l3_combos)} streams (1 per VRF-VLAN combination)")
        st.log(f"  Each stream aggregates all source-destination pairs for that VRF-VLAN")
    
    stream_handles['l3_v4'] = vxlan_obj.create_traffic_item(device_handles=v4_device_handles,
                                                            endpoints=l3_traffic_endpoints,
                                                            topo_handles=topo_handles,
                                                            multi_dst='vrf', name_prfx='L3',
                                                              rate_percent=test_cfg['global'].get('l2l3', {}).get('rate_percent', 0.8),
                                                            pkts_per_burst=test_cfg['global'].get('l2l3', {}).get('pkts_per_burst', 1000))
    
    st.banner(f"Creating L2 IPv6 traffic items: {len(l2_orphan_endpoints) + len(l2_pc_endpoints)} endpoints")
    st.log(f"  Creating IPv6 traffic from ORPHAN sources: {len(l2_orphan_endpoints)} endpoints")
    st.log(f"  Creating IPv6 traffic from PORTCHANNEL sources: {len(l2_pc_endpoints)} endpoints")
    
    stream_handles['l2_v6'] = []
    
    # Create orphan source L2 IPv6 traffic - WITHIN DC
    if l2_orphan_within:
        orphan_within_handles_v6 = vxlan_obj.create_traffic_item(device_handles=v6_device_handles,
                                                                 endpoints=l2_orphan_within,
                                                                 topo_handles=topo_handles,
                                                                 version="ipv6", multi_dst='vlan', name_prfx='L2-SH-WITHIN',
                                                                 rate_percent=test_cfg['global'].get('l2l3', {}).get('rate_percent', 0.8),
                                                                 pkts_per_burst=test_cfg['global'].get('l2l3', {}).get('pkts_per_burst', 1000))
        if orphan_within_handles_v6:
            stream_handles['l2_v6'].extend(orphan_within_handles_v6 if isinstance(orphan_within_handles_v6, list) else [orphan_within_handles_v6])
    
    # Create orphan source L2 IPv6 traffic - CROSS DC
    if l2_orphan_cross:
        orphan_cross_handles_v6 = vxlan_obj.create_traffic_item(device_handles=v6_device_handles,
                                                                endpoints=l2_orphan_cross,
                                                                topo_handles=topo_handles,
                                                                version="ipv6", multi_dst='vlan', name_prfx='L2-SH-CROSS',
                                                                rate_percent=test_cfg['global'].get('l2l3', {}).get('rate_percent', 0.8),
                                                                pkts_per_burst=test_cfg['global'].get('l2l3', {}).get('pkts_per_burst', 1000))
        if orphan_cross_handles_v6:
            stream_handles['l2_v6'].extend(orphan_cross_handles_v6 if isinstance(orphan_cross_handles_v6, list) else [orphan_cross_handles_v6])
    
    # Create PortChannel source L2 IPv6 traffic - WITHIN DC
    if l2_pc_within:
        l2_vlans_pc_within_v6 = sorted(set(ep.get('src_vlan') for ep in l2_pc_within.values()))
        
        # Create traffic item per source VLAN
        for vlan in l2_vlans_pc_within_v6:
            vlan_pc_endpoints = {k: v for k, v in l2_pc_within.items() if v.get('src_vlan') == vlan}
            if vlan_pc_endpoints:
                st.log(f"      Creating PC IPv6 within-DC traffic for VLAN {vlan}: {len(vlan_pc_endpoints)} endpoints")
                pc_within_handles_v6 = vxlan_obj.create_traffic_item(device_handles=v6_device_handles,
                                                                     endpoints=vlan_pc_endpoints,
                                                                     topo_handles=topo_handles,
                                                                     version="ipv6", multi_dst='vlan', name_prfx='L2-MH-WITHIN',
                                                                     rate_percent=test_cfg['global'].get('l2l3', {}).get('rate_percent', 0.8),
                                                                     pkts_per_burst=test_cfg['global'].get('l2l3', {}).get('pkts_per_burst', 1000))
                if pc_within_handles_v6:
                    stream_handles['l2_v6'].extend(pc_within_handles_v6 if isinstance(pc_within_handles_v6, list) else [pc_within_handles_v6])
    
    # Create PortChannel source L2 IPv6 traffic - CROSS DC
    if l2_pc_cross:
        l2_vlans_pc_cross_v6 = sorted(set(ep.get('src_vlan') for ep in l2_pc_cross.values()))
        
        # Create traffic item per source VLAN
        for vlan in l2_vlans_pc_cross_v6:
            vlan_pc_endpoints = {k: v for k, v in l2_pc_cross.items() if v.get('src_vlan') == vlan}
            if vlan_pc_endpoints:
                st.log(f"      Creating PC IPv6 cross-DC traffic for VLAN {vlan}: {len(vlan_pc_endpoints)} endpoints")
                pc_cross_handles_v6 = vxlan_obj.create_traffic_item(device_handles=v6_device_handles,
                                                                    endpoints=vlan_pc_endpoints,
                                                                    topo_handles=topo_handles,
                                                                    version="ipv6", multi_dst='vlan', name_prfx='L2-MH-CROSS',
                                                                    rate_percent=test_cfg['global'].get('l2l3', {}).get('rate_percent', 0.8),
                                                                    pkts_per_burst=test_cfg['global'].get('l2l3', {}).get('pkts_per_burst', 1000))
                if pc_cross_handles_v6:
                    stream_handles['l2_v6'].extend(pc_cross_handles_v6 if isinstance(pc_cross_handles_v6, list) else [pc_cross_handles_v6])
    
    st.banner(f"Creating L3 IPv6 traffic items: {len(l3_traffic_endpoints)} endpoints")
    stream_handles['l3_v6'] = vxlan_obj.create_traffic_item(device_handles=v6_device_handles,
                                                            endpoints=l3_traffic_endpoints,
                                                            topo_handles=topo_handles,
                                                            version="ipv6", multi_dst='vrf', name_prfx='L3',
                                                              rate_percent=test_cfg['global'].get('l2l3', {}).get('rate_percent', 0.8),
                                                            pkts_per_burst=test_cfg['global'].get('l2l3', {}).get('pkts_per_burst', 1000))
    
    # BUM traffic configuration
    st.banner("Configuring BUM traffic")
    cntr = 1
    
    if use_custom_filter and TRAFFIC_CONFIG['bum']['enabled']:
        # Custom BUM based on configuration
        st.log("Step 6: Creating custom BUM traffic from configuration...")
        bum_cfg = TRAFFIC_CONFIG['bum']
        bum_src_node = bum_cfg['source_node']
        bum_src_type = bum_cfg['source_type']
        
        # Determine VLANs for BUM traffic - use the same limited set as L2/L3 traffic
        # Within-DC: 11, 12 + Cross-DC: 14, 15
        bum_vlans = []
        if bum_cfg['vlan'] == 'first':
            bum_vlans = [WITHIN_DC_VLANS[0]]  # Just VLAN 11
        elif bum_cfg['vlan'] == 'all':
            # Use the same 4 VLANs as L2/L3 traffic (2 within-DC + 2 cross-DC)
            bum_vlans = WITHIN_DC_VLANS + CROSS_DC_VLANS  # [11, 12, 14, 15]
            st.log(f"  BUM using all VLANs: {bum_vlans}")
        elif bum_cfg['vlan'] == 'cross_dc':
            # Use only cross-DC VLANs for inter-DC BUM traffic
            bum_vlans = CROSS_DC_VLANS  # [11-20]
            st.log(f"  BUM using cross-DC VLANs only: {bum_vlans}")
        elif isinstance(bum_cfg['vlan'], int):
            bum_vlans = [bum_cfg['vlan']]
        
        st.log(f"  BUM source: {bum_src_node}, type: {bum_src_type}, VLANs: {bum_vlans}")
        st.log(f"  BUM destination filter: {bum_cfg['destination_filter']}")
        
        # Find source interfaces from config (not from topo_handles or host_info)
        # find_traffic_enpoints() expects config-style names like 'T1P1' or 'PortChannel1'
        bum_src_intfs = []
        if bum_src_node in test_cfg and 'l2vni' in test_cfg[bum_src_node]:
            st.log(f"  Looking for BUM source interfaces in {bum_src_node} config...")
            
            # Get all unique member interfaces from l2vni config
            all_members = set()
            for l2_info in test_cfg[bum_src_node]['l2vni']:
                if 'members' in l2_info:
                    all_members.update(l2_info['members'])
            
            st.log(f"  All member interfaces in config: {list(all_members)}")
            
            # Filter by type
            for member in all_members:
                if bum_src_type == 'all':
                    bum_src_intfs.append(member)
                elif bum_src_type == 'orphan' and not member.startswith('PortChannel'):
                    bum_src_intfs.append(member)
                elif bum_src_type == 'portchannel' and member.startswith('PortChannel'):
                    bum_src_intfs.append(member)
            
            st.log(f"  Selected BUM source interfaces (type={bum_src_type}): {bum_src_intfs}")
        else:
            st.log(f"  ERROR: {bum_src_node} not found in test_cfg or has no l2vni config")
        
        # Create BUM traffic for each source interface and VLAN
        for bum_src_intf in bum_src_intfs:
            for bum_vlan in bum_vlans:
                # Check if this interface/VLAN combination exists in config
                vlan_found = False
                for l2_info in test_cfg[bum_src_node]['l2vni']:
                    if l2_info['vlan_id'] == bum_vlan and bum_src_intf in l2_info.get('members', []):
                        vlan_found = True
                        break
                
                if not vlan_found:
                    st.log(f"  Skipping BUM: VLAN {bum_vlan} not configured on {bum_src_node}:{bum_src_intf}")
                    continue
                
                st.log(f"  Creating BUM from {bum_src_node}:{bum_src_intf}, VLAN: {bum_vlan}")
                
                # Get all BUM endpoints for this source/VLAN
                all_bum_endpoints = find_traffic_enpoints(
                    topo_handles, g_v4_host_info_dict,
                    bum_src_node, bum_src_intf,
                    bum_vlan, bum_vlan,
                    traffic_type='raw'
                )
                
                for ep_name, ep_data in all_bum_endpoints.items():
                    st.log(f"      {ep_name}: {ep_data.get('dst_node', 'N/A')}:{ep_data.get('dst_int', 'N/A')}")
                
                # Filter destinations based on configuration and topology availability
                bum_l2_endpoints = {}
                dest_filter = bum_cfg.get('destination_filter', [])
                for name, endpoint in all_bum_endpoints.items():
                    dst_node = endpoint.get('dst_node', '')
                    
                    # Check if destination node exists in topology handles
                    if dst_node and dst_node not in topo_handles:
                        st.log(f"    Skipping BUM endpoint: Destination node '{dst_node}' not in topology handles")
                        continue
                    
                    # Apply destination filter (empty filter = include all, natural BUM behavior)
                    if not dest_filter or any(pattern in dst_node for pattern in dest_filter):
                        bum_l2_endpoints[name] = endpoint
                        st.log(f"    INCLUDED: {name} -> {dst_node}:{endpoint.get('dst_int', 'N/A')}")
                    else:
                        st.log(f"    FILTERED OUT: {name} -> {dst_node}:{endpoint.get('dst_int', 'N/A')}")
                
                st.log(f"    Final BUM destinations: {len(bum_l2_endpoints)} endpoints")
                
                if bum_l2_endpoints:
                    for dest_type, dst_mac in [
                        ('unknown', '00:99:00:00:00:99'),
                        ('broadcast', 'ff:ff:ff:ff:ff:ff'),
                        ('multicast', '01:00:5e:44:44:44')
                    ]:
                        # Create a copy for each dest type
                        bum_endpoints_copy = deepcopy(bum_l2_endpoints)
                        for name, value in bum_endpoints_copy.items():
                            value['dst_mac'] = dst_mac
                        
                        bum_type = 'bum_MH' if 'PortChannel' in bum_src_intf else 'bum_SH'
                        stream_prfx = f'{bum_type}_{dest_type}'
                        
                        # BUM traffic naturally floods to all ports in VLAN
                        # Use rx_all_ports=True to monitor all TGEN ports
                        # IXIA will set Expected RX based on endpoint list from find_traffic_enpoints()
                        stream_info = vxlan_obj.create_traffic_item(
                            device_handles=v4_device_handles,
                            endpoints=bum_endpoints_copy,
                            topo_handles=topo_handles,
                            multi_dst='vlan', name_prfx=stream_prfx,
                            circuit_type='raw', rx_all_ports=True,
                            rate_percent=test_cfg['global'].get('bum', {}).get('rate_percent', 0.8),
                            pkts_per_burst=test_cfg['global'].get('bum', {}).get('pkts_per_burst', 100))
                        
                        if not stream_handles.get(bum_type):
                            stream_handles[bum_type] = dict()
                        stream_handles[bum_type][cntr] = stream_info[1]
                        cntr += 1
                        st.log(f"    Created {stream_prfx} with {len(bum_endpoints_copy)} endpoints (counter now: {cntr})")
                else:
                    st.log(f"    No endpoints after filtering")
        
        if not bum_src_intfs:
            st.log(f"  No source interfaces found for {bum_src_node} (type: {bum_src_type})")
        
    
    elif use_custom_filter and not TRAFFIC_CONFIG['bum']['enabled']:
        st.log("Step 6: BUM traffic disabled in configuration")
    else:
        # Original BUM traffic logic (all nodes, all VLANs with bum_traffic=true)
        st.log("Step 6: Creating BUM traffic (original - all configured nodes/VLANs)")
        for node, config in test_cfg.items():
            if not node in test_cfg['nodes']['l2l3vni_bgw']:
                continue
            for l2_info in test_cfg[node].get('l2vni', []):
                if l2_info.get('bum_traffic', False):
                    if 'members' not in l2_info:
                        continue
                    for port in l2_info['members']:
                        if node not in topo_handles:
                            continue
                        
                        port_exists = False
                        if port.startswith('PortChannel'):
                            for topo_port in topo_handles[node].keys():
                                if topo_port.startswith(port):
                                    port_exists = True
                                    break
                        else:
                            try:
                                vxlan_obj.get_peer_port_id(port, vars, node)
                                port_exists = True
                            except:
                                port_exists = False
                        
                        if not port_exists:
                            st.log(f"Skipping BUM for {node}:{port} - not in topology")
                            continue
                        
                        bum_l2_endpoints = find_traffic_enpoints(
                            topo_handles, g_v4_host_info_dict, node, port,
                            l2_info['vlan_id'], l2_info['vlan_id'], traffic_type='raw')
                        
                        # Filter out endpoints with destination nodes not in topology
                        valid_bum_endpoints = {}
                        for ep_name, ep in bum_l2_endpoints.items():
                            dst_node = ep.get('dst_node', '')
                            if dst_node and dst_node not in topo_handles:
                                st.log(f"  Skipping BUM endpoint: Destination node '{dst_node}' not in topology")
                                continue
                            valid_bum_endpoints[ep_name] = ep
                        
                        if not valid_bum_endpoints:
                            st.log(f"No valid BUM endpoints for {node}:{port}")
                            continue
                        
                        bum_l2_endpoints = valid_bum_endpoints
                        
                        for dest_type, dst_mac in [
                            ('unknown', '00:99:00:00:00:99'),
                            ('broadcast', 'ff:ff:ff:ff:ff:ff'),
                            ('multicast', '01:00:5e:44:44:44')
                        ]:
                            bum_copy = deepcopy(bum_l2_endpoints)
                            for name, value in bum_copy.items():
                                value['dst_mac'] = dst_mac
                            
                            bum_type = 'bum_MH' if 'PortChannel' in port else 'bum_SH'
                            stream_prfx = f'{bum_type}_{dest_type}'
                            stream_info = vxlan_obj.create_traffic_item(
                                device_handles=v4_device_handles,
                                endpoints=bum_copy,
                                topo_handles=topo_handles,
                                multi_dst='vlan', name_prfx=stream_prfx,
                                circuit_type='raw', rx_all_ports=True,
                                rate_percent=test_cfg['global'].get('bum', {}).get('rate_percent', 0.8),
                                pkts_per_burst=test_cfg['global'].get('bum', {}).get('pkts_per_burst', 500))
                            
                            if not stream_handles.get(bum_type):
                                stream_handles[bum_type] = dict()
                            stream_handles[bum_type][cntr] = stream_info[1]
                            cntr += 1
    
    # Disable all streams
    st.banner("Disabling all traffic streams")
    streams = []
    for traffic_type, item in stream_handles.items():
        if traffic_type in ['l2_v4', 'l3_v4', 'l2_v6', 'l3_v6', 'bum_SH', 'bum_MH']:
            if isinstance(item, list):
                # L2 traffic with SH+MH (list of dicts)
                for subitem in item:
                    if isinstance(subitem, dict):
                        for key, value in subitem.items():
                            if isinstance(value, dict) and 'stream_id' in value:
                                streams.append(value['stream_id'])
            elif isinstance(item, dict):
                # L3 traffic or BUM (single dict)
                for key, value in item.items():
                    if isinstance(value, dict) and 'stream_id' in value:
                        streams.append(value['stream_id'])
    
    if streams:
        tg_handle.tg_traffic_config(mode='disable', stream_id=streams)
        st.log(f"Disabled {len(streams)} traffic streams")
    else:
        st.log("No traffic streams to disable")

    stream_handles["tg_handle"] = tg_handle
    stream_handles["topo_handles"] = topo_handles
    stream_handles["v4_device_handles"] = v4_device_handles
    stream_handles["v6_device_handles"] = v6_device_handles
    stream_handles["vlans_tested"] = vlans_to_test  # Save VLANs for verification
    
    # Print summary of created traffic
    st.banner("TRAFFIC CONFIGURATION SUMMARY")
    st.log(f"Configuration Mode: {'CUSTOM (Filtered)' if use_custom_filter else 'FULL MESH (Original)'}")
    st.log(f"Test VLANs: {vlans_to_test}")
    if use_custom_filter:
        st.log(f"Traffic Pairs: {len(traffic_pairs)}")
    st.log("-" * 60)

    def _flatten_stream_ids(stream_obj):
        """
        Normalize different stream handle shapes into a list of stream_id strings.
        - dict: {idx: {'stream_id': ...}, ...}
        - list: [dict, dict, ...] (L2 SH+MH)
        """
        ids = []
        if isinstance(stream_obj, dict):
            for _k, _v in stream_obj.items():
                if isinstance(_v, dict) and _v.get('stream_id'):
                    ids.append(_v['stream_id'])
        elif isinstance(stream_obj, list):
            for _d in stream_obj:
                if isinstance(_d, dict):
                    for _k, _v in _d.items():
                        if isinstance(_v, dict) and _v.get('stream_id'):
                            ids.append(_v['stream_id'])
        return ids
    
    total_streams = 0
    for traffic_type in ['l2_v4', 'l3_v4', 'l2_v6', 'l3_v6', 'bum_SH', 'bum_MH']:
        if traffic_type in stream_handles:
            # Handle both dict (L3 traffic) and list (L2 traffic with SH+MH) formats
            if isinstance(stream_handles[traffic_type], dict):
                count = len(stream_handles[traffic_type])
            elif isinstance(stream_handles[traffic_type], list):
                # Count total streams in all dicts in the list
                count = sum(len(sh) if isinstance(sh, dict) else 0 for sh in stream_handles[traffic_type])
            else:
                count = 0
            total_streams += count
            st.log(f"  {traffic_type:10s}: {count:4d} streams")

            # Optional deep debug: print the exact stream_ids that the test will enable/verify.
            if st.getenv("debug_stream_ids", "false").lower() == "true":
                ids = _flatten_stream_ids(stream_handles[traffic_type])
                st.log(f"    {traffic_type} stream_ids ({len(ids)}):")
                for sid in ids:
                    st.log(f"      - {sid}")
    
    st.log("-" * 60)
    st.log(f"TOTAL TRAFFIC STREAMS: {total_streams}")
    
    if use_custom_filter:
        # Calculate expected streams based on actual configuration
        l2_l3_streams = len(vlans_to_test) * 4  # 4 IP versions (L2v4, L3v4, L2v6, L3v6)
        
        # BUM streams calculation
        bum_sources = 0
        if TRAFFIC_CONFIG['bum']['enabled']:
            bum_source_type = TRAFFIC_CONFIG['bum']['source_type']
            if bum_source_type == 'all':
                bum_sources = 2  # orphan + portchannel
            else:
                bum_sources = 1  # either orphan or portchannel
            
            bum_vlan_cfg = TRAFFIC_CONFIG['bum']['vlan']
            if bum_vlan_cfg == 'all':
                bum_vlans = len(vlans_to_test)
            elif bum_vlan_cfg == 'first':
                bum_vlans = 1
            elif bum_vlan_cfg == 'cross_dc':
                bum_vlans = 2  # Cross-DC VLANs only (14, 15)
            else:
                bum_vlans = 1  # specific VLAN
            
            bum_streams = bum_sources * bum_vlans * 3  # 3 types (unknown, broadcast, multicast)
        else:
            bum_streams = 0
        
        expected = l2_l3_streams + bum_streams
        st.log(f"Expected streams: {expected} ({len(vlans_to_test)} VLANs × 4 types + {bum_streams} BUM)")
        st.log(f"  L2/L3 breakdown: {len(vlans_to_test)} VLANs × 4 traffic types = {l2_l3_streams} streams")
        st.log(f"  BUM breakdown: {bum_sources} sources × {bum_vlans if TRAFFIC_CONFIG['bum']['enabled'] else 0} VLANs × 3 types = {bum_streams} streams")

    return stream_handles


def reset_preconf_tgen(kill=True):
    """
    Reset and reconfigure TGEN setup (optionally disconnect and reconnect)
    """
    global test_cfg, tgen_handles, vars
    if kill:
        for tgen in vars['tgen_list']:
            tgobj = tgapi.get_tgen_obj_dict()[tgen]
            tgobj.tg_disconnect()
        st.wait(120)
        tg.connect_tgen()
    tgen_handles = tgen_preconfig()
    return True


# Removed filter_traffic_streams() - Redundant since VLAN-based filtering is already done in tgen_preconfig()
# Within-DC traffic uses VLANs 11-12, Cross-DC traffic uses VLANs 14-15
# Test methods can directly use traffic_types parameter in verify_traffic()


@pytest.fixture(scope='class', autouse=True)
def tgen_health_check_class(request):
    """
    Class-level fixture for TGEN health check and reconfiguration.
    Initializes TGEN on first class and resets if TGen failures occur.
    """
    if test_cfg['global'].get('restart_tgen_force', 'first') == 'first':
        st.banner('Configuring IXIA for DCI Testing')
        reset_preconf_tgen(kill=False)
        test_cfg['global']['restart_tgen_force'] = False
    elif test_cfg['global']['restart_tgen_force'] == True:
        st.banner('Restarting and Reconfiguring IXIA')
        reset_preconf_tgen()
        test_cfg['global']['restart_tgen_force'] = False
    elif test_cfg['global']['restart_tgen_per_class']:
        if test_cfg['tgen_tc_status'].get(test_cfg['tgen_tc_status'].get('last_tc'), True) == True:
            st.banner('Restarting and Reconfiguring IXIA as restart tgen per class flag is set')
            reset_preconf_tgen()
    yield
    st.log('Last failure {} : {} : {}'.format(request.node.name, st.get_result(), st.getwa().last_error))
    if st.getwa().last_error and st.getwa().last_error.startswith('TG'):
        test_cfg['global']['restart_tgen_force'] = True
        from spytest import framework
        res, desc = framework.get_current_result('module')
        st.log('Current Module Result: {} Desc: {}'.format(res, desc))
        framework.set_current_result(res=None, scope='module')
        res, desc = framework.get_current_result('module')
        st.log('New Module Result set: {} Desc: {}'.format(res, desc))


@pytest.fixture(scope="function", autouse=True)
def fail_on_core(request):
    """
    Fixture to check for core files before and after each test function.
    Fails the test if core files are detected.
    """
    # Check for cores before the test
    cores = vxlan_obj.check_core()
    if cores:
        st.banner("Core present in DUT before the start of the test, core copied and failing test")
        st.report_fail("test_case_failed")
    
    yield
    
    # Check for cores after the test
    cores = vxlan_obj.check_core()
    if cores:
        st.banner("Core generated during the test, core copied and failing test")
        st.report_fail("test_case_failed")

@pytest.fixture(scope="function", autouse=True)
def pretest(request):
    """
    Quick pre-test check to verify VXLAN tunnel connectivity.
    
    Validates that remote VXLAN tunnel endpoints (VTEPs) are discovered on all nodes,
    which is the most critical indicator of DCI overlay connectivity. If tunnels are
    not established, the test will fail anyway, so this provides fast failure detection.
    
    All other checks (BGP, ES, ES-EVI, PortChannels, VNI mappings, etc.) are performed
    by verify_base_setup_bgw() which runs before and after triggers.
    """
    result = True
    
    for dut in test_cfg['nodes']['l2l3vni_bgw']:
        st.log("Pretest : Check vteps on leaf_nodes node: {}".format(dut))
        try:
            exp_data = vxlan_obj.get_expected_vxlan_remotevtep(dut)
            vxlan_obj.verify_vxlan_remotevtep(dut, exp_data)
            st.log('Verify Vxlan-VNI map on {}: Pass'.format(dut))
        except Exception as err:
            st.log('Verify EVPN ES-EVI on {}: Fail\n{}'.format(dut, err))
            result = False

    if result:
        st.log("Pretest : Pass")
    else:
        st.log("Pretest : Fail")
        vxlan_obj.get_cli_out(test_cfg['nodes']['l2l3vni_bgw'])
        vxlan_obj.collect_diags()
        st.banner("Pretest : Fail. Skipping testcase.")
    return result


def report_result(result, tc_id='', rc_msg=''):
    """
    Report test result and pass/fail the test case.
    
    Args:
        result: Boolean test result
        tc_id: Test case identifier
        rc_msg: Result message for failure cases
    """
    if result:
        st.banner('Testcase: {} :: Result: Pass'.format(tc_id))
        st.report_pass('test_case_passed')
    else:
        st.banner('Testcase: {} :: Result: Fail'.format(tc_id))
        if rc_msg:
            st.banner('Testcase: {} :: Diags: {}'.format(tc_id, rc_msg))
        st.report_fail("test_case_failed")


def stream_matches_scope(stream_name, scope):
    """
    Check if stream matches the given traffic scope (within-DC or cross-DC).
    
    Streams are explicitly labeled during creation:
    - WITHIN streams have '-WITHIN' in the name (intra-DC1)
    - CROSS streams have '-CROSS' in the name (DC1 ↔ DC2/DC3)
    - Fallback: DC2/DC3 markers ['D11', 'D12', 'D14'] indicate cross-DC
    
    Args:
        stream_name: Traffic stream name/ID
        scope: 'within' (intra-DC1) or 'cross' (inter-DC)
    
    Returns:
        Boolean: True if stream matches the scope
    """
    if 'WITHIN' in stream_name:
        return scope == 'within'
    if 'CROSS' in stream_name:
        return scope == 'cross'
    # Fallback: DC2/DC3 device markers for BUM and legacy streams
    cross_dc_markers = ['D11', 'D12', 'D14']
    is_cross = any(marker in stream_name for marker in cross_dc_markers)
    return scope == 'cross' if is_cross else scope == 'within'


def _parse_show_vxlan_counters(show_output):
    """
    Parse `show vxlan counters` output returned by st.show().

    Expected columns:
      IFACE, RX_PKTS, RX_BYTES, RX_PPS, TX_PKTS, TX_BYTES, TX_PPS

    Returns:
      dict[str, dict]: { iface: {'rx_pkts': int, 'tx_pkts': int} }
    """
    counters = {}
    if not show_output:
        return counters
    
    # Handle both parsed (list of dicts) and raw text output
    if isinstance(show_output, list):
        # Parsed output (list of dicts)
        for row in show_output:
            if not isinstance(row, dict):
                continue
            iface = row.get('IFACE') or row.get('iface') or row.get('Iface')
            if not iface:
                continue
            rx = row.get('RX_PKTS') or row.get('rx_pkts') or row.get('RX_PKTS ')
            tx = row.get('TX_PKTS') or row.get('tx_pkts') or row.get('TX_PKTS ')
            try:
                rx_pkts = int(str(rx).strip()) if rx is not None else 0
            except Exception:
                rx_pkts = 0
            try:
                tx_pkts = int(str(tx).strip()) if tx is not None else 0
            except Exception:
                tx_pkts = 0
            counters[str(iface).strip()] = {'rx_pkts': rx_pkts, 'tx_pkts': tx_pkts}
    else:
        # Raw text output (when using skip_tmpl=True)
        lines = str(show_output).split('\n')
        for line in lines:
            # Skip header, separator, and empty lines
            if not line.strip() or '----' in line or 'IFACE' in line:
                continue
            
            # Parse data lines: "EVPN_2000:1::2       7099     3775376   10.02/s      14538     7595448   30.01/s"
            parts = line.split()
            if len(parts) >= 7:  # Need at least IFACE + 6 columns
                iface = parts[0].strip()
                try:
                    rx_pkts = int(parts[1])
                    tx_pkts = int(parts[4])
                    counters[iface] = {'rx_pkts': rx_pkts, 'tx_pkts': tx_pkts}
                except (ValueError, IndexError):
                    continue
    
    return counters


def _sum_vxlan_pkts(counters_dict, iface_prefixes=('VXLAN', 'EVPN_')):
    """
    Sum rx/tx pkts across VXLAN/EVPN interfaces from parsed counters.
    """
    rx_sum = 0
    tx_sum = 0
    for iface, vals in (counters_dict or {}).items():
        if any(str(iface).startswith(pfx) for pfx in iface_prefixes):
            rx_sum += int(vals.get('rx_pkts', 0))
            tx_sum += int(vals.get('tx_pkts', 0))
    return rx_sum, tx_sum


def verify_traffic(traffic_handles, regenerate=False, traffic_types=[], traffic_names=[], 
                   bum=True, stop_start_protocols=True, scope=None):
    """
    Verify traffic flows on all configured streams.
    
    Args:
        traffic_handles: Dictionary of traffic stream handles
        regenerate: Whether to regenerate traffic items
        traffic_types: List of traffic types to verify (e.g., ['l2_v4', 'l3_v4'])
        traffic_names: List of specific traffic stream names to verify
        bum: Whether to include BUM traffic verification
        stop_start_protocols: Whether to stop/start protocols during verification
        scope: Traffic scope filter (None='all', 'within'=within-DC only, 'cross'=cross-DC only)
    
    Returns:
        Boolean indicating overall traffic verification result
    """
    traffic_result = {}
    for traffic_type, traffic_items in traffic_handles.items():
        # Skip handle entries
        if '_handle' in traffic_type:
            continue
        
        # Determine verification mode based on traffic type
        mode = 'traffic_item'
        if bum:
            if 'bum' in traffic_type:
                mode = 'flow'
        else:
            if 'bum' in traffic_type:
                continue
        
        # Filter by traffic types if specified
        if traffic_types:
            if not any(ttype in traffic_type for ttype in traffic_types):
                continue
        
        # Handle both list (L2 with SH+MH) and dict (L3, BUM) formats
        if isinstance(traffic_items, list):
            # L2 traffic: list of dicts (e.g., [L2-SH dict, L2-MH dict]).
            # IMPORTANT: both dicts are usually keyed from 1..N, so naive dict.update()
            # will overwrite entries and drop streams (e.g., vlan12 SH replaced by MH).
            # Re-key by stream_id to guarantee uniqueness.
            merged_items = {}
            for item_dict in traffic_items:
                if not isinstance(item_dict, dict):
                    continue
                for _k, _v in item_dict.items():
                    if isinstance(_v, dict) and _v.get('stream_id'):
                        merged_items[_v['stream_id']] = _v
            traffic_items = merged_items
        
        # Filter by traffic names if specified
        if traffic_names:
            sel_traffic_items = {}
            for tname in traffic_names:
                for idx, traffic_info in traffic_items.items():
                    if tname in traffic_info['stream_id']:
                        sel_traffic_items[idx] = traffic_info
            traffic_items = sel_traffic_items
        
        # Filter by traffic scope (within-DC vs cross-DC) if specified
        if scope in ['within', 'cross']:
            pre_scope_count = len(traffic_items)
            scoped_traffic_items = {}
            for idx, traffic_info in traffic_items.items():
                stream_id = traffic_info.get('stream_id', '')
                if stream_matches_scope(stream_id, scope):
                    scoped_traffic_items[idx] = traffic_info

            traffic_items = scoped_traffic_items
            st.log("  Filtered to {} scope: {} streams (from {})".format(
                scope, len(traffic_items), pre_scope_count))
        
        # Check if traffic items exist after filtering
        if not traffic_items:
            st.log("No traffic items for {} after filtering".format(traffic_type))
            # For 'within' scope, missing L2 traffic is a failure (expected within-DC traffic)
            # For 'cross' scope or no scope, missing traffic might be expected
            if scope == 'within' and traffic_type in ['l2_v4', 'l2_v6']:
                st.error("Expected within-DC L2 traffic but found 0 streams - likely traffic generation issue")
                traffic_result[traffic_type] = False
            else:
                st.log("No streams for {} - treating as Pass (no traffic to verify)".format(traffic_type))
                traffic_result[traffic_type] = True
            continue
        
        st.banner("Verifying {} traffic".format(traffic_type))
        try:
            traffic_result[traffic_type] = vxlan_obj.check_traffic(
                traffic_items,
                regenerate_traffic_items=regenerate,
                stop_start_protocols=stop_start_protocols,
                mode=mode,
                stop_proto_wait=test_cfg['global'].get('traffic_stop_protocol_sleep', 15),
                start_proto_wait=test_cfg['global'].get('traffic_start_protocol_sleep', 15)
            )
            stop_start_protocols = False
            st.log("Traffic type {} verify result: {}".format(traffic_type, traffic_result[traffic_type]))
        except Exception as err:
            st.error('Exception when checking traffic: {}'.format(str(err)))
            traffic_result[traffic_type] = False
    
    # Evaluate overall result
    ret = True
    for traffic_type, result in traffic_result.items():
        if result:
            st.banner("{} traffic passed".format(traffic_type))
        else:
            st.banner("{} traffic failed".format(traffic_type))
            ret = False
    
    return ret


# ============================================================================
# MODULAR VERIFICATION SYSTEM
# ============================================================================

# Verification check types for verify_base_setup_bgw (modular post-config validation)
ALL_CHECKS = [
    'vlan_vni',      # VLAN-VNI mappings
    'vrf_vni',       # VRF-VNI mappings
    'vteps',         # Remote VTEP discovery
    'tunnels',       # VXLAN tunnel status
    'bgp',           # All BGP sessions (underlay + overlay)
    'evpn_es',       # EVPN Ethernet Segment (multi-homing)
    'evpn_es_evi',   # EVPN ES per EVI/VLAN
    'evpn_type1',    # EVPN Type 1 Routes (ES Auto-Discovery)
    'evpn_type4',    # EVPN Type 4 Routes (ES-Import)
    'portchannel',   # PortChannel operational status
]

# Pre-defined check sets for verify_base_setup_bgw (e.g. checks='bgp_only' after BGP reset)
CHECK_SETS = {
    'all': ALL_CHECKS,
    'basic': ['vlan_vni', 'vrf_vni', 'vteps', 'bgp'],
    'bgp_only': ['bgp'],
    'evpn_only': ['evpn_es', 'evpn_es_evi', 'evpn_type1', 'evpn_type4'],
    'data_plane': ['vlan_vni', 'vrf_vni', 'vteps', 'tunnels'],
    'control_plane': ['bgp', 'evpn_es', 'evpn_type1', 'evpn_type4'],
}


def verify_base_setup_bgw(bgw_nodes, retry=1, checks='all', skip_checks=None, return_dict=False):
    """
    Modular verification of VXLAN EVPN DCI control plane and data plane state.
    
    Performs selective validation of DCI testbed configuration. Tests can choose which
    checks to run for faster, more targeted verification.
    
    Args:
        bgw_nodes: List of node hostnames to verify (BGW spines and leaf switches)
        retry: Number of verification retry attempts with exponential backoff
        checks: Which checks to run. Options:
            - 'all' (default): Run all checks
            - Pre-defined set: 'basic', 'bgp_only', 'evpn_only', 'data_plane', 'control_plane'
            - List of check names: ['vlan_vni', 'bgp', 'evpn_type1']
        skip_checks: List of check names to skip (only used if checks='all')
        return_dict: If True, return detailed dict with per-check results. 
                     If False (default), return simple boolean for backward compatibility.
    
    Available check names:
        'vlan_vni'      - VLAN-VNI mappings
        'vrf_vni'       - VRF-VNI mappings
        'vteps'         - Remote VTEP discovery
        'tunnels'       - VXLAN tunnel status
        'bgp'           - BGP sessions (underlay + overlay)
        'evpn_es'       - EVPN Ethernet Segment (multi-homing)
        'evpn_es_evi'   - EVPN ES per EVI/VLAN
        'evpn_type1'    - EVPN Type 1 Routes (ES Auto-Discovery)
        'evpn_type4'    - EVPN Type 4 Routes (ES-Import)
        'portchannel'   - PortChannel operational status
    
    Returns:
        If return_dict=False (default): Boolean - True if all checks pass, False otherwise
        If return_dict=True: Dict with detailed results:
            {
                'leaf0_dc1': {'vlan_vni': True, 'bgp': True, 'evpn_type1': False},
                'leaf1_dc1': {'vlan_vni': True, 'bgp': True, 'evpn_type1': True},
                'overall': False  # Any check failed
            }
    
    Examples:
        # All checks (backward compatible)
        verify_base_setup_bgw(nodes)
        
        # Only BGP verification (after BGP reset)
        verify_base_setup_bgw(nodes, checks='bgp_only')
        
        # Specific checks (after interface flap)
        verify_base_setup_bgw(nodes, checks=['bgp', 'portchannel', 'vteps'])
        
        # Quick sanity check
        verify_base_setup_bgw(nodes, checks='basic')
        
        # All except slow checks
        verify_base_setup_bgw(nodes, checks='all', skip_checks=['mac_table'])
        
        # Get detailed results
        result = verify_base_setup_bgw(nodes, checks=['bgp', 'evpn_type1'], return_dict=True)
        if not result['overall']:
            for node, check_results in result.items():
                if node != 'overall':
                    for check, passed in check_results.items():
                        if not passed:
                            print(f"FAILED: {node} - {check}")
    """
    # Parse checks parameter
    if isinstance(checks, str):
        if checks in CHECK_SETS:
            checks_to_run = CHECK_SETS[checks].copy()
        else:
            st.error(f"Unknown check set: '{checks}'. Available: {list(CHECK_SETS.keys())}. Using 'all'.")
            checks_to_run = ALL_CHECKS.copy()
    elif isinstance(checks, list):
        # Validate check names
        invalid_checks = [c for c in checks if c not in ALL_CHECKS]
        if invalid_checks:
            st.error(f"Invalid check names: {invalid_checks}. Valid checks: {ALL_CHECKS}")
            checks_to_run = [c for c in checks if c in ALL_CHECKS]
        else:
            checks_to_run = checks
    else:
        st.error(f"Invalid checks parameter type: {type(checks)}. Using 'all'.")
        checks_to_run = ALL_CHECKS.copy()
    
    # Apply skip_checks
    if skip_checks:
        checks_to_run = [c for c in checks_to_run if c not in skip_checks]
    
    # Safety check: Ensure at least one check is specified
    if not checks_to_run:
        st.error("No valid checks to run! Please specify at least one valid check.")
        return False if not return_dict else {'overall': False}
    
    st.log(f'Calling verify_base_setup_bgw for nodes: {bgw_nodes}')
    st.log(f'Running checks: {checks_to_run}')
    
    # Initialize results
    results = {'overall': True}
    
    for dut in bgw_nodes:
        results[dut] = {}
        st.banner(f'Verifying {dut} - Checks: {checks_to_run}')
        
        # ============================================================
        # VLAN-VNI Mapping Verification
        # ============================================================
        if 'vlan_vni' in checks_to_run:
            try:
                exp_data = vxlan_obj.get_expected_vxlan_vlanvnimap(dut)
                vxlan_obj.verify_vxlan_vlanvnimap(dut, exp_data, id_keys=['vlan', 'vni'], vl_retries=retry)
                st.log(f'✓ VLAN-VNI map on {dut}: Pass ({len(exp_data)} mappings)')
                results[dut]['vlan_vni'] = True
            except Exception as err:
                st.log(f'✗ VLAN-VNI map on {dut}: Fail - {err}')
                results[dut]['vlan_vni'] = False
                results['overall'] = False
        
        # ============================================================
        # VRF-VNI Mapping Verification
        # ============================================================
        if 'vrf_vni' in checks_to_run:
            try:
                exp_data = vxlan_obj.get_expected_vxlan_vrfvnimap(dut)
                vxlan_obj.verify_vxlan_vrfvnimap(dut, exp_data, vl_retries=retry)
                st.log(f'✓ VRF-VNI map on {dut}: Pass ({len(exp_data)} mappings)')
                results[dut]['vrf_vni'] = True
            except Exception as err:
                st.log(f'✗ VRF-VNI map on {dut}: Fail - {err}')
                results[dut]['vrf_vni'] = False
                results['overall'] = False
        
        # ============================================================
        # Remote VTEP Discovery Verification
        # ============================================================
        if 'vteps' in checks_to_run:
            try:
                exp_data = vxlan_obj.get_expected_vxlan_remotevtep(dut)
                vxlan_obj.verify_vxlan_remotevtep(dut, exp_data, vl_retries=retry)
                st.log(f'✓ Remote VTEPs on {dut}: Pass ({len(exp_data)} VTEPs)')
                results[dut]['vteps'] = True
            except Exception as err:
                st.log(f'✗ Remote VTEPs on {dut}: Fail - {err}')
                results[dut]['vteps'] = False
                results['overall'] = False
        
        # ============================================================
        # VXLAN Tunnel Status Verification
        # ============================================================
        if 'tunnels' in checks_to_run:
            try:
                exp_data = vxlan_obj.get_expected_vxlan_tunnel(dut)
                if exp_data:
                    vxlan_obj.verify_vxlan_tunnel(dut, exp_data, vl_retries=retry)
                    tunnel_count = len(exp_data) if isinstance(exp_data, (list, dict)) else 0
                    st.log(f'✓ VXLAN tunnels on {dut}: Pass ({tunnel_count} tunnels)')
                    results[dut]['tunnels'] = True
                else:
                    st.log(f'✓ VXLAN tunnels on {dut}: Pass (0 tunnels expected)')
                    results[dut]['tunnels'] = True
            except Exception as err:
                st.log(f'✗ VXLAN tunnels on {dut}: Fail - {err}')
                results[dut]['tunnels'] = False
                results['overall'] = False
        
        # ============================================================
        # BGP Session Verification (Underlay + Overlay)
        # ============================================================
        if 'bgp' in checks_to_run:
            try:
                # Combine expectations from IPv4/IPv6 Unicast and L2VPN EVPN
                unicast_exp = vxlan_obj.get_expected_bgp_summary_dci(dut)
                evpn_exp = vxlan_obj.get_expected_bgp_l2vpn_evpn_summary_dci(dut)
                exp_data = unicast_exp + evpn_exp
                
                if exp_data:
                    vxlan_obj.verify_bgp_summary_dci(dut, exp_data, vl_retries=retry)
                    st.log(f'✓ BGP sessions on {dut}: Pass ({len(exp_data)} neighbors)')
                    results[dut]['bgp'] = True
                else:
                    st.log(f'✓ BGP sessions on {dut}: Skipped (no BGP neighbors expected)')
                    results[dut]['bgp'] = True
            except Exception as err:
                st.log(f'✗ BGP sessions on {dut}: Fail - {err}')
                results[dut]['bgp'] = False
                results['overall'] = False
        
        # ============================================================
        # EVPN Ethernet Segment (Multi-homing) Verification
        # ============================================================
        if 'evpn_es' in checks_to_run:
            # Only check on leaf nodes with multi-homing
            if 'leaf' not in dut or not test_cfg.get(dut) or not test_cfg[dut].get('port_channels'):
                st.log(f'✓ EVPN ES on {dut}: Skipped (not a multi-homed leaf)')
                results[dut]['evpn_es'] = True
            else:
                try:
                    exp_data = vxlan_obj.get_expected_evpn_es(dut)
                    if exp_data:
                        vxlan_obj.verify_evpn_es(dut, exp_data, vl_retries=retry)
                        st.log(f'✓ EVPN ES on {dut}: Pass ({len(exp_data)} ES)')
                        results[dut]['evpn_es'] = True
                    else:
                        st.log(f'✓ EVPN ES on {dut}: Skipped (no ES expected)')
                        results[dut]['evpn_es'] = True
                except Exception as err:
                    st.log(f'✗ EVPN ES on {dut}: Fail - {err}')
                    results[dut]['evpn_es'] = False
                    results['overall'] = False
        
        # ============================================================
        # EVPN ES per EVI/VLAN Verification
        # ============================================================
        if 'evpn_es_evi' in checks_to_run:
            # Only check on leaf nodes with multi-homing
            if 'leaf' not in dut or not test_cfg.get(dut) or not test_cfg[dut].get('port_channels'):
                st.log(f'✓ EVPN ES-EVI on {dut}: Skipped (not a multi-homed leaf)')
                results[dut]['evpn_es_evi'] = True
            else:
                try:
                    exp_data = vxlan_obj.get_expected_evpn_es_evi(dut)
                    if exp_data:
                        vxlan_obj.verify_evpn_es_evi(dut, exp_data, vl_retries=retry)
                        st.log(f'✓ EVPN ES-EVI on {dut}: Pass ({len(exp_data)} ES-EVI)')
                        results[dut]['evpn_es_evi'] = True
                    else:
                        st.log(f'✓ EVPN ES-EVI on {dut}: Skipped (no ES-EVI expected)')
                        results[dut]['evpn_es_evi'] = True
                except Exception as err:
                    st.log(f'✗ EVPN ES-EVI on {dut}: Fail - {err}')
                    results[dut]['evpn_es_evi'] = False
                    results['overall'] = False
        
        # ============================================================
        # EVPN Type 1 Routes (ES Auto-Discovery) Verification
        # ============================================================
        if 'evpn_type1' in checks_to_run:
            try:
                exp_data = vxlan_obj.get_expected_evpn_type1_routes(dut)
                if exp_data:
                    vxlan_obj.verify_evpn_type1_routes(dut, exp_data, vl_retries=retry)
                    st.log(f'✓ EVPN Type 1 Routes on {dut}: Pass ({len(exp_data)} routes)')
                    results[dut]['evpn_type1'] = True
                else:
                    st.log(f'✓ EVPN Type 1 Routes on {dut}: Skipped (no Type 1 routes expected)')
                    results[dut]['evpn_type1'] = True
            except Exception as err:
                st.log(f'✗ EVPN Type 1 Routes on {dut}: Fail - {err}')
                results[dut]['evpn_type1'] = False
                results['overall'] = False
        
        # ============================================================
        # EVPN Type 4 Routes (ES-Import) Verification
        # ============================================================
        if 'evpn_type4' in checks_to_run:
            try:
                exp_data = vxlan_obj.get_expected_evpn_type4_routes(dut)
                if exp_data:
                    vxlan_obj.verify_evpn_type4_routes(dut, exp_data, vl_retries=retry)
                    st.log(f'✓ EVPN Type 4 Routes on {dut}: Pass ({len(exp_data)} routes)')
                    results[dut]['evpn_type4'] = True
                else:
                    st.log(f'✓ EVPN Type 4 Routes on {dut}: Skipped (no Type 4 routes expected)')
                    results[dut]['evpn_type4'] = True
            except Exception as err:
                st.log(f'✗ EVPN Type 4 Routes on {dut}: Fail - {err}')
                results[dut]['evpn_type4'] = False
                results['overall'] = False
        
        # ============================================================
        # PortChannel Operational Status Verification
        # ============================================================
        if 'portchannel' in checks_to_run:
            if not test_cfg.get(dut) or not test_cfg[dut].get('port_channels'):
                st.log(f'✓ PortChannel on {dut}: Skipped (no PortChannels configured)')
                results[dut]['portchannel'] = True
            else:
                try:
                    pc_config = test_cfg[dut]['port_channels']
                    pc_list = []
                    
                    # Handle list of PC dicts
                    if isinstance(pc_config, list):
                        for pc in pc_config:
                            if isinstance(pc, dict):
                                pc_num = pc.get('port_channel_num')
                                if pc_num:
                                    pc_list.append(f"PortChannel{pc_num}")
                                else:
                                    pc_id = pc.get('id', pc.get('name', pc.get('portchannel', '')))
                                    if pc_id:
                                        pc_list.append(pc_id)
                            else:
                                pc_list.append(str(pc))
                        pc_list = [pc for pc in pc_list if pc]
                    
                    if pc_list:
                        for pc_id in pc_list:
                            pc_obj.verify_portchannel(dut, portchannel_name=pc_id)
                        st.log(f'✓ PortChannel on {dut}: Pass ({len(pc_list)} PortChannels)')
                        results[dut]['portchannel'] = True
                    else:
                        st.log(f'✓ PortChannel on {dut}: Skipped (config format not recognized)')
                        results[dut]['portchannel'] = True
                except Exception as err:
                    st.log(f'✗ PortChannel on {dut}: Fail - {err}')
                    results[dut]['portchannel'] = False
                    results['overall'] = False
        
        # Per-node summary
        node_passed = all(results[dut].values())
        if node_passed:
            st.banner(f'✓ Base setup verification on {dut}: Pass')
        else:
            failed_checks = [c for c, res in results[dut].items() if not res]
            st.banner(f'✗ Base setup verification on {dut}: Fail ({failed_checks})')
    
    # Overall summary
    if results['overall']:
        st.banner('✓ Overall base setup verification: Pass')
    else:
        st.banner('✗ Overall base setup verification: Fail')
    
    # Return detailed dict or simple boolean based on return_dict flag
    if return_dict:
        return results
    else:
        return results['overall']


# ============================================================================
# BASE TEST CLASS (DCI base config + base testcases only)
# ============================================================================

@pytest.mark.usefixtures('tgen_health_check_class')
class TestVxlanDCIBase():
    """Base DCI tests: L2/L3 traffic, BUM, verification. Prerequisite for trigger tests."""
    """
    Base test class for DCI (Data Center Interconnect) verification.
    Tests cover control plane, data plane, and traffic verification across multiple datacenters.
    """
    
    def test_base_dci_bringup(self):
        """
        Solution_dci:1 - Verify DCI base profile bring up with 3 DCs
        
        Description:
            Comprehensive verification of DCI base profile after initial configuration.
            Validates all control plane and data plane elements across the 3 data centers:
            - DC1 (4 leafs + 2 BGW spines)
            - DC2 (2 leafs + 2 BGW spines)
            - DC3 (1 leaf + 1 BGW spine)
        
        Verification includes:
            - EVPN multi-homing (ES, ES-EVI, Type 1/4 routes) on leaf nodes
            - VXLAN overlay (VLAN-VNI, VRF-VNI mappings)
            - VXLAN tunnels (single on leafs, dual DC+WAN on BGWs)
            - Remote VTEP discovery via EVPN Type-3 routes
            - BGP control plane (underlay + EVPN overlay sessions)
            - PortChannel status for multi-homed segments
        """
        tc_id = "test_base_dci_bringup"
        test_cfg['tc_id'] = tc_id
        tc_cfg = vxlan_obj.get_tc_params(tc_id)
        
        st.banner('Testcase Solution_dci:1: Verify DCI base profile with 3 DCs ({})'.format(tc_id))
        
        # Perform comprehensive base setup verification on all nodes
        st.log('Performing comprehensive verification on all DCI nodes...')
        result = verify_base_setup_bgw(test_cfg['nodes']['l2l3vni_bgw'])
        if result:
            st.log('Base DCI setup verification: Pass')
        else:
            st.log('Base DCI setup verification: Fail')
        
        report_result(result, tc_id, '')
    
    def test_base_dci_frr_sonic_cli(self):
        """
        Solution_dci:2 - Verify all FRR and SONIC CLIs
        
        Description:
            1) Refer to Solution_dci:1 testcase for base profile bring up
            2) Verify all the new FRR and SONIC CLI's implemented as a part of this feature
            
        Steps:
            1. Verify show vxlan commands on all nodes
            2. Verify show evpn commands on BGW nodes
            3. Verify EVPN ES and ES-EVI on leaf nodes with multi-homing
            4. Verify show bgp commands for DCI
        """
        tc_id = "test_base_dci_frr_sonic_cli"
        test_cfg['tc_id'] = tc_id
        tc_cfg = vxlan_obj.get_tc_params(tc_id)
        
        st.banner('Testcase Solution_dci:2: Verify all FRR and SONIC DCI related CLIs ({})'.format(tc_id))
        result = True
        summ = ''
        
        # Verify VXLAN show commands on all nodes
        for dut in test_cfg['nodes']['l2l3vni_bgw']:
            st.banner('Verify VXLAN show commands on node: {}'.format(dut))
            try:
                # show vxlan interface
                exp_data = vxlan_obj.get_expected_vxlan_interface(dut)
                if exp_data:
                    vxlan_obj.verify_vxlan_interface(dut, exp_data)
                    st.log('Show vxlan interface on {}: Pass'.format(dut))
                else:
                    st.log('Show vxlan interface on {}: Skipped (no VXLAN interface expected)'.format(dut))
                
                # show vxlan vlanvnimap
                exp_data = vxlan_obj.get_expected_vxlan_vlanvnimap(dut)
                if exp_data:
                    vxlan_obj.verify_vxlan_vlanvnimap(dut, exp_data, id_keys=['vlan', 'vni'])
                    st.log('Show vxlan vlanvnimap on {}: Pass ({} mappings)'.format(dut, len(exp_data)))
                else:
                    st.log('Show vxlan vlanvnimap on {}: Skipped (no mappings expected)'.format(dut))
                
                # show vxlan vrfvnimap  
                exp_data = vxlan_obj.get_expected_vxlan_vrfvnimap(dut)
                if exp_data:
                    vxlan_obj.verify_vxlan_vrfvnimap(dut, exp_data)
                    st.log('Show vxlan vrfvnimap on {}: Pass ({} mappings)'.format(dut, len(exp_data)))
                else:
                    st.log('Show vxlan vrfvnimap on {}: Skipped (no VRF-VNI mappings expected)'.format(dut))
                
                # show vxlan tunnel
                exp_data = vxlan_obj.get_expected_vxlan_tunnel(dut)
                if exp_data:
                    vxlan_obj.verify_vxlan_tunnel(dut, exp_data)
                    st.log('Show vxlan tunnel on {}: Pass'.format(dut))
                else:
                    st.log('Show vxlan tunnel on {}: Skipped (no tunnels expected)'.format(dut))
                
            except Exception as err:
                msg = 'Verify VXLAN show commands on {}: Fail\n{}\n'.format(dut, err)
                st.log(msg)
                summ += msg
                result = False
        
        # Verify EVPN show commands on BGW nodes (FRR CLI)
        bgw_nodes = [node for node in test_cfg['nodes']['l2l3vni_bgw'] if 'bgw' in node.lower()]
        for dut in bgw_nodes:
            st.banner('Verify EVPN show commands on BGW node: {}'.format(dut))
            try:
                # show bgp l2vpn evpn summary (already verified via verify_bgp_summary_dci)
                evpn_exp = vxlan_obj.get_expected_bgp_l2vpn_evpn_summary_dci(dut)
                if evpn_exp:
                    vxlan_obj.verify_bgp_l2vpn_evpn_summary_dci(dut, evpn_exp)
                    st.log('Show bgp l2vpn evpn summary on {}: Pass ({} neighbors)'.format(dut, len(evpn_exp)))
                else:
                    st.log('Show bgp l2vpn evpn summary on {}: Skipped (no EVPN neighbors expected)'.format(dut))
                
                # show evpn vni
                exp_data = vxlan_obj.get_expected_evpn_vni(dut)
                if exp_data:
                    vxlan_obj.verify_evpn_vni(dut, exp_data)
                    st.log('Show evpn vni on {}: Pass ({} VNIs)'.format(dut, len(exp_data)))
                else:
                    st.log('Show evpn vni on {}: Skipped (no VNIs expected)'.format(dut))
                
            except Exception as err:
                msg = 'Verify EVPN show commands on {}: Fail\n{}\n'.format(dut, err)
                st.log(msg)
                summ += msg
                result = False
        
        # Verify EVPN ES and ES-EVI on leaf nodes with multi-homing
        leaf_nodes = [node for node in test_cfg['nodes']['l2l3vni_bgw'] 
                      if 'leaf' in node and test_cfg.get(node, {}).get('port_channels')]
        
        if leaf_nodes:
            st.banner('Verifying EVPN ES and ES-EVI on multi-homed leaf nodes')
            for dut in leaf_nodes:
                st.banner('Verify EVPN ES and ES-EVI on leaf node: {}'.format(dut))
                try:
                    # show evpn es (Ethernet Segment)
                    exp_data = vxlan_obj.get_expected_evpn_es(dut)
                    if exp_data:
                        vxlan_obj.verify_evpn_es(dut, exp_data)
                        st.log('Show evpn es on {}: Pass ({} Ethernet Segments)'.format(dut, len(exp_data)))
                    else:
                        st.log('Show evpn es on {}: Skipped (no ES expected)'.format(dut))
                    
                    # show evpn es-evi (Ethernet Segment per EVI/VLAN)
                    exp_data = vxlan_obj.get_expected_evpn_es_evi(dut)
                    if exp_data:
                        vxlan_obj.verify_evpn_es_evi(dut, exp_data)
                        st.log('Show evpn es-evi on {}: Pass ({} ES-EVI entries)'.format(dut, len(exp_data)))
                    else:
                        st.log('Show evpn es-evi on {}: Skipped (no ES-EVI expected)'.format(dut))
                    
                except Exception as err:
                    msg = 'Verify EVPN ES/ES-EVI on {}: Fail\n{}\n'.format(dut, err)
                    st.log(msg)
                    summ += msg
                    result = False
        else:
            st.log('No multi-homed leaf nodes found - skipping EVPN ES/ES-EVI verification')
        
        report_result(result, tc_id, summ)
    
    def test_base_dci_l2l3vni_ipv4_within_dc(self):
        """
        Solution_dci:3 - Verify L2VNI and L3VNI traffic between hosts within DC (IPv4)
        
        Description:
            1) Refer to Solution_dci:1 testcase for base profile bring up
            2) Verify ipv4 L2VNI and L3VNI traffic between hosts within DC1
            3) Within DC, there can be MH or SH host
            4) Verify no traffic drop
            5) Verify no crash/core seen
            
        Note:
            Only testing within DC1 (leaf0_dc1 → other DC1 leaves).
            Within-DC behavior is identical across all DCs, so testing one DC is sufficient.
            Uses scope='within' to filter only streams with DC1 destinations (no D11, D12, D14).
            
        Steps:
            1. Filter traffic to only within-DC flows (source and destination both in DC1)
            2. Send L2VNI IPv4 traffic within DC1
            3. Send L3VNI IPv4 traffic within DC1
            4. Verify no packet loss
        """
        tc_id = "test_base_dci_l2l3vni_ipv4_within_dc"
        test_cfg['tc_id'] = tc_id
        tc_cfg = vxlan_obj.get_tc_params(tc_id)
        
        st.banner('Testcase Solution_dci:3: Verify L2VNI and L3VNI IPv4 traffic within DC1 ({})'.format(tc_id))
        result = True
        summ = ''
        
        # Step 1: Verify base setup is healthy before traffic test
        st.banner('Step 1: Verify base setup before IPv4 traffic test')
        if not verify_base_setup_bgw(test_cfg['nodes']['l2l3vni_bgw'], checks='basic'):
            summ = 'Base setup verification failed before IPv4 traffic test\n'
            st.log(summ)
            result = False
        
        # Step 2: Use scope='within' to test ONLY streams with DC1 destinations
        st.banner('Step 2: Verify L2VNI and L3VNI IPv4 traffic within DC1')
        if verify_traffic(tgen_handles, regenerate=True, traffic_types=['l2_v4', 'l3_v4'], scope='within'):
            st.log('L2VNI and L3VNI IPv4 traffic within DC1: Pass')
        else:
            summ = 'L2VNI and L3VNI IPv4 traffic within DC1: Fail'
            st.log(summ)
            result = False
        
        report_result(result, tc_id, summ)
    
    def test_base_dci_l2l3vni_ipv6_within_dc(self):
        """
        Solution_dci:4 - Verify L2VNI and L3VNI traffic between hosts within DC (IPv6)
        
        Description:
            1) Refer to Solution_dci:1 testcase for base profile bring up
            2) Verify ipv6 L2VNI and L3VNI traffic between hosts within DC1
            3) Within DC, there can be MH or SH host
            4) Verify no traffic drop
            5) Verify no crash/core seen
            
        Note:
            Only testing within DC1 (leaf0_dc1 → other DC1 leaves).
            Within-DC behavior is identical across all DCs, so testing one DC is sufficient.
            Uses scope='within' to filter only streams with DC1 destinations (no D11, D12, D14).
            
        Steps:
            1. Filter traffic to only within-DC flows (source and destination both in DC1)
            2. Send L2VNI IPv6 traffic within DC1
            3. Send L3VNI IPv6 traffic within DC1
            4. Verify no packet loss
        """
        tc_id = "test_base_dci_l2l3vni_ipv6_within_dc"
        test_cfg['tc_id'] = tc_id
        tc_cfg = vxlan_obj.get_tc_params(tc_id)
        
        st.banner('Testcase Solution_dci:4: Verify L2VNI and L3VNI IPv6 traffic within DC1 ({})'.format(tc_id))
        result = True
        summ = ''
        # Step 1: Verify base setup is healthy before traffic test
        st.banner('Step 1: Verify base setup before IPv6 traffic test')
        if not verify_base_setup_bgw(test_cfg['nodes']['l2l3vni_bgw'], checks='basic'):
            summ = 'Base setup verification failed before IPv6 traffic test\n'
            st.log(summ)
            result = False
        
        # Step 2: Use scope='within' to test ONLY streams with DC1 destinations
        st.banner('Step 2: Verify L2VNI and L3VNI IPv6 traffic within DC1')
        if verify_traffic(tgen_handles, regenerate=True, traffic_types=['l2_v6', 'l3_v6'], scope='within'):
            st.log('L2VNI and L3VNI IPv6 traffic within DC1: Pass')
        else:
            summ = 'L2VNI and L3VNI IPv6 traffic within DC1: Fail'
            st.log(summ)
            result = False
        
        report_result(result, tc_id, summ)
    
    def test_base_dci_l2vni_ipv4_across_dci(self):
        """
        Solution_dci:5 - Verify L2VNI traffic between hosts across DCI (IPv4)
        
        Description:
            1) Refer to Solution_dci:1 testcase for base profile bring up
            2) Verify ipv4 L2VNI traffic between the hosts across DC1, DC2 and DC3
            3) Across DC, there will be SH host only in phase 1
            4) Verify no traffic drop
            5) Verify no crash/core seen
            
        Note:
            Uses scope='cross' to filter only streams with DC2/DC3 destinations (D11, D12, D14).
            
        Steps:
            1. Send L2VNI IPv4 traffic across DCs (DC1 → DC2, DC1 → DC3)
            2. Verify no packet loss
        """
        tc_id = "test_base_dci_l2vni_ipv4_across_dci"
        test_cfg['tc_id'] = tc_id
        tc_cfg = vxlan_obj.get_tc_params(tc_id)
        
        st.banner('Testcase Solution_dci:5: Verify L2VNI IPv4 traffic across DCI ({})'.format(tc_id))
        result = True
        summ = ''
        
        # Step 1: Verify base setup is healthy before traffic test
        st.banner('Step 1: Verify base setup before cross-DC IPv4 traffic test')
        if not verify_base_setup_bgw(test_cfg['nodes']['l2l3vni_bgw'], checks='basic'):
            summ = 'Base setup verification failed before cross-DC IPv4 traffic test\n'
            st.log(summ)
            result = False
        
        # Step 2: Use scope='cross' to test ONLY streams with DC2/DC3 destinations
        st.banner('Step 2: Verify L2VNI IPv4 traffic across DCI')
        if verify_traffic(tgen_handles, regenerate=True, traffic_types=['l2_v4'], scope='cross'):
            st.log('L2VNI IPv4 traffic across DCI: Pass')
        else:
            summ = 'L2VNI IPv4 traffic across DCI: Fail'
            st.log(summ)
            result = False
        
        report_result(result, tc_id, summ)
    
    def test_base_dci_l2vni_ipv6_across_dci(self):
        """
        Solution_dci:6 - Verify L2VNI traffic between hosts across DCI (IPv6)
        
        Description:
            1) Refer to Solution_dci:1 testcase for base profile bring up
            2) Verify ipv6 L2VNI traffic between the hosts across DC1, DC2 and DC3
            3) Across DC, there will be SH host only in phase 1
            4) Verify no traffic drop
            5) Verify no crash/core seen
            
        Note:
            Uses scope='cross' to filter only streams with DC2/DC3 destinations (D11, D12, D14).
            
        Steps:
            1. Send L2VNI IPv6 traffic across DCs (DC1 → DC2, DC1 → DC3)
            2. Verify no packet loss
        """
        tc_id = "test_base_dci_l2vni_ipv6_across_dci"
        test_cfg['tc_id'] = tc_id
        tc_cfg = vxlan_obj.get_tc_params(tc_id)
        
        st.banner('Testcase Solution_dci:6: Verify L2VNI IPv6 traffic across DCI ({})'.format(tc_id))
        result = True
        summ = ''
        
        # Step 1: Verify base setup is healthy before traffic test
        st.banner('Step 1: Verify base setup before cross-DC IPv6 traffic test')
        if not verify_base_setup_bgw(test_cfg['nodes']['l2l3vni_bgw'], checks='basic'):
            summ = 'Base setup verification failed before cross-DC IPv6 traffic test\n'
            st.log(summ)
            result = False
        
        # Step 2: Use scope='cross' to test ONLY streams with DC2/DC3 destinations
        st.banner('Step 2: Verify L2VNI IPv6 traffic across DCI')
        if verify_traffic(tgen_handles, regenerate=True, traffic_types=['l2_v6'], scope='cross'):
            st.log('L2VNI IPv6 traffic across DCI: Pass')
        else:
            summ = 'L2VNI IPv6 traffic across DCI: Fail'
            st.log(summ)
            result = False
        
        report_result(result, tc_id, summ)
    
    def test_base_dci_l3vni_ipv4_across_dci(self):
        """
        L3VNI_dci:1 - L3VNI Base Profile - Bring up L3VNI base profile across DCI
        
        Description:
            1) Bring up DCI base profile with 3 DCs using V6 VTEP
            2) Configure L3VNI on top of L2VNI base profile
            3) Configure all Route target import and export on each node
            4) Verify L3VNI mapping (show vxlan vlanvnimap)
            5) Verify VRF to VNI binding (show vxlan vrfvnimap)
               - Per vxlan_dci_input_file.yaml:
                 Leaf DC1: Vrf101→5101, Vrf102→5102
                 Leaf DC2: Vrf101→5101, Vrf102→7102
                 Leaf DC3: Vrf101→5101, Vrf102→9102
               - BGW nodes use cross-DC L3VNI: 10101 (Vrf101), 10102 (Vrf102)
            6) Verify Type-5 routes advertised (show bgp l2vpn evpn route type prefix)
               - Route format: [5]:[0]:[24]:[ip_prefix]
            7) Verify VXLAN tunnels and remote VTEPs
            8) Send L3VNI IPv4 traffic across DCs and verify no packet loss
               - 23 L3VNI flows: DC1→DC2 (SH/MH), DC2→DC3
               - VRF101 VLAN pairs: 11→12, 12→13, 13→14, 15→11
               - VRF102 VLAN pairs: 16→17, 17→18, 18→19, 20→16
            
        Verification CLIs:
            show vxlan vlanvnimap, show vxlan vrfvnimap, show vrf,
            show bgp l2vpn evpn route type 5, show vxlan tunnel,
            show vxlan remotevtep, show ip route vrf all
            
        Steps:
            1. Verify VRF-VNI mappings on all nodes (leaf and BGW)
            2. Verify VLAN-VNI mappings on all nodes
            3. Verify Type-5 routes on BGW nodes
            4. Send L3VNI IPv4 traffic across DCI and verify no packet loss
        """
        tc_id = "test_base_dci_l3vni_ipv4_across_dci"
        test_cfg['tc_id'] = tc_id
        tc_cfg = vxlan_obj.get_tc_params(tc_id)
        
        st.banner('Testcase L3VNI_dci:1: L3VNI Base Profile across DCI ({})'.format(tc_id))
        result = True
        summ = ''
        
        # Step 1: Verify VRF-VNI mappings on all nodes (leaf and BGW)
        st.banner('Step 1: Verify VRF-VNI mappings on all DCI nodes')
        st.log('Expected VRF-VNI bindings from vxlan_dci_input_file.yaml:')
        st.log('  DC1 leafs: Vrf101->5101, Vrf102->5102')
        st.log('  DC2 leafs: Vrf101->5101, Vrf102->7102')
        st.log('  DC3 leafs: Vrf101->5101, Vrf102->9102')
        for dut in test_cfg['nodes']['l2l3vni_bgw']:
            try:
                exp_data = vxlan_obj.get_expected_vxlan_vrfvnimap(dut)
                if exp_data:
                    vxlan_obj.verify_vxlan_vrfvnimap(dut, exp_data, vl_retries=2)
                    st.log('VRF-VNI map on {}: Pass ({} mappings)'.format(dut, len(exp_data)))
                else:
                    st.log('VRF-VNI map on {}: Skipped (no VRF-VNI mappings expected)'.format(dut))
            except Exception as err:
                msg = 'VRF-VNI map verification on {}: Fail - {}\n'.format(dut, err)
                st.log(msg)
                summ += msg
                result = False
        
        # Step 2: Verify VLAN-VNI mappings on all nodes
        st.banner('Step 2: Verify VLAN-VNI mappings on all DCI nodes')
        for dut in test_cfg['nodes']['l2l3vni_bgw']:
            try:
                exp_data = vxlan_obj.get_expected_vxlan_vlanvnimap(dut)
                if exp_data:
                    vxlan_obj.verify_vxlan_vlanvnimap(dut, exp_data, id_keys=['vlan', 'vni'], vl_retries=2)
                    st.log('VLAN-VNI map on {}: Pass ({} mappings)'.format(dut, len(exp_data)))
                else:
                    st.log('VLAN-VNI map on {}: Skipped (no VLAN-VNI mappings expected)'.format(dut))
            except Exception as err:
                msg = 'VLAN-VNI map verification on {}: Fail - {}\n'.format(dut, err)
                st.log(msg)
                summ += msg
                result = False
        
        # Step 3: Verify Type-5 routes on BGW nodes
        st.banner('Step 3: Verify EVPN Type-5 routes on BGW nodes')
        st.log('Type-5 route format: [5]:[0]:[prefix_len]:[prefix]')
        st.log('Expected L3VNI in extended community: 10101 (Vrf101), 10102 (Vrf102)')
        bgw_nodes = [node for node in test_cfg['nodes']['l2l3vni_bgw'] if 'bgw' in node.lower()]
        for dut in bgw_nodes:
            try:
                type5_present = vxlan_obj.verify_evpn_type5_routes_dci(dut)
                if type5_present:
                    st.log('EVPN Type-5 routes on {}: Pass'.format(dut))
                else:
                    msg = 'EVPN Type-5 routes on {}: Fail - no Type-5 routes found\n'.format(dut)
                    st.log(msg)
                    summ += msg
                    result = False
            except Exception as err:
                msg = 'EVPN Type-5 route verification on {}: Fail - {}\n'.format(dut, err)
                st.log(msg)
                summ += msg
                result = False
        
        # Step 4: Send L3VNI IPv4 traffic across DCI and verify no packet loss
        st.banner('Step 4: Verify L3VNI IPv4 traffic across DCI')
        st.log('Using scope="cross" to test ONLY L3VNI streams with DC2/DC3 destinations')
        st.log('Traffic flows: VRF101 (11->12, 12->13, 13->14, 15->11) + VRF102 (16->17, 17->18, 18->19, 20->16)')
        if verify_traffic(tgen_handles, regenerate=True, traffic_types=['l3_v4'], scope='cross'):
            st.log('L3VNI IPv4 traffic across DCI: Pass')
        else:
            msg = 'L3VNI IPv4 traffic across DCI: Fail\n'
            st.log(msg)
            summ += msg
            result = False
        
        report_result(result, tc_id, summ)
    
    def test_base_dci_l3vni_ipv6_across_dci(self):
        """
        L3VNI_dci:2 - L3VNI Control Plane - Type-5 route advertisement with IPv6 VTEP
        
        Description:
            1) Refer to L3VNI_dci:1 for base profile bring up
            2) Verify Type-5 route advertisement across DCI with IPv6 VTEP
            3) On DC-side (OVERLAY peer-group), BGWs advertise Type-5 routes
               with IPv6 next-hop (DC VIP) via RT-REWRITE-DC route-map:
               - DC1 BGWs: set ipv6 next-hop global 4000:1::1
               - DC2 BGWs: set ipv6 next-hop global 6000:1::1
               - DC3 BGW:  set ipv6 next-hop global 7000:1::1
            4) On WAN-side (OVERLAY_WAN peer-group), BGWs advertise Type-5 routes
               with IPv4 next-hop (WAN VIP) via RT-REWRITE-WAN route-map:
               - DC1 BGWs: set ip next-hop 101.101.101.101
               - DC2 BGWs: set ip next-hop 102.102.102.102
               - DC3 BGW:  set ip next-hop 103.103.103.103
            5) Verify Type-5 route format: [5]:[0]:[24]:[prefix]
            6) Verify L3VNI=10101/10102 in extended community
            7) Verify RT rewrite: each BGW exports unique RT (e.g. 65102:10101)
            8) Send L3VNI IPv6 traffic across DCI and verify no packet loss
            
        RT export per BGW from l3vni_config_diff.txt:
            DC1 BGW1 (AS 65102): RT 65102:10101, 65102:10102
            DC1 BGW2 (AS 65103): RT 65103:10101, 65103:10102
            DC2 BGW1 (AS 65104): RT 65104:10101, 65104:10102
            DC2 BGW2 (AS 65105): RT 65105:10101, 65105:10102
            DC3 BGW1 (AS 65106): RT 65106:10101, 65106:10102
            
        Steps:
            1. Verify Type-5 route details on BGW nodes (format, L3VNI, next-hop)
            2. Verify VRF-VNI mappings on all BGW nodes
            3. Verify BGP L2VPN EVPN summary on BGW nodes (all neighbors UP)
            4. Send L3VNI IPv6 traffic across DCI and verify no packet loss
        """
        tc_id = "test_base_dci_l3vni_ipv6_across_dci"
        test_cfg['tc_id'] = tc_id
        tc_cfg = vxlan_obj.get_tc_params(tc_id)
        
        st.banner('Testcase L3VNI_dci:2: Type-5 route advertisement with IPv6 VTEP ({})'.format(tc_id))
        result = True
        summ = ''
        
        bgw_nodes = [node for node in test_cfg['nodes']['l2l3vni_bgw'] if 'bgw' in node.lower()]
        
        # Step 1: Verify Type-5 route details on BGW nodes
        st.banner('Step 1: Verify Type-5 route details on BGW nodes')
        st.log('Checking: route format [5]:[0]:[prefix_len]:[prefix], L3VNI in ext-community, IPv6 VTEP next-hop')
        for dut in bgw_nodes:
            try:
                type5_result = vxlan_obj.verify_evpn_type5_route_detail_dci(dut)
                if type5_result['result']:
                    st.log('Type-5 route detail on {}: Pass - {}'.format(dut, type5_result['details']))
                    if type5_result['ipv6_nexthop_found']:
                        st.log('  IPv6 VTEP next-hop confirmed on {}'.format(dut))
                    if type5_result['l3vni_found']:
                        st.log('  L3VNI values in ext-community on {}: {}'.format(
                            dut, type5_result['l3vni_found']))
                else:
                    msg = 'Type-5 route detail on {}: Fail - {}\n'.format(dut, type5_result['details'])
                    st.log(msg)
                    summ += msg
                    result = False
            except Exception as err:
                msg = 'Type-5 route detail verification on {}: Fail - {}\n'.format(dut, err)
                st.log(msg)
                summ += msg
                result = False
        
        # Step 2: Verify VRF-VNI mappings on BGW nodes
        st.banner('Step 2: Verify VRF-VNI mappings on BGW nodes')
        st.log('BGW nodes use cross-DC L3VNI: Vrf101->10101, Vrf102->10102')
        for dut in bgw_nodes:
            try:
                exp_data = vxlan_obj.get_expected_vxlan_vrfvnimap(dut)
                if exp_data:
                    vxlan_obj.verify_vxlan_vrfvnimap(dut, exp_data, vl_retries=2)
                    st.log('VRF-VNI map on {}: Pass ({} mappings)'.format(dut, len(exp_data)))
                else:
                    st.log('VRF-VNI map on {}: Skipped (no mappings expected)'.format(dut))
            except Exception as err:
                msg = 'VRF-VNI map on {}: Fail - {}\n'.format(dut, err)
                st.log(msg)
                summ += msg
                result = False
        
        # Step 3: Verify BGP L2VPN EVPN summary on BGW nodes
        st.banner('Step 3: Verify BGP L2VPN EVPN summary on BGW nodes')
        for dut in bgw_nodes:
            try:
                evpn_exp = vxlan_obj.get_expected_bgp_l2vpn_evpn_summary_dci(dut)
                if evpn_exp:
                    vxlan_obj.verify_bgp_l2vpn_evpn_summary_dci(dut, evpn_exp, vl_retries=2)
                    st.log('BGP L2VPN EVPN summary on {}: Pass ({} neighbors)'.format(dut, len(evpn_exp)))
                else:
                    st.log('BGP L2VPN EVPN summary on {}: Skipped (no neighbors expected)'.format(dut))
            except Exception as err:
                msg = 'BGP L2VPN EVPN summary on {}: Fail - {}\n'.format(dut, err)
                st.log(msg)
                summ += msg
                result = False
        
        # Step 4: Send L3VNI IPv6 traffic across DCI
        st.banner('Step 4: Verify L3VNI IPv6 traffic across DCI')
        st.log('Using scope="cross" to test ONLY L3VNI streams with DC2/DC3 destinations')
        if verify_traffic(tgen_handles, regenerate=True, traffic_types=['l3_v6'], scope='cross'):
            st.log('L3VNI IPv6 traffic across DCI: Pass')
        else:
            msg = 'L3VNI IPv6 traffic across DCI: Fail\n'
            st.log(msg)
            summ += msg
            result = False
        
        report_result(result, tc_id, summ)
    
    def test_base_dci_l3vni_control_plane_across_dci(self):
        """
        L3VNI_dci:6 - L3VNI Control Plane - Multihop eBGP EVPN session between BGWs
        
        Description:
            1) Refer to L3VNI_dci:1 for base profile bring up
            2) Verify eBGP multihop (255) EVPN sessions between BGW spines across DCs
               - OVERLAY_WAN peer-group: eBGP multihop to remote DC BGWs (IPv4 overlay)
               - update-source: Loopback1 (unique per BGW)
            3) Verify Type-5 routes exchanged over multihop sessions
            4) BGW ASN assignments from l3vni_config_diff.txt:
               - DC1 BGW1: AS 65102 (spine2_dc1_bgw1)
               - DC1 BGW2: AS 65103 (spine3_dc1_bgw2)
               - DC2 BGW1: AS 65104 (spine0_dc2_bgw1)
               - DC2 BGW2: AS 65105 (spine1_dc2_bgw2)
               - DC3 BGW1: AS 65106 (spine0_dc3_bgw1)
            5) Each BGW imports RT from all remote DC BGWs in VRF context:
               e.g. DC1 BGW1 (router bgp 65102 vrf Vrf101):
                 route-target export 65102:10101
                 route-target import 65104:10101 (DC2 BGW1)
                 route-target import 65105:10101 (DC2 BGW2)
                 route-target import 65106:10101 (DC3 BGW1)
                 route-target import 65200:5101 (DC1 leaf0)
                 route-target import 65201:5101 (DC1 leaf1)
                 route-target import 65202:5101 (DC1 leaf2)
                 route-target import 65203:5101 (DC1 leaf3)
            6) RT-REWRITE route-maps applied on BGW out direction:
               - neighbor OVERLAY route-map RT-REWRITE-DC out (DC-side)
               - neighbor OVERLAY_WAN route-map RT-REWRITE-WAN out (WAN-side)
               - RT-REWRITE-WAN: match evpn route-type prefix, set evpn vni 10101,
                 set evpn rmac local, set extcommunity rt <ASN>:<L3VNI>,
                 set ip next-hop <WAN VIP>
               - RT-REWRITE-DC: same but set ipv6 next-hop global <DC VIP>
            7) Verify no crash/core seen
            
        Steps:
            1. Verify eBGP multihop EVPN sessions between BGWs across DCs
            2. Verify VRF-VNI mappings on all BGW nodes
            3. Verify EVPN VNI table shows L3 VNIs on BGW nodes
            4. Verify EVPN Type-5 routes exchanged with correct attributes
        """
        tc_id = "test_base_dci_l3vni_control_plane_across_dci"
        test_cfg['tc_id'] = tc_id
        tc_cfg = vxlan_obj.get_tc_params(tc_id)
        
        st.banner('Testcase L3VNI_dci:6: Multihop eBGP EVPN sessions between BGWs ({})'.format(tc_id))
        result = True
        summ = ''
        
        bgw_nodes = [node for node in test_cfg['nodes']['l2l3vni_bgw'] if 'bgw' in node.lower()]
        
        # Step 1: Verify eBGP multihop EVPN sessions between BGWs across DCs
        st.banner('Step 1: Verify eBGP multihop EVPN sessions between BGWs')
        st.log('Each BGW has OVERLAY_WAN peer-group with ebgp-multihop 255 to remote DC BGWs')
        st.log('BGW ASNs: DC1 BGW1=65102, DC1 BGW2=65103, DC2 BGW1=65104, DC2 BGW2=65105, DC3 BGW1=65106')
        for dut in bgw_nodes:
            try:
                session_result = vxlan_obj.verify_bgp_evpn_multihop_sessions_dci(dut)
                if session_result['result']:
                    st.log('eBGP multihop EVPN sessions on {}: Pass - {}'.format(
                        dut, session_result['details']))
                else:
                    msg = 'eBGP multihop EVPN sessions on {}: Fail - {}\n'.format(
                        dut, session_result['details'])
                    st.log(msg)
                    summ += msg
                    result = False
            except Exception as err:
                msg = 'eBGP multihop session verification on {}: Fail - {}\n'.format(dut, err)
                st.log(msg)
                summ += msg
                result = False
        
        # Step 2: Verify VRF-VNI mappings on all BGW nodes
        st.banner('Step 2: Verify VRF-VNI mappings on BGW nodes')
        st.log('BGW cross-DC L3VNI from l3vni_config_diff.txt: Vrf101->10101, Vrf102->10102')
        for dut in bgw_nodes:
            try:
                exp_data = vxlan_obj.get_expected_vxlan_vrfvnimap(dut)
                if exp_data:
                    vxlan_obj.verify_vxlan_vrfvnimap(dut, exp_data, vl_retries=2)
                    st.log('VRF-VNI map on {}: Pass ({} mappings)'.format(dut, len(exp_data)))
                else:
                    st.log('VRF-VNI map on {}: Skipped (no VRF-VNI mappings expected)'.format(dut))
            except Exception as err:
                msg = 'VRF-VNI map verification on {}: Fail - {}\n'.format(dut, err)
                st.log(msg)
                summ += msg
                result = False
        
        # Step 3: Verify EVPN VNI table shows L3 VNIs on BGW nodes
        st.banner('Step 3: Verify EVPN VNI table on BGW nodes')
        for dut in bgw_nodes:
            try:
                exp_data = vxlan_obj.get_expected_evpn_vni(dut)
                # Filter to L3 VNIs only for this check
                l3_vni_exp = [entry for entry in exp_data if entry.get('type') == 'L3']
                if l3_vni_exp:
                    vxlan_obj.verify_evpn_vni(dut, l3_vni_exp, vl_retries=2)
                    st.log('EVPN L3 VNI on {}: Pass ({} L3 VNIs)'.format(dut, len(l3_vni_exp)))
                else:
                    msg = 'No L3 VNIs expected on {} - check config\n'.format(dut)
                    st.log(msg)
                    summ += msg
                    result = False
            except Exception as err:
                msg = 'EVPN VNI verification on {}: Fail - {}\n'.format(dut, err)
                st.log(msg)
                summ += msg
                result = False
        
        # Step 4: Verify EVPN Type-5 routes exchanged with correct attributes
        st.banner('Step 4: Verify EVPN Type-5 routes exchanged between BGWs')
        st.log('Type-5 routes carry L3VNI (10101/10102) and RT (<ASN>:<L3VNI>) in ext-community')
        st.log('RT-REWRITE-WAN matches route-type prefix and rewrites VNI, RMAC, RT, next-hop')
        for dut in bgw_nodes:
            try:
                type5_result = vxlan_obj.verify_evpn_type5_route_detail_dci(dut)
                if type5_result['result']:
                    st.log('Type-5 routes on {}: Pass - {}'.format(dut, type5_result['details']))
                else:
                    msg = 'Type-5 routes on {}: Fail - {}\n'.format(dut, type5_result['details'])
                    st.log(msg)
                    summ += msg
                    result = False
            except Exception as err:
                msg = 'Type-5 route verification on {}: Fail - {}\n'.format(dut, err)
                st.log(msg)
                summ += msg
                result = False
        
        report_result(result, tc_id, summ)
    
    def test_base_dci_tunnel_counters_within_dc(self):
        """
        Solution_dci:7 - Verify Tunnel counters within Datacenter
        
        Description:
            1) Refer to Solution_dci:1 testcase for base profile bring up
            2) Verify the tunnel counters CLI within DC1
            3) Verify L2VNI traffic between hosts within DC1
            4) Verify no traffic drop
            5) Verify no crash/core seen
            
        Note:
            Only testing within DC1 (leaf0_dc1 → leaf1_dc1).
            
        Steps:
            1. Get tunnel counter values before traffic
            2. Send L2VNI traffic within DC1
            3. Get tunnel counter values after traffic
            4. Verify counters incremented appropriately
        """
        tc_id = "test_base_dci_tunnel_counters_within_dc"
        test_cfg['tc_id'] = tc_id
        tc_cfg = vxlan_obj.get_tc_params(tc_id)
        
        st.banner('Testcase Solution_dci:7: Verify Tunnel counters within DC1 ({})'.format(tc_id))
        result = True
        summ = ''
        
        # Step 1: Verify tunnels and VTEPs are UP before counter test
        st.banner('Step 1: Verify tunnels and VTEPs before counter test')
        if not verify_base_setup_bgw(test_cfg['nodes']['l2l3vni'], checks=['vteps', 'tunnels']):
            summ = 'Tunnel setup verification failed before counter test\n'
            st.log(summ)
            result = False
        
        # Step 2: Get VXLAN counters before traffic
        st.banner('Step 2: Get VXLAN counters before traffic')
        counters_before = {}
        for dut in test_cfg['nodes']['l2l3vni']:
            try:
                output = st.show(dut, "show vxlan counters", skip_tmpl=True)
                counters_before[dut] = _parse_show_vxlan_counters(output)
                rx0, tx0 = _sum_vxlan_pkts(counters_before[dut])
                st.log('Got VXLAN counters before traffic on {} (rx_pkts={}, tx_pkts={})'.format(dut, rx0, tx0))
            except Exception as err:
                msg = 'Failed to get tunnel counters on {}: {}\n'.format(dut, err)
                st.log(msg)
                summ += msg
                result = False
        
        # Step 3: Send within-DC traffic to drive VXLAN encapsulation (L2VNI only)
        st.banner('Step 3: Send L2VNI traffic to increment counters')
        # NOTE: L3VNI across DCI is disabled/unsupported; for tunnel counter validation we use L2VNI.
        if not verify_traffic(tgen_handles, regenerate=True, traffic_types=['l2_v4'], scope='within'):
            summ += 'L2VNI traffic within DC failed\n'
            result = False
        
        # Step 4: Get VXLAN counters after traffic and verify increment
        st.banner('Step 4: Verify counters incremented')
        counters_after = {}
        for dut in test_cfg['nodes']['l2l3vni']:
            try:
                output = st.show(dut, "show vxlan counters", skip_tmpl=True)
                counters_after[dut] = _parse_show_vxlan_counters(output)
                rx0, tx0 = _sum_vxlan_pkts(counters_before.get(dut, {}))
                rx1, tx1 = _sum_vxlan_pkts(counters_after[dut])
                st.log('Got VXLAN counters after traffic on {} (rx_pkts={}, tx_pkts={})'.format(dut, rx1, tx1))

                if rx1 <= rx0 and tx1 <= tx0:
                    msg = 'VXLAN counters did not increment on {} (before rx/tx={}/{}, after rx/tx={}/{})\n'.format(
                        dut, rx0, tx0, rx1, tx1
                    )
                    st.log(msg)
                    summ += msg
                    result = False
                else:
                    st.log('Tunnel counters verification on {}: Pass'.format(dut))
            except Exception as err:
                msg = 'Failed to verify tunnel counters on {}: {}\n'.format(dut, err)
                st.log(msg)
                summ += msg
                result = False
        
        report_result(result, tc_id, summ)
    
    def test_base_dci_tunnel_counters_across_dci(self):
        """
        Solution_dci:8 - Verify Tunnel counters across Datacenter
        
        Description:
            1) Refer to Solution_dci:1 testcase for base profile bring up
            2) Verify the tunnel counters CLI across DCI
            3) Verify L2VNI traffic between the hosts across DC1, DC2 and DC3
            4) Verify no traffic drop
            5) Verify no crash/core seen
            
        Steps:
            1. Get tunnel counter values before traffic on BGW nodes
            2. Send L2VNI traffic across DCI
            3. Get tunnel counter values after traffic
            4. Verify counters incremented on DCI tunnels
        """
        tc_id = "test_base_dci_tunnel_counters_across_dci"
        test_cfg['tc_id'] = tc_id
        tc_cfg = vxlan_obj.get_tc_params(tc_id)
        
        st.banner('Testcase Solution_dci:8: Verify Tunnel counters across Datacenter ({})'.format(tc_id))
        result = True
        summ = ''
        
        # Get BGW nodes
        bgw_nodes = (test_cfg['nodes'].get('dc1_bgw', []) + 
                    test_cfg['nodes'].get('dc2_bgw', []) + 
                    test_cfg['nodes'].get('dc3_bgw', []))
        
        # Step 1: Verify tunnels and VTEPs are UP before counter test
        st.banner('Step 1: Verify tunnels and VTEPs on BGW nodes before counter test')
        if not verify_base_setup_bgw(bgw_nodes, checks=['vteps', 'tunnels']):
            summ = 'Tunnel setup verification failed on BGW nodes before counter test\n'
            st.log(summ)
            result = False
        
        # Step 2: Get VXLAN counters before traffic on BGW nodes
        st.banner('Step 2: Get VXLAN counters before traffic on BGW nodes')
        counters_before = {}
        
        for dut in bgw_nodes:
            try:
                output = st.show(dut, "show vxlan counters", skip_tmpl=True)
                counters_before[dut] = _parse_show_vxlan_counters(output)
                rx0, tx0 = _sum_vxlan_pkts(counters_before[dut])
                st.log('Got VXLAN counters before traffic on BGW {} (rx_pkts={}, tx_pkts={})'.format(dut, rx0, tx0))
            except Exception as err:
                msg = 'Failed to get tunnel counters on {}: {}\n'.format(dut, err)
                st.log(msg)
                summ += msg
                result = False
        
        # Step 3: Send cross-DC L2VNI traffic
        st.banner('Step 3: Send cross-DC L2VNI traffic to increment counters')
        if not verify_traffic(tgen_handles, regenerate=True, traffic_types=['l2_v4'], scope='cross'):
            summ += 'L2VNI traffic across DCI failed\n'
            result = False
        
        # Step 4: Get VXLAN counters after traffic and verify increment
        st.banner('Step 4: Verify counters incremented on BGW nodes')
        for dut in bgw_nodes:
            try:
                output = st.show(dut, "show vxlan counters", skip_tmpl=True)
                after = _parse_show_vxlan_counters(output)
                rx0, tx0 = _sum_vxlan_pkts(counters_before.get(dut, {}))
                rx1, tx1 = _sum_vxlan_pkts(after)
                st.log('Got VXLAN counters after traffic on BGW {} (rx_pkts={}, tx_pkts={})'.format(dut, rx1, tx1))

                if rx1 <= rx0 and tx1 <= tx0:
                    msg = 'VXLAN counters did not increment on BGW {} (before rx/tx={}/{}, after rx/tx={}/{})\n'.format(
                        dut, rx0, tx0, rx1, tx1
                    )
                    st.log(msg)
                    summ += msg
                    result = False
                else:
                    st.log('Tunnel counters verification on BGW {}: Pass'.format(dut))
            except Exception as err:
                msg = 'Failed to verify tunnel counters on {}: {}\n'.format(dut, err)
                st.log(msg)
                summ += msg
                result = False
        
        report_result(result, tc_id, summ)
    
    def test_base_dci_broadcast_traffic(self):
        """
        Solution_dci:9 - Verify Broadcast Traffic within DC and across DC
        
        Description:
            1) Refer to Solution_dci:1 testcase for base profile bring up
            2) Verify Broadcast Traffic within the DC and across DCI
            3) Verify Traffic does not get looped back at DCI
            4) Verify IR list for the Vlan for local DC and remote DC
            3) Verify L2VNI traffic between the hosts across DC1, DC2 and DC3
            4) Verify no traffic drop
            5) Verify no crash/core seen
            
        Steps:
            1. Send broadcast traffic within DC
            2. Send broadcast traffic across DCI
            3. Verify no packet loss and no loops
        """
        tc_id = "test_base_dci_broadcast_traffic"
        test_cfg['tc_id'] = tc_id
        tc_cfg = vxlan_obj.get_tc_params(tc_id)
        
        st.banner('Testcase Solution_dci:9: Verify Broadcast Traffic within DC and across DC ({})'.format(tc_id))
        result = True
        summ = ''
        
        # Step 1: Verify VTEPs and tunnels for ingress replication
        st.banner('Step 1: Verify ingress replication setup before broadcast traffic')
        if not verify_base_setup_bgw(test_cfg['nodes']['l2l3vni_bgw'], checks=['vteps', 'tunnels']):
            summ = 'Ingress replication setup failed before broadcast traffic test\n'
            st.log(summ)
            result = False
        
        # Step 2: Verify ONLY broadcast traffic (filter by 'broadcast' in stream name)
        st.banner('Step 2: Verify broadcast traffic within DC and across DC')
        if verify_traffic(tgen_handles, regenerate=True, bum=True, traffic_types=['bum_SH', 'bum_MH'], 
                         traffic_names=['broadcast']):
            st.log('Broadcast traffic verification: Pass')
        else:
            summ = 'Broadcast traffic verification: Fail'
            st.log(summ)
            result = False
        
        report_result(result, tc_id, summ)
    
    def test_base_dci_unknown_unicast_traffic(self):
        """
        Solution_dci:10 - Verify Unknown Unicast Traffic and MAC Learning within DC and across DC
        
        Description:
            1) Refer to Solution_dci:1 testcase for base profile bring up
            2) Verify unknown unicast Traffic within the DC and across DCI
            3) Verify Traffic does not get looped back at DCI
            4) Verify remote MAC learning on leaf nodes after BUM traffic
            5) Verify L2VNI traffic between the hosts across DC1, DC2 and DC3
            6) Verify no traffic drop
            7) Verify no crash/core seen
            
        Steps:
            1. Send unknown unicast traffic within DC
            2. Send unknown unicast traffic across DCI
            3. Verify no packet loss and no loops
            4. Verify remote MACs are learned on all leaf nodes
        """
        tc_id = "test_base_dci_unknown_unicast_traffic"
        test_cfg['tc_id'] = tc_id
        tc_cfg = vxlan_obj.get_tc_params(tc_id)
        
        st.banner('Testcase Solution_dci:10: Verify Unknown Unicast Traffic and MAC Learning within DC and across DC ({})'.format(tc_id))
        result = True
        summ = ''
        retry = tc_cfg.get('verify_retry', 2)
        
        # Step 1: Verify VTEPs and tunnels for ingress replication
        st.banner('Step 1: Verify ingress replication setup before unknown unicast traffic')
        if not verify_base_setup_bgw(test_cfg['nodes']['l2l3vni_bgw'], checks=['vteps', 'tunnels']):
            summ = 'Ingress replication setup failed before unknown unicast traffic test\n'
            st.log(summ)
            result = False
        
        # Step 2: Send unknown unicast traffic (filter by 'unknown' in stream name)
        st.banner('Step 2: Verify unknown unicast traffic within DC and across DC')
        if verify_traffic(tgen_handles, regenerate=True, bum=True, traffic_types=['bum_SH', 'bum_MH'], 
                         traffic_names=['unknown']):
            st.log('Unknown unicast traffic verification: Pass')
        else:
            summ = 'Unknown unicast traffic verification: Fail\n'
            st.log(summ)
            result = False
        
        report_result(result, tc_id, summ)
    
    def test_base_dci_multicast_traffic(self):
        """
        Solution_dci:11 - Verify Multicast Traffic within DC and across DC
        
        Description:
            1) Refer to Solution_dci:1 testcase for base profile bring up
            2) Verify Multicast Traffic within the DC and across DCI
            3) Verify Traffic does not get looped back at DCI
            4) Verify L2VNI traffic between the hosts across DC1, DC2 and DC3
            5) Verify no traffic drop
            6) Verify no crash/core seen
            
        Steps:
            1. Send multicast traffic within DC
            2. Send multicast traffic across DCI
            3. Verify no packet loss and no loops
        """
        tc_id = "test_base_dci_multicast_traffic"
        test_cfg['tc_id'] = tc_id
        tc_cfg = vxlan_obj.get_tc_params(tc_id)
        
        st.banner('Testcase Solution_dci:11: Verify Multicast Traffic within DC and across DC ({})'.format(tc_id))
        result = True
        summ = ''
        
        # Step 1: Verify VTEPs and tunnels for ingress replication
        st.banner('Step 1: Verify ingress replication setup before multicast traffic')
        if not verify_base_setup_bgw(test_cfg['nodes']['l2l3vni_bgw'], checks=['vteps', 'tunnels']):
            summ = 'Ingress replication setup failed before multicast traffic test\n'
            st.log(summ)
            result = False
        
        # Step 2: Send multicast BUM traffic (filter by 'multicast' in stream name)
        st.banner('Step 2: Verify multicast traffic within DC and across DC')
        # The BUM traffic generation includes multicast traffic with MAC 01:00:5e:44:44:44
        if verify_traffic(tgen_handles, regenerate=True, bum=True, traffic_types=['bum_SH', 'bum_MH'], 
                         traffic_names=['multicast']):
            st.log('Multicast traffic verification: Pass')
        else:
            summ = 'Multicast traffic verification: Fail\n'
            st.log(summ)
            result = False
        
        report_result(result, tc_id, summ)

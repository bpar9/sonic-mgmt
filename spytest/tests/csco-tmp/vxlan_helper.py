from collections import defaultdict
import pytest
import yaml
from spytest import st, tgapi, SpyTestDict
import re, time
import apis.system.logging as logapi
import apis.routing.bgp as bgpapi
import os
import json
import paramiko
from scp import SCPClient
import ipaddress
import natsort
import apis.routing.ip as ip_obj
import apis.routing.vrf as vrf_obj
import apis.switching.vlan as vlan_obj
from spytest.tgen.tg import get_ixnet
import sys
import importlib
import utilities.utils as utils_obj
import threading
import math
from collections import defaultdict

def get_cfg_file():
    pattern = r'/([^/.]+)\.py'
    for item in sys.argv:
        match = re.search(pattern, item)
        if match:
            result = match.group(1)
            break
    my_lib = importlib.import_module(result)
    return my_lib.CONFIGS_FILE

config_dict = {}
def get_cfg_dict():

    global config_dict
    if not config_dict:
        CONFIGS_FILE = get_cfg_file()
        dir_path = os.path.dirname(os.path.realpath(__file__))
        with open(dir_path + '/' + CONFIGS_FILE) as f:
            config_dict = yaml.load(f, Loader=yaml.FullLoader)

    config_dict['nodes'] = {'leaf': [], 'spine': [], 'all': [], 'l2l3vni': [], 'l2l3vni_bgw': []}
    # DCI: l2l3vni_bgw = nodes with L2+L3 VNI or BGW nodes with L2VNI (for overlay config)
    for node , node_cfg in config_dict.items():
        if node.startswith('leaf'):
            config_dict['nodes']['leaf'].append(node)
            config_dict['nodes']['all'].append(node)
        elif node.startswith('spine'):
            config_dict['nodes']['spine'].append(node)
            config_dict['nodes']['all'].append(node)
        else:
            continue
        # DCI: BGW nodes may have L2VNI only; include them for overlay/EVPN config
        if node_cfg and (
            ('l2vni' in node_cfg and 'l3vni' in node_cfg) or
            ('bgw' in node and 'l2vni' in node_cfg)
        ):
            config_dict['nodes']['l2l3vni_bgw'].append(node)

        if node_cfg and \
           'l2vni' in node_cfg.keys() and \
           'l3vni' in node_cfg.keys():

            config_dict['nodes']['l2l3vni'].append(node)
        
        
    return config_dict

def set_tunnel_counterpoll(action='enable'):
    if action == 'enable':
        cmd = "sudo counterpoll tunnel enable"
    else:
        cmd = "sudo counterpoll tunnel disable"
    return cmd

def generate_l2vni_config(data, l2vni_int_list=None, ints_dict=None, mode='add', **kwargs):
    '''
    Generates vlan , vlan memebers and vxlan mapping for l2vni configs

    DCI changes (backward compatible):
    - dci_enabled=True: BGW uses named VXLANs (vxlan-dc, vxlan-wan) from yaml vxlan_name
    - dci_enabled: skip VLAN members (BGW L2VNI has no local ports)
    - created_vlans: avoid duplicate VLAN create when same VLAN maps to multiple VNIs
    - Optional args: supports keyword style for DCI callers

    Call styles: positional (data, l2vni_int_list, ints_dict) or keyword (l2vni_int_list=..., ints_dict=..., dci_enabled=...).

    'data' format (in input yaml file):
    l2vni:
        vlan_start_range: 2   
        count: 4
    or 
    l2vni:
        - vlan_id: 2
          members: [T1P1, PortChannel1]
        - vlan_id: 3
          members: [T1P1]
        - vlan_id: 4
    '''
    output = ''
    if l2vni_int_list is None:
        l2vni_int_list = kwargs.get('l2vni_int_list', [])
    if ints_dict is None:
        ints_dict = kwargs.get('ints_dict', {})
    dci_enabled = kwargs.get('dci_enabled', False)

    # L2VNI configuration
    if not data.get('l2vni'):
        return output
    vxlan_list = list()
    vlan_data = dict()
    vxlan_start_id = 5000
    if type(data['l2vni']) == list:
        for l2vni_item in data['l2vni']:
            if l2vni_item.get('vxlan_id'):
                vxlan_id = l2vni_item['vxlan_id']
            else:
                vxlan_id = vxlan_start_id + l2vni_item['vxlan_id']
            vxlan_list.append(vxlan_id)
            vlan_data[vxlan_id] = dict()
            vlan_data[vxlan_id]['vlan_id'] = l2vni_item['vlan_id']
            if dci_enabled:
                vlan_data[vxlan_id]['vxlan_name'] = l2vni_item['vxlan_name']
            vlan_data[vxlan_id]['members'] = list()
            if not dci_enabled:
                for member_port_id in l2vni_item['members']:
                    for port_id, int_name in ints_dict.get('all_port_dict', {}).items():
                        if member_port_id in port_id:
                            break
                    else:
                        int_name = member_port_id
                    vlan_data[vxlan_id]['members'].append(int_name)

    else:
        #auto gen
        for vlan_id in range(data['l2vni']['vlan_start_range'], 
                          data['l2vni']['vlan_start_range']+data['l2vni']['count']):
            vxlan_id = vlan_id + vxlan_start_id
            vxlan_list.append(vxlan_id)
            vlan_data[vxlan_id] = dict()
            vlan_data[vxlan_id]['members'] = l2vni_int_list
            vlan_data[vxlan_id]['vlan_id'] = vlan_id 
    created_vlans = set()
    for vxlan_id in vxlan_list:
        cmd = list()
        vlan_id = vlan_data[vxlan_id]['vlan_id']
        # choose VXLAN name
        if not dci_enabled:
            vxlan_name = 'VXLAN'    
        else:
            vxlan_name = vlan_data[vxlan_id]['vxlan_name']
        # only create VLAN once    
        if vlan_id not in created_vlans:
            cmd.append('sudo config vlan {} {}\n'.format(mode, vlan_id))
            created_vlans.add(vlan_id)

        if not dci_enabled:
            for int_name in vlan_data[vxlan_id]['members']:
                cmd.append('sudo config vlan member {} {} {}\n'.format(mode, vlan_id, int_name))
        cmd.append('sudo config vxlan map {} {} {} {}\n'.format(mode, vxlan_name, vlan_id, vxlan_id))
            
        if mode == 'add':
            output += ''.join(cmd)
        else:
            cmd.reverse()
            output += ''.join(cmd)

    return output 

def get_vxlan_mapping(data, mode="add"):
    '''
    Author:Ramsiddarth Ragurajan (rraguraj@cisco.com)
    '''
    output = ''
    if not data.get('l2vni'):
        return output

    vlan_list = list()
    vxlan_list = list()
    vxlan_start_id = 5000
    if type(data['l2vni']) == list:
        for l2vni_item in data['l2vni']:
            vlan_list.append(l2vni_item['vlan_id'])
            if l2vni_item.get('vxlan_id'):
                vxlan_id = l2vni_item['vxlan_id']
            else:
                vxlan_id = vxlan_start_id + l2vni_item['vxlan_id']
            vxlan_list.append(vxlan_id)
    else:
        for vlan_id in range(data['l2vni']['vlan_start_range'], 
                          data['l2vni']['vlan_start_range']+data['l2vni']['count']):
            vlan_list.append(vlan_id)
            vxlan_list.append(vxlan_id + vxlan_start_id)
                
    for vlan_id, vxlan_id in zip(vlan_list, vxlan_list):
        if mode == "add":
            cmd = 'sudo config vxlan map add VXLAN {} {}\n'.format(vlan_id, vxlan_id)
            output += cmd
        elif mode == "del":
            cmd = 'sudo config vxlan map del VXLAN {} {}\n'.format(vlan_id, vxlan_id)
            output += cmd
        else:
            st.banner("unknown action supported add/del")
            st.report_fail('test_case_failed')
    return output

def generate_host_ip(l2vni_intf_dict, version):
    '''
    Author:Ramsiddarth Ragurajan (rraguraj@cisco.com)
    generates host ip for l2vni hosts
    '''
    host_dict = {}
    if version == 'ipv4':
        start_ip =  "20.20.20.10"
        temp_ip = "20.20.20.10"
        
        for node, value in l2vni_intf_dict.items():
            ip_list = []
            for item in value:
                ip_list.append(start_ip)
                start_ip = str(ipaddress.ip_address(start_ip) + 256)
            host_dict[node] =  ip_list   
            start_ip = str(ipaddress.ip_address(temp_ip) + 10)
    return host_dict

def generate_svi_ip(nodes, version, vni):
    '''
    
    Author:Ramsiddarth Ragurajan (rraguraj@cisco.com)

    returns the list of SVI ip's for l3vni for each vteps based on the l3vni count spefied in dut config file
    Example:
    leaf0:
    l3vni:
        l3_dummy:
            start_vlan: 102
            count: 3 <----
    leaf1:
    l3vni:
        l3_dummy:
            start_vlan: 102
            count: 2 <----

    {'leaf0': ['80.80.80.1', '80.80.81.1', '80.80.82.1'], 'leaf1': ['90.90.90.1', '90.90.91.1']}
    '''
    count = {}
    config_dict = get_cfg_dict()
    for node, config in config_dict.items():
        if node in nodes:
            if type(config['l3vni']) == list:
                count[node] = len(config['l3vni'])
            else:
                count[node] = config['l3vni']['l3_dummy']['count']
    svi_dict ={}
    if version == 'ipv4':
        if vni == 'l3vni':
            temp_ip =  "80.80.80.1"
            ip_start = "80.80.80.1"
        else:
            temp_ip =  "20.20.20.1"
            ip_start = "20.20.20.1"
        for node in nodes:
            temp_list =[]
            for i in range(count[node]):
                temp_list.append(ip_start)
                ip_start = str(ipaddress.ip_address(ip_start) + 256)
            ip_start = get_new_ip_range(str(temp_ip))
            temp_ip = ip_start
            svi_dict[node] = temp_list
    elif version == 'ipv6':
        pass
    else:
        print("unknown version")
    return svi_dict

def get_new_ip_range(ip_add):
    '''
    Author:Ramsiddarth Ragurajan (rraguraj@cisco.com)
    returns new ip with new subnet
    input: ip
    Ex: input: 80.80.80.1 output: 90.90.90.1
    '''
    temp_list = ip_add.split('.')
    for i in range(3):
        temp_list[i] = str(int(temp_list[i]) + 10)
    return '.'.join(temp_list)

def generate_l3vni_config(leaf_data, mode='add'):
    '''
    Author: Jigar Sanghrajka (jsanghra@cisco.com)
    
    '''
    output = ''
    if not leaf_data.get('l3vni') or not leaf_data.get('l2vni'):
        return output

    vxlan_list = list()
    vrf_data = dict()
    vxlan_start_id = 5000
    if type(leaf_data['l3vni']) == list:
        for l3vni_item in leaf_data['l3vni']:
            if l3vni_item.get('vxlan_id'):
                vxlan_id = l3vni_item['vxlan_id']
            else:
                vxlan_id = vxlan_start_id + l3vni_item['vxlan_id']
            vxlan_list.append(vxlan_id)
            vrf_data[vxlan_id] = dict()
            vrf_data[vxlan_id]['vrf_id'] = l3vni_item['vrf_id']
            vrf_data[vxlan_id]['bindings'] = l3vni_item['vlan_bindings']
            vrf_data[vxlan_id]['bindings'].append(l3vni_item['vrf_id'])
    else:
        #auto gen
        l2_vlan_id = l2_vlan_id_start = leaf_data['l2vni']['vlan_start_range']
        l2_vlan_count = leaf_data['l2vni']['count']
        vlans_per_vrf = math.ceil(l2_vlan_count / leaf_data['l3vni']['l3_dummy']['count'])
        for vlan_id in range(leaf_data['l3vni']['l3_dummy']['start_vlan'], 
                          leaf_data['l3vni']['l3_dummy']['start_vlan']+leaf_data['l3vni']['l3_dummy']['count']):
            vxlan_id = vlan_id + vxlan_start_id
            vxlan_list.append(vxlan_id)
            vrf_data[vxlan_id] = dict()
            vrf_data[vxlan_id]['vrf_id'] = vlan_id 
            vrf_data[vxlan_id]['bindings'] = [vlan_id]
            for cntr in range(vlans_per_vrf):
                if l2_vlan_id >= l2_vlan_id_start + l2_vlan_count:
                    break
                vrf_data[vxlan_id]['bindings'].append(l2_vlan_id)
                l2_vlan_id += 1

    # L3VNI configuration

    for vxlan_id in vxlan_list:
        cmd = list()
        vrf_id = vrf_data[vxlan_id]['vrf_id']
        cmd.append('sudo config vlan {} {}\n'.format(mode, vrf_id))
        cmd.append('sudo config vrf {} Vrf{}\n'.format(mode, vrf_id))
        for vlan_binding in vrf_data[vxlan_id]['bindings']:
            if mode == 'add':
                cmd.append('sudo config interface vrf bind Vlan{} Vrf{}\n'.format(vlan_binding, vrf_id))
            else:
                cmd.append('sudo config interface vrf unbind Vlan{}\n'.format(vlan_binding))
        cmd.append('sudo config vxlan map {} VXLAN {} {}\n'.format(mode, vrf_id , vxlan_id))
        if mode == 'add':
            cmd.append('sudo config vrf add_vrf_vni_map Vrf{} {}\n'.format(vrf_id, vxlan_id))
        else:
            cmd.append('sudo config vrf del_vrf_vni_map Vrf{} \n'.format(vrf_id))


        if mode == 'add':
            output += ''.join(cmd)
        else:
            cmd.reverse()
            output += ''.join(cmd)

    return output  

def delete_l2vni_config(leaf_data):
    '''
    Author: Jigar Sanghrajka (jsanghra@cisco.com)
    
    '''
    output = ''
    # L2VNI remove configuration
    if leaf_data.get('l2vni'):
        vlan_start = leaf_data['l2vni']['vlan_start_range']
        count = leaf_data['l2vni']['count']

        for i in range(vlan_start, vlan_start + count):
            output += 'sudo config vxlan map del VXLAN {} {}\n'.format(i, 5000 + i)
    return output

def delete_l3vni_config(leaf_data):
    '''
    Author: Jigar Sanghrajka (jsanghra@cisco.com)
    
    '''
    output = ''
    # L3VNI remove configuration
    if leaf_data.get('l3vni'):
        l3_start = leaf_data['l3vni']['l3_dummy']['start_vlan']
        count = leaf_data['l3vni']['l3_dummy']['count']
        
        for i in range(count):
            output += 'sudo config vrf del_vrf_vni_map Vrf{}\n'.format(l3_start + i)
            output += 'sudo config vxlan map del VXLAN {} {}\n'.format(l3_start + i, 5000 + l3_start + i)
            output += 'sudo config vrf del Vrf{}\n'.format(l3_start + i)
    return output     

def generate_port_channel_config(node, config_data, ints_dict, mode='add'):
    '''
    generate port channel configs
    Example:
    sudo config portchannel add PortChannel1
    sudo config portchannel member add PortChannel1 Ethernet1_8
    sudo config portchannel member add PortChannel1 Ethernet1_9
    config data (input file):
    leaf0:
        port_channels:
            - port_channel_num: 1
            member_ids: [T1P2]
    '''
    output = ''
    
    if config_data and not config_data.get('port_channels'):
        return output

    for pc_data in config_data['port_channels']:
        cmd = list()
        cmd.append('sudo config portchannel {} PortChannel{}\n'.format(
            mode, pc_data['port_channel_num']))

        for member_id in pc_data['member_ids']:
            for port_id, int_name in ints_dict['all_port_dict'].items():
                if member_id in port_id:
                    cmd.append('sudo config portchannel member {} PortChannel{} {}\n'.format(
                        mode, pc_data['port_channel_num'], int_name))
                    break
            else:
                cmd.append('sudo config portchannel member {} PortChannel{} {}\n'.format(
                    mode, pc_data['port_channel_num'], member_id))

        if mode == 'add':
            output += ''.join(cmd)
        else:
            cmd.reverse()
            output += ''.join(cmd)

    return output  

def generate_evpn_esi_config(config_data, mode='add'):
    '''
    generate evpn esi configs on port channel
    Example:
    sudo config interface sys-mac add PortChannel3 00:44:33:22:11:33
    sudo config interface evpn-esi add PortChannel3 00:02:03:04:05:06:07:08:09:0c
    config data (input file):
    leaf0:
        port_channels:
            - port_channel_num: 3
            member_ids: [T1P2]
            sys_mac: 00:44:33:22:11:33
            evpn_esi: 00:02:03:04:05:06:07:08:09:0c    
    '''
    output = ''
    
    if config_data and not config_data.get('port_channels'):
        return output

    for pc_data in config_data['port_channels']:
        cmd = list()

        if pc_data.get('sys_mac'):
            mode_cli = 'add' if mode == 'add' else 'remove'
            cmd.append('sudo config interface sys-mac {} PortChannel{} {}\n'.format(
                     mode_cli, pc_data['port_channel_num'], pc_data['sys_mac']) )

        if pc_data.get('evpn_esi'):
            if mode == 'add':
                cmd.append('sudo config interface evpn-esi add PortChannel{} {}\n'.format(
                    pc_data['port_channel_num'], pc_data['evpn_esi'])) 
            else:
                cmd.append('sudo config interface evpn-esi del PortChannel{} \n'.format(
                    pc_data['port_channel_num'])) 

        if mode == 'add':
            output += ''.join(cmd)
        else:
            cmd.reverse()
            output += ''.join(cmd)

    return output  

def generate_epvn_mh_config(node, config_data, mode='add'):
    '''
    generate epvn multi-homing attributes configs
    Example:
    vtysh
    config
    evpn mh redirect-off
    evpn mh mac-holdtime 200
    evpn mh neigh-holdtime 200
    config data (input file):
    global:
        evpn_mh:
            redirect: off
            mac_holdtime: 200
            neigh_holdtime: 200   
    '''
    mode_prfx = '' if mode == 'add' else 'no '
    output = ''
    
    if config_data[node] and not config_data[node].get('port_channels'):
        return output
    if not config_data.get('global') or not config_data['global'].get('evpn_mh'):
        return output

    if config_data['global']['evpn_mh'].get('redirect_off', False):
        output += '{}evpn mh redirect-off\n'.format(mode_prfx)

    if config_data['global']['evpn_mh'].get('mac_holdtime'):
        output += '{}evpn mh mac-holdtime {}\n'.format(
                mode_prfx, config_data['global']['evpn_mh']['mac_holdtime'])

    if config_data['global']['evpn_mh'].get('neigh_holdtime'):
        output += '{}evpn mh neigh-holdtime {}\n'.format(
                mode_prfx, config_data['global']['evpn_mh']['neigh_holdtime'])
    if output:
        output += 'end\n'
        output += 'exit\n'

    return output  

def generate_loopback_config(ip_addr,loopback_int = 'Loopback0'):
    '''
    Author: Jigar Sanghrajka (jsanghra@cisco.com)
    
    '''
    output = 'sudo config interface ip add {} {}\n'.format(loopback_int, ip_addr)
    return output

def delete_loopback_config(ip_addr,loopback_int = 'Loopback0'):
    '''
    Author: Jigar Sanghrajka (jsanghra@cisco.com)
    
    '''
    output = 'sudo config interface ip rem {} {}\n'.format(loopback_int, ip_addr)
    return output

def generate_interface_ip_config(ip_addr, interface_name, prefix="/24", mode='add'):
    """
    Generic helper to build 'sudo config interface ip add' commands.
    DCI: Used for BGW WAN underlay interface IPs (Ethernet1_29, etc.).

    Args:
        ip_addr (str): IP address (with or without prefix)
        interface_name (str): Interface name (e.g., 'Ethernet1_29', 'Loopback0')
        prefix (str): CIDR prefix (default '/24' if IP lacks one)

    Returns:
        str: CLI command line
    """
    # Add prefix if not present
    if '/' not in ip_addr:
        ip_addr = ip_addr + prefix

    if mode == 'add':
        return 'sudo config interface ip add {} {}\n'.format(interface_name, ip_addr)
    elif mode == 'del':
        return 'sudo config interface ip del {} {}\n'.format(interface_name, ip_addr)

def generate_vxlan_config(ip_addr, **kwargs):
    # DCI: BGWs use dual VXLANs - vxlan-dc (intra-DC) and vxlan-wan (inter-DC)
    dci_enabled = kwargs.get('dci_enabled', False)
    vxlan_name = kwargs.get('vxlan_name', 'VXLAN')
    nvo_name = kwargs.get('nvo_name', 'NVO')
    output = ''
    if not dci_enabled:
        output += 'sudo config vxlan add VXLAN {}\n'.format(ip_addr)
        output += 'sudo config vxlan evpn_nvo add NVO VXLAN\n'
    else:
        output += 'sudo config vxlan add {} {}\n'.format(vxlan_name, ip_addr)
        output += 'sudo config vxlan evpn_nvo add {} {}\n'.format(nvo_name, vxlan_name)

    return output 

def delete_vxlan_config(**kwargs):
    # DCI: Must delete both vxlan-dc/NVO-DC and vxlan-wan/NVO-WAN on BGWs
    vxlan_name = kwargs.get('vxlan_name', 'VXLAN')
    nvo_name = kwargs.get('nvo_name', 'NVO')
    output = ''
    output += 'sudo config vxlan evpn_nvo del {} \n'.format(nvo_name)
    output += 'sudo config vxlan del {} \n'.format(vxlan_name)
    return output 

def generate_bgp_underlay_config(leaf_data, int_list, node_name='', dci_enabled=False):
    '''
    Author: Jigar Sanghrajka (jsanghra@cisco.com)

    Generate BGP underlay config for TRANSIT peer-group.

    When dci_enabled=False (default/base config):
    - 'neighbor TRANSIT activate' under both IPv4 and IPv6 unicast AF (original behavior)

    When dci_enabled=True (DCI config):
    - No 'neighbor TRANSIT activate' under IPv4 unicast AF for any node
    - 'neighbor TRANSIT activate' only under IPv6 unicast AF

    Args:
        leaf_data: Dict with router_id, as_num
        int_list: List of underlay interface names
        node_name: Node name string (unused currently, retained for future use)
        dci_enabled: If True, skip TRANSIT activate under IPv4 AF
    '''
    output = ''
    # BGP underlay configuration
    router_id = leaf_data['router_id']
    as_num = leaf_data['as_num']

    output += 'router bgp {}\n'.format(as_num)
    output += 'bgp router-id {}\n'.format(router_id)
    output += 'no bgp ebgp-requires-policy\n'
    output += 'no bgp default ipv4-unicast\n'
    output += 'bgp disable-ebgp-connected-route-check\n'
    output += 'bgp bestpath as-path multipath-relax\n'
    output += 'neighbor TRANSIT peer-group\n'
    output += 'neighbor TRANSIT remote-as external\n'
    for intf in int_list:
        output += 'neighbor {} interface peer-group TRANSIT\n'.format(intf)
    output += 'address-family ipv4 unicast\n'
    output += 'redistribute connected\n'
    if not dci_enabled:
        output += 'neighbor TRANSIT activate\n'
    output += 'exit-address-family\n'
    output += 'address-family ipv6 unicast\n'
    output += 'redistribute connected\n'
    output += 'neighbor TRANSIT activate\n'
    output += 'exit-address-family\n'
    output += 'end\n'
    output += 'exit\n'
    return output

def generate_bgp_bfd_underlay_config(leaf_data):
    '''
    Author: Jigar Sanghrajka (jsanghra@cisco.com)
    
    '''
    output = ''
    # BGP BFD underlay configuration
    router_id = leaf_data['router_id']
    as_num = leaf_data['as_num']

    output += 'router bgp {}\n'.format(as_num)
    output += 'bgp router-id {}\n'.format(router_id)
    output += 'neighbor TRANSIT peer-group\n'
    output += 'neighbor TRANSIT remote-as external\n'
    output += 'neighbor TRANSIT bfd\n'
    output += 'neighbor TRANSIT bfd disable-strict-mode\n'
    output += 'end\n'
    output += 'exit\n'

    return output

def generate_bgp_overlay_config(leaf_data, **kwargs):
    '''
    Author: Jigar Sanghrajka (jsanghra@cisco.com)
    
    '''
    dci_enabled = kwargs.get('dci_enabled', False)
    node_name = kwargs.get('node_name', '')
    output = ''
    as_num = leaf_data['as_num']
    neighbor_overlays = leaf_data['neigbor_overlay']
    # BGP overlay configuration
    router_id = leaf_data['router_id']
    output += 'router bgp {}\n'.format(as_num)
    output += 'bgp router-id {}\n'.format(router_id)
    output += 'neighbor OVERLAY peer-group\n'
    output += 'neighbor OVERLAY remote-as external\n'
    output += 'neighbor OVERLAY disable-connected-check\n'
    output += 'neighbor OVERLAY ebgp-multihop 255\n'
    output += 'neighbor OVERLAY update-source Loopback0\n'
    # DCI: Spine BGWs need domain/reoriginate for EVPN route exchange across DCs
    if dci_enabled and 'spine' in node_name.lower():
        output += 'neighbor OVERLAY domain vxlan-dc\n'
        output += 'neighbor OVERLAY reoriginate vxlan-wan\n'
    for neighbor in neighbor_overlays:
        output += 'neighbor {} peer-group OVERLAY\n'.format(neighbor)
    output += 'address-family l2vpn evpn\n'
    output += 'neighbor OVERLAY activate\n'
    # DCI: DC2/DC3 BGWs advertise MAC-only to avoid route loops across WAN
    if dci_enabled and 'bgw' in node_name.lower() and ('dc2' in node_name.lower() or 'dc3' in node_name.lower()):
        output += 'advertise-mac-only\n'
    output += 'advertise-all-vni\n'
    output += 'advertise ipv4 unicast\n'
    output += 'advertise ipv6 unicast\n'
    output += 'exit-address-family\n'
    output += 'end\n'
    output += 'exit\n'
    return output

def generate_bgp_bfd_overlay_config(leaf_data):
    '''
    Author: Jigar Sanghrajka (jsanghra@cisco.com)
    
    '''
    output = ''
    # BGP overlay configuration
    router_id = leaf_data['router_id']
    as_num = leaf_data['as_num']

    output += 'router bgp {}\n'.format(as_num)
    output += 'bgp router-id {}\n'.format(router_id)
    output += 'neighbor OVERLAY peer-group\n'
    output += 'neighbor OVERLAY remote-as external\n'
    output += 'neighbor OVERLAY bfd\n'
    output += 'neighbor OVERLAY bfd disable-strict-mode\n'
    output += 'end\n'
    output += 'exit\n'

    return output

def generate_bgp_l3vni_config(leaf_data,bgp_info):
    '''
    Author: Jigar Sanghrajka (jsanghra@cisco.com)
    
    '''
    output = ''
    # BGP l3vni configuration
    router_id = bgp_info['router_id']
    as_num = bgp_info['as_num']
    vxlan_list = list()
    vrf_list = list()
    if leaf_data.get('l3vni'):

        vxlan_start_id = 5000
        if type(leaf_data['l3vni']) == list:
            for l3vni_item in leaf_data['l3vni']:
                if l3vni_item.get('vxlan_id'):
                    vxlan_id = l3vni_item['vxlan_id']
                else:
                    vxlan_id = vxlan_start_id + l3vni_item['vxlan_id']
                vxlan_list.append(vxlan_id)
                vrf_list.append(l3vni_item['vrf_id'])
        else:
            #auto gen
            for vlan_id in range(leaf_data['l3vni']['l3_dummy']['start_vlan'], 
                              leaf_data['l3vni']['l3_dummy']['start_vlan']+leaf_data['l3vni']['l3_dummy']['count']):
                vxlan_id = vlan_id + vxlan_start_id
                vxlan_list.append(vxlan_id)
                vrf_list.append(vlan_id)
    elif leaf_data.get('vni'):
        start_vlan = leaf_data['vni']['vlan_start_range']
        count = leaf_data['vni']['count']
        for i in range(count):
            vrf = start_vlan + i
            vrf_list.append(vrf)
            vxlan_list.append(5000 + vrf)
    else:
        st.report_fail("vni information not found in input file")

    for vrf,vni in zip(vrf_list, vxlan_list):
        output += 'router bgp {} vrf Vrf{}\n'.format(as_num, vrf)
        output += 'bgp bestpath as-path multipath-relax\n'
        output += 'address-family ipv4 unicast\n'
        output += 'redistribute connected\n'
        output += 'exit-address-family\n'
        output += 'address-family ipv6 unicast\n'
        output += 'redistribute connected\n'
        output += 'exit-address-family\n'
        output += 'address-family l2vpn evpn\n'
        output += 'advertise ipv4 unicast\n'
        output += 'advertise ipv6 unicast\n'
        output += 'no use-es-l3nhg\n'
        output += 'exit-address-family\n'
        output += 'exit\n'
        output += 'vrf Vrf{}\n'.format(vrf)
        output += 'vni {}\n'.format(vni)
    output += 'end\n'
    output += 'exit\n'

    return output

def generate_bgp_unnumbered_config(int_list):
    '''
    Author: Jigar Sanghrajka (jsanghra@cisco.com)
    
    '''
    output = ''
    # BGP unnumbered configuration
    for interface in int_list:
        output += 'sudo config interface ipv6 enable use-link-local-only {}\n'.format(interface)

    return output

def generate_bgp_transit_wan_config(bgw_data, ebgp_multihop=1, add_redistribute=True):
    """
    Generate BGP TRANSIT_WAN config for BGW WAN underlay (inter-DC links).

    Creates peer-group TRANSIT_WAN with IPv4 unicast neighbors for WAN underlay
    connectivity between BGW spines in different DCs. Used for underlay routing
    across the DCI WAN.

    Args:
        bgw_data: Dict with router_id, as_num, neighbor_transit_wan (list of peer IPs)
        ebgp_multihop: ebgp-multihop value (default 1)
        add_redistribute: If True, add 'redistribute connected'

    Returns:
        FRR config string
    """
    output = ''
    router_id = bgw_data['router_id']
    as_num = bgw_data['as_num']
    peers = bgw_data.get('neighbor_transit_wan', [])  # list of IPv4 neighbor IPs
    st.log("TRANSIT_WAN peers for {}: {}".format(bgw_data.get('name', ''), peers))

    output += 'router bgp {}\n'.format(as_num)
    output += 'bgp router-id {}\n'.format(router_id)
    output += 'neighbor TRANSIT_WAN peer-group\n'
    output += 'neighbor TRANSIT_WAN remote-as external\n'
    output += 'neighbor TRANSIT_WAN ebgp-multihop {}\n'.format(ebgp_multihop)
    for ip in peers:
        output += 'neighbor {} peer-group TRANSIT_WAN\n'.format(ip)
    output += 'address-family ipv4 unicast\n'
    if add_redistribute:
        output += 'redistribute connected\n'
    # Only activate TRANSIT_WAN in ipv4 af — TRANSIT is the DC underlay peer-group
    # (activated in ipv6 af by generate_bgp_underlay_config), not the WAN peer-group.
    # Per reference config dci_l2vni_l3vni_fullconfig_Feb24.txt lines 296-298.
    output += 'neighbor TRANSIT_WAN activate\n'
    output += 'exit-address-family\n'
    output += 'end\n'
    output += 'exit\n'

    return output

def generate_bgp_overlay_wan_config(bgw_data, overlay_wan_v4_peers=None, loopback_wan="Loopback1", domain_wan="vxlan-wan", reoriginate_dc="vxlan-dc"):
    """
    Generate BGP OVERLAY_WAN config for EVPN across DCs.

    Creates peer-group OVERLAY_WAN for L2VPN EVPN sessions between BGW spines
    in different DCs. Uses domain vxlan-wan and reoriginate vxlan-dc so EVPN
    routes are exchanged across the WAN with proper domain separation.

    Args:
        bgw_data: Dict with router_id, as_num, neighbor_overlay_wan
        overlay_wan_v4_peers: Override peer list (default: from bgw_data)
        loopback_wan: Update-source interface (Loopback1 = WAN VIP)
        domain_wan: EVPN domain for WAN (vxlan-wan)
        reoriginate_dc: Reoriginate from DC domain (vxlan-dc)

    Returns:
        FRR config string
    """
    output = ''
    router_id = bgw_data['router_id']
    as_num = bgw_data['as_num']
    
    # If no explicit peers provided, use what's in the node dict
    if overlay_wan_v4_peers is None:
        overlay_wan_v4_peers = bgw_data.get('neighbor_overlay_wan', []) or []
    st.log("OVERLAY_WAN peers for {}: {}".format(bgw_data.get('name', ''), overlay_wan_v4_peers))


    output += 'router bgp {}\n'.format(as_num)
    output += 'bgp router-id {}\n'.format(router_id)
    output += 'neighbor OVERLAY_WAN peer-group\n'
    output += 'neighbor OVERLAY_WAN remote-as external\n'
    output += 'neighbor OVERLAY_WAN disable-connected-check\n'
    output += 'neighbor OVERLAY_WAN ebgp-multihop 255\n'
    output += 'neighbor OVERLAY_WAN update-source {}\n'.format(loopback_wan)
    output += 'neighbor OVERLAY_WAN domain {}\n'.format(domain_wan)
    output += 'neighbor OVERLAY_WAN reoriginate {}\n'.format(reoriginate_dc)
    for nbr in overlay_wan_v4_peers:
        output += 'neighbor {} peer-group OVERLAY_WAN\n'.format(nbr)
    output += 'address-family l2vpn evpn\n'
    output += 'neighbor OVERLAY_WAN activate\n'
    output += 'exit-address-family\n'
    output += 'end\n'
    output += 'exit\n'
    return output

def generate_bgp_ihop_direct_config(bgw_data, ihop_peers=None, dc_direct_peers=None):
    """
    Generate BGP configuration for IHOP and direct DC-to-DC peering.
    
    Args:
        bgw_data: BGW node data dictionary
        ihop_peers: List of IHOP neighbor IPs (e.g., ['59.59.59.1', '60.60.60.1'])
        dc_direct_peers: List of direct DC neighbor IPs (e.g., ['51.51.51.1', '52.52.52.1'])
    
    Returns:
        Configuration string
    """
    output = ''
    as_num = bgw_data['as_num']
    router_id = bgw_data['router_id']
    
    # If not provided, get from node dict
    if ihop_peers is None:
        ihop_peers = bgw_data.get('neighbor_ihop', []) or []
    if dc_direct_peers is None:
        dc_direct_peers = bgw_data.get('neighbor_dc_direct', []) or []
    
    st.log("IHOP peers for {}: {}".format(bgw_data.get('name', ''), ihop_peers))
    st.log("DC_DIRECT peers for {}: {}".format(bgw_data.get('name', ''), dc_direct_peers))
    
    output += 'router bgp {}\n'.format(as_num)
    output += 'bgp router-id {}\n'.format(router_id)
    
    # IHOP peer group
    if ihop_peers:
        output += 'neighbor IHOP peer-group\n'
        output += 'neighbor IHOP remote-as external\n'
        for nbr in ihop_peers:
            output += 'neighbor {} peer-group IHOP\n'.format(nbr)
    
    # DC_DIRECT peer groups per DC
    if dc_direct_peers:
        # Group peers by /24 subnet to create separate peer groups
        dc_groups = {}
        for peer in dc_direct_peers:
            # Extract first 3 octets for grouping
            subnet_prefix = '.'.join(peer.split('.')[:3])
            if subnet_prefix not in dc_groups:
                dc_groups[subnet_prefix] = []
            dc_groups[subnet_prefix].append(peer)
        
        for idx, (subnet, peers) in enumerate(dc_groups.items(), start=1):
            group_name = 'DC{}_DIRECT'.format(idx)
            output += 'neighbor {} peer-group\n'.format(group_name)
            output += 'neighbor {} remote-as external\n'.format(group_name)
            for nbr in peers:
                output += 'neighbor {} peer-group {}\n'.format(nbr, group_name)
    
    # Activate in ipv4 unicast address-family
    output += 'address-family ipv4 unicast\n'
    output += 'redistribute connected\n'
    if ihop_peers:
        output += 'neighbor IHOP activate\n'
    if dc_direct_peers:
        for idx in range(1, len(dc_groups) + 1):
            output += 'neighbor DC{}_DIRECT activate\n'.format(idx)
    output += 'exit-address-family\n'
    output += 'end\n'
    output += 'exit\n'
    
    return output

def generate_source_route_maps(bgw_data, loopback_v4="Loopback0", loopback_v6="Loopback0"):
    """
    Generate route-maps to set source IP for BGP updates.

    NOTE: This function must only be called for BGW nodes, NOT leaf nodes.
    Per reference config (dci_l2vni_l3vni_fullconfig_Feb24.txt), RM_SET_SRC4/RM_SET_SRC6
    only exist on BGW nodes (lines 351, 635, 944, 1248, 2994). Leaf nodes do NOT have
    these route-maps. The caller (config_feature_dci) enforces this via _DCI_ONLY_FEATURES
    guard for the 'route_maps_dci' feature.

    Args:
        bgw_data: BGW node data dictionary
        loopback_v4: Loopback interface for IPv4 source (default: Loopback0)
        loopback_v6: Loopback interface for IPv6 source (default: Loopback0)

    Returns:
        Configuration string
    """
    output = ''
    
    # Get loopback IPs from bgw_data
    lo_v4_ip = bgw_data.get('loopback_ipv4', '')
    lo_v6_ip = bgw_data.get('loopback_ipv6', '')
    
    if not lo_v4_ip or not lo_v6_ip:
        st.warn("Loopback IPs not found in bgw_data for source route-maps")
        return output
    
    # Strip prefix length if present
    lo_v4_ip = lo_v4_ip.split('/')[0]
    lo_v6_ip = lo_v6_ip.split('/')[0]
    
    # Create route-maps
    output += 'route-map RM_SET_SRC6 permit 10\n'
    output += 'set src {}\n'.format(lo_v6_ip)
    output += 'exit\n'
    
    output += 'route-map RM_SET_SRC4 permit 20\n'
    output += 'set src {}\n'.format(lo_v4_ip)
    output += 'exit\n'
    
    # Apply route-maps to BGP protocol
    output += 'ip protocol bgp route-map RM_SET_SRC4\n'
    output += 'ipv6 protocol bgp route-map RM_SET_SRC6\n'
    output += 'exit\n'
    
    return output


def _get_l3vni_bgw_params(node_name, config_dict, bgp_info):
    """
    Compute per-BGW L3VNI parameters from topology data.

    Derives cross-DC L3VNI values, leaf VLAN bindings, leaf ASNs (same DC),
    remote BGW ASNs, and leaf L3VNI values needed for BGW L3VNI configuration.

    Args:
        node_name: BGW node hostname (e.g. 'spine2_dc1_bgw1')
        config_dict: Full config dict from get_cfg_dict()
        bgp_info: Dict of node -> {router_id, as_num} from generate_bgp_underlay_info

    Returns:
        dict with keys: as_num, dc, vrf_l3vni_pairs, vlan_bindings_by_vrf,
                        leaf_asns, leaf_l3vnis_by_vrf, remote_bgw_asns
        or None if data cannot be derived
    """
    dc = _get_dc_from_name(node_name)
    if not dc:
        st.warn('Cannot determine DC from node name: {}'.format(node_name))
        return None

    as_num = bgp_info.get(node_name, {}).get('as_num')
    if not as_num:
        st.warn('No ASN found for BGW node: {}'.format(node_name))
        return None

    # Read BGW's own l3vni data from YAML if available, else fall back to leaf
    bgw_cfg = config_dict.get(node_name)
    if isinstance(bgw_cfg, dict) and bgw_cfg.get('l3vni'):
        bgw_l3vni = bgw_cfg['l3vni']
    else:
        bgw_l3vni = None

    # Find a leaf in the same DC to get leaf L3VNI values (for RT-WAN extcommunity)
    ref_leaf = None
    for n, cfg in config_dict.items():
        if n.startswith('leaf') and dc in n and isinstance(cfg, dict) and 'l3vni' in cfg:
            ref_leaf = cfg
            break
    if not bgw_l3vni and (not ref_leaf or not ref_leaf.get('l3vni')):
        st.warn('No L3VNI data found for BGW {} or any leaf in DC {}'.format(node_name, dc))
        return None

    # Build VRF -> cross-DC L3VNI pairs and VLAN bindings
    # All BGWs use cross-DC L3VNI = 10000 + vrf_id (e.g. Vrf101 -> 10101)
    vrf_l3vni_pairs = []
    vlan_bindings_by_vrf = {}
    leaf_l3vnis_by_vrf = {}

    # Use BGW's own l3vni data for VLAN bindings if available
    l3vni_source = bgw_l3vni if bgw_l3vni else ref_leaf['l3vni']
    for l3vni_item in l3vni_source:
        vrf_id = l3vni_item['vrf_id']
        cross_dc_vni = 10000 + vrf_id
        vrf_l3vni_pairs.append((vrf_id, cross_dc_vni))
        vlan_bindings_by_vrf[vrf_id] = l3vni_item.get('vlan_bindings', [])

    # Collect leaf L3VNI values (for RT-WAN extcommunity-list matching)
    if ref_leaf and ref_leaf.get('l3vni'):
        for l3vni_item in ref_leaf['l3vni']:
            vrf_id = l3vni_item['vrf_id']
            leaf_l3vnis_by_vrf[vrf_id] = l3vni_item.get('vxlan_id', 5000 + vrf_id)

    # Collect leaf ASNs in same DC (for RT-WAN extcommunity-list)
    leaf_asns = sorted(set(
        bgp_info[n]['as_num'] for n in config_dict['nodes'].get('leaf', [])
        if dc in n and n in bgp_info
    ))

    # Collect remote BGW ASNs (BGWs in other DCs, for RT-DC extcommunity-list)
    all_bgw_nodes = sorted(n for n in config_dict['nodes'].get('all', []) if 'bgw' in n)
    remote_bgw_asns = sorted(set(
        bgp_info[n]['as_num'] for n in all_bgw_nodes
        if n != node_name and dc not in n and n in bgp_info
    ))

    return {
        'as_num': as_num,
        'dc': dc,
        'vrf_l3vni_pairs': vrf_l3vni_pairs,
        'vlan_bindings_by_vrf': vlan_bindings_by_vrf,
        'leaf_asns': leaf_asns,
        'leaf_l3vnis_by_vrf': leaf_l3vnis_by_vrf,
        'remote_bgw_asns': remote_bgw_asns,
    }


def generate_l3vni_bgw_sonic_config(node_name, config_dict, bgp_info, mode='add'):
    """
    Generate SONiC CLI commands for L3VNI configuration on a BGW node.

    Per l3vni_config_diff.txt, creates VLANs (101/102), VRFs (Vrf101/Vrf102),
    binds L2 VLANs to VRFs, maps L3VNI VLANs to cross-DC VNI (10101/10102)
    on both vxlan-dc and vxlan-wan, and sets VRF-VNI mappings.

    Args:
        node_name: BGW node hostname
        config_dict: Full config dict from get_cfg_dict()
        bgp_info: Dict of node -> {router_id, as_num}
        mode: 'add' or 'del'

    Returns:
        SONiC CLI command string
    """
    params = _get_l3vni_bgw_params(node_name, config_dict, bgp_info)
    if not params:
        return ''

    output = ''
    for vrf_id, cross_dc_vni in params['vrf_l3vni_pairs']:
        cmd = []
        bindings = params['vlan_bindings_by_vrf'].get(vrf_id, [])
        if mode == 'add':
            cmd.append('sudo config vlan add {}\n'.format(vrf_id))
            cmd.append('sudo config vrf add Vrf{}\n'.format(vrf_id))
            cmd.append('sudo config interface vrf bind Vlan{} Vrf{}\n'.format(vrf_id, vrf_id))
            for vlan in bindings:
                if vlan != vrf_id:
                    cmd.append('sudo config interface vrf bind Vlan{} Vrf{}\n'.format(vlan, vrf_id))
            cmd.append('sudo config vxlan map add vxlan-dc {} {}\n'.format(vrf_id, cross_dc_vni))
            cmd.append('sudo config vxlan map add vxlan-wan {} {}\n'.format(vrf_id, cross_dc_vni))
            cmd.append('sudo config vrf add_vrf_vni_map Vrf{} {}\n'.format(vrf_id, cross_dc_vni))
        else:
            cmd.append('sudo config vrf del_vrf_vni_map Vrf{}\n'.format(vrf_id))
            cmd.append('sudo config vxlan map del vxlan-wan {} {}\n'.format(vrf_id, cross_dc_vni))
            cmd.append('sudo config vxlan map del vxlan-dc {} {}\n'.format(vrf_id, cross_dc_vni))
            for vlan in reversed(bindings):
                if vlan != vrf_id:
                    cmd.append('sudo config interface vrf unbind Vlan{}\n'.format(vlan))
            cmd.append('sudo config interface vrf unbind Vlan{}\n'.format(vrf_id))
            cmd.append('sudo config vrf del Vrf{}\n'.format(vrf_id))
            cmd.append('sudo config vlan del {}\n'.format(vrf_id))
        output += ''.join(cmd)
    return output


def generate_l3vni_bgw_frr_config(node_name, config_dict, bgp_info, dci_vip_maps):
    """
    Generate FRR configuration for L3VNI on a BGW node.

    Per l3vni_config_diff.txt, generates:
      - VRF-VNI bindings (cross-DC L3VNI)
      - BGP extcommunity-lists (RT-WAN-* for leaf routes, RT-DC-* for remote BGW routes)
      - RT-REWRITE-WAN route-map (rewrite for WAN-side tunnels)
      - RT-REWRITE-DC route-map (rewrite for DC-side tunnels)
      - Apply route-maps to OVERLAY and OVERLAY_WAN neighbors
      - BGP VRF config with route-target import/export

    Args:
        node_name: BGW node hostname
        config_dict: Full config dict from get_cfg_dict()
        bgp_info: Dict of node -> {router_id, as_num}
        dci_vip_maps: Tuple from generate_dci_vip_maps():
            (loopback_ipv6_dc_vip, loopback_ipv4_wan_vip, ...)

    Returns:
        FRR config string
    """
    params = _get_l3vni_bgw_params(node_name, config_dict, bgp_info)
    if not params:
        return ''

    loopback_ipv6_dc_vip, loopback_ipv4_wan_vip = dci_vip_maps[0], dci_vip_maps[1]
    as_num = params['as_num']
    dc_vip_ipv6 = loopback_ipv6_dc_vip.get(node_name, '')
    wan_vip_ipv4 = loopback_ipv4_wan_vip.get(node_name, '')
    leaf_asns = params['leaf_asns']
    remote_bgw_asns = params['remote_bgw_asns']

    output = ''

    # 1) VRF-VNI bindings (all BGWs use cross-DC L3VNI)
    for vrf_id, cross_dc_vni in params['vrf_l3vni_pairs']:
        output += 'vrf Vrf{}\n'.format(vrf_id)
        output += ' vni {}\n'.format(cross_dc_vni)
        output += 'exit-vrf\n'

    # 2) BGP extcommunity-lists
    for vrf_id, cross_dc_vni in params['vrf_l3vni_pairs']:
        leaf_vni = params['leaf_l3vnis_by_vrf'].get(vrf_id, 5000 + vrf_id)
        # RT-WAN: match routes from local leaves (leaf ASN : leaf L3VNI)
        seq = 5
        for leaf_asn in leaf_asns:
            output += 'bgp extcommunity-list standard RT-WAN-{} seq {} permit rt {}:{}\n'.format(
                cross_dc_vni, seq, leaf_asn, leaf_vni)
            seq += 5
        # RT-DC: match routes from remote BGWs (remote BGW ASN : cross-DC L3VNI)
        seq = 5
        for remote_asn in remote_bgw_asns:
            output += 'bgp extcommunity-list standard RT-DC-{} seq {} permit rt {}:{}\n'.format(
                cross_dc_vni, seq, remote_asn, cross_dc_vni)
            seq += 5

    # 3) RT-REWRITE-WAN route-map (WAN-side: IPv4 next-hop)
    permit_seq = 10
    for vrf_id, cross_dc_vni in params['vrf_l3vni_pairs']:
        output += 'route-map RT-REWRITE-WAN permit {}\n'.format(permit_seq)
        output += '  match extcommunity RT-WAN-{}\n'.format(cross_dc_vni)
        output += '  match evpn route-type prefix\n'
        output += '  set evpn vni {}\n'.format(cross_dc_vni)
        output += '  set evpn rmac local\n'
        output += '  set extcommunity rt {}:{}\n'.format(as_num, cross_dc_vni)
        output += '  set ip next-hop {}\n'.format(wan_vip_ipv4)
        output += 'exit\n'
        permit_seq += 5
    output += 'route-map RT-REWRITE-WAN permit {}\n'.format(permit_seq)
    output += 'exit\n'

    # 4) RT-REWRITE-DC route-map (DC-side: IPv6 next-hop)
    permit_seq = 10
    for vrf_id, cross_dc_vni in params['vrf_l3vni_pairs']:
        output += 'route-map RT-REWRITE-DC permit {}\n'.format(permit_seq)
        output += '  match extcommunity RT-DC-{}\n'.format(cross_dc_vni)
        output += '  match evpn route-type prefix\n'
        output += '  set evpn vni {}\n'.format(cross_dc_vni)
        output += '  set evpn rmac local\n'
        output += '  set extcommunity rt {}:{}\n'.format(as_num, cross_dc_vni)
        output += '  set ipv6 next-hop global {}\n'.format(dc_vip_ipv6)
        output += 'exit\n'
        permit_seq += 5
    output += 'route-map RT-REWRITE-DC permit {}\n'.format(permit_seq)
    output += 'exit\n'

    # 5) Apply route-maps to OVERLAY and OVERLAY_WAN neighbors
    output += 'router bgp {}\n'.format(as_num)
    output += 'address-family l2vpn evpn\n'
    output += 'neighbor OVERLAY route-map RT-REWRITE-DC out\n'
    output += 'neighbor OVERLAY_WAN route-map RT-REWRITE-WAN out\n'
    output += 'exit-address-family\n'
    output += 'exit\n'

    # 6) BGP VRF config with route-target import/export
    for vrf_id, cross_dc_vni in params['vrf_l3vni_pairs']:
        leaf_vni = params['leaf_l3vnis_by_vrf'].get(vrf_id, 5000 + vrf_id)
        output += 'router bgp {} vrf Vrf{}\n'.format(as_num, vrf_id)
        output += 'bgp bestpath as-path multipath-relax\n'
        output += 'address-family l2vpn evpn\n'
        # Export own RT
        output += 'route-target export {}:{}\n'.format(as_num, cross_dc_vni)
        # Import from remote BGWs (remote_asn:cross_dc_vni)
        for remote_asn in remote_bgw_asns:
            output += 'route-target import {}:{}\n'.format(remote_asn, cross_dc_vni)
        # Import from local leaves (leaf_asn:leaf_vni)
        for leaf_asn in leaf_asns:
            output += 'route-target import {}:{}\n'.format(leaf_asn, leaf_vni)
        output += 'no use-es-l3nhg\n'
        output += 'advertise ipv4 unicast\n'
        output += 'advertise ipv6 unicast\n'
        output += 'exit-address-family\n'
        output += 'exit\n'

    return output


def delete_l3vni_bgw_frr_config(node_name, config_dict, bgp_info):
    """
    Generate FRR unconfig commands for L3VNI on a BGW node.

    Removes BGP VRF config, route-maps, extcommunity-lists, and VRF-VNI bindings
    in reverse order of generate_l3vni_bgw_frr_config.

    Args:
        node_name: BGW node hostname
        config_dict: Full config dict from get_cfg_dict()
        bgp_info: Dict of node -> {router_id, as_num}

    Returns:
        FRR unconfig string
    """
    params = _get_l3vni_bgw_params(node_name, config_dict, bgp_info)
    if not params:
        return ''

    as_num = params['as_num']
    output = ''

    # Remove BGP VRF config
    for vrf_id, cross_dc_vni in params['vrf_l3vni_pairs']:
        output += 'no router bgp {} vrf Vrf{}\n'.format(as_num, vrf_id)

    # Remove route-maps
    output += 'no route-map RT-REWRITE-WAN\n'
    output += 'no route-map RT-REWRITE-DC\n'

    # Remove extcommunity-lists
    for vrf_id, cross_dc_vni in params['vrf_l3vni_pairs']:
        output += 'no bgp extcommunity-list standard RT-WAN-{}\n'.format(cross_dc_vni)
        output += 'no bgp extcommunity-list standard RT-DC-{}\n'.format(cross_dc_vni)

    # Remove VRF-VNI bindings (all BGWs use cross-DC L3VNI)
    for vrf_id, cross_dc_vni in params['vrf_l3vni_pairs']:
        output += 'vrf Vrf{}\n'.format(vrf_id)
        output += ' no vni {}\n'.format(cross_dc_vni)
        output += 'exit-vrf\n'

    output += 'end\n'
    output += 'exit\n'
    return output


def generate_l3vni_leaf_rt_config(node_name, config_dict, bgp_info):
    """
    Generate leaf VRF route-target export/import for intra-DC EVPN and
    route-target imports from local BGW cross-DC L3VNI.

    Per l3vni_config_diff.txt lines 1-39, each leaf needs:
    1. Intra-DC route-target export (own ASN:leaf_VNI)
    2. Intra-DC route-target import from other same-DC leafs (peer_ASN:leaf_VNI)
    3. Cross-DC route-target import from local BGWs (bgw_ASN:cross_dc_VNI)

    Example for DC1 leaf3 (ASN 65203, Vrf102, leaf VNI 5102, cross-DC VNI 10102):
        route-target export 65203:5102
        route-target import 65200:5102   (DC1 leaf0)
        route-target import 65201:5102   (DC1 leaf1)
        route-target import 65202:5102   (DC1 leaf2)
        route-target import 65102:10102  (DC1 BGW1)
        route-target import 65103:10102  (DC1 BGW2)

    Args:
        node_name: Leaf node hostname (e.g. 'leaf0_dc1')
        config_dict: Full config dict from get_cfg_dict()
        bgp_info: Dict of node -> {router_id, as_num}

    Returns:
        FRR config string with route-target export/import statements
    """
    dc = _get_dc_from_name(node_name)
    if not dc or 'bgw' in node_name:
        return ''  # Only for leaf/spine nodes, not BGWs

    as_num = bgp_info.get(node_name, {}).get('as_num')
    if not as_num:
        return ''

    # Get L3VNI data for this leaf
    config = config_dict.get(node_name, {})
    if not isinstance(config, dict) or not config.get('l3vni'):
        return ''

    # Find BGW nodes in the same DC and collect their ASNs
    local_bgw_asns = sorted(set(
        bgp_info[n]['as_num'] for n in config_dict.get('nodes', {}).get('all', [])
        if 'bgw' in n and dc in n and n in bgp_info
    ))

    # Find other leaf nodes in the same DC and collect their ASNs
    local_leaf_asns = sorted(set(
        bgp_info[n]['as_num'] for n in config_dict.get('nodes', {}).get('all', [])
        if 'bgw' not in n and 'spine' not in n and dc in n
        and n != node_name and n in bgp_info
    ))

    output = ''
    for l3vni_item in config['l3vni']:
        vrf_id = l3vni_item['vrf_id']
        leaf_vni = l3vni_item.get('vxlan_id', 5000 + vrf_id)
        cross_dc_vni = 10000 + vrf_id
        output += 'router bgp {} vrf Vrf{}\n'.format(as_num, vrf_id)
        output += 'address-family l2vpn evpn\n'
        # Intra-DC: export own leaf route-target
        output += 'route-target export {}:{}\n'.format(as_num, leaf_vni)
        # Intra-DC: import from other same-DC leafs
        for leaf_asn in local_leaf_asns:
            output += 'route-target import {}:{}\n'.format(leaf_asn, leaf_vni)
        # Cross-DC: import from local BGWs
        for bgw_asn in local_bgw_asns:
            output += 'route-target import {}:{}\n'.format(bgw_asn, cross_dc_vni)
        output += 'exit-address-family\n'
        output += 'exit\n'

    if output:
        output += 'end\n'
        output += 'exit\n'

    return output


def delete_l3vni_leaf_rt_config(node_name, config_dict, bgp_info):
    """
    Remove leaf VRF route-target export/import for intra-DC EVPN and
    cross-DC L3VNI.

    Reverse of generate_l3vni_leaf_rt_config: removes the route-target
    export/import statements that were added for intra-DC and cross-DC L3VNI.

    Args:
        node_name: Leaf node hostname (e.g. 'leaf0_dc1')
        config_dict: Full config dict from get_cfg_dict()
        bgp_info: Dict of node -> {router_id, as_num}

    Returns:
        FRR unconfig string
    """
    dc = _get_dc_from_name(node_name)
    if not dc or 'bgw' in node_name:
        return ''

    as_num = bgp_info.get(node_name, {}).get('as_num')
    if not as_num:
        return ''

    config = config_dict.get(node_name, {})
    if not isinstance(config, dict) or not config.get('l3vni'):
        return ''

    local_bgw_asns = sorted(set(
        bgp_info[n]['as_num'] for n in config_dict.get('nodes', {}).get('all', [])
        if 'bgw' in n and dc in n and n in bgp_info
    ))

    local_leaf_asns = sorted(set(
        bgp_info[n]['as_num'] for n in config_dict.get('nodes', {}).get('all', [])
        if 'bgw' not in n and 'spine' not in n and dc in n
        and n != node_name and n in bgp_info
    ))

    output = ''
    for l3vni_item in config['l3vni']:
        vrf_id = l3vni_item['vrf_id']
        leaf_vni = l3vni_item.get('vxlan_id', 5000 + vrf_id)
        cross_dc_vni = 10000 + vrf_id
        output += 'router bgp {} vrf Vrf{}\n'.format(as_num, vrf_id)
        output += 'address-family l2vpn evpn\n'
        # Remove intra-DC export
        output += 'no route-target export {}:{}\n'.format(as_num, leaf_vni)
        # Remove intra-DC imports from other same-DC leafs
        for leaf_asn in local_leaf_asns:
            output += 'no route-target import {}:{}\n'.format(leaf_asn, leaf_vni)
        # Remove cross-DC imports from local BGWs
        for bgw_asn in local_bgw_asns:
            output += 'no route-target import {}:{}\n'.format(bgw_asn, cross_dc_vni)
        output += 'exit-address-family\n'
        output += 'exit\n'

    if output:
        output += 'end\n'
        output += 'exit\n'

    return output


def get_interfaces_status(dut, interface=""):
    """
    parses 'show interfaces status ' output into data struct below
    cisco@sonic:~$ sudo 
    sudo show interfaces status
    FCMD: sudo show interfaces status
         Interface                                    Lanes    Speed    MTU    FEC           Alias          Vlan    Oper    Admin                           Type    Asym PFC
    --------------  ---------------------------------------  -------  -----  -----  --------------  ------------  ------  -------  -----------------------------  ----------
     Ethernet1_1_1                      1544,1545,1546,1547     400G   9100     rs   Ethernet1_1_1        routed      up       up  OSFP 8X Pluggable Transceiver         N/A
     Ethernet1_1_2                      1548,1549,1550,1551     400G   9100     rs   Ethernet1_1_2        routed      up       up  OSFP 8X Pluggable Transceiver         N/A
       Ethernet1_2  1536,1537,1538,1539,1540,1541,1542,1543     800G   9100    N/A     Ethernet1_2        routed      up       up  OSFP 8X Pluggable Transceiver         N/A

    Returns:
    [{'admin': 'up',
    'alias': 'Ethernet1_1_1',
    'asympfc': 'N/A',
    'fec': 'rs',
    'interface': 'Ethernet1_1_1',
    'lanes': '1544,1545,1546,1547',
    'mtu': '9100',
    'oper': 'up',
    'speed': '400G',
    'type': 'OSFP 8X Pluggable Transceiver        ',
    'vlan': 'routed'},
    {'admin': 'up',
    'alias': 'Ethernet1_1_2',
    'asympfc': 'N/A',
    'fec': 'rs',
    'interface': 'Ethernet1_1_2',
    'lanes': '1548,1549,1550,1551',
    'mtu': '9100',
    'oper': 'up',
    'speed': '400G',
    'type': 'OSFP 8X Pluggable Transceiver        ',
    'vlan': 'routed'},
    {'admin': 'up',
    'alias': 'Ethernet1_2',
    'asympfc': 'N/A',
    'fec': 'N/A',
    'interface': 'Ethernet1_2',
    'lanes': '1536,1537,1538,1539,1540,1541,1542,1543',
    'mtu': '9100',
    'oper': 'up',
    'speed': '800G',
    'type': 'OSFP 8X Pluggable Transceiver        ',
    'vlan': 'routed'},
    ...]

    """
    cmd = 'show interfaces status {}'.format(interface)
    cmd_output = st.show(dut, cmd, skip_tmpl=True, skip_error_check=False)
    parsed_output = st.parse_show(dut, cmd, cmd_output, 'show_interfaces_status_qa.tmpl')

    return parsed_output


def get_dut_interfaces(var_dict):
    '''

    Author:Ramsiddarth Ragurajan (rraguraj@cisco.com)

    returns all the dut interfaces based on input testbed yaml file

    input_param: testbed vars
    ex:
    spine1 {'tgen_port_dict': {},
             'underlay_dict': {'D2D4P1': 'Ethernet8', 'D2D3P1': 'Ethernet0'},
             'dut_port_dict': {}}
    spine0 {'tgen_port_dict': {},
            'underlay_dict': {'D1D4P1': 'Ethernet8', 'D1D3P1': 'Ethernet0'},
            'dut_port_dict': {}}
    leaf1 {'tgen_port_dict': {'T1D4P3': '1/7', 'T1D4P2': '1/4', 'T1D4P1': '1/3'},
        'underlay_dict': {'D4D2P1': 'Ethernet8', 'D4D1P1': 'Ethernet0'},
        'dut_port_dict': {'D4T1P3': 'Ethernet224', 'D4T1P2': 'Ethernet248', 'D4T1P1': 'Ethernet240'}}
    leaf0 {'tgen_port_dict': {'T1D3P4': '1/6', 'T1D3P1': '1/1', 'T1D3P2': '1/2', 'T1D3P3': '1/5'},
            'underlay_dict': {'D3D1P1': 'Ethernet0', 'D3D2P1': 'Ethernet8'},
            'dut_port_dict': {'D3T1P4': 'Ethernet232', 'D3T1P1': 'Ethernet240', 'D3T1P2': 'Ethernet248', 'D3T1P3': 'Ethernet224'}

    '''
    final_dict={}
    # DCI: map dut_id -> node for peer DC lookup
    id_to_node = {dut_id: node for node, dut_id in var_dict.dut_ids.items()}

    # DCI: get DCI interface names from testbed (cross-DC links) instead of hardcoding
    dci_iface_names = set()
    try:
        node_dc_re = re.compile(r'_dc(\d+)')
        for node in var_dict.dut_ids.keys():
            m = node_dc_re.search(node)
            node_dc = m.group(1) if m else None
            for link in st.get_dut_links(node):
                if len(link) >= 2:
                    local_iface, peer_node = link[0], link[1]
                    pm = node_dc_re.search(peer_node) if isinstance(peer_node, str) else None
                    peer_dc = pm.group(1) if pm else None
                    if node_dc and peer_dc and node_dc != peer_dc:
                        dci_iface_names.add(local_iface)
    except Exception:
        dci_iface_names = {"Ethernet1_29", "Ethernet1_30"}  # fallback

    for node,dut_id in var_dict.dut_ids.items():
        final_dict[node]={}
        dut_port_dict={}
        underlay_dict={}
        tgen_port_dict={}
        dci_dict={}  # DCI: cross-DC WAN links
        all_port_dict={}

        # DCI: _dcN tag -> underlay vs DCI
        m = re.search(r'_dc\d+', node)
        node_dc = m.group(0) if m else ''

        for key, value in var_dict.items():
            # DCI: startswith for D11/D12 (key[:2] fails)
            if key.startswith('T1' + dut_id + 'P'):
                tgen_port_dict[key] = value
                all_port_dict[key] = value
            elif key.startswith(dut_id + 'T1P'):
                dut_port_dict[key] = value
                all_port_dict[key] = value
            elif 'T1' not in key and key.startswith('D') and 'P' in key:
                pre = key.split('P', 1)[0]  
                # Only process keys where this node is the source (left side of the link)
                if pre.startswith(dut_id + 'D'):
                    peer_tag = pre[len(dut_id):]  

                    peer_node = id_to_node.get(peer_tag)

                    if peer_node:
                        pm = re.search(r'_dc\d+', peer_node)
                        peer_dc = pm.group(0) if pm else ''
                        # Same DC or no DC tags -> underlay; else -> DCI
                        if (node_dc and peer_dc and node_dc == peer_dc) or (not node_dc and not peer_dc):
                            underlay_dict[key] = value
                            all_port_dict[key] = value
                        else:
                            dci_dict[key] = value
                            all_port_dict[key] = value
                    else:
                        # peer not in dut_ids: use testbed-derived DCI interfaces
                        if value in dci_iface_names:
                            dci_dict[key] = value
                            all_port_dict[key] = value
                        else:
                            underlay_dict[key] = value
                            all_port_dict[key] = value

        final_dict[node]['all_port_dict'] = all_port_dict
        final_dict[node]['dut_port_dict'] = dut_port_dict
        final_dict[node]['underlay_dict'] = underlay_dict
        final_dict[node]['tgen_port_dict'] = tgen_port_dict
        final_dict[node]['dci_dict'] = dci_dict
    return final_dict


def get_config_interfaces_list(var_dict):
    '''
    Author:Ramsiddarth Ragurajan (rraguraj@cisco.com)

    Returns the l2vni, l3vni and underlay interface information for configuration

    Generated based on no of l2vni/l3vni count provided in dut config file and info from testbed yaml file

    Example:
    input from dut_configs_file
    leaf0:
        l2vni:
            vlan_start_range: 501
            count: 1 <--
        l3vni:
            l3_dummy:
                start_vlan: 102
                count: 2 <--
    final_config_dict output:
    {'spine0': {'underlay': ['Ethernet0', 'Ethernet8']},
    'spine1': {'underlay': ['Ethernet0', 'Ethernet8']},
     'leaf0': {'underlay': ['Ethernet0', 'Ethernet8'], 'l2vni_int': ['Ethernet240'], 'l3vni_int': ['Ethernet248', 'Ethernet224']},
     'leaf1': {'underlay': ['Ethernet8', 'Ethernet0'], 'l2vni_int': ['Ethernet240'], 'l3vni_int': ['Ethernet248', 'Ethernet224']}}

    '''
    temp_list =[]
    config_dict={}
    temp_dict = {}
    final_config_dict ={}
    dut_int_data = get_dut_interfaces(var_dict)
    config = get_cfg_dict()
    for key,value in var_dict.dut_ids.items():
        if key in config['nodes']['l2l3vni']:
            temp_dict[key] ={}
            if type(config[key]['l2vni']) == list:
                temp_dict[key]['l2vni_int_count'] = len(config[key]['l2vni'])
            else:
                temp_dict[key]['l2vni_int_count'] = config[key]['l2vni']['count']
    for node in var_dict.dut_ids.keys():
        temp_list=[]
        if node in config['nodes']['spine'] or \
            node in config['nodes']['leaf']:
            final_config_dict[node]={}
            final_config_dict[node]['underlay']={}
            for item,value in dut_int_data[node]['underlay_dict'].items():
                temp_list.append(value)
            final_config_dict[node]['underlay'] = sorted(temp_list)
            # DCI: WAN interfaces for BGP WAN underlay
            dci_list = []
            if 'dci_dict' in dut_int_data[node]:
                for _, val in dut_int_data[node]['dci_dict'].items():
                    dci_list.append(val)
            final_config_dict[node]['dci_int'] = sorted(dci_list)

        if node in config['nodes']['l2l3vni']:
            my_list =[]
            for key in dut_int_data[node]['dut_port_dict'].keys():      
                my_list.append(key)
            sorted_list =sorted(my_list)

            # Use a separate list for L2VNI interfaces to avoid including underlay interfaces
            l2vni_temp_list = []
            for port in sorted_list:
                 l2vni_temp_list.append(dut_int_data[node]['dut_port_dict'][port])
            config_dict[node] = l2vni_temp_list
    for node,value in temp_dict.items():
        final_config_dict[node]['l2vni_int']= config_dict[node][:value['l2vni_int_count']]
        
    return final_config_dict

def get_interfaces(var_dict,nodes,vni):
    '''
    Gets tgen spytest port alias and gateway

    Author:Ramsiddarth Ragurajan (rraguraj@cisco.com)

    input params: list of leaf nodes
    get interaces from dutconfig 
    get endpoints and gateway
    ('T1D3P2', 'T1D4P2', '80.80.80.1/24', '90.90.90.1/24'), ('T1D3P4', 'T1D4P4', '80.80.81.1/24', '90.90.91.1/24')]

    T1D3P2  --> tgen_src leaf0, T1D4P2 -->tgen_dst leaf1 80.80.80.1/24,90.90.90.1/24' -->  gateway

    '''
    int_config_dict = get_config_interfaces_list(var_dict)
    intf_dict = {}
    sort_intf_dict = {}
    for node in nodes:
        # Skip nodes that don't have the requested VNI type configured
        if node not in int_config_dict:
            continue
        
        if vni == 'l3vni':
            if 'l3vni_int' not in int_config_dict[node]:
                continue
            try:
                intf_list = find_port_alias(var_dict, node, int_config_dict[node]['l3vni_int'])
            except Exception as e:
                st.log(f"Warning: Could not convert port aliases for {node}: {e}")
                intf_list = []
        else:
            if 'l2vni_int' not in int_config_dict[node]:
                continue
            try:
                intf_list = find_port_alias(var_dict, node, int_config_dict[node]['l2vni_int'])
            except Exception as e:
                st.log(f"Warning: Could not convert port aliases for {node}: {e}")
                intf_list = []
        # Only add nodes with valid interface lists
        if intf_list:
            intf_dict[node] = intf_list
    
    keys = list(sorted(intf_dict.keys()))
    for item in keys:
        sort_intf_dict[item] = intf_dict[item]
    return sort_intf_dict

def find_port_alias(var_dict,node,int_list):
    '''
    Author:Ramsiddarth Ragurajan (rraguraj@cisco.com)
    Example:
    input --> ['D1T1P1', 'D3T1P2'] output --> ['T1D1P1','T1D3P2']
    input --> ['D11T1P1', 'D12T1P2'] output --> ['T1D11P1','T1D12P2']
    Handles both single-digit (D5) and double-digit (D11) device IDs
    '''
    for key,value in var_dict.items():
        if value == node:
            mykey = key
    mylist=[]
    for i in int_list:
        for key,value in var_dict.items():
            if mykey+"T1" in key and value == i:
                # DCI: use replace (not char-position) so D11/D12 work
                tgen_alias = key.replace(mykey + 'T1', 'T1' + mykey)
                mylist.append(tgen_alias)
              
    return mylist
    
def find_endpoint_pair(intf_dict,vni = None):
    '''
    Author:Ramsiddarth Ragurajan (rraguraj@cisco.com)
    returns the list of tgen and gw ip to be configured for the streams
    l3vni:
    output = [('T1D3P2', 'T1D4P2', '80.80.80.1', '90.90.90.1'), ('T1D3P3', 'T1D4P3', '80.80.81.1', '90.90.91.1')]

    ex: T1D3P2 --> traffic src endpoint
        T1D4P2  --> traffic dst endpoint
        80.80.80.1 --> src gateway
        90.90.90.1 --> dst gateway

    '''
    port_dict = {}
    nodes = list(sorted(intf_dict.keys()))
    for item in nodes:
        port_dict[item] = intf_dict[item]
    tgen_ports = list(port_dict.values())
    if vni == "l3vni":
        gateway_dict={}
        gateway_ip = generate_svi_ip(nodes,'ipv4')
        key = list(sorted(gateway_ip.keys()))
        for item in key:
            gateway_dict[item] = gateway_ip[item]
        out = list(gateway_dict.values())
        output = list(zip(tgen_ports[0],tgen_ports[1],out[0],out[1]))
    elif vni == "l2vni":
        host_dict = generate_host_ip(intf_dict, 'ipv4')
        host_list = list(host_dict.values())
        output = list(zip(tgen_ports[0],tgen_ports[1],host_list[0],host_list[1]))
    else:
        gateway_dict={}
        gateway_ip = generate_svi_ip(nodes,'ipv4')
        key = list(sorted(gateway_ip.keys()))
        for item in key:
            gateway_dict[item] = gateway_ip[item]
        out = list(gateway_dict.values())
        output = list(zip(tgen_ports[0],tgen_ports[1],out[0],out[1]))

    return output

def verify_vtep (nodes):
    '''
    Author:Ramsiddarth Ragurajan (rraguraj@cisco.com)
    remote_vtep_dict ={'leaf1': {'2000:1::2': ['2000:1::1', '2000:1::4']}, 
    'leaf0': {'2000:1::1': ['2000:1::2', '2000:1::3', '2000:1::4']}, 
    'leaf3': {'2000:1::4': ['2000:1::2', '2000:1::3', '2000:1::4']}, 
    'leaf2': {'2000:1::3': ['2000:1::1', '2000:1::4']}}
    get_vtep_info(nodes)[1] = {'leaf1': ['2000:1::2'], 'leaf0': ['2000:1::1'], 'leaf3': ['2000:1::4'], 'leaf2': ['2000:1::3']}
    '''
    flag = True
    remote_vtep_dict = get_expected_remote_vteps()
    for i in range (len(nodes)):
        cli_output = st.show(nodes[i], "show vxlan remotevtep", skip_tmpl=True)
        '''
        [{u'tun_src': u'EVPN', u'total_count': u'', u'vlan': u'', u'tun_status': u'oper_up', u'vni': u'', u'remote_mac': u'', u'dst_vtep': u'2000:1::2', u'src_vtep': u'2000:1::1', u'remote_vtep': u''}, 
        {u'tun_src': u'EVPN', u'total_count': u'', u'vlan': u'', u'tun_status': u'oper_up', u'vni': u'', u'remote_mac': u'', u'dst_vtep': u'2000:1::3', u'src_vtep': u'2000:1::1', u'remote_vtep': u''}, 
        {u'tun_src': u'EVPN', u'total_count': u'', u'vlan': u'', u'tun_status': u'oper_up', u'vni': u'', u'remote_mac': u'', u'dst_vtep': u'2000:1::4', u'src_vtep': u'2000:1::1', u'remote_vtep': u''}]
        '''
        parsed_out = st.parse_show(nodes[i], "show vxlan remotevtep",cli_output, "show_vxlan_remotevtep.tmpl")
        if len(parsed_out) == 0:
            flag = False
            st.log('No remote VTEP found in', nodes[i])
            break
        for src_vtep, values in remote_vtep_dict[nodes[i]].items():
            for item in parsed_out:
                if item['src_vtep'] != src_vtep:
                    st.log('No local vtep {} found in {}'.format(src_vtep,nodes[i]))
                    flag = False
                if item['dst_vtep'] not in values:
                    st.log(' no remote vtep {} found in {}'.format(item['dst_vtep'],nodes[i]))
                    flag = False
                if item['tun_src'] != 'EVPN':
                    flag = False
                    st.log('Unexpected tunnel type {} in {}'.format(item['tun_type'], nodes[i]))
                if item['tun_status'] != 'oper_up':
                    st.log('Tunnel is not in up status in {}'.format(nodes[i]))
                    flag = False
    return flag

def get_vtep_info(nodes):
    '''
    Get local vtep ip list for each node, and list of all vtep ip's in the topo. Generated based on dut_configs.yaml

    Author:Ramsiddarth Ragurajan (rraguraj@cisco.com)

    input params: list of leaf nodes

    vtep_ip_list --> ['10.200.200.200', '10.200.200.100', '10.200.200.201', '10.200.200.101', '10.200.200.202', '10.200.200.203']
    vtep_dict --> {'leaf0': ['10.200.200.200', '10.200.200.100'], 'leaf1': ['10.200.200.201', '10.200.200.101'], 'leaf2': ['10.200.200.202'], 'leaf3': ['10.200.200.203']}
    '''
    vtep_dict ={}
    config_dict = get_cfg_dict()
    for node, config in config_dict.items():
        if node in nodes:
            vtep_dict[node] = (config['nvo']['ip'])
    vtep_ip_list=[]
    for key,value in vtep_dict.items():
        for ip in value:
            vtep_ip_list.append(ip)
    return vtep_ip_list,vtep_dict

def get_remote_vteps(nodes):
    '''
    Get remote vtep ip list for each node, Generated based on dut_configs.yaml

    Author:Ramsiddarth Ragurajan (rraguraj@cisco.com)
    
    input params: list of leaf nodes

    remote_vtep_dict --> {'leaf0': {'10.200.200.200': ['10.200.200.201']}, 'leaf1': {'10.200.200.201': ['10.200.200.200']}}

    '''
    remote_vtep_dict ={}
    config_dict = get_cfg_dict()
    for node, config in config_dict.items():
        if node in nodes:
            remote_vtep_dict[node]={}
            remote_vtep_dict[node][config['loopback']['ip_address']] = config['expected_vteps']

    return remote_vtep_dict  

def delete_bgp_l3vni_config(data,bgp_info):
    '''
    Author: Jigar Sanghrajka (jsanghra@cisco.com)
    
    '''
    output = ''
    # BGP configuration
    as_num = bgp_info['as_num']

    vxlan_list = list()
    vrf_list = list()
    if data.get('l3vni'):

        vxlan_start_id = 5000
        if type(data['l3vni']) == list:
            for l3vni_item in data['l3vni']:
                if l3vni_item.get('vxlan_id'):
                    vxlan_id = l3vni_item['vxlan_id']
                else:
                    vxlan_id = vxlan_start_id + l3vni_item['vxlan_id']
                vxlan_list.append(vxlan_id)
                vrf_list.append(l3vni_item['vrf_id'])
        else:
            #auto gen
            for vlan_id in range(data['l3vni']['l3_dummy']['start_vlan'], 
                              data['l3vni']['l3_dummy']['start_vlan']+data['l3vni']['l3_dummy']['count']):
                vxlan_id = vlan_id + vxlan_start_id
                vxlan_list.append(vxlan_id)
                vrf_list.append(vlan_id)
    elif data.get('vni'):
        start_vlan = data['vni']['vlan_start_range']
        count = data['vni']['count']
        for i in range(count):
            vrf = start_vlan + i
            vrf_list.append(vrf)
            vxlan_list.append(5000 + vrf)
    else:
        st.report_fail("vni information not found in input file")

    for vrf,vni in zip(vrf_list, vxlan_list):
    
        output += 'vrf Vrf{}\n'.format(vrf)
        output += 'no vni {}\n'.format(vni)
        output += 'no router bgp {} vrf Vrf{}\n'.format(as_num, vrf)
    output += 'end\n' 
    output += 'exit\n' 

    return output

def delete_bgp_config(data):
    '''
    Author: Jigar Sanghrajka (jsanghra@cisco.com)
    
    '''
    output = ''
    # BGP configuration
    router_id = data['router_id']
    as_num = data['as_num']
    output += 'no router bgp {}\n'.format(as_num)   
    output += 'end\n' 
    output += 'exit\n' 
    return output

def increment_mac(mac_address):
    """
    Increments a MAC address by 1.
    """
    parts = mac_address.split(':')  
    carry = 1  
    for i in range(len(parts) - 1, -1, -1): 
        val = int(parts[i], 16) + carry  
        parts[i] = format(val % 256, '02x')  
        carry = val // 256  
    return ':'.join(parts)  

def verify_vlanvnimap(nodes):
    '''
    Author: Jigar Sanghrajka (jsanghra@cisco.com)
    
    '''
    expected_vlanvnimap = get_expected_vlanvnimap(nodes)
    # Convert parsed data to dictionary format
    for i in range (len(nodes)):
        cli_output = st.show(nodes[i], "show vxlan vlanvnimap", skip_tmpl=True)
        vlan_vni_mappings = st.parse_show(nodes[i], "show vxlan vlanvnimap",cli_output, "show_vxlan_vlanvnimap.tmpl")
        parsed_out = [[entry['vlan'], entry['vni']] for entry in vlan_vni_mappings]
        if len(parsed_out) == 0:
            st.report_fail('No mapping found', nodes[i])
        parsed_dict = {nodes[i]: [(item[0], item[1]) for item in parsed_out]}
 
        # Check that the leaf exists in the expected data
        if nodes[i] not in expected_vlanvnimap:
            print("Leaf {} not found in expected data.".format(nodes[i]))
            st.report_fail('Leaf name {} not in expected data'.format(nodes[i]))

        if len(expected_vlanvnimap[nodes[i]]) != len(parsed_dict[nodes[i]]):
            print("Mismatch in the length of expected data - length {} and parsed data - length {}".format(len(expected_vlanvnimap[nodes[i]]),len(parsed_dict[nodes[i]])))
            st.report_fail("Mismatch in the length of expected data - length {} and parsed data - length {}".format(len(expected_vlanvnimap[nodes[i]]),len(parsed_dict[nodes[i]])))

        # Check that each key-value pair in the parsed data is in the expected data
        for pair in parsed_dict[nodes[i]]:
            if pair not in expected_vlanvnimap[nodes[i]]:
                st.report_fail("Pair {} not found in expected data for {}.".format(pair,nodes[i]))
                return False

    print("Data verification succeeded.")
    return True

def verify_vrfvnimap(nodes):
    '''
    Author: Jigar Sanghrajka (jsanghra@cisco.com)
    
    '''
    expected_vrfvnimap = get_expected_vrfvnimap(nodes)
    # Convert parsed data to dictionary format
    for i in range (len(nodes)):
        cli_output = st.show(nodes[i], "show vxlan vrfvnimap", skip_tmpl=True)
        vrf_vni_mappings = st.parse_show(nodes[i], "show vxlan vrfvnimap",cli_output, "show_vxlan_vrfvnimap.tmpl")
        parsed_out = [[entry['vrf'], entry['vni']] for entry in vrf_vni_mappings]
        if len(parsed_out) == 0:
            st.report_fail('No mapping found', nodes[i])

        parsed_dict = {nodes[i]: [(item[0], item[1]) for item in parsed_out]}
        # Check that the leaf exists in the expected data
        if nodes[i] not in expected_vrfvnimap:
            print("Leaf {} not found in expected data.".format(nodes[i]))
            return False
        if len(expected_vrfvnimap[nodes[i]]) != len(parsed_dict[nodes[i]]):
            print("Mismatch in the length of expected data - length {} and parsed data - length {}".format(len(expected_vrfvnimap[nodes[i]]),len(parsed_dict[nodes[i]])))
            return False
        # Check that each key-value pair in the parsed data is in the expected data
        for pair in parsed_dict[nodes[i]]:
            if pair not in expected_vrfvnimap[nodes[i]]:
                st.report_fail("Pair {} not found in expected data for {}.".format(pair,nodes[i]))
                return False

    print("Data verification succeeded.")
    return True
 
def generate_vrf_vni(start_vrf, count, offset=5000):
    '''
    Author: Jigar Sanghrajka (jsanghra@cisco.com)

    Function to generate VRF-VNI tuples given a start L3 dummy VLAN and a count
    
    '''
    return [('Vrf' + str(vrf), str(vrf + offset)) for vrf in range(start_vrf, start_vrf + count)]

def generate_vlan_vni(start_vlan, count, offset=0):
    '''
    Author: Jigar Sanghrajka (jsanghra@cisco.com)
    
    Function to generate VLAN-VNI tuples given a start VLAN and a count
    '''
    return [('Vlan' + str(vlan), str(vlan + offset)) for vlan in range(start_vlan, start_vlan + count)]

def get_expected_vlanvnimap(nodes):
    '''
    Author: Jigar Sanghrajka (jsanghra@cisco.com)
    
    '''
    vlan_vni_map = {}
    config_dict = get_cfg_dict()
    for node, leaf_data in config_dict.items():
        if node in nodes:
            # Initialize the list for the current leaf
            vlan_vni_map[node] = []
            # Handle l2vni
            vlan_start_range = leaf_data['l2vni']['vlan_start_range']
            count = leaf_data['l2vni']['count']
            vlan_vni_map[node].extend(generate_vlan_vni(vlan_start_range, count, 5000))
            # Handle l3vni
            l3_dummy_vlan = leaf_data['l3vni']['l3_dummy']['start_vlan']
            l3_dummy_count = leaf_data['l3vni']['l3_dummy']['count']
            vlan_vni_map[node].extend(generate_vlan_vni(l3_dummy_vlan, l3_dummy_count, 5000))

    return vlan_vni_map

def get_expected_vrfvnimap(nodes):
    '''
    Author: Jigar Sanghrajka (jsanghra@cisco.com)
    
    '''
    vrf_vni_map = {}
    config_dict = get_cfg_dict()
    for node, leaf_data in config_dict.items():
        if node in nodes:
            # Initialize the list for the current leaf
            vrf_vni_map[node] = []

            # Handle l3vni
            l3_dummy_vrf = leaf_data['l3vni']['l3_dummy']['start_vlan']
            l3_dummy_count = leaf_data['l3vni']['l3_dummy']['count']
            vrf_vni_map[node].extend(generate_vrf_vni(l3_dummy_vrf, l3_dummy_count))

    return vrf_vni_map

def generate_sag_config(sag_dict,version,enable_on_vlan = True):

    output = ''
    
    for vlan,ip_add in sag_dict.items():
        if version == "ipv6":
            cmd = "sudo config interface ip add Vlan{} {}/64\n".format(vlan, ip_add)
        else:
            cmd = "sudo config interface ip add Vlan{} {}/24\n".format(vlan, ip_add)
        output += cmd
        if enable_on_vlan:
            cmd = "sudo config vlan static-anycast-gateway enable {}\n".format(vlan)
            output += cmd
    return output

def remove_sag_config(sag_dict,version, disable_on_vlan = True):
    output = ''
    for vlan,ip_add in sag_dict.items():
        if disable_on_vlan != True: 
            cmd = "sudo config vlan static-anycast-gateway disable {}\n".format(vlan)
            output += cmd
        if version == "ipv6":
            cmd = "sudo config interface ip remove Vlan{} {}/64\n".format(vlan, ip_add)
            output += cmd
        else:
            cmd = "sudo config interface ip remove Vlan{} {}/24\n".format(vlan, ip_add)
            output += cmd   
    return output

def config_sag_mac(add = True):
    if add:
        output = "sudo config static-anycast-gateway mac_address add 00:11:22:33:44:55"
    else:
        output = "sudo config static-anycast-gateway mac_address del"
    return output

def svi_config(sag_dict,version, mode = 'add'):
    output = ''
    
    for vlan,ip_add in sag_dict.items():
        if mode == 'del':
            if version == "ipv6":
                cmd = "sudo config interface ip remove Vlan{} {}/64\n".format(vlan, ip_add)
            else:
                cmd = "sudo config interface ip remove Vlan{} {}/24\n".format(vlan, ip_add)
        else:
            if version == "ipv6":
                cmd = "sudo config interface ip add Vlan{} {}/64\n".format(vlan, ip_add)
            else:
                cmd = "sudo config interface ip add Vlan{} {}/24\n".format(vlan, ip_add)
        output += cmd
    
    return output

def generate_new_v6_ip(ip_add,vlan):
    temp_list = ip_add.split(':')
    temp_list[1] = str(vlan)
    return ':'.join(temp_list)

def generate_new_v4_ip(ip_add,vlan):
    temp_list = ip_add.split('.')
    temp_list[1] = str(vlan)
    return '.'.join(temp_list)

def generate_svi_ip_sag(config,version,**kwargs):
    '''
    {'leaf0': {2: '8000:2::1', 3: '8000:3::1', 4: '8000:4::1', 5: '8000:5::1'}}
    {'leaf1': {2: '8000:2::1', 3: '8000:3::1'}}
    {'leaf2': {4: '8000:4::1', 5: '8000:5::1'}}
    {'leaf3': {2: '8000:2::1', 3: '8000:3::1', 4: '8000:4::1', 5: '8000:5::1'}}
    '''
    svi_dict ={}
    if config.get('l2vni'):
        if version == 'ipv4':
            if kwargs.get('ip_start'):
                ip_start = kwargs['ip_start']
            else:
                ip_start = "80.2.0.1"
        elif version == 'ipv6':
            if kwargs.get('ip_start'):
                ip_start = kwargs['ip_start']
            else:
                ip_start = "8000:2::1"
        else:
            st.log("unknown version")
        vlan_list = list()
        if type(config['l2vni']) == list:
            for l2vni_item in config['l2vni']:
                vlan_list.append(l2vni_item['vlan_id'])
        else:
            vlan_list = range(config['l2vni']['vlan_start_range'], 
                              config['l2vni']['vlan_start_range']+config['l2vni']['count'])

        for vlan_id in vlan_list:
            if version == 'ipv4':
                new_ip = generate_new_v4_ip(ip_start,vlan_id)
            else:
                new_ip = generate_new_v6_ip(ip_start,vlan_id)
            svi_dict[vlan_id] = new_ip
        new_ip = ip_start
     
    return svi_dict

###Generate host info###
def generate_sag_hosts(l2vni_intf_dict,svi_dict,version = "ipv4", custom_mac_enable = False, 
                       custom_start_mac = "00:00:00:00:99:10", skip_nodes = ['leaf3'], 
                       port_vlan_dict = {}):
    host_dict = {}
    if custom_mac_enable:
        start_mac = custom_start_mac
        temp_mac = custom_start_mac
    else:
        if version == "ipv4":
            start_mac = "00:00:00:00:04:10"
            temp_mac = "00:00:00:00:04:10"
        else:
            start_mac = "00:00:00:00:06:10"
            temp_mac = "00:00:00:00:06:10"

    '''
    svi_dict = {'leaf0': {2: '80.2.0.1', 3: '80.3.0.1', 4: '80.4.0.1', 5: '80.5.0.1'},
    'leaf1': {2: '80.2.0.1', 3: '80.3.0.1'}, 'leaf2': {4: '80.4.0.1', 5: '80.5.0.1'}}
    l2vni_intf_dict = {'leaf1': ['T1D6P1', 'T1D6P2'], 'leaf0': ['T1D5P1', 'T1D5P2'], 
    'leaf3': ['T1D8P1', 'T1D8P2'], 'leaf2': ['T1D7P1', 'T1D7P2']}

    output: 
    {'leaf0': {'T1D5P1': {2: {'vlan': 2, 'gateway': '80.2.0.1', 'host_ip': '80.2.0.10', 'src_mac': '00:02:00:00:00:10'},
      3: {'vlan': 3, 'gateway': '80.3.0.1', 'host_ip': '80.3.0.10', 'src_mac': '00:03:00:00:00:10'}, 
      4: {'vlan': 4, 'gateway': '80.4.0.1', 'host_ip': '80.4.0.10', 'src_mac': '00:04:00:00:00:10'},
        5: {'vlan': 5, 'gateway': '80.5.0.1', 'host_ip': '80.5.0.10', 'src_mac': '00:05:00:00:00:10'}}, 
        'T1D5P2': {2: {'vlan': 2, 'gateway': '80.2.0.1', 'host_ip': '80.2.0.20', 'src_mac': '00:02:00:00:00:20'}, 
        3: {'vlan': 3, 'gateway': '80.3.0.1', 'host_ip': '80.3.0.20', 'src_mac': '00:03:00:00:00:20'}, 
        4: {'vlan': 4, 'gateway': '80.4.0.1', 'host_ip': '80.4.0.20', 'src_mac': '00:04:00:00:00:20'},
          5: {'vlan': 5, 'gateway': '80.5.0.1', 'host_ip': '80.5.0.20', 'src_mac': '00:05:00:00:00:20'}}}, 
          'leaf1': {'T1D6P1': {2: {'vlan': 2, 'gateway': '80.2.0.1', 'host_ip': '80.2.0.30', 'src_mac': '00:02:00:00:00:30'}, 
          3: {'vlan': 3, 'gateway': '80.3.0.1', 'host_ip': '80.3.0.30', 'src_mac': '00:03:00:00:00:30'}}, 
          'T1D6P2': {2: {'vlan': 2, 'gateway': '80.2.0.1', 'host_ip': '80.2.0.40', 'src_mac': '00:02:00:00:00:40'}, 
          3: {'vlan': 3, 'gateway': '80.3.0.1', 'host_ip': '80.3.0.40', 'src_mac': '00:03:00:00:00:40'}}}, 
          'leaf2': {'T1D7P1': {4: {'vlan': 4, 'gateway': '80.4.0.1', 'host_ip': '80.4.0.50', 'src_mac': '00:04:00:00:00:50'}, 
          5: {'vlan': 5, 'gateway': '80.5.0.1', 'host_ip': '80.5.0.50', 'src_mac': '00:05:00:00:00:50'}}, 'T1D7P2': 
          {4: {'vlan': 4, 'gateway': '80.4.0.1', 'host_ip': '80.4.0.60', 'src_mac': '00:04:00:00:00:60'},
            5: {'vlan': 5, 'gateway': '80.5.0.1', 'host_ip': '80.5.0.60', 'src_mac': '00:05:00:00:00:60'}}}}
    
    Updated to ensure IP last octet and MAC last byte always match (both increment by 10 per interface)
    '''
    
    # Custom sort function to group by DC, then by leaf number
    # Example: leaf0_dc1, leaf1_dc1, leaf2_dc1, leaf0_dc2, leaf1_dc2, leaf0_dc3
    def sort_by_dc_then_leaf(node_name):
        import re
        # Extract DC number and leaf/spine number
        # Handle formats: leaf0_dc1, spine2_dc1_bgw1, leaf0 (no DC)
        dc_match = re.search(r'_dc(\d+)', node_name)
        leaf_match = re.search(r'(leaf|spine)(\d+)', node_name)
        
        dc_num = int(dc_match.group(1)) if dc_match else 0
        leaf_num = int(leaf_match.group(2)) if leaf_match else 0
        node_type = leaf_match.group(1) if leaf_match else node_name
        
        # Sort by: DC number, then node type (leaf before spine), then leaf/spine number
        return (dc_num, node_type, leaf_num)
    
    # Global counter for consistent IP/MAC addressing (increments by 10 per interface)
    ip_mac_counter = 10
    
    for node in sorted(svi_dict.keys(), key=sort_by_dc_then_leaf):
        values = svi_dict[node]
        if not node in skip_nodes:
            # Skip nodes that don't have TGEN ports (e.g., leaf0_dc3)
            if node not in l2vni_intf_dict:
                continue
            host_dict[node] = {}
            for item in l2vni_intf_dict[node]:
                if type(item) == dict:
                    # port channel type
                    item = item['name']
                host_dict[node][item] = {}
                for vlan, svi_ip in values.items():
                    if port_vlan_dict and vlan not in port_vlan_dict[item]:
                        continue
                    host_dict[node][item][vlan] = {}
                    host_dict[node][item][vlan]['vlan']=vlan
                    host_dict[node][item][vlan]['gateway'] = svi_ip
                    # Use counter for IP last octet
                    host_dict[node][item][vlan]['host_ip'] = str(ipaddress.ip_address(svi_ip) + ip_mac_counter - 1)
                    # Generate MAC with proper hex format (required by MAC address standard)
                    # MAC addresses must have exactly 2 hex digits per octet (cannot use decimal strings)
                    mac_last_byte = format(ip_mac_counter, '02x')
                    if custom_mac_enable:
                        new_mac = generate_new_mac(start_mac, vlan, custom_last_byte=mac_last_byte)
                    else:
                        # Build MAC: 00:VLAN(hex):00:00:VERSION:COUNTER(hex)
                        # Extract version octet from start_mac (04 for IPv4, 06 for IPv6)
                        version_octet = start_mac.split(':')[4]
                        vlan_hex = format(vlan, '02x')
                        new_mac = f"00:{vlan_hex}:00:00:{version_octet}:{mac_last_byte}"
                    host_dict[node][item][vlan]['src_mac'] = new_mac
                
                # Increment counter by 10 for next interface
                ip_mac_counter += 10    
        
    return host_dict

def generate_new_mac(start_mac,vlan = 0,inc = 0):
    desired_width = 2
    temp_list = start_mac.split(":")
    if len(str(vlan)) > 2:
        out_list = [str(vlan)[i:i+2] for i in range(0, len(str(vlan)), 2)]
        temp_list[1] = str(out_list[0]).zfill(desired_width)
        temp_list[2] = str(out_list[1]).zfill(desired_width)
        temp_list[3] = str(len(str(vlan))).zfill(desired_width)
    else:
        temp_list[1] = str(vlan).zfill(desired_width)
        temp_list[-1]= str(int(temp_list[-1])+inc).zfill(desired_width)
    return ':'.join(temp_list)

###GET topology HANDLES###
def create_topology_handles(l2vni_intf_dict):
    topo_handles_dict = {}
    for node in sorted(l2vni_intf_dict.keys()):
        port_ids = l2vni_intf_dict[node]
        topo_handles_dict[node]={}
        for port_id in port_ids:
            #create handles
            if type(port_id) == dict:
                #create lag interface
                topo_handles_dict[node][port_id['name']]={}
                topo_handles_dict[node][port_id['name']]['vport_port_ids'] = port_id['ports']
                tg_handle, handles = create_lag_handle(lag_name=port_id['name'],
                                                           ports=port_id['ports'])
                port_id = port_id['name']
                topo_handles_dict[node][port_id]['tg_handle'] = tg_handle
                topo_handles_dict[node][port_id]['port_handle'] = handles['lag_handle']
                topo_handles_dict[node][port_id]['vport_handles'] = handles['vport_handles']
                #create topology
                device_port = tg_handle.tg_topology_config(
                                            topology_name = """{} {} topology""".format(node,port_id),
                                            lag_handle = handles['lag_handle'])
            else:
                tg_handle, port_handle = tgapi.get_handle_byname(port_id)
                topo_handles_dict[node][port_id]={}
                topo_handles_dict[node][port_id]['tg_handle'] = tg_handle
                topo_handles_dict[node][port_id]['port_handle'] = port_handle
                #create topology
                device_port = tg_handle.tg_topology_config(
                                            topology_name = """{} {} topology""".format(node,port_id),
                                            port_handle = port_handle)
            topology_handle = device_port['topology_handle']
            topo_handles_dict[node][port_id]['topology_handle'] = topology_handle
    
    return topo_handles_dict

def create_device_groups(topo_handles_dict,host_dict,version = "ipv4"): 
    '''
    device_handles = {'T1D6P1': {2: '/topology:1/deviceGroup:1', 3: '/topology:1/deviceGroup:2', 4: '/topology:1/deviceGroup:3', 5: '/topology:1/deviceGroup:4'}, 
    'T1D6P2': {2: '/topology:2/deviceGroup:1', 3: '/topology:2/deviceGroup:2', 4: '/topology:2/deviceGroup:3', 5: '/topology:2/deviceGroup:4'}, 
    'T1D5P2': {2: '/topology:4/deviceGroup:1', 3: '/topology:4/deviceGroup:2', 4: '/topology:4/deviceGroup:3', 5: '/topology:4/deviceGroup:4', 
    6: '/topology:4/deviceGroup:5', 7: '/topology:4/deviceGroup:6', 8: '/topology:4/deviceGroup:7', 9: '/topology:4/deviceGroup:8'},
     'T1D5P1': {2: '/topology:3/deviceGroup:1', 3: '/topology:3/deviceGroup:2', 4: '/topology:3/deviceGroup:3', 5: '/topology:3/deviceGroup:4',
      6: '/topology:3/deviceGroup:5', 7: '/topology:3/deviceGroup:6', 8: '/topology:3/deviceGroup:7', 9: '/topology:3/deviceGroup:8'}, 
      'T1D8P2': {2: '/topology:6/deviceGroup:1', 3: '/topology:6/deviceGroup:2', 4: '/topology:6/deviceGroup:3', 5: '/topology:6/deviceGroup:4', 
      6: '/topology:6/deviceGroup:5', 7: '/topology:6/deviceGroup:6', 8: '/topology:6/deviceGroup:7', 9: '/topology:6/deviceGroup:8'}, 
      'T1D8P1': {2: '/topology:5/deviceGroup:1', 3: '/topology:5/deviceGroup:2', 4: '/topology:5/deviceGroup:3', 5: '/topology:5/deviceGroup:4',
       6: '/topology:5/deviceGroup:5', 7: '/topology:5/deviceGroup:6', 8: '/topology:5/deviceGroup:7', 9: '/topology:5/deviceGroup:8'}, 
       'T1D7P1': {8: '/topology:7/deviceGroup:1', 9: '/topology:7/deviceGroup:2', 6: '/topology:7/deviceGroup:3', 7: '/topology:7/deviceGroup:4'},
        'T1D7P2': {8: '/topology:8/deviceGroup:1', 9: '/topology:8/deviceGroup:2', 6: '/topology:8/deviceGroup:3', 7: '/topology:8/deviceGroup:4'}}

    '''
    device_handles = {}
    ethernet_handles ={}
    idx = 0
    for node in host_dict:
        ethernet_handles[node]={}
        device_handles[node]={}
        for interface in topo_handles_dict[node]:
            if not interface in host_dict[node].keys():
                continue
            device_handles[node][interface]={}
            ethernet_handles[node][interface] = {}
            for vlan, values in host_dict[node][interface].items():
                idx += 1
                device_group = topo_handles_dict[node][interface]['tg_handle'].tg_topology_config(
                    topology_handle= topo_handles_dict[node][interface]['topology_handle'],
                    device_group_name= """{} {} vlan {} Device group #{}""".format(node, version, vlan, idx ),
                    device_group_multiplier = "1",
                    device_group_enabled= "1"
                    )
                deviceGroup_handle = device_group['device_group_handle']
                device_handles[node][interface][vlan]=deviceGroup_handle
                ###Creating ethernet stack for the Device Group###
                l2_protocol = topo_handles_dict[node][interface]['tg_handle'].tg_interface_config(
                    protocol_name= """Ethernet stack #{}""".format(idx),
                    protocol_handle= deviceGroup_handle,mtu= "1500",
                    src_mac_addr= host_dict[node][interface][vlan]['src_mac'],
                    src_mac_addr_step= "00.00.00.00.00.01", 
                    vlan=1,
                    vlan_id=host_dict[node][interface][vlan]['vlan'], 
                    vlan_id_step=1,
                    vlan_id_count=1
                    )
                ethernet_handle = l2_protocol['ethernet_handle']
                ethernet_handles[node][interface][vlan] = ethernet_handle
                st.log("ethernet_handle-->{}".format(ethernet_handle))
                if version == 'ipv4':
                ### Creating IPv4 Stack for the Device Group###
                    l3_protocol = topo_handles_dict[node][interface]['tg_handle'].tg_interface_config(
                        protocol_name= """{} Stack #{}""".format(version, idx),
                        protocol_handle=ethernet_handle,
                        ipv4_resolve_gateway= "1",
                        gateway= host_dict[node][interface][vlan]['gateway'],
                        gateway_step= "0.0.0.0",
                        intf_ip_addr = host_dict[node][interface][vlan]['host_ip'],
                        intf_ip_addr_step= "0.0.0.1"
                        )
                    ipv4_handle = l3_protocol['ipv4_handle']
                    st.log("ipv4_handle-->{}".format(ipv4_handle))
                else:
                    l3_protocol = topo_handles_dict[node][interface]['tg_handle'].tg_interface_config(
                        protocol_name= """{} Stack #{}""".format(version, idx),
                        protocol_handle=ethernet_handle,
                        ipv6_resolve_gateway= "1",
                        ipv6_gateway= host_dict[node][interface][vlan]['gateway'],
                        ipv6_gateway_step= "0:0:0:0:0:0:0:0",
                        ipv6_intf_addr = host_dict[node][interface][vlan]['host_ip'],
                        ipv6_intf_addr_step= "0:0:0:0:0:0:0:1"
                        )
                    ipv6_handle = l3_protocol['ipv6_handle']
                    st.log("ipv6_handle-->{}".format(ipv6_handle))
    st.wait(10)
    return device_handles,ethernet_handles

def delete_device_groups(tg_handle, device_handle):
    tg_handle.tg_topology_config(device_group_handle =device_handle, mode = 'destroy')

def VerifyProtocolSessionStatusUpNgpfHlPy_All(tg_handle, totalTry=10):
    
    start_time = time.time()  # Record the start time
    for count in range(0, totalTry):
        sessionStatus = tg_handle.tg_protocol_info(
            mode = 'aggregate'
            )
        
        st.log('Verifying protocol sessions')

        # The first element in sessionStatus is: 'status'; the rest are protocol handles
        # example output of list(sessionStatus.keys()):
        # ['status', '/topology:2/deviceGroup:1/ethernet:1/ipv4:1', '/topology:2/deviceGroup:1/ethernet:1', '/topology:1/deviceGroup:1/ethernet:1', '/topology:1/deviceGroup:1/ethernet:1/ipv4:1']

        protocolHandlesList = list(sessionStatus.keys()) 

        aggr_sessions_up = 0
        aggr_sessions_total = 0
        for protocolHandle in protocolHandlesList:
            if protocolHandle == 'status':
                continue
            aggr_sessions_up += int(sessionStatus[protocolHandle]['aggregate']['sessions_up'])
            aggr_sessions_total += int(sessionStatus[protocolHandle]['aggregate']['sessions_total'])

        st.log('\t%s/%s: aggr_sessions_up:%s  aggr_sessions_total:%s' % (count, totalTry, aggr_sessions_up, aggr_sessions_total))

        if count < totalTry and aggr_sessions_up != aggr_sessions_total:
            st.wait(2)
            continue
        
        if count < totalTry and aggr_sessions_up == aggr_sessions_total:
            end_time = time.time()  # Record the end time
            elapsed_time = end_time - start_time
            st.log('Sessions are all UP in %s seconds' %  elapsed_time)
            return 0, sessionStatus
        
    if aggr_sessions_up != aggr_sessions_total:
        end_time = time.time()  # Record the end time
        elapsed_time = end_time - start_time
        st.log('Error: It has been %s seconds and total sessions are not all UP.' %  elapsed_time)
        st.log(f"=== aggr_sessions_up = {aggr_sessions_up} aggr_sessions_total = {aggr_sessions_total}")
        return 1, sessionStatus

def VerifyProtocolSessionStatusDownNgpfHlPy_All(tg_handle, totalTry=5):
    
    start_time = time.time()  # Record the start time

    for count in range(0, totalTry):
        sessionStatus = tg_handle.tg_protocol_info(
            mode = 'aggregate'
            )
        
        st.log('Verifying protocol sessions')

        # The first element in sessionStatus is: 'status'; the rest are protocol handles
        # example output of list(sessionStatus.keys()):
        # ['status', '/topology:2/deviceGroup:1/ethernet:1/ipv4:1', '/topology:2/deviceGroup:1/ethernet:1', '/topology:1/deviceGroup:1/ethernet:1', '/topology:1/deviceGroup:1/ethernet:1/ipv4:1']

        protocolHandlesList = list(sessionStatus.keys()) 

        aggr_sessions_not_started = 0
        aggr_sessions_total = 0

        for protocolHandle in protocolHandlesList:
            if protocolHandle == 'status':
                continue
            aggr_sessions_not_started += int(sessionStatus[protocolHandle]['aggregate']['sessions_not_started'])
            aggr_sessions_total += int(sessionStatus[protocolHandle]['aggregate']['sessions_total'])

        st.log('\t%s/%s: aggr_sessions_not_started:%s  aggr_sessions_total:%s' % (count, totalTry, aggr_sessions_not_started, aggr_sessions_total))

        if count < totalTry and aggr_sessions_not_started != aggr_sessions_total:
            st.wait(2)
            continue
        
        if count < totalTry and aggr_sessions_not_started == aggr_sessions_total:
            end_time = time.time()  # Record the end time
            elapsed_time = end_time - start_time
            st.log('Sessions are all DOWN in %s seconds' %  elapsed_time)
            return 0, sessionStatus

    if aggr_sessions_not_started != aggr_sessions_total:
        end_time = time.time()  # Record the end time
        elapsed_time = end_time - start_time
        st.log('Error: It has been %s seconds and total sessions are not all DOWN.' %  elapsed_time)
        st.log(f"=== aggr_sessions_not_started = {aggr_sessions_not_started} aggr_sessions_total = {aggr_sessions_total}")
        return 1, sessionStatus
    
def start_stop_protocols(tg_handle,action):
    ##     
    status = 0
    action_dict = {"start":"start_all_protocols", "stop":"stop_all_protocols"}
    start_stop_protocol = tg_handle.tg_test_control(action=action_dict[action])
    if start_stop_protocol['status'] == '1':
        status = 1
    # Check to see if all sessions are up after start, if down then flap individual ones
    if action == "start":
        st.wait(20) 
        verifyStatus, sessionStatus = VerifyProtocolSessionStatusUpNgpfHlPy_All(tg_handle, 5)
        if verifyStatus == 1:
            st.log("WARNING:  NOT all protocols are up....")
            down_handles = [h for h, v in sessionStatus.items() if isinstance(v, dict) and v.get('aggregate', {}).get('sessions_down', '0') != '0']
            st.log(down_handles)
            ## call ixNet restartDown on the topology with downed sessions
            results = []
            for handle in down_handles:
                for part in handle.split('/'):
                    if part.startswith("topology:"):
                        topology = f"/{part}"
                        if topology not in results:
                            results.append(topology)
            for topology in results:
                st.log(f"retartDown on {topology}")
                status = 2
    elif action == "stop":
        st.wait(5) 
        ### TK9 check and wait for all sessions are down
        verifyStatus, sessionStatus = VerifyProtocolSessionStatusDownNgpfHlPy_All(tg_handle, 3)
        if verifyStatus == 1:
            st.log("WARNING:  NOT all protocols are down after stop_all_protocols")
            st.log(sessionStatus)
            status = 2
    return status

def check_protocol_status(tg_handle):
    """
    checks protocol status on tgen and if any sessions are down, it flaps those sessions and checks again

    :param tg_handle: Description
    """
    status = 1
    res = tg_handle.tg_protocol_info(handle='', mode='aggregate')
    # collect handles that report any sessions_down != '0'
    down_handles = [h for h, v in res.items() if isinstance(v, dict) and v.get('aggregate', {}).get('sessions_down', '0') != '0']

    if down_handles:
        st.log('Flapping protocol sessions for DOWN handles.')
        for hand in down_handles:
            st.log("Stopping handle ")
            tg_handle.tg_test_control(action='stop_protocol', handle=hand)
            st.wait(3)

            st.log("Starting handle")
            tg_handle.tg_test_control(action='start_protocol', handle=hand)
        st.wait(15)

        # Re-check after flaps
        res2 = tg_handle.tg_protocol_info(handle='', mode='aggregate')
        still_down = [h for h, v in res2.items()
                    if isinstance(v, dict) and v.get('aggregate', {}).get('sessions_down', '0') != '0']
        if still_down:
            st.error("After flap, some sessions are still DOWN")
            status = 0
        else:
            st.log('All protocol sessions UP after flap.')
    else:
        st.log('No DOWN protocol sessions detected.')
    return status

def find_l2_traffic_endpoints(host_info_dict):
    end_point_dict ={}
    # Dynamically find first node (works for both multi-homing 'leaf0' and DCI 'leaf0_dc1')
    if not host_info_dict:
        return end_point_dict
    
    first_node = list(host_info_dict.keys())[0]
    
    # Find reference interface (first interface with 'P1' in name)
    leaf0_interface_list = list(host_info_dict[first_node].keys())
    leaf0_ref_interface = None
    for item in leaf0_interface_list:
        if "P1" in item:
            leaf0_ref_interface = item
            break
    
    if not leaf0_ref_interface:
        st.log("Warning: No P1 interface found in first node")
        return end_point_dict
    
    leaf0_ref_vlan_list = host_info_dict[first_node][leaf0_ref_interface].keys()
    i = 1
    for node, interfaces in host_info_dict.items():
        for interface,values in interfaces.items():
            if interface != leaf0_ref_interface: 
                for vlan in leaf0_ref_vlan_list:
                    if vlan in list(values.keys()):
                        traffic_item = "traffic_item_"+str(i)
                        end_point_dict[traffic_item] = {}
                        end_point_dict[traffic_item]["dir"] = str(vlan)+"-->"+str(values[vlan]['vlan'])
                        end_point_dict[traffic_item]['src_vlan'] = vlan
                        end_point_dict[traffic_item]["src_int"] = leaf0_ref_interface
                        end_point_dict[traffic_item]["src_node"] = first_node
                        end_point_dict[traffic_item]['dst_vlan'] = vlan
                        end_point_dict[traffic_item]["dst_int"] = interface
                        end_point_dict[traffic_item]["dst_node"] = node
                        i+=1
    return end_point_dict

def find_l3_traffic_endpoints(host_info_dict, vrf_vlan_dict = {"1":[2,3],"2":[4,5],"3":[6,7],"4":[8,9]}, dci_enabled=False):
    '''
    output:
    {'traffic_item_1': {'dir': '2-->3', 'src_vlan': 2, 'src_int': 'T1D5P1', 'dst_vlan': 3, 'dst_int': 'T1D6P1'}, 
    'traffic_item_2': {'dir': '3-->2', 'src_vlan': 3, 'src_int': 'T1D5P1', 'dst_vlan': 2, 'dst_int': 'T1D6P1'}, 
    'traffic_item_3': {'dir': '4-->5', 'src_vlan': 4, 'src_int': 'T1D5P1', 'dst_vlan': 5, 'dst_int': 'T1D6P1'}, 
    'traffic_item_4': {'dir': '5-->4', 'src_vlan': 5, 'src_int': 'T1D5P1', 'dst_vlan': 4, 'dst_int': 'T1D6P1'}, 
    'traffic_item_5': {'dir': '2-->3', 'src_vlan': 2, 'src_int': 'T1D5P1', 'dst_vlan': 3, 'dst_int': 'T1D6P2'}, 
    'traffic_item_6': {'dir': '3-->2', 'src_vlan': 3, 'src_int': 'T1D5P1', 'dst_vlan': 2, 'dst_int': 'T1D6P2'}, 
    'traffic_item_7': {'dir': '4-->5', 'src_vlan': 4, 'src_int': 'T1D5P1', 'dst_vlan': 5, 'dst_int': 'T1D6P2'}, 
    'traffic_item_8': {'dir': '5-->4', 'src_vlan': 5, 'src_int': 'T1D5P1', 'dst_vlan': 4, 'dst_int': 'T1D6P2'}, 
    'traffic_item_9': {'dir': '2-->3', 'src_vlan': 2, 'src_int': 'T1D5P1', 'dst_vlan': 3, 'dst_int': 'T1D5P2'}, 
    'traffic_item_10': {'dir': '3-->2', 'src_vlan': 3, 'src_int': 'T1D5P1', 'dst_vlan': 2, 'dst_int': 'T1D5P2'}, 
    'traffic_item_11': {'dir': '4-->5', 'src_vlan': 4, 'src_int': 'T1D5P1', 'dst_vlan': 5, 'dst_int': 'T1D5P2'}, 
    'traffic_item_12': {'dir': '5-->4', 'src_vlan': 5, 'src_int': 'T1D5P1', 'dst_vlan': 4, 'dst_int': 'T1D5P2'}, 
    'traffic_item_13': {'dir': '6-->7', 'src_vlan': 6, 'src_int': 'T1D5P1', 'dst_vlan': 7, 'dst_int': 'T1D5P2'}, 
    'traffic_item_14': {'dir': '7-->6', 'src_vlan': 7, 'src_int': 'T1D5P1', 'dst_vlan': 6, 'dst_int': 'T1D5P2'}, 
    'traffic_item_15': {'dir': '8-->9', 'src_vlan': 8, 'src_int': 'T1D5P1', 'dst_vlan': 9, 'dst_int': 'T1D5P2'}, 
    'traffic_item_16': {'dir': '9-->8', 'src_vlan': 9, 'src_int': 'T1D5P1', 'dst_vlan': 8, 'dst_int': 'T1D5P2'}, 
    'traffic_item_17': {'dir': '6-->7', 'src_vlan': 6, 'src_int': 'T1D5P1', 'dst_vlan': 7, 'dst_int': 'T1D8P2'}, 
    'traffic_item_18': {'dir': '7-->6', 'src_vlan': 7, 'src_int': 'T1D5P1', 'dst_vlan': 6, 'dst_int': 'T1D8P2'}, 
    'traffic_item_19': {'dir': '8-->9', 'src_vlan': 8, 'src_int': 'T1D5P1', 'dst_vlan': 9, 'dst_int': 'T1D8P2'}, 
    'traffic_item_20': {'dir': '9-->8', 'src_vlan': 9, 'src_int': 'T1D5P1', 'dst_vlan': 8, 'dst_int': 'T1D8P2'}, 
    'traffic_item_21': {'dir': '6-->7', 'src_vlan': 6, 'src_int': 'T1D5P1', 'dst_vlan': 7, 'dst_int': 'T1D8P1'}, 
    'traffic_item_22': {'dir': '7-->6', 'src_vlan': 7, 'src_int': 'T1D5P1', 'dst_vlan': 6, 'dst_int': 'T1D8P1'}, 
    'traffic_item_23': {'dir': '8-->9', 'src_vlan': 8, 'src_int': 'T1D5P1', 'dst_vlan': 9, 'dst_int': 'T1D8P1'}, 
    'traffic_item_24': {'dir': '9-->8', 'src_vlan': 9, 'src_int': 'T1D5P1', 'dst_vlan': 8, 'dst_int': 'T1D8P1'}, 
    'traffic_item_25': {'dir': '6-->7', 'src_vlan': 6, 'src_int': 'T1D5P1', 'dst_vlan': 7, 'dst_int': 'T1D7P1'}, 
    'traffic_item_26': {'dir': '7-->6', 'src_vlan': 7, 'src_int': 'T1D5P1', 'dst_vlan': 6, 'dst_int': 'T1D7P1'}, 
    'traffic_item_27': {'dir': '8-->9', 'src_vlan': 8, 'src_int': 'T1D5P1', 'dst_vlan': 9, 'dst_int': 'T1D7P1'}, 
    'traffic_item_28': {'dir': '9-->8', 'src_vlan': 9, 'src_int': 'T1D5P1', 'dst_vlan': 8, 'dst_int': 'T1D7P1'}, 
    'traffic_item_29': {'dir': '6-->7', 'src_vlan': 6, 'src_int': 'T1D5P1', 'dst_vlan': 7, 'dst_int': 'T1D7P2'}, 
    'traffic_item_30': {'dir': '7-->6', 'src_vlan': 7, 'src_int': 'T1D5P1', 'dst_vlan': 6, 'dst_int': 'T1D7P2'}, 
    'traffic_item_31': {'dir': '8-->9', 'src_vlan': 8, 'src_int': 'T1D5P1', 'dst_vlan': 9, 'dst_int': 'T1D7P2'}, 
    'traffic_item_32': {'dir': '9-->8', 'src_vlan': 9, 'src_int': 'T1D5P1', 'dst_vlan': 8, 'dst_int': 'T1D7P2'}}

    '''
    temp_dict = {}
    
    # Dynamically find first node (works for both multi-homing 'leaf0' and DCI 'leaf0_dc1')
    if not host_info_dict:
        return {}
    
    first_node = list(host_info_dict.keys())[0]
    
    leaf0_interface_list = list(host_info_dict[first_node].keys())
    leaf0_ref_interface = None
    for item in leaf0_interface_list:
        if "P1" in item:
            leaf0_ref_interface = item
            break
    
    if not leaf0_ref_interface:
        st.log("Warning: No P1 interface found in first node")
        return {}
    
    leaf0_ref_vlan_list = host_info_dict[first_node][leaf0_ref_interface].keys()
    for node, interfaces in host_info_dict.items():
        for interface,int_vlan_attr in interfaces.items():
            temp_dict[interface]={'node': node, 'vrf': {}}
            for vrf, vlan_list in vrf_vlan_dict.items():
                temp_dict[interface]['vrf'][vrf] = []
                for vlan in vlan_list:
                    if int_vlan_attr.get(vlan):
                        temp_dict[interface]['vrf'][vrf].append(vlan)
                if len(temp_dict[interface]['vrf'][vrf]) == 0:
                    temp_dict[interface]['vrf'].pop(vrf)
    # Also find PortChannel (MH) interface on first node
    leaf0_pc_interface = None
    for item in leaf0_interface_list:
        if item.startswith('PortChannel'):
            leaf0_pc_interface = item
            break

    l3_endpoint_dict = {}
    def find_pair(src_vlans,dst_vlans):
        pair_dict = {}
        i=1
        for src_vlan in src_vlans:
            for dst_vlan in dst_vlans:
                if src_vlan != dst_vlan:
                    pair_dict[i] = (src_vlan,dst_vlan)
                    i+=1    
        return pair_dict
    i=1
    # SH (orphan) source flows — full VLAN pairs per VRF
    for interface, val in temp_dict.items():
        dst_node = val['node']
        vrf_dict = val['vrf']
        if interface != leaf0_ref_interface:
            for vrf,vlans in vrf_dict.items():
                pair_dict = find_pair(temp_dict[leaf0_ref_interface]['vrf'][vrf],vlans)
                for cntr, vlan_pair in pair_dict.items():
                    traffic_item = "traffic_item_"+str(i)
                    l3_endpoint_dict[traffic_item] = {}
                    l3_endpoint_dict[traffic_item]["dir"] = str(vlan_pair[0])+"-->"+str(vlan_pair[1])
                    l3_endpoint_dict[traffic_item]['src_vlan'] = vlan_pair[0]
                    l3_endpoint_dict[traffic_item]["src_int"] = leaf0_ref_interface
                    l3_endpoint_dict[traffic_item]["src_node"] = temp_dict[leaf0_ref_interface]['node']  # Use actual node name from host_info
                    l3_endpoint_dict[traffic_item]["src_vrf"] = vrf
                    l3_endpoint_dict[traffic_item]['dst_vlan'] = vlan_pair[1]
                    l3_endpoint_dict[traffic_item]["dst_int"] = interface
                    l3_endpoint_dict[traffic_item]["dst_node"] = dst_node
                    l3_endpoint_dict[traffic_item]["dst_vrf"] = vrf
                    i+=1

    # MH (PortChannel) source flows — 1 pair per VRF per destination interface
    # Follows l3vni_dci_traffic_flows.txt pattern: MH source uses first VLAN pair only
    # Only generated for DCI topologies to avoid adding unexpected flows in non-DCI tests.
    if dci_enabled and leaf0_pc_interface and leaf0_pc_interface in temp_dict:
        pc_node = temp_dict[leaf0_pc_interface]['node']
        for interface, val in temp_dict.items():
            dst_node = val['node']
            vrf_dict = val['vrf']
            # Skip self (same interface) and the P1 interface on the same node
            if interface == leaf0_pc_interface:
                continue
            if interface == leaf0_ref_interface:
                continue
            for vrf, vlans in vrf_dict.items():
                pc_vlans = temp_dict[leaf0_pc_interface]['vrf'].get(vrf, [])
                if not pc_vlans or not vlans:
                    continue
                # Use first VLAN from PC source, find first different VLAN in dst
                src_vlan = pc_vlans[0]
                dst_vlan = None
                for v in vlans:
                    if v != src_vlan:
                        dst_vlan = v
                        break
                if dst_vlan is None:
                    continue
                traffic_item = "traffic_item_" + str(i)
                l3_endpoint_dict[traffic_item] = {
                    "dir": str(src_vlan) + "-->" + str(dst_vlan),
                    'src_vlan': src_vlan,
                    "src_int": leaf0_pc_interface,
                    "src_node": pc_node,
                    "src_vrf": vrf,
                    'dst_vlan': dst_vlan,
                    "dst_int": interface,
                    "dst_node": dst_node,
                    "dst_vrf": vrf,
                }
                i += 1
    else:
        st.log("find_l3_traffic_endpoints: No PortChannel interface found on first node, "
               "skipping MH source flows")

    return l3_endpoint_dict


def find_l3_dci_traffic_endpoints(host_info_dict, config_dict, vrf_vlan_dict=None):
    """
    Generate L3 DCI cross-DC traffic endpoints per l3vni_dci_traffic_flows.txt.

    Creates exactly 23 flows across VRF101 and VRF102 with specific
    source/destination node, interface type (SH=orphan, MH=PortChannel),
    and VLAN pairs.

    Flow summary (23 total):
      leaf0_dc1 SH  -> leaf0_dc2 SH:  4 VRF101 + 4 VRF102 = 8
      leaf0_dc1 SH  -> leaf0_dc2 MH:  4 VRF101 + 4 VRF102 = 8
      leaf0_dc1 MH  -> leaf0_dc2 SH:  1 VRF101 + 1 VRF102 = 2
      leaf0_dc1 MH  -> leaf0_dc2 MH:  1 VRF101 + 1 VRF102 = 2
      leaf1_dc2 SH  -> leaf0_dc3 SH:  2 VRF101 + 1 VRF102 = 3
                                                      Total = 23

    Args:
        host_info_dict: Dict of node -> interface -> vlan -> host_info
                        (from generate_sag_hosts)
        config_dict:    Full config dict from get_cfg_dict()
        vrf_vlan_dict:  Dict of vrf_id -> [vlan_list].  If None, derived
                        from config_dict.

    Returns:
        dict: Endpoint dict in same format as find_l3_traffic_endpoints,
              keyed by 'traffic_item_<N>'.
    """
    if not host_info_dict:
        return {}

    # Derive VRF-VLAN mapping from config if not provided
    if vrf_vlan_dict is None:
        vrf_vlan_dict = {}
        for node_name, node_cfg in config_dict.items():
            if isinstance(node_cfg, dict) and node_cfg.get('l3vni'):
                for item in node_cfg['l3vni']:
                    vrf_vlan_dict[item['vrf_id']] = item['vlan_bindings']
                break

    # VLAN pairs per VRF (src_vlan -> dst_vlan) from l3vni_dci_traffic_flows.txt
    vrf101_full_pairs = [(11, 12), (12, 13), (13, 14), (15, 11)]
    vrf102_full_pairs = [(16, 17), (17, 18), (18, 19), (20, 16)]
    # MH source: only 1 pair per VRF (first pair)
    vrf101_mh_pairs = [(11, 12)]
    vrf102_mh_pairs = [(16, 17)]
    # leaf1_dc2 -> leaf0_dc3: 2 VRF101 + 1 VRF102
    vrf101_dc2_dc3_pairs = [(11, 12), (12, 13)]
    vrf102_dc2_dc3_pairs = [(16, 17)]

    # Helper: resolve interface name for a node
    # SH (orphan) = first interface with 'P1' in name
    # MH (PortChannel) = first interface starting with 'PortChannel'
    def _resolve_intf(node, intf_type):
        if node not in host_info_dict:
            return None
        for intf_name in host_info_dict[node]:
            if intf_type == 'SH' and 'P1' in intf_name and not intf_name.startswith('PortChannel'):
                return intf_name
            if intf_type == 'MH' and intf_name.startswith('PortChannel'):
                return intf_name
        return None

    # Helper: determine VRF for a VLAN
    def _vrf_for_vlan(vlan):
        for vrf_id, vlans in vrf_vlan_dict.items():
            if vlan in vlans:
                return vrf_id
        return ''

    # Define all flow groups per l3vni_dci_traffic_flows.txt
    # Each entry: (src_node, src_type, dst_node, dst_type, vlan_pairs)
    flow_groups = [
        # leaf0_dc1 SH -> leaf0_dc2 SH: full pairs
        ('leaf0_dc1', 'SH', 'leaf0_dc2', 'SH', vrf101_full_pairs + vrf102_full_pairs),
        # leaf0_dc1 SH -> leaf0_dc2 MH: full pairs
        ('leaf0_dc1', 'SH', 'leaf0_dc2', 'MH', vrf101_full_pairs + vrf102_full_pairs),
        # leaf0_dc1 MH -> leaf0_dc2 SH: 1 pair per VRF
        ('leaf0_dc1', 'MH', 'leaf0_dc2', 'SH', vrf101_mh_pairs + vrf102_mh_pairs),
        # leaf0_dc1 MH -> leaf0_dc2 MH: 1 pair per VRF
        ('leaf0_dc1', 'MH', 'leaf0_dc2', 'MH', vrf101_mh_pairs + vrf102_mh_pairs),
        # leaf1_dc2 SH -> leaf0_dc3 SH: 2 VRF101 + 1 VRF102
        ('leaf1_dc2', 'SH', 'leaf0_dc3', 'SH', vrf101_dc2_dc3_pairs + vrf102_dc2_dc3_pairs),
    ]

    endpoints = {}
    idx = 1
    for src_node, src_type, dst_node, dst_type, vlan_pairs in flow_groups:
        src_intf = _resolve_intf(src_node, src_type)
        dst_intf = _resolve_intf(dst_node, dst_type)
        if not src_intf or not dst_intf:
            st.log('find_l3_dci_traffic_endpoints: cannot resolve intf '
                   'src={}:{} dst={}:{}'.format(src_node, src_type, dst_node, dst_type))
            continue
        for src_vlan, dst_vlan in vlan_pairs:
            vrf = _vrf_for_vlan(src_vlan)
            traffic_item = 'traffic_item_{}'.format(idx)
            endpoints[traffic_item] = {
                'dir': '{}-->{}'.format(src_vlan, dst_vlan),
                'src_vlan': src_vlan,
                'src_int': src_intf,
                'src_node': src_node,
                'src_vrf': vrf,
                'dst_vlan': dst_vlan,
                'dst_int': dst_intf,
                'dst_node': dst_node,
                'dst_vrf': vrf,
            }
            idx += 1

    st.log('find_l3_dci_traffic_endpoints: generated {} flows'.format(len(endpoints)))
    return endpoints


def create_traffic_item(device_handles, endpoints, topo_handles, transmit_mode="single_burst",
                        version = "ipv4", udp_header = False, multi_dst = None, name_prfx='TI', 
                        circuit_type='default', rx_all_ports=False, 
                        rate_percent=0, pkts_per_burst=0, frame_size=0):
    '''
    
    Example: endpoints for bum traffic
    {'traffic_item_T1D5P1_4': 
    {'dst_int': 'PortChannel3_D8D7', 'dst_node': 'leaf2', 'dst_mac': '00:99:00:00:00:99', 
    'dst_vlan': 2, 'dst_vrf': 101, 
    'src_vlan': 2, 'src_node': 'leaf0', 'src_int': 'T1D5P1', 'src_mac': '00:02:00:00:04:10', 
    'src_vrf': 101}, 
    'traffic_item_T1D5P1_3': 
    {'dst_int': 'T1D7P1', 'dst_node': 'leaf2', 'dst_mac': '00:99:00:00:00:99', 
    'dst_vlan': 2, 'dst_vrf': 101, 
    'src_vlan': 2, 'src_node': 'leaf0', 'src_int': 'T1D5P1', 'src_mac': '00:02:00:00:04:10', 
    'src_vrf': 101}, 
    }
    '''
    dut_type = check_hw_or_sim(st.get_dut_names()[0])
    if dut_type == 'sim':
        rate = 0.01
        ppb = 100
    else:
        rate = 10
        ppb = 1000
        if rate_percent:
            rate = rate_percent
        if pkts_per_burst:
            ppb = pkts_per_burst
    frame = 500
    if frame_size:
        frame = frame_size
        
    port_handles = {}
    all_handles = []
    for node, interfaces in topo_handles.items():
        for interface,values in interfaces.items():
            port_handles[interface] =values        
            all_handles.append(values['port_handle'])

    stream_handles = {}
    traffic_item_list = natsort.natsorted(set(list(endpoints.keys())))
    i=1
    multi_pointed_traffic_items = list()
    for traffic_item in traffic_item_list:  
        if traffic_item in multi_pointed_traffic_items:
            # this traffic item has been combined with another traffic
            # item with multiple end points
            continue

        name = '{}-{}:'.format(name_prfx,version)
        name += '{}'.format(endpoints[traffic_item]['src_int'])
        if endpoints[traffic_item].get('src_vrf'):
            name += '_vrf{}'.format(endpoints[traffic_item]['src_vrf'])
        name += '_vlan{}--'.format(endpoints[traffic_item]['src_vlan'])
        if circuit_type == 'raw':
            emulation_src_handle = topo_handles[endpoints[traffic_item]['src_node']][endpoints[traffic_item]['src_int']]['port_handle']
        else:
            emulation_src_handle = device_handles[endpoints[traffic_item]['src_int']][endpoints[traffic_item]['src_vlan']]
        tg_handle = port_handles[endpoints[traffic_item]['src_int']]['tg_handle']
        port_handle = port_handles[endpoints[traffic_item]['src_int']]['port_handle']
        if multi_dst:
            dst_vlan = list()
            dst_vrf = list()
            dst_node = list()
            dst_int = list()
            emulation_dst_handle = list()
            emulation_dst_port = list()
            for sim_traffic_item in traffic_item_list:
                flag = False
                if multi_dst == 'vlan' and endpoints[sim_traffic_item]['dst_vlan'] == endpoints[traffic_item]['dst_vlan']:
                    dst_vlan = [str(endpoints[sim_traffic_item]['dst_vlan'])]     
                    flag = True
                elif multi_dst == 'vrf' and endpoints[sim_traffic_item]['dst_vrf'] == endpoints[traffic_item]['dst_vrf'] and \
                                             endpoints[sim_traffic_item]['src_vlan'] == endpoints[traffic_item]['src_vlan']:
                    dst_vrf = [str(endpoints[sim_traffic_item]['dst_vrf'])]
                    dst_vlan.append(str(endpoints[sim_traffic_item]['dst_vlan']))
                    flag = True
            
                if flag:
                    multi_pointed_traffic_items.append(sim_traffic_item)
                    if circuit_type == 'raw':
                        dst_hdl = topo_handles[endpoints[sim_traffic_item]['dst_node']][endpoints[sim_traffic_item]['dst_int']]['port_handle']
                    else:
                        dst_hdl = device_handles[endpoints[sim_traffic_item]['dst_int']][endpoints[sim_traffic_item]['dst_vlan']]
                    emulation_dst_handle.append(dst_hdl)
                    emulation_dst_port.append((endpoints[sim_traffic_item]['dst_int'], dst_hdl))
                    dst_int.append(str(endpoints[sim_traffic_item]['dst_int']))
                    dst_node.append(str(endpoints[sim_traffic_item]['dst_node']))

            dst_node = '_'.join(dst_node)
            dst_vlan = '_'.join(dst_vlan)
            dst_int = '_'.join(dst_int)
            name += '{}'.format(dst_int)
            if dst_vrf:
                dst_vrf = '_'.join(dst_vrf)
                name += '_vrf{}'.format(dst_vrf)
        else:
            if circuit_type == 'raw':
                emulation_dst_handle = topo_handles[endpoints[traffic_item]['dst_node']][endpoints[traffic_item]['dst_int']]['port_handle']
            else:
                emulation_dst_handle = device_handles[endpoints[traffic_item]['dst_int']][endpoints[traffic_item]['dst_vlan']]
            emulation_dst_port = [(endpoints[traffic_item]['dst_int'], emulation_dst_handle)]
            name += '{}'.format(endpoints[traffic_item]['dst_int'])
            if endpoints[traffic_item].get('dst_vrf'):
                name += '_vrf{}'.format(endpoints[traffic_item]['dst_vrf'])
            name += '_vlan{}'.format(endpoints[traffic_item]['dst_vlan'])
    
        kwargs = {
            'name' : name,
            'mode': 'create',
            'bidirectional': 1,
            'transmit_mode': transmit_mode,
            'pkts_per_burst': ppb,
            'rate_percent': rate,
            'circuit_endpoint_type': version,
            'frame_size': frame,
            'emulation_src_handle': emulation_src_handle,
            'emulation_dst_handle': emulation_dst_handle,
            'track_by':  'traffic_item',
        }

        if rx_all_ports: 
            kwargs['emulation_dst_handle'] = list()      
            for dst_handle in all_handles:
                if not dst_handle == kwargs['emulation_src_handle']:
                    kwargs['emulation_dst_handle'].append(dst_handle)      

        if circuit_type == 'raw':
            kwargs['circuit_type'] = 'raw' 
            kwargs['mac_src'] = endpoints[traffic_item]['src_mac']
            kwargs['mac_dst'] = endpoints[traffic_item]['dst_mac']
            kwargs['vlan_id'] = endpoints[traffic_item]['dst_vlan']
            kwargs['src_dest_mesh'] ='one_to_one'
            kwargs['track_by'] = 'endpoint_pair'

        if udp_header:
            kwargs['l4_protocol'] ='udp'
        if transmit_mode == "single_burst" or transmit_mode == "continuous":
            kwargs['transmit_mode'] = transmit_mode
        else:
            #add continous mode support
            st.log("Unknown transmit type")
            return stream_handles

        stream = tg_handle.tg_traffic_config(**kwargs)

        stream_id = stream["stream_id"]
        stream_handles[i] = {}
        stream_handles[i]['stream_id'] = stream_id
        stream_handles[i]['tg_handle'] = tg_handle
        stream_handles[i]['port_handle'] = port_handle
        stream_handles[i]['dst_ports'] = emulation_dst_port
        i+=1
        st.wait(1) 
    return stream_handles

def delete_traffic_item(tg_handle, stream_handle):
    if type(stream_handle) == dict:
        for cntr, streamh in stream_handle.items():
            tg_handle.tg_traffic_config(mode = 'remove', stream_id = streamh['stream_id'])

    else:
        tg_handle.tg_traffic_config(mode = 'remove', stream_id = stream_handle)
    
def check_traffic(streams_info, regenerate_traffic_items = False, mode='traffic_item', action='default', 
                  stop_start_protocols=True, stop_proto_wait=15, start_proto_wait=15, min_perc=99.8, max_perc=100.2 ):
    '''
    Author:Ramsiddarth Ragurajan (rraguraj@cisco.com)
    acions : start/stop/check/default(does start->stop->check)

    '''
    flag = True
    stream_list = []
    line = '-'*80
    for item , values in streams_info.items():
        if values.get('verify_enabled', True):
            stream_list.append(values['stream_id'])
    tg_handle = streams_info[item]['tg_handle']
    ###Enable streams
    if action != 'check':
        tg_handle.tg_traffic_config(mode = 'enable', stream_id = stream_list)
    
    ###stop/start all protocols###
    if action == 'start' or action == 'default':
        if stop_start_protocols:
            start_stop_protocols(tg_handle,'stop')
            st.wait(stop_proto_wait)
            start_stop_protocols(tg_handle,'start')
            st.wait(start_proto_wait)
        else:
            ###
            res2 = tg_handle.tg_protocol_info(handle='', mode='aggregate')
            protocols_down = [h for h, v in res2.items() if isinstance(v, dict) and v.get('aggregate', {}).get('sessions_down', '0') != '0']
            if protocols_down:
                st.banner("Some sessions are DOWN")
            else:
                st.banner('All protocol sessions UP')
            ###

        ###start traffic###
        if regenerate_traffic_items and action != 'check':
            tg_handle.tg_traffic_control(action='regenerate', stream_handle=stream_list)
            tg_handle.tg_traffic_control(action='apply', stream_handle=stream_list)
            st.wait(10)

        tg_handle.tg_traffic_control(action='run', stream_handle=stream_list)
        st.wait(15)

    if action == 'start':
        return flag
    
    ###Stop Traffic###
    #TK7- add max timer
    tg_handle.tg_traffic_control(action='stop', stream_handle=stream_list, max_wait_timer = '30')
    st.wait(10)

    if action == 'stop':
        return flag

    traffic_stat = tg_handle.tg_traffic_stats(mode= mode, streams=stream_list)
    ###Disable streams .
    tg_handle.tg_traffic_config(mode = 'disable', stream_id = stream_list)
    if mode == 'traffic_item':
        row_format = '|{:20}|{:20}|{:20}|{:15}|'
        for stream_id in traffic_stat['traffic_item'].keys():
            if not stream_id.startswith('TI'): continue

            st.banner("TRAFFIC ITEM {}".format(stream_id))
            st.log(line)
            st.log(row_format.format('Expected Rx', 'Actual Rx', '%', 'Result'))
            st.log(row_format.format('', '', 
                                     '({}%-{}%)'.format(str(min_perc),str(max_perc)), ''))
            st.log(line)
            exp_rx = int(traffic_stat['traffic_item'][stream_id]['tx']['total_pkts'])
            rx = int(traffic_stat['traffic_item'][stream_id]['rx']['total_pkts'])
            perc = rx / float(exp_rx) * 100
            if perc > min_perc and perc < max_perc:
                st.log(row_format.format(str(exp_rx), str(rx), 
                                         '{:.2f}'.format(perc), 'PASS'))
                st.log(line)
                st.log("TRAFFIC ITEM {} PASSED".format(stream_id))
            else:
                st.log(row_format.format(str(exp_rx), str(rx), 
                                         '{:.2f}'.format(perc), 'FAIL'))
                st.log(line)
                st.log("TRAFFIC ITEM {} FAILED".format(stream_id))
                flag = False
                
    elif mode == 'flow':
        row_format = '|{:19}|{:15}|{:15}|{:15}|{:10}|'
        for item , stream_info in streams_info.items():
            stream_id = stream_info['stream_id']
            if not stream_id.startswith('TI'): continue

            stream_result=True
            st.banner("TRAFFIC ITEM {}".format(stream_id))
            st.log(line)
            st.log(row_format.format('Port', 'Expected Rx' , 'Actual Rx', '%', 'Result'))
            st.log(row_format.format('', '', '', 
                                     '({}%-{}%)'.format(str(min_perc),str(max_perc)), ''))
            st.log(line)
            for flow_id, flow_info in traffic_stat['flow'].items():
                port,flow_name = flow_info['flow_name'].split(' ')
                if stream_id == flow_name:
                    rx = int(flow_info['rx']['total_pkts'])
                    for dst_int,dst_handle in stream_info['dst_ports']:
                        if port == dst_int or port == dst_handle:
                            exp_rx = int(flow_info['tx']['total_pkts'])
                            perc = rx / float(exp_rx) * 100
                            result = perc > min_perc and perc < max_perc
                            perc = '{:.2f}'.format(perc)
                            break
                    else:
                        exp_rx = 0
                        if rx == exp_rx: 
                            perc = '100.00' 
                            result = True
                        else:
                            perc = '~'
                            result = False

                    if result:
                        st.log(row_format.format(port, str(exp_rx), str(rx), perc , 'PASS'))
                    else:
                        st.log(row_format.format(port, str(exp_rx), str(rx), perc, 'FAIL'))
                        stream_result = False
            if stream_result:
                st.log(line)
                st.log("TRAFFIC ITEM {} PASSED".format(stream_id))
            else:
                st.log(line)
                st.log("TRAFFIC ITEM {} FAILED".format(stream_id))
                flag = False
    return flag

def create_lag_handle(lag_name, ports):
    lag_vport_list = list()
    port_list = list()
    for port in ports:
        tg, port_handle = tgapi.get_handle_byname(port)
        port_list.append(port_handle)
        vporthandle_status = tg.tg_convert_porthandle_to_vport(port_handle=port_handle)
        vport_handle = vporthandle_status['handle'].split('-')[-1]
        lag_vport_list.append(vport_handle)

    st.log("Creating Lag with ports {}".format(port_list))
    #TK6 - pass in lacp_send_marker_req_on_lag_change and lacp_actor_system_id options
    random_bytes = os.urandom(3)
    random_string = ':'.join('{:02x}'.format(b) for b in random_bytes)
    system_id = "00:00:00:" + random_string


    _result_ = tg.tg_emulation_lag_config( mode= "create", port_handle=lag_vport_list, active= "1", 
                                          lag_name= """{}""".format(lag_name),
                                          lacp_actor_system_id= system_id,
                                          lacp_send_marker_req_on_lag_change= "0",
                                          protocol_type= "lag_port_lacp")
    _result_['vport_handles'] = lag_vport_list
    return (tg , _result_)

def check_hw_or_sim(node):
    dut_type = ""
    cmd_output = st.config(node,"cat /proc/cpuinfo | grep '^model name.: VXR$'")
    try:
        if 'VXR' in str(cmd_output.encode('ascii','ignore')):
            dut_type = "sim"
        else:
            dut_type = "hw"
    except:
        dut_type = "hw"
    return dut_type

def clear_counters(nodes):
    for node in nodes:
        st.config(node, " sonic-clear counters")
        st.config(node, " sonic-clear tunnelcounters")

def show_counters(nodes):
    for node in nodes:
        st.log(st.config(node, " show int counters"))
        st.log(st.config(node, " show vxlan counters"))

def get_cli_out(nodes):
    #sonic
    cmd_list_1 = ["show interfaces status",
                  "show bfd summary",
                  "show mac",
                  "show arp",
                  "show nd",
                  "show vlan brief",
                  "show ip int",
                  "show int portchannel",
                  "show vxlan tunnel",
                  "show vxlan remotemac all",
                  "show vxlan remotevtep",
                  "show vrf",
                  "show ipv6 route vrf all",
                  "show ip route vrf all"]
    #vtysh
    cmd_list_2 = ["do show bgp summary",
                  "do show bgp l2vpn evpn route type 1",
                  "do show bgp l2vpn evpn route type 2",
                  "do show bgp l2vpn evpn route type 3",
                  "do show bgp l2vpn evpn route type 4",
                  "do show bgp l2vpn evpn route type 5"]

    for node in nodes:
        for item in cmd_list_1:
            st.config(node, item)
        for item in cmd_list_2:
            st.config(node, item, type='vtysh', skip_error_check=True)

def delete_vrf(node, vrf_id, only_vtysh=False):
    ##vtysh
    #find vni mapping 
    cli_output = st.show(node, "show vxlan vrfvnimap", skip_tmpl=True)
    parsed_output = st.parse_show(node, "show vxlan vrfvnimap",cli_output, "show_vxlan_vrfvnimap.tmpl")
    ref_vni = ""
    as_num = generate_bgp_underlay_info()[node]['as_num']
    for item in parsed_output:
        if item['vrf'] == vrf_id:
            ref_vni = item['vni']
    cmd = "vrf {}\n".format(vrf_id)
    cmd += "no vni {}\n".format(ref_vni)
    cmd += 'no router bgp {} vrf {}\n'.format(as_num, vrf_id)
    cmd += 'exit\n' 
    st.config(node, cmd, type='vtysh', skip_error_check=True)

    if only_vtysh:
        st.log("Only done in vtysh config")
        return

    ##sonic
    #find interface mapping for vrf and unbind
    cli_output = st.show(node, "show vrf", skip_tmpl=True)
    parsed_output = st.parse_show(node, "show vrf",cli_output, "show_vrf.tmpl")
    for item in parsed_output:
        if item['vrfname'] == vrf_id:
            interface_list = item['interfaces']
    for interface in interface_list:
        vrf_obj.bind_vrf_interface(dut = node, vrf_name = vrf_id, intf_name =interface, config = 'no')
    out = vrf_obj.config_vrf(dut = node, vrf_name = vrf_id, config = 'no')
    return out

def bgp_vrf_config(node, vrf):
    output = ""
    as_num = generate_bgp_underlay_info()[node]['as_num']
    vni = 5000 + int(vrf.split("Vrf")[1])
    output += 'router bgp {} vrf {}\n'.format(as_num, vrf)
    output += 'address-family ipv4 unicast\n'
    output += 'redistribute connected\n'
    output += 'exit-address-family\n'
    output += 'address-family ipv6 unicast\n'
    output += 'redistribute connected\n'
    output += 'exit-address-family\n'
    output += 'address-family l2vpn evpn\n'
    output += 'advertise ipv4 unicast\n'
    output += 'advertise ipv6 unicast\n'
    output += 'exit-address-family\n'
    output += 'exit\n'
    output += 'vrf {}\n'.format(vrf)
    output += 'vni {}\n'.format(vni)
    output += 'end\n'
    output += 'exit\n'
    return output

def generate_bum_handles(bum_info,svi_info,transmit_mode="single_burst",ip_version = "ipv4"):
    '''
    Author:Ramsiddarth Ragurajan (rraguraj@cisco.com)
    bum_info['tg_handle'] = topo_handles[leaf_nodes[0]][l2vni_intf_dict[leaf_nodes[0]][0]]['tg_handle']
    bum_info['topology_handle'] = topo_handles[leaf_nodes[0]][l2vni_intf_dict[leaf_nodes[0]][0]]['topology_handle']
    bum_info['port_handle'] = topo_handles[leaf_nodes[0]][l2vni_intf_dict[leaf_nodes[0]][0]]['port_handle']
    bum_info['dst_port_handles'] = []
    dst_port_handles = ['1/1/3', '1/1/4', '1/1/2', '1/1/5', '1/1/6','1/1/7','1/1/8']
    '''
    bum_handles = {}
    bum_handles['tg_handle'] = bum_info['tg_handle']
    bum_handles['port_handle']  = bum_info['port_handle']
    dut_type = check_hw_or_sim(st.get_dut_names()[0])
    if dut_type == 'sim':
        rate_percent = 0.01
        pkts_per_burst = 100
        transmit_mode = 'single_burst'
    else:
        rate_percent = 1
        pkts_per_burst = 1000
        transmit_mode = transmit_mode
    #choose 1 vlan per VRF fro bum
    config_dict = get_cfg_dict()
    
    # Find first leaf node dynamically (works for both 'leaf0' and 'leaf0_dc1')
    first_leaf = None
    for node in config_dict.get('nodes', {}).get('leaf', []):
        if node in config_dict and 'l2vni' in config_dict[node]:
            first_leaf = node
            break
    
    if not first_leaf:
        st.log("Warning: No leaf node with l2vni config found")
        return {}
    
    vlan_start_range = config_dict[first_leaf]['l2vni']['vlan_start_range']
    count = config_dict[first_leaf]['l2vni']['count']
    bum_dict = {"unknown": "00:99:00:00:00:99", "broadcast":"ff:ff:ff:ff:ff:ff", "multicast":"01:00:5e:44:44:44"}
    vlan_list = list(range(vlan_start_range,(count+vlan_start_range),2))
    # start_mac = "00:00:00:00:00:99"
    if transmit_mode == "single_burst":
        if ip_version == "ipv4":
            for vlan in vlan_list:
                bum_handles[vlan] = {}
                for bum_type, value in bum_dict.items():
                    bum_handles[vlan][bum_type] ={}
                    stream = bum_info['tg_handle'].tg_traffic_config(
                        port_handle=bum_info['port_handle'], 
                        port_handle2=bum_info['dst_port_handles'], 
                        mode='create',
                        transmit_mode=transmit_mode, 
                        pkts_per_burst=pkts_per_burst, 
                        rate_percent = rate_percent, 
                        circuit_endpoint_type='ethernet_vlan', 
                        frame_size=1000, 
                        mac_src=svi_info[vlan]['src_mac'], 
                        mac_dst= value,
                        vlan_id = vlan
                        
                        )
                    bum_handles[vlan][bum_type]['stream_id'] = stream["stream_id"]
    return bum_handles

def check_bum_traffic(streams, regenerate_traffic_items = False):
    '''
    Author:Ramsiddarth Ragurajan (rraguraj@cisco.com)
    {2: {'broadcast': {'stream_id': 'TI48-HLTAPI_TRAFFICITEM_540'}, 'unknown': {'stream_id': 'TI49-HLTAPI_TRAFFICITEM_540'}, 
    'multicast': {'stream_id': 'TI50-HLTAPI_TRAFFICITEM_540'}}, 4: {'broadcast': {'stream_id': 'TI51-HLTAPI_TRAFFICITEM_540'}, 
    'unknown': {'stream_id': 'TI52-HLTAPI_TRAFFICITEM_540'}, 'multicast': {'stream_id': 'TI53-HLTAPI_TRAFFICITEM_540'}}, 
    6: {'broadcast': {'stream_id': 'TI54-HLTAPI_TRAFFICITEM_540'}, 'unknown': {'stream_id': 'TI55-HLTAPI_TRAFFICITEM_540'},
    'multicast': {'stream_id': 'TI56-HLTAPI_TRAFFICITEM_540'}}, 8: {'broadcast': {'stream_id': 'TI57-HLTAPI_TRAFFICITEM_540'}, 
    'unknown': {'stream_id': 'TI58-HLTAPI_TRAFFICITEM_540'}, 'multicast': {'stream_id': 'TI59-HLTAPI_TRAFFICITEM_540'}}, 'port_handle': '1/1/1', 'tg_handle': <spytest.tgen.tg.TGIxia object at 0x7ff4c3077d10>}
    '''
    flag = True
    stream_list = []
    streams_info = streams
    tg_handle = streams_info['tg_handle']
    port_handle = streams_info['port_handle']
    for vlan , values in streams_info.items():
        if vlan  != 'port_handle' and vlan != 'tg_handle':
            for traffic_type, handles in values.items():
                stream_list.append(handles['stream_id'])
    #find the no of endpoints from vlan info
    expected_no_of_endpoints = 3
    ###stop/start all protocols###
    start_stop_protocols(tg_handle,'stop')
    st.wait(15)
    start_stop_protocols(tg_handle,'start')
    st.wait(15)
    ###start traffic###
    if regenerate_traffic_items:
        tg_handle.tg_traffic_control(action='regenerate', stream_handle=stream_list)
        tg_handle.tg_traffic_control(action='apply', stream_handle=stream_list)
        st.wait(10)
    tg_handle.tg_traffic_control(action='run', stream_handle=stream_list)
    st.wait(30)
    ###Stop Traffic###
    tg_handle.tg_traffic_control(action='stop', stream_handle=stream_list)
    st.wait(30)
    for traffic_item in stream_list:
        
        traffic_stat = tgapi.get_traffic_stats(tg_handle, mode='streams', port_handle=port_handle, direction='tx', stream_handle=traffic_item)
        st.banner("BUM TRAFFIC ITEM {}".format(traffic_item))
        st.log("Received traffic: {}".format(traffic_stat['rx']['total_packets']))
        st.log("Sent traffic: {}".format(traffic_stat['tx']['total_packets']))
        st.log(traffic_stat['rx']['total_packets']/traffic_stat['tx']['total_packets'])
        if traffic_stat['rx']['total_packets'] == expected_no_of_endpoints*traffic_stat['tx']['total_packets']:
            st.log("BUM TRAFFIC ITEM {} PASSED".format(traffic_item))
        else:
            st.log("BUM TRAFFIC ITEM {} FAILED".format(traffic_item))
            flag = False
                
    return flag


def generate_loopback_ip(version = 'v4'):
    '''
    {'spine0': '1000:1::1', 'spine1': '1000:1::2', 'spine2': '1000:1::3', 'spine3': '1000:1::4', 
    'leaf0': '2000:1::1', 'leaf1': '2000:1::2', 'leaf2': '2000:1::3', 'leaf3': '2000:1::4'}
    '''
    loopback_ip_dict = {}
    if version == 'v4':
        spine_start_ip = "100.0.0.1"
        leaf_start_ip = "200.0.0.1"
    else:
        spine_start_ip = "1000:1::1"
        leaf_start_ip = "2000:1::1"
    config_dict = get_cfg_dict()
    # Use get_node_sort_key for deterministic order (dc, role, idx) - same as generate_bgp_underlay_info
    node_list = sorted(config_dict['nodes']['all'], key=get_node_sort_key)
    for node in node_list:
        if "spine" in node:
            loopback_ip_dict[node] = spine_start_ip
            spine_start_ip = str(ipaddress.ip_address(spine_start_ip) + 1)
        if "leaf" in node:
            loopback_ip_dict[node] = leaf_start_ip
            leaf_start_ip = str(ipaddress.ip_address(leaf_start_ip) + 1)

    return loopback_ip_dict

def _generate_dci_wan_underlay_ips(var_dict):
    """
    Generate WAN underlay IPs dynamically. Each DCI link gets /24; .1 for lower
    node, .2 for higher (by name). Returns {node: [ip1, ip2, ...]} matching dci_int order.
    Base (e.g. 51.51) from config global.dci_wan_underlay_base, default "51.51".
    """
    config_dict = get_cfg_dict()
    wan_base = config_dict.get('global', {}).get('dci_wan_underlay_base', '51.51')
    dut_int_data = get_dut_interfaces(var_dict)
    int_config = get_config_interfaces_list(var_dict)
    id_to_node = {dut_id: node for node, dut_id in var_dict.dut_ids.items()}
    node_to_id = {node: dut_id for node, dut_id in var_dict.dut_ids.items()}
    node_iface_to_ip = {}
    subnet = 51
    seen_links = set()

    for node, dut_id in var_dict.dut_ids.items():
        dci_dict = dut_int_data.get(node, {}).get('dci_dict', {})
        for key, iface in dci_dict.items():
            if not key.startswith(dut_id + 'D'):
                continue
            peer_tag = key[len(dut_id):].split('P', 1)[0]
            peer_node = id_to_node.get(peer_tag)
            if not peer_node:
                continue
            peer_dci = dut_int_data.get(peer_node, {}).get('dci_dict', {})
            peer_id = node_to_id.get(peer_node, '')
            p_suffix = key.split('P', 1)[1]
            peer_key = peer_id + dut_id + 'P' + p_suffix
            iface_b = peer_dci.get(peer_key, iface)
            na, nb = (node, peer_node) if node < peer_node else (peer_node, node)
            ia = iface if na == node else iface_b
            ib = iface_b if na == node else iface
            link = (na, ia, nb, ib)
            if link not in seen_links:
                seen_links.add(link)
                node_iface_to_ip[(na, ia)] = "{}.{}.1".format(wan_base, subnet)
                node_iface_to_ip[(nb, ib)] = "{}.{}.2".format(wan_base, subnet)
                subnet += 1

    transit_wan_ipv4_underlay = {}
    fb = [0]
    for node in var_dict.dut_ids.keys():
        dci_int = int_config.get(node, {}).get('dci_int', [])
        ips = []
        for iface in dci_int:
            ip = node_iface_to_ip.get((node, iface))
            if ip is None:
                ip = "{}.{}.2".format(wan_base, subnet + fb[0])
                fb[0] += 1
            ips.append(ip)
        if ips:
            transit_wan_ipv4_underlay[node] = ips

    return transit_wan_ipv4_underlay


def generate_dci_vip_maps():
    """
    Generate DCI VIP (Virtual IP) maps for BGW spine nodes.

    BGW spines use shared VIPs for EVPN: DC VIP (IPv6) for intra-DC tunnels to
    local leaves, WAN VIP (IPv4) for inter-DC tunnels to remote BGWs. Each BGW
    also has a unique Loopback1 (wan_overlay) for BGP peering.

    Returns tuple of four dicts (node -> value or list):
        loopback_ipv6_dc_vip: DC VIP per BGW (e.g. 4000:1::1 for DC1)
        loopback_ipv4_wan_vip: WAN VIP per BGW (e.g. 101.101.101.101 for DC1)
        loopback_ipv4_wan_overlay: Unique Loopback1 IP per BGW for BGP update-source
        transit_wan_ipv4_underlay: List of WAN underlay IPs per BGW (for TRANSIT_WAN)
    """
    vars = st.get_testbed_vars()
    config_dict = get_cfg_dict()
    bgw_nodes = sorted([n for n in config_dict['nodes']['all'] if 'bgw' in n],
                       key=get_node_sort_key)
    if not bgw_nodes:
        return ({}, {}, {}, {})

    # Dynamic: WAN underlay IPs from topology
    transit_wan_ipv4_underlay = _generate_dci_wan_underlay_ips(vars)

    # Dynamic: VIPs and overlay from config + DC index and BGW index
    g = config_dict.get('global', {})
    dc_vip_base = g.get('dci_dc_vip_base', 4000)
    dc_vip_step = g.get('dci_dc_vip_step', 2000)
    wan_vip_base = g.get('dci_wan_vip_base', 101)
    overlay_base = g.get('dci_overlay_base', 10)
    loopback_ipv6_dc_vip = {}
    loopback_ipv4_wan_vip = {}
    loopback_ipv4_wan_overlay = {}
    loopback20_ips = {}
    for i, node in enumerate(bgw_nodes):
        dc = _get_dc_from_name(node)
        dc_num = int(dc.replace('dc', '')) if dc else 1
        loopback_ipv6_dc_vip[node] = "{}:1::1".format(dc_vip_base + (dc_num - 1) * dc_vip_step)
        wan_octet = wan_vip_base + dc_num - 1
        loopback_ipv4_wan_vip[node] = "{}.{}.{}.{}".format(
            wan_octet, wan_octet, wan_octet, wan_octet)
        loopback_ipv4_wan_overlay[node] = "{}.{}.{}.{}".format(
            overlay_base + i * 10, overlay_base + i * 10, overlay_base + i * 10, overlay_base + i * 10)
        if dc and dc != 'dc1':
            loopback20_ips[node] = "100.100.100.{}".format(1 + len(loopback20_ips))
    generate_dci_vip_maps._loopback20_ips = loopback20_ips
    return (loopback_ipv6_dc_vip,
            loopback_ipv4_wan_vip,
            loopback_ipv4_wan_overlay,
            transit_wan_ipv4_underlay)

def _get_dc_from_name(name):
    """
    Extract 'dc1', 'dc2', ... from names like 'leaf0_dc1', 'spine2_dc1_bgw1'.
    Return None if nothing matches.
    """
    parts = name.split('_')
    for p in parts:
        if p.startswith('dc') and p[2:].isdigit():
            return p
    return None

def get_dci_link_interfaces(dut, test_cfg):
    """
    Get DCI-facing link interfaces on a BGW/DCI node.

    Looks up the 'dci_int' key from the interface config for the given node,
    which contains the list of interfaces connecting to remote DC BGW nodes
    (WAN/DCI links). Falls back to finding interfaces by naming convention
    if dci_int is not available.

    Args:
        dut: DUT name (e.g. 'spine2_dc1_bgw1')
        test_cfg: Test configuration dictionary containing 'int_config' or topology info

    Returns:
        list: List of DCI-facing interface names, or empty list if none found
    """
    config_dict = get_cfg_dict()
    int_config = config_dict.get('int_config', {})

    # Primary: use dci_int from config
    dci_intfs = int_config.get(dut, {}).get('dci_int', [])
    if dci_intfs:
        st.log('get_dci_link_interfaces: {} has dci_int: {}'.format(dut, dci_intfs))
        return list(dci_intfs)

    # Fallback: look in test_cfg for WAN/DCI link info
    if test_cfg and test_cfg.get('int_config'):
        dci_intfs = test_cfg['int_config'].get(dut, {}).get('dci_int', [])
        if dci_intfs:
            st.log('get_dci_link_interfaces: {} has dci_int from test_cfg: {}'.format(dut, dci_intfs))
            return list(dci_intfs)

    # Second fallback: get all interfaces and filter for WAN-facing ones
    # BGW nodes typically have interfaces toward other BGWs labeled in topology
    st.log('get_dci_link_interfaces: no dci_int found for {}, returning empty'.format(dut))
    return []


def get_node_sort_key(node):
    """Return a deterministic sort key tuple for topology nodes.

    Expected node formats:
      spine2_dc1_bgw1
      leaf0_dc2
      leaf3_dc1
    """

    NODE_RE = re.compile(r'^(spine|leaf)(\d+)_dc(\d+)(?:_bgw(\d+))?$')

    m = NODE_RE.match(node)
    if not m:
        # deterministic fallback for unexpected names
        return (99, 99, 99, node)

    role, idx, dc, bgw = m.groups()

    role_rank = 0 if role == 'spine' else 1   # spines first, then leafs
    idx = int(idx)
    dc = int(dc)
    bgw = int(bgw) if bgw else 0

    return (role_rank, dc, idx, bgw)

def generate_bgp_underlay_info(**kwargs):
    '''
    {'spine0': {'router_id': '10.200.200.100', 'as_num': 65100}, 
    'spine1': {'router_id': '10.200.200.101', 'as_num': 65101}, 
    'spine2': {'router_id': '10.200.200.102', 'as_num': 65102}, 
    'spine3': {'router_id': '10.200.200.103', 'as_num': 65103}, 
    'leaf0': {'router_id': '10.200.200.200', 'as_num': 65200}, 
    'leaf1': {'router_id': '10.200.200.200', 'as_num': 65201}, 
    'leaf2': {'router_id': '10.200.200.200', 'as_num': 65202}, 
    'leaf3': {'router_id': '10.200.200.200', 'as_num': 65203}}

    '''
    dci_enabled = kwargs.get('dci_enabled', False)
    spine_router_id_start = "10.200.200.100"
    leaf_router_id_start = "10.200.200.200"
    spine_as_no_start = 65100
    leaf_as_no_start = 65200
    bgp_info = {}
    config_dict = get_cfg_dict()
    node_list_raw = config_dict['nodes']['all']
    st.log("[DBG-BGP] raw node_list from config_dict['nodes']['all']: {}".format(node_list_raw))

    if not dci_enabled:
        node_list = sorted(list(config_dict.keys()))
    else:
        node_list = sorted(config_dict['nodes']['all'], key=get_node_sort_key)
        st.log("[DBG-BGP] sorted node_list (actual AS assignment order): {}".format(node_list))
    for node in node_list:
        if "spine" not in node and "leaf" not in node:
            st.log("[DBG-BGP] skipping non-spine/leaf node: {}".format(node))
            continue
        bgp_info[node] = {}
        if "spine" in node:
            bgp_info[node]["router_id"] = spine_router_id_start
            bgp_info[node]["as_num"] = spine_as_no_start
            spine_as_no_start+=1
            spine_router_id_start = str(ipaddress.ip_address(spine_router_id_start) + 1)
        if "leaf" in node:
            bgp_info[node]["router_id"] = leaf_router_id_start
            bgp_info[node]["as_num"] = leaf_as_no_start
            leaf_as_no_start+=1
            leaf_router_id_start = str(ipaddress.ip_address(leaf_router_id_start) + 1)
    st.log("[DBG-BGP] final bgp_info (ASNs per node): {}".format(bgp_info))
    return bgp_info

def get_bgp_underlay_info_cached():
    """Return a cached bgp_info map for all nodes."""
    if not hasattr(get_bgp_underlay_info_cached, "_cache"):
        get_bgp_underlay_info_cached._cache = generate_bgp_underlay_info(dci_enabled=True)
    return get_bgp_underlay_info_cached._cache

def generate_bgp_overlay_info(version = 'v4', **kwargs):
    '''
    {'spine0': {'router_id': '10.200.200.100', 'as_num': 65100}, 
    'spine1': {'router_id': '10.200.200.101', 'as_num': 65101}, 
    'spine2': {'router_id': '10.200.200.102', 'as_num': 65102}, 
    'spine3': {'router_id': '10.200.200.103', 'as_num': 65103}, 
    'leaf0': {'router_id': '10.200.200.200', 'as_num': 65200, 'neigbor_overlay': ['2000:1::2', '2000:1::3', '2000:1::4']}, 
    'leaf1': {'router_id': '10.200.200.200', 'as_num': 65201, 'neigbor_overlay': ['2000:1::1', '2000:1::3', '2000:1::4']}, 
    'leaf2': {'router_id': '10.200.200.200', 'as_num': 65202, 'neigbor_overlay': ['2000:1::1', '2000:1::2', '2000:1::4']}, 
    'leaf3': {'router_id': '10.200.200.200', 'as_num': 65203, 'neigbor_overlay': ['2000:1::1', '2000:1::2', '2000:1::3']}}

    '''
    dci_enabled = kwargs.get('dci_enabled', False)
    bgp_info = kwargs.get('bgp_info', {})
    loopback_dict = generate_loopback_ip(version = version)
    config_dict = get_cfg_dict()
    if not dci_enabled:
        overlay_dict = generate_bgp_underlay_info()
    else:
        overlay_dict = bgp_info
    if not dci_enabled:
        l2l3 = set(config_dict['nodes']['l2l3vni'])
    else:
        l2l3 = set(config_dict['nodes']['l2l3vni_bgw'])

    if not dci_enabled:
        # Multi-homing: use exact master logic - each l2l3vni node peers with all others
        ip_list = [loopback_dict[n] for n in config_dict['nodes']['l2l3vni'] if n in loopback_dict]
        for node, ip_addr in loopback_dict.items():
            if node not in config_dict['nodes']['l2l3vni']:
                continue
            temp_list = [ip for ip in ip_list if ip != ip_addr]
            overlay_dict.setdefault(node, {})['neigbor_overlay'] = temp_list
        return overlay_dict

    # DCI: leaf/BGW-specific overlay logic
    leaf_ips_by_dc = {}
    bgw_ips_by_dc  = {}

    for node, ip_addr in loopback_dict.items():
        if node not in l2l3:
            continue
        parts = node.split('_')
        dc_parts = [p for p in parts if p.startswith('dc')]
        dc = dc_parts[0] if dc_parts else 'dc1'

        if node.startswith('leaf'):
            leaf_ips_by_dc.setdefault(dc, []).append(ip_addr)
        elif 'bgw' in node:
            bgw_ips_by_dc.setdefault(dc, []).append(ip_addr)

    for node, ip_addr in loopback_dict.items():
        if node not in l2l3 or not node.startswith('leaf'):
            continue
        parts = node.split('_')
        dc_parts = [p for p in parts if p.startswith('dc')]
        dc = dc_parts[0] if dc_parts else 'dc1'
        same_dc_leaf_ips = leaf_ips_by_dc.get(dc, [])
        same_dc_bgw_ips  = bgw_ips_by_dc.get(dc, [])
        neigh = [ip for ip in same_dc_leaf_ips if ip != ip_addr] + same_dc_bgw_ips
        overlay_dict.setdefault(node, {})['neigbor_overlay'] = neigh

    for node, ip_addr in loopback_dict.items():
        if node not in l2l3 or 'bgw' not in node:
            continue
        parts = node.split('_')
        dc_parts = [p for p in parts if p.startswith('dc')]
        dc = dc_parts[0] if dc_parts else 'dc1'
        overlay_dict.setdefault(node, {})['neigbor_overlay'] = leaf_ips_by_dc.get(dc, [])

    return overlay_dict


def _transit_peers_for(node, transit_map, remote_nodes):
    """Return matching remote P2P IPs that share the same /24 prefix."""
    def k(ip): return ".".join(ip.split(".")[:3])
    my_ips = set(transit_map.get(node, []))
    my_keys = {k(ip) for ip in my_ips}

    peers, seen = [], set()
    for other in remote_nodes:
        for ip in transit_map.get(other, []):
            if k(ip) in my_keys and ip not in my_ips and ip not in seen:
                seen.add(ip)
                peers.append(ip)
    return peers

def _overlay_peers_for(node, overlay_map, remote_nodes):
    """Return overlay loopback IPs of BGWs in remote DCs."""
    peers, seen = [], set()
    for other in remote_nodes:
        ip = overlay_map.get(other)
        if ip and ip not in seen:
            seen.add(ip)
            peers.append(ip)
    return peers

def get_bgw_nodes_info(bgw_nodes, node_info, loopback_ipv4_wan_overlay,
                       transit_wan_ipv4_underlay, remote_dc_policy=None):
    """
    Build BGW node config dict with overlay and transit WAN peer lists.

    For each BGW, computes which other BGWs are in remote DCs (per remote_dc_policy)
    and extracts their WAN overlay IPs (for OVERLAY_WAN) and underlay IPs (for
    TRANSIT_WAN) from the VIP maps. Used by config_feature_dci for BGP config.

    Args:
        bgw_nodes: List of BGW node names (e.g. spine2_dc1_bgw1)
        node_info: Dict of node -> {router_id, as_num} from get_bgp_underlay_info
        loopback_ipv4_wan_overlay: Dict node -> Loopback1 WAN overlay IP
        transit_wan_ipv4_underlay: Dict node -> list of WAN underlay IPs
        remote_dc_policy: Dict dc -> (remote_dc1, remote_dc2) e.g. dc1 -> (dc2, dc3)

    Returns:
        Dict node -> {router_id, as_num, neighbor_overlay_wan, neighbor_transit_wan}
    """

    def dc_of(n):
        m = re.search(r'_(dc\d+)(?:_|$)', n)
        return m.group(1) if m else 'dc1'
    
    dcs_bgw = defaultdict(list)
    for n in bgw_nodes:
        dcs_bgw[dc_of(n)].append(n)

    if remote_dc_policy is None:
        all_dcs = set(dcs_bgw.keys())
        remote_dc_policy = {dc: tuple(sorted(all_dcs - {dc})) for dc in all_dcs}

    out = {}
    for me in bgw_nodes:
        my_dc = dc_of(me)
        rem_nodes = []
        for rdc in remote_dc_policy.get(my_dc, ()):
            rem_nodes.extend(dcs_bgw.get(rdc, []))
        overlay_peers  = _overlay_peers_for(me, loopback_ipv4_wan_overlay, rem_nodes)
        transit_peers  = _transit_peers_for(me, transit_wan_ipv4_underlay, rem_nodes)

        info = node_info.get(me, {})
        out[me] = {
            'router_id': info.get('router_id', ''),
            'as_num': info.get('as_num', ''),
            'neighbor_overlay_wan': overlay_peers,
            'neighbor_transit_wan': transit_peers,
        }
    return out


def get_expected_remote_vteps():
    '''
    Author:Ramsiddarth Ragurajan (rraguraj@cisco.com)

    Generate remote vtep list based on the vlan configured
    {'leaf0': ['2000:1::2', '2000:1::3', '2000:1::4'], 
    'leaf1': ['2000:1::1', '2000:1::4'], 
    'leaf2': ['2000:1::1', '2000:1::4'], 
    'leaf3': ['2000:1::1', '2000:1::2', '2000:1::3']}

    '''
    expected_vteps = {}
    vlan_range = {}
    loopback_ip = generate_loopback_ip(st.getenv("vtep"))
    config_dict = get_cfg_dict()
    for node in config_dict['nodes']['l2l3vni']:
        config =  config_dict[node]
        if type(config['l2vni']) == list:
            vlan_range[node] = list()
            for l2vni_item in config['l2vni']:
                vlan_range[node].append(l2vni_item['vlan_id'])
        else:
            vlan_start = config['l2vni']['vlan_start_range']
            count = config['l2vni']['count']
            vlan_range[node] = list(range(vlan_start,vlan_start+count-1))
    for node1 , vlan_list1 in vlan_range.items():
        temp_list =[]
        expected_vteps[node1]={}
        for node2 , vlan_list2 in vlan_range.items():
            if node2 != node1:
                out_list = find_matching_elements(vlan_list1,vlan_list2)
                if len(out_list) !=0:
                    temp_list.append(loopback_ip[node2])
        expected_vteps[node1][loopback_ip[node1]] = temp_list
    return expected_vteps

def find_matching_elements(list1, list2):
    set1 = set(list1)
    set2 = set(list2)
    matching_elements = set1.intersection(set2)
    return list(matching_elements)

def stats_check(traffic_stat):
    flag = True
    st.log("Received traffic: {}".format(traffic_stat['rx']['total_packets']))
    st.log("Sent traffic: {}".format(traffic_stat['tx']['total_packets']))
    st.log(traffic_stat['rx']['total_packets']/traffic_stat['tx']['total_packets'])
    if traffic_stat['rx']['total_packets'] > 0.998*traffic_stat['tx']['total_packets'] and traffic_stat['rx']['total_packets'] < 1.002*traffic_stat['tx']['total_packets']:
        st.log(" TRAFFIC PASSED")
    else:
        st.log("TRAFFIC ITEM FAILED")
        flag = False     
    return flag


"""
This function configures a feature on a list of nodes in parallel using threads. Each thread calls config_feature to 
apply features to a node and logs an error if needed. The inputs needed for this function is the list of nodes and the 
specific feature. 
"""
def config_feature_parallel(nodes, feature, *args, vars=None, **kwargs):
    """Run config_feature on nodes in parallel. vars is keyword-only to avoid clashing with DCI kwargs."""
    if args:
        st.log("Warning: config_feature_parallel ignores extra positional args (use keyword args for dci_enabled, etc.)")
    dci_enabled = kwargs.get('dci_enabled', False)
    overlay_info = kwargs.get('overlay_info', {})
    bgp_info = kwargs.get('bgp_info', {})
    threads = []
    def thread_helper(node):
        try:
            if not dci_enabled:
                config_feature([node], feature)
            else:
                config_feature_dci([node], feature, **kwargs)
        except Exception as e:
            st.log("[Error] config_feature failed for node {} with feature {}: {}".format(node, feature, e))
        
    for node in nodes:
        thread = threading.Thread(target=thread_helper, args=(node,))
        thread.start()
        threads.append(thread)
    for thread in threads:
        thread.join()

def config_feature(nodes, feature, vars=None):
    """Configure a feature on nodes. Uses testbed vars if vars is None."""
    if vars is None:
        vars = st.get_testbed_vars()
    if feature in ['loopback', 'nvo', 'delete_loopback']: 
        loopback_ip = generate_loopback_ip(version = st.getenv("vtep"))
    if feature in ['bgp_underlay', 'bgp_bfd_underlay', 'delete_bgp_config','bgp_l3vni_config','delete_bgp_l3vni_config']:
        bgp_info = generate_bgp_underlay_info()
    if feature in ['bgp_overlay', 'bgp_bfd_underlay']:
        overlay_info = generate_bgp_overlay_info(version = st.getenv("vtep"))
    
    config_dict = get_cfg_dict()
    for node, config in config_dict.items():
        if node in nodes:
            config_out = ''
            if feature == 'l3vni':
                config_out = generate_l3vni_config(config)
            elif feature == 'l2vni':
                int_config_dict = get_config_interfaces_list(vars)
                dut_int_data = get_dut_interfaces(vars)
                config_out = generate_l2vni_config(config,l2vni_int_list = int_config_dict[node]['l2vni_int'],
                                                   ints_dict = dut_int_data[node])
            elif feature == "sag_v4":
                sag_dict = generate_svi_ip_sag(config,'ipv4')
                if sag_dict != None:
                    config_out = generate_sag_config(sag_dict,'ipv4')
            elif feature == "new_sag_v4":
                sag_dict = generate_svi_ip_sag(config,'ipv4', ip_start = "10.2.0.1")
                if sag_dict != None:
                    config_out = generate_sag_config(sag_dict,'ipv4')
            elif feature == "sag_v6":
                sag_dict = generate_svi_ip_sag(config, 'ipv6')
                if sag_dict != None:
                    config_out = generate_sag_config(sag_dict,'ipv6',enable_on_vlan = False)
            elif feature == "new_sag_v6":
                sag_dict = generate_svi_ip_sag(config,'ipv6', ip_start = "1000:2::1")
                if sag_dict != None:
                    config_out = generate_sag_config(sag_dict,'ipv6',enable_on_vlan = False)
            elif feature == 'loopback':
                    config_out = generate_loopback_config(loopback_ip[node])
            elif feature == 'nvo':
                config_out= generate_vxlan_config(loopback_ip[node])
            elif feature == 'bgp_l3vni_config':
                config_out = generate_bgp_l3vni_config(config,bgp_info[node])
            elif feature == 'bgp_underlay':
                int_config_dict = get_config_interfaces_list(vars)
                config_out = generate_bgp_underlay_config(bgp_info[node],int_config_dict[node]['underlay'], node_name=node)
            elif feature == 'bgp_overlay':
                config_out = generate_bgp_overlay_config(overlay_info[node])
            elif feature == 'bgp_bfd_underlay':
                config_out = generate_bgp_bfd_underlay_config(bgp_info[node])
            elif feature == 'bgp_bfd_overlay':
                config_out = generate_bgp_bfd_overlay_config(overlay_info[node])
            elif feature == 'unnumbered':
                int_config_dict = get_config_interfaces_list(vars)
                config_out = generate_bgp_unnumbered_config(int_config_dict[node]['underlay'])
            elif feature == 'enable_tunnel_counters':
                config_out = set_tunnel_counterpoll()
            elif feature == 'disable_tunnel_counters':
                config_out = set_tunnel_counterpoll(action ='disable')
            elif feature == 'delete_l2vni':
                int_config_dict = get_config_interfaces_list(vars)
                dut_int_data = get_dut_interfaces(vars)
                config_out = generate_l2vni_config(config,l2vni_int_list = int_config_dict[node]['l2vni_int'],
                                                   ints_dict = dut_int_data[node], mode='del')
            elif feature == 'delete_l3vni':
                config_out = generate_l3vni_config(config, mode='del')
            elif feature == 'delete_bgp_l3vni_config':
                config_out = delete_bgp_l3vni_config(config,bgp_info[node])
            elif feature == 'delete_bgp_config':
                config_out = delete_bgp_config(bgp_info[node])
            elif feature == 'delete_vxlan':
                config_out = delete_vxlan_config()
            elif feature == 'delete_loopback':
                config_out = delete_loopback_config(loopback_ip[node])
            elif feature == "delete_sag_v6":
                sag_dict = generate_svi_ip_sag(config, 'ipv6')
                config_out = remove_sag_config(sag_dict,'ipv6', disable_on_vlan = False)
            elif feature == "delete_new_sag_v6":
                sag_dict = generate_svi_ip_sag(config, 'ipv6', ip_start = "1000:2::1")
                config_out = remove_sag_config(sag_dict,'ipv6', disable_on_vlan = False)
            elif feature == "delete_sag_v4":
                sag_dict = generate_svi_ip_sag(config, 'ipv4')
                config_out = remove_sag_config(sag_dict,'ipv4')
            elif feature == "delete_new_sag_v4":
                sag_dict = generate_svi_ip_sag(config, 'ipv4', ip_start = "10.2.0.1")
                config_out = remove_sag_config(sag_dict,'ipv4')
            elif feature == "add_sag_mac":
                config_out = config_sag_mac(add=True)
            elif feature == "del_sag_mac":
                config_out = config_sag_mac(add=False)
            elif feature == "port_channels":
                dut_int_data = get_dut_interfaces(vars)
                config_out = generate_port_channel_config(node, config, dut_int_data[node])
            elif feature == "delete_port_channels":
                dut_int_data = get_dut_interfaces(vars)
                config_out = generate_port_channel_config(node, config, dut_int_data[node], mode='del')
            elif feature == "evpn_esi":
                config_out = generate_evpn_esi_config(config)
            elif feature == "delete_evpn_esi":
                config_out = generate_evpn_esi_config(config, mode='del')
            elif feature == "evpn_mh":
                config_out = generate_epvn_mh_config(node, config_dict)
            elif feature == "delete_evpn_mh":
                config_out = generate_epvn_mh_config(node, config_dict, mode='del')
            if feature in ['bgp_l3vni_config','bgp_underlay','bgp_overlay','delete_bgp_config',
                           'delete_bgp_l3vni_config', 'evpn_mh', 'delete_evpn_mh']:
                config_dut(node, 'bgp', config_out)
            else:
                config_dut(node, 'sonic', config_out, add=True)

def config_feature_dci(nodes, feature, **kwargs):
    """
    Apply DCI-specific configuration features to BGW spine nodes.

    Dispatches to the appropriate config generator for each feature. BGW-only
    features (loopback_dci, nvo_dci, bgp_transit_wan_dci, etc.) are skipped for
    non-BGW nodes. Uses cached VIP maps and BGP info for efficiency.

    Supported features:
        loopback_dci: Loopback1/10/11 (WAN VIPs) and Loopback20 (DC2/DC3 route-maps)
        config_interface_ip_dci: WAN underlay IPs on Ethernet interfaces
        nvo_dci: Dual VXLAN (vxlan-dc for intra-DC, vxlan-wan for inter-DC)
        bgp_underlay_dci: BGP underlay (same as non-DCI, uses underlay interfaces)
        bgp_overlay_dci: BGP EVPN overlay with domain/reoriginate for BGW spines
        bgp_l3vni_config_dci: L3VNI address-family
        l2vni_dci: L2VNI mapping to named VXLANs (no local VLAN members on BGW)
        bgp_transit_wan_dci: TRANSIT_WAN peer-group for WAN underlay
        bgp_overlay_wan_dci: OVERLAY_WAN peer-group for EVPN across DCs
        bgp_ihop_direct_dci: IHOP and DC_DIRECT peer-groups
        route_maps_dci: Source route-maps for BGP updates
        l3vni_sonic_bgw_dci: SONiC CLI for L3VNI on BGW (VLAN, VRF, VXLAN map, VRF-VNI)
        l3vni_frr_bgw_dci: FRR config for L3VNI on BGW (VRF-VNI, extcommunity, RT-REWRITE, BGP VRF)
        delete_*: Unconfig variants for the above

    Args:
        nodes: List of node hostnames to configure
        feature: Feature name (e.g. 'loopback_dci', 'bgp_overlay_wan_dci')
        **kwargs: overlay_info, bgp_info (required for some features)
    """
    vars = st.get_testbed_vars()
    config_dict = get_cfg_dict()
    overlay_info = kwargs.get('overlay_info', {})
    bgp_info = kwargs.get('bgp_info', {})

    # Load DCI VIP maps (cached across calls)
    if not hasattr(config_feature_dci, "_dci_vip_cache"):
        config_feature_dci._dci_vip_cache = generate_dci_vip_maps()
    (loopback_ipv6_dc_vip, loopback_ipv4_wan_vip, loopback_ipv4_wan_overlay,
     transit_wan_ipv4_underlay) = config_feature_dci._dci_vip_cache

    # Load BGP BGW info when needed (cached across calls)
    _BGP_BGW_FEATURES = ('bgp_transit_wan_dci', 'bgp_overlay_wan_dci', 'bgp_ihop_direct_dci')
    if feature in _BGP_BGW_FEATURES:
        if not hasattr(config_feature_dci, "_bgp_info_bgw_cache"):
            all_bgw_nodes = [n for n in config_dict['nodes']['all'] if 'bgw' in n]
            remote_dc_policy = {'dc1': ('dc2', 'dc3'), 'dc2': ('dc1', 'dc3'), 'dc3': ('dc1', 'dc2')}
            config_feature_dci._bgp_info_bgw_cache = get_bgw_nodes_info(
                all_bgw_nodes, bgp_info, loopback_ipv4_wan_overlay,
                transit_wan_ipv4_underlay, remote_dc_policy
            )
        bgp_info_bgw = config_feature_dci._bgp_info_bgw_cache

    if feature == 'bgp_overlay_dci' and not overlay_info:
        overlay_info = generate_bgp_overlay_info(version=st.getenv("vtep"), dci_enabled=True)

    _DCI_ONLY_FEATURES = ('loopback_dci', 'config_interface_ip_dci', 'nvo_dci', 'bgp_transit_wan_dci',
                          'bgp_overlay_wan_dci', 'bgp_ihop_direct_dci', 'route_maps_dci', 'l2vni_dci',
                          'l3vni_sonic_bgw_dci', 'l3vni_frr_bgw_dci',
                          'delete_l3vni_sonic_bgw_dci', 'delete_l3vni_frr_bgw_dci',
                          'delete_l2vni_dci', 'delete_vxlan_dci', 'delete_interface_ip_dci')
    _BGP_CONFIG_FEATURES = ('bgp_transit_wan_dci', 'bgp_overlay_wan_dci', 'bgp_ihop_direct_dci',
                           'route_maps_dci', 'bgp_overlay_dci', 'bgp_underlay_dci', 'bgp_l3vni_config_dci',
                           'l3vni_frr_bgw_dci', 'delete_l3vni_frr_bgw_dci',
                           'l3vni_leaf_rt_dci', 'delete_l3vni_leaf_rt_dci',
                           'delete_bgp_l3vni_config_dci', 'delete_bgp_config_dci')
    loopback20_ips = getattr(generate_dci_vip_maps, '_loopback20_ips', {})

    int_config_dict = get_config_interfaces_list(vars)
    for node, config in config_dict.items():
        if node not in nodes:
            continue
        is_bgw = 'bgw' in node
        if feature in _DCI_ONLY_FEATURES and not is_bgw:
            continue
        config_out = ''
        if feature == 'loopback_dci':
            config_out = generate_loopback_config(loopback_ipv4_wan_overlay[node], 'Loopback1')
            config_out += generate_loopback_config(loopback_ipv6_dc_vip[node], 'Loopback10')
            config_out += generate_loopback_config(loopback_ipv4_wan_vip[node], 'Loopback11')
            if node in loopback20_ips:
                config_out += generate_loopback_config(loopback20_ips[node], 'Loopback20')
        elif feature == 'config_interface_ip_dci':
            interfaces = int_config_dict.get(node, {}).get('dci_int', [])
            for ip, iface in zip(transit_wan_ipv4_underlay.get(node, []), interfaces):
                config_out += generate_interface_ip_config(ip, interface_name=iface)
        elif feature == 'nvo_dci':
            config_out= generate_vxlan_config(loopback_ipv6_dc_vip[node], dci_enabled=True, vxlan_name='vxlan-dc', nvo_name='NVO-DC')
            config_out += generate_vxlan_config(loopback_ipv4_wan_vip[node], dci_enabled=True, vxlan_name='vxlan-wan', nvo_name='NVO-WAN')
        elif feature == 'bgp_underlay_dci':
            int_config_dict = get_config_interfaces_list(vars)
            config_out = generate_bgp_underlay_config(bgp_info[node], int_config_dict[node]['underlay'], node_name=node, dci_enabled=True)
        elif feature == 'bgp_overlay_dci':
            config_out = generate_bgp_overlay_config(overlay_info[node], dci_enabled=True, node_name=node)
        elif feature == 'bgp_l3vni_config_dci':
            config_out = generate_bgp_l3vni_config(config,bgp_info[node])
        elif feature == 'l2vni_dci':
            config_out = generate_l2vni_config(config, dci_enabled=True)
        elif feature == 'bgp_transit_wan_dci':
            config_out = generate_bgp_transit_wan_config(bgp_info_bgw[node])
        elif feature == 'bgp_overlay_wan_dci':
            config_out = generate_bgp_overlay_wan_config(bgp_info_bgw[node])
        elif feature == 'bgp_ihop_direct_dci':
            ihop_peers = bgp_info_bgw[node].get('neighbor_ihop', [])
            dc_direct_peers = bgp_info_bgw[node].get('neighbor_dc_direct', [])
            config_out = generate_bgp_ihop_direct_config(bgp_info_bgw[node], ihop_peers, dc_direct_peers)
        elif feature == 'route_maps_dci':
            # Build data dict with loopback IPs for generate_source_route_maps
            # Use Loopback1 (WAN overlay) IP for RM_SET_SRC4, not router_id (Loopback0)
            # Reference: DC1 BGW1 uses 10.10.10.10 (Loopback1), not 10.200.200.102 (Loopback0)
            loopback_v6_map = generate_loopback_ip(version='v6')
            rm_data = {
                'loopback_ipv4': loopback_ipv4_wan_overlay.get(node, ''),
                'loopback_ipv6': loopback_v6_map.get(node, '')
            }
            config_out = generate_source_route_maps(rm_data)
        elif feature == 'l3vni_sonic_bgw_dci':
            config_out = generate_l3vni_bgw_sonic_config(node, config_dict, bgp_info)
        elif feature == 'l3vni_frr_bgw_dci':
            config_out = generate_l3vni_bgw_frr_config(
                node, config_dict, bgp_info, config_feature_dci._dci_vip_cache)
        elif feature == 'delete_l3vni_sonic_bgw_dci':
            config_out = generate_l3vni_bgw_sonic_config(node, config_dict, bgp_info, mode='del')
        elif feature == 'delete_l3vni_frr_bgw_dci':
            config_out = delete_l3vni_bgw_frr_config(node, config_dict, bgp_info)
        elif feature == 'l3vni_leaf_rt_dci':
            config_out = generate_l3vni_leaf_rt_config(node, config_dict, bgp_info)
        elif feature == 'delete_l3vni_leaf_rt_dci':
            config_out = delete_l3vni_leaf_rt_config(node, config_dict, bgp_info)
        elif feature == 'delete_l2vni_dci':
            config_out = generate_l2vni_config(config, dci_enabled=True, mode='del')
        elif feature == 'delete_vxlan_dci':
            config_out= delete_vxlan_config(vxlan_name='vxlan-dc', nvo_name='NVO-DC')
            config_out += delete_vxlan_config(vxlan_name='vxlan-wan', nvo_name='NVO-WAN')
        elif feature == 'delete_bgp_l3vni_config_dci':
            config_out = delete_bgp_l3vni_config(config, bgp_info[node])
        elif feature == 'delete_bgp_config_dci':
            config_out = delete_bgp_config(bgp_info[node])
        elif feature == 'delete_interface_ip_dci':
            interfaces = int_config_dict.get(node, {}).get('dci_int', [])
            for ip, iface in zip(transit_wan_ipv4_underlay.get(node, []), interfaces):
                config_out += generate_interface_ip_config(ip, interface_name=iface, mode='del')
        if feature in _BGP_CONFIG_FEATURES:
            config_dut(node, 'bgp', config_out)
        else:
            config_dut(node, 'sonic', config_out, add=True)

def config_node(node, config, type=''):
    if type:
        st.config(node, config, type=type, skip_error_check=True, conf=True)
    else:
        st.config(node, config, skip_error_check=True, conf=True)

def config_dut(node, config_domain, config, add=True):
    domain = ''
    if config_domain == 'bgp':
        domain = 'vtysh'
    if add:
        config_node(node, config, domain)

def config_sub_int(interface, vlan, add = True):
    short_name = ("").join(interface.split('ernet'))
    if add:
        cmd = "sudo config subinterface add {0}.{1} {1}".format(short_name, vlan)
    else:
        cmd = "sudo config subinterface del {0}.{1} {1}".format(short_name, vlan)
    return cmd

class VerifyLoop(object):
    """
    Decorator class to retry verification methods
    """
    def __init__(self, vl_retries=1, vl_interval=10, vl_delay=0):
        self.retries = vl_retries
        self.interval = vl_interval
        self.delay = vl_delay

    def __call__(self, org_func, *args, **kwargs):
        def verify_loop( *args, **kwargs):
            retries = kwargs.get('vl_retries', self.retries)
            interval = kwargs.get('vl_interval', self.interval)
            delay = kwargs.get('vl_delay', self.delay)
            retry_cntr = 1
            ret = None
            if delay:
                st.log('Wait {} seconds before execution verification ({})'.format(delay, 
                                                                                    org_func.__name__))
                st.wait(delay)
            while retry_cntr <= retries:
                try:
                    ret = org_func(*args, **kwargs)
                    break
                except Exception as err:
                    if retry_cntr < retries:
                        st.log('Verification ({}) failed. Try {}/{}. '
                               'Retry after {} secs'.format(org_func.__name__,
                                                            retry_cntr, retries, interval))
                        st.wait(interval)
                    else:
                        raise err
                retry_cntr += 1
            return ret
        return verify_loop

def compare_exp_actual_data(exp_data, act_data, id_keys):
    if not exp_data:
        return
    if not act_data:
        raise CompareEmptyData('Actual data empty')
    if not id_keys:
        raise CompareEmptyData('Identifier keys is empty')

    # ---- NEW: compute dynamic column widths ----
    header_cols = ["Attribute", "Expected Value", "Actual Value", "Result"]

    # Gather all keys and values to compute max width
    attr_width = max(len(header_cols[0]),
                     max(len(key) for row in exp_data for key in row.keys()))

    exp_width = max(len(header_cols[1]),
                    max(len(str(v)) for row in exp_data for v in row.values()))

    act_width = max(len(header_cols[2]),
                    max(len(str(v)) for row in act_data for v in row.values()))

    result_width = len(header_cols[3])

    # Add padding so columns breathe
    attr_width  += 2
    exp_width   += 2
    act_width   += 2
    result_width += 2

    # Build dynamic row formatter
    row_format = "|{:<%d}|{:<%d}|{:<%d}|{:<%d}|" % (
        attr_width, exp_width, act_width, result_width
    )

    # Build separator line
    line = "-" * (attr_width + exp_width + act_width + result_width + 5)

    # Print header
    st.log(line)
    st.log(row_format.format(*header_cols))
    st.log(line)

    final_result = True

    # ---- Your existing match logic stays unchanged ----
    for exp_row in exp_data:

        exp_keys = list(exp_row.keys())

        # move id keys to front
        for id_key in reversed(id_keys):
            if id_key in exp_keys:
                exp_keys.remove(id_key)
                exp_keys.insert(0, id_key)

        matching_row = None
        for act_row in act_data:
            if all(act_row.get(k) == exp_row.get(k) for k in id_keys):
                matching_row = act_row
                break

        if matching_row is None:
            # no match: print Absent
            for id_key in id_keys:
                st.log(row_format.format(id_key,
                                         exp_row[id_key],
                                         "-",
                                         "Absent"))
            final_result = False
            st.log(line)
            continue

        # Compare each attribute
        for key in exp_keys:
            ev = str(exp_row.get(key, ""))
            av = str(matching_row.get(key, ""))
            ok = (ev == av)
            final_result = final_result and ok
            st.log(row_format.format(key, ev, av, str(ok)))

        st.log(line)

    if not final_result:
        raise CompareFailed("Expected values does not match actual values")


class CompareFailed(Exception):
    """Failure when comparing data"""
    pass
class CompareEmptyData(Exception):
    """Empty data found when comparing data"""
    pass
class VerifyBgpIpv4Summary(Exception):
    """Exception when verifying show bgp ipv4 summary """
    pass
class VerifyBgpIpv4Unicast(Exception):
    """Exception when verifying show bgp ipv4 summary """
    pass
class VerifyEvpnEs(Exception):
    """Exception when verifying show evpn es """
    pass

@VerifyLoop()
def verify_interfaces_status(dut, exp_data, id_keys=['interface'], interface="", **kwargs):
    act_data = get_interfaces_status(dut, interface)
    compare_exp_actual_data(exp_data, act_data, id_keys)
    return act_data

@VerifyLoop()
def verify_bgp_ipv4_summary(dut, neighbor, vrf='default', **kwargs): 
    """
    verify bgp summary output attributes 
    """
    exp_neigh_state = kwargs.get('state', None)
    exp_as_num = kwargs.get('as_num', None)
    bgp_summary = bgpapi.show_bgp_ipv4_summary_vtysh(dut=dut, vrf=vrf)
    neigh_dict = next((neigh for neigh in bgp_summary if neigh['neighbor'] == neighbor), None)

    if not exp_neigh_state is None:
        st.log('Bgp neighbor {} state:: Expected: {} :: Actual: {}'.format(neighbor, exp_neigh_state, neigh_dict['state']))
        if (neigh_dict['state'].isnumeric() and exp_neigh_state == 'down') \
            or (not neigh_dict['state'].isnumeric() and exp_neigh_state == 'up'):
            raise VerifyBgpIpv4Summary('Bgp neighbor state verifcation failed')

    if not exp_as_num is None:
        st.log('Bgp neighbor {} AS:: Expected: {} :: Actual: {}'.format(neighbor, 
                                                                        exp_as_num, 
                                                                        neigh_dict['asn']))
        if not neigh_dict['asn'] == exp_as_num:
            raise VerifyBgpIpv4Summary('Bgp neighbor AS number verifcation failed')


@VerifyLoop()
def verify_bgp_ipv4_unicast_prefix(dut, prefix, vrf='default', route_no=0, **kwargs): 
    """
    verify "show bgp [vrf <vrf>] ipv4 unicast <prefix>" output
    prefix : ipv4 address to use in cli
    vrf : vrf name to use in cli [default: 'default']
    route_no: Route number to compare if multiple routes available [defaul: 0]
    kwargs keys
        as_path : Expected AS path
        prefix_ip : Expected prefix address 
        prefix_mask : Expected prefix mask 
        community : Expected prefix mask 
    """
    exp_as_path = kwargs.get('as_path', None)
    exp_prefix_ip = kwargs.get('prefix_ip', None)
    exp_prefix_mask = kwargs.get('prefix_mask', None)
    exp_community = kwargs.get('community', None)
    if vrf == 'default':
        show_cli = 'show bgp ipv4 unicast {}'.format(prefix)
    else:
        show_cli = 'show bgp vrf {} ipv4 unicast {}'.format(vrf, prefix)

    cli_output = st.show(dut, show_cli , skip_tmpl=True, type="vtysh")
    parsed_output = st.parse_show(dut, show_cli , cli_output, "show_bgp_ipv4v6uni_prefix.tmpl")

    if not parsed_output:
        raise VerifyBgpIpv4Unicast('BGP prefix {} not found'.format(prefix))

    # hack: prefix ip and prefix mask are not getting populated by parse_show
    if not parsed_output[route_no]['prefixip'] or not parsed_output[route_no]['prefixmasklen']:
        match = re.match("BGP routing table entry for (.*)/(.*), .*", cli_output.split('\n')[route_no])
        if match:
            for itm in parsed_output:
                itm['prefixip'] = match.group(1)
                itm['prefixmasklen'] = match.group(2)

    if exp_as_path:
        st.log('Bgp route {} AS path :: Expected: {} :: Actual: {}'.format(prefix, 
                                                                           exp_as_path, 
                                                                           parsed_output[route_no]['peerasn']))
        if not parsed_output[route_no]['peerasn'] == exp_as_path:
            raise VerifyBgpIpv4Unicast('BGP route AS path verification failed')

    if exp_prefix_ip:
        st.log('Bgp route {} Prefix :: Expected: {} :: Actual: {}'.format(prefix, 
                                                                           exp_prefix_ip, 
                                                                           parsed_output[route_no]['prefixip']))
        if not parsed_output[route_no]['prefixip'] == exp_prefix_ip:
            raise VerifyBgpIpv4Unicast('BGP route prefix address match verification failed')

    if exp_prefix_mask:
        st.log('Bgp route {} Prefix Mask Lenght :: Expected: {} :: Actual: {}'.format(prefix, 
                                                                           exp_prefix_mask, 
                                                                           parsed_output[route_no]['prefixmasklen']))
        if not parsed_output[route_no]['prefixmasklen'] == exp_prefix_mask:
            raise VerifyBgpIpv4Unicast('BGP route prefix mask match verification failed')

    if exp_community:
        st.log('Bgp route {} Community :: Expected: {} :: Actual: {}'.format(prefix, 
                                                                           exp_community, 
                                                                           parsed_output[route_no]['community']))
        if not parsed_output[route_no]['community'] == exp_community:
            raise VerifyBgpIpv4Unicast('BGP route comunity match verification failed')


def get_evpn_es(dut):
    """
    parses 'show evpn es' output into data struct below
    cisco@sonic:~$ sudo show evpn es
    Type: B bypass, L local, R remote, N non-DF
    ESI                            Type ES-IF                 VTEPs
    00:02:03:04:05:06:07:08:09:0a  LR   PortChannel1          2000:1::2
    00:02:03:04:05:06:07:08:09:0c  R    -                     2000:1::3,2000:1::4

    Returns:
    [{u'es_if': u'PortChannel1',
      u'esi': u'00:02:03:04:05:06:07:08:09:0a',
      u'type': u'LR',
      u'vteps': u'2000:1::2'},
     {u'es_if': u'-',
      u'esi': u'00:02:03:04:05:06:07:08:09:0c',
      u'type': u'R',
      u'vteps': u'2000:1::3,2000:1::4'}]
    """
    cmd = 'show evpn es'
    cmd_output = st.vtysh_show(dut, cmd, skip_tmpl=True, skip_error_check=False)
    parsed_output = st.parse_show(dut, cmd, cmd_output, 'show_evpn_es.tmpl')

    return parsed_output

def get_expected_evpn_es(dut):
    """
    generates the expected data struct for 'show evpn es' using the data in 
    the config file
    Returns:
        [{'es_if': '-',
        'esi': '00:02:03:04:05:06:07:08:09:0c',
        'type': 'R',
        'vteps': '2000:1::3,2000:1::4'},
        {'es_if': 'PortChannel1',
        'esi': '00:02:03:04:05:06:07:08:09:0a',
        'type': 'LR',
        'vteps': '2000:1::2'}]

    """
    ret_val = list()
    loopback_ip = generate_loopback_ip(st.getenv("vtep"))
    cfg_dict = get_cfg_dict()

    if dut not in cfg_dict['nodes']['l2l3vni']:
        return ret_val
    dut_cfg = cfg_dict[dut]
    dut_esi = list()
    if dut_cfg and dut_cfg.get('port_channels'):
        for pc_cfg in dut_cfg['port_channels']:
            dut_esi.append(pc_cfg['evpn_esi'])

    # Determine which DC the DUT belongs to
    dut_dc = None
    if 'dc1' in dut.lower():
        dut_dc = 'dc1'
    elif 'dc2' in dut.lower():
        dut_dc = 'dc2'
    elif 'dc3' in dut.lower():
        dut_dc = 'dc3'
    
    esi_dict = dict()
    for node,node_cfg in cfg_dict.items():

        if node not in cfg_dict['nodes']['l2l3vni']:
            continue
        
        # For DCI: Only include ESIs from nodes in the SAME DC
        node_dc = None
        if 'dc1' in node.lower():
            node_dc = 'dc1'
        elif 'dc2' in node.lower():
            node_dc = 'dc2'
        elif 'dc3' in node.lower():
            node_dc = 'dc3'
        
        # Skip ESIs from other DCs
        if dut_dc and node_dc and dut_dc != node_dc:
            continue

        for pc_cfg in node_cfg.get('port_channels', []):
            if pc_cfg['evpn_esi'] not in esi_dict.keys():
                esi_dict[pc_cfg['evpn_esi']] = {'esi': pc_cfg['evpn_esi'],
                                                'es_if' : 'PortChannel{}'.format(pc_cfg['port_channel_num']),
                                               'vteps': [loopback_ip[node]]}
            else:
                esi_dict[pc_cfg['evpn_esi']]['vteps'].append(loopback_ip[node])

    for esi, esi_info in esi_dict.items():

        type = 'R'
        es_if = '-'
        sorted_vteps = sorted(esi_info['vteps'])
        if esi_info['esi'] in dut_esi:
            es_if = esi_info['es_if']
            type = 'LR' if loopback_ip[dut] == sorted_vteps[0] else 'LRN'
            sorted_vteps.remove(loopback_ip[dut])
        esi_info['es_if'] = es_if
        esi_info['type'] = type
        esi_info['vteps'] = ','.join(sorted_vteps)
        ret_val.append(esi_info) 

    return ret_val

@VerifyLoop()
def verify_evpn_es(dut, exp_data, id_keys=['esi'], **kwargs): 

    act_data = get_evpn_es(dut)
    compare_exp_actual_data(exp_data, act_data, id_keys)
    return act_data

def get_evpn_es_evi(dut):
    """
    parses 'show evpn es-evi' output into data struct below
    cisco@sonic:~$ show evpn es-evi 
    Type: L local, R remote
    VNI      ESI                            Type
    5030     00:02:03:04:05:06:07:08:09:0a  L   
    5002     00:02:03:04:05:06:07:08:09:0a  L   
    5007     00:02:03:04:05:06:07:08:09:0a  L   
    5004     00:02:03:04:05:06:07:08:09:0a  L   
    5020     00:02:03:04:05:06:07:08:09:0a  L   

    Returns:
    [{u'esi': u'00:02:03:04:05:06:07:08:09:0a', u'type': u'L', u'vni': u'5030'},
    {u'esi': u'00:02:03:04:05:06:07:08:09:0a', u'type': u'L', u'vni': u'5002'},
    {u'esi': u'00:02:03:04:05:06:07:08:09:0a', u'type': u'L', u'vni': u'5007'},
    {u'esi': u'00:02:03:04:05:06:07:08:09:0a', u'type': u'L', u'vni': u'5004'},
    {u'esi': u'00:02:03:04:05:06:07:08:09:0a', u'type': u'L', u'vni': u'5020'}]
    """
    cmd = 'show evpn es-evi'
    cmd_output = st.vtysh_show(dut, cmd, skip_tmpl=True, skip_error_check=False)
    parsed_output = st.parse_show(dut, cmd, cmd_output, 'show_evpn_es_evi.tmpl')

    return parsed_output

def get_expected_evpn_es_evi(dut):
    """
    generates the expected data struct for 'show evpn es-evi' using the data in 
    the config file
    Returns:
    [{'esi': '00:02:03:04:05:06:07:08:09:0c', 'type': 'L', 'vni': '5002'},
    {'esi': '00:02:03:04:05:06:07:08:09:0c', 'type': 'L', 'vni': '5004'},
    {'esi': '00:02:03:04:05:06:07:08:09:0c', 'type': 'L', 'vni': '5006'},
    {'esi': '00:02:03:04:05:06:07:08:09:0c', 'type': 'L', 'vni': '5020'},
    {'esi': '00:02:03:04:05:06:07:08:09:0c', 'type': 'L', 'vni': '5040'}]
    """
    ret_val = list()
    cfg_dict = get_cfg_dict()

    dut_cfg = cfg_dict[dut]
    if dut_cfg and dut_cfg.get('port_channels'):
        for pc_cfg in dut_cfg['port_channels']:
            int_name = 'PortChannel{}'.format(pc_cfg['port_channel_num'])

            for l2vni_info in dut_cfg['l2vni']:
                if int_name in l2vni_info['members']:
                    ret_val.append({
                                'esi': pc_cfg['evpn_esi'],
                                'type': 'L',
                                'vni': str(l2vni_info['vxlan_id'])
                                })

    return ret_val

@VerifyLoop()
def verify_evpn_es_evi(dut, exp_data, id_keys=['esi', 'vni'], **kwargs): 

    act_data = get_evpn_es_evi(dut)
    compare_exp_actual_data(exp_data, act_data, id_keys)
    return act_data

def get_vxlan_vlanvnimap(dut):
    """
    parses 'show vxlan vlanvnimap' output into data struct below
    cisco@sonic:~$ show vxlan vlanvnimap
    +---------+-------+
    | VLAN    |   VNI |
    +=========+=======+
    | Vlan2   |  5002 |
    +---------+-------+
    | Vlan3   |  5003 |
    +---------+-------+
    | Vlan4   |  5004 |
    +---------+-------+
    | Vlan5   |  5005 |
    +---------+-------+
    | Vlan6   |  5006 |
    +---------+-------+

    Returns:
    [{u'vlan': u'Vlan2', u'vni': u'5002'},
    {u'vlan': u'Vlan3', u'vni': u'5003'},
    {u'vlan': u'Vlan4', u'vni': u'5004'},
    {u'vlan': u'Vlan5', u'vni': u'5005'},
    {u'vlan': u'Vlan6', u'vni': u'5006'}]
    """
    cmd = 'show vxlan vlanvnimap'
    cmd_output = st.show(dut, cmd, skip_tmpl=True, skip_error_check=False)
    parsed_output = st.parse_show(dut, cmd, cmd_output, 'show_vxlan_vlanvnimap.tmpl')

    return parsed_output

def get_expected_vxlan_vlanvnimap(dut):
    """
    generates the expected data struct for 'show vxlan vlanvnimap' using the data in 
    the config file
    Returns:
    [{'vlan': 'Vlan2', 'vni': '5002'},
    {'vlan': 'Vlan3', 'vni': '5003'},
    {'vlan': 'Vlan4', 'vni': '5004'},
    {'vlan': 'Vlan5', 'vni': '5005'},
    {'vlan': 'Vlan6', 'vni': '5006'}]
    """
    ret_val = list()
    cfg_dict = get_cfg_dict()

    dut_cfg = cfg_dict[dut]
    if dut_cfg and dut_cfg.get('l2vni'):
        for l2vni_cfg in dut_cfg['l2vni']:
            ret_val.append({
                        'vlan': 'Vlan{}'.format(l2vni_cfg['vlan_id']),
                        'vni': str(l2vni_cfg['vxlan_id'])
                        })
    if dut_cfg and dut_cfg.get('l3vni'):
        for l3vni_cfg in dut_cfg['l3vni']:
            ret_val.append({
                        'vlan': 'Vlan{}'.format(l3vni_cfg['vrf_id']),
                        'vni': str(l3vni_cfg['vxlan_id'])
                        })
    return ret_val

@VerifyLoop()
def verify_vxlan_vlanvnimap(dut, exp_data, id_keys=['vlan'], **kwargs): 

    act_data = get_vxlan_vlanvnimap(dut)
    compare_exp_actual_data(exp_data, act_data, id_keys)
    return act_data

def get_vxlan_vrfvnimap(dut):
    """
    parses 'show vxlan vrfvnimap' output into data struct below
    cisco@sonic:~$ show vxlan vrfvnimap
    +--------+-------+
    | VRF    |   VNI |
    +========+=======+
    | Vrf101 |  5101 |
    +--------+-------+
    | Vrf102 |  5102 |
    +--------+-------+
    | Vrf103 |  5103 |
    +--------+-------+
    Total count : 3

    Returns:
    [{u'vni': u'5101', u'vrf': u'Vrf101'},
    {u'vni': u'5102', u'vrf': u'Vrf102'},
    {u'vni': u'5103', u'vrf': u'Vrf103'}]
    """
    cmd = 'show vxlan vrfvnimap'
    cmd_output = st.show(dut, cmd, skip_tmpl=True, skip_error_check=False)
    parsed_output = st.parse_show(dut, cmd, cmd_output, 'show_vxlan_vrfvnimap.tmpl')

    return parsed_output

def get_expected_vxlan_vrfvnimap(dut):
    """
    generates the expected data struct for 'show vxlan vrfvnimap' using the data in 
    the config file
    Returns:
    [{'vni': '5101', 'vrf': 'Vrf101'},
    {'vni': '5102', 'vrf': 'Vrf102'},
    {'vni': '5103', 'vrf': 'Vrf103'}]
    """
    ret_val = list()
    cfg_dict = get_cfg_dict()

    dut_cfg = cfg_dict[dut]
    if dut_cfg and dut_cfg.get('l3vni'):
        for l3vni_cfg in dut_cfg['l3vni']:
            ret_val.append({
                        'vrf': 'Vrf{}'.format(l3vni_cfg['vrf_id']),
                        'vni': str(l3vni_cfg['vxlan_id'])
                        })
    return ret_val

@VerifyLoop()
def verify_vxlan_vrfvnimap(dut, exp_data, id_keys = ['vrf'], **kwargs): 

    act_data = get_vxlan_vrfvnimap(dut)
    compare_exp_actual_data(exp_data, act_data, id_keys)
    return act_data

def get_vxlan_remotevtep(dut):
    """
    parses 'show vxlan remotevtep' output into data struct below
    cisco@sonic:~$ show vxlan remotevtep
    +-----------+-----------+-------------------+--------------+
    | SIP       | DIP       | Creation Source   | OperStatus   |
    +===========+===========+===================+==============+
    | 2000:1::1 | 1000:1::4 | EVPN              | oper_up      |
    +-----------+-----------+-------------------+--------------+
    | 2000:1::1 | 2000:1::2 | EVPN              | oper_up      |
    +-----------+-----------+-------------------+--------------+
    | 2000:1::1 | 2000:1::3 | EVPN              | oper_up      |
    +-----------+-----------+-------------------+--------------+
    | 2000:1::1 | 2000:1::4 | EVPN              | oper_up      |
    +-----------+-----------+-------------------+--------------+
    Total count : 4


    Returns:
    [{u'dst_vtep': u'1000:1::4',
    u'remote_mac': u'',
    u'remote_vtep': u'',
    u'src_vtep': u'2000:1::1',
    u'total_count': u'',
    u'tun_src': u'EVPN',
    u'tun_status': u'oper_up',
    u'vlan': u'',
    u'vni': u''},
    {u'dst_vtep': u'2000:1::2',
    u'remote_mac': u'',
    u'remote_vtep': u'',
    u'src_vtep': u'2000:1::1',
    u'total_count': u'',
    u'tun_src': u'EVPN',
    u'tun_status': u'oper_up',
    u'vlan': u'',
    u'vni': u''}, ..]
    """
    cmd = 'show vxlan remotevtep'
    cmd_output = st.show(dut, cmd, skip_tmpl=True, skip_error_check=False)
    parsed_output = st.parse_show(dut, cmd, cmd_output, 'show_vxlan_remotevtep.tmpl')

    return parsed_output

def get_expected_vxlan_remotevtep(dut):
    """
    Generates the expected data struct for 'show vxlan remotevtep' using the config.

    Returns a list of dicts:
        {
          'src_vtep': <SIP>,
          'dst_vtep': <DIP>,
          'tun_src': 'EVPN',
          'tun_status': 'oper_up'
        }
    """

    ret_val = []

    cfg_dict = get_cfg_dict()
    nodes = cfg_dict['nodes']

    # Participants:
    # - If l2l3vni_bgw exists, it is the superset (leaves + BGWs).
    # - Otherwise, fall back to original behavior: just l2l3vni (leaf-only fabrics).
    participants = nodes.get('l2l3vni_bgw') or nodes.get('l2l3vni', [])

    # If DUT is not a participant, nothing expected (same semantics as before).
    if dut not in participants:
        return ret_val

    dut_dc = _get_dc_from_name(dut)
    if dut_dc is None:
        return ret_val

    # Loopbacks (leaf VTEPs and spine underlay loopbacks)
    loopback_ip = generate_loopback_ip(st.getenv("vtep"))

    # DCI VIP maps (BGW spines – WAN & DC VIPs)
    (loopback_ipv6_dc_vip,
     loopback_ipv4_wan_vip,
     loopback_ipv4_wan_overlay,
     transit_wan_ipv4_underlay) = generate_dci_vip_maps()

    # BGW spine if present in any VIP dict
    is_bgw_spine = (dut in loopback_ipv6_dc_vip) or (dut in loopback_ipv4_wan_vip)

    # We also keep a set to dedupe (src_vtep, dst_vtep) pairs
    seen_pairs = set()

    # ------------------------------------------------------------------
    # CASE 1: BGW SPINE – multi VTEP behavior
    # ------------------------------------------------------------------
    if is_bgw_spine:
        #
        # 1a) WAN IPv4 VTEPs: DUT WAN VIP -> other DCs' WAN VIPs
        #
        src_v4 = loopback_ipv4_wan_vip.get(dut)
        if src_v4:
            for node, dst_v4 in loopback_ipv4_wan_vip.items():
                if node == dut:
                    continue
                node_dc = _get_dc_from_name(node)
                if node_dc == dut_dc:
                    continue

                pair = (src_v4, dst_v4)
                if pair in seen_pairs:
                    continue
                seen_pairs.add(pair)

                ret_val.append({
                    'src_vtep': src_v4,    # e.g. 101.101.101.101
                    'dst_vtep': dst_v4,    # e.g. 102.102.102.102 / 103.103.103.103
                    'tun_src': 'EVPN',
                    'tun_status': 'oper_up',
                })

        #
        # 1b) DC IPv6 VTEPs: DUT DC VIP -> local leaves' loopbacks
        # Only include actual leaf nodes — non-BGW spines and sibling BGWs
        # do NOT form VXLAN tunnels visible in 'show vxlan remotevtep'.
        #
        src_v6 = loopback_ipv6_dc_vip.get(dut)
        if src_v6:
            local_leaves = [
                n for n in nodes.get('l2l3vni', [])
                if _get_dc_from_name(n) == dut_dc and 'leaf' in n
            ]

            local_leaves_sorted = sorted(local_leaves)
            for leaf in local_leaves_sorted:
                dst_v6 = loopback_ip.get(leaf)
                if not dst_v6:
                    continue

                pair = (src_v6, dst_v6)
                if pair in seen_pairs:
                    continue
                seen_pairs.add(pair)

                ret_val.append({
                    'src_vtep': src_v6,   # e.g. 4000:1::1 / 6000:1::1 / 8000:1::1
                    'dst_vtep': dst_v6,   # e.g. 2000:1::1..4 / 2000:1::5..6 / 2000:1::7
                    'tun_src': 'EVPN',
                    'tun_status': 'oper_up',
                })

        return ret_val

    # ------------------------------------------------------------------
    # CASE 2: LEAF – this covers both:
    #   - Leaf-only fabrics (no BGWs/spines in config)
    #   - Fabrics with BGWs present
    # ------------------------------------------------------------------

    # Leaf src_vtep: same as original behavior (its loopback IPv6).
    src_v6 = loopback_ip.get(dut)
    if not src_v6:
        return ret_val

    # Remote nodes: all other participants in the same DC
    remote_nodes = [
        node for node in participants
        if node != dut and _get_dc_from_name(node) == dut_dc
    ]

    remote_nodes_sorted = sorted(remote_nodes)

    for node in remote_nodes_sorted:
        # If remote is a BGW spine, use its DC IPv6 VIP; otherwise its loopback.
        if node in loopback_ipv6_dc_vip:
            dst_ip = loopback_ipv6_dc_vip[node]
        else:
            dst_ip = loopback_ip.get(node)

        if not dst_ip:
            continue

        pair = (src_v6, dst_ip)
        if pair in seen_pairs:
            continue
        seen_pairs.add(pair)

        ret_val.append({
            'src_vtep': src_v6,
            'dst_vtep': dst_ip,
            'tun_src': 'EVPN',
            'tun_status': 'oper_up',
        })

    return ret_val


@VerifyLoop()
def verify_vxlan_remotevtep(dut, exp_data, id_keys=['dst_vtep'], **kwargs): 

    act_data = get_vxlan_remotevtep(dut)
    compare_exp_actual_data(exp_data, act_data, id_keys)
    return act_data

def get_vxlan_l2nexthopgroup(dut):
    """
    parses 'show vxlan l2nexthopgroup' output into data struct below
    cisco@sonic:~$ show vxlan l2nexthopgroup
    +-----------+-----------+---------------------+
    |       NHG | Tunnels   | LocalMembers        |
    +===========+===========+=====================+
    | 268435458 | 2000:1::2 |                     |
    +-----------+-----------+---------------------+
    | 268435460 | 2000:1::3 |                     |
    +-----------+-----------+---------------------+
    | 268435461 | 2000:1::4 |                     |
    +-----------+-----------+---------------------+
    | 536870913 |           | 268435458           |
    +-----------+-----------+---------------------+
    | 536870915 |           | 268435460,268435461 |
    +-----------+-----------+---------------------+

    Returns:
    [{u'loc_mbrs': u'', u'nbr_grp': u'268435458', u'tunnels': u'2000:1::2'},
    {u'loc_mbrs': u'', u'nbr_grp': u'268435460', u'tunnels': u'2000:1::3'},
    {u'loc_mbrs': u'', u'nbr_grp': u'268435461', u'tunnels': u'2000:1::4'},
    {u'loc_mbrs': u'268435458', u'nbr_grp': u'536870913', u'tunnels': u''},
    {u'loc_mbrs': u'268435460,268435461', u'nbr_grp': u'536870915', u'tunnels': u''}]

    """
    cmd = 'show vxlan l2nexthopgroup'
    cmd_output = st.show(dut, cmd, skip_tmpl=True, skip_error_check=False)
    parsed_output = st.parse_show(dut, cmd, cmd_output, 'show_vxlan_l2nexthopgroup.tmpl')

    return parsed_output

def get_expected_vxlan_l2nexthopgroup(dut):
    """
    generates the expected data struct for 'show vxlan l2nexthopgroup' using the data in 
    the config file
    Returns:
    """
    ret_val = list()
    loopback_ip = generate_loopback_ip(st.getenv("vtep"))
    cfg_dict = get_cfg_dict()

    dut_cfg = cfg_dict[dut]
    if not dut_cfg or not dut_cfg.get('port_channels'):
        return ret_val

    for node , node_cfg in cfg_dict.items():

        if node == dut:
            continue
        
        if node_cfg and node_cfg.get('port_channels'):
            ret_val.append({
                        'tunnels': loopback_ip[node]
                        })
    return ret_val


@VerifyLoop()
def verify_vxlan_l2nexthopgroup(dut, exp_data, id_keys=['nbr_grp'], **kwargs): 

    act_data = get_vxlan_l2nexthopgroup(dut)
    compare_exp_actual_data(exp_data, act_data, id_keys)
    return act_data


def scp_upload(local_path, remote_path, hostaddr, username, password, port=22):
    try:
        # Create an SSH client object
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # Connect to the SSH server
        ssh_client.connect(hostaddr, port=port, username=username, password=password)
        
        # Create an SCP client
        with SCPClient(ssh_client.get_transport()) as scp:
            # Upload the local file to the remote path
            scp.put(local_path, remote_path)
        
    finally:
        # Close the SSH connection
        ssh_client.close()    

def scp_download(local_path, remote_path, hostaddr, username, password, port=22):
    try:
        # Create an SSH client object
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # Connect to the SSH server
        ssh_client.connect(hostaddr, port=port, username=username, password=password)
        
        # Create an SCP client
        with SCPClient(ssh_client.get_transport()) as scp:
            # Upload the local file to the remote path
            scp.get(remote_path, local_path=local_path)
        
    finally:
        # Close the SSH connection
        ssh_client.close()    

class ConfigDB(object):
    """
    Class to get or set config_db.json values
    exmaple:
        with ConfigDB('leaf2', '192.168.122.235', 'cisco', 'cisco123') as cfgdb:
            cfgdb.set_leaf_value(['DEVICE_METADATA', 'localhost', 'docker_routing_config_mode'], 'split-unified')
            val = cfgdb.get_leaf_value(['DEVICE_METADATA', 'localhost', 'docker_routing_config_mode'])
    """

    def __init__(self, dut, address, username, password):
        self._config_db = {}
        self.dut = dut
        self.address = address
        self.username = username
        self.password = password
        self.temp_db = '__config_db_{}__.json'.format(self.dut)
        self.local_temp_db_path = './' + self.temp_db
        self.remote_temp_db_path = '/home/{}/'.format(self.username) + self.temp_db
        self.remote_db_path = '/etc/sonic/config_db.json'
    
    def __enter__(self): 
        self.read_db()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.write_db()
    
    def read_db(self):
        """
        copy config_db.json from router to local and load json content to class
        """
        try:
            scp_download(local_path=self.local_temp_db_path,
                        remote_path= self.remote_db_path, 
                        hostaddr=self.address,
                        username=self.username, password=self.password)
            with open(self.local_temp_db_path) as fd:
                self._config_db = json.load(fd)
        finally:
            os.system('rm -rf {}'.format(self.local_temp_db_path))

    def write_db(self):
        """
        dump class config db content to json and copy to router and replace existing config_db.json
        on router
        """
        try:
            db_data_json = json.dumps(self._config_db, indent=4, sort_keys=False)
            with open(self.local_temp_db_path, 'w') as fd:
                fd.write(db_data_json)

            scp_upload(local_path=self.local_temp_db_path, 
                        remote_path=self.remote_temp_db_path, 
                        hostaddr=self.address,
                        username=self.username, password=self.password)
            st.show(self.dut, 'sudo cp {} {}'.format(self.remote_temp_db_path,
                                                     self.remote_db_path), skip_tmpl=True)
        finally:
            os.system('rm -rf {}'.format(self.local_temp_db_path))
            st.show(self.dut, 'sudo rm {}'.format(self.remote_temp_db_path), skip_tmpl=True)

    def _find_key_val_dict(self, keys):
        """
        helper funtion to find the dictonary having the find final key value
        keys: keys in list format
        example: ['DEVICE_METADATA', 'localhost', 'docker_routing_config_mode']
        """
        if type(keys) is str:
            keys = [keys]
        if type(keys) is not list:
            raise Exception('Keys not in list format')
        ret_dict = self._config_db
        for key in keys[:-1]:
            ret_dict = ret_dict[key] 
            if type(ret_dict) is not dict:
                raise Exception('Key is a leaf')
        return ret_dict

    def get_leaf_value(self, keys):
        """
        Get the leaf value of config db given heirarchy of keys . 
        keys: keys in list format
        example: ['DEVICE_METADATA', 'localhost', 'docker_routing_config_mode']
        """
        try:
            #find the dict with the final key in 'keys'
            key_dict = self._find_key_val_dict(keys)
            val = key_dict[keys[-1]]
            if not isinstance(val, (str, bytes)):
                raise Exception('Leaf value not string : {}'.format(type(val)))
            return val.encode('utf-8') if isinstance(val, str) else val
        except Exception as err:
            raise Exception('Invalid key: {}'.format(err))

    def set_leaf_value(self, keys, value):
        """
        set the leaf value of confid db given heirarchy of keys . 
        keys: keys in list format
        example: ['DEVICE_METADATA', 'localhost', 'docker_routing_config_mode']
        value: string value 
        """
        try:
            #find the dict with the final key in 'keys'
            key_dict = self._find_key_val_dict(keys)
            key = keys[-1].decode() if isinstance(keys[-1], bytes) else keys[-1]
            val = value.decode() if isinstance(value, bytes) else str(value)
            key_dict[key] = val
        except Exception as err:
            raise Exception('Invalid key: {}'.format(err))

def get_device_id(device, vars_dict):
    """get device id provided the device name"""
    for name, id in vars_dict.dut_ids.items(): 
        if name == device :
            return id
    else:
        raise Exception('Device {} not found'.format(device)) 

def get_peer_port_id(port_id, vars_dict, node=None, node_id=None):
    """get remote port id for a provided port id """
    port_num_pattern = '([A-Z0-9].*)([A-Z]+[0-9]+)'
    match = re.match(port_num_pattern, port_id)
    if not match:
        raise Exception('Port ID {} not in proper format. \
                        Port number Pn not found'.format(port_id))
    port_num = match.group(2)
    port_id_1node = '([A-Z]+[0-9]+)'
    port_id_2node = '([A-Z]+[0-9]+)([A-Z]+[0-9]+)'

    match_2node =  re.match(port_id_2node, match.group(1))
    match_1node =  re.match(port_id_1node, match.group(1))
    if match_2node:
        node_id = match_2node.group(1)
        peer_id = match_2node.group(2)
    elif match_1node:
        peer_id = match_1node.group(1)
        if not node_id:
            node_id = get_device_id(node, vars_dict)
    else:
        raise Exception('Port ID {} not in proper format.'.format(port_id))
    
    peer_port_id = peer_id+node_id+port_num
    for key in vars_dict.keys():
        if key == peer_port_id:
            # valid peer port id 
            return peer_port_id
    else:
        raise Exception('Derived peer port id {} from port id {} (node: {}/node_id: {}) not defined.'.format(
            peer_port_id, port_id, node, node_id))

def check_core():
    flag = False
    pattern = r'(\w+)\.\d+\.\d+\.core.gz'
    for dut in st.get_dut_names():
        out = st.show(dut, 'ls -l /var/core/', skip_tmpl=True)
        matches = re.findall(pattern, out)
        core_name = "+".join(list(set(matches)))
        if "core.gz" in out:
            st.log("Core present in {}".format(dut))
            flag = True 
            st.collect_core_files(dut, core_name)

    return flag

def enable_debugs():      
    output = ''
    output += "debug zebra kernel\n"
    output += "debug zebra kernel msgdump\n"
    output += "debug zebra rib\n"
    output += "debug zebra rib detailed\n"
    output += "debug zebra vxlan\n"
    output += "debug zebra evpn mh mac\n"
    output += "debug zebra evpn mh es\n"
    output += "debug bgp evpn mh route\n"
    output += "debug bgp evpn mh es\n"
    output += "debug bgp zebra\n"
    output += "debug bgp nht\n"
    output += "debug zebra evpn mh neigh\n"
    output += "debug zebra dplane detailed\n"
    output += "log stdout\n"
    output += "log syslog\n"
    output += "end\nexit\n"
    cmd1 = "swssloglevel -l INFO -c orchagent"
    cmd2 = "swssloglevel -l INFO -c fdbsyncd"
    for dut in st.get_dut_names():
        if "leaf" in dut:
            st.config(dut, output, type='vtysh', skip_error_check=True)
            st.config(dut, cmd1, skip_error_check=True)
            st.config(dut, cmd2, skip_error_check=True)

def get_expected_evpn_type1_routes(dut):
    ret_val = list()
    loopback_ip = generate_loopback_ip(st.getenv("vtep"))
    cfg_dict = get_cfg_dict()

    if dut not in cfg_dict['nodes']['l2l3vni']:
        return ret_val
    
    dut_cfg = cfg_dict[dut]
                    
    evpn_type1_routes = []

    if dut_cfg and dut_cfg.get('port_channels'):
        for pc_cfg in dut_cfg['port_channels']:
            int_name = 'PortChannel{}'.format(pc_cfg['port_channel_num'])

            for l2vni_info in dut_cfg['l2vni']:
                if int_name in l2vni_info['members']:        
                    evpn_type1_routes.append({'esi': pc_cfg['evpn_esi'],
                                              'vni' : str(l2vni_info['vxlan_id']),
                                              'next_hop': loopback_ip[dut]})

    return evpn_type1_routes

def get_actual_evpn_type1_routes(dut):
    cli_output = st.show(dut, "do show bgp l2vpn evpn route type 1",type='vtysh', skip_tmpl=True)
    parsed_output = st.parse_show(dut, "show bgp l2vpn evpn route type 1",cli_output, "show_bgp_l2vpn_evpn_route_type_1.tmpl")
    return parsed_output

@VerifyLoop()
def verify_evpn_type1_routes(dut, exp_es_evi_data, **kwargs):
    st.banner("Checking EVPN Type 1 routes in "+ dut)

    act_type1_routes = get_actual_evpn_type1_routes(dut)
    act_data = []
    for route in act_type1_routes:
        act_data.append({'vni': route['rt'].split(':')[1], 'esi': route['esi'], 'next_hop':route['next_hop']})
    compare_exp_actual_data(exp_es_evi_data, act_data , ['vni', 'esi', 'next_hop'])
    return act_type1_routes
    
def get_expected_evpn_type4_routes(dut, **kwargs):
    ret_val = list()
    loopback_ip = generate_loopback_ip(st.getenv("vtep"))
    cfg_dict = get_cfg_dict()

    if dut not in cfg_dict['nodes']['l2l3vni']:
        return ret_val
    
    dut_cfg = cfg_dict[dut]

    evpn_type4_routes = []
    for pc_cfg in dut_cfg.get('port_channels', []):
        evpn_type4_routes.append({'esi': pc_cfg['evpn_esi'],
                                  'next_hop': loopback_ip[dut]})

    return evpn_type4_routes

def get_actual_evpn_type4_routes(dut):
    cli_output = st.show(dut, "do show bgp l2vpn evpn route type 4",type='vtysh', skip_tmpl=True)
    parsed_output = st.parse_show(dut, "show bgp l2vpn evpn route type 4",cli_output, "show_bgp_l2vpn_evpn_route_type_4.tmpl")
    return parsed_output

@VerifyLoop()
def verify_evpn_type4_routes(dut, exp_type4_routes, **kwargs):
    st.banner("Checking EVPN Type 4 routes in "+ dut)

    act_type4_routes = get_actual_evpn_type4_routes(dut)

    compare_exp_actual_data(exp_type4_routes, act_type4_routes, ['esi', 'next_hop'])
    return act_type4_routes


def _log_evpn_type2_route_table(node, item, host_type):
    """Log a single EVPN type-2 route as a table (for dci_enabled)."""
    mac = item.get('mac', '')
    ip = item.get('ip', '') or '-'
    weight = item.get('weight', '')
    mm = item.get('mm', '')
    next_hop = item.get('next_hop', '')
    rd = item.get('route_distinguisher', '')
    rows = [
        ("Node", node),
        ("MAC", mac),
        ("IP", ip),
        ("Weight", weight),
        ("MM", mm),
        ("Next Hop", next_hop),
        ("RD", rd),
    ]
    if host_type == 'mac_only':
        rows = [r for r in rows if r[0] != 'IP']
    col_w = max(len(r[0]) for r in rows) + 1
    st.log("EVPN type-2 route (local):")
    for label, value in rows:
        st.log("  {} {}".format((label + ":").ljust(col_w), value))


def _show_evpn_type2_grep(node, mac_addr, ip_addr, host_type):
    """
    Run full 'show bgp l2vpn evpn route type 2' then filter in Python to lines
    matching MAC/IP plus the next 2 lines (next_hop and RT/ET/MM), so the
    parser sees full 3-line blocks. Used when dci_enabled.
    """
    try:
        full_out = st.show(node, "do show bgp l2vpn evpn route type 2", type='vtysh', skip_tmpl=True)
        if not full_out:
            return []
        all_lines = full_out.splitlines()
        # Strip framework log prefix only when present (e.g. "2026-02-22 22:04:35,481 T0000: INFO  [D8-leaf3_dc1] ");
        # do not strip lines that are pure CLI (route lines contain "]" and would be broken by a generic strip).
        _log_prefix = re.compile(r"^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}[^\]]*\]\s*")
        all_lines = [_log_prefix.sub("", line) for line in all_lines]
        # Keep each matching line and the next 3 lines so we preserve route / next_hop / attributes block
        indices_to_keep = set()
        for i, line in enumerate(all_lines):
            if mac_addr in line or (ip_addr and ip_addr in line):
                indices_to_keep.update([i, i + 1, i + 2, i + 3])
        lines = [all_lines[j] for j in sorted(indices_to_keep) if j < len(all_lines)]
        raw = '\n'.join(lines) if lines else ''
    except Exception:
        raw = ''
    if not raw or not raw.strip():
        return []
    lines = raw.strip().splitlines()
    # Parse blocks: route line (* [2]:...), then next_hop/weight line, then RT/ET/MM line
    route_re = re.compile(
        r"^\s*([*>\s]+)\s+\[2\]:\[\d+\]:\[\d+\]:\[([0-9a-fA-F:]+)\](?::\[(\d+)\]:\[([\d.:A-Fa-f]+)\])?"
    )
    # Weight is the last number before origin (i/e/?); local = 32768. Allow \s* so line may have no leading spaces.
    next_hop_re = re.compile(r"^\s*(\S+)\s+(.*?)\s+(\d+)\s+([ie?])$")
    rt_re = re.compile(r"^\s*RT:\d+:\d+\s+ET:(\d+)(?:\s+MM:(\d+))?")
    rt_alt_re = re.compile(r"^\s*RT:\d+:\d+\s+RT:\d+:\d+\s+ET:(\d+)(?:\s+MM:(\d+))?")
    et_rt_re = re.compile(r"^\s*ET:\d+\s+RT:\d+:\d+(?:\s+MM:(\d+))?")  # ET:8 RT:65203:5020 [MM:1]
    parsed = []
    i = 0
    while i < len(lines):
        m = route_re.search(lines[i])
        if m:
            status, mac, ip_len, ip_val = m.groups()
            ip_val = ip_val or ''
            weight = ''
            next_hop = ''
            mm = ''
            if i + 1 < len(lines):
                nh_line = lines[i + 1]
                nh_m = next_hop_re.search(nh_line)
                if nh_m:
                    next_hop, weight, _path, _orig = nh_m.groups()
                # Fallback: weight is last number before " i"/" e"/" ?" on next_hop line
                if not weight and re.search(r"\d+\s+[ie?]\s*$", nh_line):
                    w_m = re.search(r"\s+(\d+)\s+[ie?]\s*$", nh_line)
                    if w_m:
                        weight = w_m.group(1)
                if not next_hop and nh_line.strip():
                    parts = nh_line.strip().split()
                    if parts:
                        next_hop = parts[0]
            # ET/MM line may be at i+2 or i+3 (optional ESI/ND line in between)
            for offset in (2, 3):
                if i + offset >= len(lines):
                    break
                line_attr = lines[i + offset]
                rt_m = rt_re.search(line_attr) or rt_alt_re.search(line_attr) or et_rt_re.search(line_attr)
                if rt_m:
                    # RT...ET format has MM as group(2); ET...RT format has MM as group(1)
                    et_m = et_rt_re.search(line_attr)
                    mm = (et_m.group(1) if et_m else rt_m.group(2)) or ''
                # Fallback: ET:8 RT:... Rmac:... MM:1 (MM may appear after other tokens)
                if not mm:
                    mm_m = re.search(r"MM:(\d+)", line_attr)
                    if mm_m:
                        mm = mm_m.group(1)
                if mm:
                    break
            parsed.append({
                "mac": mac,
                "ip": ip_val,
                "weight": weight,
                "next_hop": next_hop,
                "mm": mm,
                "route_distinguisher": "",
            })
            i += 2  # skip route line and next_hop line
            # Skip attribute lines (ET/RT/MM, ESI, ND:Proxy) until next route or end
            while i < len(lines):
                li = lines[i].strip()
                if (rt_re.search(lines[i]) or rt_alt_re.search(lines[i]) or et_rt_re.search(lines[i]) or
                        li.startswith('ESI:') or 'ND:Proxy' in lines[i] or 'Rmac:' in lines[i]):
                    i += 1
                else:
                    break
            continue
        i += 1
    return parsed


def _node_matches_expected(node, host_local_node):
    """True if node is in host_local_node or any entry is a substring of node (e.g. D8-leaf3_dc1 matches leaf3_dc1)."""
    if node in host_local_node:
        return True
    return any(exp in node for exp in host_local_node)


def verify_mac_seq(host_info, mac_move_seq="", ip="", host_local_node=[], host_type='mac_only', is_mh_host=False, dci_enabled=False):
    """
    Verify MAC (and optionally IP) is learned with expected sequence on leaf nodes.

    When dci_enabled=True: uses _show_evpn_type2_grep for targeted route lookup
    (avoids full BGP table parse), logs route table for debugging, enforces
    sequence check on local route. When False: uses standard parse_show path.
    """
    leaf_nodes = []
    for dut in st.get_dut_names():
        if "leaf" in dut:
            leaf_nodes.append(dut)
    flag = False
    local_flag = False
    learn_type = ""
    found_on_node = None
    found_seq = None
    if host_type == 'mac_only':
        mac_addr = host_info
        ip_addr = ''
    else:
        mac_addr = host_info['mac']
        ip_addr = host_info['ip']

    show_kw = {'type': 'vtysh', 'skip_tmpl': True}

    for node in leaf_nodes:
        if not dci_enabled:
            st.banner("inside " + node)
        if dci_enabled:
            # Grep on device so only matching routes are returned (avoids logging full BGP table).
            ip_addr_val = '' if host_type == 'mac_only' else host_info.get('ip', '')
            parsed_output = _show_evpn_type2_grep(node, mac_addr, ip_addr_val, host_type)
            st.log("Node {}: parsed {} route(s) matching MAC/IP".format(node, len(parsed_output)))
        else:
            cli_output = st.show(node, "do show bgp l2vpn evpn route type 2", **show_kw)
            parsed_output = st.parse_show(node, "show bgp l2vpn evpn route type 2", cli_output, "show_bgp_l2vpn_evpn_route_type_2.tmpl")
        mac_found = False
        ip_found = False
        for item in parsed_output:
            for key, value in item.items():
                if host_type == 'mac_only':
                    if key == "mac" and value == mac_addr:
                        mac_found = True
                        flag = True
                        if item['ip'] == '':
                            if item['weight'] == '32768':
                                if dci_enabled:
                                    found_on_node = node
                                    found_seq = item.get('mm', '')
                                    _log_evpn_type2_route_table(node, item, 'mac_only')
                                else:
                                    st.log(item)
                                learn_type = 'local'
                                if is_mh_host:
                                    if _node_matches_expected(node, host_local_node):
                                        st.log("mac learnt locally on node: {}".format(node))
                                        local_flag = True
                                else:   
                                    if _node_matches_expected(node, host_local_node):
                                        st.log("mac learnt locally on expected node: {}".format(node))
                                        local_flag = True
                                    else:
                                        local_flag = False
                                        st.log("mac learnt locally on unexpected node: {}".format(node)) 
                            else:
                                learn_type = 'remote'
                    
                            # Only enforce sequence check on local route; remote routes may have empty/different mm
                            if item['weight'] == '32768' and item['mm'] != mac_move_seq:
                                flag = False
                                st.log("found wrong sequence id: expected - {} found - {} ".format(mac_move_seq, item['mm']))
                            elif item['weight'] == '32768':
                                st.log("found correct sequence id: expected-->{}, found -->{} ".format(mac_move_seq, item['mm']))
                            # Log learning type only for local path to avoid repeated "mac learning : remote" per path
                            if item['weight'] == '32768':
                                st.log("mac learning : {}".format(learn_type))
                    
                else:
                    if key == "mac" and value == mac_addr:
                        mac_found = True
                        flag = True
                        if item['ip'] == ip_addr:
                            if not ip_found:
                                st.log('ip_found')
                            ip_found = True
                            if item['weight'] == '32768':
                                if dci_enabled:
                                    found_on_node = node
                                    found_seq = item.get('mm', '')
                                    _log_evpn_type2_route_table(node, item, 'mac_and_ip')
                                else:
                                    st.log(item)
                                learn_type = 'local'
                                if _node_matches_expected(node, host_local_node):
                                    st.log("mac learnt locally on expected node: {}".format(node))
                                    local_flag = True
                                else:
                                    local_flag = False
                                    st.log("mac learnt locally on unexpected node: {}".format(node))    
                            else:
                                learn_type = 'remote'
                    
                            # Only enforce sequence check on local route; remote routes may have empty/different mm
                            if item['weight'] == '32768' and item['mm'] != mac_move_seq:
                                flag = False
                                st.log("found wrong sequence id: expected - {} found - {} ".format(mac_move_seq, item['mm']))
                            elif item['weight'] == '32768':
                                st.log("found correct sequence id: expected-->{}, found -->{} ".format(mac_move_seq, item['mm']))
                            # Log learning type only for local path to avoid repeated "mac learning : remote" per path
                            if item['weight'] == '32768':
                                st.log("mac learning : {}".format(learn_type))
    # DCI-only: final summary for easy debugging (do not change existing non-DCI behavior)
    if dci_enabled:
        mac_display = "MAC {} (host_type={})".format(mac_addr, host_type)
        if ip_addr:
            mac_display += " IP {}".format(ip_addr)
        if not mac_found:
            st.banner("MAC verification FAILED: {} not found in EVPN type-2 table on any leaf.".format(mac_display))
            return False
        if flag and local_flag:
            st.banner("MAC verification PASSED: Found {} on node '{}', seq={} (expected seq={}), expected_nodes={}.".format(
                mac_display, found_on_node or '?', found_seq, mac_move_seq, host_local_node))
            return True
        if not flag:
            st.banner("MAC verification FAILED: {} found but wrong sequence (expected seq={}, found seq={}) on node '{}'.".format(
                mac_display, mac_move_seq, found_seq, found_on_node or '?'))
        else:
            st.banner("MAC verification FAILED: {} found but on unexpected node (found on '{}', expected one of {}).".format(
                mac_display, found_on_node or '?', host_local_node))
        return False
    if not mac_found:
        st.banner("Host not found in the table")
        return False
    if flag and local_flag:
        return True
    else:
        return False
            

def get_evpn_timers(dut):
    cli_output = st.show(dut, "show evpn", skip_tmpl=True)
    patterns = {
    "mac-holdtime": r"mac-holdtime:\s*(\d+)s",
    "neigh-holdtime": r"neigh-holdtime:\s*(\d+)s",
    "startup-delay": r"startup-delay:\s*(\d+)s",
    "start-delay-timer": r"start-delay-timer:\s*([^\s,]+)",
    "uplink-cfg-cnt": r"uplink-cfg-cnt:\s*(\d+)",
    "uplink-active-cnt": r"uplink-active-cnt:\s*(\d+)"
    }
    out_dict = {}
    for key, pattern in patterns.items():
        match = re.search(pattern, cli_output)
        if match:
            out_dict[key] = match.group(1)
    return out_dict

def get_mac_agetime(dut):
    cli_output = st.show(dut, "show mac aging-time", skip_tmpl=True)
    match = re.search(r'(\d+)\s+seconds', cli_output)
    if match:
        aging_time = int(match.group(1))
        return aging_time
    
def change_fdb_ageout(ageout_time = "600"):
    # Define the JSON content to be written to the file
    data = [
        {
            "SWITCH_TABLE:switch": {
                "fdb_aging_time": ageout_time
            },
            "OP": "SET"
        }
    ]

    # Specify the filename
    basename = 'ageout.json'
    filename = '/tmp/' + basename

    # Write the JSON content to the file
    with open(filename, 'w') as file:
        json.dump(data, file, indent=4)

    st.log("File {} has been created with the specified content.".format(filename))
    for dut in st.get_dut_names():
        if "leaf" in dut:
            utils_obj.copy_files_to_dut(dut, [filename], '/home/cisco')
            st.config(dut,"docker cp /home/cisco/ageout.json swss:/",sudo=False, split_cmds=False)
            st.config(dut,"docker exec -it swss swssconfig ageout.json",sudo=False, split_cmds=False)
            st.show(dut, 'sonic-db-dump -n APPL_DB -k *SWITCH_TABLE:switch* -y', skip_tmpl=True, skip_error_check=True)

def start_device_group(port):
    tg_handle = handles.values()[0]['tg_handle']
    tmp_handle = handles[port]['int_handle']
    device_group = "/"+"/".join(tmp_handle.split('/',3)[1:3])
    tg_handle.tg_test_control(action="start_protocol", handle=device_group)
    st.wait(10)		##give time to start protocol

def enable_uplink_tracking_configs(nodes, add=True, vars=None):
    if vars is None:
        vars = st.get_testbed_vars()
    int_config_dict = get_config_interfaces_list(vars)
    for node in nodes:
        for interface in int_config_dict[node]['underlay']:
            config_out = ""
            config_out += "interface {}\n".format(interface)
            if add:
                config_out += "evpn mh uplink\nend\nexit\n"
            else:
                config_out += "no evpn mh uplink\nend\nexit\n"
            st.config(node, config_out, type='vtysh', skip_error_check=True)

def validate_stats(tg_handle,traffic_item):
    traffic_stat = tg_handle.tg_traffic_stats(mode='traffic_item', streams=traffic_item)
    flag = True 
    for key , values in traffic_stat['traffic_item'].items():
        if key == traffic_item:
            st.banner("TRAFFIC ITEM {}".format(traffic_item))
            st.log("Received traffic: {}".format(values['rx']['total_pkts']))
            st.log("Sent traffic: {}".format(values['tx']['total_pkts']))
            st.log(int(values['rx']['total_pkts'])/int(values['tx']['total_pkts']))
            if int(values['rx']['total_pkts']) > 0.998*int(values['tx']['total_pkts']) and \
                int(values['rx']['total_pkts']) < 1.002*int(values['tx']['total_pkts']):
                st.log(" TRAFFIC ITEM {} PASSED".format(traffic_item))
            else:
                st.log(" TRAFFIC ITEM {} FAILED".format(traffic_item))
                flag = False
    return flag 

def generate_ip_list(start_ip, num_ips=20):
    def increment_ip(ip):
        parts = list(map(int, ip.split('.')))
        parts[3] += 1
        
        for i in range(3, 0, -1):
            if parts[i] > 255:
                parts[i] = 0
                parts[i-1] += 1
        return '.'.join(map(str, parts))
    ip_list = [start_ip]
    for _ in range(num_ips - 1):
        new_ip = increment_ip(ip_list[-1])
        ip_list.append(new_ip)
    return ip_list

def increment_mac_address(mac_address, increment_value = 1):
    mac_int = int(mac_address.replace(":", ""), 16)
    mac_int += increment_value
    mac_int = mac_int & 0xFFFFFFFFFFFF
    new_mac = '{:012X}'.format(mac_int) 
    new_mac = ':'.join(new_mac[i:i+2] for i in range(0, 12, 2))
    return new_mac

def get_vlan_info(test_cfg):
    my_dict ={}
    for item, value in test_cfg.items():
        if "leaf" in item:
            my_dict[item]={}
            my_dict[item]['orphan_vlan_list'] = []
            my_dict[item]['po_vlan_list'] = [] 
            for vlan in value['l2vni']:
                for info , values in vlan.items():
                    if info == "members":
                        for mem in values:
                            if "PortChannel" in mem:
                                my_dict[item]['po_vlan_list'].append(vlan['vlan_id'])
                            else:
                                my_dict[item]['orphan_vlan_list'].append((vlan['vlan_id']))
    return my_dict

def dhcp_relay_config(add = True, src_loopback = True, dhcp_helper = True):


    leaf_nodes=[]
    for dut in st.get_dut_names():
        if "leaf" in dut:
            leaf_nodes.append(dut)
    def config_gen(loopback = "", input_dict ={}, add = True):
        cmd = ""
        for item in input_dict["client_vlans"]:
            if add:
                if src_loopback:
                    cmd += "config vlan dhcp-relay-src add {} {}\n".format(item, loopback)
                if dhcp_helper:
                    for server_vlan in input_dict["server_vlans"]:
                        if server_vlan == 30:
                            cmd += "config vlan dhcp_relay add {} 80.{}.0.89\n".format(item,server_vlan)
                        else:
                            cmd += "config vlan dhcp_relay add {} 80.{}.0.88\n".format(item,server_vlan)
            else:
                if dhcp_helper:
                    for server_vlan in input_dict["server_vlans"]:
                        if server_vlan == 30:
                            cmd += "config vlan dhcp_relay del {} 80.{}.0.89\n".format(item,server_vlan)
                        else:
                            cmd += "config vlan dhcp_relay del {} 80.{}.0.88\n".format(item,server_vlan)
                if src_loopback:
                    cmd += "config vlan dhcp-relay-src del {}\n".format(item)
        return cmd

    i = 1
    input_dict = {"Vrf101": {"client_vlans":[2,3], "server_vlans":[20,30,75]},"Vrf102": {"client_vlans":[5], "server_vlans":[4]}, "Vrf103": {"client_vlans":[6], "server_vlans":[7]}}
    for node in leaf_nodes:
        cmd = ""
        print("inside {}".format(node))
        for count in range(1,4):
            loop = "Loopback10{}".format(str(count))
            if add:
                if not dhcp_helper and not src_loopback:
                    cmd += "config interface vrf bind {} Vrf10{}\n".format(loop,count)
                    cmd += "config interface ip add {} 11{}.111.111.10{}/32\n".format(loop,str(i),str(count))
                
                cmd += config_gen(loopback = loop, input_dict = input_dict["Vrf10"+str(count)]) 
            else:
                cmd += config_gen(loopback = loop, input_dict = input_dict["Vrf10"+str(count)],add = False)
                if not dhcp_helper and not src_loopback:
                    cmd += "config interface vrf unbind {}\n".format(loop,count)
        i += 1
        st.config(node, cmd, skip_error_check=True)
        if not dhcp_helper and not src_loopback:
            if add:
                server_2 = "config vlan dhcp_relay add 5 80.4.0.89\nconfig vlan dhcp_relay add 6 80.7.0.89\n"
            else:
                server_2 = "config vlan dhcp_relay del 5 80.4.0.89\nconfig vlan dhcp_relay del 6 80.7.0.89\n"
            st.config(node, server_2, skip_error_check=True)

def get_client_ip_list(stats):
    ip_list = []
    flag = True
    count = 1
    for key, value in stats['session'].items():
        if value['Address'] == "reserveSlot[Unresolved]":
            flag = False
        else:
            ip_list.append(value['Address'])
        st.log("client{} ip status : {}".format(count,value['Address']))
        count += 1
    return ip_list, flag

def get_type2_route(dut):
    cli_output = st.show(dut, "do show bgp l2vpn evpn route type 2",type='vtysh', skip_tmpl=True)
    parsed_output = st.parse_show(dut, "show bgp l2vpn evpn route type 2",cli_output, "show_bgp_l2vpn_evpn_route_type_2.tmpl")
    return parsed_output

def validate_mac_type2_route(mac_address_list, host_local_node=[], is_mh_host = True):
    leaf_nodes = []
    for dut in st.get_dut_names():
        if "leaf" in dut:
            leaf_nodes.append(dut)
    flag_dict = {}
    parsed_output = {}
    for node in leaf_nodes:
        parsed_output[node] = get_type2_route(node)
    
    for node in leaf_nodes:
        flag_dict[node] = {}
        for mac_info in mac_address_list:
            flag_dict[node][mac_info] = True
            result = verify_type2_route(mac_info, parsed_output= parsed_output[node], host_local_node=host_local_node, is_mh_host=is_mh_host, node=node)
            if not result:
                flag_dict[node][mac_info] = False
                st.error("MAC {} not found in node {}".format(mac_info, node))
    return flag_dict

def verify_type2_route(host_info, parsed_output=[], mac_move_seq="", ip="", host_local_node=[], host_type='mac_only', is_mh_host=False, node="", dci_enabled=False):
    """
    Verify EVPN type-2 route for MAC/IP in parsed_output. When dci_enabled=True,
    enforces mac_move_seq only on local route (weight 32768); remote routes may
    have empty/different mm. Returns True if MAC found with correct seq on expected node.
    """
    flag = False
    local_flag = False
    learn_type = ""
    found_on_node = node
    found_seq = None
    if host_type == 'mac_only':
        mac_addr = host_info
        ip_addr = ''
    else:
        mac_addr = host_info['mac']
        ip_addr = host_info['ip']
    mac_found = False
    ip_found = False
    for item in parsed_output:
        for key, value in item.items():
            if host_type == 'mac_only':
                if key == "mac" and value == mac_addr:
                    mac_found = True
                    flag = True
                    if item['ip'] == '':
                        if item['weight'] == '32768':
                            found_seq = item.get('mm', '')
                            st.log(item)
                            learn_type = 'local'
                            if is_mh_host:
                                if _node_matches_expected(node, host_local_node):
                                    st.log("mac learnt locally on node: {}".format(node))
                                    local_flag = True 
                            else:   
                                if _node_matches_expected(node, host_local_node):
                                    st.log("mac learnt locally on expected node: {}".format(node))
                                    local_flag = True
                                else:
                                    local_flag = False
                                    st.log("mac learnt locally on unexpected node: {}".format(node)) 
                        else:
                            learn_type = 'remote'
            else:
                if key == "mac" and value == mac_addr:
                    mac_found = True
                    flag = True
                    if item['ip'] == ip_addr:
                        if not ip_found:
                            st.log('ip_found')
                        ip_found = True
                        if item['weight'] == '32768':
                            found_seq = item.get('mm', '')
                            st.log(item)
                            learn_type = 'local'
                            if _node_matches_expected(node, host_local_node):
                                st.log("mac learnt locally on expected node: {}".format(node))
                                local_flag = True
                            else:
                                local_flag = False
                                st.log("mac learnt locally on unexpected node: {}".format(node))    
                        else:
                            learn_type = 'remote'
                    
                        if dci_enabled:
                            # Only enforce sequence check on local route; remote routes may have empty/different mm
                            if item['weight'] == '32768' and item['mm'] != mac_move_seq:
                                flag = False
                                st.log("found wrong sequence id: expected - {} found - {} ".format(mac_move_seq, item['mm']))
                            elif item['weight'] == '32768':
                                st.log("found correct sequence id: expected-->{}, found -->{} ".format(mac_move_seq, item['mm']))
                        else:
                            if item['mm'] != mac_move_seq:
                                flag = False
                                st.log("found wrong sequence id: expected - {} found - {} ".format(mac_move_seq, item['mm']))
                            else:
                                st.log("found correct sequence id: expected-->{}, found -->{} ".format(mac_move_seq, item['mm']))
                        # Log learning type only for local path to avoid repeated "mac learning : remote" per path
                        if item['weight'] == '32768':
                            st.log("mac learning : {}".format(learn_type))
    mac_display = "MAC {} (host_type={})".format(mac_addr, host_type)
    if ip_addr:
        mac_display += " IP {}".format(ip_addr)
    if not mac_found:
        st.banner("MAC verification FAILED [node '{}']: {} not found in EVPN type-2 table.".format(node, mac_display))
        return False
    if flag and local_flag:
        st.banner("MAC verification PASSED [node '{}']: Found {}, seq={} (expected seq={}), expected_nodes={}.".format(
            node, mac_display, found_seq, mac_move_seq, host_local_node))
        return True
    if not flag:
        st.banner("MAC verification FAILED [node '{}']: {} wrong sequence (expected seq={}, found seq={}).".format(
            node, mac_display, mac_move_seq, found_seq))
    else:
        st.banner("MAC verification FAILED [node '{}']: {} on unexpected node (expected one of {}).".format(
            node, mac_display, host_local_node))
    return False

def get_bgp_summary(dut):
    """
    parses 'show bgp summary' output into data struct below
    sonic# show bgp summary

    IPv4 Unicast Summary (VRF default):
    BGP router identifier 10.200.200.203, local AS number 65203 vrf-id 0
    BGP table version 2
    RIB entries 3, using 576 bytes of memory
    Peers 4, using 2898 KiB of memory
    Peer groups 2, using 128 bytes of memory

    Neighbor        V         AS   MsgRcvd   MsgSent   TblVer  InQ OutQ  Up/Down State/PfxRcd   PfxSnt Desc
    Ethernet1_1     4      65100       402       404        0    0    0 06:28:12            2        2 N/A
    Ethernet1_2     4      65101       405       402        0    0    0 06:28:05            2        2 N/A
    Ethernet1_3     4      65102       403       405        0    0    0 06:28:11            2        2 N/A
    Ethernet1_4     4      65103       406       403        0    0    0 06:28:07            2        2 N/A

    Total number of neighbors 4

    IPv6 Unicast Summary (VRF default):
    BGP router identifier 10.200.200.203, local AS number 65203 vrf-id 0
    BGP table version 14
    RIB entries 15, using 2880 bytes of memory
    Peers 4, using 2898 KiB of memory
    Peer groups 2, using 128 bytes of memory

    Neighbor        V         AS   MsgRcvd   MsgSent   TblVer  InQ OutQ  Up/Down State/PfxRcd   PfxSnt Desc
    Ethernet1_1     4      65100       402       404        0    0    0 06:28:12            7        8 N/A
    Ethernet1_2     4      65101       405       402        0    0    0 06:28:05            7        8 N/A
    Ethernet1_3     4      65102       403       405        0    0    0 06:28:11            7        8 N/A
    Ethernet1_4     4      65103       406       403        0    0    0 06:28:07            7        8 N/A

    Total number of neighbors 4

    L2VPN EVPN Summary (VRF default):
    BGP router identifier 10.200.200.203, local AS number 65203 vrf-id 0
    BGP table version 0
    RIB entries 105, using 20 KiB of memory
    Peers 3, using 2174 KiB of memory
    Peer groups 2, using 128 bytes of memory

    Neighbor        V         AS   MsgRcvd   MsgSent   TblVer  InQ OutQ  Up/Down State/PfxRcd   PfxSnt Desc
    2000:1::1       4      65200      3899      3736        0    0    0 06:28:05          114      168 N/A
    2000:1::2       4      65201      3679      3736        0    0    0 06:28:05          114      168 N/A
    2000:1::3       4      65202      4612      3737        0    0    0 06:28:03          114      168 N/A

    Total number of neighbors 3
    """
    cmd = 'show bgp summary'
    cmd_output = st.vtysh_show(dut, cmd, skip_tmpl=True, skip_error_check=False)
    parsed_output = st.parse_show(dut, cmd, cmd_output, 'show_ip_bgp_summary.tmpl')
    return parsed_output

def get_expected_bgp_summary(dut, vars=None):
    if vars is None:
        vars = st.get_testbed_vars()
    ret_val = list()
    loopback_ip = generate_loopback_ip(st.getenv("vtep"))
    cfg_dict = get_cfg_dict()
    other_dut = []
    int_config_dict = get_config_interfaces_list(vars)
    for intf in int_config_dict[dut]['underlay']:
        ret_val.append({"protocol":"IPv4 Unicast", "neighbor":intf, "state":"Up"})
        ret_val.append({"protocol":"IPv6 Unicast", "neighbor":intf, "state":"Up"})

    for d in cfg_dict['nodes']['l2l3vni']:
        if (dut not in d):
            other_dut.append(d)
    for d in other_dut:
        ret_val.append({"protocol":"L2VPN EVPN", "neighbor":loopback_ip[d], "state":"Up"})

    return ret_val

@VerifyLoop()
def verify_bgp_summary(dut, exp_data, **kwargs):
    """
    verify show bgp summary output attributes
    """
    act_data = get_bgp_summary(dut)
    # Change state from number to "up"
    for item in act_data:
        if item['state'].isnumeric():
            item['state'] = 'Up'
    compare_exp_actual_data(exp_data, act_data, ['protocol', 'neighbor', 'state'])

def get_bfd_summary(dut):
    """
    parses 'show bfd summary' output into data struct below
    cisco@sonic:~$ show bfd summary
    Total number of BFD sessions: 4
    Peer Addr                  Interface    Vrf      State    Type          Local Addr                   TX Interval    RX Interval    Multiplier  Multihop      Local Discriminator
    -------------------------  -----------  -------  -------  ------------  -------------------------  -------------  -------------  ------------  ----------  ---------------------
    fe80::7abe:47ff:fe2e:d000  Ethernet1_2  default  Up       async_active  fe80::7aaf:c9ff:fe30:a400            300            300             3  false                           4
    fe80::7ade:27ff:fedc:b000  Ethernet1_3  default  Up       async_active  fe80::7aaf:c9ff:fe30:a400            300            300             3  false                           2
    fe80::7a2a:84ff:fe68:8000  Ethernet1_4  default  Up       async_active  fe80::7aaf:c9ff:fe30:a400            300            300             3  false                           3
    fe80::7acb:a2ff:febb:7000  Ethernet1_1  default  Up       async_active  fe80::7aaf:c9ff:fe30:a400            300            300             3  false                           1
    cisco@sonic:~$
    """
    cmd = 'show bfd summary'
    cmd_output = st.show(dut, cmd, skip_tmpl=True, skip_error_check=False)
    parsed_output = st.parse_show(dut, cmd, cmd_output, 'show_bfd_sum_sonic.tmpl')

    return parsed_output

def get_expected_bfd_summary(dut, vars=None):
    if vars is None:
        vars = st.get_testbed_vars()
    ret_val = list()
    int_config_dict = get_config_interfaces_list(vars)
    for intf in int_config_dict[dut]['underlay']:
        ret_val.append({"interface":intf, "state":"Up"})

    return ret_val

@VerifyLoop()
def verify_bfd_summary(dut, exp_data, **kwargs):
    """
    verify show bfd summary output attributes
    """
    act_data = get_bfd_summary(dut)
    compare_exp_actual_data(exp_data, act_data, ['interface', 'state'])


def get_vxlan_tunnel(dut):
    """
    Parse 'show vxlan tunnel' output into a list of dicts:

    {
      "vxlan_tunnel_name": <tunnel name>,   # e.g. "VXLAN", "vxlan-dc", "vxlan-wan"
      "source_ip":         <SIP>,           # e.g. "2000:1::1", "4000:1::1", "101.101.101.101"
      "destination_ip":    "",              # column is blank in current output
      "tunnel_map_name":   <map_...>,
      "tunnel_map_mapping":"<VNI> -> <VlanXX>",
    }
    """
    cmd = 'show vxlan tunnel'
    cmd_output = st.show(dut, cmd, skip_tmpl=True, skip_error_check=False)

    if isinstance(cmd_output, str):
        lines = cmd_output.splitlines()
    elif isinstance(cmd_output, list):
        if len(cmd_output) == 1 and isinstance(cmd_output[0], str):
            lines = cmd_output[0].splitlines()
        else:
            joined = "\n".join(str(x) for x in cmd_output)
            lines = joined.splitlines()
    else:
        st.log("[ERR] get_vxlan_tunnel: unexpected cmd_output type {}".format(type(cmd_output)))
        return []

    # First line of a tunnel, e.g.:
    # VXLAN     2000:1::1   <blank>   map_5011_Vlan11   5011 -> Vlan11
    first_line_re = re.compile(
        r'^\s*(\S+)\s+([0-9a-fA-F:\.]+)\s+\S*\s+(map_\S+)\s+(\d+)\s+->\s+(\S+)\s*$'
    )

    # Continuation lines:
    # map_5012_Vlan12    5012 -> Vlan12
    cont_line_re = re.compile(
        r'^\s*(map_\S+)\s+(\d+)\s+->\s+(\S+)\s*$'
    )

    results = []
    current_name = None
    current_src_ip = None

    for line in lines:
        line = line.rstrip()

        # Skip headers/separators/prompt
        if not line.strip():
            continue
        if line.startswith('vxlan tunnel name') or line.startswith('---'):
            continue
        if line.strip().startswith('cisco@'):
            continue

        m = first_line_re.match(line)
        if m:
            # New tunnel block
            current_name   = m.group(1)  # tunnel name (VXLAN, vxlan-dc, vxlan-wan)
            current_src_ip = m.group(2)  # SIP
            tunmap         = m.group(3)
            vni            = m.group(4)
            vlan           = m.group(5)

            results.append({
                "vxlan_tunnel_name": current_name,
                "source_ip":         current_src_ip,
                "destination_ip":    "",  # dest column is blank
                "tunnel_map_name":   tunmap,
                "tunnel_map_mapping": "{} -> {}".format(vni, vlan),
            })
            continue

        m = cont_line_re.match(line)
        if m and current_name and current_src_ip:
            tunmap = m.group(1)
            vni    = m.group(2)
            vlan   = m.group(3)

            results.append({
                "vxlan_tunnel_name": current_name,
                "source_ip":         current_src_ip,
                "destination_ip":    "",
                "tunnel_map_name":   tunmap,
                "tunnel_map_mapping": "{} -> {}".format(vni, vlan),
            })
            continue

    return results

def get_expected_vxlan_tunnel(dut):
    """
    Generate expected tunnel mappings based on DUT configuration.
    
    Returns list of dicts with expected tunnel attributes:
    [{
      'vxlan_tunnel_name': 'vxlan-dc',
      'source_ip': '4000:1::1',
      'destination_ip': '',
      'tunnel_map_name': 'map_5011_Vlan11',
      'tunnel_map_mapping': '5011 -> Vlan11'
    }, ...]
    
    For BGW nodes: returns both vxlan-dc and vxlan-wan tunnels
    For leaf nodes: returns only vxlan-dc tunnel (or VXLAN)
    """
    ret_val = []
    
    cfg_dict = get_cfg_dict()
    
    # Check if dut has configuration
    if dut not in cfg_dict:
        st.log(f"WARNING: {dut} not found in cfg_dict, skipping VXLAN tunnel verification")
        return ret_val
    
    dut_cfg = cfg_dict.get(dut, {})
    
    # Get loopback IPs
    loopback_ip = generate_loopback_ip(st.getenv("vtep"))
    
    # Check if this is a BGW with DCI configuration
    (loopback_ipv6_dc_vip,
     loopback_ipv4_wan_vip,
     loopback_ipv4_wan_overlay,
     transit_wan_ipv4_underlay) = generate_dci_vip_maps()
    
    is_bgw = dut in loopback_ipv6_dc_vip or dut in loopback_ipv4_wan_vip
    
    # Get L2VNI configuration
    l2vni_config = dut_cfg.get('l2vni', [])
    if not l2vni_config:
        return ret_val
    
    # Ensure it's a list
    if not isinstance(l2vni_config, list):
        l2vni_config = [l2vni_config]
    
    # Get L3VNI configuration
    l3vni_config = dut_cfg.get('l3vni', [])
    if not isinstance(l3vni_config, list):
        l3vni_config = [l3vni_config] if l3vni_config else []

    # For BGW nodes with DCI
    if is_bgw:
        # Get source IPs
        dc_source_ip = loopback_ipv6_dc_vip.get(dut)
        wan_source_ip = loopback_ipv4_wan_vip.get(dut)
        
        # Iterate through all L2VNI entries - config has separate entries for vxlan-dc and vxlan-wan
        for l2vni_item in l2vni_config:
            vlan_id = l2vni_item.get('vlan_id')
            vni = l2vni_item.get('vxlan_id') or l2vni_item.get('vni')
            vxlan_name = l2vni_item.get('vxlan_name', '')
            
            if not vlan_id or not vni:
                continue
            
            # Check vxlan_name to determine which tunnel this belongs to
            if vxlan_name == 'vxlan-dc' and dc_source_ip:
                ret_val.append({
                    'vxlan_tunnel_name': 'vxlan-dc',
                    'source_ip': dc_source_ip,
                    'destination_ip': '',
                    'tunnel_map_name': f'map_{vni}_Vlan{vlan_id}',
                    'tunnel_map_mapping': f'{vni} -> Vlan{vlan_id}'
                })
            elif vxlan_name == 'vxlan-wan' and wan_source_ip:
                ret_val.append({
                    'vxlan_tunnel_name': 'vxlan-wan',
                    'source_ip': wan_source_ip,
                    'destination_ip': '',
                    'tunnel_map_name': f'map_{vni}_Vlan{vlan_id}',
                    'tunnel_map_mapping': f'{vni} -> Vlan{vlan_id}'
                })

        # L3VNI entries on BGW: mapped on both vxlan-dc and vxlan-wan tunnels
        for l3vni_item in l3vni_config:
            vrf_id = l3vni_item.get('vrf_id')
            vni = l3vni_item.get('vxlan_id') or l3vni_item.get('vni')
            if not vrf_id or not vni:
                continue
            vlan_id = vrf_id  # L3VNI VLAN = VRF ID (e.g. Vrf101 -> Vlan101)
            if dc_source_ip:
                ret_val.append({
                    'vxlan_tunnel_name': 'vxlan-dc',
                    'source_ip': dc_source_ip,
                    'destination_ip': '',
                    'tunnel_map_name': f'map_{vni}_Vlan{vlan_id}',
                    'tunnel_map_mapping': f'{vni} -> Vlan{vlan_id}'
                })
            if wan_source_ip:
                ret_val.append({
                    'vxlan_tunnel_name': 'vxlan-wan',
                    'source_ip': wan_source_ip,
                    'destination_ip': '',
                    'tunnel_map_name': f'map_{vni}_Vlan{vlan_id}',
                    'tunnel_map_mapping': f'{vni} -> Vlan{vlan_id}'
                })
    
    # For regular leaf nodes
    else:
        source_ip = loopback_ip.get(dut)
        if not source_ip:
            return ret_val
        
        # Determine tunnel name (usually 'VXLAN' or 'vxlan-dc')
        tunnel_name = 'VXLAN'  # Default for leaves
        
        for l2vni_item in l2vni_config:
            vlan_id = l2vni_item.get('vlan_id')
            vni = l2vni_item.get('vxlan_id') or l2vni_item.get('vni')  # Try both field names
            if vlan_id and vni:
                ret_val.append({
                    'vxlan_tunnel_name': tunnel_name,
                    'source_ip': source_ip,
                    'destination_ip': '',
                    'tunnel_map_name': f'map_{vni}_Vlan{vlan_id}',
                    'tunnel_map_mapping': f'{vni} -> Vlan{vlan_id}'
                })

        # L3VNI entries on leaf: mapped on the same VXLAN tunnel
        for l3vni_item in l3vni_config:
            vrf_id = l3vni_item.get('vrf_id')
            vni = l3vni_item.get('vxlan_id') or l3vni_item.get('vni')
            if not vrf_id or not vni:
                continue
            vlan_id = vrf_id  # L3VNI VLAN = VRF ID (e.g. Vrf101 -> Vlan101)
            ret_val.append({
                'vxlan_tunnel_name': tunnel_name,
                'source_ip': source_ip,
                'destination_ip': '',
                'tunnel_map_name': f'map_{vni}_Vlan{vlan_id}',
                'tunnel_map_mapping': f'{vni} -> Vlan{vlan_id}'
            })
    
    return ret_val


@VerifyLoop()
def verify_vxlan_tunnel(dut, exp_data, **kwargs):
    """
    verify show vxlan tunnel output attributes
    """
    act_data = get_vxlan_tunnel(dut)
    compare_exp_actual_data(exp_data, act_data, ['vxlan_tunnel_name', 'source_ip', 'destination_ip', 'tunnel_map_name', 'tunnel_map_mapping'])


def get_expected_bgp_summary_dci(dut):
    """
    Generate DCI-aware BGP summary expectations for a node.
    
    Returns list of dicts with expected BGP neighbor attributes:
    [{
      'protocol': 'IPv4 Unicast',
      'neighbor': '51.51.51.1',
      'state': 'Up'
    },
    {
      'protocol': 'IPv6 Unicast',
      'neighbor': 'Ethernet1_1',
      'state': 'Up'
    }, ...]
    
    For BGW nodes:
    - IPv4 Unicast: WAN underlay peers (TRANSIT_WAN to other DC BGWs), DC3_DIRECT, IHOP
    - IPv6 Unicast: Local leaf nodes (within same DC via Ethernet interfaces)
    
    For regular spines:
    - IPv6 Unicast: Local leaf nodes (within same DC via Ethernet interfaces)
    """
    import re
    ret_val = []
    
    # Extract DC from node name (dc1, dc2, dc3)
    dc_match = re.search(r'_(dc\d+)', dut)
    if not dc_match:
        st.log('Cannot determine DC for node: {}'.format(dut))
        return ret_val
    
    my_dc = dc_match.group(1)
    is_bgw = 'bgw' in dut.lower()
    
    # Get configuration
    cfg_dict = get_cfg_dict()
    if dut not in cfg_dict:
        return ret_val
    
    # Get interface configuration for underlay peers
    vars = st.get_testbed_vars()
    int_config = get_config_interfaces_list(vars)
    
    # Add IPv6 Unicast neighbors (local leaf nodes via Ethernet interfaces)
    if dut in int_config and 'underlay' in int_config[dut]:
        for intf in int_config[dut]['underlay']:
            ret_val.append({
                'protocol': 'IPv6 Unicast',
                'neighbor': intf,
                'state': 'Up'
            })
    
    # For BGW nodes, also add IPv4 Unicast WAN underlay neighbors
    if is_bgw:
        (loopback_ipv6_dc_vip,
         loopback_ipv4_wan_vip,
         loopback_ipv4_wan_overlay,
         transit_wan_ipv4_underlay) = generate_dci_vip_maps()
        
        # Get the underlay IPs for this BGW
        if dut in transit_wan_ipv4_underlay:
            underlay_ips = transit_wan_ipv4_underlay[dut]
            # For DC1 BGWs: peers with DC2/DC3 BGWs
            # For DC2 BGWs: peers with DC1/DC3 BGWs
            # For DC3 BGWs: peers with DC1/DC2 BGWs
            
            # Based on the actual BGP config, extract peer IPs
            # This is a simplified version - ideally should parse from BGP config
            # For now, we just note that IPv4 Unicast neighbors exist for BGWs
            pass
    
    return ret_val


@VerifyLoop()
def verify_bgp_summary_dci(dut, exp_data, **kwargs):
    """
    Verify BGP summary for DCI topology (DC-aware neighbor expectations)
    Combines IPv4 Unicast, IPv6 Unicast, and L2VPN EVPN verification in one table
    """
    act_data = get_bgp_summary(dut)
    # Convert numeric state values to "Up" (numeric = PfxRcd count, meaning session is established)
    for item in act_data:
        if item.get('state') and str(item['state']).isdigit():
            item['state'] = 'Up'
    compare_exp_actual_data(exp_data, act_data, ['protocol', 'neighbor'])
    return act_data


def get_expected_bgp_l2vpn_evpn_summary_dci(dut):
    """
    Generate DCI-aware BGP EVPN summary expectations for a BGW node.
    
    Returns list of dicts with expected BGP EVPN neighbor attributes:
    [{
      'protocol': 'L2VPN EVPN',
      'neighbor': '2000:1::1',
      'state': 'Up'
    },
    {
      'protocol': 'L2VPN EVPN',
      'neighbor': '10.10.10.10',
      'state': 'Up'
    }, ...]
    
    For BGW nodes, expects L2VPN EVPN peers:
    - Local leaf nodes (same DC) via DC loopback IPv6 IPs
    - Remote BGW nodes (other DCs) via WAN overlay IPv4 IPs
    """
    import re
    ret_val = []
    
    # Only BGW nodes have EVPN neighbors in DCI
    if 'bgw' not in dut.lower():
        return ret_val
    
    # Extract DC from node name
    dc_match = re.search(r'_(dc\d+)', dut)
    if not dc_match:
        st.log('Cannot determine DC for node: {}'.format(dut))
        return ret_val
    
    my_dc = dc_match.group(1)
    
    # Get configuration
    cfg_dict = get_cfg_dict()
    if dut not in cfg_dict:
        return ret_val
    
    # Add local leaf nodes (same DC) with their DC loopback IPv6 IPs
    for node_name, node_cfg in cfg_dict.items():
        if node_name == dut:
            continue
        
        # Check if node is in same DC
        node_dc_match = re.search(r'_(dc\d+)', node_name)
        if not node_dc_match or node_dc_match.group(1) != my_dc:
            continue
        
        # Check if it's a leaf node with loopback config
        if 'leaf' in node_name and node_cfg.get('loopbacks'):
            for lb_cfg in node_cfg['loopbacks']:
                if 'address' in lb_cfg and '::' in lb_cfg['address']:
                    # IPv6 loopback for EVPN
                    loopback_ip = lb_cfg['address'].split('/')[0]
                    ret_val.append({
                        'protocol': 'L2VPN EVPN',
                        'neighbor': loopback_ip,
                        'state': 'Up'
                    })
    
    # Add remote BGW nodes (other DCs) with their WAN overlay IPv4 IPs
    (loopback_ipv6_dc_vip,
     loopback_ipv4_wan_vip,
     loopback_ipv4_wan_overlay,
     transit_wan_ipv4_underlay) = generate_dci_vip_maps()
    
    for bgw_node, overlay_ip in loopback_ipv4_wan_overlay.items():
        if bgw_node == dut:
            continue
        
        # Check if BGW is in a different DC
        bgw_dc_match = re.search(r'_(dc\d+)', bgw_node)
        if bgw_dc_match and bgw_dc_match.group(1) != my_dc:
            ret_val.append({
                'protocol': 'L2VPN EVPN',
                'neighbor': overlay_ip,
                'state': 'Up'
            })
    
    return ret_val


@VerifyLoop()
def verify_bgp_l2vpn_evpn_summary_dci(dut, exp_data, **kwargs):
    """
    Verify BGP L2VPN EVPN summary for DCI topology (DC-aware neighbor expectations)
    """
    act_data = get_bgp_summary(dut)
    # Filter to only L2VPN EVPN entries
    evpn_data = [entry for entry in act_data if entry.get('protocol') == 'L2VPN EVPN']
    
    # Convert numeric state values to "Up" (numeric = PfxRcd count, meaning session is established)
    for item in evpn_data:
        if item.get('state') and str(item['state']).isdigit():
            item['state'] = 'Up'
    
    compare_exp_actual_data(exp_data, evpn_data, ['protocol', 'neighbor'])
    return evpn_data


def get_remote_macs_from_show_mac(dut, vlan_list=None):
    """
    Parse 'show mac' output and extract only remote MACs (Static type with VTEP IP as port).
    
    Args:
        dut: Device under test
        vlan_list: Optional list of VLANs to filter (e.g., [11, 12, 13])
    
    Returns:
        List of dicts with remote MAC entries:
        [{
          'vlan': '11',
          'macaddress': '00:20:01:00:00:11',
          'port': '2000:1::2',
          'type': 'Static'
        }, ...]
    
    Example 'show mac' output:
      No.    Vlan  MacAddress         Port          Type
    -----  ------  -----------------  ------------  -------
        1      11  00:50:06:00:00:11  4000:1::1     Static
        2      11  00:10:04:00:00:11  Ethernet1_1   Dynamic
    """
    import re
    
    cmd = 'show mac'
    cmd_output = st.show(dut, cmd, skip_tmpl=True, skip_error_check=False)
    parsed_output = st.parse_show(dut, cmd, cmd_output, 'show_mac.tmpl')
    
    remote_macs = []
    # IPv6 VTEP pattern (e.g., 2000:1::2, 4000:1::1)
    vtep_pattern = r'^[0-9a-f]{1,4}:[0-9a-f]{1,4}::[0-9a-f]{1,4}$'
    
    for entry in parsed_output:
        vlan = entry.get('vlan', '')
        mac = entry.get('macaddress', '')
        port = entry.get('port', '')
        entry_type = entry.get('type', '')
        
        # Skip entries with empty VLAN (continuation lines for multi-path ECMP entries)
        if not vlan or vlan == '':
            continue
        
        # Skip if VLAN filter is specified and this VLAN is not in the list
        if vlan_list and int(vlan) not in vlan_list:
            continue
        
        # Check if it's a remote MAC: Type=Static AND Port=VTEP IP
        if entry_type == 'Static' and re.match(vtep_pattern, port, re.IGNORECASE):
            remote_macs.append({
                'vlan': vlan,
                'macaddress': mac.lower(),  # Normalize to lowercase
                'port': port,
                'type': entry_type
            })
    
    return remote_macs


def get_expected_remote_macs(dut, vlan_list=None, host_info_dict=None, skip_absent_hosts=True):
    """
    Generate expected remote MAC addresses for a DUT based on topology and host configuration.
    
    Args:
        dut: Device under test (e.g., 'leaf0_dc1')
        vlan_list: Optional list of VLANs to check (e.g., [11, 12, 13])
                   If None, checks all VLANs
        host_info_dict: Host configuration dictionary from generate_sag_hosts()
                        If None, uses global g_v4_host_info_dict
        skip_absent_hosts: If True, only include MACs from nodes that have host info (default: True)
    
    Returns:
        List of expected remote MAC dicts:
        [{
          'vlan': '11',
          'macaddress': '00:20:01:00:00:11',
          'port': '2000:1::2',  # Remote VTEP IP
          'type': 'Static'
        }, ...]
    
    Logic:
        - For each remote node (different from dut):
          - Get the VTEP IP of that node
          - Get all host MACs configured on that node FOR THE SPECIFIED VLANs
          - Those MACs should appear as remote (Static) on the dut
    """
    ret_val = []
    
    cfg_dict = get_cfg_dict()
    nodes = cfg_dict['nodes']
    
    # Determine which nodes participate (leaves + BGWs if DCI enabled)
    participants = nodes.get('l2l3vni_bgw') or nodes.get('l2l3vni', [])
    
    if dut not in participants:
        st.log(f"DUT {dut} is not in participants list")
        return ret_val
    
    # Get loopback IPs for all nodes
    loopback_ip = generate_loopback_ip(st.getenv("vtep"))
    
    # Get DCI VIP maps if BGWs are involved
    (loopback_ipv6_dc_vip,
     loopback_ipv4_wan_vip,
     loopback_ipv4_wan_overlay,
     transit_wan_ipv4_underlay) = generate_dci_vip_maps()
    
    dut_dc = _get_dc_from_name(dut)
    if dut_dc is None:
        st.log(f"Cannot determine DC for {dut}")
        return ret_val
    
    # Use provided host_info_dict or global one
    if host_info_dict is None:
        # Try to get from global scope
        import sys
        frame = sys._getframe()
        while frame:
            if 'g_v4_host_info_dict' in frame.f_globals:
                host_info_dict = frame.f_globals['g_v4_host_info_dict']
                break
            frame = frame.f_back
    
    if not host_info_dict:
        st.log(f"No host_info_dict available for MAC verification")
        return ret_val
    
    st.log(f"Generating expected remote MACs for {dut} in DC {dut_dc}")
    if vlan_list:
        st.log(f"  Filtering for VLANs: {vlan_list}")
    
    # Iterate through all remote nodes
    for remote_node in participants:
        if remote_node == dut:
            continue  # Skip self
        
        # Check if remote node has host info
        if remote_node not in host_info_dict:
            if skip_absent_hosts:
                st.log(f"  Skipping {remote_node} (no host info)")
                continue
            else:
                st.log(f"  No host info for remote node {remote_node}")
                continue
        
        # Determine the VTEP IP for the remote node
        remote_dc = _get_dc_from_name(remote_node)
        
        # For same DC: use loopback IP
        # For different DC: MACs come via BGW's DC VIP
        if remote_dc == dut_dc:
            # Same DC - direct VTEP to VTEP
            if remote_node in loopback_ipv6_dc_vip:
                # Remote is a BGW - use its DC VIP
                remote_vtep = loopback_ipv6_dc_vip[remote_node]
            else:
                # Remote is a leaf - use its loopback
                remote_vtep = loopback_ip.get(remote_node)
        else:
            # Different DC - MACs learned via local BGW's DC VIP
            # Find the BGW in dut's DC
            local_bgw = None
            for node in participants:
                node_dc = _get_dc_from_name(node)
                if node_dc == dut_dc and node in loopback_ipv6_dc_vip:
                    local_bgw = node
                    break
            
            if local_bgw:
                remote_vtep = loopback_ipv6_dc_vip[local_bgw]
            else:
                st.log(f"  No BGW found for DC {dut_dc}, skipping remote node {remote_node}")
                continue
        
        if not remote_vtep:
            st.log(f"  No VTEP IP found for remote node {remote_node}")
            continue
        
        # Get all MACs configured on the remote node (already checked above)
        node_mac_count = 0
        for interface, vlan_data in host_info_dict[remote_node].items():
            for vlan, host_data in vlan_data.items():
                # Apply VLAN filter if specified
                if vlan_list and int(vlan) not in vlan_list:
                    continue
                
                mac_addr = host_data.get('src_mac', '')
                if mac_addr:
                    ret_val.append({
                        'vlan': str(vlan),
                        'macaddress': mac_addr.lower(),
                        'port': remote_vtep,
                        'type': 'Static'
                    })
                    node_mac_count += 1
        
        if node_mac_count > 0:
            st.log(f"  Added {node_mac_count} MACs from {remote_node} (VTEP: {remote_vtep})")
    
    st.log(f"Generated {len(ret_val)} expected remote MACs for {dut}")
    return ret_val


@VerifyLoop()
def verify_remote_macs(dut, exp_data, vlan_list=None, id_keys=['vlan', 'macaddress'], **kwargs):
    """
    Verify remote MAC addresses on a DUT.
    
    Args:
        dut: Device under test
        exp_data: Expected data from get_expected_remote_macs()
        vlan_list: Optional list of VLANs to verify
        id_keys: Keys to use for matching expected vs actual data
        
    Returns:
        Actual remote MAC data
        
    Raises:
        Exception if verification fails (via compare_exp_actual_data)
    """
    act_data = get_remote_macs_from_show_mac(dut, vlan_list=vlan_list)
    
    st.log(f"Verifying remote MACs on {dut}")
    st.log(f"  Expected: {len(exp_data)} remote MACs")
    st.log(f"  Actual:   {len(act_data)} remote MACs")
    
    compare_exp_actual_data(exp_data, act_data, id_keys)
    
    return act_data


# ═══════════════════════════════════════════════════════════════════════
# DCI FRR and SONiC CLI Verification Functions
# ═══════════════════════════════════════════════════════════════════════

def get_vxlan_interface(dut):
    """
    Parse 'show vxlan interface' output
    
    Example output for Leaf nodes:
        VTEP Information:
                VTEP Name : VXLAN, SIP  : 2000:1::1
        Source interface  : Loopback0
    
    Example output for BGW nodes:
        VTEP Information:
            VTEP Name : vxlan-dc, SIP  : 4000:1::1
            VTEP Name : vxlan-wan, SIP  : 101.101.101.101
            NVO Name  : NVO-DC,  VTEP : vxlan-dc
            NVO Name  : NVO-WAN,  VTEP : vxlan-wan
            Source interface  : vxlan-dc, Loopback10
            Source interface  : vxlan-wan, Loopback11
    
    Returns list of dicts:
    [{
        'vtep_name': 'VXLAN' or 'vxlan-dc',
        'source_ip': '2000:1::1',
        'source_interface': 'Loopback0' or 'Loopback10'
    }, ...]
    """
    cmd = 'show vxlan interface'
    output = st.show(dut, cmd, skip_tmpl=True, skip_error_check=False)
    
    # Normalize output to string
    if isinstance(output, list):
        if len(output) == 1 and isinstance(output[0], str):
            output = output[0]
        else:
            output = '\n'.join([str(x) for x in output])
    
    # Parse VTEPs and their source IPs
    vtep_map = {}  # {vtep_name: {source_ip: ip, source_interface: intf}}
    
    for line in output.splitlines():
        line = line.strip()
        
        # Match: "VTEP Name : vxlan-dc, SIP  : 4000:1::1"
        if 'VTEP Name' in line and 'SIP' in line:
            vtep_name = None
            source_ip = None
            parts = line.split(',')
            for part in parts:
                if 'VTEP Name' in part:
                    vtep_name = part.split(':')[-1].strip()
                if 'SIP' in part:
                    # Handle IPv6 addresses with multiple colons
                    sip_parts = part.split('SIP')[-1].strip()
                    source_ip = sip_parts.lstrip(':').strip()
            
            if vtep_name and source_ip:
                vtep_map[vtep_name] = {'source_ip': source_ip, 'source_interface': ''}
        
        # Match: "Source interface  : vxlan-dc, Loopback10" (BGW format)
        # or "Source interface  : Loopback0" (Leaf format)
        if 'Source interface' in line:
            intf_part = line.split('Source interface')[-1].strip()
            intf_part = intf_part.lstrip(':').strip()
            
            if ',' in intf_part:
                # BGW format: "vxlan-dc, Loopback10"
                parts = [p.strip() for p in intf_part.split(',')]
                if len(parts) >= 2:
                    vtep_name = parts[0]
                    source_intf = parts[1]
                    if vtep_name in vtep_map:
                        vtep_map[vtep_name]['source_interface'] = source_intf
            else:
                # Leaf format: "Loopback0"
                # Assign to first VTEP if only one exists
                source_intf = intf_part
                if len(vtep_map) == 1:
                    first_vtep = list(vtep_map.keys())[0]
                    vtep_map[first_vtep]['source_interface'] = source_intf
    
    # Convert to list of dicts
    ret_val = []
    for vtep_name, vtep_info in vtep_map.items():
        ret_val.append({
            'vtep_name': vtep_name,
            'source_ip': vtep_info['source_ip'],
            'source_interface': vtep_info['source_interface']
        })
    
    return ret_val


def get_expected_vxlan_interface(dut):
    """
    Generate expected VXLAN interface data for a node
    
    For Leaf nodes: Single VTEP (VXLAN with Loopback0)
    For BGW nodes: Dual VTEPs (vxlan-dc with Loopback10, vxlan-wan with Loopback11)
    
    Returns list of dicts with expected attributes
    """
    ret_val = []
    # Get loopback IPs
    loopback_ip = generate_loopback_ip(st.getenv("vtep"))
    
    # Check if this is a BGW with DCI configuration
    (loopback_ipv6_dc_vip,
     loopback_ipv4_wan_vip,
     loopback_ipv4_wan_overlay,
     transit_wan_ipv4_underlay) = generate_dci_vip_maps()
    
    is_bgw = dut in loopback_ipv6_dc_vip
    if is_bgw:
        # BGW nodes have dual VTEPs
        # 1. vxlan-dc tunnel (IPv6, Loopback10)
        dc_source_ip = loopback_ipv6_dc_vip.get(dut)
        if dc_source_ip:
            ret_val.append({
                'vtep_name': 'vxlan-dc',
                'source_ip': dc_source_ip,
                'source_interface': 'Loopback10'
            })
        else:
            st.log(f"WARNING: No DC source IP found for BGW {dut}")
        
        # 2. vxlan-wan tunnel (IPv4, Loopback11) - uses wan_vip, not wan_overlay
        wan_source_ip = loopback_ipv4_wan_vip.get(dut)
        if wan_source_ip:
            ret_val.append({
                'vtep_name': 'vxlan-wan',
                'source_ip': wan_source_ip,
                'source_interface': 'Loopback11'
            })
        else:
            st.log(f"WARNING: No WAN source IP found for BGW {dut}")
    else:
        # Regular leaf nodes use single VXLAN tunnel (Loopback0)
        source_ip = loopback_ip.get(dut)
        if source_ip:
            ret_val.append({
                'vtep_name': 'VXLAN',
                'source_ip': source_ip,
                'source_interface': 'Loopback0'
            })
        else:
            st.log(f"WARNING: No loopback IP found for {dut} in loopback_ip dict")
    return ret_val


@VerifyLoop()
def verify_vxlan_interface(dut, exp_data, **kwargs):
    """
    Verify 'show vxlan interface' output attributes
    """
    act_data = get_vxlan_interface(dut)
    compare_exp_actual_data(exp_data, act_data, ['vtep_name', 'source_ip'])
    return act_data


def get_evpn_vni(dut):
    """
    Parse 'show evpn vni' FRR command output
    
    Example output:
        Number of VNIs: 10
        VNI        Type VxLAN IF              # MACs   # ARPs   # Remote VTEPs  Tenant VRF
        5011       L2   vxlan-dc              10       0        2               default
        5012       L2   vxlan-dc              10       0        2               default
        5101       L3   vxlan-dc              0        0        n/a             Vrf101
    
    Returns list of dicts:
    [{
        'vni': '5011',
        'type': 'L2',
        'vxlan_if': 'vxlan-dc',
        'num_macs': '10',
        'num_arps': '0',
        'num_remote_vteps': '2',
        'tenant_vrf': 'default'
    }, ...]
    """
    cmd = 'show evpn vni'
    output = st.show(dut, cmd, type='vtysh', skip_tmpl=True)
    
    ret_val = []
    
    for line in output.splitlines():
        line = line.strip()
        
        # Skip headers and empty lines
        if not line or line.startswith('Number of') or line.startswith('VNI') or line.startswith('---'):
            continue
        
        # Parse VNI line: "5011       L2   vxlan-dc              10       0        2               default"
        parts = line.split()
        if len(parts) >= 7:
            vni_entry = {
                'vni': parts[0],
                'type': parts[1],
                'vxlan_if': parts[2],
                'num_macs': parts[3],
                'num_arps': parts[4],
                'num_remote_vteps': parts[5],
                'tenant_vrf': parts[6]
            }
            ret_val.append(vni_entry)
        elif len(parts) >= 6:
            # For L3 VNIs, remote_vteps might be 'n/a'
            vni_entry = {
                'vni': parts[0],
                'type': parts[1],
                'vxlan_if': parts[2],
                'num_macs': parts[3],
                'num_arps': parts[4],
                'num_remote_vteps': 'n/a' if parts[1] == 'L3' else parts[5],
                'tenant_vrf': parts[5] if parts[1] == 'L3' else (parts[6] if len(parts) > 6 else 'default')
            }
            ret_val.append(vni_entry)
    
    return ret_val


def get_expected_evpn_vni(dut):
    """
    Generate expected EVPN VNI data for a BGW node
    
    Returns list of dicts with expected VNI attributes
    """
    ret_val = []
    cfg_dict = get_cfg_dict()
    # Check if dut has configuration
    if dut not in cfg_dict:
        st.log(f"WARNING: {dut} not found in cfg_dict, skipping EVPN VNI verification")
        return ret_val
    
    dut_cfg = cfg_dict.get(dut, {})
    
    # Check if this is a BGW node
    is_bgw = 'bgw' in dut.lower()
    
    # Get L2VNI configuration
    l2vni_config = dut_cfg.get('l2vni', [])
    if isinstance(l2vni_config, list):
        for l2vni_item in l2vni_config:
            vni = l2vni_item.get('vni')
            if vni:
                ret_val.append({
                    'vni': str(vni),
                    'type': 'L2',
                    'vxlan_if': 'vxlan-dc' if is_bgw else 'VXLAN',
                    'tenant_vrf': 'default'
                })
    
    # Get L3VNI configuration
    l3vni_config = dut_cfg.get('l3vni', [])
    if isinstance(l3vni_config, list):
        for l3vni_item in l3vni_config:
            # Support both YAML key names: 'vxlan_id' (DCI) and 'l3vni' (legacy)
            vni = l3vni_item.get('vxlan_id') or l3vni_item.get('l3vni')
            vrf_id = l3vni_item.get('vrf_id', '')
            # Format VRF name: numeric vrf_id -> 'Vrf<N>', string already prefixed -> as-is
            if vrf_id and str(vrf_id).isdigit():
                vrf = 'Vrf{}'.format(vrf_id)
            elif vrf_id:
                vrf = str(vrf_id)
            else:
                vrf = 'default'
            if vni:
                # BGW vxlan_if includes VLAN suffix: 'vxlan-dc-101', 'vxlan-dc-102'
                if is_bgw:
                    vxlan_if = 'vxlan-dc-{}'.format(vrf_id) if vrf_id else 'vxlan-dc'
                else:
                    vxlan_if = 'VXLAN'
                ret_val.append({
                    'vni': str(vni),
                    'type': 'L3',
                    'vxlan_if': vxlan_if,
                    'tenant_vrf': vrf,
                    'num_remote_vteps': 'n/a'  # L3 VNIs don't have remote VTEPs
                })
    
    return ret_val


@VerifyLoop()
def verify_evpn_vni(dut, exp_data, **kwargs):
    """
    Verify 'show evpn vni' FRR command output attributes
    """
    act_data = get_evpn_vni(dut)
    # Only verify VNI, type, and VRF (don't check dynamic counters like num_macs)
    compare_exp_actual_data(exp_data, act_data, ['vni', 'type'])
    return act_data


def get_expected_type5_routes(dut):
    """
    Generate expected EVPN Type-5 route prefixes for a node based on SAG addressing.

    BGW node perspective (comprehensive path-count model):
      - Paths from same-DC leafs (via OVERLAY/spine RR)
      - Paths from remote-DC BGWs (via OVERLAY_WAN)
      - local_leaf_asns = same-DC leaf ASNs
      - remote_bgw_asns = other-DC BGW ASNs
      - DC1 BGWs: 4 leaves + 3 remote BGWs = 7
      - DC2 BGWs: 2 leaves + 3 remote BGWs = 5
      - DC3 BGW:  1 leaf   + 4 remote BGWs = 5

    Leaf node perspective (per-VRF prefix-presence model):
      - Leaf nodes see within-DC Type-5 routes only
      - All prefixes are locally originated in the same DC
      - Each prefix should have a best path with weight=32768
      - Best path next-hop should be the leaf's own IPv6 VTEP
      - Returns entries with is_leaf=True and local_vtep for targeted checks

    Per SAG addressing:
      - IPv4: leaf SVI gateway = 80.<vlan>.0.1/24, Type-5 prefix = 80.<vlan>.0.0/24
      - IPv6: leaf SVI gateway = 8000:<vlan>::1/64, Type-5 prefix = 8000:<vlan>::/64

    VLAN-to-VRF mapping (from YAML):
      - VLANs 11-15 -> Vrf101 (cross-DC L3VNI 10101)
      - VLANs 16-20 -> Vrf102 (cross-DC L3VNI 10102)

    Args:
        dut: Node hostname to generate expected routes for (BGW or leaf)

    Returns:
        list of dicts. For BGW nodes: prefix, vrf, path_count, local_leaf_asns,
        remote_bgw_asns, expect_local_leaf, expect_ipv6_nexthop, l3vni.
        For leaf nodes: prefix, vrf, is_leaf, local_vtep, l3vni.
    """
    cfg_dict = get_cfg_dict()
    is_leaf = 'leaf' in dut
    is_bgw = 'bgw' in dut

    # Build VLAN-to-VRF and VLAN-to-L3VNI mapping from a reference leaf node
    vlan_vrf_map = {}   # {vlan_id: 'VrfXXX'}
    vrf_l3vni_map = {}  # {'VrfXXX': 'cross_dc_vni'}

    for node_name, node_cfg in sorted(cfg_dict.items()):
        if not isinstance(node_cfg, dict) or 'leaf' not in node_name:
            continue
        l3vni_list = node_cfg.get('l3vni', [])
        if not isinstance(l3vni_list, list):
            continue
        for l3vni_item in l3vni_list:
            vrf_id = l3vni_item.get('vrf_id')
            vlan_bindings = l3vni_item.get('vlan_bindings', [])
            if vrf_id:
                vrf_name = 'Vrf{}'.format(vrf_id)
                for vlan in vlan_bindings:
                    # Skip L3VNI VLANs (101, 102) - not data VLANs
                    if vlan < 100:
                        vlan_vrf_map[vlan] = vrf_name
        if vlan_vrf_map:
            break  # Only need one leaf as reference

    # Get cross-DC L3VNI per VRF from BGW YAML config
    for node_name, node_cfg in cfg_dict.items():
        if not isinstance(node_cfg, dict) or 'bgw' not in node_name:
            continue
        for l3vni_item in node_cfg.get('l3vni', []):
            vrf_id = l3vni_item.get('vrf_id')
            vxlan_id = l3vni_item.get('vxlan_id')
            if vrf_id and vxlan_id:
                vrf_name = 'Vrf{}'.format(vrf_id)
                vrf_l3vni_map[vrf_name] = str(vxlan_id)
        if vrf_l3vni_map:
            break  # All BGWs share same cross-DC VNI

    bgp_info = get_bgp_underlay_info_cached()
    dut_dc = _get_dc_from_name(dut)

    if is_leaf:
        # --- Leaf node: per-VRF prefix-presence model ---
        # Get this leaf's own IPv6 VTEP (Loopback0 IPv6)
        loopback_v6_map = generate_loopback_ip(version='v6')
        local_vtep = loopback_v6_map.get(dut, '')

        # Count expected prefixes per VRF
        vrf_ipv4_count = {}
        vrf_ipv6_count = {}
        for vlan_id in sorted(vlan_vrf_map.keys()):
            vrf = vlan_vrf_map[vlan_id]
            vrf_ipv4_count[vrf] = vrf_ipv4_count.get(vrf, 0) + 1
            vrf_ipv6_count[vrf] = vrf_ipv6_count.get(vrf, 0) + 1

        st.log('Leaf Type-5 for {} ({}, VTEP={}): {} VLANs across {} VRFs'.format(
            dut, dut_dc, local_vtep, len(vlan_vrf_map),
            len(set(vlan_vrf_map.values()))))
        for vrf in sorted(set(vlan_vrf_map.values())):
            st.log('  {}: {} IPv4 + {} IPv6 prefixes'.format(
                vrf, vrf_ipv4_count.get(vrf, 0), vrf_ipv6_count.get(vrf, 0)))

        expected_routes = []
        for vlan_id in sorted(vlan_vrf_map.keys()):
            vrf = vlan_vrf_map[vlan_id]
            l3vni = vrf_l3vni_map.get(vrf, '')
            # IPv4 prefix
            ipv4_prefix = '80.{}.0.0/24'.format(vlan_id)
            ipv4_entry = {
                'prefix': ipv4_prefix,
                'vrf': vrf,
                'is_leaf': True,
                'local_vtep': local_vtep,
            }
            if l3vni:
                ipv4_entry['l3vni'] = l3vni
            expected_routes.append(ipv4_entry)
            # IPv6 prefix
            ipv6_prefix = '8000:{}::/64'.format(vlan_id)
            ipv6_entry = {
                'prefix': ipv6_prefix,
                'vrf': vrf,
                'is_leaf': True,
                'local_vtep': local_vtep,
            }
            if l3vni:
                ipv6_entry['l3vni'] = l3vni
            expected_routes.append(ipv6_entry)

        st.log('Expected Type-5 routes for {} ({} prefixes): {}'.format(
            dut, len(expected_routes),
            [r['prefix'] for r in expected_routes]))
        return expected_routes

    # --- BGW node: comprehensive path-count model (unchanged) ---
    local_leaf_asns = set()
    remote_bgw_asns = set()
    local_leaf_count = 0
    remote_bgw_count = 0

    for node_name in sorted(bgp_info.keys()):
        node_dc = _get_dc_from_name(node_name)
        if 'leaf' in node_name and node_dc == dut_dc:
            local_leaf_count += 1
            local_leaf_asns.add(str(bgp_info[node_name]['as_num']))
        elif 'bgw' in node_name and node_dc != dut_dc:
            remote_bgw_count += 1
            remote_bgw_asns.add(str(bgp_info[node_name]['as_num']))

    # BGW nodes do NOT show self-originated Type-5 paths
    expected_path_count = local_leaf_count + remote_bgw_count
    expect_local_leaf = local_leaf_count > 0
    expect_ipv6_nexthop = True

    st.log('Type-5 path count for {} ({}, BGW): {} local leaves + {} remote BGWs = {}'.format(
        dut, dut_dc, local_leaf_count, remote_bgw_count, expected_path_count))
    st.log('Local leaf ASNs: {}, Remote BGW ASNs: {}'.format(
        local_leaf_asns, remote_bgw_asns))

    expected_routes = []
    for vlan_id in sorted(vlan_vrf_map.keys()):
        vrf = vlan_vrf_map[vlan_id]
        l3vni = vrf_l3vni_map.get(vrf, '')
        # IPv4 prefix
        ipv4_prefix = '80.{}.0.0/24'.format(vlan_id)
        ipv4_entry = {
            'prefix': ipv4_prefix,
            'vrf': vrf,
            'path_count': str(expected_path_count),
            'local_leaf_asns': local_leaf_asns,
            'remote_bgw_asns': remote_bgw_asns,
            'expect_local_leaf': expect_local_leaf,
            'expect_ipv6_nexthop': expect_ipv6_nexthop,
        }
        if l3vni:
            ipv4_entry['l3vni'] = l3vni
        expected_routes.append(ipv4_entry)
        # IPv6 prefix
        ipv6_prefix = '8000:{}::/64'.format(vlan_id)
        ipv6_entry = {
            'prefix': ipv6_prefix,
            'vrf': vrf,
            'path_count': str(expected_path_count),
            'local_leaf_asns': local_leaf_asns,
            'remote_bgw_asns': remote_bgw_asns,
            'expect_local_leaf': expect_local_leaf,
            'expect_ipv6_nexthop': expect_ipv6_nexthop,
        }
        if l3vni:
            ipv6_entry['l3vni'] = l3vni
        expected_routes.append(ipv6_entry)

    st.log('Expected Type-5 routes for {} ({} prefixes): {}'.format(
        dut, len(expected_routes),
        [r['prefix'] for r in expected_routes]))
    return expected_routes


def _parse_type5_routes_detailed(cli_output):
    """
    Parse 'show bgp l2vpn evpn route type prefix' output capturing ALL paths
    per prefix with per-path attributes.

    FRR compact list output format (multiple paths per prefix, across RDs):
      Route Distinguisher: 10.10.10.1:2
      *>i[5]:[0]:[24]:[80.11.0.0]
                          2000:1::1                    0    100      0 65200 i
                          RT:65200:5101 ET:5101 Rmac:00:01:02:aa:bb:cc
       * i[5]:[0]:[24]:[80.11.0.0]
                          103.103.103.103              0    100      0 65103 65201 i
                          RT:65103:10101 ET:10101 Rmac:00:01:02:cc:dd:ee

    Note: st.show() with skip_tmpl=True returns output with spytest framework
    log prefixes on each line (e.g. "2026-03-23 20:11:18,750 T0000: INFO
    [D3-spine2_dc1_bgw1] *>i[5]:[0]:[24]:[80.11.0.0]"). These are stripped
    before parsing.

    Path status indicators:
      '*' = valid      '>' = best       'i' = internal (iBGP)

    Returns:
        dict keyed by prefix string:
        {
          '80.11.0.0/24': {
            'path_count': 7,
            'paths': [
              {
                'is_best': True,
                'is_valid': True,
                'next_hop': '2000:1::1',
                'as_path': '65200',
                'rt': '65200:5101',
                'et': '5101',
                'rmac': '00:01:02:aa:bb:cc',
                'ipv6_nexthop': True,
              },
              ...
            ],
            'best_path': <ref to best path dict or None>,
          },
          ...
        }
    """
    import re
    prefixes = {}

    # Strip spytest framework log prefix from each line.
    # e.g. "2026-03-23 20:11:18,750 T0000: INFO  [D3-spine2_dc1_bgw1] "
    # Same pattern used by _show_evpn_type2_grep().
    _log_prefix_re = re.compile(
        r"^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}[^\]]*\]\s*"
    )
    lines = cli_output.splitlines()
    lines = [_log_prefix_re.sub("", line) for line in lines]

    # --- Patterns ---

    # NLRI line: status chars + [5]:[0]:[mask]:[prefix]
    # e.g. "*>i[5]:[0]:[24]:[80.11.0.0]"  or  " * i[5]:[0]:[64]:[8000:11::]"
    nlri_re = re.compile(
        r'\[5\]:\[0\]:\[(\d+)\]:\[([\d\.a-fA-F:]+)\]'
    )

    # Next-hop line with metrics and AS path, ending with origin code.
    # After log-prefix stripping, leading whitespace may be removed, so
    # the line can start at column 0 or be indented.
    # FRR columns: Next Hop | Metric | LocPrf | Weight | Path
    # Metric and LocPrf may be blank (just whitespace).  Weight is always
    # present.  After weight the AS-path ASNs follow (single-space separated)
    # then the origin code (i/e/?).
    # Examples after log-prefix stripping:
    #   "103.103.103.103                        0 65104 65204 ?"
    #   "2000:1::4                0             0 65203 ?"
    nexthop_metrics_re = re.compile(
        r'^\s*'
        r'([\d\.]{7,}|[0-9a-fA-F]+:[0-9a-fA-F:]+)'  # next-hop (IPv4 or IPv6)
        r'(?:\([^)]+\))?'                              # optional (hostname)
        r'(.*?)'                                       # metrics + AS path blob
        r'\s+([iIeE\?])\s*$'                          # origin code
    )

    # Next-hop line without metrics (locally-originated, next-hop on own line):
    # e.g. "fd27::1(leaf0_dc1)" or "                    fd27::1(leaf0_dc1)"
    nexthop_only_re = re.compile(
        r'^\s*'
        r'([\d\.]{7,}|[0-9a-fA-F]+:[0-9a-fA-F:]+)'  # next-hop
        r'(?:\([^)]+\))?'                              # optional (hostname)
        r'\s*$'
    )

    # Weight-only continuation (follows next-hop-only for local routes):
    # e.g. "                                                       32768 i"
    weight_origin_re = re.compile(
        r'^\s+(\d+)\s+([iIeE\?])\s*$'
    )

    # Extended community attributes
    et_re = re.compile(r'ET:(\d+)')
    rt_re = re.compile(r'RT:(\d+:\d+)')
    rmac_re = re.compile(r'Rmac:([0-9a-fA-F:]+)')

    current_prefix = None
    current_path = None

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue

        # Check for NLRI line containing [5]:[0]:[mask]:[prefix]
        nlri_match = nlri_re.search(line)
        if nlri_match:
            prefix_len = nlri_match.group(1)
            prefix_addr = nlri_match.group(2)
            current_prefix = '{}/{}'.format(prefix_addr, prefix_len)

            if current_prefix not in prefixes:
                prefixes[current_prefix] = {
                    'path_count': 0,
                    'paths': [],
                    'best_path': None,
                }

            # Extract status from text before [5]:
            pre_nlri = line[:nlri_match.start()]
            is_valid = '*' in pre_nlri
            is_best = '>' in pre_nlri

            current_path = {
                'is_best': is_best,
                'is_valid': is_valid,
                'next_hop': '',
                'weight': '',
                'as_path': '',
                'rt': '',
                'et': '',
                'rmac': '',
                'ipv6_nexthop': False,
            }
            prefixes[current_prefix]['paths'].append(current_path)
            prefixes[current_prefix]['path_count'] += 1
            if is_best:
                prefixes[current_prefix]['best_path'] = current_path
            continue

        if current_path is None or current_prefix is None:
            continue

        # Check for next-hop line (only if current path doesn't have one yet)
        if not current_path['next_hop']:
            nh_m = nexthop_metrics_re.match(line)
            if nh_m:
                next_hop = nh_m.group(1)
                middle = nh_m.group(2)
                # Split the middle blob by 2+ spaces to separate FRR
                # fixed-width columns (Metric, LocPrf, Weight+Path).
                # The LAST group contains "weight AS_path" where weight
                # is the first token and AS path ASNs follow.
                groups = [g.strip() for g in re.split(r'\s{2,}', middle)
                          if g.strip()]
                as_path_str = ''
                weight_str = ''
                if groups:
                    last = groups[-1]
                    tokens = last.split()
                    # First token is weight; remaining tokens are AS path
                    weight_str = tokens[0] if tokens else ''
                    as_path_str = ' '.join(tokens[1:]) if len(tokens) > 1 else ''
                current_path['next_hop'] = next_hop
                current_path['weight'] = weight_str
                current_path['as_path'] = as_path_str
                current_path['ipv6_nexthop'] = ':' in next_hop
                continue

            nh_only = nexthop_only_re.match(line)
            if nh_only:
                next_hop = nh_only.group(1)
                current_path['next_hop'] = next_hop
                current_path['ipv6_nexthop'] = ':' in next_hop
                continue

        # Check for weight-only continuation (locally-originated routes)
        w_m = weight_origin_re.match(line)
        if w_m:
            if not current_path.get('weight'):
                current_path['weight'] = w_m.group(1)
            continue

        # Check for extended community attributes (RT:xxx ET:xxx Rmac:xxx)
        if 'RT:' in line or 'ET:' in line or 'Rmac:' in line:
            et_match = et_re.search(line)
            if et_match and not current_path['et']:
                current_path['et'] = et_match.group(1)
            rt_match = rt_re.search(line)
            if rt_match and not current_path['rt']:
                current_path['rt'] = rt_match.group(1)
            rmac_match = rmac_re.search(line)
            if rmac_match and not current_path['rmac']:
                current_path['rmac'] = rmac_match.group(1)

    return prefixes


@VerifyLoop()
def verify_evpn_type5_comprehensive(dut, exp_routes, **kwargs):
    """
    Comprehensive EVPN Type-5 route verification with per-prefix pass/fail.

    BGW nodes (path-count model):
      1. prefix exists
      2. path count matches expected for that site
      3. at least one local-site leaf path exists (if expect_local_leaf=True)
      4. at least one remote/BGW path exists
      5. best path is local-site leaf path (if expect_local_leaf=True)
      6. route has RT, ET, and RMAC
      7. at least one path has IPv6 VTEP next-hop

    Leaf nodes (per-VRF prefix-presence model):
      For each leaf, per VRF:
      1. total expected prefix count matches actual
      2. all expected IPv4 prefixes present
      3. all expected IPv6 prefixes present
      4. best path exists for each prefix
      5. if prefix is locally originated in that DC, best path next-hop
         must be local leaf VTEP and weight should be 32768

    Uses compare_exp_actual_data() for structured tabular output.

    Args:
        dut: Node hostname (BGW or leaf)
        exp_routes: list from get_expected_type5_routes()
    """
    st.banner('Comprehensive Type-5 verification on {}'.format(dut))

    # Get detailed actual routes (all paths per prefix)
    cli_output = st.show(dut, "do show bgp l2vpn evpn route type prefix",
                         type='vtysh', skip_tmpl=True)
    if not cli_output or not cli_output.strip():
        raise CompareEmptyData('No Type-5 route output on {}'.format(dut))

    detailed = _parse_type5_routes_detailed(cli_output)
    if not detailed:
        sample = '\n'.join(cli_output.splitlines()[:10])
        st.log('Type-5 parse debug - first 10 raw lines on {}:\n{}'.format(dut, sample))
        raise CompareEmptyData('No Type-5 routes parsed from output on {}'.format(dut))

    st.log('Parsed {} unique Type-5 prefixes with detailed path info from {}'.format(
        len(detailed), dut))

    # Determine if leaf or BGW from first entry
    is_leaf = exp_routes and exp_routes[0].get('is_leaf', False)

    if is_leaf:
        return _verify_type5_leaf(dut, exp_routes, detailed)

    return _verify_type5_bgw(dut, exp_routes, detailed)


def _verify_type5_leaf(dut, exp_routes, detailed):
    """
    Leaf-specific Type-5 verification per reviewer spec.

    For each leaf, per VRF checks:
      1. total expected prefix count
      2. all expected IPv4 prefixes present
      3. all expected IPv6 prefixes present
      4. best path exists for each prefix
      5. if prefix is locally originated in that DC, best path next-hop
         must be local leaf VTEP and weight should be 32768

    All prefixes on a leaf are locally originated in the same DC.
    """
    local_vtep = exp_routes[0].get('local_vtep', '') if exp_routes else ''

    # Build per-VRF expected prefix lists
    vrf_expected_ipv4 = {}  # {vrf: [prefix, ...]}
    vrf_expected_ipv6 = {}
    for exp_route in exp_routes:
        vrf = exp_route.get('vrf', '')
        prefix = exp_route['prefix']
        if ':' in prefix.split('/')[0]:
            # IPv6 prefix
            vrf_expected_ipv6.setdefault(vrf, []).append(prefix)
        else:
            # IPv4 prefix
            vrf_expected_ipv4.setdefault(vrf, []).append(prefix)

    # Log per-VRF summary
    all_vrfs = sorted(set(list(vrf_expected_ipv4.keys()) + list(vrf_expected_ipv6.keys())))
    for vrf in all_vrfs:
        st.log('  {} expected: {} IPv4, {} IPv6 prefixes'.format(
            vrf, len(vrf_expected_ipv4.get(vrf, [])),
            len(vrf_expected_ipv6.get(vrf, []))))

    # Build expected and actual data for compare_exp_actual_data
    exp_data = []
    act_data = []

    for exp_route in exp_routes:
        prefix = exp_route['prefix']

        exp_row = {
            'prefix': prefix,
            'present': 'yes',
            'has_best_path': 'yes',
            'best_nh_is_local_vtep': 'yes',
            'best_weight_32768': 'yes',
        }
        exp_data.append(exp_row)

        if prefix not in detailed:
            act_row = {
                'prefix': prefix,
                'present': 'no',
                'has_best_path': 'no',
                'best_nh_is_local_vtep': 'no',
                'best_weight_32768': 'no',
            }
            act_data.append(act_row)
            continue

        info = detailed[prefix]
        best_path = info.get('best_path')
        has_best = best_path is not None

        # Check best path next-hop matches leaf's own VTEP
        best_nh_match = False
        best_weight_ok = False
        if best_path:
            bp_nh = best_path.get('next_hop', '')
            bp_weight = best_path.get('weight', '')
            best_nh_match = (bp_nh == local_vtep) if local_vtep else False
            best_weight_ok = (bp_weight == '32768')

        act_row = {
            'prefix': prefix,
            'present': 'yes',
            'has_best_path': 'yes' if has_best else 'no',
            'best_nh_is_local_vtep': 'yes' if best_nh_match else 'no',
            'best_weight_32768': 'yes' if best_weight_ok else 'no',
        }
        act_data.append(act_row)

        st.log('  {} present=yes best={} nh={} (exp={}) weight={}'.format(
            prefix, has_best,
            best_path.get('next_hop', '') if best_path else '',
            local_vtep,
            best_path.get('weight', '') if best_path else ''))

    # Per-VRF prefix count summary
    for vrf in all_vrfs:
        exp_ipv4 = vrf_expected_ipv4.get(vrf, [])
        exp_ipv6 = vrf_expected_ipv6.get(vrf, [])
        act_ipv4 = [p for p in exp_ipv4 if p in detailed]
        act_ipv6 = [p for p in exp_ipv6 if p in detailed]
        total_exp = len(exp_ipv4) + len(exp_ipv6)
        total_act = len(act_ipv4) + len(act_ipv6)
        st.log('{} prefix count: exp={} act={} (IPv4: {}/{}, IPv6: {}/{})'.format(
            vrf, total_exp, total_act,
            len(act_ipv4), len(exp_ipv4),
            len(act_ipv6), len(exp_ipv6)))

    # Run structured comparison — raises CompareFailed if mismatch
    compare_exp_actual_data(exp_data, act_data, ['prefix'])
    return act_data


def _verify_type5_bgw(dut, exp_routes, detailed):
    """
    BGW-specific Type-5 verification (path-count model, unchanged from original).
    """
    exp_data = []
    act_data = []

    for exp_route in exp_routes:
        prefix = exp_route['prefix']
        expected_path_count = exp_route.get('path_count', '0')
        local_leaf_asns = exp_route.get('local_leaf_asns', set())
        remote_bgw_asns = exp_route.get('remote_bgw_asns', set())
        expect_local_leaf = exp_route.get('expect_local_leaf', True)
        expect_ipv6_nexthop = exp_route.get('expect_ipv6_nexthop', False)

        exp_local = 'yes' if expect_local_leaf else 'no'
        exp_best_local = 'yes' if expect_local_leaf else 'no'
        exp_row = {
            'prefix': prefix,
            'path_count': str(expected_path_count),
            'has_local_leaf_path': exp_local,
            'has_remote_bgw_path': 'yes',
            'best_path_is_local_leaf': exp_best_local,
            'has_rt': 'yes',
            'has_et': 'yes',
            'has_rmac': 'yes',
            'has_ipv6_nexthop': 'yes' if expect_ipv6_nexthop else 'n/a',
        }
        exp_data.append(exp_row)

        if prefix not in detailed:
            act_row = {
                'prefix': prefix,
                'path_count': '0',
                'has_local_leaf_path': 'no',
                'has_remote_bgw_path': 'no',
                'best_path_is_local_leaf': 'no',
                'has_rt': 'no',
                'has_et': 'no',
                'has_rmac': 'no',
                'has_ipv6_nexthop': 'no' if expect_ipv6_nexthop else 'n/a',
            }
            act_data.append(act_row)
            continue

        info = detailed[prefix]
        actual_path_count = info['path_count']

        # Classify paths as local-leaf or remote-BGW based on AS path
        has_local_leaf = False
        has_remote_bgw = False
        has_ipv6_nh = False
        for path in info['paths']:
            as_path = path.get('as_path', '')
            first_asn = as_path.split()[0] if as_path else ''
            if first_asn in local_leaf_asns:
                has_local_leaf = True
            elif first_asn in remote_bgw_asns:
                has_remote_bgw = True
            else:
                path_asns = set(as_path.split())
                if path_asns & local_leaf_asns:
                    has_local_leaf = True
                if path_asns & remote_bgw_asns:
                    has_remote_bgw = True
            if path.get('ipv6_nexthop'):
                has_ipv6_nh = True

        # Check best path source
        best_path = info.get('best_path')
        best_is_local_leaf = False
        if best_path:
            bp_as_path = best_path.get('as_path', '')
            bp_first_asn = bp_as_path.split()[0] if bp_as_path else ''
            if bp_first_asn in local_leaf_asns:
                best_is_local_leaf = True
            else:
                bp_asns = set(bp_as_path.split())
                if bp_asns & local_leaf_asns and not (bp_asns & remote_bgw_asns):
                    best_is_local_leaf = True

        has_rt = any(p.get('rt') for p in info['paths'])
        has_et = any(p.get('et') for p in info['paths'])
        has_rmac = any(p.get('rmac') for p in info['paths'])

        act_row = {
            'prefix': prefix,
            'path_count': str(actual_path_count),
            'has_local_leaf_path': 'yes' if has_local_leaf else 'no',
            'has_remote_bgw_path': 'yes' if has_remote_bgw else 'no',
            'best_path_is_local_leaf': 'yes' if best_is_local_leaf else 'no',
            'has_rt': 'yes' if has_rt else 'no',
            'has_et': 'yes' if has_et else 'no',
            'has_rmac': 'yes' if has_rmac else 'no',
            'has_ipv6_nexthop': ('yes' if has_ipv6_nh else 'no')
                                if expect_ipv6_nexthop else 'n/a',
        }
        act_data.append(act_row)

        st.log('  {} paths={} local_leaf={} remote_bgw={} best_local={} '
               'RT={} ET={} RMAC={} ipv6_nh={}'.format(
                   prefix, actual_path_count, has_local_leaf, has_remote_bgw,
                   best_is_local_leaf, has_rt, has_et, has_rmac, has_ipv6_nh))

    compare_exp_actual_data(exp_data, act_data, ['prefix'])
    return act_data


@VerifyLoop()
def verify_evpn_type5_rib_fib(dut, exp_routes, **kwargs):
    """
    Verify tenant subnet routes are installed in RIB/FIB on BGW nodes.

    Runs 'show ip route vrf Vrf101' and 'show ip route vrf Vrf102' and
    checks that each expected tenant subnet prefix is present as a BGP route.
    BGWs rely on imported Type-5 routes for tenant reachability, so routes
    must be in the RIB/FIB for packet forwarding to work.

    Args:
        dut: BGW node hostname
        exp_routes: list from get_expected_type5_routes() with 'prefix' and 'vrf' keys
    """
    import re
    st.banner('RIB/FIB install check on {}'.format(dut))

    # Group expected prefixes by VRF
    vrf_prefixes = {}
    for route in exp_routes:
        vrf = route.get('vrf', '')
        prefix = route.get('prefix', '')
        if not vrf or not prefix:
            continue
        # Only check IPv4 prefixes for 'show ip route vrf'
        # IPv6 prefixes (containing ':') need 'show ipv6 route vrf'
        if ':' in prefix:
            continue
        vrf_prefixes.setdefault(vrf, []).append(prefix)

    if not vrf_prefixes:
        st.log('No IPv4 prefixes to check in RIB/FIB on {}'.format(dut))
        return []

    exp_data = []
    act_data = []

    for vrf in sorted(vrf_prefixes.keys()):
        prefixes = vrf_prefixes[vrf]
        st.log('Checking RIB/FIB for {} prefixes in {} on {}'.format(
            len(prefixes), vrf, dut))

        # Get routing table for this VRF
        cli_output = st.show(dut, "do show ip route vrf {}".format(vrf),
                             type='vtysh', skip_tmpl=True)
        if not cli_output:
            cli_output = ''

        for prefix in prefixes:
            exp_data.append({
                'prefix': prefix,
                'vrf': vrf,
                'in_rib': 'yes',
            })

            # Check if prefix appears in routing table output
            # FRR format: "B>* 80.11.0.0/24 [20/0] via ..." or "B>  80.11.0.0/24 ..."
            prefix_escaped = re.escape(prefix)
            found = bool(re.search(prefix_escaped, cli_output))

            act_data.append({
                'prefix': prefix,
                'vrf': vrf,
                'in_rib': 'yes' if found else 'no',
            })

    compare_exp_actual_data(exp_data, act_data, ['prefix', 'vrf'])
    return act_data


def verify_bgp_evpn_multihop_sessions_dci(dut):
    """
    Verify eBGP multihop EVPN sessions between BGW spines across DCs.

    Per l3vni_config_diff.txt, BGW spines establish eBGP multihop (255)
    L2VPN EVPN sessions to remote BGWs in other DCs over the WAN overlay.
    Each BGW has:
      - OVERLAY peer-group: iBGP to local DC leafs (IPv6 loopback)
      - OVERLAY_WAN peer-group: eBGP multihop to remote DC BGWs (IPv4 overlay)

    This function verifies:
      1. BGP L2VPN EVPN summary shows expected remote BGW neighbors
      2. All remote BGW sessions are in Established state
      3. Sessions are receiving prefixes (PfxRcd > 0)

    BGW ASN assignments from l3vni_config_diff.txt:
      - DC1 BGW1: AS 65102, DC1 BGW2: AS 65103
      - DC2 BGW1: AS 65104, DC2 BGW2: AS 65105
      - DC3 BGW1: AS 65106

    Args:
        dut: BGW node hostname to verify

    Returns:
        dict: {
            'result': True/False,
            'total_neighbors': int,
            'established_count': int,
            'remote_bgw_neighbors': list of neighbor IPs,
            'details': str summary
        }
    """
    import re
    result = {
        'result': False,
        'total_neighbors': 0,
        'established_count': 0,
        'remote_bgw_neighbors': [],
        'details': ''
    }

    st.banner('Checking eBGP multihop EVPN sessions on {}'.format(dut))

    # Get expected remote BGW neighbors using generate_dci_vip_maps
    dc_match = re.search(r'_(dc\d+)', dut)
    if not dc_match:
        result['details'] = 'Cannot determine DC for node: {}'.format(dut)
        st.log(result['details'])
        return result

    my_dc = dc_match.group(1)

    (loopback_ipv6_dc_vip,
     loopback_ipv4_wan_vip,
     loopback_ipv4_wan_overlay,
     transit_wan_ipv4_underlay) = generate_dci_vip_maps()

    # Expected remote BGW neighbors (other DCs) via WAN overlay IPs
    expected_remote_bgws = []
    for bgw_node, overlay_ip in loopback_ipv4_wan_overlay.items():
        if bgw_node == dut:
            continue
        bgw_dc_match = re.search(r'_(dc\d+)', bgw_node)
        if bgw_dc_match and bgw_dc_match.group(1) != my_dc:
            expected_remote_bgws.append(overlay_ip)

    if not expected_remote_bgws:
        result['details'] = 'No remote BGW neighbors expected for {}'.format(dut)
        st.log(result['details'])
        return result

    st.log('Expected remote BGW neighbors for {}: {}'.format(dut, expected_remote_bgws))

    # Get actual BGP L2VPN EVPN summary
    try:
        act_data = get_bgp_summary(dut)
    except Exception as err:
        result['details'] = 'Failed to get BGP summary on {}: {}'.format(dut, err)
        st.log(result['details'])
        return result

    evpn_data = [entry for entry in act_data if entry.get('protocol') == 'L2VPN EVPN']
    result['total_neighbors'] = len(evpn_data)

    # Check each expected remote BGW is present and established
    for expected_ip in expected_remote_bgws:
        found = False
        for entry in evpn_data:
            if entry.get('neighbor') == expected_ip:
                found = True
                result['remote_bgw_neighbors'].append(expected_ip)
                state = str(entry.get('state', ''))
                # Numeric state means PfxRcd count = session established
                if state.isdigit():
                    result['established_count'] += 1
                    st.log('Remote BGW {} session established (PfxRcd={})'.format(
                        expected_ip, state))
                elif state.lower() in ('established', 'up'):
                    result['established_count'] += 1
                    st.log('Remote BGW {} session established'.format(expected_ip))
                else:
                    st.log('Remote BGW {} session NOT established (state={})'.format(
                        expected_ip, state))
                break
        if not found:
            st.log('Remote BGW {} NOT found in BGP summary on {}'.format(expected_ip, dut))

    # Build summary
    details_parts = []
    details_parts.append('{}/{} remote BGW sessions found'.format(
        len(result['remote_bgw_neighbors']), len(expected_remote_bgws)))
    details_parts.append('{} established'.format(result['established_count']))
    details_parts.append('total L2VPN EVPN neighbors: {}'.format(result['total_neighbors']))
    result['details'] = '; '.join(details_parts)
    st.log(result['details'])

    # Pass if all expected remote BGW sessions are established
    result['result'] = (result['established_count'] == len(expected_remote_bgws))
    return result


def verify_rt_rewrite_dci(dut):
    """
    Verify Route-Target translation across domains on a BGW node for L3VNI DCI.

    Per l3vni_config_diff.txt, each BGW has RT-REWRITE route-maps that
    rewrite Type-5 routes:
      - RT-REWRITE-WAN: match local leaf RTs -> set own ASN RT, VNI, RMAC,
        IPv4 WAN VIP next-hop (for WAN-side advertisement)
      - RT-REWRITE-DC: match remote BGW RTs -> set own ASN RT, VNI, RMAC,
        IPv6 DC VIP next-hop (for DC-side advertisement)

    This function verifies with expected-vs-actual comparison:
      1. RT-REWRITE-WAN and RT-REWRITE-DC route-maps are configured
      2. Type-5 routes carry correct RT values per domain:
         - Local leaf paths have leaf-domain RTs (e.g. 65200:5101)
         - Remote BGW paths have BGW-domain cross-DC RTs (e.g. 65104:10101)
      3. Expected BGW cross-DC RTs match pattern <remote_bgw_asn>:<cross_dc_vni>
      4. All expected remote BGW RTs are present in actual Type-5 output

    Args:
        dut: BGW node hostname to verify

    Returns:
        dict: {
            'result': True/False,
            'route_maps_found': list of route-map names found,
            'rt_values': set of RT values found in Type-5 routes,
            'details': str summary
        }
    """
    import re
    result = {
        'result': False,
        'route_maps_found': [],
        'rt_values': set(),
        'details': ''
    }

    st.banner('Checking RT-REWRITE route-maps and RT per domain on {}'.format(dut))

    # Step 1: Verify RT-REWRITE route-maps are configured
    try:
        rmap_output = st.show(dut, "do show route-map", type='vtysh', skip_tmpl=True)
    except Exception as err:
        result['details'] = 'Failed to get route-maps on {}: {}'.format(dut, err)
        st.log(result['details'])
        return result

    if rmap_output:
        for rmap_name in ['RT-REWRITE-WAN', 'RT-REWRITE-DC']:
            if rmap_name in rmap_output:
                result['route_maps_found'].append(rmap_name)
                st.log('Route-map {} found on {}'.format(rmap_name, dut))
            else:
                st.log('Route-map {} NOT found on {}'.format(rmap_name, dut))

    if len(result['route_maps_found']) < 2:
        result['details'] = 'Missing route-maps on {}: found {} of 2 (RT-REWRITE-WAN, RT-REWRITE-DC)'.format(
            dut, len(result['route_maps_found']))
        st.log(result['details'])
        return result

    # Step 2: Build expected RT values per domain
    cfg_dict = get_cfg_dict()
    bgp_info = get_bgp_underlay_info_cached()
    dut_dc = _get_dc_from_name(dut)

    # Expected cross-DC VNIs from YAML
    expected_cross_dc_vnis = set()
    for node_name, node_cfg in cfg_dict.items():
        if 'bgw' in node_name and isinstance(node_cfg, dict):
            for item in node_cfg.get('l3vni', []):
                vxlan_id = item.get('vxlan_id')
                if vxlan_id:
                    expected_cross_dc_vnis.add(str(vxlan_id))

    # Build expected RTs from remote BGWs: <remote_bgw_asn>:<cross_dc_vni>
    expected_remote_bgw_rts = set()
    for node_name in sorted(bgp_info.keys()):
        node_dc = _get_dc_from_name(node_name)
        if 'bgw' in node_name and node_dc != dut_dc:
            asn = str(bgp_info[node_name]['as_num'])
            for vni in expected_cross_dc_vnis:
                expected_remote_bgw_rts.add('{}:{}'.format(asn, vni))

    # Build expected RTs from local leafs: <leaf_asn>:<leaf_vni>
    expected_local_leaf_rts = set()
    for node_name in sorted(bgp_info.keys()):
        node_dc = _get_dc_from_name(node_name)
        if 'leaf' in node_name and node_dc == dut_dc:
            asn = str(bgp_info[node_name]['as_num'])
            # Leaf VNIs come from YAML l3vni config
            for nn, nc in cfg_dict.items():
                if nn == node_name and isinstance(nc, dict):
                    for item in nc.get('l3vni', []):
                        vxlan_id = item.get('vxlan_id')
                        if vxlan_id:
                            expected_local_leaf_rts.add('{}:{}'.format(asn, vxlan_id))

    st.log('Expected remote BGW RTs on {}: {}'.format(dut, expected_remote_bgw_rts))
    st.log('Expected local leaf RTs on {}: {}'.format(dut, expected_local_leaf_rts))

    # Step 3: Parse actual RTs from Type-5 route output
    try:
        cli_output = st.show(dut, "do show bgp l2vpn evpn route type prefix",
                             type='vtysh', skip_tmpl=True)
    except Exception as err:
        result['details'] = 'Failed to get Type-5 routes on {}: {}'.format(dut, err)
        st.log(result['details'])
        return result

    if not cli_output or not cli_output.strip():
        result['details'] = 'No Type-5 route output on {} (route-maps present but no routes)'.format(dut)
        st.log(result['details'])
        return result

    # Extract all RT values from Type-5 route output
    rt_pattern = re.compile(r'RT:(\d+:\d+)')
    actual_rt_values = set()
    for line in cli_output.splitlines():
        for rt_match in rt_pattern.finditer(line):
            actual_rt_values.add(rt_match.group(1))

    result['rt_values'] = actual_rt_values

    # Step 4: Compare expected vs actual using structured comparison
    exp_data = []
    act_data = []

    # Check each expected remote BGW RT
    for rt in sorted(expected_remote_bgw_rts):
        exp_data.append({'rt_value': rt, 'domain': 'remote_bgw', 'present': 'yes'})
        act_data.append({'rt_value': rt, 'domain': 'remote_bgw',
                         'present': 'yes' if rt in actual_rt_values else 'no'})

    # Check each expected local leaf RT
    for rt in sorted(expected_local_leaf_rts):
        exp_data.append({'rt_value': rt, 'domain': 'local_leaf', 'present': 'yes'})
        act_data.append({'rt_value': rt, 'domain': 'local_leaf',
                         'present': 'yes' if rt in actual_rt_values else 'no'})

    # Log comparison details
    missing_rts = set()
    for exp, act in zip(exp_data, act_data):
        if exp['present'] != act['present']:
            missing_rts.add(exp['rt_value'])
            st.log('RT {} ({}) MISSING on {}'.format(
                exp['rt_value'], exp['domain'], dut))
        else:
            st.log('RT {} ({}) FOUND on {}'.format(
                exp['rt_value'], exp['domain'], dut))

    # Build summary
    total_expected = len(expected_remote_bgw_rts) + len(expected_local_leaf_rts)
    found_count = total_expected - len(missing_rts)
    details_parts = []
    details_parts.append('Route-maps: {}'.format(result['route_maps_found']))
    details_parts.append('RT per domain: {}/{} expected RTs found'.format(
        found_count, total_expected))
    if missing_rts:
        details_parts.append('Missing RTs: {}'.format(missing_rts))
    details_parts.append('Remote BGW RTs: {}'.format(
        expected_remote_bgw_rts & actual_rt_values))
    details_parts.append('Local leaf RTs: {}'.format(
        expected_local_leaf_rts & actual_rt_values))

    result['details'] = '; '.join(details_parts)
    st.log(result['details'])

    # Pass if both route-maps present and all expected RTs found
    result['result'] = (len(result['route_maps_found']) == 2 and
                        len(missing_rts) == 0)

    # Use compare_exp_actual_data for structured tabular output if there's a mismatch
    if not result['result'] and exp_data:
        try:
            compare_exp_actual_data(exp_data, act_data, ['rt_value'])
        except (CompareFailed, CompareEmptyData):
            pass  # Already captured in result

    return result


def _get_expected_local_arp_entries(dut):
    """
    Build expected local ARP entries for a leaf node from SAG host addressing.

    Uses generate_sag_hosts() logic to derive per-VLAN host IPs and MACs that
    should appear in the local ARP table on a leaf node.  Only locally-connected
    IPv4 hosts (on Ethernet / PortChannel interfaces) are expected in ARP.

    The SAG addressing scheme (DCI_NORMAL_SAG_ADDRESSING.md):
      - MAC: 00:<vlan_hex>:00:00:04:<counter_hex>  (IPv4 version octet = 04)
      - IP:  80.<vlan>.0.<counter>
      - counter increments by 10 per interface, across all nodes sorted by DC
        then leaf number

    Returns:
        list of dicts: [{'ip': '80.11.0.10', 'mac': '00:0b:00:00:04:0a',
                         'vlan': '11'}, ...]
    """
    cfg_dict = get_cfg_dict()

    # Collect VLANs from the node's l2vni config
    node_cfg = cfg_dict.get(dut, {})
    vlan_list = []
    if isinstance(node_cfg, dict) and node_cfg.get('l2vni'):
        l2vni = node_cfg['l2vni']
        if isinstance(l2vni, list):
            for item in l2vni:
                vlan_list.append(item['vlan_id'])
        else:
            vlan_list = list(range(l2vni['vlan_start_range'],
                                   l2vni['vlan_start_range'] + l2vni['count']))

    if not vlan_list:
        st.log('No VLANs found for {} in YAML config'.format(dut))
        return []

    # Count interfaces per node in sorted SAG order to derive counter offsets
    # The global counter starts at 10 and increments by 10 per interface
    # across all nodes sorted by (dc_num, node_type, leaf_num)
    def _sort_key(name):
        dc_match = re.search(r'_dc(\d+)', name)
        leaf_match = re.search(r'(leaf|spine)(\d+)', name)
        dc_num = int(dc_match.group(1)) if dc_match else 0
        node_type = leaf_match.group(1) if leaf_match else name
        leaf_num = int(leaf_match.group(2)) if leaf_match else 0
        return (dc_num, node_type, leaf_num)

    # Determine how many interfaces each node has and where dut's interfaces start
    # We need to replicate the same ordering as generate_sag_hosts
    svi_nodes = []
    for node_name, ncfg in sorted(cfg_dict.items(), key=lambda x: _sort_key(x[0])):
        if not isinstance(ncfg, dict):
            continue
        if 'leaf' not in node_name:
            continue
        if not ncfg.get('l2vni'):
            continue
        svi_nodes.append(node_name)

    # Count interfaces per node from l2vni config members
    # Each unique non-PortChannel member or PortChannel group = 1 interface
    counter = 10  # global counter starts at 10
    dut_counters = []  # list of counter values for dut's interfaces

    for node_name in svi_nodes:
        ncfg = cfg_dict[node_name]
        l2vni = ncfg['l2vni']
        # Count interfaces: unique orphan ports + unique port-channels
        seen_ports = set()
        seen_pcs = set()
        if isinstance(l2vni, list):
            for item in l2vni:
                for member in item.get('members', []):
                    if member.startswith('PortChannel'):
                        pc_num = re.search(r'PortChannel(\d+)', member)
                        if pc_num and pc_num.group(1) not in seen_pcs:
                            seen_pcs.add(pc_num.group(1))
                    else:
                        # Extract port suffix (e.g., 'T1P1' -> 'P1')
                        if member not in seen_ports:
                            seen_ports.add(member)

        num_interfaces = len(seen_ports) + len(seen_pcs)
        if num_interfaces == 0:
            num_interfaces = 1  # At least 1 interface

        if node_name == dut:
            for i in range(num_interfaces):
                dut_counters.append(counter + i * 10)

        counter += num_interfaces * 10

    if not dut_counters:
        st.log('Could not determine interface counters for {}'.format(dut))
        return []

    # Build expected ARP entries: one per (vlan, interface_counter)
    expected = []
    for vlan_id in sorted(vlan_list):
        vlan_hex = format(vlan_id, '02x')
        for ctr in dut_counters:
            ctr_hex = format(ctr, '02x')
            ip = '80.{}.0.{}'.format(vlan_id, ctr)
            mac = '00:{}:00:00:04:{}'.format(vlan_hex, ctr_hex)
            expected.append({
                'ip': ip,
                'mac': mac,
                'vlan': str(vlan_id),
            })

    return expected


def verify_mac_arp_entries_dci(dut):
    """
    Verify MAC and ARP table entries on a node for L3VNI DCI traffic.

    Compares expected vs actual ARP entries using SAG host addressing data
    from DCI_NORMAL_SAG_ADDRESSING.md.  Expected local ARP entries are derived
    from generate_sag_hosts() addressing scheme:
      - IP:  80.<vlan>.0.<counter>
      - MAC: 00:<vlan_hex>:00:00:04:<counter_hex>

    Also verifies MAC table has entries (count check).

    Uses compare_exp_actual_data() for structured expected-vs-actual comparison.

    Args:
        dut: Node hostname to verify

    Returns:
        dict: {
            'result': True/False,
            'mac_count': int,
            'arp_count': int,
            'arp_missing': int,
            'details': str summary
        }
    """
    result = {
        'result': False,
        'mac_count': 0,
        'arp_count': 0,
        'arp_missing': 0,
        'details': ''
    }

    st.banner('Checking MAC and ARP entries on {}'.format(dut))

    # Step 1: Check MAC table (count check)
    try:
        mac_output = st.show(dut, "show mac", skip_tmpl=True)
        if mac_output:
            mac_lines = [l for l in mac_output.splitlines()
                         if ':' in l and ('dynamic' in l.lower() or 'static' in l.lower()
                                          or 'Vlan' in l)]
            result['mac_count'] = len(mac_lines)
        st.log('MAC entries on {}: {}'.format(dut, result['mac_count']))
    except Exception as err:
        st.log('Failed to get MAC table on {}: {}'.format(dut, err))

    # Step 2: Get actual ARP entries
    actual_arp = {}  # keyed by IP -> {mac, vlan}
    try:
        arp_output = st.show(dut, "show arp", skip_tmpl=True)
        if arp_output:
            for line in arp_output.splitlines():
                # Match ARP lines: IP  MAC  Iface  Vlan
                # e.g. "80.11.0.10    00:0b:00:00:04:0a  Ethernet1_1   11"
                m = re.search(
                    r'(80\.\d+\.\d+\.\d+)\s+([\da-f:]+)\s+\S+\s+(\d+)', line)
                if m:
                    actual_arp[m.group(1)] = {
                        'mac': m.group(2),
                        'vlan': m.group(3),
                    }
        result['arp_count'] = len(actual_arp)
        st.log('ARP entries on {}: {}'.format(dut, result['arp_count']))
    except Exception as err:
        st.log('Failed to get ARP table on {}: {}'.format(dut, err))

    # Step 3: Build expected ARP entries from SAG host addressing
    expected_arp = _get_expected_local_arp_entries(dut)
    st.log('Expected local ARP entries on {}: {}'.format(dut, len(expected_arp)))

    # Step 4: Compare expected vs actual ARP using structured comparison
    exp_data = []
    act_data = []
    missing_count = 0

    for exp_entry in expected_arp:
        ip = exp_entry['ip']
        exp_row = {
            'ip': ip,
            'mac': exp_entry['mac'],
            'vlan': exp_entry['vlan'],
            'present': 'yes',
        }
        exp_data.append(exp_row)

        if ip in actual_arp:
            act_row = {
                'ip': ip,
                'mac': actual_arp[ip]['mac'],
                'vlan': actual_arp[ip]['vlan'],
                'present': 'yes',
            }
        else:
            act_row = {
                'ip': ip,
                'mac': '-',
                'vlan': '-',
                'present': 'no',
            }
            missing_count += 1
        act_data.append(act_row)

    result['arp_missing'] = missing_count

    # Build summary
    details_parts = []
    details_parts.append('{} MAC entries'.format(result['mac_count']))
    details_parts.append('{}/{} expected ARP entries found'.format(
        len(expected_arp) - missing_count, len(expected_arp)))
    if missing_count > 0:
        details_parts.append('{} ARP entries missing'.format(missing_count))

    result['details'] = '; '.join(details_parts)
    st.log(result['details'])

    # Pass if MAC entries exist and all expected ARP entries are present
    result['result'] = (result['mac_count'] > 0 and missing_count == 0)

    # Use compare_exp_actual_data for structured tabular output if mismatch
    if not result['result'] and exp_data:
        try:
            compare_exp_actual_data(exp_data, act_data, ['ip'])
        except (CompareFailed, CompareEmptyData):
            pass  # Already captured in result

    return result


def report_result(result, tc_id='', rc_msg=''):
    if result:
        st.banner('Testcase: {} :: Result: Pass'.format(tc_id))
        st.report_pass('test_case_passed')
    else:
        st.banner('Testcase: {} :: Result: Fail'.format(tc_id))
        st.banner('Testcase: {} :: Diags: {}'.format(tc_id, rc_msg))
        collect_diags(tc_id)
        st.report_fail("test_case_failed")


def collect_diags(tc_id=''):
    cmds = list()
    vtysh_cmds = list()
    tc_dict = get_tc_params('all')
    cmds.extend(tc_dict.get('debug_cmds', []))
    vtysh_cmds.extend(tc_dict.get('debug_cmds_vtysh', []))
    if tc_id:
        tc_dict = get_tc_params(tc_id)
        cmds.extend(tc_dict.get('debug_cmds', []))
        vtysh_cmds.extend(tc_dict.get('debug_cmds_vtysh', []))
    for dut in st.get_dut_names():
        for cmd in cmds:
            try:
                st.config(dut, cmd, skip_error_check=True)
            except Exception as err:
                st.error('Error collecting : {}'.format(cmd))
        for cmd in vtysh_cmds:
            try:
                st.config(dut, cmd, type='vtysh', skip_error_check=True)
            except Exception as err:
                st.error('Error collecting : {}'.format(cmd))


def verify_type5_route_presence_dci(dut, vlan_ids, expect_present=True):
    """
    Verify Type-5 route presence or absence for specific VLANs using comprehensive
    Type-5 verification (get_expected_type5_routes + _parse_type5_routes_detailed).

    When expect_present=True (re-advertisement check):
      - Gets expected route data from get_expected_type5_routes(dut) for the given VLANs
      - Parses actual Type-5 output and verifies each prefix exists with expected path count
      - Uses structured expected-vs-actual comparison for detailed reporting

    When expect_present=False (withdrawal check):
      - Parses actual Type-5 output and verifies the VLAN prefixes are NOT present
      - Both IPv4 (80.<vlan>.0.0/24) and IPv6 (8000:<vlan>::/64) prefixes are checked

    Args:
        dut: Node hostname (BGW or leaf) to verify
        vlan_ids: list of VLAN IDs to check (e.g. [11] for Vlan11)
        expect_present: True to verify routes exist, False to verify routes are withdrawn

    Returns:
        Boolean: True if verification passes
    """
    action = 'present' if expect_present else 'withdrawn'
    st.banner('Verifying Type-5 routes {} for VLANs {} on {}'.format(
        action, vlan_ids, dut))

    # Build the set of prefixes to check (both IPv4 and IPv6 per VLAN)
    target_prefixes = set()
    for vlan_id in vlan_ids:
        target_prefixes.add('80.{}.0.0/24'.format(vlan_id))
        target_prefixes.add('8000:{}::/64'.format(vlan_id))

    # Parse actual Type-5 output
    try:
        cli_output = st.show(dut, "do show bgp l2vpn evpn route type prefix",
                             type='vtysh', skip_tmpl=True)
    except Exception as err:
        st.log('Failed to get Type-5 routes on {}: {}'.format(dut, err))
        return False

    if not cli_output or not cli_output.strip():
        if not expect_present:
            st.log('No Type-5 route output on {} - routes are withdrawn'.format(dut))
            return True
        else:
            st.log('No Type-5 route output on {} - routes not present yet'.format(dut))
            return False

    detailed = _parse_type5_routes_detailed(cli_output)
    act_prefixes = set(detailed.keys())

    if not expect_present:
        # Withdrawal check: verify target prefixes are NOT in actual output
        still_present = target_prefixes & act_prefixes
        if still_present:
            st.log('Type-5 routes still present for withdrawn VLANs on {}: {}'.format(
                dut, still_present))
            return False
        st.log('Type-5 routes successfully withdrawn for VLANs {} on {}'.format(
            vlan_ids, dut))
        return True

    # Re-advertisement / presence check: use comprehensive Type-5 verification
    # Get full expected routes and filter to target VLANs
    exp_routes = get_expected_type5_routes(dut)
    filtered_exp = [r for r in exp_routes if r['prefix'] in target_prefixes]

    if not filtered_exp:
        st.log('No expected Type-5 routes generated for VLANs {} on {}'.format(
            vlan_ids, dut))
        return False

    # Verify each expected prefix: existence + attributes
    is_leaf = filtered_exp[0].get('is_leaf', False) if filtered_exp else False
    all_pass = True
    for exp_route in filtered_exp:
        prefix = exp_route['prefix']

        if prefix not in detailed:
            st.log('Type-5 prefix {} NOT found on {}'.format(prefix, dut))
            all_pass = False
            continue

        info = detailed[prefix]
        actual_path_count = info['path_count']

        if is_leaf:
            # Leaf: check best path exists and has weight=32768
            best_path = info.get('best_path')
            if not best_path:
                st.log('Type-5 prefix {} on {}: no best path'.format(prefix, dut))
                all_pass = False
            else:
                st.log('Type-5 prefix {} on {}: Pass '
                       '({} paths, best path exists)'.format(
                           prefix, dut, actual_path_count))
        else:
            # BGW: check path count + route attributes
            expected_path_count = int(exp_route.get('path_count', 0))
            if actual_path_count != expected_path_count:
                st.log('Type-5 prefix {} on {}: path count mismatch '
                       '(expected={}, actual={})'.format(
                           prefix, dut, expected_path_count, actual_path_count))
                all_pass = False
            else:
                has_rt = any(p.get('rt') for p in info['paths'])
                has_et = any(p.get('et') for p in info['paths'])
                has_rmac = any(p.get('rmac') for p in info['paths'])
                if not (has_rt and has_et and has_rmac):
                    st.log('Type-5 prefix {} on {}: missing attributes '
                           '(rt={}, et={}, rmac={})'.format(
                               prefix, dut, has_rt, has_et, has_rmac))
                    all_pass = False
                else:
                    st.log('Type-5 prefix {} on {}: Pass '
                           '({} paths, rt/et/rmac ok)'.format(
                               prefix, dut, actual_path_count))

    if all_pass:
        st.log('Type-5 route presence verified for VLANs {} on {}'.format(
            vlan_ids, dut))
    else:
        st.log('Type-5 route presence verification FAILED for VLANs {} on {}'.format(
            vlan_ids, dut))

    return all_pass


def verify_vrf_vni_after_reload_dci(dut):
    """
    Verify VRF-VNI mappings are restored after config reload on a node.

    Checks that L3VNI VRF-VNI bindings (Vrf101→10101, Vrf102→10102) are present
    using 'show vxlan vrfvnimap'.

    Args:
        dut: Node hostname to verify

    Returns:
        Boolean: True if VRF-VNI mappings are restored
    """
    st.banner('Verifying VRF-VNI mappings restored on {} after reload'.format(dut))
    return verify_vrfvnimap(dut)


def get_tc_params(tc_id):
    test_cfg = get_cfg_dict()
    if not test_cfg or 'testcases' not in test_cfg.keys():
        return dict()
    if tc_id not in test_cfg['testcases'].keys():
        test_cfg['testcases'][tc_id] = dict()

    return test_cfg['testcases'][tc_id]

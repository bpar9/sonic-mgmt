# PVST Test Plan for SONiC

## 1. Overview

### 1.1 Purpose

This document defines a comprehensive test plan for validating Per-VLAN Spanning Tree (PVST) functionality in SONiC network operating system. The test plan covers PVST and Rapid PVST (RPVST) protocol implementations using the T0 topology configurations with two VLAN and four VLAN setups.

### 1.2 What is PVST?

Per-VLAN Spanning Tree (PVST) is a Cisco proprietary protocol that runs a separate instance of Spanning Tree Protocol (STP) for each VLAN configured on the network. This approach provides several advantages over traditional STP:

- **Per-VLAN Root Bridge Election**: Each VLAN can have a different root bridge, enabling better load balancing across the network.
- **Independent Topology Convergence**: A topology change in one VLAN does not affect the spanning tree topology of other VLANs.
- **Granular Traffic Engineering**: Network administrators can optimize traffic paths on a per-VLAN basis by adjusting bridge priorities and port costs.
- **Fault Isolation**: Link failures in one VLAN's spanning tree instance do not impact other VLANs.

### 1.3 Protocol Variants

The SONiC PVST implementation supports the following protocol variants:

- **PVST (Per-VLAN Spanning Tree)**: Based on IEEE 802.1D, provides separate STP instances per VLAN with standard convergence times (30-50 seconds).
- **RPVST (Rapid Per-VLAN Spanning Tree)**: Based on IEEE 802.1w, provides rapid convergence (typically under 1 second) while maintaining per-VLAN independence.
- **MSTP (Multiple Spanning Tree Protocol)**: Based on IEEE 802.1s, maps multiple VLANs to spanning tree instances for scalability.

### 1.4 Scope

This test plan focuses on validating:

- PVST instance independence across VLANs
- Correct root bridge election per VLAN
- Port state transitions (Blocking, Listening, Learning, Forwarding)
- Topology change handling and convergence
- Interface-specific PVST configuration
- Protocol variant behavior (PVST vs RPVST)
- Configuration persistence across device reboots

## 2. Test Environment

### 2.1 Topology Overview

The tests utilize the T0 (Top-of-Rack) isolated topology defined in `ansible/vars/topo_t0-isolated-d16u16s1.yml`. This topology provides a realistic data center environment with multiple host interfaces and VLAN configurations suitable for PVST testing.

### 2.2 VLAN Configurations

#### 2.2.1 Two VLAN Configuration (two_vlan_a)

This configuration divides the host interfaces into two VLANs, providing a basic multi-VLAN environment for testing PVST instance independence.

| VLAN | VLAN ID | Interfaces | IPv4 Prefix | IPv6 Prefix |
|------|---------|------------|-------------|-------------|
| Vlan1000 | 1000 | 0, 8, 16, 24, 96, 104, 112, 120 | 192.168.0.1/22 | fc02:100::1/64 |
| Vlan1100 | 1100 | 128, 136, 144, 152, 224, 232, 240, 248 | 192.168.4.1/22 | fc02:101::1/64 |

Each VLAN contains 8 interfaces, providing sufficient ports for testing various STP port roles (Root, Designated, Alternate, Backup) and states.

#### 2.2.2 Four VLAN Configuration (four_vlan_a)

This configuration provides a more complex multi-VLAN environment with four separate VLANs, enabling comprehensive testing of PVST scalability and per-VLAN independence.

| VLAN | VLAN ID | Interfaces | IPv4 Prefix | IPv6 Prefix |
|------|---------|------------|-------------|-------------|
| Vlan1000 | 1000 | 0, 8, 16, 24 | 192.168.0.1/22 | fc02:100::1/64 |
| Vlan1100 | 1100 | 96, 104, 112, 120 | 192.168.4.1/22 | fc02:101::1/64 |
| Vlan1200 | 1200 | 128, 136, 144, 152 | 192.168.8.1/22 | fc02:102::1/64 |
| Vlan1300 | 1300 | 224, 232, 240, 248 | 192.168.12.1/22 | fc02:103::1/64 |

Each VLAN contains 4 interfaces, allowing for testing of different root bridges and spanning tree topologies across multiple VLANs simultaneously.

### 2.3 Test Infrastructure Requirements

- **DUT (Device Under Test)**: SONiC switch with PVST support enabled
- **PTF Host**: Packet Test Framework container for traffic generation and verification
- **Neighbor VMs**: ARISTA T1 routers for upstream connectivity (16 VMs as defined in topology)
- **Test Framework**: SPyTest automation framework with PVST API support

### 2.4 Prerequisites

Before executing the test cases, ensure the following prerequisites are met:

1. SONiC image with PVST support is installed on the DUT
2. VLANs are configured according to the selected topology (two_vlan_a or four_vlan_a)
3. All interfaces are administratively up and operationally active
4. SPyTest framework is properly configured with access to the DUT
5. No existing STP configuration conflicts with test requirements

## 3. Test Cases

### 3.1 Per-VLAN STP Instance Independence

These test cases validate that PVST maintains separate spanning tree instances for each VLAN, ensuring that configuration changes and topology events in one VLAN do not affect other VLANs.

#### TC-PVST-001: Verify Independent STP Instances per VLAN

**Objective**: Confirm that each VLAN runs an independent STP instance with its own bridge ID and root bridge.

**Topology**: four_vlan_a

**Procedure**:
1. Enable PVST mode globally using `config_spanning_tree(dut, feature="pvst", mode="enable")`
2. Verify STP is enabled on all four VLANs (1000, 1100, 1200, 1300)
3. Use `show_stp_vlan(dut, vlan)` for each VLAN to retrieve STP instance information
4. Verify each VLAN has a unique STP instance ID
5. Confirm bridge IDs are correctly formed using VLAN ID and switch MAC address

**Expected Results**:
- Each VLAN displays a separate STP instance in the output
- Bridge IDs follow the format: priority + VLAN ID + MAC address
- Root bridge information is independently maintained per VLAN

**API Functions Used**:
- `config_spanning_tree()`
- `show_stp_vlan()`
- `get_stp_bridge_param()`

#### TC-PVST-002: Verify Different Root Bridges per VLAN

**Objective**: Validate that different VLANs can have different root bridges by configuring different bridge priorities.

**Topology**: two_vlan_a

**Procedure**:
1. Enable PVST mode on the DUT
2. Configure bridge priority 4096 for Vlan1000 using `config_stp_vlan_parameters(dut, 1000, priority=4096)`
3. Configure bridge priority 8192 for Vlan1100 using `config_stp_vlan_parameters(dut, 1100, priority=8192)`
4. Verify root bridge status for each VLAN using `check_dut_is_root_bridge_for_vlan()`
5. Use `get_root_bridge_for_vlan()` to confirm root bridge assignments

**Expected Results**:
- Vlan1000 shows DUT as root bridge with priority 4096
- Vlan1100 shows DUT as root bridge with priority 8192
- Each VLAN maintains independent root bridge election

**API Functions Used**:
- `config_stp_vlan_parameters()`
- `check_dut_is_root_bridge_for_vlan()`
- `get_root_bridge_for_vlan()`
- `check_for_single_root_bridge_per_vlan()`

#### TC-PVST-003: Verify STP Parameter Independence per VLAN

**Objective**: Confirm that STP parameters (hello time, max age, forward delay) can be configured independently per VLAN.

**Topology**: four_vlan_a

**Procedure**:
1. Enable PVST mode on the DUT
2. Configure different STP parameters for each VLAN:
   - Vlan1000: hello=1, max_age=10, forward_delay=10
   - Vlan1100: hello=2, max_age=20, forward_delay=15
   - Vlan1200: hello=3, max_age=25, forward_delay=20
   - Vlan1300: hello=4, max_age=30, forward_delay=25
3. Verify parameters using `show_stp_vlan()` for each VLAN
4. Confirm parameters are correctly applied and independent

**Expected Results**:
- Each VLAN displays its configured STP parameters
- Parameter changes in one VLAN do not affect other VLANs
- All parameters are within valid STP ranges

**API Functions Used**:
- `config_stp_vlan_parameters()`
- `show_stp_vlan()`
- `get_stp_bridge_param()`

### 3.2 Interface-Specific PVST Configuration

These test cases validate interface-level PVST configuration options and their per-VLAN behavior.

#### TC-PVST-004: Verify Per-VLAN Port Cost Configuration

**Objective**: Validate that port costs can be configured independently for each VLAN on the same physical interface.

**Topology**: two_vlan_a

**Procedure**:
1. Enable PVST mode on the DUT
2. Select an interface that is a member of both VLANs (if applicable) or test on VLAN-specific interfaces
3. Configure port cost 100 for interface 0 in Vlan1000 using `config_stp_vlan_interface()`
4. Configure port cost 200 for interface 128 in Vlan1100
5. Verify port costs using `show_stp_vlan_iface()`

**Expected Results**:
- Port costs are correctly applied per VLAN
- `show_stp_vlan_iface()` displays the configured costs
- Port cost changes affect STP path calculations independently per VLAN

**API Functions Used**:
- `config_stp_vlan_interface()`
- `show_stp_vlan_iface()`
- `get_stp_port_param()`

#### TC-PVST-005: Verify Per-VLAN Port Priority Configuration

**Objective**: Confirm that port priorities can be set independently per VLAN.

**Topology**: four_vlan_a

**Procedure**:
1. Enable PVST mode on the DUT
2. Configure different port priorities for interfaces in each VLAN:
   - Interface 0 (Vlan1000): priority 32
   - Interface 96 (Vlan1100): priority 64
   - Interface 128 (Vlan1200): priority 96
   - Interface 224 (Vlan1300): priority 128
3. Verify port priorities using `show_stp_vlan_iface()`
4. Confirm priorities affect port ID calculations

**Expected Results**:
- Port priorities are correctly configured per VLAN
- Port IDs reflect the configured priorities
- Priority changes do not affect other VLANs

**API Functions Used**:
- `config_stp_vlan_interface()`
- `show_stp_vlan_iface()`
- `verify_stp_vlan_iface()`

#### TC-PVST-006: Verify BPDU Guard Configuration

**Objective**: Validate BPDU Guard functionality on PVST-enabled interfaces.

**Topology**: two_vlan_a

**Procedure**:
1. Enable PVST mode on the DUT
2. Enable BPDU Guard on interface 0 using `config_stp_interface_params(dut, iface, bpdu_guard="enable")`
3. Enable BPDU Guard action (port shutdown) using `config_stp_interface_params(dut, iface, bpdu_guard_action="enable")`
4. Simulate BPDU reception on the protected interface
5. Verify interface is disabled using `check_bpdu_guard_action()`

**Expected Results**:
- BPDU Guard is enabled on the specified interface
- Interface is shut down upon BPDU reception
- BPDU Guard status is correctly reported

**API Functions Used**:
- `config_stp_interface_params()`
- `check_bpdu_guard_action()`
- `show_stp()`

#### TC-PVST-007: Verify Root Guard Configuration

**Objective**: Validate Root Guard functionality to prevent unauthorized root bridge changes.

**Topology**: two_vlan_a

**Procedure**:
1. Enable PVST mode and configure DUT as root bridge for Vlan1000
2. Enable Root Guard on interface 0 using `config_stp_interface_params(dut, iface, root_guard="enable")`
3. Verify Root Guard status using `get_root_guard_details()`
4. Simulate superior BPDU reception on the protected interface
5. Verify interface enters root-inconsistent state using `check_rg_current_state()`

**Expected Results**:
- Root Guard is enabled on the specified interface
- Interface enters root-inconsistent state upon superior BPDU reception
- Root bridge status is preserved

**API Functions Used**:
- `config_stp_interface_params()`
- `get_root_guard_details()`
- `check_rg_current_state()`

#### TC-PVST-008: Verify PortFast Configuration

**Objective**: Validate PortFast functionality for rapid port transition to forwarding state.

**Topology**: four_vlan_a

**Procedure**:
1. Enable PVST mode on the DUT
2. Enable PortFast on edge interfaces using `config_stp_interface_params(dut, iface, portfast="enable")`
3. Bring the interface down and then up
4. Verify immediate transition to forwarding state
5. Confirm PortFast status using `show_stp_vlan_iface()`

**Expected Results**:
- PortFast-enabled interfaces transition directly to forwarding state
- No listening/learning state delays observed
- PortFast status is correctly displayed

**API Functions Used**:
- `config_stp_interface_params()`
- `show_stp_vlan_iface()`
- `verify_stp_intf_status()`

#### TC-PVST-009: Verify Loop Guard Configuration

**Objective**: Validate Loop Guard functionality to prevent loops caused by unidirectional link failures.

**Topology**: two_vlan_a

**Procedure**:
1. Enable PVST mode on the DUT
2. Enable Loop Guard globally using `config_loopguard_global()`
3. Enable Loop Guard on specific interface using `config_stp_interface_params(dut, iface, loop_guard="enable")`
4. Verify Loop Guard status using `get_loop_guard_details()`
5. Simulate BPDU loss on a non-designated port
6. Verify interface enters loop-inconsistent state using `check_lg_current_state()`

**Expected Results**:
- Loop Guard is enabled on the specified interface
- Interface enters loop-inconsistent state when BPDUs are not received
- Loop is prevented even with unidirectional link failure

**API Functions Used**:
- `config_loopguard_global()`
- `config_stp_interface_params()`
- `get_loop_guard_details()`
- `check_lg_current_state()`

### 3.3 Topology Change Resilience

These test cases validate PVST behavior during topology changes and link failures, ensuring per-VLAN isolation.

#### TC-PVST-010: Verify Topology Change Isolation per VLAN

**Objective**: Confirm that a topology change in one VLAN does not trigger topology change notifications in other VLANs.

**Topology**: four_vlan_a

**Procedure**:
1. Enable PVST mode on the DUT
2. Record topology change counters for all VLANs using `show_stp_vlan()`
3. Trigger a topology change in Vlan1000 by shutting down interface 0
4. Wait for STP convergence
5. Verify topology change counters for all VLANs

**Expected Results**:
- Vlan1000 shows incremented topology change counter
- Vlan1100, Vlan1200, Vlan1300 topology change counters remain unchanged
- Only Vlan1000 interfaces undergo state transitions

**API Functions Used**:
- `show_stp_vlan()`
- `get_stp_bridge_param()`
- `show_stp_stats_vlan()`

#### TC-PVST-011: Verify Link Failure Recovery per VLAN

**Objective**: Validate that link failures are handled independently per VLAN with correct failover behavior.

**Topology**: two_vlan_a

**Procedure**:
1. Enable PVST mode on the DUT
2. Identify root ports for Vlan1000 and Vlan1100 using `get_stp_root_port()`
3. Shut down the root port for Vlan1000
4. Verify alternate port becomes new root port using `get_stp_next_root_port()`
5. Confirm Vlan1100 root port remains unchanged
6. Restore the original link and verify reconvergence

**Expected Results**:
- Vlan1000 converges to new root port after link failure
- Vlan1100 spanning tree topology remains stable
- Original topology is restored after link recovery

**API Functions Used**:
- `get_stp_root_port()`
- `get_stp_next_root_port()`
- `poll_for_stp_status()`
- `verify_stp_ports_by_state()`

#### TC-PVST-012: Verify Port State Transitions

**Objective**: Validate correct port state transitions (Blocking -> Listening -> Learning -> Forwarding) per VLAN.

**Topology**: two_vlan_a

**Procedure**:
1. Enable PVST mode on the DUT
2. Bring up a new interface in Vlan1000
3. Monitor port state transitions using `poll_for_stp_status()`
4. Verify state progression: Blocking -> Listening -> Learning -> Forwarding
5. Confirm timing matches configured forward_delay values

**Expected Results**:
- Port transitions through all STP states correctly
- State transition timing matches configured parameters
- Final state is appropriate for port role (Forwarding for designated/root ports)

**API Functions Used**:
- `poll_for_stp_status()`
- `get_ports_based_on_state()`
- `verify_stp_ports_by_state()`

#### TC-PVST-013: Verify Convergence Time

**Objective**: Measure and validate STP convergence time after topology changes.

**Topology**: four_vlan_a

**Procedure**:
1. Enable PVST mode on the DUT
2. Record initial STP state for all VLANs
3. Trigger topology change by shutting down root port
4. Measure time until all ports reach stable state
5. Compare convergence time against expected values (30-50 seconds for PVST)

**Expected Results**:
- Convergence completes within expected timeframe
- All ports reach appropriate final states
- No loops detected during convergence

**API Functions Used**:
- `poll_for_root_switch()`
- `poll_root_bridge_interfaces()`
- `verify_root_bridge_interface_state()`

### 3.4 Protocol Variant Testing (PVST vs RPVST)

These test cases compare behavior between PVST and Rapid PVST protocols.

#### TC-PVST-014: Verify RPVST Rapid Convergence

**Objective**: Validate that RPVST provides faster convergence than standard PVST.

**Topology**: two_vlan_a

**Procedure**:
1. Enable RPVST mode using `config_spanning_tree(dut, feature="rpvst", mode="enable")`
2. Verify RPVST is active using `show_stp()`
3. Trigger topology change by shutting down root port
4. Measure convergence time
5. Compare with PVST convergence time from TC-PVST-013

**Expected Results**:
- RPVST convergence time is significantly faster (typically < 1 second)
- Port states transition correctly under RPVST
- Rapid transition to forwarding state observed

**API Functions Used**:
- `config_spanning_tree()`
- `show_stp()`
- `poll_for_stp_status()`

#### TC-PVST-015: Verify RPVST Port Roles

**Objective**: Validate RPVST-specific port roles (Alternate, Backup) are correctly assigned.

**Topology**: four_vlan_a

**Procedure**:
1. Enable RPVST mode on the DUT
2. Create a topology with redundant paths
3. Verify port roles using `show_stp_vlan()`
4. Confirm Alternate and Backup port assignments
5. Verify rapid failover when root port fails

**Expected Results**:
- Alternate ports are correctly identified
- Backup ports are assigned where applicable
- Rapid failover occurs using pre-computed alternate paths

**API Functions Used**:
- `config_spanning_tree()`
- `show_stp_vlan()`
- `get_stp_port_list()`

#### TC-PVST-016: Verify Protocol Mode Switching

**Objective**: Validate switching between PVST and RPVST modes.

**Topology**: two_vlan_a

**Procedure**:
1. Enable PVST mode and verify operation
2. Switch to RPVST mode using `config_spanning_tree(dut, feature="rpvst", mode="enable")`
3. Verify all VLANs transition to RPVST operation
4. Switch back to PVST mode
5. Verify all VLANs return to PVST operation

**Expected Results**:
- Mode switching completes without errors
- All VLANs operate under the selected protocol
- STP topology reconverges after mode change

**API Functions Used**:
- `config_spanning_tree()`
- `show_stp()`
- `show_stp_vlan()`

### 3.5 Configuration Persistence

These test cases validate that PVST configuration persists across device reboots.

#### TC-PVST-017: Verify PVST Configuration Persistence After Warm Reboot

**Objective**: Confirm PVST configuration is preserved after a warm reboot.

**Topology**: four_vlan_a

**Procedure**:
1. Enable PVST mode and configure:
   - Bridge priorities for each VLAN
   - Port costs and priorities
   - BPDU Guard on selected interfaces
   - Root Guard on selected interfaces
2. Save configuration
3. Perform warm reboot
4. Verify all PVST configurations are restored

**Expected Results**:
- PVST mode remains enabled after reboot
- All VLAN-specific parameters are preserved
- Interface-specific settings are restored
- STP topology reconverges correctly

**API Functions Used**:
- `config_spanning_tree()`
- `config_stp_vlan_parameters()`
- `config_stp_interface_params()`
- `show_stp()`
- `show_stp_vlan()`

#### TC-PVST-018: Verify PVST Configuration Persistence After Cold Reboot

**Objective**: Confirm PVST configuration is preserved after a cold reboot.

**Topology**: two_vlan_a

**Procedure**:
1. Enable PVST mode with comprehensive configuration
2. Save configuration
3. Perform cold reboot
4. Verify all PVST configurations are restored
5. Verify STP topology converges to expected state

**Expected Results**:
- All PVST configurations persist through cold reboot
- STP instances are correctly re-established
- Root bridge elections complete successfully

**API Functions Used**:
- `config_spanning_tree()`
- `show_stp()`
- `verify_root_bridge_on_stp_instances()`

#### TC-PVST-019: Verify PVST Configuration After Config Reload

**Objective**: Validate PVST configuration is correctly applied after configuration reload.

**Topology**: four_vlan_a

**Procedure**:
1. Configure PVST with various parameters
2. Save configuration to startup config
3. Execute config reload
4. Verify PVST configuration is applied correctly
5. Verify STP operation resumes normally

**Expected Results**:
- Configuration reload completes successfully
- PVST configuration matches saved configuration
- STP topology converges correctly

**API Functions Used**:
- `config_spanning_tree()`
- `show_stp_config_using_klish()`
- `show_stp()`

### 3.6 Scale and Stress Testing

#### TC-PVST-020: Verify PVST Operation with Maximum VLANs

**Objective**: Validate PVST operation with the maximum supported number of VLANs.

**Topology**: four_vlan_a (extended)

**Procedure**:
1. Enable PVST mode on the DUT
2. Configure maximum supported VLANs with STP enabled
3. Verify STP instances are created for all VLANs
4. Verify root bridge election completes for all VLANs
5. Measure system resource utilization

**Expected Results**:
- All VLAN STP instances are operational
- Root bridge is elected for each VLAN
- System resources remain within acceptable limits

**API Functions Used**:
- `config_spanning_tree()`
- `verify_stp_scale()`
- `show_stp()`

#### TC-PVST-021: Verify PVST Statistics

**Objective**: Validate PVST statistics collection and reporting.

**Topology**: two_vlan_a

**Procedure**:
1. Enable PVST mode on the DUT
2. Clear STP statistics using `stp_clear_stats()`
3. Generate STP traffic (BPDUs) by triggering topology changes
4. Retrieve statistics using `get_stp_stats()` and `show_stp_stats_vlan()`
5. Verify statistics are accurately reported

**Expected Results**:
- BPDU transmit/receive counters are accurate
- Topology change counters reflect actual changes
- Statistics are maintained per VLAN

**API Functions Used**:
- `stp_clear_stats()`
- `get_stp_stats()`
- `show_stp_stats_vlan()`
- `verify_stp_statistics_vlan()`

## 4. API Reference

The following API functions from `spytest/apis/switching/pvst.py` are used in this test plan:

### 4.1 Configuration APIs

| Function | Description | Parameters |
|----------|-------------|------------|
| `config_spanning_tree()` | Enables/disables PVST mode globally or per-VLAN | dut, feature, mode, vlan |
| `config_stp_parameters()` | Configures global STP parameters | dut, forward_delay, max_age, priority |
| `config_stp_vlan_parameters()` | Sets VLAN-specific STP parameters | dut, vlan, priority, hello, max_age, forward_delay |
| `config_stp_vlan_parameters_parallel()` | Configures VLAN parameters on multiple DUTs | dut_list, vlan, priority |
| `config_stp_vlan_interface()` | Configures per-VLAN interface settings | dut, vlan, iface, value, mode |
| `config_stp_interface_params()` | Configures interface-specific STP settings | dut, iface, bpdu_guard, root_guard, portfast, etc. |
| `config_stp_enable_interface()` | Enables/disables STP on an interface | dut, iface, mode |
| `config_bpdu_filter()` | Configures BPDU filter | dut, interface, action |
| `config_loopguard_global()` | Enables/disables global loop guard | dut, mode |
| `config_stp_root_bridge_by_vlan()` | Configures DUT as root bridge for VLAN | dut, vlan, priority |
| `config_port_type()` | Configures port type (edge/network) | dut, interface, port_type |

### 4.2 Show/Display APIs

| Function | Description | Parameters |
|----------|-------------|------------|
| `show_stp()` | Displays global spanning tree status | dut |
| `show_stp_vlan()` | Shows VLAN-specific STP information | dut, vlan |
| `show_stp_vlan_iface()` | Displays STP status for VLAN interfaces | dut, vlan, iface |
| `show_stp_stats()` | Shows STP statistics | dut |
| `show_stp_stats_vlan()` | Shows VLAN-specific STP statistics | dut, vlan |
| `show_stp_config_using_klish()` | Displays STP configuration via KLISH | dut |
| `show_stp_in_parallel()` | Shows STP on multiple DUTs in parallel | dut_list |

### 4.3 Verification APIs

| Function | Description | Parameters |
|----------|-------------|------------|
| `verify_stp_vlan_iface()` | Verifies STP VLAN interface parameters | dut, vlan, iface, expected_values |
| `verify_stp_statistics_vlan()` | Verifies STP statistics for VLAN | dut, vlan, expected_stats |
| `verify_stp_ports_by_state()` | Verifies ports are in expected state | dut, vlan, state, ports |
| `verify_root_bridge_interface_state()` | Verifies root bridge interface states | dut, vlan |
| `verify_root_bridge_on_stp_instances()` | Verifies root bridge across instances | dut_list, vlan_list |
| `verify_stp_intf_status()` | Verifies interface STP status | dut, interface, expected_status |
| `verify_stp_scale()` | Verifies STP scale limits | dut, num_vlans |

### 4.4 Query/Get APIs

| Function | Description | Parameters |
|----------|-------------|------------|
| `get_stp_bridge_param()` | Gets bridge parameters for VLAN | dut, vlan, param |
| `get_stp_port_param()` | Gets port parameters for VLAN interface | dut, vlan, iface, param |
| `get_root_bridge_for_vlan()` | Gets root bridge for specified VLAN | dut, vlan |
| `get_stp_root_port()` | Gets root port for VLAN | dut, vlan |
| `get_stp_next_root_port()` | Gets next root port candidate | dut, vlan |
| `get_stp_port_list()` | Gets list of STP ports for VLAN | dut, vlan |
| `get_ports_based_on_state()` | Gets ports in specified state | dut, vlan, state |
| `get_default_root_bridge()` | Gets default root bridge | dut_list |
| `get_duts_mac_address()` | Gets MAC addresses of DUTs | dut_list |
| `get_root_guard_details()` | Gets root guard configuration | dut, interface |
| `get_loop_guard_details()` | Gets loop guard configuration | dut, interface |
| `get_stp_stats()` | Gets STP statistics | dut |

### 4.5 Check/Poll APIs

| Function | Description | Parameters |
|----------|-------------|------------|
| `check_dut_is_root_bridge_for_vlan()` | Checks if DUT is root bridge | dut, vlan |
| `check_for_single_root_bridge_per_vlan()` | Verifies single root bridge per VLAN | dut_list, vlan |
| `check_rg_current_state()` | Checks root guard current state | dut, interface |
| `check_lg_current_state()` | Checks loop guard current state | dut, interface |
| `check_bpdu_guard_action()` | Checks BPDU guard action status | dut, interface |
| `poll_for_root_switch()` | Polls until root switch is elected | dut_list, vlan |
| `poll_for_stp_status()` | Polls for STP status convergence | dut, vlan, expected_state |
| `poll_root_bridge_interfaces()` | Polls root bridge interface states | dut, vlan |

### 4.6 Utility APIs

| Function | Description | Parameters |
|----------|-------------|------------|
| `stp_clear_stats()` | Clears STP statistics | dut |
| `debug_stp()` | Enables STP debugging | dut, mode |
| `get_debug_stp_log()` | Gets STP debug log | dut |
| `clear_debug_stp_log()` | Clears STP debug log | dut |
| `config_stp_in_parallel()` | Configures STP on multiple DUTs | dut_list, config |

## 5. Validation Criteria

### 5.1 Test Pass Criteria

A test case is considered PASSED when all of the following conditions are met:

1. **Functional Correctness**: The PVST feature behaves as expected according to IEEE 802.1D/802.1w standards and SONiC specifications.

2. **Per-VLAN Independence**: Each VLAN maintains an independent STP instance with:
   - Unique bridge ID incorporating VLAN ID
   - Independent root bridge election
   - Isolated topology change handling
   - Separate port state machines

3. **Configuration Accuracy**: All configured parameters are correctly applied and displayed:
   - Bridge priorities match configured values
   - Port costs and priorities are accurate
   - Timer values (hello, max_age, forward_delay) are correct
   - Interface-specific settings (BPDU guard, root guard, portfast) are active

4. **Convergence Requirements**:
   - PVST: Convergence within 50 seconds (2 x forward_delay + max_age)
   - RPVST: Convergence within 3 seconds under normal conditions

5. **State Consistency**: Port states are consistent with STP algorithm:
   - Root ports in forwarding state
   - Designated ports in forwarding state
   - Alternate/backup ports in blocking state
   - No forwarding loops detected

6. **Persistence**: Configuration survives reboots and config reloads without manual intervention.

### 5.2 Test Fail Criteria

A test case is considered FAILED when any of the following conditions occur:

1. **STP Instance Failure**: VLAN fails to create or maintain STP instance
2. **Cross-VLAN Impact**: Configuration or topology change in one VLAN affects another VLAN
3. **Incorrect Root Bridge**: Wrong device elected as root bridge based on priority/MAC
4. **Port State Error**: Port in incorrect state (e.g., forwarding when should be blocking)
5. **Loop Detection**: Forwarding loop detected in any VLAN
6. **Convergence Timeout**: STP fails to converge within expected timeframe
7. **Configuration Loss**: Settings not preserved after reboot
8. **API Error**: PVST API returns error or unexpected result

### 5.3 Test Environment Validation

Before executing test cases, validate the test environment:

1. **Topology Verification**:
   - All interfaces are operationally up
   - VLANs are correctly configured per topology specification
   - Connectivity between DUT and test infrastructure is established

2. **Software Verification**:
   - SONiC version supports PVST feature
   - SPyTest framework is properly installed and configured
   - PVST API module is accessible

3. **Baseline State**:
   - No pre-existing STP configuration conflicts
   - System resources (CPU, memory) are within normal range
   - No error conditions in system logs

### 5.4 Test Reporting Requirements

Test execution reports should include:

1. **Test Identification**: Test case ID, name, and description
2. **Environment Details**: Topology used, SONiC version, DUT hardware
3. **Execution Status**: PASS/FAIL/SKIP with timestamp
4. **Evidence**: Relevant command outputs, logs, and screenshots
5. **Failure Analysis**: Root cause analysis for failed tests
6. **Performance Metrics**: Convergence times, resource utilization where applicable

## 6. Appendix

### 6.1 VLAN Interface Mapping Reference

#### Two VLAN Configuration (two_vlan_a)

```
Vlan1000 Interfaces: Ethernet0, Ethernet8, Ethernet16, Ethernet24, 
                     Ethernet96, Ethernet104, Ethernet112, Ethernet120

Vlan1100 Interfaces: Ethernet128, Ethernet136, Ethernet144, Ethernet152,
                     Ethernet224, Ethernet232, Ethernet240, Ethernet248
```

#### Four VLAN Configuration (four_vlan_a)

```
Vlan1000 Interfaces: Ethernet0, Ethernet8, Ethernet16, Ethernet24
Vlan1100 Interfaces: Ethernet96, Ethernet104, Ethernet112, Ethernet120
Vlan1200 Interfaces: Ethernet128, Ethernet136, Ethernet144, Ethernet152
Vlan1300 Interfaces: Ethernet224, Ethernet232, Ethernet240, Ethernet248
```

### 6.2 STP Timer Defaults

| Parameter | Default Value | Valid Range |
|-----------|---------------|-------------|
| Hello Time | 2 seconds | 1-10 seconds |
| Max Age | 20 seconds | 6-40 seconds |
| Forward Delay | 15 seconds | 4-30 seconds |
| Bridge Priority | 32768 | 0-61440 (increments of 4096) |
| Port Priority | 128 | 0-240 (increments of 16) |
| Path Cost | Auto (based on speed) | 1-200000000 |

### 6.3 STP Port States

| State | Description | Duration |
|-------|-------------|----------|
| Blocking | Not forwarding, learning MACs | Until topology stable |
| Listening | Not forwarding, not learning | Forward Delay |
| Learning | Not forwarding, learning MACs | Forward Delay |
| Forwarding | Forwarding, learning MACs | Stable state |
| Disabled | Administratively disabled | Until enabled |

### 6.4 References

- IEEE 802.1D-2004: MAC Bridges
- IEEE 802.1w-2001: Rapid Spanning Tree Protocol
- SONiC PVST Implementation: `spytest/apis/switching/pvst.py`
- T0 Topology Configuration: `ansible/vars/topo_t0-isolated-d16u16s1.yml`

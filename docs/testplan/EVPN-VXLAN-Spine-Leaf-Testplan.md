# EVPN-VXLAN Test Plan for 4x4 Spine-Leaf Topology

- [Overview](#overview)
  - [Scope](#scope)
  - [Testbed](#testbed)
- [Topology](#topology)
  - [4x4 Spine-Leaf Architecture](#4x4-spine-leaf-architecture)
  - [Hardware Configuration](#hardware-configuration)
- [Setup Configuration](#setup-configuration)
- [Test Methodology](#test-methodology)
- [Test Cases](#test-cases)
  - [Basic EVPN-VXLAN Functionality Tests](#basic-evpn-vxlan-functionality-tests)
    - [Test Case 1 - EVPN Type-2 MAC/IP Route Distribution](#test-case-1---evpn-type-2-macip-route-distribution)
    - [Test Case 2 - EVPN Type-3 Inclusive Multicast Route Distribution](#test-case-2---evpn-type-3-inclusive-multicast-route-distribution)
    - [Test Case 3 - VXLAN Encapsulation and Decapsulation](#test-case-3---vxlan-encapsulation-and-decapsulation)
    - [Test Case 4 - Multi-Tenant VNI Isolation](#test-case-4---multi-tenant-vni-isolation)
  - [Single Homing Tests](#single-homing-tests)
    - [Test Case 5 - Single-Homed Endpoint MAC Learning](#test-case-5---single-homed-endpoint-mac-learning)
    - [Test Case 6 - Single-Homed Endpoint ARP/ND Resolution](#test-case-6---single-homed-endpoint-arpnd-resolution)
    - [Test Case 7 - Single-Homed Endpoint Traffic Forwarding](#test-case-7---single-homed-endpoint-traffic-forwarding)
    - [Test Case 8 - Single-Homed Endpoint Leaf Switch Failure](#test-case-8---single-homed-endpoint-leaf-switch-failure)
    - [Test Case 9 - Single-Homed Endpoint VLAN to VNI Mapping](#test-case-9---single-homed-endpoint-vlan-to-vni-mapping)
    - [Test Case 10 - Single-Homed Endpoint Inter-VNI Routing](#test-case-10---single-homed-endpoint-inter-vni-routing)
    - [Test Case 11 - Single-Homed Endpoint BUM Traffic Handling](#test-case-11---single-homed-endpoint-bum-traffic-handling)
    - [Test Case 12 - Single-Homed Endpoint MAC Move Detection](#test-case-12---single-homed-endpoint-mac-move-detection)
  - [High Availability Tests](#high-availability-tests)
    - [Test Case 13 - Spine Switch Redundancy](#test-case-13---spine-switch-redundancy)
    - [Test Case 14 - BFD-Based Fast Failover](#test-case-14---bfd-based-fast-failover)
    - [Test Case 15 - ECMP Path Failover](#test-case-15---ecmp-path-failover)
  - [Scale Testing](#scale-testing)
    - [Test Case 16 - MAC Address Scale](#test-case-16---mac-address-scale)
    - [Test Case 17 - VNI Scale](#test-case-17---vni-scale)
    - [Test Case 18 - VTEP Scale](#test-case-18---vtep-scale)
  - [Multi-Encapsulation Tests](#multi-encapsulation-tests)
    - [Test Case 19 - IPv4-in-IPv4 VXLAN Encapsulation](#test-case-19---ipv4-in-ipv4-vxlan-encapsulation)
    - [Test Case 20 - IPv4-in-IPv6 VXLAN Encapsulation](#test-case-20---ipv4-in-ipv6-vxlan-encapsulation)
    - [Test Case 21 - IPv6-in-IPv4 VXLAN Encapsulation](#test-case-21---ipv6-in-ipv4-vxlan-encapsulation)
    - [Test Case 22 - IPv6-in-IPv6 VXLAN Encapsulation](#test-case-22---ipv6-in-ipv6-vxlan-encapsulation)
- [Test Infrastructure](#test-infrastructure)
- [References](#references)

## Overview

This test plan validates EVPN-VXLAN functionality in a 4x4 spine-leaf topology using SONiC network operating system. The tests cover basic EVPN-VXLAN operations, single-homing scenarios, high availability, scale testing, and multi-encapsulation support.

### Scope

These tests are targeted on a fully functioning SONiC system deployed in a 4x4 spine-leaf topology. The purpose of these tests is to validate EVPN-VXLAN control plane and data plane functionality, including EVPN Type-2 (MAC/IP) and Type-3 (Inclusive Multicast) route distribution, VXLAN encapsulation/decapsulation, single-homed endpoint behavior, BFD-based fast failover, multi-tenant VNI isolation, and spine switch redundancy.

### Testbed

The tests will run on the following testbed configuration:

- 4 Spine switches (Cisco-8101-32FH-O)
- 4 Leaf switches (Cisco-8101-32FH-O)
- Keysight Ixia chassis with IxNetwork API for traffic generation
- Full mesh connectivity between spine and leaf layers

## Topology

### 4x4 Spine-Leaf Architecture

```
                    +----------+  +----------+  +----------+  +----------+
                    | Spine-1  |  | Spine-2  |  | Spine-3  |  | Spine-4  |
                    +----+-----+  +----+-----+  +----+-----+  +----+-----+
                         |             |             |             |
         +---------------+-------------+-------------+-------------+---------------+
         |               |             |             |             |               |
    +----+-----+    +----+-----+  +----+-----+  +----+-----+  +----+-----+    +----+-----+
    | Leaf-1   |    | Leaf-2   |  | Leaf-3   |  | Leaf-4   |  |          |    |          |
    +----+-----+    +----+-----+  +----+-----+  +----+-----+  |  Ixia    |    |  Ixia    |
         |               |             |             |        | Chassis  |    | Chassis  |
    +----+-----+    +----+-----+  +----+-----+  +----+-----+  +----------+    +----------+
    | Host-1   |    | Host-2   |  | Host-3   |  | Host-4   |
    | (Ixia)   |    | (Ixia)   |  | (Ixia)   |  | (Ixia)   |
    +----------+    +----------+  +----------+  +----------+
```

Each leaf switch connects to all four spine switches, creating a full mesh fabric. Endpoints (simulated by Ixia traffic generators) connect to leaf switches in single-homed configurations.

### Hardware Configuration

| Component | Model | Interfaces | Role |
|-----------|-------|------------|------|
| Spine Switches | Cisco-8101-32FH-O | 32x400G | VXLAN underlay routing |
| Leaf Switches | Cisco-8101-32FH-O | 32x400G | VXLAN VTEP, endpoint connectivity |
| Traffic Generator | Keysight Ixia | Multiple 400G ports | Endpoint simulation, traffic generation |

## Setup Configuration

The following configuration elements are required for the EVPN-VXLAN testbed:

1. **Underlay Network Configuration**
   - OSPF or BGP underlay routing between spine and leaf switches
   - Loopback interfaces on each switch for VTEP source IP addresses
   - ECMP load balancing across spine switches

2. **EVPN Control Plane Configuration**
   - iBGP EVPN sessions between leaf switches (via route reflectors on spine switches)
   - EVPN address family enabled on BGP sessions
   - Route distinguisher and route target configuration per VNI

3. **VXLAN Data Plane Configuration**
   - VXLAN tunnel interfaces on leaf switches
   - VNI to VLAN mapping on leaf switches
   - VTEP source interface configuration

4. **BFD Configuration**
   - BFD sessions for fast failure detection
   - BFD integration with BGP and ECMP

## Test Methodology

The following test methodology will be used for validating EVPN-VXLAN functionality:

1. **Traffic Generator Setup**: Keysight Ixia chassis with IxNetwork API will be used to simulate endpoints and generate traffic patterns.

2. **Control Plane Validation**: EVPN route distribution will be verified using BGP show commands and route table inspection.

3. **Data Plane Validation**: Traffic forwarding will be verified using Ixia traffic statistics, including packet counts, latency, and loss measurements.

4. **Failure Injection**: Link failures, switch failures, and configuration changes will be injected to validate high availability and convergence behavior.

5. **Scale Testing**: Incremental scaling of MAC addresses, VNIs, and VTEPs will be performed to validate system limits.

The tests leverage the existing sonic-mgmt VXLAN infrastructure including the `Ecmp_Utils` class from `tests/common/vxlan_ecmp_utils.py` and the PTF test framework for packet-level validation.

## Test Cases

### Basic EVPN-VXLAN Functionality Tests

#### Test Case 1 - EVPN Type-2 MAC/IP Route Distribution

**Objective**

Verify that EVPN Type-2 (MAC/IP Advertisement) routes are correctly distributed across all leaf switches when a new endpoint MAC address is learned.

**Test Steps**

1. Configure EVPN-VXLAN on all leaf switches with a common VNI (e.g., VNI 10000).
2. Connect Ixia port to Leaf-1 and configure it to send traffic with source MAC 00:11:22:33:44:55.
3. Send ARP request from Ixia port to trigger MAC learning on Leaf-1.
4. Verify that Leaf-1 learns the MAC address in its local MAC table.
5. Verify that Leaf-1 generates an EVPN Type-2 route for the learned MAC.
6. Verify that all other leaf switches (Leaf-2, Leaf-3, Leaf-4) receive the EVPN Type-2 route via BGP.
7. Verify that remote leaf switches install the MAC in their EVPN MAC table with the correct VTEP IP.

**Expected Results**

- Leaf-1 learns MAC 00:11:22:33:44:55 locally.
- EVPN Type-2 route is advertised with correct RD, RT, and VNI.
- All remote leaf switches receive and install the route.
- Remote MAC table entries point to Leaf-1's VTEP IP address.

#### Test Case 2 - EVPN Type-3 Inclusive Multicast Route Distribution

**Objective**

Verify that EVPN Type-3 (Inclusive Multicast Ethernet Tag) routes are correctly distributed for BUM (Broadcast, Unknown unicast, Multicast) traffic handling.

**Test Steps**

1. Configure EVPN-VXLAN on all leaf switches with ingress replication for BUM traffic.
2. Verify that each leaf switch generates EVPN Type-3 routes for each configured VNI.
3. Verify that all leaf switches receive Type-3 routes from all other leaf switches.
4. Send broadcast traffic from Ixia port connected to Leaf-1.
5. Verify that broadcast traffic is replicated to all remote VTEPs using ingress replication.
6. Verify that Ixia ports on Leaf-2, Leaf-3, and Leaf-4 receive the broadcast traffic.

**Expected Results**

- Each leaf switch advertises Type-3 routes for its VNIs.
- All leaf switches have a complete flood list for each VNI.
- Broadcast traffic is correctly replicated to all VTEPs in the VNI.

#### Test Case 3 - VXLAN Encapsulation and Decapsulation

**Objective**

Verify correct VXLAN encapsulation on ingress VTEP and decapsulation on egress VTEP for unicast traffic.

**Test Steps**

1. Configure endpoints on Leaf-1 (source) and Leaf-3 (destination) with known MAC addresses.
2. Establish MAC learning by sending bidirectional ARP traffic.
3. Send unicast traffic from Ixia port on Leaf-1 to destination MAC on Leaf-3.
4. Capture traffic on spine switch to verify VXLAN encapsulation.
5. Verify outer IP header has correct source VTEP (Leaf-1) and destination VTEP (Leaf-3) addresses.
6. Verify VXLAN header contains correct VNI.
7. Verify traffic is received correctly on Ixia port connected to Leaf-3.

**Expected Results**

- Traffic is VXLAN encapsulated with correct outer IP addresses.
- VNI in VXLAN header matches configured VNI.
- Traffic is correctly decapsulated and delivered to destination endpoint.
- No packet loss observed.

#### Test Case 4 - Multi-Tenant VNI Isolation

**Objective**

Verify that traffic between different VNIs (tenants) is properly isolated.

**Test Steps**

1. Configure two VNIs (VNI 10000 and VNI 20000) on all leaf switches.
2. Configure Ixia ports on Leaf-1 and Leaf-2 in VNI 10000.
3. Configure Ixia ports on Leaf-3 and Leaf-4 in VNI 20000.
4. Send traffic between endpoints in VNI 10000 and verify connectivity.
5. Send traffic between endpoints in VNI 20000 and verify connectivity.
6. Attempt to send traffic from VNI 10000 endpoint to VNI 20000 endpoint.
7. Verify that cross-VNI traffic is dropped (without inter-VNI routing configured).

**Expected Results**

- Traffic within VNI 10000 is forwarded correctly.
- Traffic within VNI 20000 is forwarded correctly.
- Traffic between VNI 10000 and VNI 20000 is dropped.
- MAC tables are isolated per VNI.

### Single Homing Tests

This section covers test cases for single-homed endpoint scenarios where endpoints (hosts/VMs) are connected to only one leaf switch.

#### Test Case 5 - Single-Homed Endpoint MAC Learning

**Objective**

Verify that MAC addresses from single-homed endpoints are correctly learned and advertised in EVPN.

**Test Steps**

1. Configure a single-homed endpoint (Ixia port) connected to Leaf-1 with MAC address 00:AA:BB:CC:DD:01.
2. Configure the endpoint in VLAN 100 mapped to VNI 10000.
3. Send traffic from the single-homed endpoint to trigger MAC learning.
4. Verify that Leaf-1 learns the MAC address in its local bridge domain.
5. Verify that Leaf-1 advertises an EVPN Type-2 route for the MAC with:
   - Correct Route Distinguisher (RD)
   - Correct Route Target (RT)
   - Correct VNI (10000)
   - ESI set to 0 (indicating single-homed)
6. Verify that all remote leaf switches receive and install the MAC entry.
7. Verify that the MAC entry on remote leaf switches points to Leaf-1's VTEP IP.

**Expected Results**

- MAC address is learned locally on Leaf-1.
- EVPN Type-2 route is advertised with ESI=0 (single-homed indicator).
- All remote leaf switches install the MAC with correct VTEP next-hop.
- MAC aging timer is set correctly on the local leaf switch.

#### Test Case 6 - Single-Homed Endpoint ARP/ND Resolution

**Objective**

Verify that ARP (IPv4) and Neighbor Discovery (IPv6) resolution works correctly for single-homed endpoints across the VXLAN fabric.

**Test Steps**

1. Configure single-homed endpoint on Leaf-1 with IP 10.1.1.10/24 and MAC 00:AA:BB:CC:DD:01.
2. Configure single-homed endpoint on Leaf-3 with IP 10.1.1.20/24 and MAC 00:AA:BB:CC:DD:02.
3. Both endpoints are in the same VNI 10000.
4. Send ARP request from endpoint on Leaf-1 for IP 10.1.1.20.
5. Verify ARP request is VXLAN encapsulated and flooded to all VTEPs.
6. Verify endpoint on Leaf-3 receives the ARP request and sends ARP reply.
7. Verify ARP reply is VXLAN encapsulated and sent unicast to Leaf-1's VTEP.
8. Verify endpoint on Leaf-1 receives the ARP reply.
9. Repeat steps 4-8 for IPv6 Neighbor Discovery (NS/NA).

**Expected Results**

- ARP request is correctly flooded via VXLAN to all VTEPs in the VNI.
- ARP reply is correctly unicast via VXLAN to the requesting VTEP.
- Both endpoints learn each other's MAC-IP binding.
- EVPN Type-2 routes with IP information are advertised.
- IPv6 ND works similarly with NS/NA messages.

#### Test Case 7 - Single-Homed Endpoint Traffic Forwarding

**Objective**

Verify that unicast traffic between single-homed endpoints on different leaf switches is correctly forwarded through the VXLAN fabric.

**Test Steps**

1. Configure single-homed endpoints on Leaf-1, Leaf-2, Leaf-3, and Leaf-4.
2. All endpoints are in the same VNI 10000 with IP addresses in 10.1.1.0/24 subnet.
3. Establish ARP entries between all endpoints.
4. Send unicast traffic from endpoint on Leaf-1 to endpoint on Leaf-3 at 10 Gbps.
5. Verify traffic is VXLAN encapsulated on Leaf-1.
6. Verify traffic traverses spine switches with ECMP load balancing.
7. Verify traffic is VXLAN decapsulated on Leaf-3.
8. Measure packet loss, latency, and jitter using Ixia statistics.
9. Repeat for traffic between all endpoint pairs.

**Expected Results**

- Unicast traffic is correctly forwarded between all endpoint pairs.
- ECMP load balancing distributes traffic across multiple spine switches.
- Packet loss is 0% under normal conditions.
- Latency is within acceptable bounds (< 1ms for fabric traversal).

#### Test Case 8 - Single-Homed Endpoint Leaf Switch Failure

**Objective**

Verify the behavior when a leaf switch with single-homed endpoints fails, and validate that traffic to those endpoints is correctly blackholed until the switch recovers.

**Test Steps**

1. Configure single-homed endpoint on Leaf-1 with MAC 00:AA:BB:CC:DD:01 in VNI 10000.
2. Verify EVPN Type-2 route is advertised and installed on all remote leaf switches.
3. Send continuous traffic from endpoint on Leaf-3 to endpoint on Leaf-1.
4. Verify traffic is being received correctly on Leaf-1's endpoint.
5. Simulate Leaf-1 failure by shutting down all interfaces or rebooting the switch.
6. Verify that BGP sessions to Leaf-1 go down.
7. Verify that EVPN Type-2 routes from Leaf-1 are withdrawn.
8. Verify that remote leaf switches remove MAC entries pointing to Leaf-1's VTEP.
9. Verify that traffic destined to Leaf-1's endpoint is dropped (no valid path).
10. Recover Leaf-1 and verify that EVPN routes are re-advertised.
11. Verify that traffic forwarding resumes after recovery.

**Expected Results**

- EVPN routes are withdrawn within BGP hold timer (default 90s, or faster with BFD).
- Remote leaf switches remove stale MAC entries.
- Traffic to failed leaf's endpoints is dropped (expected behavior for single-homing).
- After recovery, EVPN routes are re-advertised and traffic resumes.
- Convergence time is measured and reported.

#### Test Case 9 - Single-Homed Endpoint VLAN to VNI Mapping

**Objective**

Verify that VLAN to VNI mapping works correctly for single-homed endpoints with multiple VLANs.

**Test Steps**

1. Configure single-homed endpoint on Leaf-1 with access to VLAN 100, 200, and 300.
2. Configure VLAN to VNI mapping: VLAN 100 -> VNI 10000, VLAN 200 -> VNI 20000, VLAN 300 -> VNI 30000.
3. Configure corresponding endpoints on Leaf-3 with the same VLAN configuration.
4. Send traffic from Leaf-1 endpoint in VLAN 100 to Leaf-3 endpoint in VLAN 100.
5. Verify traffic is encapsulated with VNI 10000.
6. Repeat for VLAN 200 (VNI 20000) and VLAN 300 (VNI 30000).
7. Verify that traffic in different VLANs uses the correct VNI.
8. Verify that EVPN Type-2 routes are advertised with correct VNI for each VLAN.

**Expected Results**

- Each VLAN is correctly mapped to its corresponding VNI.
- Traffic in each VLAN is encapsulated with the correct VNI.
- EVPN routes contain correct VNI information.
- Traffic isolation between VNIs is maintained.

#### Test Case 10 - Single-Homed Endpoint Inter-VNI Routing

**Objective**

Verify that Layer 3 routing between different VNIs works correctly for single-homed endpoints using EVPN Type-5 routes or symmetric IRB.

**Test Steps**

1. Configure single-homed endpoint on Leaf-1 in VNI 10000 with IP 10.1.1.10/24.
2. Configure single-homed endpoint on Leaf-3 in VNI 20000 with IP 10.2.2.20/24.
3. Configure Layer 3 VNI (L3VNI) for inter-VNI routing on all leaf switches.
4. Configure anycast gateway on all leaf switches for both subnets.
5. Send traffic from endpoint in VNI 10000 (10.1.1.10) to endpoint in VNI 20000 (10.2.2.20).
6. Verify that traffic is routed at the ingress leaf (Leaf-1).
7. Verify that traffic is encapsulated with L3VNI for fabric transport.
8. Verify that traffic is correctly delivered to the destination endpoint.
9. Verify bidirectional traffic flow.

**Expected Results**

- Inter-VNI routing is performed at the ingress leaf switch.
- Traffic is encapsulated with L3VNI for fabric transport.
- Destination endpoint receives traffic correctly.
- EVPN Type-5 routes (if used) are correctly advertised and installed.
- Symmetric IRB (if used) correctly handles routing and encapsulation.

#### Test Case 11 - Single-Homed Endpoint BUM Traffic Handling

**Objective**

Verify that Broadcast, Unknown unicast, and Multicast (BUM) traffic from single-homed endpoints is correctly handled using ingress replication.

**Test Steps**

1. Configure single-homed endpoints on all four leaf switches in VNI 10000.
2. Verify EVPN Type-3 routes are exchanged and flood lists are complete.
3. Send broadcast traffic (e.g., ARP request) from endpoint on Leaf-1.
4. Verify broadcast is replicated to all remote VTEPs (Leaf-2, Leaf-3, Leaf-4).
5. Verify all endpoints receive the broadcast traffic.
6. Send unknown unicast traffic (destination MAC not in table) from Leaf-1.
7. Verify unknown unicast is flooded to all VTEPs.
8. Send multicast traffic from endpoint on Leaf-1.
9. Verify multicast is replicated to all VTEPs (assuming no multicast optimization).
10. Measure replication efficiency and latency.

**Expected Results**

- Broadcast traffic is replicated to all VTEPs in the VNI.
- Unknown unicast traffic is flooded to all VTEPs.
- Multicast traffic is replicated to all VTEPs.
- No traffic loops occur.
- Ingress replication list matches EVPN Type-3 route information.

#### Test Case 12 - Single-Homed Endpoint MAC Move Detection

**Objective**

Verify that MAC move (endpoint migration) is correctly detected and handled when a single-homed endpoint moves from one leaf switch to another.

**Test Steps**

1. Configure single-homed endpoint on Leaf-1 with MAC 00:AA:BB:CC:DD:01 in VNI 10000.
2. Verify EVPN Type-2 route is advertised from Leaf-1.
3. Verify all remote leaf switches have MAC entry pointing to Leaf-1's VTEP.
4. Simulate endpoint move by disconnecting from Leaf-1 and connecting to Leaf-3.
5. Send traffic from the moved endpoint to trigger MAC learning on Leaf-3.
6. Verify Leaf-3 learns the MAC and advertises a new EVPN Type-2 route.
7. Verify Leaf-1 withdraws its EVPN Type-2 route for the MAC (after aging or explicit withdrawal).
8. Verify all remote leaf switches update their MAC entries to point to Leaf-3's VTEP.
9. Verify traffic to the endpoint is now forwarded to Leaf-3.
10. Measure MAC move convergence time.

**Expected Results**

- New leaf switch (Leaf-3) learns and advertises the MAC.
- Old leaf switch (Leaf-1) withdraws the MAC route.
- Remote leaf switches update MAC entries to new VTEP.
- Traffic is correctly forwarded to the new location.
- MAC move is detected and logged.
- Convergence time is within acceptable bounds.

### High Availability Tests

#### Test Case 13 - Spine Switch Redundancy

**Objective**

Verify that the EVPN-VXLAN fabric maintains connectivity when one or more spine switches fail.

**Test Steps**

1. Verify full connectivity between all endpoints across the fabric.
2. Send continuous traffic between endpoints on Leaf-1 and Leaf-3 at 40 Gbps.
3. Verify traffic is load balanced across all four spine switches.
4. Shut down Spine-1.
5. Verify traffic reconverges to remaining spine switches.
6. Measure traffic loss during failover.
7. Shut down Spine-2.
8. Verify traffic continues with two remaining spine switches.
9. Restore Spine-1 and Spine-2.
10. Verify traffic is rebalanced across all spine switches.

**Expected Results**

- Traffic continues with reduced spine capacity.
- ECMP reconvergence occurs within expected time (< 50ms with BFD).
- Traffic loss during failover is minimal.
- Full capacity is restored when spine switches recover.

#### Test Case 14 - BFD-Based Fast Failover

**Objective**

Verify that BFD provides fast failure detection and triggers rapid ECMP reconvergence.

**Test Steps**

1. Configure BFD on all spine-leaf links with aggressive timers (e.g., 100ms x 3).
2. Send continuous traffic between endpoints on Leaf-1 and Leaf-3.
3. Simulate link failure between Leaf-1 and Spine-1.
4. Verify BFD detects the failure within configured detection time.
5. Verify ECMP path is removed and traffic shifts to remaining paths.
6. Measure total traffic disruption time.
7. Restore the link and verify BFD session re-establishes.
8. Verify ECMP path is restored.

**Expected Results**

- BFD detects failure within 300ms (100ms x 3).
- ECMP reconvergence occurs immediately after BFD failure detection.
- Total traffic disruption is < 500ms.
- BFD session re-establishes after link recovery.

#### Test Case 15 - ECMP Path Failover

**Objective**

Verify that ECMP correctly handles path failures and maintains traffic distribution.

**Test Steps**

1. Verify ECMP is distributing traffic across all available paths.
2. Send traffic with varying 5-tuple to ensure hash distribution.
3. Measure traffic distribution across spine switches.
4. Fail one ECMP path (e.g., Leaf-1 to Spine-1 link).
5. Verify traffic redistributes to remaining paths.
6. Verify no traffic is sent to failed path.
7. Restore the path and verify traffic rebalances.

**Expected Results**

- Traffic is evenly distributed across ECMP paths.
- Failed path is removed from ECMP group.
- Traffic redistributes to remaining paths.
- Restored path is added back to ECMP group.

### Scale Testing

#### Test Case 16 - MAC Address Scale

**Objective**

Verify the system can handle a large number of MAC addresses in the EVPN-VXLAN fabric.

**Test Steps**

1. Configure VNI 10000 on all leaf switches.
2. Incrementally add MAC addresses from Ixia ports (1K, 10K, 50K, 100K).
3. Verify all MAC addresses are learned and advertised in EVPN.
4. Verify all remote leaf switches install the MAC entries.
5. Send traffic to random destination MACs and verify forwarding.
6. Measure control plane convergence time at each scale point.
7. Measure memory utilization on leaf switches.

**Expected Results**

- System supports at least 100K MAC addresses per leaf switch.
- EVPN route distribution completes within acceptable time.
- Traffic forwarding works correctly at scale.
- Memory utilization remains within acceptable limits.

#### Test Case 17 - VNI Scale

**Objective**

Verify the system can handle a large number of VNIs.

**Test Steps**

1. Incrementally configure VNIs (100, 500, 1000, 2000, 4000).
2. Configure at least one endpoint per VNI.
3. Verify EVPN Type-2 and Type-3 routes are advertised for all VNIs.
4. Verify traffic forwarding works in each VNI.
5. Measure control plane convergence time at each scale point.
6. Measure memory and CPU utilization.

**Expected Results**

- System supports at least 4000 VNIs.
- EVPN routes are correctly advertised for all VNIs.
- Traffic forwarding works in all VNIs.
- Resource utilization remains within acceptable limits.

#### Test Case 18 - VTEP Scale

**Objective**

Verify the system can handle a large number of remote VTEPs.

**Test Steps**

1. Configure additional leaf switches or simulate VTEPs using Ixia.
2. Incrementally add VTEPs (4, 8, 16, 32, 64).
3. Verify EVPN sessions are established with all VTEPs.
4. Verify flood lists include all VTEPs.
5. Send BUM traffic and verify replication to all VTEPs.
6. Measure ingress replication performance.

**Expected Results**

- System supports at least 64 VTEPs.
- EVPN sessions are stable with all VTEPs.
- BUM traffic is replicated to all VTEPs.
- Ingress replication performance is acceptable.

### Multi-Encapsulation Tests

#### Test Case 19 - IPv4-in-IPv4 VXLAN Encapsulation

**Objective**

Verify VXLAN encapsulation with IPv4 outer header and IPv4 inner payload.

**Test Steps**

1. Configure VXLAN with IPv4 VTEP addresses.
2. Send IPv4 traffic between endpoints.
3. Capture encapsulated traffic on spine switch.
4. Verify outer header is IPv4 with correct VTEP addresses.
5. Verify inner payload is IPv4.
6. Verify traffic is correctly decapsulated at egress VTEP.

**Expected Results**

- Outer header is IPv4 with correct source and destination VTEP IPs.
- Inner payload is preserved correctly.
- Traffic is delivered without errors.

#### Test Case 20 - IPv4-in-IPv6 VXLAN Encapsulation

**Objective**

Verify VXLAN encapsulation with IPv6 outer header and IPv4 inner payload.

**Test Steps**

1. Configure VXLAN with IPv6 VTEP addresses.
2. Send IPv4 traffic between endpoints.
3. Capture encapsulated traffic on spine switch.
4. Verify outer header is IPv6 with correct VTEP addresses.
5. Verify inner payload is IPv4.
6. Verify traffic is correctly decapsulated at egress VTEP.

**Expected Results**

- Outer header is IPv6 with correct source and destination VTEP IPs.
- Inner IPv4 payload is preserved correctly.
- Traffic is delivered without errors.

#### Test Case 21 - IPv6-in-IPv4 VXLAN Encapsulation

**Objective**

Verify VXLAN encapsulation with IPv4 outer header and IPv6 inner payload.

**Test Steps**

1. Configure VXLAN with IPv4 VTEP addresses.
2. Send IPv6 traffic between endpoints.
3. Capture encapsulated traffic on spine switch.
4. Verify outer header is IPv4 with correct VTEP addresses.
5. Verify inner payload is IPv6.
6. Verify traffic is correctly decapsulated at egress VTEP.

**Expected Results**

- Outer header is IPv4 with correct source and destination VTEP IPs.
- Inner IPv6 payload is preserved correctly.
- Traffic is delivered without errors.

#### Test Case 22 - IPv6-in-IPv6 VXLAN Encapsulation

**Objective**

Verify VXLAN encapsulation with IPv6 outer header and IPv6 inner payload.

**Test Steps**

1. Configure VXLAN with IPv6 VTEP addresses.
2. Send IPv6 traffic between endpoints.
3. Capture encapsulated traffic on spine switch.
4. Verify outer header is IPv6 with correct VTEP addresses.
5. Verify inner payload is IPv6.
6. Verify traffic is correctly decapsulated at egress VTEP.

**Expected Results**

- Outer header is IPv6 with correct source and destination VTEP IPs.
- Inner IPv6 payload is preserved correctly.
- Traffic is delivered without errors.

## Test Infrastructure

The tests leverage the following sonic-mgmt infrastructure:

1. **Ecmp_Utils Class** (`tests/common/vxlan_ecmp_utils.py`): Provides utilities for VXLAN ECMP testing, including route configuration and verification.

2. **PTF Test Framework**: Used for packet-level testing and verification of VXLAN encapsulation/decapsulation.

3. **Keysight Ixia IxNetwork API**: Used for traffic generation, endpoint simulation, and traffic statistics collection.

4. **Ansible Playbooks**: Used for testbed configuration and device management.

5. **pytest Fixtures**: Standard sonic-mgmt fixtures for DUT access, topology information, and test setup/teardown.

## References

- [RFC 7348 - Virtual eXtensible Local Area Network (VXLAN)](https://tools.ietf.org/html/rfc7348)
- [RFC 8365 - A Network Virtualization Overlay Solution Using EVPN](https://tools.ietf.org/html/rfc8365)
- [RFC 7432 - BGP MPLS-Based Ethernet VPN](https://tools.ietf.org/html/rfc7432)
- [SONiC VXLAN HLD](https://github.com/sonic-net/SONiC/blob/master/doc/vxlan/Vxlan_hld.md)
- [SONiC EVPN HLD](https://github.com/sonic-net/SONiC/blob/master/doc/vxlan/EVPN/EVPN_VXLAN_HLD.md)

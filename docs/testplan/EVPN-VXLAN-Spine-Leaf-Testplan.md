# EVPN-VXLAN Test Plan for 4x4 Spine-Leaf Topology

- [Overview](#overview)
  - [Scope](#scope)
  - [Testbed](#testbed)
- [Topology](#topology)
  - [4x4 Spine-Leaf Architecture](#4x4-spine-leaf-architecture)
  - [Single Homing Topology](#single-homing-topology)
  - [Multi-Homing Topology](#multi-homing-topology)
  - [Hardware Configuration](#hardware-configuration)
- [Setup Configuration](#setup-configuration)
  - [eBGP EVPN Configuration](#ebgp-evpn-configuration)
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
  - [Multi-Homing Tests](#multi-homing-tests)
    - [Test Case 13 - EVPN-MH ESI Configuration and Type-1 Route Advertisement](#test-case-13---evpn-mh-esi-configuration-and-type-1-route-advertisement)
    - [Test Case 14 - EVPN-MH Type-4 Ethernet Segment Route](#test-case-14---evpn-mh-type-4-ethernet-segment-route)
    - [Test Case 15 - Multi-Homed Endpoint Active-Active Load Balancing](#test-case-15---multi-homed-endpoint-active-active-load-balancing)
    - [Test Case 16 - Multi-Homed Endpoint Single Leaf Failure](#test-case-16---multi-homed-endpoint-single-leaf-failure)
    - [Test Case 17 - Multi-Homed Endpoint All-Active Forwarding](#test-case-17---multi-homed-endpoint-all-active-forwarding)
    - [Test Case 18 - Multi-Homed Endpoint Split-Horizon Filtering](#test-case-18---multi-homed-endpoint-split-horizon-filtering)
    - [Test Case 19 - Multi-Homed Endpoint Designated Forwarder Election](#test-case-19---multi-homed-endpoint-designated-forwarder-election)
    - [Test Case 20 - Multi-Homed Endpoint MAC Synchronization](#test-case-20---multi-homed-endpoint-mac-synchronization)
    - [Test Case 21 - Multi-Homed Endpoint Fast Failover with BFD](#test-case-21---multi-homed-endpoint-fast-failover-with-bfd)
    - [Test Case 22 - Multi-Homed Endpoint LAG Member Link Failure](#test-case-22---multi-homed-endpoint-lag-member-link-failure)
  - [High Availability Tests](#high-availability-tests)
    - [Test Case 23 - Spine Switch Redundancy](#test-case-23---spine-switch-redundancy)
    - [Test Case 24 - BFD-Based Fast Failover](#test-case-24---bfd-based-fast-failover)
    - [Test Case 25 - ECMP Path Failover](#test-case-25---ecmp-path-failover)
  - [Scale Testing](#scale-testing)
    - [Test Case 26 - MAC Address Scale](#test-case-26---mac-address-scale)
    - [Test Case 27 - VNI Scale](#test-case-27---vni-scale)
    - [Test Case 28 - VTEP Scale](#test-case-28---vtep-scale)
  - [Multi-Encapsulation Tests](#multi-encapsulation-tests)
    - [Test Case 29 - IPv4-in-IPv4 VXLAN Encapsulation](#test-case-29---ipv4-in-ipv4-vxlan-encapsulation)
    - [Test Case 30 - IPv4-in-IPv6 VXLAN Encapsulation](#test-case-30---ipv4-in-ipv6-vxlan-encapsulation)
    - [Test Case 31 - IPv6-in-IPv4 VXLAN Encapsulation](#test-case-31---ipv6-in-ipv4-vxlan-encapsulation)
    - [Test Case 32 - IPv6-in-IPv6 VXLAN Encapsulation](#test-case-32---ipv6-in-ipv6-vxlan-encapsulation)
- [Test Infrastructure](#test-infrastructure)
- [References](#references)

## Overview

This test plan validates EVPN-VXLAN functionality in a 4x4 spine-leaf topology using SONiC network operating system. The tests cover basic EVPN-VXLAN operations, single-homing scenarios, multi-homing (EVPN-MH) scenarios, high availability, scale testing, and multi-encapsulation support.

### Scope

These tests are targeted on a fully functioning SONiC system deployed in a 4x4 spine-leaf topology. The purpose of these tests is to validate EVPN-VXLAN control plane and data plane functionality, including:

- EVPN Type-1 (Ethernet Auto-Discovery) routes for multi-homing
- EVPN Type-2 (MAC/IP Advertisement) routes
- EVPN Type-3 (Inclusive Multicast Ethernet Tag) routes
- EVPN Type-4 (Ethernet Segment) routes for multi-homing
- VXLAN encapsulation/decapsulation
- Single-homed and multi-homed endpoint behavior
- BFD-based fast failover
- Multi-tenant VNI isolation
- Spine switch redundancy
- eBGP EVPN sessions between leaf switches via spine nodes

### Testbed

The tests will run on the following testbed configuration:

- 4 Spine switches (Cisco-8101-32FH-O)
- 4 Leaf switches (Cisco-8101-32FH-O)
- Keysight Ixia chassis with IxNetwork API for traffic generation
- Full mesh connectivity between spine and leaf layers
- eBGP underlay and overlay routing

## Topology

### 4x4 Spine-Leaf Architecture

The base topology consists of 4 spine switches and 4 leaf switches in a full mesh configuration. Each leaf switch connects to all four spine switches. The topology uses eBGP for both underlay (IPv4/IPv6 reachability) and overlay (EVPN) routing, with EVPN routes exchanged between leaf switches via spine nodes.

```
                         eBGP Underlay + eBGP EVPN Overlay
                    +----------+  +----------+  +----------+  +----------+
                    | Spine-1  |  | Spine-2  |  | Spine-3  |  | Spine-4  |
                    | AS 65100 |  | AS 65100 |  | AS 65100 |  | AS 65100 |
                    +----+-----+  +----+-----+  +----+-----+  +----+-----+
                         |             |             |             |
         +---------------+-------------+-------------+-------------+---------------+
         |               |             |             |             |               |
    +----+-----+    +----+-----+  +----+-----+  +----+-----+
    | Leaf-1   |    | Leaf-2   |  | Leaf-3   |  | Leaf-4   |
    | AS 65001 |    | AS 65002 |  | AS 65003 |  | AS 65004 |
    | VTEP-1   |    | VTEP-2   |  | VTEP-3   |  | VTEP-4   |
    +----+-----+    +----+-----+  +----+-----+  +----+-----+
         |               |             |             |
    Endpoints       Endpoints    Endpoints      Endpoints

    eBGP EVPN Route Flow:
    Leaf-1 (AS 65001) <--eBGP--> Spine (AS 65100) <--eBGP--> Leaf-3 (AS 65003)
    
    - Each leaf has unique AS number (65001-65004)
    - All spines share same AS number (65100)
    - EVPN routes transit through spine switches
    - No route reflectors needed - pure eBGP design
```

### Single Homing Topology

In single-homing scenarios, each endpoint connects to only one leaf switch. This provides simplicity but no redundancy at the leaf layer.

```
                    +----------+  +----------+  +----------+  +----------+
                    | Spine-1  |  | Spine-2  |  | Spine-3  |  | Spine-4  |
                    | AS 65100 |  | AS 65100 |  | AS 65100 |  | AS 65100 |
                    +----+-----+  +----+-----+  +----+-----+  +----+-----+
                         |             |             |             |
         +---------------+-------------+-------------+-------------+
         |               |             |             |
    +----+-----+    +----+-----+  +----+-----+  +----+-----+
    | Leaf-1   |    | Leaf-2   |  | Leaf-3   |  | Leaf-4   |
    | AS 65001 |    | AS 65002 |  | AS 65003 |  | AS 65004 |
    | VTEP-1   |    | VTEP-2   |  | VTEP-3   |  | VTEP-4   |
    +----+-----+    +----+-----+  +----+-----+  +----+-----+
         |               |             |             |
         |               |             |             |
    +----+-----+    +----+-----+  +----+-----+  +----+-----+
    | Host-1   |    | Host-2   |  | Host-3   |  | Host-4   |
    | (Ixia)   |    | (Ixia)   |  | (Ixia)   |  | (Ixia)   |
    | ESI=0    |    | ESI=0    |  | ESI=0    |  | ESI=0    |
    +----------+    +----------+  +----------+  +----------+

    Single-Homed Endpoints:
    - Each host connects to exactly one leaf switch
    - ESI (Ethernet Segment Identifier) = 0 indicates single-homing
    - No redundancy at leaf layer - leaf failure causes endpoint isolation
    - Simpler configuration but less resilient
    - EVPN Type-2 routes advertised via eBGP through spine switches
```

### Multi-Homing Topology

In multi-homing (EVPN-MH) scenarios, endpoints connect to multiple leaf switches via LAG (Link Aggregation Group) for redundancy and load balancing. This topology uses EVPN Type-1 and Type-4 routes for Ethernet Segment coordination, exchanged via eBGP through spine switches.

```
                    +----------+  +----------+  +----------+  +----------+
                    | Spine-1  |  | Spine-2  |  | Spine-3  |  | Spine-4  |
                    | AS 65100 |  | AS 65100 |  | AS 65100 |  | AS 65100 |
                    +----+-----+  +----+-----+  +----+-----+  +----+-----+
                         |             |             |             |
         +---------------+-------------+-------------+-------------+
         |               |             |             |
    +----+-----+    +----+-----+  +----+-----+  +----+-----+
    | Leaf-1   |    | Leaf-2   |  | Leaf-3   |  | Leaf-4   |
    | AS 65001 |    | AS 65002 |  | AS 65003 |  | AS 65004 |
    | VTEP-1   |    | VTEP-2   |  | VTEP-3   |  | VTEP-4   |
    +----+--+--+    +--+--+----+  +----+--+--+  +--+--+----+
         |  |         |  |            |  |        |  |
         |  |         |  |            |  |        |  |
         |  +---------+  |            |  +--------+  |
         |    ES-1       |            |    ES-2      |
         |   (LAG)       |            |   (LAG)      |
         |               |            |              |
    +----+---------------+----+  +----+--------------+----+
    |      Host-1 (MH)        |  |      Host-2 (MH)       |
    |        (Ixia)           |  |        (Ixia)          |
    | ESI: 00:11:22:33:44:55: |  | ESI: 00:11:22:33:44:66:|
    |       00:00:01          |  |       00:00:02         |
    +-------------------------+  +------------------------+

    Multi-Homed Endpoints:
    - Host-1 dual-homed to Leaf-1 and Leaf-2 via ES-1 (Ethernet Segment 1)
    - Host-2 dual-homed to Leaf-3 and Leaf-4 via ES-2 (Ethernet Segment 2)
    - Non-zero ESI identifies the Ethernet Segment
    - EVPN Type-1 (EAD) routes advertise ES membership via eBGP
    - EVPN Type-4 (ES) routes elect Designated Forwarder via eBGP
    - All-Active mode: both leaf switches forward traffic
    - Split-horizon filtering prevents BUM traffic loops
```

**Multi-Homing Key Concepts:**

| Concept | Description |
|---------|-------------|
| Ethernet Segment (ES) | Logical grouping of links from a multi-homed endpoint to multiple PEs |
| ESI (ES Identifier) | 10-byte identifier uniquely identifying an Ethernet Segment |
| Type-1 EAD Route | Ethernet Auto-Discovery route for fast convergence and aliasing |
| Type-4 ES Route | Ethernet Segment route for DF election among PEs |
| Designated Forwarder (DF) | PE responsible for forwarding BUM traffic to the ES |
| All-Active Mode | All PEs in ES can forward unicast traffic |
| Split-Horizon | Prevents BUM traffic from being sent back to the originating ES |

### Hardware Configuration

| Component | Model | Interfaces | Role |
|-----------|-------|------------|------|
| Spine Switches | Cisco-8101-32FH-O | 32x400G | eBGP underlay and EVPN overlay transit |
| Leaf Switches | Cisco-8101-32FH-O | 32x400G | VXLAN VTEP, endpoint connectivity, EVPN-MH |
| Traffic Generator | Keysight Ixia | Multiple 400G ports | Endpoint simulation, traffic generation, LAG support |

## Setup Configuration

The following configuration elements are required for the EVPN-VXLAN testbed:

### eBGP EVPN Configuration

This topology uses eBGP for both underlay (IPv4/IPv6 reachability) and overlay (EVPN) routing. EVPN routes are exchanged between leaf switches via spine nodes using eBGP peering. This design eliminates the need for route reflectors and provides a simpler, more scalable architecture.

**eBGP Design Principles:**

1. **Unique AS per Leaf**: Each leaf switch has a unique AS number (65001-65004)
2. **Shared AS for Spines**: All spine switches share the same AS number (65100)
3. **eBGP for Underlay**: IPv4/IPv6 routes exchanged via eBGP between leaf and spine
4. **eBGP for EVPN Overlay**: EVPN routes (Type-1 through Type-5) exchanged via eBGP
5. **No Route Reflectors**: Pure eBGP design without iBGP or route reflectors
6. **BGP Unnumbered**: Interface-based peering using IPv6 link-local addresses

**Spine Switch Configuration (Example for Spine-1, AS 65100):**

```
router bgp 65100
  bgp router-id 10.0.0.1
  bgp bestpath as-path multipath-relax
  neighbor LEAF_GROUP peer-group
  neighbor LEAF_GROUP remote-as external
  neighbor LEAF_GROUP capability extended-nexthop
  neighbor LEAF_GROUP ebgp-multihop 2
  neighbor Ethernet0 interface peer-group LEAF_GROUP
  neighbor Ethernet1 interface peer-group LEAF_GROUP
  neighbor Ethernet2 interface peer-group LEAF_GROUP
  neighbor Ethernet3 interface peer-group LEAF_GROUP
  address-family ipv4 unicast
    redistribute connected
    neighbor LEAF_GROUP activate
  address-family l2vpn evpn
    neighbor LEAF_GROUP activate
```

**Leaf Switch Configuration (Example for Leaf-1, AS 65001):**

```
router bgp 65001
  bgp router-id 10.0.1.1
  bgp bestpath as-path multipath-relax
  neighbor SPINE_GROUP peer-group
  neighbor SPINE_GROUP remote-as external
  neighbor SPINE_GROUP capability extended-nexthop
  neighbor SPINE_GROUP ebgp-multihop 2
  neighbor Ethernet0 interface peer-group SPINE_GROUP
  neighbor Ethernet1 interface peer-group SPINE_GROUP
  neighbor Ethernet2 interface peer-group SPINE_GROUP
  neighbor Ethernet3 interface peer-group SPINE_GROUP
  address-family ipv4 unicast
    redistribute connected
    neighbor SPINE_GROUP activate
    maximum-paths 4
  address-family l2vpn evpn
    neighbor SPINE_GROUP activate
    advertise-all-vni
```

**Key eBGP EVPN Features:**

1. **Interface-based Peering**: BGP sessions established using interface names instead of IP addresses (BGP unnumbered)
2. **Extended Next-Hop**: Enables IPv4 EVPN routes to be advertised with IPv6 next-hops
3. **AS Path Multipath Relax**: Allows ECMP across paths with different AS paths (required for leaf-spine-leaf paths)
4. **eBGP Multihop**: Required for EVPN routes that traverse spine switches
5. **No Route Reflectors**: Spines simply forward EVPN routes between leaves via standard eBGP
6. **Automatic RT/RD**: Route targets and distinguishers auto-derived from AS number and VNI

**EVPN Route Exchange Flow:**

```
Leaf-1 (AS 65001)                    Spine-1 (AS 65100)                    Leaf-3 (AS 65003)
      |                                     |                                     |
      |  eBGP EVPN Type-2 Route             |                                     |
      |  (MAC: 00:AA:BB:CC:DD:01)           |                                     |
      | ----------------------------------> |                                     |
      |                                     |  eBGP EVPN Type-2 Route             |
      |                                     |  (AS Path: 65001 65100)             |
      |                                     | ----------------------------------> |
      |                                     |                                     |
      |                                     |                                     |
      |  AS Path at Leaf-3: 65100 65001     |                                     |
      |  Next-Hop: Leaf-1 VTEP IP           |                                     |
```

**Additional Configuration Elements:**

1. **Loopback Interfaces**
   - Each switch has a loopback interface for VTEP source IP and BGP router-id
   - Loopback IPs are advertised via eBGP for VTEP reachability

2. **EVPN Control Plane Configuration**
   - eBGP EVPN sessions between leaf switches via spine nodes
   - EVPN address family enabled on all eBGP sessions
   - Route distinguisher auto-derived from router-id and VNI
   - Route targets auto-derived from AS number and VNI

3. **VXLAN Data Plane Configuration**
   - VXLAN tunnel interfaces on leaf switches
   - VNI to VLAN mapping on leaf switches
   - VTEP source interface configuration (loopback)

4. **Multi-Homing Configuration (for EVPN-MH tests)**
   - Ethernet Segment configuration with unique ESI
   - LAG interfaces for multi-homed endpoints
   - DF election mode (default: modulo-based)
   - Type-1 and Type-4 routes exchanged via eBGP

5. **BFD Configuration**
   - BFD sessions for fast failure detection on eBGP sessions
   - BFD integration with BGP and ECMP

## Test Methodology

The following test methodology will be used for validating EVPN-VXLAN functionality:

1. **Traffic Generator Setup**: Keysight Ixia chassis with IxNetwork API will be used to simulate endpoints and generate traffic patterns. For multi-homing tests, Ixia LAG configurations will simulate dual-homed endpoints.

2. **Control Plane Validation**: EVPN route distribution will be verified using BGP show commands and route table inspection. For eBGP EVPN, verify that routes have correct AS paths (leaf-spine-leaf) and next-hops. For multi-homing, Type-1 and Type-4 routes will be validated.

3. **Data Plane Validation**: Traffic forwarding will be verified using the **spytest framework** for packet-level validation. spytest provides:
   - Packet capture and analysis capabilities
   - VXLAN header verification
   - Traffic statistics collection
   - Automated test orchestration

4. **Failure Injection**: Link failures, switch failures, and configuration changes will be injected to validate high availability and convergence behavior.

5. **Scale Testing**: Incremental scaling of MAC addresses, VNIs, VTEPs, and Ethernet Segments will be performed to validate system limits.

The tests leverage the following infrastructure:

- **spytest Framework**: Primary test framework for packet validation, traffic verification, and test automation
- **Keysight Ixia IxNetwork API**: Traffic generation and endpoint simulation
- **sonic-mgmt VXLAN utilities**: `Ecmp_Utils` class from `tests/common/vxlan_ecmp_utils.py` for ECMP testing

## Test Cases

### Basic EVPN-VXLAN Functionality Tests

#### Test Case 1 - EVPN Type-2 MAC/IP Route Distribution

**Objective**

Verify that EVPN Type-2 (MAC/IP Advertisement) routes are correctly distributed across all leaf switches via eBGP through spine nodes when a new endpoint MAC address is learned.

**Test Steps**

1. Configure EVPN-VXLAN on all leaf switches with a common VNI (e.g., VNI 10000).
2. Verify eBGP EVPN sessions are established between all leaf switches and spine switches.
3. Connect Ixia port to Leaf-1 and configure it to send traffic with source MAC 00:11:22:33:44:55.
4. Send ARP request from Ixia port to trigger MAC learning on Leaf-1.
5. Verify that Leaf-1 learns the MAC address in its local MAC table.
6. Verify that Leaf-1 generates an EVPN Type-2 route for the learned MAC.
7. Verify that spine switches receive the Type-2 route via eBGP from Leaf-1.
8. Verify that all other leaf switches (Leaf-2, Leaf-3, Leaf-4) receive the EVPN Type-2 route via eBGP from spine switches.
9. Verify that remote leaf switches install the MAC in their EVPN MAC table with the correct VTEP IP.
10. Verify the AS path on remote leaf switches shows: spine-AS, leaf-1-AS (e.g., 65100 65001).
11. Use spytest to capture and validate VXLAN-encapsulated traffic.

**Expected Results**

- Leaf-1 learns MAC 00:11:22:33:44:55 locally.
- EVPN Type-2 route is advertised via eBGP with correct RD, RT, and VNI.
- Spine switches forward the route to all other leaf switches.
- All remote leaf switches receive and install the route with AS path showing transit through spine.
- Remote MAC table entries point to Leaf-1's VTEP IP address.
- spytest validates correct VXLAN encapsulation.

#### Test Case 2 - EVPN Type-3 Inclusive Multicast Route Distribution

**Objective**

Verify that EVPN Type-3 (Inclusive Multicast Ethernet Tag) routes are correctly distributed via eBGP for BUM (Broadcast, Unknown unicast, Multicast) traffic handling.

**Test Steps**

1. Configure EVPN-VXLAN on all leaf switches with ingress replication for BUM traffic.
2. Verify that each leaf switch generates EVPN Type-3 routes for each configured VNI.
3. Verify that spine switches receive Type-3 routes from all leaf switches via eBGP.
4. Verify that all leaf switches receive Type-3 routes from all other leaf switches via eBGP through spines.
5. Send broadcast traffic from Ixia port connected to Leaf-1.
6. Use spytest to verify that broadcast traffic is replicated to all remote VTEPs using ingress replication.
7. Verify that Ixia ports on Leaf-2, Leaf-3, and Leaf-4 receive the broadcast traffic.

**Expected Results**

- Each leaf switch advertises Type-3 routes for its VNIs via eBGP.
- All leaf switches have a complete flood list for each VNI.
- Broadcast traffic is correctly replicated to all VTEPs in the VNI.
- spytest confirms correct packet replication.

#### Test Case 3 - VXLAN Encapsulation and Decapsulation

**Objective**

Verify correct VXLAN encapsulation on ingress VTEP and decapsulation on egress VTEP for unicast traffic.

**Test Steps**

1. Configure endpoints on Leaf-1 (source) and Leaf-3 (destination) with known MAC addresses.
2. Establish MAC learning by sending bidirectional ARP traffic.
3. Verify EVPN Type-2 routes are exchanged via eBGP through spine switches.
4. Send unicast traffic from Ixia port on Leaf-1 to destination MAC on Leaf-3.
5. Use spytest to capture traffic on spine switch and verify VXLAN encapsulation.
6. Verify outer IP header has correct source VTEP (Leaf-1) and destination VTEP (Leaf-3) addresses.
7. Verify VXLAN header contains correct VNI.
8. Verify traffic is received correctly on Ixia port connected to Leaf-3.

**Expected Results**

- Traffic is VXLAN encapsulated with correct outer IP addresses.
- VNI in VXLAN header matches configured VNI.
- Traffic is correctly decapsulated and delivered to destination endpoint.
- No packet loss observed.
- spytest validates all header fields.

#### Test Case 4 - Multi-Tenant VNI Isolation

**Objective**

Verify that traffic between different VNIs (tenants) is properly isolated.

**Test Steps**

1. Configure two VNIs (VNI 10000 and VNI 20000) on all leaf switches.
2. Verify EVPN Type-2 and Type-3 routes are exchanged via eBGP for both VNIs.
3. Configure Ixia ports on Leaf-1 and Leaf-2 in VNI 10000.
4. Configure Ixia ports on Leaf-3 and Leaf-4 in VNI 20000.
5. Send traffic between endpoints in VNI 10000 and verify connectivity using spytest.
6. Send traffic between endpoints in VNI 20000 and verify connectivity using spytest.
7. Attempt to send traffic from VNI 10000 endpoint to VNI 20000 endpoint.
8. Verify that cross-VNI traffic is dropped (without inter-VNI routing configured).

**Expected Results**

- Traffic within VNI 10000 is forwarded correctly.
- Traffic within VNI 20000 is forwarded correctly.
- Traffic between VNI 10000 and VNI 20000 is dropped.
- MAC tables are isolated per VNI.

### Single Homing Tests

This section covers test cases for single-homed endpoint scenarios where endpoints (hosts/VMs) are connected to only one leaf switch.

#### Test Case 5 - Single-Homed Endpoint MAC Learning

**Objective**

Verify that MAC addresses from single-homed endpoints are correctly learned and advertised in EVPN via eBGP.

**Test Steps**

1. Configure a single-homed endpoint (Ixia port) connected to Leaf-1 with MAC address 00:AA:BB:CC:DD:01.
2. Configure the endpoint in VLAN 100 mapped to VNI 10000.
3. Send traffic from the single-homed endpoint to trigger MAC learning.
4. Verify that Leaf-1 learns the MAC address in its local bridge domain.
5. Verify that Leaf-1 advertises an EVPN Type-2 route for the MAC via eBGP with:
   - Correct Route Distinguisher (RD)
   - Correct Route Target (RT)
   - Correct VNI (10000)
   - ESI set to 0 (indicating single-homed)
6. Verify that spine switches receive and forward the Type-2 route.
7. Verify that all remote leaf switches receive and install the MAC entry via eBGP.
8. Verify that the MAC entry on remote leaf switches points to Leaf-1's VTEP IP.
9. Use spytest to validate packet forwarding.

**Expected Results**

- MAC address is learned locally on Leaf-1.
- EVPN Type-2 route is advertised via eBGP with ESI=0 (single-homed indicator).
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
5. Use spytest to verify ARP request is VXLAN encapsulated and flooded to all VTEPs.
6. Verify endpoint on Leaf-3 receives the ARP request and sends ARP reply.
7. Use spytest to verify ARP reply is VXLAN encapsulated and sent unicast to Leaf-1's VTEP.
8. Verify endpoint on Leaf-1 receives the ARP reply.
9. Repeat steps 4-8 for IPv6 Neighbor Discovery (NS/NA).

**Expected Results**

- ARP request is correctly flooded via VXLAN to all VTEPs in the VNI.
- ARP reply is correctly unicast via VXLAN to the requesting VTEP.
- Both endpoints learn each other's MAC-IP binding.
- EVPN Type-2 routes with IP information are advertised via eBGP.
- IPv6 ND works similarly with NS/NA messages.

#### Test Case 7 - Single-Homed Endpoint Traffic Forwarding

**Objective**

Verify that unicast traffic between single-homed endpoints on different leaf switches is correctly forwarded through the VXLAN fabric.

**Test Steps**

1. Configure single-homed endpoints on Leaf-1, Leaf-2, Leaf-3, and Leaf-4.
2. All endpoints are in the same VNI 10000 with IP addresses in 10.1.1.0/24 subnet.
3. Establish ARP entries between all endpoints.
4. Send unicast traffic from endpoint on Leaf-1 to endpoint on Leaf-3 at 10 Gbps.
5. Use spytest to verify traffic is VXLAN encapsulated on Leaf-1.
6. Verify traffic traverses spine switches with ECMP load balancing.
7. Use spytest to verify traffic is VXLAN decapsulated on Leaf-3.
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
2. Verify EVPN Type-2 route is advertised via eBGP and installed on all remote leaf switches.
3. Send continuous traffic from endpoint on Leaf-3 to endpoint on Leaf-1.
4. Verify traffic is being received correctly on Leaf-1's endpoint.
5. Simulate Leaf-1 failure by shutting down all interfaces or rebooting the switch.
6. Verify that eBGP sessions from Leaf-1 to spine switches go down.
7. Verify that EVPN Type-2 routes from Leaf-1 are withdrawn via eBGP.
8. Verify that remote leaf switches remove MAC entries pointing to Leaf-1's VTEP.
9. Use spytest to verify that traffic destined to Leaf-1's endpoint is dropped (no valid path).
10. Recover Leaf-1 and verify that eBGP sessions re-establish.
11. Verify that EVPN routes are re-advertised and traffic forwarding resumes.

**Expected Results**

- EVPN routes are withdrawn within BGP hold timer (default 90s, or faster with BFD).
- Remote leaf switches remove stale MAC entries.
- Traffic to failed leaf's endpoints is dropped (expected behavior for single-homing).
- After recovery, EVPN routes are re-advertised via eBGP and traffic resumes.
- Convergence time is measured and reported.

#### Test Case 9 - Single-Homed Endpoint VLAN to VNI Mapping

**Objective**

Verify that VLAN to VNI mapping works correctly for single-homed endpoints with multiple VLANs.

**Test Steps**

1. Configure single-homed endpoint on Leaf-1 with access to VLAN 100, 200, and 300.
2. Configure VLAN to VNI mapping: VLAN 100 -> VNI 10000, VLAN 200 -> VNI 20000, VLAN 300 -> VNI 30000.
3. Configure corresponding endpoints on Leaf-3 with the same VLAN configuration.
4. Send traffic from Leaf-1 endpoint in VLAN 100 to Leaf-3 endpoint in VLAN 100.
5. Use spytest to verify traffic is encapsulated with VNI 10000.
6. Repeat for VLAN 200 (VNI 20000) and VLAN 300 (VNI 30000).
7. Verify that traffic in different VLANs uses the correct VNI.
8. Verify that EVPN Type-2 routes are advertised via eBGP with correct VNI for each VLAN.

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
6. Use spytest to verify that traffic is routed at the ingress leaf (Leaf-1).
7. Verify that traffic is encapsulated with L3VNI for fabric transport.
8. Verify that traffic is correctly delivered to the destination endpoint.
9. Verify bidirectional traffic flow.

**Expected Results**

- Inter-VNI routing is performed at the ingress leaf switch.
- Traffic is encapsulated with L3VNI for fabric transport.
- Destination endpoint receives traffic correctly.
- EVPN Type-5 routes (if used) are correctly advertised via eBGP and installed.
- Symmetric IRB (if used) correctly handles routing and encapsulation.

#### Test Case 11 - Single-Homed Endpoint BUM Traffic Handling

**Objective**

Verify that Broadcast, Unknown unicast, and Multicast (BUM) traffic from single-homed endpoints is correctly handled using ingress replication.

**Test Steps**

1. Configure single-homed endpoints on all four leaf switches in VNI 10000.
2. Verify EVPN Type-3 routes are exchanged via eBGP and flood lists are complete.
3. Send broadcast traffic (e.g., ARP request) from endpoint on Leaf-1.
4. Use spytest to verify broadcast is replicated to all remote VTEPs (Leaf-2, Leaf-3, Leaf-4).
5. Verify all endpoints receive the broadcast traffic.
6. Send unknown unicast traffic (destination MAC not in table) from Leaf-1.
7. Use spytest to verify unknown unicast is flooded to all VTEPs.
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
2. Verify EVPN Type-2 route is advertised via eBGP from Leaf-1.
3. Verify all remote leaf switches have MAC entry pointing to Leaf-1's VTEP.
4. Simulate endpoint move by disconnecting from Leaf-1 and connecting to Leaf-3.
5. Send traffic from the moved endpoint to trigger MAC learning on Leaf-3.
6. Verify Leaf-3 learns the MAC and advertises a new EVPN Type-2 route via eBGP.
7. Verify Leaf-1 withdraws its EVPN Type-2 route for the MAC (after aging or explicit withdrawal).
8. Verify all remote leaf switches update their MAC entries to point to Leaf-3's VTEP.
9. Use spytest to verify traffic to the endpoint is now forwarded to Leaf-3.
10. Measure MAC move convergence time.

**Expected Results**

- New leaf switch (Leaf-3) learns and advertises the MAC via eBGP.
- Old leaf switch (Leaf-1) withdraws the MAC route.
- Remote leaf switches update MAC entries to new VTEP.
- Traffic is correctly forwarded to the new location.
- MAC move is detected and logged.
- Convergence time is within acceptable bounds.

### Multi-Homing Tests

This section covers test cases for multi-homed (EVPN-MH) endpoint scenarios where endpoints connect to multiple leaf switches via LAG for redundancy and load balancing.

#### Test Case 13 - EVPN-MH ESI Configuration and Type-1 Route Advertisement

**Objective**

Verify that Ethernet Segment Identifier (ESI) is correctly configured and EVPN Type-1 (Ethernet Auto-Discovery) routes are advertised via eBGP for multi-homed endpoints.

**Test Steps**

1. Configure Ethernet Segment on Leaf-1 and Leaf-2 with ESI 00:11:22:33:44:55:00:00:01.
2. Configure LAG interface on both leaf switches for the multi-homed endpoint.
3. Connect Ixia port to both Leaf-1 and Leaf-2 via LAG.
4. Verify that both Leaf-1 and Leaf-2 advertise EVPN Type-1 EAD per-ES route via eBGP with:
   - Correct ESI
   - Correct Route Distinguisher
   - Correct Route Target
5. Verify that both leaf switches advertise EVPN Type-1 EAD per-EVI route for each VNI via eBGP.
6. Verify that spine switches receive and forward the Type-1 routes.
7. Verify that remote leaf switches (Leaf-3, Leaf-4) receive and install the Type-1 routes via eBGP.
8. Verify that remote leaf switches recognize the endpoint as multi-homed.

**Expected Results**

- ESI is correctly configured on both leaf switches.
- Type-1 EAD per-ES routes are advertised via eBGP from both Leaf-1 and Leaf-2.
- Type-1 EAD per-EVI routes are advertised for each VNI.
- Remote leaf switches install routes and recognize multi-homing.
- Aliasing is enabled for load balancing to multi-homed endpoint.

#### Test Case 14 - EVPN-MH Type-4 Ethernet Segment Route

**Objective**

Verify that EVPN Type-4 (Ethernet Segment) routes are correctly advertised via eBGP and Designated Forwarder (DF) election occurs.

**Test Steps**

1. Configure Ethernet Segment on Leaf-1 and Leaf-2 with ESI 00:11:22:33:44:55:00:00:01.
2. Verify that both Leaf-1 and Leaf-2 advertise EVPN Type-4 ES routes via eBGP with:
   - Correct ESI
   - Originating router's IP address
3. Verify that spine switches receive and forward the Type-4 routes.
4. Verify that both leaf switches receive each other's Type-4 routes via eBGP through spines.
5. Verify that DF election occurs for each VLAN/VNI:
   - Check which leaf is elected as DF
   - Verify DF election algorithm (default: modulo-based)
6. Verify that non-DF leaf does not forward BUM traffic to the ES.
7. Verify that DF leaf forwards BUM traffic to the ES.

**Expected Results**

- Type-4 ES routes are advertised via eBGP from both leaf switches.
- DF election completes successfully.
- Only DF forwards BUM traffic to avoid duplication.
- Non-DF correctly filters BUM traffic.

#### Test Case 15 - Multi-Homed Endpoint Active-Active Load Balancing

**Objective**

Verify that traffic to a multi-homed endpoint is load balanced across all member leaf switches (aliasing).

**Test Steps**

1. Configure multi-homed endpoint on Leaf-1 and Leaf-2 with ESI 00:11:22:33:44:55:00:00:01.
2. Configure endpoint with MAC 00:AA:BB:CC:DD:01 in VNI 10000.
3. Verify EVPN Type-2 route is advertised via eBGP from both Leaf-1 and Leaf-2.
4. Send traffic from endpoint on Leaf-3 to the multi-homed endpoint at high rate.
5. Use spytest to verify traffic is load balanced across both Leaf-1 and Leaf-2.
6. Measure traffic distribution ratio (should be approximately 50/50).
7. Verify no packet loss or reordering.

**Expected Results**

- Traffic is load balanced across both leaf switches.
- Distribution is approximately equal (within acceptable variance).
- No packet loss during normal operation.
- ECMP hashing provides consistent flow distribution.

#### Test Case 16 - Multi-Homed Endpoint Single Leaf Failure

**Objective**

Verify that traffic to a multi-homed endpoint continues when one of the member leaf switches fails.

**Test Steps**

1. Configure multi-homed endpoint on Leaf-1 and Leaf-2 with ESI 00:11:22:33:44:55:00:00:01.
2. Send continuous traffic from endpoint on Leaf-3 to the multi-homed endpoint.
3. Verify traffic is being received on both Leaf-1 and Leaf-2.
4. Simulate Leaf-1 failure by shutting down all interfaces.
5. Verify that Leaf-1's eBGP sessions go down and Type-1 EAD routes are withdrawn.
6. Verify that remote leaf switches update their forwarding to use only Leaf-2.
7. Use spytest to verify traffic continues to flow via Leaf-2 without loss.
8. Measure failover convergence time.
9. Recover Leaf-1 and verify traffic is rebalanced.

**Expected Results**

- Traffic continues via surviving leaf switch (Leaf-2).
- Failover convergence is fast (< 1 second with proper BFD configuration).
- Minimal packet loss during failover.
- Traffic rebalances after recovery.

#### Test Case 17 - Multi-Homed Endpoint All-Active Forwarding

**Objective**

Verify that both leaf switches in an Ethernet Segment can forward unicast traffic to the multi-homed endpoint (all-active mode).

**Test Steps**

1. Configure multi-homed endpoint on Leaf-1 and Leaf-2 in all-active mode.
2. Send unicast traffic from multiple sources (Leaf-3 and Leaf-4) to the multi-homed endpoint.
3. Use spytest to verify that traffic from Leaf-3 may arrive via either Leaf-1 or Leaf-2.
4. Verify that traffic from Leaf-4 may arrive via either Leaf-1 or Leaf-2.
5. Verify that the endpoint receives all traffic correctly regardless of ingress leaf.
6. Verify no duplicate packets are received.

**Expected Results**

- Both Leaf-1 and Leaf-2 forward unicast traffic to the endpoint.
- Traffic is correctly delivered without duplication.
- All-active mode provides optimal load distribution.

#### Test Case 18 - Multi-Homed Endpoint Split-Horizon Filtering

**Objective**

Verify that split-horizon filtering prevents BUM traffic loops in multi-homing scenarios.

**Test Steps**

1. Configure multi-homed endpoint on Leaf-1 and Leaf-2 with ESI 00:11:22:33:44:55:00:00:01.
2. Send broadcast traffic from the multi-homed endpoint.
3. Verify that Leaf-1 receives the broadcast and floods it to remote VTEPs.
4. Verify that Leaf-2 also receives the broadcast from the endpoint.
5. Use spytest to verify that Leaf-2 does NOT send the broadcast back to the ES (split-horizon).
6. Verify that remote leaf switches receive only one copy of the broadcast.
7. Verify no traffic loops occur.

**Expected Results**

- Broadcast traffic is flooded to remote VTEPs.
- Split-horizon filtering prevents traffic from being sent back to originating ES.
- No duplicate broadcasts received at remote endpoints.
- No traffic loops in the fabric.

#### Test Case 19 - Multi-Homed Endpoint Designated Forwarder Election

**Objective**

Verify that Designated Forwarder (DF) election works correctly and only the DF forwards BUM traffic to the Ethernet Segment.

**Test Steps**

1. Configure multi-homed endpoint on Leaf-1 and Leaf-2 with ESI 00:11:22:33:44:55:00:00:01.
2. Configure multiple VLANs (100, 200, 300) on the Ethernet Segment.
3. Verify DF election for each VLAN:
   - VLAN 100: Check which leaf is DF
   - VLAN 200: Check which leaf is DF
   - VLAN 300: Check which leaf is DF
4. Send broadcast traffic from remote endpoint (Leaf-3) to each VLAN.
5. Use spytest to verify that only the DF for each VLAN forwards the broadcast to the ES.
6. Verify that non-DF does not forward BUM traffic.
7. Simulate DF failure and verify DF re-election.

**Expected Results**

- DF is elected for each VLAN (may be different per VLAN for load distribution).
- Only DF forwards BUM traffic to the ES.
- Non-DF correctly filters BUM traffic.
- DF re-election occurs upon DF failure.

#### Test Case 20 - Multi-Homed Endpoint MAC Synchronization

**Objective**

Verify that MAC addresses learned on one leaf switch in an Ethernet Segment are synchronized to other leaf switches in the same ES via eBGP.

**Test Steps**

1. Configure multi-homed endpoint on Leaf-1 and Leaf-2 with ESI 00:11:22:33:44:55:00:00:01.
2. Send traffic from the multi-homed endpoint with MAC 00:AA:BB:CC:DD:01.
3. Verify that Leaf-1 learns the MAC locally (assuming traffic arrives on Leaf-1 first).
4. Verify that Leaf-1 advertises EVPN Type-2 route with the ESI via eBGP.
5. Verify that Leaf-2 receives the Type-2 route via eBGP through spines and installs the MAC as a "sync" entry.
6. Verify that Leaf-2 can forward traffic destined to the MAC via the local ES link.
7. Use spytest to verify traffic forwarding works via both leaf switches.

**Expected Results**

- MAC is learned locally on one leaf switch.
- EVPN Type-2 route with ESI is advertised via eBGP.
- Other ES members install MAC as synchronized entry.
- Traffic can be forwarded via any ES member.

#### Test Case 21 - Multi-Homed Endpoint Fast Failover with BFD

**Objective**

Verify that BFD provides fast failure detection for multi-homed endpoints and triggers rapid failover.

**Test Steps**

1. Configure multi-homed endpoint on Leaf-1 and Leaf-2.
2. Configure BFD on the ES member links with aggressive timers (e.g., 50ms x 3).
3. Send continuous traffic from Leaf-3 to the multi-homed endpoint.
4. Simulate link failure between Leaf-1 and the endpoint.
5. Verify BFD detects the failure within configured detection time (150ms).
6. Verify that Leaf-1 withdraws its Type-1 EAD routes via eBGP.
7. Use spytest to verify traffic shifts to Leaf-2.
8. Measure total traffic disruption time.
9. Restore the link and verify traffic rebalances.

**Expected Results**

- BFD detects link failure within 150ms.
- Type-1 routes are withdrawn immediately via eBGP.
- Traffic shifts to surviving path within 200ms.
- Minimal packet loss during failover.

#### Test Case 22 - Multi-Homed Endpoint LAG Member Link Failure

**Objective**

Verify correct behavior when individual LAG member links fail in a multi-homed configuration.

**Test Steps**

1. Configure multi-homed endpoint with 2-member LAG to each leaf switch (4 total links).
2. Send continuous traffic to the multi-homed endpoint.
3. Fail one LAG member link on Leaf-1.
4. Verify LAG remains operational with reduced bandwidth.
5. Verify traffic continues to flow via remaining LAG members.
6. Use spytest to verify no traffic is sent to failed link.
7. Fail second LAG member on Leaf-1 (complete LAG failure).
8. Verify traffic shifts entirely to Leaf-2.
9. Restore links and verify traffic rebalances.

**Expected Results**

- Single LAG member failure reduces bandwidth but maintains connectivity.
- Complete LAG failure triggers failover to other ES member.
- Traffic rebalances after link restoration.

### High Availability Tests

#### Test Case 23 - Spine Switch Redundancy

**Objective**

Verify that the EVPN-VXLAN fabric maintains connectivity when one or more spine switches fail.

**Test Steps**

1. Verify full connectivity between all endpoints across the fabric.
2. Verify eBGP EVPN sessions are established through all spine switches.
3. Send continuous traffic between endpoints on Leaf-1 and Leaf-3 at 40 Gbps.
4. Verify traffic is load balanced across all four spine switches.
5. Shut down Spine-1.
6. Verify eBGP sessions through Spine-1 go down.
7. Verify traffic reconverges to remaining spine switches.
8. Measure traffic loss during failover.
9. Shut down Spine-2.
10. Verify traffic continues with two remaining spine switches.
11. Restore Spine-1 and Spine-2.
12. Verify eBGP sessions re-establish and traffic is rebalanced.

**Expected Results**

- Traffic continues with reduced spine capacity.
- ECMP reconvergence occurs within expected time (< 50ms with BFD).
- Traffic loss during failover is minimal.
- Full capacity is restored when spine switches recover.

#### Test Case 24 - BFD-Based Fast Failover

**Objective**

Verify that BFD provides fast failure detection and triggers rapid ECMP reconvergence.

**Test Steps**

1. Configure BFD on all spine-leaf eBGP sessions with aggressive timers (e.g., 100ms x 3).
2. Send continuous traffic between endpoints on Leaf-1 and Leaf-3.
3. Simulate link failure between Leaf-1 and Spine-1.
4. Verify BFD detects the failure within configured detection time.
5. Verify eBGP session goes down and ECMP path is removed.
6. Verify traffic shifts to remaining paths.
7. Use spytest to measure total traffic disruption time.
8. Restore the link and verify BFD session re-establishes.
9. Verify ECMP path is restored.

**Expected Results**

- BFD detects failure within 300ms (100ms x 3).
- ECMP reconvergence occurs immediately after BFD failure detection.
- Total traffic disruption is < 500ms.
- BFD session re-establishes after link recovery.

#### Test Case 25 - ECMP Path Failover

**Objective**

Verify that ECMP correctly handles path failures and maintains traffic distribution.

**Test Steps**

1. Verify ECMP is distributing traffic across all available paths through spine switches.
2. Send traffic with varying 5-tuple to ensure hash distribution.
3. Use spytest to measure traffic distribution across spine switches.
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

#### Test Case 26 - MAC Address Scale

**Objective**

Verify the system can handle a large number of MAC addresses in the EVPN-VXLAN fabric with eBGP EVPN.

**Test Steps**

1. Configure VNI 10000 on all leaf switches.
2. Incrementally add MAC addresses from Ixia ports (1K, 10K, 50K, 100K).
3. Verify all MAC addresses are learned and advertised via eBGP EVPN.
4. Verify all remote leaf switches install the MAC entries.
5. Send traffic to random destination MACs and verify forwarding using spytest.
6. Measure control plane convergence time at each scale point.
7. Measure memory utilization on leaf switches.

**Expected Results**

- System supports at least 100K MAC addresses per leaf switch.
- EVPN route distribution via eBGP completes within acceptable time.
- Traffic forwarding works correctly at scale.
- Memory utilization remains within acceptable limits.

#### Test Case 27 - VNI Scale

**Objective**

Verify the system can handle a large number of VNIs with eBGP EVPN.

**Test Steps**

1. Incrementally configure VNIs (100, 500, 1000, 2000, 4000).
2. Configure at least one endpoint per VNI.
3. Verify EVPN Type-2 and Type-3 routes are advertised via eBGP for all VNIs.
4. Verify traffic forwarding works in each VNI using spytest.
5. Measure control plane convergence time at each scale point.
6. Measure memory and CPU utilization.

**Expected Results**

- System supports at least 4000 VNIs.
- EVPN routes are correctly advertised via eBGP for all VNIs.
- Traffic forwarding works in all VNIs.
- Resource utilization remains within acceptable limits.

#### Test Case 28 - VTEP Scale

**Objective**

Verify the system can handle a large number of remote VTEPs with eBGP EVPN.

**Test Steps**

1. Configure additional leaf switches or simulate VTEPs using Ixia.
2. Incrementally add VTEPs (4, 8, 16, 32, 64).
3. Verify eBGP EVPN sessions are established with all VTEPs via spine switches.
4. Verify flood lists include all VTEPs.
5. Send BUM traffic and verify replication to all VTEPs using spytest.
6. Measure ingress replication performance.

**Expected Results**

- System supports at least 64 VTEPs.
- eBGP EVPN sessions are stable with all VTEPs.
- BUM traffic is replicated to all VTEPs.
- Ingress replication performance is acceptable.

### Multi-Encapsulation Tests

#### Test Case 29 - IPv4-in-IPv4 VXLAN Encapsulation

**Objective**

Verify VXLAN encapsulation with IPv4 outer header and IPv4 inner payload.

**Test Steps**

1. Configure VXLAN with IPv4 VTEP addresses.
2. Send IPv4 traffic between endpoints.
3. Use spytest to capture encapsulated traffic on spine switch.
4. Verify outer header is IPv4 with correct VTEP addresses.
5. Verify inner payload is IPv4.
6. Verify traffic is correctly decapsulated at egress VTEP.

**Expected Results**

- Outer header is IPv4 with correct source and destination VTEP IPs.
- Inner payload is preserved correctly.
- Traffic is delivered without errors.

#### Test Case 30 - IPv4-in-IPv6 VXLAN Encapsulation

**Objective**

Verify VXLAN encapsulation with IPv6 outer header and IPv4 inner payload.

**Test Steps**

1. Configure VXLAN with IPv6 VTEP addresses.
2. Send IPv4 traffic between endpoints.
3. Use spytest to capture encapsulated traffic on spine switch.
4. Verify outer header is IPv6 with correct VTEP addresses.
5. Verify inner payload is IPv4.
6. Verify traffic is correctly decapsulated at egress VTEP.

**Expected Results**

- Outer header is IPv6 with correct source and destination VTEP IPs.
- Inner IPv4 payload is preserved correctly.
- Traffic is delivered without errors.

#### Test Case 31 - IPv6-in-IPv4 VXLAN Encapsulation

**Objective**

Verify VXLAN encapsulation with IPv4 outer header and IPv6 inner payload.

**Test Steps**

1. Configure VXLAN with IPv4 VTEP addresses.
2. Send IPv6 traffic between endpoints.
3. Use spytest to capture encapsulated traffic on spine switch.
4. Verify outer header is IPv4 with correct VTEP addresses.
5. Verify inner payload is IPv6.
6. Verify traffic is correctly decapsulated at egress VTEP.

**Expected Results**

- Outer header is IPv4 with correct source and destination VTEP IPs.
- Inner IPv6 payload is preserved correctly.
- Traffic is delivered without errors.

#### Test Case 32 - IPv6-in-IPv6 VXLAN Encapsulation

**Objective**

Verify VXLAN encapsulation with IPv6 outer header and IPv6 inner payload.

**Test Steps**

1. Configure VXLAN with IPv6 VTEP addresses.
2. Send IPv6 traffic between endpoints.
3. Use spytest to capture encapsulated traffic on spine switch.
4. Verify outer header is IPv6 with correct VTEP addresses.
5. Verify inner payload is IPv6.
6. Verify traffic is correctly decapsulated at egress VTEP.

**Expected Results**

- Outer header is IPv6 with correct source and destination VTEP IPs.
- Inner IPv6 payload is preserved correctly.
- Traffic is delivered without errors.

## Test Infrastructure

The tests leverage the following infrastructure:

1. **spytest Framework**: Primary test framework for packet validation and test automation. spytest provides:
   - Packet capture and deep inspection capabilities
   - VXLAN header field verification
   - Traffic statistics collection and analysis
   - Automated test orchestration and reporting
   - Integration with Keysight Ixia for traffic generation

2. **Keysight Ixia IxNetwork API**: Used for traffic generation, endpoint simulation, LAG configuration for multi-homing tests, and traffic statistics collection.

3. **Ecmp_Utils Class** (`tests/common/vxlan_ecmp_utils.py`): Provides utilities for VXLAN ECMP testing, including route configuration and verification.

4. **Ansible Playbooks**: Used for testbed configuration and device management.

5. **pytest Integration**: spytest integrates with pytest for test discovery, execution, and reporting.

## References

- [RFC 7348 - Virtual eXtensible Local Area Network (VXLAN)](https://tools.ietf.org/html/rfc7348)
- [RFC 8365 - A Network Virtualization Overlay Solution Using EVPN](https://tools.ietf.org/html/rfc8365)
- [RFC 7432 - BGP MPLS-Based Ethernet VPN](https://tools.ietf.org/html/rfc7432)
- [RFC 8584 - Framework for Ethernet VPN Designated Forwarder Election Extensibility](https://tools.ietf.org/html/rfc8584)
- [draft-ietf-bess-evpn-fast-df-recovery - Fast Recovery for EVPN DF Election](https://datatracker.ietf.org/doc/draft-ietf-bess-evpn-fast-df-recovery/)
- [SONiC VXLAN HLD](https://github.com/sonic-net/SONiC/blob/master/doc/vxlan/Vxlan_hld.md)
- [SONiC EVPN HLD](https://github.com/sonic-net/SONiC/blob/master/doc/vxlan/EVPN/EVPN_VXLAN_HLD.md)
- [SONiC EVPN Multi-Homing HLD](https://github.com/sonic-net/SONiC/blob/master/doc/vxlan/EVPN/EVPN_MH_HLD.md)
- [spytest Framework Documentation](https://github.com/sonic-net/sonic-mgmt/tree/master/spytest)

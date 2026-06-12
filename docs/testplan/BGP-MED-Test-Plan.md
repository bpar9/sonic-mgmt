# BGP MED (Multi-Exit Discriminator) Test Plan

## Related Documents

| **Document Name** | **Link** |
|-------------------|----------|
| BGP RFC 4271 | [https://datatracker.ietf.org/doc/html/rfc4271](https://datatracker.ietf.org/doc/html/rfc4271) |
| FRRouting BGP Documentation | [https://docs.frrouting.org/en/latest/bgp.html](https://docs.frrouting.org/en/latest/bgp.html) |

## Overview

BGP MED (Multi-Exit Discriminator) is an optional non-transitive BGP path attribute used to influence inbound traffic routing decisions from external Autonomous Systems. It provides a mechanism for an AS to suggest to neighboring ASes which entry point is preferred when multiple entry points exist.

Key characteristics of MED:

- Optional non-transitive attribute (not passed to other ASes by default)
- Lower MED values are preferred (unlike local-preference where higher is better)
- Default behavior: MED is only compared between paths from the same neighboring AS
- Can be configured to compare MED across different ASes using "always-compare-med"
- MED can be set via route-maps on incoming or outgoing routes
- Used to influence inbound traffic path selection from external peers
- In BGP best path selection, MED is evaluated after local-preference, AS-path, and origin

This test plan validates the BGP MED functionality in SONiC, including configuration via route-maps, best path selection based on MED values, and proper behavior with eBGP and iBGP peers.

### Scope

The test validates the following aspects of BGP MED:

1. Default MED value behavior for routes
2. Setting MED via route-maps for incoming and outgoing routes
3. Best path selection based on MED values (same AS)
4. MED comparison across different ASes (always-compare-med)
5. MED propagation to eBGP peers
6. MED behavior within iBGP
7. MED persistence after BGP container restart
8. MED with IPv6 routes
9. MED value boundaries (0 and max uint32)
10. MED override via route-map
11. MED with multiple prefixes
12. MED interaction with local-preference (LP takes precedence)
13. MED interaction with AS-path (AS-path takes precedence)
14. MED deterministic comparison behavior
15. MED missing vs MED=0 behavior
16. MED with route reflector scenarios

### Scale / Performance

No specific scale/performance testing is included in this test plan. The focus is on functional validation of MED behavior.

### Related DUT CLI Commands

Commands to view BGP routes with MED:
```bash
# View IPv4 BGP routes with MED
vtysh -c "show bgp ipv4 unicast"
vtysh -c "show bgp ipv4 unicast <prefix> json"

# View IPv6 BGP routes with MED
vtysh -c "show bgp ipv6 unicast"
vtysh -c "show bgp ipv6 unicast <prefix> json"

# View BGP best path selection
vtysh -c "show bgp ipv4 unicast <prefix> bestpath"
```

Commands to configure route-maps with MED:
```bash
# Configure route-map to set MED (metric)
vtysh -c "configure terminal" \
      -c "route-map SET_MED permit 10" \
      -c "set metric 100"

# Apply route-map to BGP neighbor (outbound - to influence inbound traffic)
vtysh -c "configure terminal" \
      -c "router bgp <asn>" \
      -c "neighbor <peer> route-map SET_MED out"

# Apply route-map to BGP neighbor (inbound - to set MED on received routes)
vtysh -c "configure terminal" \
      -c "router bgp <asn>" \
      -c "neighbor <peer> route-map SET_MED in"
```

Commands to configure MED comparison behavior:
```bash
# Enable always-compare-med (compare MED across different ASes)
vtysh -c "configure terminal" \
      -c "router bgp <asn>" \
      -c "bgp always-compare-med"

# Enable deterministic MED comparison
vtysh -c "configure terminal" \
      -c "router bgp <asn>" \
      -c "bgp deterministic-med"
```

### Supported Topology

The tests are supported on the following topologies:
- t0
- t0-multi-asic
- t1
- t1-multi-asic

## Setup Configuration

The test uses the following setup:

1. DUT running SONiC with BGP configured
2. ExaBGP instances on PTF host to simulate BGP peers
3. Neighbor VMs (T0s/T1s) for route propagation verification
4. Route-maps configured via vtysh for MED manipulation

The test fixtures handle:
- ExaBGP session setup and teardown
- Route-map configuration and cleanup
- Route announcement and withdrawal
- BGP configuration changes (always-compare-med, deterministic-med)

## Test Cases

### Test Case #1 - Default MED Value

**Objective:** Verify the default MED behavior for routes learned from eBGP peers.

**Test Steps:**
1. Announce a route from an eBGP neighbor without setting MED
2. Wait for route convergence
3. Query the BGP route on the DUT using `show bgp ipv4 unicast <prefix> json`
4. Verify the MED attribute behavior (may be absent or 0 depending on implementation)
5. Withdraw the route

**Expected Results:**
- Routes without explicit MED should have MED absent or set to 0
- The route should be installed in the BGP table correctly

### Test Case #2 - Set MED via Route-Map (Inbound)

**Objective:** Verify that MED can be set via route-map on incoming routes.

**Test Steps:**
1. Configure a route-map on the DUT to set MED (metric) to 100
2. Apply the route-map to an eBGP neighbor (inbound direction)
3. Announce a route from the neighbor
4. Wait for route convergence
5. Query the BGP route on the DUT
6. Verify the MED value is 100
7. Remove the route-map and withdraw the route

**Expected Results:**
- The route should have MED = 100 as set by the route-map
- The route-map should be applied correctly to incoming routes

### Test Case #3 - Set MED via Route-Map (Outbound)

**Objective:** Verify that MED can be set via route-map on outgoing routes to influence inbound traffic.

**Test Steps:**
1. Configure a route-map on the DUT to set MED (metric) to 200
2. Apply the route-map to an eBGP neighbor (outbound direction)
3. Originate or redistribute a route on the DUT
4. Wait for route propagation
5. Query the BGP route on the neighbor (if accessible)
6. Verify the MED value is 200 in the advertised route
7. Remove the route-map

**Expected Results:**
- The advertised route should have MED = 200
- The route-map should be applied correctly to outgoing routes

### Test Case #4 - Best Path Selection Based on MED (Same AS)

**Objective:** Verify that BGP selects the path with lower MED as the best path when paths are from the same AS.

**Test Steps:**
1. Configure two eBGP neighbors from the SAME AS (e.g., AS 65001)
2. Configure route-maps with different MED values:
   - Route-map A: MED = 100
   - Route-map B: MED = 50
3. Apply route-map A to neighbor 1 and route-map B to neighbor 2
4. Announce the same prefix from both neighbors
5. Wait for route convergence
6. Query the BGP route on the DUT
7. Verify the best path is from neighbor 2 (lower MED)
8. Withdraw routes and remove route-maps

**Expected Results:**
- The path with MED = 50 should be selected as the best path
- The route from neighbor 1 should be present but not selected as best
- Best path reason should indicate MED comparison

### Test Case #5 - MED Not Compared Across Different ASes (Default)

**Objective:** Verify that by default, MED is NOT compared between paths from different ASes.

**Test Steps:**
1. Configure two eBGP neighbors from DIFFERENT ASes (e.g., AS 65001 and AS 65002)
2. Configure route-maps with different MED values:
   - Neighbor 1 (AS 65001): MED = 500
   - Neighbor 2 (AS 65002): MED = 10
3. Announce the same prefix from both neighbors
4. Wait for route convergence
5. Query the BGP route on the DUT
6. Verify MED is NOT the deciding factor (other criteria like router-id may decide)
7. Clean up configuration

**Expected Results:**
- MED should NOT be compared between paths from different ASes
- Best path selection should fall through to other criteria
- Both paths should be present in the BGP table

### Test Case #6 - MED Comparison with always-compare-med

**Objective:** Verify that MED is compared across different ASes when always-compare-med is enabled.

**Test Steps:**
1. Enable "bgp always-compare-med" on the DUT
2. Configure two eBGP neighbors from DIFFERENT ASes
3. Configure route-maps with different MED values:
   - Neighbor 1 (AS 65001): MED = 500
   - Neighbor 2 (AS 65002): MED = 10
4. Announce the same prefix from both neighbors
5. Wait for route convergence
6. Query the BGP route on the DUT
7. Verify the best path is from neighbor 2 (lower MED)
8. Disable always-compare-med and clean up

**Expected Results:**
- With always-compare-med enabled, MED should be compared across ASes
- The path with lower MED (10) should be selected as best
- Best path reason should indicate MED comparison

### Test Case #7 - MED Propagation to eBGP Peers

**Objective:** Verify that MED is propagated to eBGP peers when advertising routes.

**Test Steps:**
1. Configure a route-map to set MED = 150 on outbound routes
2. Apply the route-map to an eBGP neighbor
3. Originate a route on the DUT
4. Wait for route propagation
5. Verify the eBGP neighbor receives the route with MED = 150
6. Clean up configuration

**Expected Results:**
- MED should be included in route advertisements to eBGP peers
- The configured MED value should be preserved

### Test Case #8 - MED Behavior within iBGP

**Objective:** Verify that MED is propagated within iBGP sessions.

**Test Steps:**
1. Configure a route-map to set MED = 200 on routes from an eBGP neighbor
2. Announce a route from the eBGP neighbor
3. Wait for route convergence
4. Check the route on an iBGP peer (if available in topology)
5. Verify the MED value is preserved (200)
6. Clean up configuration

**Expected Results:**
- MED should be propagated to iBGP peers
- The value should be preserved during iBGP advertisement

### Test Case #9 - MED Persistence After BGP Restart

**Objective:** Verify that route-map configuration with MED persists after BGP container restart.

**Test Steps:**
1. Configure a route-map to set MED = 250
2. Apply the route-map to a BGP neighbor
3. Save the configuration
4. Restart the BGP container
5. Wait for BGP to be fully started
6. Verify the route-map configuration is restored
7. Announce a route and verify MED is applied correctly
8. Clean up configuration

**Expected Results:**
- Route-map configuration should persist after BGP restart
- MED should be applied correctly after restart

### Test Case #10 - MED with IPv6 Routes

**Objective:** Verify that MED works correctly with IPv6 routes.

**Test Steps:**
1. Configure a route-map to set MED = 175
2. Apply the route-map to an eBGP neighbor for IPv6 address family
3. Announce an IPv6 route from the neighbor
4. Wait for route convergence
5. Query the BGP IPv6 route on the DUT
6. Verify the MED value is 175
7. Clean up configuration

**Expected Results:**
- MED should work identically for IPv4 and IPv6 routes
- The configured value should be applied to IPv6 routes

### Test Case #11 - MED Value Boundary (Zero)

**Objective:** Verify that MED = 0 is accepted and applied correctly.

**Test Steps:**
1. Configure a route-map with MED = 0
2. Apply the route-map to an eBGP neighbor
3. Announce a route from the neighbor
4. Wait for route convergence
5. Query the BGP route on the DUT
6. Verify the MED value is 0
7. Clean up configuration

**Expected Results:**
- MED = 0 should be accepted and applied
- MED = 0 should be treated as the most preferred value in comparisons

### Test Case #12 - MED Value Boundary (Maximum)

**Objective:** Verify that MED accepts the maximum value (4294967295).

**Test Steps:**
1. Configure a route-map with MED = 4294967295 (max uint32)
2. Apply the route-map to an eBGP neighbor
3. Announce a route from the neighbor
4. Wait for route convergence
5. Query the BGP route on the DUT
6. Verify the MED value is 4294967295
7. Clean up configuration

**Expected Results:**
- MED = 4294967295 (max uint32) should be accepted and applied
- The maximum value should work correctly in best path selection

### Test Case #13 - MED Override

**Objective:** Verify that MED can be overridden by updating the route-map.

**Test Steps:**
1. Configure a route-map with MED = 100
2. Apply the route-map and announce a route
3. Verify MED is 100
4. Update the route-map to set MED = 300
5. Clear BGP session or re-announce the route
6. Verify MED is now 300
7. Clean up configuration

**Expected Results:**
- MED should be updated when route-map is changed
- The new value should take effect after route refresh

### Test Case #14 - MED with Multiple Prefixes

**Objective:** Verify that MED is correctly applied to multiple prefixes.

**Test Steps:**
1. Configure a route-map with MED = 400
2. Apply the route-map to a BGP neighbor
3. Announce multiple prefixes (e.g., 10 different /24 prefixes)
4. Wait for route convergence
5. Query each prefix and verify MED is 400 for all
6. Withdraw all routes and clean up

**Expected Results:**
- MED should be consistently applied to all prefixes
- All routes should have the same MED value

### Test Case #15 - MED Interaction with Local-Preference

**Objective:** Verify that local-preference takes precedence over MED in best path selection.

**Test Steps:**
1. Configure two route-maps:
   - Route-map A: local-preference = 200, MED = 10 (best MED)
   - Route-map B: local-preference = 300, MED = 1000 (worst MED)
2. Apply route-map A to Neighbor 1 and route-map B to Neighbor 2
3. Announce the same prefix from both neighbors
4. Wait for route convergence
5. Query the BGP route on the DUT
6. Verify the best path is from Neighbor 2 (higher local-preference)
7. Clean up configuration

**Expected Results:**
- Local-preference should take precedence over MED
- The path with higher local-preference should be selected despite worse MED
- This confirms BGP path selection order: Local-Preference > AS-Path > Origin > MED

### Test Case #16 - MED Interaction with AS-Path

**Objective:** Verify that AS-path length takes precedence over MED in best path selection.

**Test Steps:**
1. Configure two route-maps with the same local-preference:
   - Route-map A: MED = 10 (best MED)
   - Route-map B: MED = 1000 (worst MED)
2. Configure Neighbor 1 to announce with longer AS-Path: 65001 65002 65003
3. Configure Neighbor 2 to announce with shorter AS-Path: 65004
4. Apply route-map A to Neighbor 1 and route-map B to Neighbor 2
5. Wait for route convergence
6. Query the BGP route on the DUT
7. Verify the best path is from Neighbor 2 (shorter AS-Path)
8. Clean up configuration

**Expected Results:**
- AS-path length should take precedence over MED
- The path with shorter AS-path should be selected despite worse MED
- This confirms BGP path selection order: AS-Path > Origin > MED

### Test Case #17 - MED Deterministic Comparison

**Objective:** Verify that deterministic-med ensures consistent MED comparison order.

**Test Steps:**
1. Enable "bgp deterministic-med" on the DUT
2. Configure multiple neighbors from the same AS with different MEDs
3. Announce the same prefix from all neighbors
4. Wait for route convergence
5. Verify the best path selection is consistent
6. Restart BGP and verify the same path is selected
7. Disable deterministic-med and clean up

**Expected Results:**
- With deterministic-med, paths should be grouped by AS before MED comparison
- Best path selection should be consistent across restarts
- The path with lowest MED within each AS group should be compared

### Test Case #18 - MED Missing vs MED=0 Behavior

**Objective:** Verify the behavior when comparing routes with missing MED vs MED=0.

**Test Steps:**
1. Configure Neighbor 1 to announce a route WITHOUT setting MED
2. Configure Neighbor 2 to announce the same route with MED = 0
3. Both neighbors should be from the same AS
4. Wait for route convergence
5. Query the BGP route on the DUT
6. Verify the best path selection behavior
7. Clean up configuration

**Expected Results:**
- Missing MED may be treated as 0 or as worst (implementation-dependent)
- Document the observed behavior for SONiC/FRR
- Both routes should be present in the BGP table

### Test Case #19 - MED with Route Reflector

**Objective:** Verify that MED is preserved when routes are reflected by a route reflector.

**Test Steps:**
1. Configure DUT as a route reflector with RR clients
2. Configure an eBGP neighbor to announce a route with MED = 300
3. Wait for route convergence
4. Query the reflected route on RR clients
5. Verify the MED value is preserved (300)
6. Verify ORIGINATOR_ID and CLUSTER_LIST are added
7. Clean up configuration

**Expected Results:**
- MED should be preserved when routes are reflected
- The RR should not modify the MED value
- Route reflection attributes should be added correctly

### Test Case #20 - MED Set by Route Reflector

**Objective:** Verify that route reflector can set MED via route-map on reflected routes.

**Test Steps:**
1. Configure DUT as a route reflector
2. Configure a route-map on DUT to set MED = 500
3. Apply the route-map to incoming routes from eBGP neighbor
4. Announce a route from the eBGP neighbor
5. Wait for route convergence
6. Query the reflected route on RR clients
7. Verify MED is 500 (as set by RR's route-map)
8. Clean up configuration

**Expected Results:**
- RR should be able to set MED via route-map on incoming routes
- The modified MED should be reflected to clients

### Test Case #21 - MED with Multiple Paths from Same AS

**Objective:** Verify MED-based best path selection with multiple paths from the same AS.

**Test Steps:**
1. Configure three eBGP neighbors from the SAME AS (e.g., AS 65001)
2. Configure route-maps with different MED values:
   - Neighbor 1: MED = 100
   - Neighbor 2: MED = 50
   - Neighbor 3: MED = 200
3. Announce the same prefix from all three neighbors
4. Wait for route convergence
5. Query the BGP route on the DUT
6. Verify the best path is from Neighbor 2 (lowest MED = 50)
7. Verify all three paths are present in the BGP table
8. Clean up configuration

**Expected Results:**
- All paths should be visible in the BGP table
- The path with lowest MED (50) should be selected as best
- MED comparison should work correctly with multiple paths

### Test Case #22 - MED with Route Flapping

**Objective:** Verify that MED-based best path selection remains stable during route flapping.

**Test Steps:**
1. Configure two neighbors from the same AS with different MEDs:
   - Neighbor 1: MED = 50 (primary)
   - Neighbor 2: MED = 100 (backup)
2. Announce the same prefix from both neighbors
3. Verify Neighbor 1's path is selected as best (lower MED)
4. Withdraw the route from Neighbor 1
5. Verify the best path switches to Neighbor 2
6. Re-announce the route from Neighbor 1
7. Verify the best path switches back to Neighbor 1
8. Repeat steps 4-7 multiple times (5 iterations)
9. Verify consistent behavior throughout
10. Clean up configuration

**Expected Results:**
- Best path should consistently follow MED values
- Route flapping should not cause inconsistent best path selection
- Convergence should occur within expected timeframes

## Test Implementation

The test implementation will be located at: `tests/bgp/test_bgp_med.py`

### Key Helper Functions

| Function | Description |
|----------|-------------|
| `get_route_med()` | Get MED value for a specific route |
| `configure_route_map_med()` | Configure route-map with MED (metric) |
| `apply_route_map_to_neighbor()` | Apply route-map to BGP neighbor |
| `remove_route_map()` | Remove route-map configuration |
| `enable_always_compare_med()` | Enable always-compare-med option |
| `enable_deterministic_med()` | Enable deterministic-med option |
| `get_bgp_route_info()` | Get detailed BGP route information |

### Fixtures

| Fixture | Scope | Description |
|---------|-------|-------------|
| `setup` | module | Sets up test environment, captures original configuration |
| `cleanup_route_maps` | function | Cleans up route-map configuration after each test |
| `cleanup_bgp_options` | function | Restores BGP options (always-compare-med, etc.) |

### BGP Path Selection Order

For reference, BGP best path selection follows this order:
1. Highest Weight (Cisco-specific, not in standard BGP)
2. Highest Local-Preference
3. Locally originated routes
4. Shortest AS-Path
5. Lowest Origin type (IGP < EGP < Incomplete)
6. **Lowest MED** (compared only for paths from same AS by default)
7. eBGP over iBGP
8. Lowest IGP metric to next-hop
9. Oldest route
10. Lowest Router ID

### Test Markers

- `@pytest.mark.topology('t0', 't0-multi-asic', 't1', 't1-multi-asic')` - Supported topologies
- `@pytest.mark.device_type('vs')` - Virtual switch support
- `@pytest.mark.disable_loganalyzer` - Disabled for restart tests

# BGP Local-Preference Test Plan

## Related Documents

| **Document Name** | **Link** |
|-------------------|----------|
| BGP RFC 4271 | [https://datatracker.ietf.org/doc/html/rfc4271](https://datatracker.ietf.org/doc/html/rfc4271) |
| FRRouting BGP Documentation | [https://docs.frrouting.org/en/latest/bgp.html](https://docs.frrouting.org/en/latest/bgp.html) |

## Overview

BGP Local-Preference is a well-known BGP path attribute used to influence outbound traffic routing decisions within an Autonomous System (AS). It is one of the key attributes in BGP's best path selection algorithm and is used to prefer one path over another when multiple paths exist to the same destination.

Key characteristics of Local-Preference:
- Default value is 100
- Higher values are preferred over lower values
- Only exchanged between iBGP peers (not sent to eBGP peers)
- Used to influence outbound traffic path selection
- Can be set via route-maps on incoming or outgoing routes

This test plan validates the BGP Local-Preference functionality in SONiC, including configuration via route-maps, best path selection based on local-preference values, and proper behavior with iBGP and eBGP peers.

### Scope

The test validates the following aspects of BGP Local-Preference:

1. Default local-preference value (100) for routes learned from eBGP peers
2. Setting local-preference via route-maps for incoming routes
3. Best path selection based on local-preference values
4. Local-preference propagation within iBGP (between DUT and neighbors)
5. Local-preference NOT being sent to eBGP peers
6. Local-preference persistence after BGP container restart
7. Local-preference behavior with multiple paths to the same destination
8. Local-preference interaction with other BGP attributes (AS-Path, MED, Weight)
9. Local-preference tie-breaking behavior when values are equal
10. Local-preference stability during route flapping scenarios

### Scale / Performance

No specific scale/performance testing is included in this test plan. The focus is on functional validation of local-preference behavior.

### Related DUT CLI Commands

Commands to view BGP routes with local-preference:
```bash
# View IPv4 BGP routes with local-preference
vtysh -c "show bgp ipv4 unicast"
vtysh -c "show bgp ipv4 unicast <prefix> json"

# View IPv6 BGP routes with local-preference
vtysh -c "show bgp ipv6 unicast"
vtysh -c "show bgp ipv6 unicast <prefix> json"

# View BGP best path selection
vtysh -c "show bgp ipv4 unicast <prefix> bestpath"
```

Commands to configure route-maps with local-preference:
```bash
# Configure route-map to set local-preference
vtysh -c "configure terminal" \
      -c "route-map SET_LOCAL_PREF permit 10" \
      -c "set local-preference 200"

# Apply route-map to BGP neighbor
vtysh -c "configure terminal" \
      -c "router bgp <asn>" \
      -c "neighbor <peer> route-map SET_LOCAL_PREF in"
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
3. Neighbor VMs (T0s) for route propagation verification
4. Route-maps configured via vtysh for local-preference manipulation

The test fixtures handle:
- ExaBGP session setup and teardown
- Route-map configuration and cleanup
- Route announcement and withdrawal

## Test Cases

### Test Case #1 - Default Local-Preference Value

**Objective:** Verify that routes learned from eBGP peers have the default local-preference value of 100.

**Test Steps:**
1. Announce a route from an eBGP neighbor (T0 VM) to the DUT
2. Wait for route convergence
3. Query the BGP route on the DUT using `show bgp ipv4 unicast <prefix> json`
4. Verify the local-preference value is 100 (default)
5. Withdraw the route

**Expected Results:**
- Routes learned from eBGP peers should have local-preference = 100
- The local-preference attribute should be present in the route information

### Test Case #2 - Set Local-Preference via Route-Map (Inbound)

**Objective:** Verify that local-preference can be set via route-map on incoming routes.

**Test Steps:**
1. Configure a route-map on the DUT to set local-preference to 200
2. Apply the route-map to an eBGP neighbor (inbound direction)
3. Announce a route from the neighbor
4. Wait for route convergence
5. Query the BGP route on the DUT
6. Verify the local-preference value is 200
7. Remove the route-map and withdraw the route

**Expected Results:**
- The route should have local-preference = 200 as set by the route-map
- The route-map should be applied correctly to incoming routes

### Test Case #3 - Best Path Selection Based on Local-Preference

**Objective:** Verify that BGP selects the path with higher local-preference as the best path.

**Test Steps:**
1. Configure two route-maps with different local-preference values:
   - Route-map A: local-preference = 150
   - Route-map B: local-preference = 200
2. Apply route-map A to neighbor 1 and route-map B to neighbor 2
3. Announce the same prefix from both neighbors
4. Wait for route convergence
5. Query the BGP route on the DUT
6. Verify the best path is from neighbor 2 (higher local-preference)
7. Withdraw routes and remove route-maps

**Expected Results:**
- The path with local-preference = 200 should be selected as the best path
- The route from neighbor 1 should be present but not selected as best

### Test Case #4 - Local-Preference Propagation to iBGP Peers

**Objective:** Verify that local-preference is propagated to iBGP peers.

**Test Steps:**
1. Configure a route-map to set local-preference to 300
2. Apply the route-map to an eBGP neighbor
3. Announce a route from the eBGP neighbor
4. Wait for route convergence
5. Check the route on an iBGP peer (if available in topology)
6. Verify the local-preference value is preserved (300)
7. Clean up configuration

**Expected Results:**
- Local-preference should be propagated to iBGP peers
- The value should be preserved during iBGP advertisement

### Test Case #5 - Local-Preference NOT Sent to eBGP Peers

**Objective:** Verify that local-preference is NOT sent to eBGP peers (stripped on eBGP advertisement).

**Test Steps:**
1. Configure a route-map to set local-preference to 500
2. Apply the route-map to an incoming eBGP neighbor
3. Announce a route from the neighbor
4. Wait for route convergence
5. Check the route advertisement to other eBGP neighbors
6. Verify local-preference is not included in the eBGP advertisement
7. Clean up configuration

**Expected Results:**
- Local-preference should NOT be sent to eBGP peers
- The attribute should be stripped when advertising to eBGP neighbors

### Test Case #6 - Local-Preference Persistence After BGP Restart

**Objective:** Verify that route-map configuration with local-preference persists after BGP container restart.

**Test Steps:**
1. Configure a route-map to set local-preference to 250
2. Apply the route-map to a BGP neighbor
3. Save the configuration
4. Restart the BGP container
5. Wait for BGP to be fully started
6. Verify the route-map configuration is restored
7. Announce a route and verify local-preference is applied correctly
8. Clean up configuration

**Expected Results:**
- Route-map configuration should persist after BGP restart
- Local-preference should be applied correctly after restart

### Test Case #7 - Local-Preference with IPv6 Routes

**Objective:** Verify that local-preference works correctly with IPv6 routes.

**Test Steps:**
1. Configure a route-map to set local-preference to 175
2. Apply the route-map to an eBGP neighbor for IPv6 address family
3. Announce an IPv6 route from the neighbor
4. Wait for route convergence
5. Query the BGP IPv6 route on the DUT
6. Verify the local-preference value is 175
7. Clean up configuration

**Expected Results:**
- Local-preference should work identically for IPv4 and IPv6 routes
- The configured value should be applied to IPv6 routes

### Test Case #8 - Local-Preference Value Boundaries

**Objective:** Verify that local-preference accepts valid boundary values (0 and 4294967295).

**Test Steps:**
1. Configure a route-map with local-preference = 0
2. Announce a route and verify local-preference is 0
3. Update route-map with local-preference = 4294967295 (max value)
4. Announce a route and verify local-preference is 4294967295
5. Clean up configuration

**Expected Results:**
- Local-preference = 0 should be accepted and applied
- Local-preference = 4294967295 (max uint32) should be accepted and applied
- Both boundary values should work correctly in best path selection

### Test Case #9 - Local-Preference Override

**Objective:** Verify that local-preference can be overridden by updating the route-map.

**Test Steps:**
1. Configure a route-map with local-preference = 100
2. Apply the route-map and announce a route
3. Verify local-preference is 100
4. Update the route-map to set local-preference = 300
5. Clear BGP session or re-announce the route
6. Verify local-preference is now 300
7. Clean up configuration

**Expected Results:**
- Local-preference should be updated when route-map is changed
- The new value should take effect after route refresh

### Test Case #10 - Local-Preference with Multiple Prefixes

**Objective:** Verify that local-preference is correctly applied to multiple prefixes.

**Test Steps:**
1. Configure a route-map with local-preference = 400
2. Apply the route-map to a BGP neighbor
3. Announce multiple prefixes (e.g., 10 different /24 prefixes)
4. Wait for route convergence
5. Query each prefix and verify local-preference is 400 for all
6. Withdraw all routes and clean up

**Expected Results:**
- Local-preference should be consistently applied to all prefixes
- All routes should have the same local-preference value

### Test Case #11 - Local-Preference with Multiple Paths

**Objective:** Verify that local-preference correctly influences best path selection when multiple paths exist to the same destination from different neighbors.

**Test Steps:**
1. Identify at least 3 BGP neighbors (T0 VMs or ExaBGP instances)
2. Configure route-maps with different local-preference values for each neighbor:
   - Neighbor 1: local-preference = 100 (default)
   - Neighbor 2: local-preference = 200
   - Neighbor 3: local-preference = 150
3. Apply the route-maps to each neighbor (inbound direction)
4. Announce the same prefix (e.g., 10.100.0.0/24) from all three neighbors
5. Wait for route convergence
6. Query the BGP route on the DUT using `show bgp ipv4 unicast <prefix> json`
7. Verify:
   - All three paths are present in the BGP table
   - The path from Neighbor 2 (local-preference = 200) is selected as best
   - The bestpath reason shows "Local Pref"
8. Change Neighbor 3's local-preference to 250
9. Clear BGP session or trigger route refresh
10. Verify the best path now switches to Neighbor 3
11. Withdraw all routes and clean up

**Expected Results:**
- All paths should be visible in the BGP table with their respective local-preference values
- The path with the highest local-preference should always be selected as best
- When local-preference values change, best path selection should update accordingly
- The `bestpath` output should indicate local-preference as the deciding factor

### Test Case #12 - Local-Preference with Equal Values (Tie-Breaking)

**Objective:** Verify that when multiple paths have equal local-preference, BGP falls back to the next tie-breaking criteria (AS-Path length).

**Test Steps:**
1. Configure two neighbors with the same local-preference value (200)
2. Configure Neighbor 1 to announce a route with AS-Path: 65001 65002
3. Configure Neighbor 2 to announce the same route with AS-Path: 65003
4. Wait for route convergence
5. Query the BGP route on the DUT
6. Verify the best path is from Neighbor 2 (shorter AS-Path)
7. Clean up configuration

**Expected Results:**
- With equal local-preference, AS-Path length should be the tie-breaker
- The path with shorter AS-Path should be selected as best
- Both paths should remain in the BGP table

### Test Case #13 - Local-Preference Interaction with AS-Path

**Objective:** Verify that local-preference takes precedence over AS-Path length in best path selection.

**Test Steps:**
1. Configure two route-maps:
   - Route-map A: local-preference = 200
   - Route-map B: local-preference = 100
2. Apply route-map A to Neighbor 1 and route-map B to Neighbor 2
3. Configure Neighbor 1 to announce a route with longer AS-Path: 65001 65002 65003
4. Configure Neighbor 2 to announce the same route with shorter AS-Path: 65004
5. Wait for route convergence
6. Query the BGP route on the DUT
7. Verify the best path is from Neighbor 1 (higher local-preference) despite longer AS-Path
8. Clean up configuration

**Expected Results:**
- Local-preference should take precedence over AS-Path length
- The path with higher local-preference should be selected even with longer AS-Path
- This confirms BGP path selection order: Local-Preference > AS-Path

### Test Case #14 - Local-Preference Interaction with MED

**Objective:** Verify that local-preference takes precedence over MED (Multi-Exit Discriminator) in best path selection.

**Test Steps:**
1. Configure two route-maps:
   - Route-map A: local-preference = 150
   - Route-map B: local-preference = 100
2. Apply route-map A to Neighbor 1 and route-map B to Neighbor 2
3. Configure Neighbor 1 to announce a route with MED = 1000 (higher/worse)
4. Configure Neighbor 2 to announce the same route with MED = 10 (lower/better)
5. Wait for route convergence
6. Query the BGP route on the DUT
7. Verify the best path is from Neighbor 1 (higher local-preference) despite worse MED
8. Clean up configuration

**Expected Results:**
- Local-preference should take precedence over MED
- The path with higher local-preference should be selected regardless of MED value
- This confirms BGP path selection order: Local-Preference > AS-Path > Origin > MED

### Test Case #15 - Local-Preference Interaction with Weight (if supported)

**Objective:** Verify that Weight (Cisco-specific attribute) takes precedence over local-preference when both are configured.

**Test Steps:**
1. Configure a route-map with local-preference = 500
2. Configure weight = 100 for Neighbor 1 (if supported by FRR/SONiC)
3. Configure weight = 200 for Neighbor 2
4. Apply the local-preference route-map to Neighbor 1
5. Announce the same prefix from both neighbors
6. Wait for route convergence
7. Query the BGP route on the DUT
8. Verify the best path selection based on weight vs local-preference precedence
9. Clean up configuration

**Expected Results:**
- If weight is supported, it should take precedence over local-preference
- The path with higher weight should be selected as best
- If weight is not supported, local-preference should determine the best path

### Test Case #16 - Local-Preference with Route Flapping

**Objective:** Verify that local-preference-based best path selection remains stable during route flapping.

**Test Steps:**
1. Configure two neighbors with different local-preference values:
   - Neighbor 1: local-preference = 200 (primary)
   - Neighbor 2: local-preference = 100 (backup)
2. Announce the same prefix from both neighbors
3. Verify Neighbor 1's path is selected as best
4. Withdraw the route from Neighbor 1
5. Verify the best path switches to Neighbor 2
6. Re-announce the route from Neighbor 1
7. Verify the best path switches back to Neighbor 1
8. Repeat steps 4-7 multiple times (5 iterations)
9. Verify consistent behavior throughout
10. Clean up configuration

**Expected Results:**
- Best path should consistently follow local-preference values
- Route flapping should not cause inconsistent best path selection
- Convergence should occur within expected timeframes

## Test Implementation

The test implementation is located at: `tests/bgp/test_bgp_local_preference.py`

### Key Helper Functions

| Function | Description |
|----------|-------------|
| `get_route_local_preference()` | Get local-preference value for a specific route |
| `configure_route_map_local_pref()` | Configure route-map with local-preference |
| `apply_route_map_to_neighbor()` | Apply route-map to BGP neighbor |
| `remove_route_map()` | Remove route-map configuration |
| `announce_route_via_exabgp()` | Announce route using ExaBGP |
| `withdraw_route_via_exabgp()` | Withdraw route using ExaBGP |
| `verify_best_path()` | Verify which path is selected as best |
| `get_bgp_route_info()` | Get detailed BGP route information |

### Fixtures

| Fixture | Scope | Description |
|---------|-------|-------------|
| `setup` | module | Sets up test environment, captures original configuration |
| `exabgp_setup` | module | Sets up ExaBGP instances for route announcement |
| `cleanup_route_maps` | function | Cleans up route-map configuration after each test |

### BGP Path Selection Order

For reference, BGP best path selection follows this order:
1. Highest Weight (Cisco-specific, not in standard BGP)
2. Highest Local-Preference
3. Locally originated routes
4. Shortest AS-Path
5. Lowest Origin type (IGP < EGP < Incomplete)
6. Lowest MED
7. eBGP over iBGP
8. Lowest IGP metric to next-hop
9. Oldest route
10. Lowest Router ID

### Test Markers

- `@pytest.mark.topology('t0', 't0-multi-asic', 't1', 't1-multi-asic')` - Supported topologies
- `@pytest.mark.device_type('vs')` - Virtual switch support
- `@pytest.mark.disable_loganalyzer` - Disabled for restart tests

# BGP Aggregate Address with BBR Awareness Test Plan

## Related Documents

| **Document Name** | **Link** |
|-------------------|----------|
| BGP Route Aggregation with BBR Awareness HLD | [https://github.com/sonic-net/SONiC/blob/master/doc/BGP/BGP-route-aggregation-with-bbr-awareness.md](https://github.com/sonic-net/SONiC/blob/master/doc/BGP/BGP-route-aggregation-with-bbr-awareness.md) |
| BGP BBR Feature | [https://github.com/sonic-net/SONiC/blob/master/doc/BGP/BGP-BBR.md](https://github.com/sonic-net/SONiC/blob/master/doc/BGP/BGP-BBR.md) |

## Overview

BGP route aggregation (also known as route summarization) is a method of generating a more general route given the presence of a specific route. This feature reduces the size of routing tables and improves network stability by advertising a single aggregated route instead of multiple specific routes.

The BBR (Bounce Back Routing) awareness feature extends BGP aggregate address functionality to work in conjunction with the BBR feature. When BBR is enabled, routes with the DUT's own ASN in the AS path are accepted (up to one occurrence). The `bbr_required` flag on aggregate addresses allows administrators to specify that certain aggregate addresses should only be active when BBR is enabled.

This test plan validates the BGP aggregate address configuration with BBR awareness, ensuring that aggregate addresses are properly managed based on BBR state and configuration parameters.

### Scope

The test validates the following aspects of BGP aggregate address with BBR awareness:

1. Configuration of aggregate addresses via CONFIG_DB using Generic Config Update (GCU)
2. Proper state management in STATE_DB reflecting active/inactive status
3. Correct BGP running configuration based on aggregate address state
4. Interaction between aggregate addresses and BBR feature state
5. Persistence of configuration across BGP container restarts
6. System stability under capacity and stress conditions
7. Behavior during network events such as link flapping

### Scale / Performance

The capacity test validates the system can handle 1000 aggregate addresses without degradation of critical services.

### Related DUT CLI Commands

Commands to manage BBR feature:
```
# Enable BBR
sonic-db-cli CONFIG_DB HSET "BGP_BBR|all" "status" "enabled"

# Disable BBR
sonic-db-cli CONFIG_DB HSET "BGP_BBR|all" "status" "disabled"

# Check BBR status
sonic-db-cli CONFIG_DB HGET "BGP_BBR|all" "status"
```

Commands to view aggregate address state:
```
# View aggregate addresses in CONFIG_DB
sonic-db-cli CONFIG_DB KEYS "BGP_AGGREGATE_ADDR|*"

# View aggregate address state in STATE_DB
sonic-db-cli STATE_DB KEYS "BGP_AGGREGATE_ADDR_TABLE|*"

# View BGP running configuration
vtysh -c "show running-config" | grep "aggregate-address"
```

### Supported Topology

The tests are supported on the following topologies:
- t1
- t1-multi-asic

## Setup Configuration

The test uses the following setup:

1. DUT running SONiC with BGP configured
2. BGP_BBR table available in CONFIG_DB
3. Generic Config Update (GCU) utility available for configuration changes
4. For multi-ASIC devices, tests run on the first frontend ASIC namespace

No additional pre-configuration is required. The test fixtures handle BBR state management and cleanup of aggregate addresses.

## Test Cases

### Test Case #1 - Aggregate Address Parameter Combinations

**Objective:** Verify that aggregate addresses can be configured with various parameter combinations and behave correctly.

**Parameters tested:**
- `as_set`: When true, generates AS_SET information for the aggregate route
- `summary_only`: When true, suppresses more specific routes
- `bbr_required`: When true, the aggregate address is only active when BBR is enabled

**Test Steps:**
1. Enable BBR on the DUT
2. Add an aggregate address with the specified parameter combination using GCU
3. Verify the aggregate address appears in CONFIG_DB with correct parameters
4. Verify the aggregate address state in STATE_DB shows "active"
5. Verify the aggregate address appears in BGP running configuration
6. Remove the aggregate address using GCU
7. Verify the aggregate address is removed from CONFIG_DB, STATE_DB, and BGP config

**Expected Results:**
- All 8 parameter combinations (2^3) should work correctly
- Aggregate addresses should be active when BBR is enabled regardless of bbr_required setting
- Configuration should be properly reflected in all three locations (CONFIG_DB, STATE_DB, BGP config)

### Test Case #2 - IPv6 Aggregate Address Support

**Objective:** Verify that IPv6 aggregate addresses are supported with BBR awareness.

**Test Steps:**
1. Enable BBR on the DUT
2. Add an IPv6 aggregate address (e.g., 2001:db8::/32) with bbr_required=true
3. Verify the aggregate address appears in CONFIG_DB
4. Verify the aggregate address state in STATE_DB shows "active"
5. Verify the aggregate address appears in BGP running configuration
6. Remove the aggregate address

**Expected Results:**
- IPv6 aggregate addresses should work identically to IPv4
- State management should be consistent across address families

### Test Case #3 - BBR State Change Impact

**Objective:** Verify that aggregate addresses with bbr_required=true become inactive when BBR is disabled.

**Test Steps:**
1. Enable BBR on the DUT
2. Add an aggregate address with bbr_required=true
3. Verify the aggregate address is active (present in STATE_DB as "active" and in BGP config)
4. Disable BBR on the DUT
5. Wait for state propagation (3 seconds)
6. Verify the aggregate address becomes inactive (STATE_DB shows "inactive" or absent from BGP config)
7. Re-enable BBR on the DUT
8. Wait for state propagation (3 seconds)
9. Verify the aggregate address becomes active again

**Expected Results:**
- Aggregate addresses with bbr_required=true should transition to inactive when BBR is disabled
- Aggregate addresses should transition back to active when BBR is re-enabled
- State transitions should be reflected in both STATE_DB and BGP running configuration

### Test Case #4 - Mixed BBR Required Settings

**Objective:** Verify correct behavior when multiple aggregate addresses have different bbr_required settings.

**Test Steps:**
1. Enable BBR on the DUT
2. Add aggregate address A (192.168.1.0/24) with bbr_required=true
3. Add aggregate address B (192.168.2.0/24) with bbr_required=false
4. Verify both addresses are active
5. Disable BBR on the DUT
6. Wait for state propagation
7. Verify address A becomes inactive (not in BGP config)
8. Verify address B remains active (still in BGP config)
9. Clean up both addresses

**Expected Results:**
- When BBR is disabled, only addresses with bbr_required=true should become inactive
- Addresses with bbr_required=false should remain active regardless of BBR state
- This allows for mixed deployment scenarios

### Test Case #5 - BGP Container Restart Persistence

**Objective:** Verify that aggregate address configuration persists after BGP container restart.

**Test Steps:**
1. Enable BBR on the DUT
2. Add an aggregate address with bbr_required=true
3. Verify the aggregate address is active
4. Restart the BGP container using `sudo systemctl restart bgp`
5. Wait for BGP service to be fully started (up to 120 seconds)
6. Wait additional 10 seconds for state stabilization
7. Verify the aggregate address is still present in CONFIG_DB
8. Verify the aggregate address state is restored in STATE_DB
9. Verify the aggregate address appears in BGP running configuration

**Expected Results:**
- Aggregate address configuration should persist in CONFIG_DB across restarts
- State should be properly restored after BGP container restart
- BGP running configuration should be regenerated correctly

### Test Case #6 - Capacity and Stress Test

**Objective:** Verify system stability when configuring a large number of aggregate addresses.

**Test Steps:**
1. Enable BBR on the DUT
2. Add 1000 aggregate addresses using a single GCU batch operation
   - Prefixes: 10.0.0.0/24 through 10.3.231.0/24
   - Alternating bbr_required=true/false
3. Wait 30 seconds for configuration to be applied
4. Verify all critical services are running
5. Verify at least 90% of addresses appear in CONFIG_DB
6. Remove all aggregate addresses
7. Wait 10 seconds for cleanup
8. Verify all addresses are removed from CONFIG_DB

**Expected Results:**
- System should handle 1000 aggregate addresses without service disruption
- All critical services should remain healthy
- Configuration and cleanup should complete successfully

### Test Case #7 - Link Flapping Resilience

**Objective:** Verify that aggregate address configuration remains stable during interface state changes.

**Test Steps:**
1. Enable BBR on the DUT
2. Add an aggregate address with bbr_required=true
3. Verify the aggregate address is active
4. Select a random interface from the minigraph
5. Shut down the interface using `config interface shutdown`
6. Wait 5 seconds
7. Verify the aggregate address is still present in CONFIG_DB
8. Bring up the interface using `config interface startup`
9. Wait 10 seconds for convergence
10. Verify the aggregate address state is correct

**Expected Results:**
- Aggregate address configuration should not be affected by interface state changes
- Management plane should remain functional during link flapping
- State should be consistent after interface recovery

### Test Case #8 - Aggregate Address Update

**Objective:** Verify that existing aggregate address configuration can be updated.

**Test Steps:**
1. Enable BBR on the DUT
2. Add an aggregate address with initial configuration:
   - as_set=false
   - summary_only=false
   - bbr_required=true
3. Verify the aggregate address is active
4. Remove the aggregate address
5. Add the same prefix with updated configuration:
   - as_set=true
   - summary_only=true
   - bbr_required=true
6. Verify the aggregate address is active with new parameters
7. Verify BGP running configuration reflects the updated parameters

**Expected Results:**
- Aggregate address configuration should be updatable
- Updated parameters should be reflected in BGP running configuration
- State should remain consistent during updates

## Test Implementation

The test implementation is located at: `tests/bgp/test_bgp_aggregate_address.py`

### Key Helper Functions

| Function | Description |
|----------|-------------|
| `get_bbr_status()` | Retrieves current BBR status from CONFIG_DB |
| `enable_bbr()` | Enables BBR feature via GCU |
| `disable_bbr()` | Disables BBR feature via GCU |
| `add_aggregate_address()` | Adds a single aggregate address via GCU |
| `remove_aggregate_address()` | Removes a single aggregate address via GCU |
| `add_multiple_aggregate_addresses()` | Adds multiple addresses in a batch via GCU |
| `remove_all_aggregate_addresses()` | Removes all aggregate addresses |
| `get_aggregate_addresses_from_config_db()` | Queries CONFIG_DB for aggregate addresses |
| `get_aggregate_addresses_from_state_db()` | Queries STATE_DB for aggregate address states |
| `get_aggregate_addresses_from_bgp_config()` | Queries BGP running configuration |
| `validate_aggregate_address_state()` | Validates expected state based on BBR status |
| `common_validator()` | Common validation function for all tests |

### Fixtures

| Fixture | Scope | Description |
|---------|-------|-------------|
| `setup` | module | Sets up test environment, captures original BBR state, provides namespace info |
| `cleanup_aggregate_addresses` | function | Cleans up aggregate addresses after each test |

### Database Tables

| Database | Table | Description |
|----------|-------|-------------|
| CONFIG_DB | BGP_AGGREGATE_ADDR | Stores aggregate address configuration |
| STATE_DB | BGP_AGGREGATE_ADDR_TABLE | Stores aggregate address operational state |
| CONFIG_DB | BGP_BBR | Stores BBR feature configuration |

### Test Markers

- `@pytest.mark.topology('t1', 't1-multi-asic')` - Supported topologies
- `@pytest.mark.device_type('vs')` - Virtual switch support
- `@pytest.mark.disable_loganalyzer` - Disabled for restart and stress tests

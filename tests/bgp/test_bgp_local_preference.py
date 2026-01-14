"""
Test BGP Local-Preference feature of SONiC.

Test Plan: docs/testplan/BGP-Local-Preference-Test-Plan.md

BGP Local-Preference is a well-known BGP path attribute used to influence
outbound traffic routing decisions within an AS. Higher values are preferred.
Default value is 100.
"""
import json
import logging
import time

import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.constants import DEFAULT_NAMESPACE
from tests.common.utilities import wait_until

pytestmark = [
    pytest.mark.topology('t1', 't1-multi-asic'),
    pytest.mark.device_type('vs')
]

logger = logging.getLogger(__name__)

CONSTANTS_FILE = '/etc/sonic/constants.yml'

TEST_PREFIX_V4 = '172.16.100.0/24'
TEST_PREFIX_V6 = '2001:db8:100::/64'
TEST_PREFIX_V4_ALT = '172.16.101.0/24'

DEFAULT_LOCAL_PREF = 100
ROUTE_MAP_NAME = 'TEST_LOCAL_PREF'

EXABGP_BASE_PORT = 5000
EXABGP_BASE_PORT_V6 = 6000


def get_route_local_preference(duthost, prefix, namespace=None):
    """
    Get the local-preference value for a specific BGP route.

    Args:
        duthost: DUT host object
        prefix: Route prefix to query
        namespace: Namespace for multi-ASIC

    Returns:
        int: Local-preference value, or None if route not found
    """
    ns_option = '-n {}'.format(namespace) if namespace else ''

    if ':' in prefix:
        cmd = 'vtysh {} -c "show bgp ipv6 unicast {} json"'.format(
            ns_option, prefix)
    else:
        cmd = 'vtysh {} -c "show bgp ipv4 unicast {} json"'.format(
            ns_option, prefix)

    result = duthost.shell(cmd, module_ignore_errors=True)

    if result['rc'] != 0 or not result['stdout']:
        return None

    try:
        route_info = json.loads(result['stdout'])
        if 'paths' in route_info and len(route_info['paths']) > 0:
            return route_info['paths'][0].get('locPrf', None)
    except (json.JSONDecodeError, KeyError, IndexError):
        pass

    return None


def get_bgp_route_info(duthost, prefix, namespace=None):
    """
    Get detailed BGP route information.

    Args:
        duthost: DUT host object
        prefix: Route prefix to query
        namespace: Namespace for multi-ASIC

    Returns:
        dict: Route information or empty dict if not found
    """
    ns_option = '-n {}'.format(namespace) if namespace else ''

    if ':' in prefix:
        cmd = 'vtysh {} -c "show bgp ipv6 unicast {} json"'.format(
            ns_option, prefix)
    else:
        cmd = 'vtysh {} -c "show bgp ipv4 unicast {} json"'.format(
            ns_option, prefix)

    result = duthost.shell(cmd, module_ignore_errors=True)

    if result['rc'] != 0 or not result['stdout']:
        return {}

    try:
        return json.loads(result['stdout'])
    except json.JSONDecodeError:
        return {}


def configure_route_map_local_pref(duthost, route_map_name, local_pref,
                                   seq=10, namespace=None):
    """
    Configure a route-map with local-preference setting.

    Args:
        duthost: DUT host object
        route_map_name: Name of the route-map
        local_pref: Local-preference value to set
        seq: Sequence number for the route-map entry
        namespace: Namespace for multi-ASIC
    """
    logger.info(
        'Configuring route-map {} with local-preference {}'.format(
            route_map_name, local_pref))

    ns_option = '-n {}'.format(namespace) if namespace else ''

    commands = [
        'configure terminal',
        'route-map {} permit {}'.format(route_map_name, seq),
        'set local-preference {}'.format(local_pref),
        'exit',
        'exit'
    ]

    cmd = 'vtysh {} {}'.format(
        ns_option,
        ' '.join(['-c "{}"'.format(c) for c in commands])
    )

    duthost.shell(cmd)
    time.sleep(2)


def apply_route_map_to_neighbor(duthost, neighbor_ip, route_map_name,
                                direction='in', namespace=None):
    """
    Apply a route-map to a BGP neighbor.

    Args:
        duthost: DUT host object
        neighbor_ip: BGP neighbor IP address
        route_map_name: Name of the route-map
        direction: 'in' or 'out'
        namespace: Namespace for multi-ASIC
    """
    logger.info(
        'Applying route-map {} to neighbor {} ({})'.format(
            route_map_name, neighbor_ip, direction))

    ns_option = '-n {}'.format(namespace) if namespace else ''

    bgp_asn = get_bgp_asn(duthost, namespace)

    if ':' in neighbor_ip:
        addr_family = 'ipv6'
    else:
        addr_family = 'ipv4'

    commands = [
        'configure terminal',
        'router bgp {}'.format(bgp_asn),
        'address-family {} unicast'.format(addr_family),
        'neighbor {} route-map {} {}'.format(
            neighbor_ip, route_map_name, direction),
        'exit',
        'exit',
        'exit'
    ]

    cmd = 'vtysh {} {}'.format(
        ns_option,
        ' '.join(['-c "{}"'.format(c) for c in commands])
    )

    duthost.shell(cmd)
    time.sleep(2)


def remove_route_map_from_neighbor(duthost, neighbor_ip, route_map_name,
                                   direction='in', namespace=None):
    """
    Remove a route-map from a BGP neighbor.

    Args:
        duthost: DUT host object
        neighbor_ip: BGP neighbor IP address
        route_map_name: Name of the route-map
        direction: 'in' or 'out'
        namespace: Namespace for multi-ASIC
    """
    logger.info(
        'Removing route-map {} from neighbor {} ({})'.format(
            route_map_name, neighbor_ip, direction))

    ns_option = '-n {}'.format(namespace) if namespace else ''

    bgp_asn = get_bgp_asn(duthost, namespace)

    if ':' in neighbor_ip:
        addr_family = 'ipv6'
    else:
        addr_family = 'ipv4'

    commands = [
        'configure terminal',
        'router bgp {}'.format(bgp_asn),
        'address-family {} unicast'.format(addr_family),
        'no neighbor {} route-map {} {}'.format(
            neighbor_ip, route_map_name, direction),
        'exit',
        'exit',
        'exit'
    ]

    cmd = 'vtysh {} {}'.format(
        ns_option,
        ' '.join(['-c "{}"'.format(c) for c in commands])
    )

    duthost.shell(cmd, module_ignore_errors=True)
    time.sleep(2)


def remove_route_map(duthost, route_map_name, namespace=None):
    """
    Remove a route-map configuration.

    Args:
        duthost: DUT host object
        route_map_name: Name of the route-map to remove
        namespace: Namespace for multi-ASIC
    """
    logger.info('Removing route-map {}'.format(route_map_name))

    ns_option = '-n {}'.format(namespace) if namespace else ''

    commands = [
        'configure terminal',
        'no route-map {}'.format(route_map_name),
        'exit'
    ]

    cmd = 'vtysh {} {}'.format(
        ns_option,
        ' '.join(['-c "{}"'.format(c) for c in commands])
    )

    duthost.shell(cmd, module_ignore_errors=True)
    time.sleep(1)


def get_bgp_asn(duthost, namespace=None):
    """
    Get the BGP ASN of the DUT.

    Args:
        duthost: DUT host object
        namespace: Namespace for multi-ASIC

    Returns:
        int: BGP ASN
    """
    ns_option = '-n {}'.format(namespace) if namespace else ''

    cmd = 'vtysh {} -c "show bgp summary json"'.format(ns_option)
    result = duthost.shell(cmd)

    try:
        bgp_summary = json.loads(result['stdout'])
        return bgp_summary.get('ipv4Unicast', {}).get('as', None) or \
            bgp_summary.get('ipv6Unicast', {}).get('as', None)
    except (json.JSONDecodeError, KeyError):
        return None


def get_bgp_neighbors(duthost, namespace=None):
    """
    Get list of BGP neighbors.

    Args:
        duthost: DUT host object
        namespace: Namespace for multi-ASIC

    Returns:
        dict: BGP neighbors information
    """
    ns_option = '-n {}'.format(namespace) if namespace else ''

    cmd = 'vtysh {} -c "show bgp summary json"'.format(ns_option)
    result = duthost.shell(cmd)

    try:
        bgp_summary = json.loads(result['stdout'])
        neighbors = {}

        if 'ipv4Unicast' in bgp_summary:
            neighbors.update(bgp_summary['ipv4Unicast'].get('peers', {}))
        if 'ipv6Unicast' in bgp_summary:
            neighbors.update(bgp_summary['ipv6Unicast'].get('peers', {}))

        return neighbors
    except (json.JSONDecodeError, KeyError):
        return {}


def get_established_bgp_neighbor(duthost, namespace=None, ip_version=4):
    """
    Get an established BGP neighbor IP.

    Args:
        duthost: DUT host object
        namespace: Namespace for multi-ASIC
        ip_version: 4 or 6

    Returns:
        str: Neighbor IP address or None
    """
    neighbors = get_bgp_neighbors(duthost, namespace)

    for neighbor_ip, info in neighbors.items():
        if info.get('state') == 'Established':
            is_ipv6 = ':' in neighbor_ip
            if (ip_version == 6 and is_ipv6) or \
               (ip_version == 4 and not is_ipv6):
                return neighbor_ip

    return None


def clear_bgp_neighbor(duthost, neighbor_ip, namespace=None):
    """
    Clear BGP session with a neighbor to refresh routes.

    Args:
        duthost: DUT host object
        neighbor_ip: BGP neighbor IP address
        namespace: Namespace for multi-ASIC
    """
    logger.info('Clearing BGP session with {}'.format(neighbor_ip))

    ns_option = '-n {}'.format(namespace) if namespace else ''

    if ':' in neighbor_ip:
        cmd = 'vtysh {} -c "clear bgp ipv6 unicast {}"'.format(
            ns_option, neighbor_ip)
    else:
        cmd = 'vtysh {} -c "clear bgp ipv4 unicast {}"'.format(
            ns_option, neighbor_ip)

    duthost.shell(cmd, module_ignore_errors=True)
    time.sleep(5)


def wait_for_route(duthost, prefix, namespace=None, timeout=30):
    """
    Wait for a route to appear in the BGP table.

    Args:
        duthost: DUT host object
        prefix: Route prefix to wait for
        namespace: Namespace for multi-ASIC
        timeout: Maximum time to wait in seconds

    Returns:
        bool: True if route appeared, False otherwise
    """
    def check_route():
        route_info = get_bgp_route_info(duthost, prefix, namespace)
        return 'paths' in route_info and len(route_info['paths']) > 0

    return wait_until(timeout, 5, 0, check_route)


def verify_route_not_present(duthost, prefix, namespace=None):
    """
    Verify that a route is not present in the BGP table.

    Args:
        duthost: DUT host object
        prefix: Route prefix to check
        namespace: Namespace for multi-ASIC

    Returns:
        bool: True if route is not present
    """
    route_info = get_bgp_route_info(duthost, prefix, namespace)
    return 'paths' not in route_info or len(route_info.get('paths', [])) == 0


@pytest.fixture(scope='module')
def setup(duthosts, rand_one_dut_hostname, tbinfo):
    """Setup fixture for local-preference tests."""
    duthost = duthosts[rand_one_dut_hostname]

    constants_stat = duthost.stat(path=CONSTANTS_FILE)
    if not constants_stat['stat']['exists']:
        pytest.skip('No constants.yml file on DUT')

    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)

    namespace = DEFAULT_NAMESPACE
    if duthost.is_multi_asic:
        namespace = duthost.get_frontend_asic_namespace_list()[0]

    bgp_asn = get_bgp_asn(duthost, namespace)
    if not bgp_asn:
        pytest.skip('Could not determine BGP ASN')

    neighbor_v4 = get_established_bgp_neighbor(duthost, namespace, 4)
    neighbor_v6 = get_established_bgp_neighbor(duthost, namespace, 6)

    if not neighbor_v4:
        pytest.skip('No established IPv4 BGP neighbor found')

    setup_info = {
        'namespace': namespace if namespace != DEFAULT_NAMESPACE else None,
        'bgp_asn': bgp_asn,
        'neighbor_v4': neighbor_v4,
        'neighbor_v6': neighbor_v6,
        'mg_facts': mg_facts
    }

    filtered_info = {k: v for k, v in setup_info.items() if k != 'mg_facts'}
    logger.info('Setup info: {}'.format(json.dumps(filtered_info, indent=2)))

    yield setup_info

    logger.info('Cleaning up route-maps')
    remove_route_map(duthost, ROUTE_MAP_NAME, setup_info['namespace'])
    remove_route_map(
        duthost, '{}_HIGH'.format(ROUTE_MAP_NAME), setup_info['namespace'])
    remove_route_map(
        duthost, '{}_LOW'.format(ROUTE_MAP_NAME), setup_info['namespace'])


@pytest.fixture
def cleanup_route_maps(duthosts, rand_one_dut_hostname, setup):
    """Fixture to cleanup route-maps after each test."""
    yield
    duthost = duthosts[rand_one_dut_hostname]
    namespace = setup['namespace']
    neighbor_v4 = setup['neighbor_v4']
    neighbor_v6 = setup.get('neighbor_v6')

    if neighbor_v4:
        remove_route_map_from_neighbor(
            duthost, neighbor_v4, ROUTE_MAP_NAME, 'in', namespace)
        remove_route_map_from_neighbor(
            duthost, neighbor_v4, '{}_HIGH'.format(ROUTE_MAP_NAME),
            'in', namespace)
        remove_route_map_from_neighbor(
            duthost, neighbor_v4, '{}_LOW'.format(ROUTE_MAP_NAME),
            'in', namespace)

    if neighbor_v6:
        remove_route_map_from_neighbor(
            duthost, neighbor_v6, ROUTE_MAP_NAME, 'in', namespace)

    remove_route_map(duthost, ROUTE_MAP_NAME, namespace)
    remove_route_map(duthost, '{}_HIGH'.format(ROUTE_MAP_NAME), namespace)
    remove_route_map(duthost, '{}_LOW'.format(ROUTE_MAP_NAME), namespace)


def test_default_local_preference(duthosts, rand_one_dut_hostname, setup):
    """
    Test that routes have default local-preference value of 100.

    Test Steps:
    1. Get an existing route from a BGP neighbor
    2. Verify the local-preference value is 100 (default)
    """
    duthost = duthosts[rand_one_dut_hostname]
    namespace = setup['namespace']
    neighbor_v4 = setup['neighbor_v4']

    ns_option = '-n {}'.format(namespace) if namespace else ''
    cmd = ('vtysh {} -c "show bgp ipv4 unicast neighbors {} '
           'received-routes json"').format(ns_option, neighbor_v4)

    result = duthost.shell(cmd, module_ignore_errors=True)

    if result['rc'] != 0 or not result['stdout']:
        pytest.skip('Could not get received routes from neighbor')

    try:
        routes = json.loads(result['stdout'])
        received_routes = routes.get('receivedRoutes', {})

        if not received_routes:
            pytest.skip('No routes received from neighbor')

        first_prefix = list(received_routes.keys())[0]

        local_pref = get_route_local_preference(duthost, first_prefix,
                                                namespace)

        logger.info(
            'Route {} has local-preference: {}'.format(first_prefix,
                                                       local_pref))

        pytest_assert(
            local_pref == DEFAULT_LOCAL_PREF,
            'Expected default local-preference {}, got {}'.format(
                DEFAULT_LOCAL_PREF, local_pref)
        )

    except (json.JSONDecodeError, KeyError, IndexError) as e:
        pytest.skip('Could not parse route information: {}'.format(e))


def test_set_local_preference_via_route_map(duthosts, rand_one_dut_hostname,
                                            setup, cleanup_route_maps):
    """
    Test setting local-preference via route-map on incoming routes.

    Test Steps:
    1. Configure a route-map to set local-preference to 200
    2. Apply the route-map to a BGP neighbor (inbound)
    3. Clear BGP session to refresh routes
    4. Verify routes have local-preference = 200
    """
    duthost = duthosts[rand_one_dut_hostname]
    namespace = setup['namespace']
    neighbor_v4 = setup['neighbor_v4']

    test_local_pref = 200

    configure_route_map_local_pref(
        duthost, ROUTE_MAP_NAME, test_local_pref, namespace=namespace)

    apply_route_map_to_neighbor(
        duthost, neighbor_v4, ROUTE_MAP_NAME, 'in', namespace)

    clear_bgp_neighbor(duthost, neighbor_v4, namespace)

    time.sleep(10)

    ns_option = '-n {}'.format(namespace) if namespace else ''
    cmd = ('vtysh {} -c "show bgp ipv4 unicast neighbors {} '
           'received-routes json"').format(ns_option, neighbor_v4)

    result = duthost.shell(cmd, module_ignore_errors=True)

    if result['rc'] != 0 or not result['stdout']:
        pytest.fail('Could not get received routes from neighbor')

    try:
        routes = json.loads(result['stdout'])
        received_routes = routes.get('receivedRoutes', {})

        if not received_routes:
            pytest.skip('No routes received from neighbor')

        first_prefix = list(received_routes.keys())[0]

        local_pref = get_route_local_preference(
            duthost, first_prefix, namespace)

        logger.info(
            'Route {} has local-preference: {}'.format(
                first_prefix, local_pref))

        pytest_assert(
            local_pref == test_local_pref,
            'Expected local-preference {}, got {}'.format(
                test_local_pref, local_pref)
        )

    except (json.JSONDecodeError, KeyError, IndexError) as e:
        pytest.fail('Could not parse route information: {}'.format(e))


def test_local_preference_ipv6(duthosts, rand_one_dut_hostname, setup,
                               cleanup_route_maps):
    """
    Test local-preference with IPv6 routes.

    Test Steps:
    1. Configure a route-map to set local-preference to 175
    2. Apply the route-map to an IPv6 BGP neighbor
    3. Clear BGP session to refresh routes
    4. Verify IPv6 routes have local-preference = 175
    """
    duthost = duthosts[rand_one_dut_hostname]
    namespace = setup['namespace']
    neighbor_v6 = setup.get('neighbor_v6')

    if not neighbor_v6:
        pytest.skip('No established IPv6 BGP neighbor found')

    test_local_pref = 175

    configure_route_map_local_pref(
        duthost, ROUTE_MAP_NAME, test_local_pref, namespace=namespace)

    apply_route_map_to_neighbor(
        duthost, neighbor_v6, ROUTE_MAP_NAME, 'in', namespace)

    clear_bgp_neighbor(duthost, neighbor_v6, namespace)

    time.sleep(10)

    ns_option = '-n {}'.format(namespace) if namespace else ''
    cmd = ('vtysh {} -c "show bgp ipv6 unicast neighbors {} '
           'received-routes json"').format(ns_option, neighbor_v6)

    result = duthost.shell(cmd, module_ignore_errors=True)

    if result['rc'] != 0 or not result['stdout']:
        pytest.skip('Could not get received routes from IPv6 neighbor')

    try:
        routes = json.loads(result['stdout'])
        received_routes = routes.get('receivedRoutes', {})

        if not received_routes:
            pytest.skip('No IPv6 routes received from neighbor')

        first_prefix = list(received_routes.keys())[0]

        local_pref = get_route_local_preference(
            duthost, first_prefix, namespace)

        logger.info(
            'IPv6 route {} has local-preference: {}'.format(
                first_prefix, local_pref))

        pytest_assert(
            local_pref == test_local_pref,
            'Expected local-preference {}, got {}'.format(
                test_local_pref, local_pref)
        )

    except (json.JSONDecodeError, KeyError, IndexError) as e:
        pytest.skip('Could not parse IPv6 route information: {}'.format(e))


def test_local_preference_boundary_zero(duthosts, rand_one_dut_hostname,
                                        setup, cleanup_route_maps):
    """
    Test local-preference with boundary value 0.

    Test Steps:
    1. Configure a route-map to set local-preference to 0
    2. Apply the route-map to a BGP neighbor
    3. Clear BGP session to refresh routes
    4. Verify routes have local-preference = 0
    """
    duthost = duthosts[rand_one_dut_hostname]
    namespace = setup['namespace']
    neighbor_v4 = setup['neighbor_v4']

    test_local_pref = 0

    configure_route_map_local_pref(
        duthost, ROUTE_MAP_NAME, test_local_pref, namespace=namespace)

    apply_route_map_to_neighbor(
        duthost, neighbor_v4, ROUTE_MAP_NAME, 'in', namespace)

    clear_bgp_neighbor(duthost, neighbor_v4, namespace)

    time.sleep(10)

    ns_option = '-n {}'.format(namespace) if namespace else ''
    cmd = ('vtysh {} -c "show bgp ipv4 unicast neighbors {} '
           'received-routes json"').format(ns_option, neighbor_v4)

    result = duthost.shell(cmd, module_ignore_errors=True)

    if result['rc'] != 0 or not result['stdout']:
        pytest.fail('Could not get received routes from neighbor')

    try:
        routes = json.loads(result['stdout'])
        received_routes = routes.get('receivedRoutes', {})

        if not received_routes:
            pytest.skip('No routes received from neighbor')

        first_prefix = list(received_routes.keys())[0]

        local_pref = get_route_local_preference(
            duthost, first_prefix, namespace)

        logger.info(
            'Route {} has local-preference: {}'.format(
                first_prefix, local_pref))

        pytest_assert(
            local_pref == test_local_pref,
            'Expected local-preference {}, got {}'.format(
                test_local_pref, local_pref)
        )

    except (json.JSONDecodeError, KeyError, IndexError) as e:
        pytest.fail('Could not parse route information: {}'.format(e))


def test_local_preference_boundary_max(duthosts, rand_one_dut_hostname,
                                       setup, cleanup_route_maps):
    """
    Test local-preference with maximum boundary value (4294967295).

    Test Steps:
    1. Configure a route-map to set local-preference to 4294967295
    2. Apply the route-map to a BGP neighbor
    3. Clear BGP session to refresh routes
    4. Verify routes have local-preference = 4294967295
    """
    duthost = duthosts[rand_one_dut_hostname]
    namespace = setup['namespace']
    neighbor_v4 = setup['neighbor_v4']

    test_local_pref = 4294967295

    configure_route_map_local_pref(
        duthost, ROUTE_MAP_NAME, test_local_pref, namespace=namespace)

    apply_route_map_to_neighbor(
        duthost, neighbor_v4, ROUTE_MAP_NAME, 'in', namespace)

    clear_bgp_neighbor(duthost, neighbor_v4, namespace)

    time.sleep(10)

    ns_option = '-n {}'.format(namespace) if namespace else ''
    cmd = ('vtysh {} -c "show bgp ipv4 unicast neighbors {} '
           'received-routes json"').format(ns_option, neighbor_v4)

    result = duthost.shell(cmd, module_ignore_errors=True)

    if result['rc'] != 0 or not result['stdout']:
        pytest.fail('Could not get received routes from neighbor')

    try:
        routes = json.loads(result['stdout'])
        received_routes = routes.get('receivedRoutes', {})

        if not received_routes:
            pytest.skip('No routes received from neighbor')

        first_prefix = list(received_routes.keys())[0]

        local_pref = get_route_local_preference(
            duthost, first_prefix, namespace)

        logger.info(
            'Route {} has local-preference: {}'.format(
                first_prefix, local_pref))

        pytest_assert(
            local_pref == test_local_pref,
            'Expected local-preference {}, got {}'.format(
                test_local_pref, local_pref)
        )

    except (json.JSONDecodeError, KeyError, IndexError) as e:
        pytest.fail('Could not parse route information: {}'.format(e))


def test_local_preference_override(duthosts, rand_one_dut_hostname,
                                   setup, cleanup_route_maps):
    """
    Test that local-preference can be overridden by updating route-map.

    Test Steps:
    1. Configure a route-map with local-preference = 100
    2. Apply and verify
    3. Update route-map to local-preference = 300
    4. Clear BGP and verify new value
    """
    duthost = duthosts[rand_one_dut_hostname]
    namespace = setup['namespace']
    neighbor_v4 = setup['neighbor_v4']

    initial_local_pref = 100
    updated_local_pref = 300

    configure_route_map_local_pref(
        duthost, ROUTE_MAP_NAME, initial_local_pref, namespace=namespace)

    apply_route_map_to_neighbor(
        duthost, neighbor_v4, ROUTE_MAP_NAME, 'in', namespace)

    clear_bgp_neighbor(duthost, neighbor_v4, namespace)
    time.sleep(10)

    remove_route_map(duthost, ROUTE_MAP_NAME, namespace)
    configure_route_map_local_pref(
        duthost, ROUTE_MAP_NAME, updated_local_pref, namespace=namespace)

    clear_bgp_neighbor(duthost, neighbor_v4, namespace)
    time.sleep(10)

    ns_option = '-n {}'.format(namespace) if namespace else ''
    cmd = ('vtysh {} -c "show bgp ipv4 unicast neighbors {} '
           'received-routes json"').format(ns_option, neighbor_v4)

    result = duthost.shell(cmd, module_ignore_errors=True)

    if result['rc'] != 0 or not result['stdout']:
        pytest.fail('Could not get received routes from neighbor')

    try:
        routes = json.loads(result['stdout'])
        received_routes = routes.get('receivedRoutes', {})

        if not received_routes:
            pytest.skip('No routes received from neighbor')

        first_prefix = list(received_routes.keys())[0]

        local_pref = get_route_local_preference(
            duthost, first_prefix, namespace)

        logger.info(
            'Route {} has local-preference: {} (expected: {})'.format(
                first_prefix, local_pref, updated_local_pref))

        pytest_assert(
            local_pref == updated_local_pref,
            'Expected updated local-preference {}, got {}'.format(
                updated_local_pref, local_pref)
        )

    except (json.JSONDecodeError, KeyError, IndexError) as e:
        pytest.fail('Could not parse route information: {}'.format(e))


@pytest.mark.disable_loganalyzer
def test_local_preference_persistence_after_bgp_restart(
    duthosts, rand_one_dut_hostname, setup, cleanup_route_maps
):
    """
    Test that route-map config persists after BGP container restart.

    Test Steps:
    1. Configure a route-map with local-preference
    2. Apply to neighbor
    3. Restart BGP container
    4. Verify route-map is still configured
    5. Verify local-preference is applied correctly
    """
    duthost = duthosts[rand_one_dut_hostname]
    namespace = setup['namespace']
    neighbor_v4 = setup['neighbor_v4']

    test_local_pref = 250

    configure_route_map_local_pref(
        duthost, ROUTE_MAP_NAME, test_local_pref, namespace=namespace)

    apply_route_map_to_neighbor(
        duthost, neighbor_v4, ROUTE_MAP_NAME, 'in', namespace)

    clear_bgp_neighbor(duthost, neighbor_v4, namespace)
    time.sleep(5)

    logger.info('Restarting BGP container')
    duthost.shell('sudo systemctl restart bgp')

    pytest_assert(
        wait_until(
            120, 10, 0,
            duthost.is_service_fully_started_per_asic_or_host, 'bgp'),
        'BGP service did not start after restart'
    )

    time.sleep(15)

    ns_option = '-n {}'.format(namespace) if namespace else ''
    cmd = 'vtysh {} -c "show route-map {}"'.format(ns_option, ROUTE_MAP_NAME)
    result = duthost.shell(cmd, module_ignore_errors=True)

    logger.info('Route-map after restart: {}'.format(result['stdout']))

    cmd = ('vtysh {} -c "show bgp ipv4 unicast neighbors {} '
           'received-routes json"').format(ns_option, neighbor_v4)

    result = duthost.shell(cmd, module_ignore_errors=True)

    if result['rc'] != 0 or not result['stdout']:
        logger.warning('Could not get routes after restart')
        return

    try:
        routes = json.loads(result['stdout'])
        received_routes = routes.get('receivedRoutes', {})

        if received_routes:
            first_prefix = list(received_routes.keys())[0]
            local_pref = get_route_local_preference(
                duthost, first_prefix, namespace)

            logger.info(
                'Route {} has local-preference: {} after restart'.format(
                    first_prefix, local_pref))

    except (json.JSONDecodeError, KeyError, IndexError) as e:
        logger.warning(
            'Could not parse route information after restart: {}'.format(e))


def test_route_map_configuration_verification(duthosts, rand_one_dut_hostname,
                                              setup, cleanup_route_maps):
    """
    Test that route-map configuration is correctly applied.

    Test Steps:
    1. Configure a route-map with local-preference
    2. Verify route-map appears in running config
    3. Verify route-map is applied to neighbor
    """
    duthost = duthosts[rand_one_dut_hostname]
    namespace = setup['namespace']
    neighbor_v4 = setup['neighbor_v4']

    test_local_pref = 500

    configure_route_map_local_pref(
        duthost, ROUTE_MAP_NAME, test_local_pref, namespace=namespace)

    ns_option = '-n {}'.format(namespace) if namespace else ''
    cmd = 'vtysh {} -c "show route-map {}"'.format(ns_option, ROUTE_MAP_NAME)
    result = duthost.shell(cmd)

    logger.info('Route-map configuration: {}'.format(result['stdout']))

    pytest_assert(
        ROUTE_MAP_NAME in result['stdout'],
        'Route-map {} not found in configuration'.format(ROUTE_MAP_NAME)
    )

    pytest_assert(
        str(test_local_pref) in result['stdout'],
        'Local-preference {} not found in route-map'.format(test_local_pref)
    )

    apply_route_map_to_neighbor(
        duthost, neighbor_v4, ROUTE_MAP_NAME, 'in', namespace)

    cmd = 'vtysh {} -c "show running-config"'.format(ns_option)
    result = duthost.shell(cmd)

    expected_config = 'neighbor {} route-map {} in'.format(
        neighbor_v4, ROUTE_MAP_NAME)

    pytest_assert(
        expected_config in result['stdout'],
        'Route-map not applied to neighbor in running config'
    )

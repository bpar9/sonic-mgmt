"""
Test BGP Aggregate Address with BBR awareness feature of SONiC.

Test Plan: docs/testplan/BGP-Aggregate-Address-BBR-Awareness-Test-Plan.md
HLD: https://github.com/sonic-net/SONiC/blob/master/doc/BGP/
     BGP-route-aggregation-with-bbr-awareness.md
"""
import json
import logging
import time
import random

import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.constants import DEFAULT_NAMESPACE
from tests.common.utilities import wait_until
from tests.common.gu_utils import apply_patch, expect_op_success
from tests.common.gu_utils import generate_tmpfile, delete_tmpfile
from tests.common.gu_utils import format_json_patch_for_multiasic

pytestmark = [
    pytest.mark.topology('t1', 't1-multi-asic'),
    pytest.mark.device_type('vs')
]

logger = logging.getLogger(__name__)

CONSTANTS_FILE = '/etc/sonic/constants.yml'
CONFIG_DB_TABLE = 'BGP_AGGREGATE_ADDR'
STATE_DB_TABLE = 'BGP_AGGREGATE_ADDR_TABLE'

TEST_AGGREGATE_PREFIX_V4 = '192.168.0.0/16'
TEST_AGGREGATE_PREFIX_V6 = '2001:db8::/32'

CAPACITY_TEST_COUNT = 1000
CAPACITY_TEST_PREFIX_BASE_V4 = '10.{}.{}.0/24'


def get_bbr_status(duthost, namespace=None):
    """Get the current BBR status from config_db."""
    ns_option = '-n {}'.format(namespace) if namespace else ''
    result = duthost.shell(
        'sonic-db-cli {} CONFIG_DB HGET "BGP_BBR|all" "status"'.format(
            ns_option),
        module_ignore_errors=True
    )
    return result['stdout'].strip() if result['stdout'] else 'disabled'


def enable_bbr(duthost, namespace=None):
    """Enable BBR feature on the DUT."""
    logger.info('Enabling BBR feature')
    json_patch = [
        {
            "op": "add",
            "path": "/BGP_BBR",
            "value": {
                "all": {
                    "status": "enabled"
                }
            }
        }
    ]
    json_patch = format_json_patch_for_multiasic(
        duthost=duthost, json_data=json_patch, is_asic_specific=True)
    tmpfile = generate_tmpfile(duthost)
    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
    finally:
        delete_tmpfile(duthost, tmpfile)
    time.sleep(3)


def disable_bbr(duthost, namespace=None):
    """Disable BBR feature on the DUT."""
    logger.info('Disabling BBR feature')
    json_patch = [
        {
            "op": "replace",
            "path": "/BGP_BBR/all/status",
            "value": "disabled"
        }
    ]
    json_patch = format_json_patch_for_multiasic(
        duthost=duthost, json_data=json_patch, is_asic_specific=True)
    tmpfile = generate_tmpfile(duthost)
    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
    finally:
        delete_tmpfile(duthost, tmpfile)
    time.sleep(3)


def add_aggregate_address(duthost, prefix, as_set=False, summary_only=False,
                          bbr_required=False, namespace=None):
    """Add an aggregate address to config_db using GCU."""
    logger.info(
        'Adding aggregate address: {} '
        '(as_set={}, summary_only={}, bbr_required={})'.format(
            prefix, as_set, summary_only, bbr_required))

    config_value = {}
    if as_set:
        config_value['as_set'] = 'true'
    if summary_only:
        config_value['summary_only'] = 'true'
    if bbr_required:
        config_value['bbr_required'] = 'true'

    if not config_value:
        config_value = {'as_set': 'false'}

    json_patch = [
        {
            "op": "add",
            "path": "/BGP_AGGREGATE_ADDR/{}".format(prefix.replace('/', '|')),
            "value": config_value
        }
    ]
    json_patch = format_json_patch_for_multiasic(
        duthost=duthost, json_data=json_patch, is_asic_specific=True)
    tmpfile = generate_tmpfile(duthost)
    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
    finally:
        delete_tmpfile(duthost, tmpfile)
    time.sleep(2)


def remove_aggregate_address(duthost, prefix, namespace=None):
    """Remove an aggregate address from config_db using GCU."""
    logger.info('Removing aggregate address: {}'.format(prefix))

    json_patch = [
        {
            "op": "remove",
            "path": "/BGP_AGGREGATE_ADDR/{}".format(prefix.replace('/', '|'))
        }
    ]
    json_patch = format_json_patch_for_multiasic(
        duthost=duthost, json_data=json_patch, is_asic_specific=True)
    tmpfile = generate_tmpfile(duthost)
    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
    finally:
        delete_tmpfile(duthost, tmpfile)
    time.sleep(2)


def add_multiple_aggregate_addresses(duthost, prefixes_config, namespace=None):
    """Add multiple aggregate addresses to config_db using GCU."""
    logger.info('Adding {} aggregate addresses'.format(len(prefixes_config)))

    aggregate_addr_config = {}
    for prefix, config in prefixes_config.items():
        aggregate_addr_config[prefix.replace('/', '|')] = config

    json_patch = [
        {
            "op": "add",
            "path": "/BGP_AGGREGATE_ADDR",
            "value": aggregate_addr_config
        }
    ]
    json_patch = format_json_patch_for_multiasic(
        duthost=duthost, json_data=json_patch, is_asic_specific=True)
    tmpfile = generate_tmpfile(duthost)
    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
    finally:
        delete_tmpfile(duthost, tmpfile)
    time.sleep(5)


def remove_all_aggregate_addresses(duthost, namespace=None):
    """Remove all aggregate addresses from config_db."""
    logger.info('Removing all aggregate addresses')

    json_patch = [
        {
            "op": "remove",
            "path": "/BGP_AGGREGATE_ADDR"
        }
    ]
    json_patch = format_json_patch_for_multiasic(
        duthost=duthost, json_data=json_patch, is_asic_specific=True)
    tmpfile = generate_tmpfile(duthost)
    try:
        apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
    except Exception:
        logger.info('BGP_AGGREGATE_ADDR table may not exist, ignoring error')
    finally:
        delete_tmpfile(duthost, tmpfile)
    time.sleep(2)


def get_aggregate_addresses_from_config_db(duthost, namespace=None):
    """Get all aggregate addresses from config_db."""
    ns_option = '-n {}'.format(namespace) if namespace else ''
    result = duthost.shell(
        'sonic-db-cli {} CONFIG_DB KEYS "{}|*"'.format(
            ns_option, CONFIG_DB_TABLE),
        module_ignore_errors=True
    )
    addresses = {}
    if result['stdout']:
        for key in result['stdout'].strip().split('\n'):
            if key:
                prefix = key.replace(
                    '{}|'.format(CONFIG_DB_TABLE), '').replace('|', '/')
                config = duthost.shell(
                    'sonic-db-cli {} CONFIG_DB HGETALL "{}"'.format(
                        ns_option, key)
                )['stdout']
                addresses[prefix] = json.loads(config) if config else {}
    return addresses


def get_aggregate_addresses_from_state_db(duthost, namespace=None):
    """Get all aggregate addresses from state_db."""
    ns_option = '-n {}'.format(namespace) if namespace else ''
    result = duthost.shell(
        'sonic-db-cli {} STATE_DB KEYS "{}|*"'.format(
            ns_option, STATE_DB_TABLE),
        module_ignore_errors=True
    )
    addresses = {}
    if result['stdout']:
        for key in result['stdout'].strip().split('\n'):
            if key:
                prefix = key.replace(
                    '{}|'.format(STATE_DB_TABLE), '').replace('|', '/')
                state = duthost.shell(
                    'sonic-db-cli {} STATE_DB HGET "{}" "state"'.format(
                        ns_option, key)
                )['stdout'].strip()
                addresses[prefix] = state
    return addresses


def get_aggregate_addresses_from_bgp_config(duthost, namespace=None):
    """Get aggregate addresses from BGP running configuration."""
    ns_option = '-n {}'.format(namespace) if namespace else ''
    cmd = 'vtysh {} -c "show running-config" | grep "aggregate-address"'
    result = duthost.shell(cmd.format(ns_option), module_ignore_errors=True)
    addresses = []
    if result['stdout']:
        for line in result['stdout'].strip().split('\n'):
            if 'aggregate-address' in line:
                parts = line.strip().split()
                if len(parts) >= 2:
                    addresses.append(parts[1])
    return addresses


def validate_aggregate_address_state(duthost, prefix, expected_state,
                                     bbr_enabled, bbr_required,
                                     namespace=None):
    """
    Validate the state of an aggregate address.

    When BBR is enabled: all addresses should be active
    When BBR is disabled:
        - addresses with bbr_required=true should be inactive
        - addresses with bbr_required=false should be active
    """
    state_db_addresses = get_aggregate_addresses_from_state_db(
        duthost, namespace)
    bgp_config_addresses = get_aggregate_addresses_from_bgp_config(
        duthost, namespace)

    logger.info(
        'Validating aggregate address: {} '
        '(expected_state={}, bbr_enabled={}, bbr_required={})'.format(
            prefix, expected_state, bbr_enabled, bbr_required))
    logger.info('State DB addresses: {}'.format(state_db_addresses))
    logger.info('BGP config addresses: {}'.format(bgp_config_addresses))

    if expected_state == 'active':
        pytest_assert(
            prefix in state_db_addresses and
            state_db_addresses[prefix] == 'active',
            'Aggregate address {} should be active in state_db'.format(prefix)
        )
        pytest_assert(
            prefix in bgp_config_addresses,
            'Aggregate address {} should be in BGP running config'.format(
                prefix)
        )
    else:
        if prefix in state_db_addresses:
            pytest_assert(
                state_db_addresses[prefix] == 'inactive',
                'Aggregate address {} should be inactive in state_db'.format(
                    prefix)
            )
        pytest_assert(
            prefix not in bgp_config_addresses,
            'Aggregate address {} should not be in BGP running config'.format(
                prefix)
        )


def common_validator(duthost, expected_addresses, namespace=None):
    """
    Common validator for aggregate address tests.

    Args:
        duthost: DUT host object
        expected_addresses: dict of
            {prefix: {'bbr_required': bool, 'expected_state': str}}
        namespace: namespace for multi-asic
    """
    bbr_status = get_bbr_status(duthost, namespace)
    bbr_enabled = bbr_status == 'enabled'

    config_db_addresses = get_aggregate_addresses_from_config_db(
        duthost, namespace)
    state_db_addresses = get_aggregate_addresses_from_state_db(
        duthost, namespace)
    bgp_config_addresses = get_aggregate_addresses_from_bgp_config(
        duthost, namespace)

    logger.info('BBR status: {}'.format(bbr_status))
    logger.info('Config DB addresses: {}'.format(config_db_addresses))
    logger.info('State DB addresses: {}'.format(state_db_addresses))
    logger.info('BGP config addresses: {}'.format(bgp_config_addresses))

    for prefix, config in expected_addresses.items():
        bbr_required = config.get('bbr_required', False)

        if bbr_enabled:
            expected_state = 'active'
        else:
            expected_state = 'inactive' if bbr_required else 'active'

        validate_aggregate_address_state(
            duthost, prefix, expected_state, bbr_enabled, bbr_required,
            namespace
        )


@pytest.fixture(scope='module')
def setup(duthosts, rand_one_dut_hostname, tbinfo):
    """Setup fixture for aggregate address tests."""
    duthost = duthosts[rand_one_dut_hostname]

    constants_stat = duthost.stat(path=CONSTANTS_FILE)
    if not constants_stat['stat']['exists']:
        pytest.skip('No constants.yml file on DUT')

    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)

    namespace = DEFAULT_NAMESPACE
    if duthost.is_multi_asic:
        namespace = duthost.get_frontend_asic_namespace_list()[0]

    original_bbr_status = get_bbr_status(duthost, namespace)

    setup_info = {
        'namespace': namespace if namespace != DEFAULT_NAMESPACE else None,
        'original_bbr_status': original_bbr_status,
        'mg_facts': mg_facts
    }

    filtered_info = {k: v for k, v in setup_info.items() if k != 'mg_facts'}
    logger.info('Setup info: {}'.format(json.dumps(filtered_info, indent=2)))

    yield setup_info

    logger.info('Cleaning up aggregate addresses')
    remove_all_aggregate_addresses(duthost, setup_info['namespace'])

    if original_bbr_status == 'enabled':
        enable_bbr(duthost, setup_info['namespace'])
    else:
        try:
            disable_bbr(duthost, setup_info['namespace'])
        except Exception:
            logger.info('BBR may not be configured, ignoring error')


@pytest.fixture
def cleanup_aggregate_addresses(duthosts, rand_one_dut_hostname, setup):
    """Fixture to cleanup aggregate addresses after each test."""
    yield
    duthost = duthosts[rand_one_dut_hostname]
    remove_all_aggregate_addresses(duthost, setup['namespace'])


@pytest.mark.parametrize('as_set', [True, False])
@pytest.mark.parametrize('summary_only', [True, False])
@pytest.mark.parametrize('bbr_required', [True, False])
def test_aggregate_address_parameters_combination(
    duthosts, rand_one_dut_hostname, setup, cleanup_aggregate_addresses,
    as_set, summary_only, bbr_required
):
    """
    Test aggregate address with various parameter combinations.

    Test Steps:
    1. Add aggregate address with specified parameters
    2. Validate state using common validator
    3. Remove aggregate address
    4. Validate address is removed
    """
    duthost = duthosts[rand_one_dut_hostname]
    namespace = setup['namespace']
    prefix = TEST_AGGREGATE_PREFIX_V4

    enable_bbr(duthost, namespace)

    add_aggregate_address(
        duthost, prefix, as_set=as_set, summary_only=summary_only,
        bbr_required=bbr_required, namespace=namespace)

    expected_addresses = {
        prefix: {'bbr_required': bbr_required, 'expected_state': 'active'}
    }
    common_validator(duthost, expected_addresses, namespace)

    remove_aggregate_address(duthost, prefix, namespace)

    state_db_addresses = get_aggregate_addresses_from_state_db(
        duthost, namespace)
    pytest_assert(
        prefix not in state_db_addresses,
        'Aggregate address {} should be removed from state_db'.format(prefix)
    )


def test_aggregate_address_ipv6(duthosts, rand_one_dut_hostname, setup,
                                cleanup_aggregate_addresses):
    """
    Test aggregate address with IPv6 prefix.

    Test Steps:
    1. Enable BBR
    2. Add IPv6 aggregate address
    3. Validate state
    4. Remove aggregate address
    """
    duthost = duthosts[rand_one_dut_hostname]
    namespace = setup['namespace']
    prefix = TEST_AGGREGATE_PREFIX_V6

    enable_bbr(duthost, namespace)

    add_aggregate_address(
        duthost, prefix, bbr_required=True, namespace=namespace)

    expected_addresses = {
        prefix: {'bbr_required': True, 'expected_state': 'active'}
    }
    common_validator(duthost, expected_addresses, namespace)

    remove_aggregate_address(duthost, prefix, namespace)


def test_bbr_state_change(duthosts, rand_one_dut_hostname, setup,
                          cleanup_aggregate_addresses):
    """
    Test aggregate address behavior when BBR state changes.

    Test Steps:
    1. Enable BBR
    2. Add aggregate address with bbr_required=true
    3. Validate address is active
    4. Disable BBR
    5. Validate address becomes inactive
    6. Re-enable BBR
    7. Validate address becomes active again
    """
    duthost = duthosts[rand_one_dut_hostname]
    namespace = setup['namespace']
    prefix = TEST_AGGREGATE_PREFIX_V4

    enable_bbr(duthost, namespace)

    add_aggregate_address(
        duthost, prefix, bbr_required=True, namespace=namespace)

    expected_addresses = {prefix: {'bbr_required': True}}
    common_validator(duthost, expected_addresses, namespace)

    disable_bbr(duthost, namespace)
    time.sleep(3)

    state_db_addresses = get_aggregate_addresses_from_state_db(
        duthost, namespace)
    bgp_config_addresses = get_aggregate_addresses_from_bgp_config(
        duthost, namespace)

    logger.info(
        'After disabling BBR - State DB: {}, BGP config: {}'.format(
            state_db_addresses, bgp_config_addresses))

    if prefix in state_db_addresses:
        pytest_assert(
            state_db_addresses[prefix] == 'inactive',
            'Aggregate address should be inactive when BBR is disabled'
        )
    pytest_assert(
        prefix not in bgp_config_addresses,
        'Aggregate address should not be in BGP config when BBR is disabled'
    )

    enable_bbr(duthost, namespace)
    time.sleep(3)

    common_validator(duthost, expected_addresses, namespace)

    remove_aggregate_address(duthost, prefix, namespace)


def test_bbr_state_change_mixed_addresses(duthosts, rand_one_dut_hostname,
                                          setup, cleanup_aggregate_addresses):
    """
    Test aggregate address behavior with mixed bbr_required settings.

    Test Steps:
    1. Enable BBR
    2. Add addresses with bbr_required=true and bbr_required=false
    3. Validate all addresses are active
    4. Disable BBR
    5. Validate bbr_required=true addresses become inactive
    6. Validate bbr_required=false addresses remain active
    """
    duthost = duthosts[rand_one_dut_hostname]
    namespace = setup['namespace']

    prefix_bbr_required = '192.168.1.0/24'
    prefix_no_bbr_required = '192.168.2.0/24'

    enable_bbr(duthost, namespace)

    add_aggregate_address(
        duthost, prefix_bbr_required, bbr_required=True, namespace=namespace)
    add_aggregate_address(
        duthost, prefix_no_bbr_required, bbr_required=False,
        namespace=namespace)

    expected_addresses = {
        prefix_bbr_required: {'bbr_required': True},
        prefix_no_bbr_required: {'bbr_required': False}
    }
    common_validator(duthost, expected_addresses, namespace)

    disable_bbr(duthost, namespace)
    time.sleep(3)

    state_db_addresses = get_aggregate_addresses_from_state_db(
        duthost, namespace)
    bgp_config_addresses = get_aggregate_addresses_from_bgp_config(
        duthost, namespace)

    logger.info(
        'After disabling BBR - State DB: {}, BGP config: {}'.format(
            state_db_addresses, bgp_config_addresses))

    if prefix_bbr_required in state_db_addresses:
        pytest_assert(
            state_db_addresses[prefix_bbr_required] == 'inactive',
            'BBR required address should be inactive'
        )
    pytest_assert(
        prefix_bbr_required not in bgp_config_addresses,
        'BBR required address should not be in BGP config'
    )

    pytest_assert(
        prefix_no_bbr_required in bgp_config_addresses,
        'Non-BBR required address should remain in BGP config'
    )

    remove_aggregate_address(duthost, prefix_bbr_required, namespace)
    remove_aggregate_address(duthost, prefix_no_bbr_required, namespace)


@pytest.mark.disable_loganalyzer
def test_bgp_container_restart(duthosts, rand_one_dut_hostname, setup,
                               cleanup_aggregate_addresses):
    """
    Test aggregate address persistence after BGP container restart.

    Test Steps:
    1. Enable BBR
    2. Add aggregate address
    3. Validate state
    4. Restart BGP container
    5. Wait for BGP to be ready
    6. Validate aggregate address persists
    """
    duthost = duthosts[rand_one_dut_hostname]
    namespace = setup['namespace']
    prefix = TEST_AGGREGATE_PREFIX_V4

    enable_bbr(duthost, namespace)

    add_aggregate_address(
        duthost, prefix, bbr_required=True, namespace=namespace)

    expected_addresses = {prefix: {'bbr_required': True}}
    common_validator(duthost, expected_addresses, namespace)

    logger.info('Restarting BGP container')
    duthost.shell('sudo systemctl restart bgp')

    pytest_assert(
        wait_until(
            120, 10, 0, duthost.is_service_fully_started_per_asic_or_host,
            'bgp'),
        'BGP service did not start after restart'
    )

    time.sleep(10)

    common_validator(duthost, expected_addresses, namespace)

    remove_aggregate_address(duthost, prefix, namespace)


@pytest.mark.disable_loganalyzer
def test_capacity_stress(duthosts, rand_one_dut_hostname, setup,
                         cleanup_aggregate_addresses):
    """
    Capacity and stress test for aggregate addresses.

    Test Steps:
    1. Enable BBR
    2. Add 1000 aggregate addresses
    3. Validate no errors and containers are healthy
    4. Remove all addresses
    5. Validate cleanup
    """
    duthost = duthosts[rand_one_dut_hostname]
    namespace = setup['namespace']

    enable_bbr(duthost, namespace)

    prefixes_config = {}
    for i in range(CAPACITY_TEST_COUNT):
        octet2 = i // 256
        octet3 = i % 256
        prefix = CAPACITY_TEST_PREFIX_BASE_V4.format(octet2, octet3)
        prefixes_config[prefix] = {
            'bbr_required': 'true' if i % 2 == 0 else 'false'
        }

    logger.info('Adding {} aggregate addresses'.format(CAPACITY_TEST_COUNT))
    add_multiple_aggregate_addresses(duthost, prefixes_config, namespace)

    time.sleep(30)

    critical_services = duthost.critical_services
    for service in critical_services:
        status = duthost.is_service_fully_started(service)
        pytest_assert(
            status,
            'Service {} is not running after adding addresses'.format(service)
        )

    config_db_addresses = get_aggregate_addresses_from_config_db(
        duthost, namespace)
    logger.info(
        'Number of addresses in config_db: {}'.format(
            len(config_db_addresses)))

    expected_min = int(CAPACITY_TEST_COUNT * 0.9)
    pytest_assert(
        len(config_db_addresses) >= expected_min,
        'Expected at least {} addresses in config_db, got {}'.format(
            expected_min, len(config_db_addresses))
    )

    logger.info('Removing all aggregate addresses')
    remove_all_aggregate_addresses(duthost, namespace)

    time.sleep(10)

    config_db_addresses = get_aggregate_addresses_from_config_db(
        duthost, namespace)
    pytest_assert(
        len(config_db_addresses) == 0,
        'All aggregate addresses should be removed'
    )


def test_link_flapping(duthosts, rand_one_dut_hostname, setup,
                       cleanup_aggregate_addresses):
    """
    Test aggregate address behavior during link flapping.

    Test Steps:
    1. Enable BBR
    2. Add aggregate address
    3. Validate state
    4. Get a random interface and shut it down
    5. Validate management plane is still functional
    6. Bring interface back up
    7. Validate state
    """
    duthost = duthosts[rand_one_dut_hostname]
    namespace = setup['namespace']
    prefix = TEST_AGGREGATE_PREFIX_V4

    enable_bbr(duthost, namespace)

    add_aggregate_address(
        duthost, prefix, bbr_required=True, namespace=namespace)

    expected_addresses = {prefix: {'bbr_required': True}}
    common_validator(duthost, expected_addresses, namespace)

    mg_facts = setup['mg_facts']
    interfaces = list(mg_facts.get('minigraph_interfaces', {}).keys())
    if not interfaces:
        interfaces = list(
            mg_facts.get('minigraph_portchannel_interfaces', {}).keys())

    if interfaces:
        test_interface = random.choice(interfaces)
        logger.info('Shutting down interface: {}'.format(test_interface))

        duthost.shell(
            'sudo config interface shutdown {}'.format(test_interface))
        time.sleep(5)

        config_db_addresses = get_aggregate_addresses_from_config_db(
            duthost, namespace)
        pytest_assert(
            prefix.replace('/', '|') in str(config_db_addresses) or
            prefix in config_db_addresses,
            'Aggregate address should still be in config_db after '
            'interface shutdown'
        )

        logger.info('Bringing up interface: {}'.format(test_interface))
        duthost.shell(
            'sudo config interface startup {}'.format(test_interface))
        time.sleep(10)

        common_validator(duthost, expected_addresses, namespace)
    else:
        logger.warning(
            'No interfaces found for link flapping test, '
            'skipping interface operations')

    remove_aggregate_address(duthost, prefix, namespace)


def test_aggregate_address_update(duthosts, rand_one_dut_hostname, setup,
                                  cleanup_aggregate_addresses):
    """
    Test updating an existing aggregate address configuration.

    Test Steps:
    1. Enable BBR
    2. Add aggregate address with initial config
    3. Validate state
    4. Update aggregate address with new config
    5. Validate updated state
    """
    duthost = duthosts[rand_one_dut_hostname]
    namespace = setup['namespace']
    prefix = TEST_AGGREGATE_PREFIX_V4

    enable_bbr(duthost, namespace)

    add_aggregate_address(
        duthost, prefix, as_set=False, summary_only=False,
        bbr_required=True, namespace=namespace)

    expected_addresses = {prefix: {'bbr_required': True}}
    common_validator(duthost, expected_addresses, namespace)

    remove_aggregate_address(duthost, prefix, namespace)
    time.sleep(2)
    add_aggregate_address(
        duthost, prefix, as_set=True, summary_only=True,
        bbr_required=True, namespace=namespace)

    common_validator(duthost, expected_addresses, namespace)

    bgp_config = duthost.shell(
        'vtysh -c "show running-config" | grep "aggregate-address {}"'.format(
            prefix),
        module_ignore_errors=True
    )['stdout']

    logger.info('BGP config for aggregate address: {}'.format(bgp_config))

    remove_aggregate_address(duthost, prefix, namespace)

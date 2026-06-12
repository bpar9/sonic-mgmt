import json
import logging
import pytest

from tests.common.helpers.assertions import pytest_assert

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.device_type('vs')
]

logger = logging.getLogger(__name__)

SHOW_AAA_CMD = "show aaa"
AAA_KEYS = ["authentication", "authorization", "accounting"]


def is_mgmt_framework_running(duthost):
    result = duthost.shell("docker ps --filter name=mgmt-framework --format '{{.Names}}'",
                           module_ignore_errors=True)
    return result['rc'] == 0 and 'mgmt-framework' in result['stdout']


def run_klish_command(duthost, command):
    result = duthost.shell(
        "docker exec mgmt-framework bash -c "
        "\"source /usr/sbin/cli/klish/clish_start && "
        "echo '{}' | /usr/sbin/cli/clish -o 2>/dev/null\"".format(command),
        module_ignore_errors=True
    )
    return result


def get_aaa_config_db_all(duthost):
    saved = {}
    for key in AAA_KEYS:
        result = duthost.shell(
            'sonic-db-cli CONFIG_DB HGETALL "AAA|{}"'.format(key),
            module_ignore_errors=True
        )
        if result['rc'] == 0 and result['stdout'].strip():
            lines = result['stdout'].strip().split('\n')
            fields = {}
            for i in range(0, len(lines) - 1, 2):
                fields[lines[i]] = lines[i + 1]
            if fields:
                saved[key] = fields
    return saved


def get_aaa_table_field(duthost, table_key, field):
    result = duthost.shell(
        'sonic-db-cli CONFIG_DB HGET "AAA|{}" "{}"'.format(table_key, field),
        module_ignore_errors=True
    )
    if result['rc'] != 0:
        return None
    val = result['stdout'].strip()
    return val if val else None


def set_aaa_config(duthost, table_key, field, value):
    duthost.shell(
        'sonic-db-cli CONFIG_DB HSET "AAA|{}" "{}" "{}"'.format(table_key, field, value)
    )


def del_aaa_config(duthost, table_key, field):
    duthost.shell(
        'sonic-db-cli CONFIG_DB HDEL "AAA|{}" "{}"'.format(table_key, field),
        module_ignore_errors=True
    )


def del_aaa_table(duthost):
    duthost.shell(
        'sonic-db-cli CONFIG_DB keys "AAA|*" | xargs -r sonic-db-cli CONFIG_DB del',
        module_ignore_errors=True
    )


def get_show_aaa_output(duthost):
    result = duthost.shell(SHOW_AAA_CMD, module_ignore_errors=True)
    pytest_assert(result['rc'] == 0, "Failed to run '{}'".format(SHOW_AAA_CMD))
    return result['stdout']


def parse_show_aaa(output):
    parsed = {}
    for line in output.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("AAA authentication login"):
            parsed["authentication_login"] = line.split("AAA authentication login")[-1].strip()
        elif line.startswith("AAA authentication failthrough"):
            parsed["authentication_failthrough"] = line.split("AAA authentication failthrough")[-1].strip()
        elif line.startswith("AAA authentication fallback"):
            parsed["authentication_fallback"] = line.split("AAA authentication fallback")[-1].strip()
        elif line.startswith("AAA authentication debug"):
            parsed["authentication_debug"] = line.split("AAA authentication debug")[-1].strip()
        elif line.startswith("AAA authentication trace"):
            parsed["authentication_trace"] = line.split("AAA authentication trace")[-1].strip()
        elif line.startswith("AAA authorization login"):
            parsed["authorization_login"] = line.split("AAA authorization login")[-1].strip()
        elif line.startswith("AAA accounting login"):
            parsed["accounting_login"] = line.split("AAA accounting login")[-1].strip()
    return parsed


def rest_api_call(duthost, method, path, body=None):
    base_url = "https://localhost:8443"
    url = "{}{}".format(base_url, path)
    if method == "GET":
        cmd = "curl -sk -X GET '{}'".format(url)
    elif method == "PATCH":
        cmd = "curl -sk -X PATCH '{}' -H 'Content-Type: application/json' -d '{}'".format(
            url, json.dumps(body))
    elif method == "DELETE":
        cmd = "curl -sk -X DELETE '{}'".format(url)
    else:
        pytest.fail("Unsupported HTTP method: {}".format(method))

    result = duthost.shell(cmd, module_ignore_errors=True)
    return result


@pytest.fixture(autouse=True)
def save_and_restore_aaa(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    saved_config = get_aaa_config_db_all(duthost)
    logger.info("Saved AAA config: %s", saved_config)

    yield

    del_aaa_table(duthost)
    for key, fields in saved_config.items():
        for field, value in fields.items():
            set_aaa_config(duthost, key, field, value)
    logger.info("Restored AAA config")


@pytest.fixture
def duthost(duthosts, rand_one_dut_hostname):
    return duthosts[rand_one_dut_hostname]


@pytest.fixture
def mgmt_framework_available(duthost):
    available = is_mgmt_framework_running(duthost)
    if not available:
        pytest.skip("mgmt-framework container is not running")
    return available


class TestAAAShowDefault:

    def test_show_aaa_default(self, duthost):
        del_aaa_table(duthost)
        output = get_show_aaa_output(duthost)
        parsed = parse_show_aaa(output)
        logger.info("Default show aaa: %s", parsed)
        pytest_assert(
            "local" in parsed.get("authentication_login", ""),
            "Default authentication login should contain 'local'"
        )
        for field in ["authentication_failthrough", "authentication_fallback"]:
            val = parsed.get(field, "")
            pytest_assert(
                "default" in val.lower() or "false" in val.lower(),
                "Default {} should be False/default, got: {}".format(field, val)
            )


class TestAAAAuthenticationFailthrough:

    def test_failthrough_enable(self, duthost):
        set_aaa_config(duthost, "authentication", "failthrough", "True")
        val = get_aaa_table_field(duthost, "authentication", "failthrough")
        pytest_assert(val == "True", "Expected failthrough=True, got: {}".format(val))
        output = get_show_aaa_output(duthost)
        parsed = parse_show_aaa(output)
        pytest_assert(
            "True" in parsed.get("authentication_failthrough", ""),
            "show aaa should show failthrough True"
        )

    def test_failthrough_disable(self, duthost):
        set_aaa_config(duthost, "authentication", "failthrough", "True")
        set_aaa_config(duthost, "authentication", "failthrough", "False")
        val = get_aaa_table_field(duthost, "authentication", "failthrough")
        pytest_assert(val == "False", "Expected failthrough=False, got: {}".format(val))
        output = get_show_aaa_output(duthost)
        parsed = parse_show_aaa(output)
        pytest_assert(
            "False" in parsed.get("authentication_failthrough", ""),
            "show aaa should show failthrough False"
        )

    def test_failthrough_default_reset(self, duthost):
        set_aaa_config(duthost, "authentication", "failthrough", "True")
        del_aaa_config(duthost, "authentication", "failthrough")
        val = get_aaa_table_field(duthost, "authentication", "failthrough")
        pytest_assert(val is None or val == "",
                      "After reset, failthrough should be unset, got: {}".format(val))
        output = get_show_aaa_output(duthost)
        parsed = parse_show_aaa(output)
        pytest_assert(
            "default" in parsed.get("authentication_failthrough", "").lower()
            or "false" in parsed.get("authentication_failthrough", "").lower(),
            "show aaa should show default failthrough"
        )


class TestAAAAuthenticationFallback:

    def test_fallback_enable(self, duthost):
        set_aaa_config(duthost, "authentication", "fallback", "True")
        val = get_aaa_table_field(duthost, "authentication", "fallback")
        pytest_assert(val == "True", "Expected fallback=True, got: {}".format(val))
        output = get_show_aaa_output(duthost)
        parsed = parse_show_aaa(output)
        pytest_assert(
            "True" in parsed.get("authentication_fallback", ""),
            "show aaa should show fallback True"
        )

    def test_fallback_disable(self, duthost):
        set_aaa_config(duthost, "authentication", "fallback", "True")
        set_aaa_config(duthost, "authentication", "fallback", "False")
        val = get_aaa_table_field(duthost, "authentication", "fallback")
        pytest_assert(val == "False", "Expected fallback=False, got: {}".format(val))

    def test_fallback_default_reset(self, duthost):
        set_aaa_config(duthost, "authentication", "fallback", "True")
        del_aaa_config(duthost, "authentication", "fallback")
        val = get_aaa_table_field(duthost, "authentication", "fallback")
        pytest_assert(val is None or val == "",
                      "After reset, fallback should be unset, got: {}".format(val))


class TestAAAAuthenticationDebug:

    def test_debug_enable(self, duthost):
        set_aaa_config(duthost, "authentication", "debug", "True")
        val = get_aaa_table_field(duthost, "authentication", "debug")
        pytest_assert(val == "True", "Expected debug=True, got: {}".format(val))
        output = get_show_aaa_output(duthost)
        parsed = parse_show_aaa(output)
        pytest_assert(
            "True" in parsed.get("authentication_debug", ""),
            "show aaa should show debug True"
        )

    def test_debug_disable(self, duthost):
        set_aaa_config(duthost, "authentication", "debug", "True")
        set_aaa_config(duthost, "authentication", "debug", "False")
        val = get_aaa_table_field(duthost, "authentication", "debug")
        pytest_assert(val == "False", "Expected debug=False, got: {}".format(val))

    def test_debug_default_reset(self, duthost):
        set_aaa_config(duthost, "authentication", "debug", "True")
        del_aaa_config(duthost, "authentication", "debug")
        val = get_aaa_table_field(duthost, "authentication", "debug")
        pytest_assert(val is None or val == "",
                      "After reset, debug should be unset, got: {}".format(val))


class TestAAAAuthenticationTrace:

    def test_trace_enable(self, duthost):
        set_aaa_config(duthost, "authentication", "trace", "True")
        val = get_aaa_table_field(duthost, "authentication", "trace")
        pytest_assert(val == "True", "Expected trace=True, got: {}".format(val))
        output = get_show_aaa_output(duthost)
        parsed = parse_show_aaa(output)
        pytest_assert(
            "True" in parsed.get("authentication_trace", ""),
            "show aaa should show trace True"
        )

    def test_trace_disable(self, duthost):
        set_aaa_config(duthost, "authentication", "trace", "True")
        set_aaa_config(duthost, "authentication", "trace", "False")
        val = get_aaa_table_field(duthost, "authentication", "trace")
        pytest_assert(val == "False", "Expected trace=False, got: {}".format(val))

    def test_trace_default_reset(self, duthost):
        set_aaa_config(duthost, "authentication", "trace", "True")
        del_aaa_config(duthost, "authentication", "trace")
        val = get_aaa_table_field(duthost, "authentication", "trace")
        pytest_assert(val is None or val == "",
                      "After reset, trace should be unset, got: {}".format(val))


class TestAAAAuthenticationLogin:

    def test_login_local(self, duthost):
        set_aaa_config(duthost, "authentication", "login", "local")
        val = get_aaa_table_field(duthost, "authentication", "login")
        pytest_assert(val == "local", "Expected login=local, got: {}".format(val))
        output = get_show_aaa_output(duthost)
        parsed = parse_show_aaa(output)
        pytest_assert(
            "local" in parsed.get("authentication_login", ""),
            "show aaa should show login local"
        )

    def test_login_tacacs(self, duthost):
        set_aaa_config(duthost, "authentication", "login", "tacacs+")
        val = get_aaa_table_field(duthost, "authentication", "login")
        pytest_assert(val == "tacacs+", "Expected login=tacacs+, got: {}".format(val))
        output = get_show_aaa_output(duthost)
        parsed = parse_show_aaa(output)
        pytest_assert(
            "tacacs+" in parsed.get("authentication_login", ""),
            "show aaa should show login tacacs+"
        )

    def test_login_radius(self, duthost):
        set_aaa_config(duthost, "authentication", "login", "radius")
        val = get_aaa_table_field(duthost, "authentication", "login")
        pytest_assert(val == "radius", "Expected login=radius, got: {}".format(val))

    def test_login_multiple_methods(self, duthost):
        set_aaa_config(duthost, "authentication", "login", "tacacs+,local")
        val = get_aaa_table_field(duthost, "authentication", "login")
        pytest_assert(val == "tacacs+,local",
                      "Expected login=tacacs+,local, got: {}".format(val))
        output = get_show_aaa_output(duthost)
        parsed = parse_show_aaa(output)
        pytest_assert(
            "tacacs+" in parsed.get("authentication_login", "")
            and "local" in parsed.get("authentication_login", ""),
            "show aaa should show both tacacs+ and local"
        )

    def test_login_default_reset(self, duthost):
        set_aaa_config(duthost, "authentication", "login", "tacacs+")
        del_aaa_config(duthost, "authentication", "login")
        val = get_aaa_table_field(duthost, "authentication", "login")
        pytest_assert(val is None or val == "",
                      "After reset, login should be unset, got: {}".format(val))
        output = get_show_aaa_output(duthost)
        parsed = parse_show_aaa(output)
        pytest_assert(
            "local" in parsed.get("authentication_login", ""),
            "Default login should contain local"
        )


class TestAAAAuthorization:

    def test_authorization_local(self, duthost):
        set_aaa_config(duthost, "authorization", "login", "local")
        val = get_aaa_table_field(duthost, "authorization", "login")
        pytest_assert(val == "local", "Expected authorization login=local, got: {}".format(val))
        output = get_show_aaa_output(duthost)
        parsed = parse_show_aaa(output)
        pytest_assert(
            "local" in parsed.get("authorization_login", ""),
            "show aaa should show authorization login local"
        )

    def test_authorization_tacacs(self, duthost):
        set_aaa_config(duthost, "authorization", "login", "tacacs+")
        val = get_aaa_table_field(duthost, "authorization", "login")
        pytest_assert(val == "tacacs+",
                      "Expected authorization login=tacacs+, got: {}".format(val))

    def test_authorization_multiple(self, duthost):
        set_aaa_config(duthost, "authorization", "login", "tacacs+,local")
        val = get_aaa_table_field(duthost, "authorization", "login")
        pytest_assert(val == "tacacs+,local",
                      "Expected authorization login=tacacs+,local, got: {}".format(val))

    def test_authorization_default_reset(self, duthost):
        set_aaa_config(duthost, "authorization", "login", "tacacs+")
        del_aaa_config(duthost, "authorization", "login")
        val = get_aaa_table_field(duthost, "authorization", "login")
        pytest_assert(val is None or val == "",
                      "After reset, authorization login should be unset, got: {}".format(val))


class TestAAAAccounting:

    def test_accounting_local(self, duthost):
        set_aaa_config(duthost, "accounting", "login", "local")
        val = get_aaa_table_field(duthost, "accounting", "login")
        pytest_assert(val == "local", "Expected accounting login=local, got: {}".format(val))
        output = get_show_aaa_output(duthost)
        parsed = parse_show_aaa(output)
        pytest_assert(
            "local" in parsed.get("accounting_login", ""),
            "show aaa should show accounting login local"
        )

    def test_accounting_tacacs(self, duthost):
        set_aaa_config(duthost, "accounting", "login", "tacacs+")
        val = get_aaa_table_field(duthost, "accounting", "login")
        pytest_assert(val == "tacacs+",
                      "Expected accounting login=tacacs+, got: {}".format(val))

    def test_accounting_multiple(self, duthost):
        set_aaa_config(duthost, "accounting", "login", "tacacs+,local")
        val = get_aaa_table_field(duthost, "accounting", "login")
        pytest_assert(val == "tacacs+,local",
                      "Expected accounting login=tacacs+,local, got: {}".format(val))

    def test_accounting_disable_reset(self, duthost):
        set_aaa_config(duthost, "accounting", "login", "tacacs+")
        del_aaa_config(duthost, "accounting", "login")
        val = get_aaa_table_field(duthost, "accounting", "login")
        pytest_assert(val is None or val == "",
                      "After reset, accounting login should be unset, got: {}".format(val))


class TestAAARestAPI:

    def test_rest_get_aaa_default(self, duthost, mgmt_framework_available):
        resp = rest_api_call(duthost, "GET",
                             "/restconf/data/openconfig-system:system/aaa")
        logger.info("REST GET AAA response: rc=%s, stdout=%s",
                    resp['rc'], resp['stdout'][:500] if resp['stdout'] else "")
        pytest_assert(resp['rc'] == 0, "REST API GET call failed")

    def test_rest_patch_failthrough_enable(self, duthost, mgmt_framework_available):
        body = {
            "openconfig-system:config": {
                "openconfig-system-ext:failthrough": True
            }
        }
        resp = rest_api_call(
            duthost, "PATCH",
            "/restconf/data/openconfig-system:system/aaa/authentication/config",
            body
        )
        logger.info("REST PATCH failthrough: rc=%s", resp['rc'])
        pytest_assert(resp['rc'] == 0, "REST API PATCH call failed")
        val = get_aaa_table_field(duthost, "authentication", "failthrough")
        pytest_assert(val == "True",
                      "CONFIG_DB failthrough should be True after REST PATCH, got: {}".format(val))

    def test_rest_patch_authentication_methods(self, duthost, mgmt_framework_available):
        body = {
            "openconfig-system:config": {
                "authentication-method": ["tacacs+", "local"]
            }
        }
        resp = rest_api_call(
            duthost, "PATCH",
            "/restconf/data/openconfig-system:system/aaa/authentication/config",
            body
        )
        logger.info("REST PATCH auth methods: rc=%s", resp['rc'])
        pytest_assert(resp['rc'] == 0, "REST API PATCH call failed")
        val = get_aaa_table_field(duthost, "authentication", "login")
        pytest_assert(
            val is not None and "tacacs+" in val and "local" in val,
            "CONFIG_DB login should contain tacacs+ and local, got: {}".format(val)
        )

    def test_rest_delete_failthrough(self, duthost, mgmt_framework_available):
        set_aaa_config(duthost, "authentication", "failthrough", "True")
        resp = rest_api_call(
            duthost, "DELETE",
            "/restconf/data/openconfig-system:system/aaa/authentication/config/"
            "openconfig-system-ext:failthrough"
        )
        logger.info("REST DELETE failthrough: rc=%s", resp['rc'])
        pytest_assert(resp['rc'] == 0, "REST API DELETE call failed")

    def test_rest_patch_authorization(self, duthost, mgmt_framework_available):
        body = {
            "openconfig-system:config": {
                "authorization-method": ["tacacs+", "local"]
            }
        }
        resp = rest_api_call(
            duthost, "PATCH",
            "/restconf/data/openconfig-system:system/aaa/authorization/config",
            body
        )
        logger.info("REST PATCH authorization: rc=%s", resp['rc'])
        pytest_assert(resp['rc'] == 0, "REST API PATCH call failed")

    def test_rest_patch_accounting(self, duthost, mgmt_framework_available):
        body = {
            "openconfig-system:config": {
                "accounting-method": ["tacacs+", "local"]
            }
        }
        resp = rest_api_call(
            duthost, "PATCH",
            "/restconf/data/openconfig-system:system/aaa/accounting/config",
            body
        )
        logger.info("REST PATCH accounting: rc=%s", resp['rc'])
        pytest_assert(resp['rc'] == 0, "REST API PATCH call failed")


class TestAAAKlishCLI:

    def test_klish_show_aaa(self, duthost, mgmt_framework_available):
        result = run_klish_command(duthost, "show aaa")
        logger.info("Klish show aaa: rc=%s, stdout=%s", result['rc'], result['stdout'])
        if result['rc'] != 0:
            pytest.skip("Klish CLI not available: {}".format(result.get('stderr', '')))
        pytest_assert(
            "AAA authentication" in result['stdout'],
            "Klish show aaa should display AAA authentication info"
        )

    def test_klish_config_failthrough_enable(self, duthost, mgmt_framework_available):
        del_aaa_config(duthost, "authentication", "failthrough")
        result = run_klish_command(duthost, "configure terminal\naaa authentication failthrough enable\nexit")
        logger.info("Klish failthrough enable: rc=%s, stdout=%s", result['rc'], result['stdout'])
        if result['rc'] != 0:
            pytest.skip("Klish CLI not available")
        val = get_aaa_table_field(duthost, "authentication", "failthrough")
        pytest_assert(val == "True",
                      "CONFIG_DB failthrough should be True after Klish command, got: {}".format(val))

    def test_klish_config_failthrough_disable(self, duthost, mgmt_framework_available):
        set_aaa_config(duthost, "authentication", "failthrough", "True")
        result = run_klish_command(duthost, "configure terminal\naaa authentication failthrough disable\nexit")
        logger.info("Klish failthrough disable: rc=%s", result['rc'])
        if result['rc'] != 0:
            pytest.skip("Klish CLI not available")
        val = get_aaa_table_field(duthost, "authentication", "failthrough")
        pytest_assert(val == "False",
                      "CONFIG_DB failthrough should be False after Klish command, got: {}".format(val))

    def test_klish_config_login_methods(self, duthost, mgmt_framework_available):
        result = run_klish_command(
            duthost,
            "configure terminal\naaa authentication login tacacs+ local\nexit"
        )
        logger.info("Klish login methods: rc=%s", result['rc'])
        if result['rc'] != 0:
            pytest.skip("Klish CLI not available")
        val = get_aaa_table_field(duthost, "authentication", "login")
        if val is not None:
            pytest_assert(
                "tacacs+" in val and "local" in val,
                "CONFIG_DB login should contain tacacs+ and local, got: {}".format(val)
            )

    def test_klish_no_failthrough(self, duthost, mgmt_framework_available):
        set_aaa_config(duthost, "authentication", "failthrough", "True")
        result = run_klish_command(duthost, "configure terminal\nno aaa authentication failthrough\nexit")
        logger.info("Klish no failthrough: rc=%s", result['rc'])
        if result['rc'] != 0:
            pytest.skip("Klish CLI not available")
        val = get_aaa_table_field(duthost, "authentication", "failthrough")
        pytest_assert(val is None or val == "",
                      "CONFIG_DB failthrough should be unset after 'no' command, got: {}".format(val))

    def test_klish_config_authorization(self, duthost, mgmt_framework_available):
        result = run_klish_command(
            duthost,
            "configure terminal\naaa authorization tacacs+ local\nexit"
        )
        logger.info("Klish authorization: rc=%s", result['rc'])
        if result['rc'] != 0:
            pytest.skip("Klish CLI not available")

    def test_klish_config_accounting(self, duthost, mgmt_framework_available):
        result = run_klish_command(
            duthost,
            "configure terminal\naaa accounting tacacs+ local\nexit"
        )
        logger.info("Klish accounting: rc=%s", result['rc'])
        if result['rc'] != 0:
            pytest.skip("Klish CLI not available")

    def test_klish_no_authorization(self, duthost, mgmt_framework_available):
        set_aaa_config(duthost, "authorization", "login", "tacacs+")
        result = run_klish_command(duthost, "configure terminal\nno aaa authorization\nexit")
        logger.info("Klish no authorization: rc=%s", result['rc'])
        if result['rc'] != 0:
            pytest.skip("Klish CLI not available")

    def test_klish_no_accounting(self, duthost, mgmt_framework_available):
        set_aaa_config(duthost, "accounting", "login", "tacacs+")
        result = run_klish_command(duthost, "configure terminal\nno aaa accounting\nexit")
        logger.info("Klish no accounting: rc=%s", result['rc'])
        if result['rc'] != 0:
            pytest.skip("Klish CLI not available")


class TestAAAFullWorkflow:

    def test_full_aaa_configure_and_verify(self, duthost):
        del_aaa_table(duthost)
        output = get_show_aaa_output(duthost)
        parsed = parse_show_aaa(output)
        pytest_assert(
            "local" in parsed.get("authentication_login", ""),
            "Default login should be local"
        )

        set_aaa_config(duthost, "authentication", "failthrough", "True")
        set_aaa_config(duthost, "authentication", "fallback", "True")
        set_aaa_config(duthost, "authentication", "debug", "True")
        set_aaa_config(duthost, "authentication", "trace", "True")
        set_aaa_config(duthost, "authentication", "login", "tacacs+,local")
        set_aaa_config(duthost, "authorization", "login", "tacacs+,local")
        set_aaa_config(duthost, "accounting", "login", "tacacs+,local")

        output = get_show_aaa_output(duthost)
        parsed = parse_show_aaa(output)
        logger.info("Full config show aaa: %s", parsed)

        pytest_assert("True" in parsed.get("authentication_failthrough", ""),
                      "failthrough should be True")
        pytest_assert("True" in parsed.get("authentication_fallback", ""),
                      "fallback should be True")
        pytest_assert("True" in parsed.get("authentication_debug", ""),
                      "debug should be True")
        pytest_assert("True" in parsed.get("authentication_trace", ""),
                      "trace should be True")
        pytest_assert("tacacs+" in parsed.get("authentication_login", ""),
                      "login should contain tacacs+")
        pytest_assert("tacacs+" in parsed.get("authorization_login", ""),
                      "authorization should contain tacacs+")
        pytest_assert("tacacs+" in parsed.get("accounting_login", ""),
                      "accounting should contain tacacs+")

    def test_full_aaa_negate_and_verify(self, duthost):
        set_aaa_config(duthost, "authentication", "failthrough", "True")
        set_aaa_config(duthost, "authentication", "fallback", "True")
        set_aaa_config(duthost, "authentication", "debug", "True")
        set_aaa_config(duthost, "authentication", "trace", "True")
        set_aaa_config(duthost, "authentication", "login", "tacacs+,local")
        set_aaa_config(duthost, "authorization", "login", "tacacs+")
        set_aaa_config(duthost, "accounting", "login", "tacacs+")

        del_aaa_config(duthost, "authentication", "failthrough")
        del_aaa_config(duthost, "authentication", "fallback")
        del_aaa_config(duthost, "authentication", "debug")
        del_aaa_config(duthost, "authentication", "trace")
        del_aaa_config(duthost, "authentication", "login")
        del_aaa_config(duthost, "authorization", "login")
        del_aaa_config(duthost, "accounting", "login")

        output = get_show_aaa_output(duthost)
        parsed = parse_show_aaa(output)
        logger.info("After negate show aaa: %s", parsed)

        for line in output.strip().splitlines():
            line = line.strip()
            if line and line.startswith("AAA"):
                pytest_assert(
                    "default" in line.lower() or "local" in line.lower() or "disable" in line.lower(),
                    "After reset all, every AAA line should show default. Got: {}".format(line)
                )

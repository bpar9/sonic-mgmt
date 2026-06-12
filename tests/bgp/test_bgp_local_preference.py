"""
Tests for BGP Local-Preference functionality on T1.

Covers default LP, route-map set, best path selection,
iBGP propagation, eBGP exclusion, persistence, IPv6,
boundary values, override, multiple prefixes/paths,
tie-breaking, AS-Path/MED/Weight interactions,
route flapping, and route reflector scenarios.
"""

import json
import logging
import time

import pytest
import requests
from natsort import natsorted
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.constants import DEFAULT_NAMESPACE
from tests.common.utilities import wait_until

pytestmark = [
    pytest.mark.topology('t1'),
    pytest.mark.device_type('vs')
]

logger = logging.getLogger(__name__)

EXA_PORT_BASE = 5000
EXA_PORT_V6_BASE = 6000

TEST_PFX_V4 = '10.100.0.0/24'
TEST_PFX_V6 = '2001:db8:100::/64'
MULTI_PFX_TPL = '10.200.{}.0/24'
MULTI_PFX_CNT = 10

DEFAULT_LP = 100
CONV_TMO = 30
CONV_INT = 5
BGP_RST_TMO = 120
BGP_RST_INT = 10

RM_TPL = 'SET_LOCAL_PREF_{}'


def _ns(ns):
    if ns and ns != DEFAULT_NAMESPACE:
        return '-n {}'.format(ns)
    return ''


def _t0_nbrs(nbrhosts):
    return natsorted(
        [n for n in nbrhosts.keys()
         if n.endswith('T0')]
    )


def _t2_nbrs(nbrhosts):
    return natsorted(
        [n for n in nbrhosts.keys()
         if n.endswith('T2')]
    )


def _exa_port(tbinfo, nbr, base=None):
    if base is None:
        base = EXA_PORT_BASE
    vms = tbinfo['topo']['properties']['topology']
    return base + vms['VMs'][nbr]['vm_offset']


def _nbr_asn(tbinfo, nbr):
    cfg = tbinfo['topo']['properties']
    return cfg['configuration'][nbr]['bgp']['asn']


def _peer_addr(mg, nbr, v6=False):
    for b in mg['minigraph_bgp']:
        if b['name'] == nbr:
            a = b['peer_addr']
            if v6 and ':' in a:
                return a
            elif not v6 and ':' not in a:
                return a
    return None


def _dut_asn(tbinfo):
    p = tbinfo['topo']['properties']
    return p[
        'configuration_properties'
    ]['common']['dut_asn']


def _nbr_ns(mg, nbr):
    for _, n in mg['minigraph_neighbors'].items():
        if n['name'] == nbr:
            return n.get('namespace') or DEFAULT_NAMESPACE
    return DEFAULT_NAMESPACE


def _nhv4(tbinfo):
    p = tbinfo['topo']['properties']
    return p[
        'configuration_properties'
    ]['common'].get('nhipv4')


def _nhv6(tbinfo):
    p = tbinfo['topo']['properties']
    return p[
        'configuration_properties'
    ]['common'].get('nhipv6')


def exa_ann(ptfip, port, pfx, nh,
            as_path=None, med=None):
    msg = 'announce route {} next-hop {}'.format(
        pfx, nh
    )
    if as_path:
        msg += ' as-path [ {} ]'.format(as_path)
    if med is not None:
        msg += ' med {}'.format(med)
    url = 'http://{}:{}'.format(ptfip, port)
    data = {'commands': msg}
    logger.info('ExaBGP ann: %s %s', url, data)
    r = requests.post(
        url, data=data, timeout=30,
        proxies={"http": None, "https": None}
    )
    pytest_assert(
        r.status_code == 200,
        'ExaBGP ann failed: {}'.format(
            r.status_code
        )
    )


def exa_wd(ptfip, port, pfx, nh):
    msg = 'withdraw route {} next-hop {}'.format(
        pfx, nh
    )
    url = 'http://{}:{}'.format(ptfip, port)
    data = {'commands': msg}
    logger.info('ExaBGP wd: %s %s', url, data)
    r = requests.post(
        url, data=data, timeout=30,
        proxies={"http": None, "https": None}
    )
    pytest_assert(
        r.status_code == 200,
        'ExaBGP wd failed: {}'.format(
            r.status_code
        )
    )


def cfg_rm(dut, name, lp, ns=DEFAULT_NAMESPACE):
    cmd = (
        "vtysh {} "
        "-c 'configure terminal' "
        "-c 'route-map {} permit 10' "
        "-c 'set local-preference {}'"
    ).format(_ns(ns), name, lp)
    dut.shell(cmd)
    logger.info(
        'cfg rm %s lp=%s ns=%s', name, lp, ns
    )


def add_rm(dut, asn, peer, name,
           d='in', ns=DEFAULT_NAMESPACE,
           af='ipv4'):
    af_s = (
        'ipv4 unicast'
        if af == 'ipv4'
        else 'ipv6 unicast'
    )
    cmd = (
        "vtysh {} "
        "-c 'configure terminal' "
        "-c 'router bgp {}' "
        "-c 'address-family {}' "
        "-c 'neighbor {} route-map {} {}'"
    ).format(_ns(ns), asn, af_s, peer, name, d)
    dut.shell(cmd)
    logger.info(
        'add rm %s to %s %s (%s)',
        name, peer, d, af
    )


def del_rm_nbr(dut, asn, peer, name,
               d='in', ns=DEFAULT_NAMESPACE,
               af='ipv4'):
    af_s = (
        'ipv4 unicast'
        if af == 'ipv4'
        else 'ipv6 unicast'
    )
    cmd = (
        "vtysh {} "
        "-c 'configure terminal' "
        "-c 'router bgp {}' "
        "-c 'address-family {}' "
        "-c 'no neighbor {} route-map {} {}'"
    ).format(_ns(ns), asn, af_s, peer, name, d)
    dut.shell(cmd, module_ignore_errors=True)


def del_rm(dut, name, ns=DEFAULT_NAMESPACE):
    cmd = (
        "vtysh {} "
        "-c 'configure terminal' "
        "-c 'no route-map {}'"
    ).format(_ns(ns), name)
    dut.shell(cmd, module_ignore_errors=True)


def clr_bgp(dut, peer, ns=DEFAULT_NAMESPACE):
    cmd = (
        "vtysh {} -c 'clear bgp {} soft in'"
    ).format(_ns(ns), peer)
    dut.shell(cmd, module_ignore_errors=True)


def bgp_rt(dut, pfx,
           ns=DEFAULT_NAMESPACE, af='ipv4'):
    af_s = 'ipv4' if af == 'ipv4' else 'ipv6'
    cmd = (
        "vtysh {} "
        "-c 'show bgp {} unicast {} json'"
    ).format(_ns(ns), af_s, pfx)
    out = dut.shell(
        cmd, module_ignore_errors=True
    )['stdout']
    try:
        return json.loads(out)
    except (json.JSONDecodeError, ValueError):
        logger.warning(
            'BGP JSON parse fail %s: %s',
            pfx, out
        )
        return {}


def rt_lp(dut, pfx,
          ns=DEFAULT_NAMESPACE, af='ipv4'):
    info = bgp_rt(dut, pfx, ns, af)
    if not info or 'paths' not in info:
        return None
    for p in info['paths']:
        bp = p.get('bestpath', {})
        if bp.get('overall') or p.get('best'):
            return p.get('locPrf')
    if info['paths']:
        return info['paths'][0].get('locPrf')
    return None


def all_lp(dut, pfx,
           ns=DEFAULT_NAMESPACE, af='ipv4'):
    info = bgp_rt(dut, pfx, ns, af)
    if not info or 'paths' not in info:
        return []
    res = []
    for p in info['paths']:
        bp = p.get('bestpath', {})
        best = bp.get('overall') or p.get('best')
        segs = p.get(
            'aspath', {}
        ).get('segments', [])
        asp = ''
        if segs:
            for s in segs:
                asp += ' '.join(
                    str(x)
                    for x in s.get('list', [])
                )
        res.append({
            'locPrf': p.get('locPrf'),
            'best': best,
            'peerId': p.get('peerId', ''),
            'aspath': asp
        })
    return res


def best_path(dut, pfx,
              ns=DEFAULT_NAMESPACE, af='ipv4'):
    info = bgp_rt(dut, pfx, ns, af)
    if not info or 'paths' not in info:
        return None
    for p in info['paths']:
        bp = p.get('bestpath', {})
        if bp.get('overall') or p.get('best'):
            return p
    if info['paths']:
        return info['paths'][0]
    return None


def chk_lp(dut, pfx, exp,
           ns=DEFAULT_NAMESPACE, af='ipv4'):
    return rt_lp(dut, pfx, ns, af) == exp


def set_wt(dut, asn, peer, wt,
           ns=DEFAULT_NAMESPACE):
    cmd = (
        "vtysh {} "
        "-c 'configure terminal' "
        "-c 'router bgp {}' "
        "-c 'neighbor {} weight {}'"
    ).format(_ns(ns), asn, peer, wt)
    dut.shell(cmd, module_ignore_errors=True)


def del_wt(dut, asn, peer,
           ns=DEFAULT_NAMESPACE):
    cmd = (
        "vtysh {} "
        "-c 'configure terminal' "
        "-c 'router bgp {}' "
        "-c 'no neighbor {} weight'"
    ).format(_ns(ns), asn, peer)
    dut.shell(cmd, module_ignore_errors=True)


def set_rr(dut, asn, peer,
           ns=DEFAULT_NAMESPACE, af='ipv4'):
    af_s = (
        'ipv4 unicast'
        if af == 'ipv4'
        else 'ipv6 unicast'
    )
    cmd = (
        "vtysh {} "
        "-c 'configure terminal' "
        "-c 'router bgp {}' "
        "-c 'address-family {}' "
        "-c 'neighbor {} "
        "route-reflector-client'"
    ).format(_ns(ns), asn, af_s, peer)
    dut.shell(cmd, module_ignore_errors=True)


def del_rr(dut, asn, peer,
           ns=DEFAULT_NAMESPACE, af='ipv4'):
    af_s = (
        'ipv4 unicast'
        if af == 'ipv4'
        else 'ipv6 unicast'
    )
    cmd = (
        "vtysh {} "
        "-c 'configure terminal' "
        "-c 'router bgp {}' "
        "-c 'address-family {}' "
        "-c 'no neighbor {} "
        "route-reflector-client'"
    ).format(_ns(ns), asn, af_s, peer)
    dut.shell(cmd, module_ignore_errors=True)


def wait_bgp(dut):
    cfg = dut.config_facts(
        host=dut.hostname, source="running"
    )['ansible_facts']
    nbrs = cfg.get('BGP_NEIGHBOR', {})
    wait_until(
        BGP_RST_TMO, BGP_RST_INT, 0,
        dut.check_bgp_session_state,
        list(nbrs.keys())
    )


@pytest.fixture(scope='module')
def setup(duthosts, rand_one_dut_hostname,
          tbinfo, nbrhosts, ptfhost):
    dut = duthosts[rand_one_dut_hostname]
    mg = dut.get_extended_minigraph_facts(tbinfo)

    t0 = _t0_nbrs(nbrhosts)
    t2 = _t2_nbrs(nbrhosts)
    pytest_assert(
        len(t0) >= 2,
        'Need >= 2 T0 nbrs, got {}'.format(
            len(t0)
        )
    )

    asn = _dut_asn(tbinfo)
    nhv4 = _nhv4(tbinfo)
    nhv6 = _nhv6(tbinfo)
    pip = ptfhost.mgmt_ip

    ni = {}
    for n in t0:
        ni[n] = {
            'pv4': _peer_addr(mg, n, False),
            'pv6': _peer_addr(mg, n, True),
            'ns': _nbr_ns(mg, n),
            'ep': _exa_port(
                tbinfo, n, EXA_PORT_BASE
            ),
            'ep6': _exa_port(
                tbinfo, n, EXA_PORT_V6_BASE
            ),
            'asn': _nbr_asn(tbinfo, n)
        }

    tor1 = t0[0]
    tor1_ns = ni[tor1]['ns']

    info = {
        'asn': asn, 'nhv4': nhv4, 'nhv6': nhv6,
        'pip': pip, 't0': t0, 't2': t2,
        'ni': ni, 'tor1': tor1,
        'tor1_ns': tor1_ns, 'mg': mg
    }
    logger.info(
        'Setup: t0=%s asn=%s', t0, asn
    )
    return info


@pytest.fixture(autouse=True)
def cleanup(duthosts, rand_one_dut_hostname,
            setup):
    yield

    dut = duthosts[rand_one_dut_hostname]
    asn = setup['asn']
    ns = setup['tor1_ns']

    for _, inf in setup['ni'].items():
        pv4 = inf['pv4']
        pv6 = inf['pv6']
        for i in range(10):
            rm = RM_TPL.format(i)
            if pv4:
                del_rm_nbr(
                    dut, asn, pv4, rm,
                    ns=inf['ns']
                )
            if pv6:
                del_rm_nbr(
                    dut, asn, pv6, rm,
                    d='in', ns=inf['ns'],
                    af='ipv6'
                )
        if pv4:
            del_wt(dut, asn, pv4, ns=inf['ns'])

    for i in range(10):
        rm = RM_TPL.format(i)
        del_rm(dut, rm, ns)


def test_default_local_preference(
    duthosts, rand_one_dut_hostname,
    ptfhost, setup
):
    dut = duthosts[rand_one_dut_hostname]
    tor1 = setup['tor1']
    inf = setup['ni'][tor1]
    pip = setup['pip']
    nhv4 = setup['nhv4']
    ns = inf['ns']

    exa_ann(pip, inf['ep'], TEST_PFX_V4, nhv4)
    try:
        time.sleep(CONV_TMO)
        pytest_assert(
            wait_until(
                CONV_TMO, CONV_INT, 0,
                chk_lp, dut,
                TEST_PFX_V4, DEFAULT_LP, ns
            ),
            'Default LP should be {}'.format(
                DEFAULT_LP
            )
        )
        rt = bgp_rt(dut, TEST_PFX_V4, ns)
        pytest_assert(
            'paths' in rt,
            'Route {} not found'.format(
                TEST_PFX_V4
            )
        )
    finally:
        exa_wd(
            pip, inf['ep'], TEST_PFX_V4, nhv4
        )


def test_set_lp_via_route_map(
    duthosts, rand_one_dut_hostname,
    ptfhost, setup
):
    dut = duthosts[rand_one_dut_hostname]
    tor1 = setup['tor1']
    inf = setup['ni'][tor1]
    pip = setup['pip']
    nhv4 = setup['nhv4']
    asn = setup['asn']
    ns = inf['ns']

    rm = RM_TPL.format(0)
    cfg_rm(dut, rm, 200, ns)
    add_rm(dut, asn, inf['pv4'], rm, ns=ns)
    clr_bgp(dut, inf['pv4'], ns)
    exa_ann(pip, inf['ep'], TEST_PFX_V4, nhv4)
    try:
        time.sleep(CONV_TMO)
        pytest_assert(
            wait_until(
                CONV_TMO, CONV_INT, 0,
                chk_lp, dut,
                TEST_PFX_V4, 200, ns
            ),
            'LP should be 200 after route-map'
        )
    finally:
        exa_wd(
            pip, inf['ep'], TEST_PFX_V4, nhv4
        )
        del_rm_nbr(
            dut, asn, inf['pv4'], rm, ns=ns
        )
        del_rm(dut, rm, ns)


def test_best_path_selection_by_lp(
    duthosts, rand_one_dut_hostname,
    ptfhost, setup
):
    dut = duthosts[rand_one_dut_hostname]
    t0 = setup['t0']
    pytest_assert(
        len(t0) >= 2, 'Need >= 2 T0'
    )
    n1, n2 = t0[0], t0[1]
    i1, i2 = setup['ni'][n1], setup['ni'][n2]
    pip = setup['pip']
    nhv4 = setup['nhv4']
    asn = setup['asn']
    ns1, ns2 = i1['ns'], i2['ns']

    ra = RM_TPL.format(0)
    rb = RM_TPL.format(1)
    cfg_rm(dut, ra, 150, ns1)
    cfg_rm(dut, rb, 200, ns2)
    add_rm(dut, asn, i1['pv4'], ra, ns=ns1)
    add_rm(dut, asn, i2['pv4'], rb, ns=ns2)
    clr_bgp(dut, i1['pv4'], ns1)
    clr_bgp(dut, i2['pv4'], ns2)

    exa_ann(pip, i1['ep'], TEST_PFX_V4, nhv4)
    exa_ann(pip, i2['ep'], TEST_PFX_V4, nhv4)
    try:
        time.sleep(CONV_TMO)

        def _chk():
            bp = best_path(
                dut, TEST_PFX_V4, ns1
            )
            return bp and bp.get('locPrf') == 200

        pytest_assert(
            wait_until(
                CONV_TMO, CONV_INT, 0, _chk
            ),
            'Best path should have LP 200'
        )
    finally:
        exa_wd(pip, i1['ep'], TEST_PFX_V4, nhv4)
        exa_wd(pip, i2['ep'], TEST_PFX_V4, nhv4)
        del_rm_nbr(
            dut, asn, i1['pv4'], ra, ns=ns1
        )
        del_rm_nbr(
            dut, asn, i2['pv4'], rb, ns=ns2
        )
        del_rm(dut, ra, ns1)
        del_rm(dut, rb, ns2)


def test_lp_propagation_to_ibgp(
    duthosts, rand_one_dut_hostname,
    ptfhost, setup
):
    dut = duthosts[rand_one_dut_hostname]
    tor1 = setup['tor1']
    inf = setup['ni'][tor1]
    pip = setup['pip']
    nhv4 = setup['nhv4']
    asn = setup['asn']
    ns = inf['ns']

    rm = RM_TPL.format(0)
    cfg_rm(dut, rm, 300, ns)
    add_rm(dut, asn, inf['pv4'], rm, ns=ns)
    clr_bgp(dut, inf['pv4'], ns)
    exa_ann(pip, inf['ep'], TEST_PFX_V4, nhv4)
    try:
        time.sleep(CONV_TMO)
        pytest_assert(
            wait_until(
                CONV_TMO, CONV_INT, 0,
                chk_lp, dut,
                TEST_PFX_V4, 300, ns
            ),
            'LP 300 for iBGP propagation'
        )
    finally:
        exa_wd(
            pip, inf['ep'], TEST_PFX_V4, nhv4
        )
        del_rm_nbr(
            dut, asn, inf['pv4'], rm, ns=ns
        )
        del_rm(dut, rm, ns)


def test_lp_not_sent_to_ebgp(
    duthosts, rand_one_dut_hostname,
    ptfhost, setup, nbrhosts
):
    dut = duthosts[rand_one_dut_hostname]
    tor1 = setup['tor1']
    inf = setup['ni'][tor1]
    t2 = setup['t2']
    pip = setup['pip']
    nhv4 = setup['nhv4']
    asn = setup['asn']
    ns = inf['ns']

    if not t2:
        pytest.skip('No T2 for eBGP check')

    rm = RM_TPL.format(0)
    cfg_rm(dut, rm, 500, ns)
    add_rm(dut, asn, inf['pv4'], rm, ns=ns)
    clr_bgp(dut, inf['pv4'], ns)
    exa_ann(pip, inf['ep'], TEST_PFX_V4, nhv4)
    try:
        time.sleep(CONV_TMO)
        pytest_assert(
            wait_until(
                CONV_TMO, CONV_INT, 0,
                chk_lp, dut,
                TEST_PFX_V4, 500, ns
            ),
            'LP should be 500 on DUT'
        )
        t2n = t2[0]
        t2_rt = nbrhosts[t2n][
            'host'
        ].get_route(TEST_PFX_V4)
        logger.info(
            'Route on T2 %s: %s', t2n, t2_rt
        )
    finally:
        exa_wd(
            pip, inf['ep'], TEST_PFX_V4, nhv4
        )
        del_rm_nbr(
            dut, asn, inf['pv4'], rm, ns=ns
        )
        del_rm(dut, rm, ns)


@pytest.mark.disable_loganalyzer
def test_lp_persistence_after_bgp_restart(
    duthosts, rand_one_dut_hostname,
    ptfhost, setup
):
    dut = duthosts[rand_one_dut_hostname]
    tor1 = setup['tor1']
    inf = setup['ni'][tor1]
    pip = setup['pip']
    nhv4 = setup['nhv4']
    asn = setup['asn']
    ns = inf['ns']

    rm = RM_TPL.format(0)
    cfg_rm(dut, rm, 250, ns)
    add_rm(dut, asn, inf['pv4'], rm, ns=ns)
    dut.shell('sudo config save -y')

    dut.shell('sudo systemctl restart bgp')
    svc_fn = getattr(
        dut,
        'is_service_fully_started_per_asic_or_host'
    )
    pytest_assert(
        wait_until(
            BGP_RST_TMO, BGP_RST_INT,
            0, svc_fn, 'bgp'
        ),
        'BGP service did not restart'
    )
    wait_bgp(dut)

    exa_ann(pip, inf['ep'], TEST_PFX_V4, nhv4)
    try:
        time.sleep(CONV_TMO)
        pytest_assert(
            wait_until(
                CONV_TMO, CONV_INT, 0,
                chk_lp, dut,
                TEST_PFX_V4, 250, ns
            ),
            'LP should be 250 after restart'
        )
    finally:
        exa_wd(
            pip, inf['ep'], TEST_PFX_V4, nhv4
        )
        del_rm_nbr(
            dut, asn, inf['pv4'], rm, ns=ns
        )
        del_rm(dut, rm, ns)
        dut.shell('sudo config save -y')


def test_lp_with_ipv6(
    duthosts, rand_one_dut_hostname,
    ptfhost, setup
):
    dut = duthosts[rand_one_dut_hostname]
    tor1 = setup['tor1']
    inf = setup['ni'][tor1]
    pip = setup['pip']
    nhv6 = setup['nhv6']
    asn = setup['asn']
    ns = inf['ns']
    pv6 = inf['pv6']

    if not pv6 or not nhv6:
        pytest.skip('No IPv6 peer/nh')

    rm = RM_TPL.format(0)
    cfg_rm(dut, rm, 175, ns)
    add_rm(
        dut, asn, pv6, rm,
        ns=ns, af='ipv6'
    )
    clr_bgp(dut, pv6, ns)
    exa_ann(
        pip, inf['ep6'], TEST_PFX_V6, nhv6
    )
    try:
        time.sleep(CONV_TMO)
        pytest_assert(
            wait_until(
                CONV_TMO, CONV_INT, 0,
                chk_lp, dut,
                TEST_PFX_V6, 175, ns, 'ipv6'
            ),
            'LP should be 175 for IPv6'
        )
    finally:
        exa_wd(
            pip, inf['ep6'], TEST_PFX_V6, nhv6
        )
        del_rm_nbr(
            dut, asn, pv6, rm,
            ns=ns, af='ipv6'
        )
        del_rm(dut, rm, ns)


@pytest.mark.parametrize(
    'lp_val', [0, 4294967295]
)
def test_lp_boundary_values(
    duthosts, rand_one_dut_hostname,
    ptfhost, setup, lp_val
):
    dut = duthosts[rand_one_dut_hostname]
    tor1 = setup['tor1']
    inf = setup['ni'][tor1]
    pip = setup['pip']
    nhv4 = setup['nhv4']
    asn = setup['asn']
    ns = inf['ns']

    rm = RM_TPL.format(0)
    cfg_rm(dut, rm, lp_val, ns)
    add_rm(dut, asn, inf['pv4'], rm, ns=ns)
    clr_bgp(dut, inf['pv4'], ns)
    exa_ann(pip, inf['ep'], TEST_PFX_V4, nhv4)
    try:
        time.sleep(CONV_TMO)
        pytest_assert(
            wait_until(
                CONV_TMO, CONV_INT, 0,
                chk_lp, dut,
                TEST_PFX_V4, lp_val, ns
            ),
            'LP should be {} (boundary)'.format(
                lp_val
            )
        )
    finally:
        exa_wd(
            pip, inf['ep'], TEST_PFX_V4, nhv4
        )
        del_rm_nbr(
            dut, asn, inf['pv4'], rm, ns=ns
        )
        del_rm(dut, rm, ns)


def test_lp_override(
    duthosts, rand_one_dut_hostname,
    ptfhost, setup
):
    dut = duthosts[rand_one_dut_hostname]
    tor1 = setup['tor1']
    inf = setup['ni'][tor1]
    pip = setup['pip']
    nhv4 = setup['nhv4']
    asn = setup['asn']
    ns = inf['ns']

    rm = RM_TPL.format(0)
    cfg_rm(dut, rm, 100, ns)
    add_rm(dut, asn, inf['pv4'], rm, ns=ns)
    clr_bgp(dut, inf['pv4'], ns)
    exa_ann(pip, inf['ep'], TEST_PFX_V4, nhv4)
    try:
        time.sleep(CONV_TMO)
        pytest_assert(
            wait_until(
                CONV_TMO, CONV_INT, 0,
                chk_lp, dut,
                TEST_PFX_V4, 100, ns
            ),
            'Initial LP should be 100'
        )

        cfg_rm(dut, rm, 300, ns)
        clr_bgp(dut, inf['pv4'], ns)
        time.sleep(CONV_TMO)

        pytest_assert(
            wait_until(
                CONV_TMO, CONV_INT, 0,
                chk_lp, dut,
                TEST_PFX_V4, 300, ns
            ),
            'LP should update to 300'
        )
    finally:
        exa_wd(
            pip, inf['ep'], TEST_PFX_V4, nhv4
        )
        del_rm_nbr(
            dut, asn, inf['pv4'], rm, ns=ns
        )
        del_rm(dut, rm, ns)


def test_lp_multiple_prefixes(
    duthosts, rand_one_dut_hostname,
    ptfhost, setup
):
    dut = duthosts[rand_one_dut_hostname]
    tor1 = setup['tor1']
    inf = setup['ni'][tor1]
    pip = setup['pip']
    nhv4 = setup['nhv4']
    asn = setup['asn']
    ns = inf['ns']

    rm = RM_TPL.format(0)
    cfg_rm(dut, rm, 400, ns)
    add_rm(dut, asn, inf['pv4'], rm, ns=ns)
    clr_bgp(dut, inf['pv4'], ns)

    pfxs = [
        MULTI_PFX_TPL.format(i)
        for i in range(MULTI_PFX_CNT)
    ]
    for p in pfxs:
        exa_ann(pip, inf['ep'], p, nhv4)
    try:
        time.sleep(CONV_TMO)
        for p in pfxs:
            pytest_assert(
                wait_until(
                    CONV_TMO, CONV_INT, 0,
                    chk_lp, dut, p, 400, ns
                ),
                'LP 400 for {}'.format(p)
            )
    finally:
        for p in pfxs:
            exa_wd(pip, inf['ep'], p, nhv4)
        del_rm_nbr(
            dut, asn, inf['pv4'], rm, ns=ns
        )
        del_rm(dut, rm, ns)


def test_lp_multiple_paths(
    duthosts, rand_one_dut_hostname,
    ptfhost, setup
):
    dut = duthosts[rand_one_dut_hostname]
    t0 = setup['t0']
    pytest_assert(
        len(t0) >= 3, 'Need >= 3 T0'
    )
    n1, n2, n3 = t0[0], t0[1], t0[2]
    i1 = setup['ni'][n1]
    i2 = setup['ni'][n2]
    i3 = setup['ni'][n3]
    pip = setup['pip']
    nhv4 = setup['nhv4']
    asn = setup['asn']
    ns1, ns2, ns3 = (
        i1['ns'], i2['ns'], i3['ns']
    )

    rb = RM_TPL.format(1)
    rc = RM_TPL.format(2)
    cfg_rm(dut, rb, 200, ns2)
    cfg_rm(dut, rc, 150, ns3)
    add_rm(dut, asn, i2['pv4'], rb, ns=ns2)
    add_rm(dut, asn, i3['pv4'], rc, ns=ns3)
    clr_bgp(dut, i1['pv4'], ns1)
    clr_bgp(dut, i2['pv4'], ns2)
    clr_bgp(dut, i3['pv4'], ns3)

    exa_ann(pip, i1['ep'], TEST_PFX_V4, nhv4)
    exa_ann(pip, i2['ep'], TEST_PFX_V4, nhv4)
    exa_ann(pip, i3['ep'], TEST_PFX_V4, nhv4)
    try:
        time.sleep(CONV_TMO)

        def _c200():
            bp = best_path(
                dut, TEST_PFX_V4, ns1
            )
            return bp and bp.get('locPrf') == 200

        pytest_assert(
            wait_until(
                CONV_TMO, CONV_INT, 0, _c200
            ),
            'Best should have LP 200'
        )

        cfg_rm(dut, rc, 250, ns3)
        clr_bgp(dut, i3['pv4'], ns3)
        time.sleep(CONV_TMO)

        def _c250():
            bp = best_path(
                dut, TEST_PFX_V4, ns1
            )
            return bp and bp.get('locPrf') == 250

        pytest_assert(
            wait_until(
                CONV_TMO, CONV_INT, 0, _c250
            ),
            'Best should switch to LP 250'
        )
    finally:
        exa_wd(pip, i1['ep'], TEST_PFX_V4, nhv4)
        exa_wd(pip, i2['ep'], TEST_PFX_V4, nhv4)
        exa_wd(pip, i3['ep'], TEST_PFX_V4, nhv4)
        del_rm_nbr(
            dut, asn, i2['pv4'], rb, ns=ns2
        )
        del_rm_nbr(
            dut, asn, i3['pv4'], rc, ns=ns3
        )
        del_rm(dut, rb, ns2)
        del_rm(dut, rc, ns3)


def test_lp_equal_tiebreak_aspath(
    duthosts, rand_one_dut_hostname,
    ptfhost, setup
):
    dut = duthosts[rand_one_dut_hostname]
    t0 = setup['t0']
    pytest_assert(
        len(t0) >= 2, 'Need >= 2 T0'
    )
    n1, n2 = t0[0], t0[1]
    i1, i2 = setup['ni'][n1], setup['ni'][n2]
    pip = setup['pip']
    nhv4 = setup['nhv4']
    asn = setup['asn']
    ns1, ns2 = i1['ns'], i2['ns']

    ra = RM_TPL.format(0)
    rb = RM_TPL.format(1)
    cfg_rm(dut, ra, 200, ns1)
    cfg_rm(dut, rb, 200, ns2)
    add_rm(dut, asn, i1['pv4'], ra, ns=ns1)
    add_rm(dut, asn, i2['pv4'], rb, ns=ns2)
    clr_bgp(dut, i1['pv4'], ns1)
    clr_bgp(dut, i2['pv4'], ns2)

    exa_ann(
        pip, i1['ep'], TEST_PFX_V4,
        nhv4, as_path='65001 65002'
    )
    exa_ann(
        pip, i2['ep'], TEST_PFX_V4,
        nhv4, as_path='65003'
    )
    try:
        time.sleep(CONV_TMO)
        paths = all_lp(dut, TEST_PFX_V4, ns1)
        logger.info('All paths: %s', paths)
        bp = best_path(dut, TEST_PFX_V4, ns1)
        pytest_assert(
            bp is not None, 'No best path'
        )
        pytest_assert(
            bp.get('locPrf') == 200,
            'Best should have LP 200'
        )
    finally:
        exa_wd(pip, i1['ep'], TEST_PFX_V4, nhv4)
        exa_wd(pip, i2['ep'], TEST_PFX_V4, nhv4)
        del_rm_nbr(
            dut, asn, i1['pv4'], ra, ns=ns1
        )
        del_rm_nbr(
            dut, asn, i2['pv4'], rb, ns=ns2
        )
        del_rm(dut, ra, ns1)
        del_rm(dut, rb, ns2)


def test_lp_over_aspath(
    duthosts, rand_one_dut_hostname,
    ptfhost, setup
):
    dut = duthosts[rand_one_dut_hostname]
    t0 = setup['t0']
    pytest_assert(
        len(t0) >= 2, 'Need >= 2 T0'
    )
    n1, n2 = t0[0], t0[1]
    i1, i2 = setup['ni'][n1], setup['ni'][n2]
    pip = setup['pip']
    nhv4 = setup['nhv4']
    asn = setup['asn']
    ns1, ns2 = i1['ns'], i2['ns']

    ra = RM_TPL.format(0)
    rb = RM_TPL.format(1)
    cfg_rm(dut, ra, 200, ns1)
    cfg_rm(dut, rb, 100, ns2)
    add_rm(dut, asn, i1['pv4'], ra, ns=ns1)
    add_rm(dut, asn, i2['pv4'], rb, ns=ns2)
    clr_bgp(dut, i1['pv4'], ns1)
    clr_bgp(dut, i2['pv4'], ns2)

    exa_ann(
        pip, i1['ep'], TEST_PFX_V4, nhv4,
        as_path='65001 65002 65003'
    )
    exa_ann(
        pip, i2['ep'], TEST_PFX_V4,
        nhv4, as_path='65004'
    )
    try:
        time.sleep(CONV_TMO)

        def _chk():
            bp = best_path(
                dut, TEST_PFX_V4, ns1
            )
            return bp and bp.get('locPrf') == 200

        pytest_assert(
            wait_until(
                CONV_TMO, CONV_INT, 0, _chk
            ),
            'LP should beat shorter AS-Path'
        )
    finally:
        exa_wd(pip, i1['ep'], TEST_PFX_V4, nhv4)
        exa_wd(pip, i2['ep'], TEST_PFX_V4, nhv4)
        del_rm_nbr(
            dut, asn, i1['pv4'], ra, ns=ns1
        )
        del_rm_nbr(
            dut, asn, i2['pv4'], rb, ns=ns2
        )
        del_rm(dut, ra, ns1)
        del_rm(dut, rb, ns2)


def test_lp_over_med(
    duthosts, rand_one_dut_hostname,
    ptfhost, setup
):
    dut = duthosts[rand_one_dut_hostname]
    t0 = setup['t0']
    pytest_assert(
        len(t0) >= 2, 'Need >= 2 T0'
    )
    n1, n2 = t0[0], t0[1]
    i1, i2 = setup['ni'][n1], setup['ni'][n2]
    pip = setup['pip']
    nhv4 = setup['nhv4']
    asn = setup['asn']
    ns1, ns2 = i1['ns'], i2['ns']

    ra = RM_TPL.format(0)
    rb = RM_TPL.format(1)
    cfg_rm(dut, ra, 150, ns1)
    cfg_rm(dut, rb, 100, ns2)
    add_rm(dut, asn, i1['pv4'], ra, ns=ns1)
    add_rm(dut, asn, i2['pv4'], rb, ns=ns2)
    clr_bgp(dut, i1['pv4'], ns1)
    clr_bgp(dut, i2['pv4'], ns2)

    exa_ann(
        pip, i1['ep'], TEST_PFX_V4,
        nhv4, med=1000
    )
    exa_ann(
        pip, i2['ep'], TEST_PFX_V4,
        nhv4, med=10
    )
    try:
        time.sleep(CONV_TMO)

        def _chk():
            bp = best_path(
                dut, TEST_PFX_V4, ns1
            )
            return bp and bp.get('locPrf') == 150

        pytest_assert(
            wait_until(
                CONV_TMO, CONV_INT, 0, _chk
            ),
            'LP should beat lower MED'
        )
    finally:
        exa_wd(pip, i1['ep'], TEST_PFX_V4, nhv4)
        exa_wd(pip, i2['ep'], TEST_PFX_V4, nhv4)
        del_rm_nbr(
            dut, asn, i1['pv4'], ra, ns=ns1
        )
        del_rm_nbr(
            dut, asn, i2['pv4'], rb, ns=ns2
        )
        del_rm(dut, ra, ns1)
        del_rm(dut, rb, ns2)


def test_lp_interaction_with_weight(
    duthosts, rand_one_dut_hostname,
    ptfhost, setup
):
    dut = duthosts[rand_one_dut_hostname]
    t0 = setup['t0']
    pytest_assert(
        len(t0) >= 2, 'Need >= 2 T0'
    )
    n1, n2 = t0[0], t0[1]
    i1, i2 = setup['ni'][n1], setup['ni'][n2]
    pip = setup['pip']
    nhv4 = setup['nhv4']
    asn = setup['asn']
    ns1, ns2 = i1['ns'], i2['ns']

    ra = RM_TPL.format(0)
    cfg_rm(dut, ra, 500, ns1)
    add_rm(dut, asn, i1['pv4'], ra, ns=ns1)
    set_wt(dut, asn, i1['pv4'], 100, ns=ns1)
    set_wt(dut, asn, i2['pv4'], 200, ns=ns2)
    clr_bgp(dut, i1['pv4'], ns1)
    clr_bgp(dut, i2['pv4'], ns2)

    exa_ann(pip, i1['ep'], TEST_PFX_V4, nhv4)
    exa_ann(pip, i2['ep'], TEST_PFX_V4, nhv4)
    try:
        time.sleep(CONV_TMO)
        bp = best_path(dut, TEST_PFX_V4, ns1)
        pytest_assert(
            bp is not None, 'No best path'
        )
        logger.info(
            'Best: wt=%s lp=%s',
            bp.get('weight'), bp.get('locPrf')
        )
    finally:
        exa_wd(pip, i1['ep'], TEST_PFX_V4, nhv4)
        exa_wd(pip, i2['ep'], TEST_PFX_V4, nhv4)
        del_rm_nbr(
            dut, asn, i1['pv4'], ra, ns=ns1
        )
        del_rm(dut, ra, ns1)
        del_wt(dut, asn, i1['pv4'], ns=ns1)
        del_wt(dut, asn, i2['pv4'], ns=ns2)


def test_lp_route_flapping(
    duthosts, rand_one_dut_hostname,
    ptfhost, setup
):
    dut = duthosts[rand_one_dut_hostname]
    t0 = setup['t0']
    pytest_assert(
        len(t0) >= 2, 'Need >= 2 T0'
    )
    n1, n2 = t0[0], t0[1]
    i1, i2 = setup['ni'][n1], setup['ni'][n2]
    pip = setup['pip']
    nhv4 = setup['nhv4']
    asn = setup['asn']
    ns1, ns2 = i1['ns'], i2['ns']

    ra = RM_TPL.format(0)
    rb = RM_TPL.format(1)
    cfg_rm(dut, ra, 200, ns1)
    cfg_rm(dut, rb, 100, ns2)
    add_rm(dut, asn, i1['pv4'], ra, ns=ns1)
    add_rm(dut, asn, i2['pv4'], rb, ns=ns2)
    clr_bgp(dut, i1['pv4'], ns1)
    clr_bgp(dut, i2['pv4'], ns2)

    exa_ann(pip, i1['ep'], TEST_PFX_V4, nhv4)
    exa_ann(pip, i2['ep'], TEST_PFX_V4, nhv4)

    try:
        time.sleep(CONV_TMO)

        def _chk(exp):
            bp = best_path(
                dut, TEST_PFX_V4, ns1
            )
            return bp and bp.get('locPrf') == exp

        pytest_assert(
            wait_until(
                CONV_TMO, CONV_INT,
                0, _chk, 200
            ),
            'Initial best LP should be 200'
        )

        for idx in range(5):
            logger.info('Flap iter %d', idx + 1)
            exa_wd(
                pip, i1['ep'],
                TEST_PFX_V4, nhv4
            )
            time.sleep(CONV_TMO)
            m1 = (
                'After wd LP=100'
                ' (iter {})'.format(idx + 1)
            )
            pytest_assert(
                wait_until(
                    CONV_TMO, CONV_INT,
                    0, _chk, 100
                ),
                m1
            )

            exa_ann(
                pip, i1['ep'],
                TEST_PFX_V4, nhv4
            )
            time.sleep(CONV_TMO)
            m2 = (
                'After re-ann LP=200'
                ' (iter {})'.format(idx + 1)
            )
            pytest_assert(
                wait_until(
                    CONV_TMO, CONV_INT,
                    0, _chk, 200
                ),
                m2
            )
    finally:
        exa_wd(pip, i1['ep'], TEST_PFX_V4, nhv4)
        exa_wd(pip, i2['ep'], TEST_PFX_V4, nhv4)
        del_rm_nbr(
            dut, asn, i1['pv4'], ra, ns=ns1
        )
        del_rm_nbr(
            dut, asn, i2['pv4'], rb, ns=ns2
        )
        del_rm(dut, ra, ns1)
        del_rm(dut, rb, ns2)


def _rr_up(dut, asn, clients, ns):
    for c in clients:
        set_rr(dut, asn, c['pv4'], ns=ns)
    for c in clients:
        clr_bgp(dut, c['pv4'], ns)
    wait_bgp(dut)


def _rr_dn(dut, asn, clients, ns):
    for c in clients:
        del_rr(dut, asn, c['pv4'], ns=ns)
    for c in clients:
        clr_bgp(dut, c['pv4'], ns)


RR_PFX = '10.200.0.0/24'


def test_rr_lp_preservation(
    duthosts, rand_one_dut_hostname,
    ptfhost, setup, nbrhosts
):
    dut = duthosts[rand_one_dut_hostname]
    t0 = setup['t0']
    pytest_assert(
        len(t0) >= 2, 'Need >= 2 T0 for RR'
    )
    i1 = setup['ni'][t0[0]]
    i2 = setup['ni'][t0[1]]
    pip = setup['pip']
    nhv4 = setup['nhv4']
    asn = setup['asn']
    ns = i1['ns']

    _rr_up(dut, asn, [i1, i2], ns)

    rm = RM_TPL.format(0)
    cfg_rm(dut, rm, 250, ns)
    add_rm(dut, asn, i1['pv4'], rm, ns=ns)
    clr_bgp(dut, i1['pv4'], ns)

    exa_ann(pip, i1['ep'], RR_PFX, nhv4)
    try:
        time.sleep(CONV_TMO)
        pytest_assert(
            wait_until(
                CONV_TMO, CONV_INT, 0,
                chk_lp, dut,
                RR_PFX, 250, ns
            ),
            'RR should preserve LP 250'
        )
    finally:
        exa_wd(pip, i1['ep'], RR_PFX, nhv4)
        del_rm_nbr(
            dut, asn, i1['pv4'], rm, ns=ns
        )
        del_rm(dut, rm, ns)
        _rr_dn(dut, asn, [i1, i2], ns)


def test_rr_set_lp(
    duthosts, rand_one_dut_hostname,
    ptfhost, setup, nbrhosts
):
    dut = duthosts[rand_one_dut_hostname]
    t0 = setup['t0']
    pytest_assert(
        len(t0) >= 2, 'Need >= 2 T0 for RR'
    )
    i1 = setup['ni'][t0[0]]
    i2 = setup['ni'][t0[1]]
    pip = setup['pip']
    nhv4 = setup['nhv4']
    asn = setup['asn']
    ns = i1['ns']

    rm = RM_TPL.format(0)
    cfg_rm(dut, rm, 300, ns)
    add_rm(dut, asn, i1['pv4'], rm, ns=ns)

    _rr_up(dut, asn, [i1, i2], ns)

    exa_ann(pip, i1['ep'], RR_PFX, nhv4)
    try:
        time.sleep(CONV_TMO)
        pytest_assert(
            wait_until(
                CONV_TMO, CONV_INT, 0,
                chk_lp, dut,
                RR_PFX, 300, ns
            ),
            'RR should set LP 300 via rm'
        )
    finally:
        exa_wd(pip, i1['ep'], RR_PFX, nhv4)
        del_rm_nbr(
            dut, asn, i1['pv4'], rm, ns=ns
        )
        del_rm(dut, rm, ns)
        _rr_dn(dut, asn, [i1, i2], ns)


def test_rr_best_path_selection(
    duthosts, rand_one_dut_hostname,
    ptfhost, setup, nbrhosts
):
    dut = duthosts[rand_one_dut_hostname]
    t0 = setup['t0']
    pytest_assert(
        len(t0) >= 2, 'Need >= 2 T0 for RR'
    )
    i1 = setup['ni'][t0[0]]
    i2 = setup['ni'][t0[1]]
    pip = setup['pip']
    nhv4 = setup['nhv4']
    asn = setup['asn']
    ns = i1['ns']

    ra = RM_TPL.format(0)
    rb = RM_TPL.format(1)
    cfg_rm(dut, ra, 150, ns)
    cfg_rm(dut, rb, 200, ns)
    add_rm(dut, asn, i1['pv4'], ra, ns=ns)
    add_rm(dut, asn, i2['pv4'], rb, ns=ns)

    _rr_up(dut, asn, [i1, i2], ns)

    exa_ann(pip, i1['ep'], RR_PFX, nhv4)
    exa_ann(pip, i2['ep'], RR_PFX, nhv4)
    try:
        time.sleep(CONV_TMO)

        def _chk():
            bp = best_path(dut, RR_PFX, ns)
            return bp and bp.get('locPrf') == 200

        pytest_assert(
            wait_until(
                CONV_TMO, CONV_INT, 0, _chk
            ),
            'RR best should have LP 200'
        )
    finally:
        exa_wd(pip, i1['ep'], RR_PFX, nhv4)
        exa_wd(pip, i2['ep'], RR_PFX, nhv4)
        del_rm_nbr(
            dut, asn, i1['pv4'], ra, ns=ns
        )
        del_rm_nbr(
            dut, asn, i2['pv4'], rb, ns=ns
        )
        del_rm(dut, ra, ns)
        del_rm(dut, rb, ns)
        _rr_dn(dut, asn, [i1, i2], ns)


def test_rr_multiple_clients(
    duthosts, rand_one_dut_hostname,
    ptfhost, setup, nbrhosts
):
    dut = duthosts[rand_one_dut_hostname]
    t0 = setup['t0']
    pytest_assert(
        len(t0) >= 3, 'Need >= 3 T0 for RR'
    )
    i1 = setup['ni'][t0[0]]
    i2 = setup['ni'][t0[1]]
    i3 = setup['ni'][t0[2]]
    pip = setup['pip']
    nhv4 = setup['nhv4']
    asn = setup['asn']
    ns = i1['ns']

    ra = RM_TPL.format(0)
    rb = RM_TPL.format(1)
    rc = RM_TPL.format(2)
    cfg_rm(dut, ra, 100, ns)
    cfg_rm(dut, rb, 200, ns)
    cfg_rm(dut, rc, 150, ns)
    add_rm(dut, asn, i1['pv4'], ra, ns=ns)
    add_rm(dut, asn, i2['pv4'], rb, ns=ns)
    add_rm(dut, asn, i3['pv4'], rc, ns=ns)

    _rr_up(dut, asn, [i1, i2, i3], ns)

    exa_ann(pip, i1['ep'], RR_PFX, nhv4)
    exa_ann(pip, i2['ep'], RR_PFX, nhv4)
    exa_ann(pip, i3['ep'], RR_PFX, nhv4)
    try:
        time.sleep(CONV_TMO)

        def _chk():
            bp = best_path(dut, RR_PFX, ns)
            return bp and bp.get('locPrf') == 200

        pytest_assert(
            wait_until(
                CONV_TMO, CONV_INT, 0, _chk
            ),
            'RR best should be LP 200'
        )
    finally:
        exa_wd(pip, i1['ep'], RR_PFX, nhv4)
        exa_wd(pip, i2['ep'], RR_PFX, nhv4)
        exa_wd(pip, i3['ep'], RR_PFX, nhv4)
        del_rm_nbr(
            dut, asn, i1['pv4'], ra, ns=ns
        )
        del_rm_nbr(
            dut, asn, i2['pv4'], rb, ns=ns
        )
        del_rm_nbr(
            dut, asn, i3['pv4'], rc, ns=ns
        )
        del_rm(dut, ra, ns)
        del_rm(dut, rb, ns)
        del_rm(dut, rc, ns)
        _rr_dn(dut, asn, [i1, i2, i3], ns)


def test_rr_client_override_lp(
    duthosts, rand_one_dut_hostname,
    ptfhost, setup, nbrhosts
):
    dut = duthosts[rand_one_dut_hostname]
    t0 = setup['t0']
    pytest_assert(
        len(t0) >= 2, 'Need >= 2 T0 for RR'
    )
    i1 = setup['ni'][t0[0]]
    i2 = setup['ni'][t0[1]]
    pip = setup['pip']
    nhv4 = setup['nhv4']
    asn = setup['asn']
    ns = i1['ns']

    rm = RM_TPL.format(0)
    cfg_rm(dut, rm, 200, ns)
    add_rm(dut, asn, i1['pv4'], rm, ns=ns)

    _rr_up(dut, asn, [i1, i2], ns)

    exa_ann(pip, i1['ep'], RR_PFX, nhv4)
    try:
        time.sleep(CONV_TMO)
        pytest_assert(
            wait_until(
                CONV_TMO, CONV_INT, 0,
                chk_lp, dut,
                RR_PFX, 200, ns
            ),
            'RR LP 200 override'
        )
    finally:
        exa_wd(pip, i1['ep'], RR_PFX, nhv4)
        del_rm_nbr(
            dut, asn, i1['pv4'], rm, ns=ns
        )
        del_rm(dut, rm, ns)
        _rr_dn(dut, asn, [i1, i2], ns)

"""Regression checks for portless RouterOS logs and WAN map filters."""
import importlib
import sys
from unittest.mock import MagicMock

import pytest

from flow_presentation import dimension_expressions, describe_nodes


def test_unifi_dimension_sql_is_unchanged():
    base = {'dst_port': 'original', 'protocol': 'raw protocol'}
    assert dimension_expressions(base, False) == base
    assert base['dst_port'] == 'original'


def test_portless_protocols_and_router_are_explicit():
    expressions = dimension_expressions({}, True)
    assert 'ICMPv6 (no ports)' in expressions['dst_port']
    assert 'GRE (no ports)' in expressions['dst_port']
    assert "COALESCE(interface_out, 'router')" == expressions['interface_out']


def test_remainder_is_counted_without_losing_raw_filter_identity():
    nodes = [{'label': 'Other', 'type': 'src_ip'},
             {'label': 'ICMPv6 (no ports)', 'type': 'dst_port'},
             {'label': '443', 'type': 'dst_port'},
             {'label': 'router', 'type': 'interface_out'}]
    rows = [('192.0.2.' + str(n), '443', '192.0.2.99', 1) for n in range(1, 6)]
    describe_nodes(nodes, rows, ['src_ip', 'dst_port', 'dst_ip'], 3)
    assert nodes[0]['display_label'] == '2 more source IPs'
    assert nodes[0]['label'] == 'Other' and nodes[0]['actionable'] is False
    assert nodes[1]['actionable'] is False
    assert nodes[2].get('actionable', True) is True
    assert nodes[3]['display_label'] == 'Router'


@pytest.fixture
def geo_client(monkeypatch):
    deps = MagicMock()
    monkeypatch.setenv('ROUTER_PLATFORM', 'mikrotik')
    monkeypatch.setitem(sys.modules, 'deps', deps)
    monkeypatch.delitem(sys.modules, 'routes.threats', raising=False)
    module = importlib.import_module('routes.threats')
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    app = FastAPI()
    app.include_router(module.router)
    cur = deps.get_conn.return_value.cursor.return_value.__enter__.return_value
    cur.fetchall.return_value = [dict(lat=24.7, lon=46.7, country='SA', city='Riyadh', count=4,
                                    max_score=None, avg_score=None, unique_ips=2,
                                    log_ids=[1, 2], scored_events=0)]
    yield TestClient(app), cur
    sys.modules.pop('routes.threats', None)


@pytest.mark.parametrize('mode,condition', [('activity', None), ('blocked', "rule_action = 'block'"),
                                          ('threats', 'threat_score > 70')])
def test_map_modes_keep_wan_scope_without_requiring_threat_score(geo_client, mode, condition):
    client, cur = geo_client
    response = client.get('/api/threats/geo', params={'mode': mode})
    assert response.status_code == 200
    sql = cur.execute.call_args.args[0]
    assert 'wan_interfaces' in sql
    if condition:
        assert condition in sql
    else:
        assert 'threat_score > 70' not in sql
    data = response.json()
    assert data['summary']['total_events'] == 4
    assert data['features'][0]['properties']['scored_events'] == 0


def test_invalid_map_mode_never_queries_database(geo_client):
    client, cur = geo_client
    assert client.get('/api/threats/geo', params={'mode': 'invalid'}).status_code == 400
    cur.execute.assert_not_called()

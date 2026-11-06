"""Never disclose local endpoints to external reputation services."""
from unittest.mock import MagicMock

import pytest

import abuseipdb_scope as scope


@pytest.fixture
def context(monkeypatch):
    db = MagicMock()
    settings = {'wan_interfaces': ['pppoe-out1'],
                'mikrotik_local_networks': ['192.168.100.0/24', '2001:4860:1234::/48'],
                'gateway_ips': ['8.8.4.4'],
                'mikrotik_device_inventory': [{'addresses': ['9.9.9.9']}]}
    monkeypatch.setattr(scope, 'get_config', lambda db, key: settings.get(key))
    monkeypatch.setattr(scope, 'get_wan_ips_from_config', lambda db: ['8.8.8.8'])
    cur = db.get_conn.return_value.__enter__.return_value.cursor.return_value.__enter__.return_value
    cur.fetchone.return_value = (True,)
    return db, cur, settings


@pytest.mark.parametrize('ip', ['192.168.100.7', '10.0.30.2', 'fd00::1', 'fe80::1',
                               '2001:4860:1234:1::abcd', '8.8.8.8', '8.8.4.4', '9.9.9.9'])
def test_local_prefixes_inventory_router_and_wan_addresses_never_reach_query(context, ip):
    db, cur, _ = context
    assert scope.allowed_remote_ip(db, ip) is False
    cur.execute.assert_not_called()


def test_public_ip_requires_observed_blocked_wan_side_and_no_local_evidence(context):
    db, cur, _ = context
    assert scope.allowed_remote_ip(db, '1.1.1.1') is True
    sql, params = cur.execute.call_args.args
    assert "rule_action='block'" in sql
    assert 'interface_in = ANY' in sql and 'interface_out = ANY' in sql
    assert 'NOT EXISTS' in sql and 'set_masklen' in sql
    cur.fetchone.return_value = (False,)
    assert scope.allowed_remote_ip(db, '1.1.1.1') is False


def test_missing_scope_or_database_failure_fails_closed(context):
    db, cur, settings = context
    settings['mikrotik_local_networks'] = []
    assert scope.allowed_remote_ip(db, '1.1.1.1') is False
    settings['mikrotik_local_networks'] = ['192.168.100.0/24']
    cur.execute.side_effect = RuntimeError('unavailable')
    assert scope.allowed_remote_ip(db, '1.1.1.1') is False


def test_final_external_call_guard_covers_background_lookup(context, monkeypatch):
    from enrichment import AbuseIPDBEnricher
    import enrichment
    db, _, _ = context
    db.get_threat_cache.return_value = None
    monkeypatch.setenv('ROUTER_PLATFORM', 'mikrotik')
    request = MagicMock()
    monkeypatch.setattr(enrichment.requests, 'get', request)
    enricher = AbuseIPDBEnricher(api_key='test', db=db)
    assert enricher.lookup('2001:4860:1234:1::abcd') == {}
    request.assert_not_called()

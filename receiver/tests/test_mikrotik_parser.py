"""RouterOS/Jotne protocol fixtures, independent of the router or network."""
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
import parsers
import mikrotik_parser as mk
from db import INSERT_COLUMNS, _log_values, _learn_mikrotik_clients


@pytest.fixture(autouse=True)
def reset(monkeypatch):
    monkeypatch.setattr(mk, 'RULE_ACTIONS', {})
    monkeypatch.setattr(parsers, 'WAN_INTERFACES', {'pppoe-out1'})


FW = 'FF_D_Test forward: in:pppoe-out1 out:bridge, connection-state:new src-mac 02:00:00:00:00:01, proto TCP (SYN), 198.51.100.2:44500->192.0.2.10:443, len 60'


def test_native_firewall_headerless_jotne_prefix():
    log = mk.parse_routeros('<190>firewall,info serial=TEST123 MikroTik: '+FW, '192.0.2.1')
    assert log['src_ip'] == '198.51.100.2'
    assert log['dst_ip'] == '192.0.2.10'
    assert log['src_port'] == 44500 and log['dst_port'] == 443
    assert log['router_serial'] == 'TEST123'
    assert log['router_host'] == '192.0.2.1'
    assert log['router_topics'] == ['firewall','info']
    assert log['rule_action'] == 'block' and log['direction'] == 'inbound'
    assert log['router_fields']['packet_length'] == 60
    assert log['mac_address'] == '02:00:00:00:00:01'


def test_routeros_syslog_bsd_header(monkeypatch):
    monkeypatch.setenv('TZ','Asia/Riyadh')
    log = mk.parse_routeros('<30>Nov  5 02:00:00 lab-router firewall,info '+FW)
    assert log['router_host'] == 'lab-router'
    assert log['timestamp'].hour == 23


def test_iso_timestamp_keeps_offset():
    log = mk.parse_routeros('<30>2026-11-05T02:00:00+03:00 lab-router '+FW)
    assert log['timestamp'] == datetime(2026,11,4,23,tzinfo=timezone.utc)


def test_ipv6_ports_and_unknown_interface():
    log = mk.parse_routeros('firewall,info FI_D_Test input: in:pppoe-out1 out:(unknown 0), proto UDP, [2001:db8::2]:500->[2001:db8::1]:500, len 100')
    assert log['src_ip'] == '2001:db8::2' and log['src_port'] == 500
    assert log['dst_ip'] == '2001:db8::1' and log['dst_port'] == 500
    assert log['interface_out'] is None and log['direction'] == 'inbound'


def test_bare_ipv6_icmp_and_bridge_port():
    log = mk.parse_routeros('forward: in:bridge(ether2) out:pppoe-out1, proto ICMPv6, fe80::1->ff02::1, len 80')
    assert log['src_ip'] == 'fe80::1' and log['dst_ip'] == 'ff02::1'
    assert log['src_port'] is None and log['interface_in'] == 'bridge'


@pytest.mark.parametrize('prefix',['','invalid','log','observed','new_connection','WAN_LOCAL'])
def test_does_not_invent_allow_or_block(prefix):
    log = mk.parse_routeros(FW.replace('FF_D_Test',prefix))
    assert log['rule_action'] is None
    assert log['router_fields']['action_source'] == 'not present in syslog'


def test_explicit_mapping_and_jotne_control_actions(monkeypatch):
    monkeypatch.setattr(mk,'RULE_ACTIONS',{'custom': 'block'})
    assert mk.parse_routeros(FW.replace('FF_D_Test','custom'))['rule_action'] == 'block'
    assert mk.parse_routeros(FW.replace('FF_D_Test','FF_L_Log'))['rule_action'] is None
    assert mk.parse_routeros(FW.replace('FF_D_Test','RP_N_Notrack'))['rule_action'] is None
    assert mk.parse_routeros(FW.replace('FF_D_Test','ND_N_Netmap'))['rule_action'] == 'redirect'


def test_configured_vpn_and_unknown_wan(monkeypatch):
    monkeypatch.setattr(parsers,'VPN_INTERFACES',{'Remote Access'})
    text=FW.replace('in:pppoe-out1','in:Remote Access')
    assert mk.parse_routeros(text)['direction'] == 'vpn'
    monkeypatch.setattr(parsers,'WAN_INTERFACES',set())
    assert mk.parse_routeros(text)['direction'] is None


def test_invalid_ip_and_port_are_not_sent_to_postgres():
    log=mk.parse_routeros(FW.replace('198.51.100.2:44500','999.999.1.1:999999'))
    assert log['src_ip'] is None and log['src_port'] is None


def test_resource_fields_preserve_units_and_uptime():
    log=mk.parse_routeros('script,info script=resource free_memory=10 MB total_memory=100 MB cpu_load=4 uptime=1w2d03:04:05')
    assert log['log_type']=='telemetry'
    assert log['router_fields']['free_memory']=='10 MB'
    assert log['router_fields']['uptime']=='1w2d03:04:05'


def test_semicolon_record_and_quoted_delimiters():
    log=mk.parse_routeros('script,info .id=*1;comment="guest; note=hello world";name=MGMT-50;rx-byte=12345;script=if_traffic;tx-byte=23456')
    assert log['router_fields']['comment']=='guest; note=hello world'
    assert log['router_fields']['rx-byte']=='12345'
    assert log['interface_in']=='MGMT-50'


def test_neighbor_serial_is_not_the_sending_router_serial():
    log=mk.parse_routeros('script,info script=neighbor nid=1 serial=OTHERDEVICE')
    assert log['router_serial'] is None
    assert log['router_fields']['serial']=='OTHERDEVICE'


@pytest.mark.parametrize('family',['version','ntp','sysinfo','resource','health','if_traffic','kids','upnp','wifi','address_lists','neighbor','pool','route','ospf','bgp','ppp','ipsec','future_family'])
def test_every_exporter_family_is_retained(family):
    log=mk.parse_routeros(f'script,info script={family} name="Example router" value=42')
    assert log['log_type']=='telemetry'
    assert log['router_fields']['script']==family
    assert log['router_fields']['name']=='Example router'


def test_dhcp_lease_and_deassignment():
    text='dhcp,info dhcp-lan assigned 192.0.2.25 to 02:00:00:00:00:02 workstation'
    log=mk.parse_routeros(text)
    assert log['hostname']=='workstation' and log['dhcp_event']=='assigned'
    assert log['src_ip']=='192.0.2.25' and 'interface_in' not in log
    assert log['router_fields']['dhcp_server']=='dhcp-lan'
    released=mk.parse_routeros(text.replace('assigned','deassigned').replace(' to ',' from '))
    assert released['dhcp_event']=='deassigned'
    actual_format=mk.parse_routeros(text.replace(' to ',' for '))
    assert actual_format['src_ip']=='192.0.2.25' and actual_format['hostname']=='workstation'


def test_dns_ipv6_and_wifi():
    log=mk.parse_routeros('dns,packet query from 2001:db8::10: #42 example.org. AAAA')
    assert log['src_ip']=='2001:db8::10' and log['dns_query']=='example.org'
    wifi=mk.parse_routeros('wireless,info 02:00:00:00:00:02@wifi1: disconnected, signal strength -60')
    assert wifi['log_type']=='wifi' and wifi['wifi_event']=='disconnected'
    assert wifi['interface_in']=='wifi1'


def test_system_login_and_malformed_timestamp():
    log=mk.parse_routeros('system,info,account user admin logged in from 192.0.2.20 via winbox')
    assert log['src_ip']=='192.0.2.20'
    assert mk.parse_routeros('Feb 99 99:99:99 router script,info script=version ver=5.6') is None
    assert mk.parse_routeros('') is None


def test_mikrotik_profile_dispatch(monkeypatch):
    monkeypatch.setenv('ROUTER_PLATFORM','mikrotik')
    assert parsers.parse_log('script,info script=version ver=5.6')['log_type']=='telemetry'


def test_jsonb_insert_adapter_and_client_cache_are_parameterized():
    log=mk.parse_routeros('script,info script=resource cpu_load=5')
    values=_log_values(log)
    assert values[INSERT_COLUMNS.index('router_fields')].adapted==log['router_fields']
    lease=mk.parse_routeros('dhcp,info server assigned 192.0.2.20 to 02:00:00:00:00:20 host', '192.0.2.1')
    cur=MagicMock();_learn_mikrotik_clients(cur,[lease])
    assert cur.execute.call_args.args[1][0]=='02:00:00:00:00:20'
    assert 'ON CONFLICT' in cur.execute.call_args.args[0]


def test_mikrotik_profile_never_initializes_controller_credentials(monkeypatch):
    from unifi_api import UniFiAPI
    monkeypatch.setenv('ROUTER_PLATFORM','mikrotik')
    monkeypatch.setenv('UNIFI_HOST','https://should-not-be-contacted.example')
    monkeypatch.setenv('UNIFI_API_KEY','not-a-real-key')
    db=MagicMock();client=UniFiAPI(db)
    assert not client.enabled and client.host=='' and client.api_key==''
    db.get_config.assert_not_called()

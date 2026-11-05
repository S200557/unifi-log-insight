"""WAN scoping, RouterOS custom chains and DHCP-comment display correctness."""
import pytest
import parsers
from mikrotik_parser import parse_routeros
from mikrotik_dashboard import logs_source, presentation, device_identity, group_devices
from ip_identity import IdentityConfig, annotate_record


def test_profile_scope_is_wan_only_and_fails_closed_without_config(monkeypatch):
    monkeypatch.setenv('ROUTER_PLATFORM','mikrotik')
    sql=logs_source()
    assert "log_type='firewall'" in sql
    assert 'interface_in=wan.name OR interface_out=wan.name' in sql
    assert "'[]'::jsonb" in sql
    assert 'DELETE' not in sql
    with pytest.raises(ValueError):logs_source('logs; DROP TABLE logs')
    monkeypatch.setenv('ROUTER_PLATFORM','unifi')
    assert logs_source()=='logs' and logs_source('l')=='logs l'


@pytest.mark.parametrize('chain,prefix,family',[
    ('ZT4-INTERNET','FF_D_unkown-device',4),('ZT6-INTERNET','FF_D_unknown-devic6',6),
])
def test_custom_chain_preserved_without_polluting_prefix(monkeypatch,chain,prefix,family):
    monkeypatch.setattr(parsers,'WAN_INTERFACES',{'pppoe-out1'})
    source,destination=('192.0.2.2:1234','198.51.100.2:443') if family==4 else ('[2001:db8::2]:1234','[2001:db8:1::2]:443')
    row=parse_routeros(f'{prefix} {chain}: in:bridge out:pppoe-out1, proto TCP (SYN), {source}->{destination}, len 60')
    assert row['rule_name']==prefix and row['rule_action']=='block'
    assert row['router_fields']['chain']==chain
    presentation(row)
    assert row['direction_label']==f'Outbound IPv{family}'
    assert row['category_label']=='Unknown-Device'


def test_network_icmp6_direction_comes_from_interfaces(monkeypatch):
    monkeypatch.setattr(parsers,'WAN_INTERFACES',{'pppoe-out1'})
    packet='FF_A_Network-ICMP6 forward: in:IN out:OUT, proto IPv6-ICMP (type 128, code 0), 2001:db8::2->2001:db8:1::2, len 80'
    for incoming,outgoing,expected in [('pppoe-out1','bridge','inbound'),('bridge','pppoe-out1','outbound'),('iot30','bridge','inter_vlan')]:
        row=parse_routeros(packet.replace('IN',incoming).replace('OUT',outgoing))
        assert row['direction']==expected
        presentation(row)
        assert row['category_label']=='Network-ICMP'
        assert row['ip_version']==6 and row['router_fields']['icmp_type']==128


def test_router_ping_keeps_actual_public_destination_and_infers_family_without_suffix(monkeypatch):
    monkeypatch.setenv('ROUTER_PLATFORM','mikrotik')
    cfg=IdentityConfig({}, {}, [], set(),wan_interfaces=['pppoe-out1'])
    row={'log_type':'firewall','src_ip':'2001:db8::2','dst_ip':'2001:db8:50::1',
         'direction':'inbound','interface_in':'pppoe-out1','rule_name':'FI_A_RouterICMP',
         'rule_action':'allow','router_fields':{'chain':'input','prefix':'FI_A_RouterICMP'}}
    annotate_record(cfg,row)
    assert row['dst_ip']=='2001:db8:50::1' and row['dst_device_name']=='Router'
    assert row['direction_label']=='Inbound IPv6' and row['category_label']=='Router-ICMP'


def test_dhcp_comment_wins_and_same_mac_different_vlan_is_not_guessed(monkeypatch):
    monkeypatch.setenv('ROUTER_PLATFORM','mikrotik')
    devices=[{'mac':'02:00:00:00:00:01','name':'My server','addresses':['192.0.2.20'],'interface':'bridge'},
             {'mac':'02:00:00:00:00:02','name':'Phone LAN','addresses':['2001:db8:1::10'],'interface':'bridge'},
             {'mac':'02:00:00:00:00:02','name':'Phone IoT','addresses':['2001:db8:30::10'],'interface':'iot30'}]
    assert device_identity(devices,'', '02:00:00:00:00:02') is None
    assert device_identity(devices,'', '02:00:00:00:00:02','iot30')['name']=='Phone IoT'
    cfg=IdentityConfig({}, {}, [], set(),mikrotik_devices=devices,wan_interfaces=['pppoe-out1'])
    row={'src_ip':'192.0.2.20','src_device_name':'advertised-hostname','interface_in':'bridge'}
    annotate_record(cfg,row)
    assert row['src_device_name']=='My server'
    row={'src_ip':'198.51.100.2','mac_address':'02:00:00:00:00:01','interface_in':'pppoe-out1'}
    annotate_record(cfg,row)
    assert not row.get('src_device_name')


def test_device_rollup_combines_dual_stack_but_preserves_segment_labels():
    inventory=[{'mac':'02:00:00:00:00:01','name':'Phone LAN','interface':'bridge','addresses':['192.0.2.10','2001:db8:1::10']},
               {'mac':'02:00:00:00:00:01','name':'Phone IoT','interface':'iot30','addresses':['2001:db8:30::10']}]
    rows=[{'ip':ip,'count':count,'blocked':1,'mac_address':'02:00:00:00:00:01','interface_in':iface}
          for ip,count,iface in [('2001:db8:1::10',8,'bridge'),('192.0.2.10',5,'bridge'),('2001:db8:30::10',3,'iot30')]]
    result=group_devices(rows,inventory)
    assert len(result)==2 and result[0]['name']=='Phone LAN' and result[0]['count']==13
    assert result[0]['blocked']==2 and result[0]['ip']=='192.0.2.10'
    assert result[1]['name']=='Phone IoT' and result[1]['count']==3

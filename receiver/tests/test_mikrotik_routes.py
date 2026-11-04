"""Telemetry correctness and the local-only configuration contract."""
import importlib
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException


@pytest.fixture
def api(monkeypatch):
    deps=SimpleNamespace(enricher_db=MagicMock(),get_conn=MagicMock(),put_conn=MagicMock(),signal_receiver=MagicMock())
    monkeypatch.setitem(sys.modules,'deps',deps)
    monkeypatch.delitem(sys.modules,'routes.mikrotik',raising=False)
    module=importlib.import_module('routes.mikrotik')
    yield module,deps
    sys.modules.pop('routes.mikrotik',None)


def test_resource_percentages_and_units(api):
    m,_=api
    r=m.resource_sample({'timestamp':'2026-11-05T01:00:00Z','fields':{'free_memory':'10 MB','total_memory':'100 MB','free_hdd_space':'0 MB','total_hdd_space':'100 MB','cpu_load':'4','uptime':'2w'}})
    assert r['memory']==90 and r['disk']==100 and r['cpu']==4
    assert m.resource_sample({'timestamp':'x','fields':{'total_memory':'0'}})['memory'] is None
    assert m.number('NaN') is None
    assert m.number('1' * 1000) is None


def test_interface_rate_units_reset_and_duplicate_timestamp(api):
    m,_=api
    def row(sec,rx,tx,ident=1):
        return {'id':ident,'router_host':'r','timestamp':f'2026-11-05T01:00:{sec:02d}+00:00','fields':{'name':'bridge','rx-byte':str(rx),'tx-byte':str(tx)}}
    rates=m.interface_rates([row(10,1000,2000),row(20,2000,4000)])
    assert rates[0]['rx_bps']==800 and rates[0]['tx_bps']==1600
    assert m.interface_rates([row(10,1000,2000),row(20,100,100)])[0]['rx_bps'] is None
    assert m.interface_rates([row(10,1000,2000),row(10,2000,4000,2)])[0]['rx_bps'] is None
    huge=2**63
    assert m.interface_rates([row(10,huge,huge),row(20,huge+10,huge+20)])[0]['rx_bps']==8


def test_config_accepts_real_routeros_names_without_vlan_guesses(api):
    m,_=api
    body={'wan_interfaces':['pppoe-out1'],'interface_labels':{'bridge':'LAN','MGMT-50':'Management','iot30':'IoT'},'vpn_networks':{'Remote Access':{'badge':'WG','cidr':'2001:db8::/64'}},'mikrotik_rule_actions':{'custom prefix':'unknown'}}
    assert m.validate_config(body)==body


def test_neighbor_fragments_merge_without_crossing_router_boundaries(api):
    m,_=api
    rows=[
        {'id':3,'router_host':'router-a','timestamp':'2026-11-05T00:03:00Z','fields':{'script':'neighbor','nid':'1','identity':'switch'}},
        {'id':2,'router_host':'router-b','timestamp':'2026-11-05T00:02:00Z','fields':{'script':'neighbor','nid':'1','address':'192.0.2.3'}},
        {'id':1,'router_host':'router-a','timestamp':'2026-11-05T00:01:00Z','fields':{'script':'neighbor','nid':'1','address':'192.0.2.2'}},
    ]
    result=m.latest_snapshots(rows)
    assert len(result)==2
    a=next(r for r in result if r['router_host']=='router-a')
    assert a['fields']['identity']=='switch' and a['fields']['address']=='192.0.2.2'


def test_serial_aliases_do_not_invent_additional_routers(api):
    m,_=api
    rows=[{'router_host':'UTC','serial':'example','events':2,'latest_event':'2026-11-05','latest_received':'2026-11-05'},
          {'router_host':'192.0.2.1','serial':'example','events':100,'latest_event':'2026-11-05','latest_received':'2026-11-05'}]
    result=m.collapse_router_sources(rows)
    assert len(result)==1 and result[0]['events']==102
    assert result[0]['router_host']=='192.0.2.1'
    assert result[0]['source_aliases']==['192.0.2.1','UTC']


@pytest.mark.parametrize('body',[
    {'wan_interfaces':[]}, {'wan_interfaces':['x','x']},
    {'wan_interfaces':['bad\nname']}, {'wan_interfaces':['pppoe-out1'],'router_password':'never'},
    {'wan_interfaces':['wan'],'mikrotik_rule_actions':{'foo':'accept-all'}},
    {'wan_interfaces':['wan'],'vpn_networks':{'vpn':{'cidr':'not-a-network'}}},
])
def test_invalid_settings_never_reach_database(api,body):
    m,deps=api
    with pytest.raises(HTTPException): m.save_config(body)
    deps.get_conn.assert_not_called()
    deps.signal_receiver.assert_not_called()


def test_valid_configuration_only_writes_local_settings(api):
    m,deps=api
    result=m.save_config({'wan_interfaces':['pppoe-out1'],'interface_labels':{'bridge':'LAN'}})
    assert result=={'success':True,'management_access':False}
    conn=deps.get_conn.return_value
    statements=conn.cursor.return_value.__enter__.return_value.execute.call_args_list
    assert all('system_config' in call.args[0] for call in statements)
    assert any(call.args[1][0]=='unifi_enabled' and call.args[1][1].adapted is False for call in statements)
    conn.commit.assert_called_once()
    deps.signal_receiver.assert_called_once()

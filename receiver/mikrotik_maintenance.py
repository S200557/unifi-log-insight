"""Apply a reviewed local device inventory and repair parsed firewall metadata.

Run inside the app container. This never connects to RouterOS, deletes logs,
or changes authentication, enrichment secrets or any other service.
"""
import argparse
import ipaddress
import json
import re
from pathlib import Path

from psycopg2.extras import Json
from db import Database, build_conn_params, wait_for_postgres
from parsers import reload_config_from_db
from mikrotik_parser import parse_routeros


def validate_inventory(data):
    devices = data['devices']
    if not isinstance(devices,list) or len(devices)>1000:
        raise ValueError('Invalid inventory size')
    for device in devices:
        if not isinstance(device.get('name'),str) or not 0<len(device['name'])<=255:
            raise ValueError('Invalid device name')
        if not re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', device.get('mac','')):
            raise ValueError('Invalid MAC')
        for address in device.get('addresses',[]):
            ipaddress.ip_address(address)
    if not isinstance(data.get('wan_interfaces'),list) or not data['wan_interfaces']:
        raise ValueError('WAN interfaces required')
    if not all(isinstance(s,str) and re.fullmatch(r'[A-Za-z0-9 ._:+/@()-]{1,64}',s) for s in data['wan_interfaces']):
        raise ValueError('Invalid WAN interface')
    return devices


def apply(db, data, backfill=False):
    devices = validate_inventory(data)
    db.set_config('mikrotik_device_inventory', devices)
    db.set_config('mikrotik_inventory_observed_at', data.get('observed_at'))
    db.set_config('wan_interfaces', data['wan_interfaces'])
    labels = db.get_config('interface_labels', {}) or {}
    labels.update(data.get('interface_labels',{}))
    db.set_config('interface_labels', labels)
    db.set_config('ui_theme', 'light')
    reload_config_from_db(db)
    changed = 0
    if backfill:
        last = 0
        while True:
            with db.get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute('''SELECT id,raw_log,router_host FROM logs
                                   WHERE log_type='firewall' AND router_host IS NOT NULL AND id>%s
                                   ORDER BY id LIMIT 500''',[last])
                    rows = cur.fetchall()
                    if not rows:
                        break
                    for ident, raw, host in rows:
                        last = ident
                        parsed = parse_routeros(raw, host)
                        if parsed and parsed.get('log_type')=='firewall':
                            cur.execute('''UPDATE logs SET rule_name=%s,rule_action=%s,direction=%s,
                                           router_fields=COALESCE(router_fields,'{}'::jsonb)||%s
                                           WHERE id=%s''',
                                        [parsed.get('rule_name'),parsed.get('rule_action'),
                                         parsed.get('direction'),Json(parsed.get('router_fields',{})),ident])
                            changed += 1
                conn.commit()
    return {'inventory_records':len(devices),'firewall_metadata_rows_reparsed':changed,
            'logs_deleted':0,'router_requests':0}


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inventory',type=Path,required=True)
    parser.add_argument('--backfill',action='store_true')
    args=parser.parse_args()
    data=json.loads(args.inventory.read_text())
    validate_inventory(data)
    params=build_conn_params();wait_for_postgres(params)
    db=Database(params);db.connect()
    print(json.dumps(apply(db,data,args.backfill)))

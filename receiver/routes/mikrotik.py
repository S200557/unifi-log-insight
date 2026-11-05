"""MikroTik passive discovery, retained telemetry and local configuration.

These endpoints never connect to RouterOS. All observations come from syslog.
"""
import math
import ipaddress
import re
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Query
from psycopg2.extras import Json, RealDictCursor

from db import get_config
from mikrotik_dashboard import logs_source, presentation
from deps import enricher_db, get_conn, put_conn, signal_receiver

router = APIRouter(prefix='/api/mikrotik', tags=['MikroTik'])
IFACE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9 ._:+/@()-]{0,63}$')


@router.get('/firewall')
def firewall_dashboard(hours: int = Query(24, ge=1, le=336),
                       ip_version: int | None = Query(None),
                       direction: str | None = Query(None),
                       result: str | None = Query(None)):
    """WAN-only counts, charts and event rows use the same SQL source/filter."""
    from routes.logs import _annotate_logs
    from ip_identity import load_identity_config, annotate_ip
    if ip_version not in (None, 4, 6) or direction not in (None, 'inbound', 'outbound') or result not in (None, 'allow', 'block'):
        raise HTTPException(400, 'Invalid firewall filter')
    conditions = ["timestamp >= NOW() - (%s * INTERVAL '1 hour')"]
    params = [hours]
    if ip_version:
        conditions.append('family(src_ip)=%s'); params.append(ip_version)
    if direction:
        conditions.append('direction=%s'); params.append(direction)
    if result:
        conditions.append('rule_action=%s'); params.append(result)
    where = ' AND '.join(conditions)
    source = logs_source()
    groups = _query(f'''SELECT rule_name,rule_action,direction,family(src_ip) AS ip_version,interface_in,
                       COUNT(*) AS count FROM {source} WHERE {where}
                       GROUP BY 1,2,3,4,5 ORDER BY count DESC''', params)
    series = _query(f'''SELECT date_trunc(%s,timestamp) AS timestamp,
                       COUNT(*) FILTER(WHERE rule_action='allow') AS accepted,
                       COUNT(*) FILTER(WHERE rule_action='block') AS blocked
                       FROM {source} WHERE {where} GROUP BY 1 ORDER BY 1''',
                    ['minute' if hours <= 6 else 'hour'] + params)
    events = _query(f'''SELECT * FROM {source} WHERE {where}
                       ORDER BY timestamp DESC,id DESC LIMIT 50''', params)
    for row in events:
        for key in ('src_ip','dst_ip','remote_ip','mac_address'):
            if row.get(key) is not None:
                row[key] = str(row[key])
    _annotate_logs(events)
    devices = _query(f'''SELECT host(src_ip) AS ip,MAX(mac_address::text) AS mac_address,
                        MAX(interface_in) AS interface_in,COUNT(*) AS count,
                        COUNT(*) FILTER(WHERE rule_action='block') AS blocked
                        FROM {source} WHERE {where} AND direction='outbound'
                        GROUP BY src_ip ORDER BY count DESC LIMIT 8''', params)
    cfg = load_identity_config(enricher_db)
    from mikrotik_dashboard import device_identity
    for row in devices:
        device = device_identity(cfg.mikrotik_devices, row['ip'], row.get('mac_address'), row.get('interface_in'))
        row['name'] = device['name'] if device else annotate_ip(cfg,row['ip'])[0]
    categories = {}
    for row in groups:
        # Family is returned by PostgreSQL, not guessed from a prefix suffix.
        probe = dict(row, src_ip='::1' if row['ip_version']==6 else '127.0.0.1')
        label = presentation(probe,cfg.interface_labels)['category_label']
        categories[label] = categories.get(label,0) + row['count']
    return {'total':sum(r['count'] for r in groups),
            'accepted':sum(r['count'] for r in groups if r['rule_action']=='allow'),
            'blocked':sum(r['count'] for r in groups if r['rule_action']=='block'),
            'inbound':sum(r['count'] for r in groups if r['direction']=='inbound'),
            'outbound':sum(r['count'] for r in groups if r['direction']=='outbound'),
            'series':series,'events':events,'devices':devices,
            'categories':[{'name':k,'count':v} for k,v in sorted(categories.items(),key=lambda x:-x[1])],
            'wan_interfaces':get_config(enricher_db,'wan_interfaces',[]),
            'scope':'WAN firewall events only','count_unit':'logged packets'}


def collapse_router_sources(rows):
    """One reported serial may have several hostname labels in relayed logs.

    Keep observed aliases, prefer the busiest IP source for the UI selector,
    and do not present timezone/header aliases as additional physical routers.
    This is an observed identifier, not an authenticated device identity.
    """
    groups = {}
    def rank(row):
        try:
            ipaddress.ip_address(row['router_host'])
            is_ip = True
        except ValueError:
            is_ip = False
        return is_ip, row['events'], row['latest_received']
    for row in rows:
        key = ('serial',row['serial']) if row['serial'] else ('host',row['router_host'])
        if key not in groups:
            groups[key] = {**row, 'source_aliases': [row['router_host']], '_rank': rank(row)}
            continue
        group = groups[key]
        group['events'] += row['events']
        group['latest_event'] = max(group['latest_event'], row['latest_event'])
        group['latest_received'] = max(group['latest_received'], row['latest_received'])
        group['source_aliases'].append(row['router_host'])
        if rank(row) > group['_rank']:
            group['router_host'], group['_rank'] = row['router_host'], rank(row)
    for group in groups.values():
        del group['_rank']
        group['source_aliases'] = sorted(set(group['source_aliases']))
    return sorted(groups.values(), key=lambda row: row['latest_received'], reverse=True)


def _query(sql, params=()):
    conn = get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(sql, params)
            rows = [dict(r) for r in cur.fetchall()]
        conn.commit()
        for row in rows:
            for key, value in row.items():
                if isinstance(value, datetime):
                    row[key] = value.isoformat()
        return rows
    finally:
        put_conn(conn)


@router.get('/status')
def status():
    routers = _query('''SELECT router_host, router_serial AS serial,
                       MAX(timestamp) AS latest_event, MAX(created_at) AS latest_received,
                       COUNT(*) AS events
                       FROM logs WHERE router_host IS NOT NULL AND timestamp>NOW()-INTERVAL '24 hours'
                       GROUP BY router_host,router_serial ORDER BY latest_received DESC LIMIT 300''')
    routers = collapse_router_sources(routers)
    families = _query('''SELECT router_fields->>'script' AS family,COUNT(*) AS events,MAX(timestamp) AS latest
                        FROM logs WHERE log_type='telemetry' AND timestamp>NOW()-INTERVAL '24 hours'
                        GROUP BY 1 ORDER BY 1''')
    info = _query('''SELECT DISTINCT ON(router_host) router_host,router_fields AS fields,timestamp
                    FROM logs WHERE log_type='telemetry' AND router_fields->>'script'='sysinfo'
                    AND timestamp>NOW()-INTERVAL '14 days' ORDER BY router_host,timestamp DESC,id DESC''')
    return {'routers': routers, 'families': families, 'device_info': info,
            'management_access': False, 'source': 'syslog', 'action_policy': 'unknown unless evidenced by prefix'}


@router.get('/telemetry')
def telemetry(host: str = Query('', max_length=255), family: str = Query('', max_length=64),
              hours: int = Query(24, ge=1, le=336), limit: int = Query(500, ge=1, le=10000)):
    rows = _query('''SELECT id,timestamp,router_host,router_serial,router_fields AS fields
                     FROM logs WHERE log_type='telemetry'
                     AND timestamp>=NOW()-(%s * INTERVAL '1 hour')
                     AND (%s='' OR router_host=%s)
                     AND (%s='' OR router_fields->>'script'=%s)
                     ORDER BY timestamp DESC,id DESC LIMIT %s''',
                  [hours, host, host, family, family, limit])
    return {'data': rows, 'snapshots': latest_snapshots(rows), 'limit': limit, 'truncated': len(rows) == limit}


def latest_snapshots(rows):
    """Jotne emits each neighbor attribute in a separate syslog message."""
    snapshots = {}
    singleton = {'version', 'ntp', 'resource', 'sysinfo'}
    for row in reversed(rows):
        fields = row['fields'] or {}
        family = fields.get('script')
        identity = (fields.get('nid') if family == 'neighbor' else None) or fields.get('.id') or fields.get('mac-address') or fields.get('name') or fields.get('pool') or fields.get('list')
        if not identity:
            identity = family if family in singleton else row['id']
        key = (row['router_host'], family, identity)
        if family == 'neighbor' and key in snapshots:
            fields = {**snapshots[key]['fields'], **fields}
        snapshots[key] = {**row, 'fields': fields}
    return sorted(snapshots.values(), key=lambda r: (r['timestamp'], r['id']), reverse=True)


def number(value):
    match = re.match(r'^\s*(-?\d+(?:\.\d+)?)', str('' if value is None else value))
    if not match:
        return None
    try:
        val = float(match[1])
        return val if math.isfinite(val) else None
    except ValueError:
        return None


def resource_sample(row):
    f = row['fields'] or {}
    def used(total_key, free_key):
        total, free = number(f.get(total_key)), number(f.get(free_key))
        return round(100 * (total-free) / total, 2) if total and free is not None and 0 <= free <= total else None
    return {'timestamp': row['timestamp'], 'cpu': number(f.get('cpu_load')),
            'memory': used('total_memory', 'free_memory'), 'disk': used('total_hdd_space', 'free_hdd_space'),
            'uptime': f.get('uptime'), 'free_memory_mb': number(f.get('free_memory')),
            'total_memory_mb': number(f.get('total_memory'))}


def interface_rates(rows):
    """Counter deltas, never lifetime byte counters mislabeled as bandwidth.

    Reset/wrap, duplicate timestamp and gaps over 15 minutes produce no rate.
    """
    previous, latest = {}, {}
    def counter(value):
        text = str('' if value is None else value).strip()
        return int(text) if re.fullmatch(r'\d{1,20}',text) and int(text)<2**64 else None
    for row in sorted(rows, key=lambda r: (r['timestamp'], r.get('id', 0))):
        f = row['fields'] or {}
        name = f.get('name')
        if not name:
            continue
        key = (row['router_host'], name)
        now = datetime.fromisoformat(row['timestamp'])
        rx, tx = counter(f.get('rx-byte')), counter(f.get('tx-byte'))
        sample = {'name': name, 'router_host': row['router_host'], 'timestamp': row['timestamp'],
                  'rx_bytes': f.get('rx-byte'), 'tx_bytes': f.get('tx-byte'), 'rx_bps': None, 'tx_bps': None,
                  'rx_drops': f.get('rx-drop'), 'tx_drops': f.get('tx-drop'), 'running': f.get('running')}
        if key in previous:
            before, old_rx, old_tx = previous[key]
            dt = (now-before).total_seconds()
            if 0 < dt <= 900:
                if rx is not None and old_rx is not None and rx >= old_rx:
                    sample['rx_bps'] = round((rx-old_rx)*8/dt, 2)
                if tx is not None and old_tx is not None and tx >= old_tx:
                    sample['tx_bps'] = round((tx-old_tx)*8/dt, 2)
        previous[key] = (now, rx, tx)
        latest[key] = sample
    return list(latest.values())


@router.get('/resources')
def resources(host: str = Query('', max_length=255), hours: int = Query(24, ge=1, le=336)):
    # MCP invokes this function directly, outside FastAPI's parameter coercion.
    if not isinstance(hours,int) or not 1<=hours<=336 or not isinstance(host,str) or len(host)>255:
        raise HTTPException(400, 'Invalid host or telemetry time range')
    raw = telemetry(host=host, family='resource', hours=hours, limit=2000)
    counters = telemetry(host=host, family='if_traffic', hours=hours, limit=10000)
    health = _query('''SELECT DISTINCT ON(router_host,router_fields->>'name')
                      router_host,timestamp,router_fields AS fields
                      FROM logs WHERE log_type='telemetry' AND router_fields->>'script'='health'
                      AND timestamp>=NOW()-(%s*INTERVAL '1 hour') AND (%s='' OR router_host=%s)
                      ORDER BY router_host,router_fields->>'name',timestamp DESC,id DESC''', [hours, host, host])
    return {'series': [resource_sample(r) for r in reversed(raw['data'])],
            'interfaces': interface_rates(counters['data']), 'health': health,
            'truncated': raw['truncated'] or counters['truncated']}


@router.get('/clients')
def clients():
    return {'data': _query('''SELECT mac::text,ip::text,hostname,device_name,network,last_seen
                            FROM unifi_clients WHERE last_seen>NOW()-INTERVAL '14 days'
                            ORDER BY last_seen DESC LIMIT 1000'''), 'source': 'observed DHCP leases'}


@router.get('/config')
def config():
    values = {key: get_config(enricher_db, key, default) for key, default in (
        ('wan_interfaces', []), ('interface_labels', {}), ('vpn_networks', {}),
        ('mikrotik_rule_actions', {}), ('setup_complete', False))}
    values['observed_interfaces'] = [r['name'] for r in _query('''SELECT DISTINCT name FROM
        (SELECT interface_in AS name FROM logs WHERE timestamp>NOW()-INTERVAL '24 hours'
         UNION SELECT interface_out AS name FROM logs WHERE timestamp>NOW()-INTERVAL '24 hours') observed
        WHERE name IS NOT NULL ORDER BY name LIMIT 256''')]
    return values


def validate_config(body):
    import ipaddress
    allowed = {'wan_interfaces', 'interface_labels', 'vpn_networks', 'mikrotik_rule_actions'}
    if set(body) - allowed:
        raise ValueError('Unsupported configuration field')
    wans, labels, vpn, actions = (body.get('wan_interfaces', []), body.get('interface_labels', {}),
                                 body.get('vpn_networks', {}), body.get('mikrotik_rule_actions', {}))
    if not isinstance(wans, list) or not wans or len(wans)>16 or not all(isinstance(x,str) and IFACE.fullmatch(x) for x in wans):
        raise ValueError('Select at least one WAN interface, using its exact RouterOS name (maximum 16).')
    if len(set(wans)) != len(wans):
        raise ValueError('WAN interfaces must be unique.')
    if not isinstance(labels,dict) or len(labels)>256 or not all(isinstance(k,str) and IFACE.fullmatch(k) and isinstance(v,str) and len(v)<=100 and not any(ord(c)<32 for c in v) for k,v in labels.items()):
        raise ValueError('Interface labels must be names of up to 100 characters.')
    if not isinstance(actions,dict) or len(actions)>500 or not all(isinstance(k,str) and 0<len(k)<=100 and not any(ord(c)<32 for c in k) and v in ('allow','block','redirect','unknown') for k,v in actions.items()):
        raise ValueError('Invalid firewall prefix action mapping.')
    if not isinstance(vpn,dict) or len(vpn)>100:
        raise ValueError('Invalid VPN configuration.')
    for iface, entry in vpn.items():
        if not isinstance(iface,str) or not IFACE.fullmatch(iface) or not isinstance(entry,dict):
            raise ValueError('Invalid VPN interface.')
        if not isinstance(entry.get('badge',''),str) or len(entry.get('badge',''))>8:
            raise ValueError('VPN badges are limited to eight characters.')
        if entry.get('cidr'):
            ipaddress.ip_network(entry['cidr'], strict=False)
    return dict(wan_interfaces=wans, interface_labels=labels, vpn_networks=vpn, mikrotik_rule_actions=actions)


@router.put('/config')
def save_config(body: dict):
    try:
        values = validate_config(body)
    except (ValueError, TypeError) as exc:
        raise HTTPException(400, str(exc)) from None
    values.update(setup_complete=True, config_version=2, wizard_path='mikrotik_syslog',
                  unifi_enabled=False, direction_backfill_pending=True)
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            for key,value in values.items():
                cur.execute('''INSERT INTO system_config(key,value,updated_at) VALUES(%s,%s,NOW())
                               ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value,updated_at=NOW()''', [key,Json(value)])
        conn.commit()
    finally:
        put_conn(conn)
    signal_receiver()
    return {'success': True, 'management_access': False}

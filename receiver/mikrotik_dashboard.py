"""WAN-only firewall presentation. No router client or credentials are used."""
import ipaddress
import re

from router_platform import is_mikrotik


def logs_source(alias='logs'):
    """SQL FROM source shared by logs, exports, charts, maps and flow queries.

    Read WAN membership from system_config inside the query, so saved settings
    apply to existing history immediately and an empty WAN list fails closed.
    The alias is a developer-supplied SQL identifier, never request input.
    """
    if not re.fullmatch(r'[a-z][a-z0-9_]*', alias):
        raise ValueError('Invalid SQL alias')
    if not is_mikrotik():
        return 'logs' if alias == 'logs' else 'logs ' + alias
    return """(SELECT * FROM logs WHERE log_type='firewall' AND EXISTS (
        SELECT 1 FROM jsonb_array_elements_text(COALESCE(
            (SELECT CASE WHEN jsonb_typeof(value)='array' THEN value ELSE '[]'::jsonb END
             FROM system_config WHERE key='wan_interfaces'), '[]'::jsonb)) AS wan(name)
        WHERE interface_in=wan.name OR interface_out=wan.name)) AS """ + alias


def category(prefix, interface_in=None, local_interfaces=None):
    text = (prefix or '').lower()
    if 'network-icmp' in text:
        return 'Network-ICMP'
    if text.startswith('fi_a_') and 'icmp' in text:
        return 'Router-ICMP'
    if text.startswith('fi_d_'):
        return 'Router-Port-Scan'
    if any(x in text for x in ('unknown-devic', 'unkown-devic')):
        return 'Unknown-Device'
    if text.startswith('ff_d_') and ('wan' in text or 'port-test' in text):
        return 'Network-Port-Scan'
    if text.startswith('ff_a_') and 'wan' in text:
        label = (local_interfaces or {}).get(interface_in, '')
        return 'LAN-Internet' if label == 'LAN' else 'VLAN-Internet'
    return (prefix or 'Firewall').split('_', 2)[-1]


def presentation(record, labels=None):
    fields = record.get('router_fields') or {}
    prefix = fields.get('prefix') or record.get('rule_name') or ''
    try:
        family = ipaddress.ip_address(str(record.get('src_ip') or record.get('dst_ip'))).version
    except ValueError:
        family = None
    direction = record.get('direction')
    direction_label = {'inbound': 'Inbound', 'outbound': 'Outbound',
                       'local': 'Local', 'inter_vlan': 'Local', 'vpn': 'VPN'}.get(direction, 'Unknown')
    record['ip_version'] = family
    record['direction_label'] = direction_label + (f' IPv{family}' if family else '')
    record['result_label'] = {'allow': 'Accepted', 'block': 'Blocked Traffic',
                              'redirect': 'Redirected'}.get(record.get('rule_action'), 'Unknown')
    record['category_label'] = category(prefix, record.get('interface_in'), labels)
    record['rule_desc'] = record['category_label']
    record['firewall_chain'] = fields.get('chain') or ('input' if prefix.startswith('FI_') else 'forward')
    if record['firewall_chain'] == 'input':
        record['dst_device_name'] = 'Router'
    if record['firewall_chain'] == 'output':
        record['src_device_name'] = 'Router'
    return record


def device_identity(devices, ip, mac=None, interface=None):
    """DHCP comments first, with exact IP/MAC/segment evidence.

    Multiple labels for one MAC on different VLANs must stay distinct. Never
    infer a device from an IPv6 suffix or silently choose an ambiguous name.
    """
    ip = str(ip or '').split('/')[0]
    mac = str(mac or '').lower()
    exact = [d for d in devices if ip and ip in d.get('addresses', [])]
    if mac:
        exact = [d for d in exact if not d.get('mac') or d['mac'].lower() == mac]
    candidates = exact
    if not candidates and mac:
        candidates = [d for d in devices if d.get('mac', '').lower() == mac]
        if interface:
            matched = [d for d in candidates if d.get('interface') == interface]
            if matched:
                candidates = matched
    names = {d['name'] for d in candidates if d.get('name')}
    if len(names) != 1:
        return None
    return next(d for d in candidates if d.get('name') in names)


def group_devices(rows, inventory, fallback_name=lambda ip: None):
    """Combine verified dual-stack identities; keep per-segment names distinct."""
    groups = {}
    for row in rows:
        device = device_identity(inventory,row['ip'],row.get('mac_address'),row.get('interface_in'))
        key = (device['mac'],device.get('interface')) if device else ('ip',row['ip'])
        if key not in groups:
            groups[key] = dict(row,name=device['name'] if device else fallback_name(row['ip']),addresses=[row['ip']])
        else:
            group = groups[key]
            group['count'] += row['count']; group['blocked'] += row['blocked']
            group['addresses'].append(row['ip'])
            if ':' not in row['ip']:
                group['ip'] = row['ip']
    return sorted(groups.values(),key=lambda row:-row['count'])[:8]

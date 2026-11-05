"""Passive RouterOS/Jotne 5.6 syslog adapter; no RouterOS API calls.

RouterOS BSD, ISO8601 and headerless remote logging formats are supported.
Jotne's space-separated and RouterOS as-value semicolon-separated records
remain structured, including unrecognized/new exporter fields and families.
"""
import ipaddress
import re
from datetime import datetime, timezone

from services import get_service_name

RULE_ACTIONS = {}
HEADER = re.compile(r'^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<body>.*)$')
ISO_HEADER = re.compile(r'^(?:1\s+)?(?P<time>\d{4}-\d\d-\d\dT\S+)\s+(?P<host>\S+)\s+(?P<body>.*)$')
TOPICS = re.compile(r'^(?P<topics>(?:[a-z][a-z0-9-]*,)+(?:[a-z][a-z0-9-]*))\s+')
KV = re.compile(r'(?<![\w.-])(?P<key>[.\w-]+)=(?P<value>"(?:\\.|[^"\\])*"|.*?)(?=(?:[;\s]+)[.\w-]+=|[;\s]*$)', re.S)
MAC = re.compile(r'\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b')
FW = re.compile(r'(?P<head>.*?)\bin:(?P<in>.*?)\s+out:(?P<out>[^,]+),(?P<rest>.*)', re.S)
PROTOCOL = re.compile(r'\bproto\s+(?P<proto>[A-Za-z0-9-]+)(?:\s+\((?P<flags>[^)]*)\))?,\s*(?P<src>\[[^]]+\](?::\d+)?|[^\s,]+?)->(?P<dst>\[[^]]+\](?::\d+)?|[^\s,]+)')
JOTNE_ACTION = re.compile(r'^(?:FF|FI|FO|FX|ND|NS|RP|RO|MF|MI|MP|MR)_(?P<action>[A-Z]+)(?:_|$)')


def parse_fields(text):
    result = {}
    for m in KV.finditer(text):
        value = m['value'].strip().rstrip(';')
        if value.startswith('"') and value.endswith('"'):
            value = value[1:-1].replace(r'\"', '"').replace(r'\\', '\\')
        result[m['key']] = value
    return result


def _ip(value):
    try:
        return str(ipaddress.ip_address(value))
    except (ValueError, TypeError):
        return None


def _endpoint(value):
    if value.startswith('['):
        match = re.fullmatch(r'\[([^]]+)\](?::(\d+))?', value)
        if not match:
            return None, None
        addr, port = match.groups()
    elif value.count(':') == 1 and '.' in value:
        addr, port = value.rsplit(':', 1)
    else:
        addr, port = value, None
    port = int(port) if port and port.isdigit() and int(port) <= 65535 else None
    return _ip(addr), port


def _interface(value):
    value = value.strip()
    if value.lower() in ('(unknown 0)', '(unknown)', 'unknown', '(none)', 'none', ''):
        return None
    # RouterOS may append a bridge port in parentheses. Preserve it separately
    # in the raw message; classification uses the interface's exact base name.
    return value.split('(', 1)[0].strip()


def rule_action(prefix):
    if prefix in RULE_ACTIONS:
        return (None if RULE_ACTIONS[prefix] == 'unknown' else RULE_ACTIONS[prefix]), 'configured prefix'
    m = JOTNE_ACTION.match(prefix)
    if m:
        action = {'A': 'allow', 'F': 'allow', 'D': 'block', 'RJ': 'block',
                  'DE': 'redirect', 'RE': 'redirect', 'T': 'block'}.get(m['action'])
        if prefix[:2] in ('ND', 'NS') and m['action'] in ('M', 'S', 'N'):
            action = 'redirect'
        if action:
            return action, 'Jotne prefix'
    m = re.match(r'^(DROP|DENY|REJECT|BLOCK|ACCEPT|ALLOW)(?:\b|[_:\[ -])', prefix, re.I)
    if m:
        return ('allow' if m[1].upper() in ('ACCEPT', 'ALLOW') else 'block'), 'explicit prefix'
    # action=log, invalid, connection-state and chain names do not prove a verdict.
    return None, 'not present in syslog'


def parse_firewall(body):
    from parsers import derive_direction, WAN_INTERFACES
    m = FW.search(body)
    if not m:
        return None
    p = PROTOCOL.search(m['rest'])
    if not p:
        return None
    head = m['head'].strip().rstrip(':').strip()
    # RouterOS prints the actual custom chain too (e.g. ZT6-INTERNET).
    chain_match = re.search(r'(?:^|\s)(input|forward|output|prerouting|postrouting)$', head, re.I)
    if not chain_match and ' ' in head:
        chain_match = re.search(r'\s+([A-Za-z0-9_.-]+)$', head)
    chain = chain_match[1] if chain_match else None
    if chain and chain.lower() in ('input', 'forward', 'output', 'prerouting', 'postrouting'):
        chain = chain.lower()
    prefix = head[:chain_match.start()].strip().rstrip(':') if chain_match else head
    src, sport = _endpoint(p['src'])
    dst, dport = _endpoint(p['dst'])
    iface_in, iface_out = _interface(m['in']), _interface(m['out'])
    action, evidence = rule_action(prefix)
    fields = {'chain': chain, 'prefix': prefix, 'action_source': evidence,
              'tcp_flags': p['flags']}
    if 'icmp' in p['proto'].lower():
        for key in ('type', 'code'):
            value = re.search(r'\b' + key + r'[ :=]*(\d+)', p['flags'] or '')
            if value:
                fields['icmp_' + key] = int(value[1])
    for key in ('connection-state', 'connection-mark', 'packet-mark'):
        match = re.search(re.escape(key) + r':([^,\s]+)', m['rest'])
        if match:
            fields[key] = match[1]
    length = re.search(r'\blen\s+(\d+)', m['rest'])
    if length:
        fields['packet_length'] = int(length[1])
    mac = re.search(r'\bsrc-mac\s+(' + MAC.pattern.replace(r'\b', '') + ')', m['rest'], re.I)
    direction_rule = 'WAN_LOCAL' if chain == 'input' and iface_in in WAN_INTERFACES else ''
    return {'log_type': 'firewall', 'src_ip': src, 'dst_ip': dst,
            'src_port': sport, 'dst_port': dport, 'protocol': p['proto'].lower(),
            'interface_in': iface_in, 'interface_out': iface_out,
            'rule_name': prefix[:100] or None, 'rule_desc': None,
            'rule_action': action, 'mac_address': mac[1].lower() if mac else None,
            'service_name': get_service_name(dport, p['proto'].lower()),
            'direction': derive_direction(iface_in, iface_out, direction_rule, src, dst) if WAN_INTERFACES else None,
            'router_fields': fields}


def parse_routeros(raw, sender_host=None):
    from parsers import parse_syslog_timestamp
    if not raw.strip():
        return None
    text = re.sub(r'^<\d{1,3}>', '', raw.strip())
    timestamp = datetime.now(timezone.utc)
    host = sender_host
    header = HEADER.match(text)
    iso = ISO_HEADER.match(text)
    if header:
        timestamp = parse_syslog_timestamp(header['month'], header['day'], header['time'])
        if timestamp is None:
            return None
        host, text = header['host'], header['body']
    elif iso:
        try:
            timestamp = datetime.fromisoformat(iso['time'].replace('Z', '+00:00'))
            if timestamp.tzinfo is None:
                return None
            timestamp = timestamp.astimezone(timezone.utc)
        except ValueError:
            return None
        host, text = iso['host'], iso['body']
    topics = []
    match = TOPICS.match(text)
    if match:
        topics = match['topics'].split(',')
        text = text[match.end():]
    # Jotne installation prefix often supplies serial + MikroTik marker, even
    # when RouterOS remote logging omits the hostname/timestamp entirely.
    marker = re.search(r'(?:serial=(?P<serial>[^\s;]+)\s+)?[Mm]ikro[Tt]ik:\s*', text)
    serial = marker['serial'] if marker else None
    if marker:
        text = text[marker.end():]
    fields = parse_fields(text)
    # A neighbor's serial belongs to that observed neighbor, not the sender.
    serial = serial or (fields.get('serial') if fields.get('script') == 'sysinfo' else None)
    parsed = parse_firewall(text)
    script = fields.get('script')
    if parsed is None and script:
        # Every exporter family is retained, including future/optional ones.
        parsed = {'log_type': 'telemetry', 'router_fields': fields}
        if script in ('if_traffic', 'interface'):
            parsed['interface_in'] = fields.get('name')
        if script == 'wifi':
            parsed['mac_address'] = fields.get('mac-address')
            parsed['interface_in'] = fields.get('interface')
    if parsed is None and ('dhcp' in topics or re.search(r'\b(?:de)?assigned\s+\d+\.\d+\.', text)):
        parsed = {'log_type': 'dhcp', 'router_fields': fields}
        lease = re.search(r'(?P<server>\S+)\s+(?P<event>deassigned|assigned)\s+(?P<ip>\S+)\s+(?:from|to|for)\s+(?P<mac>' + MAC.pattern.replace(r'\b', '') + r')(?:\s+(?P<name>.*))?$', text, re.I)
        if lease:
            parsed.update(src_ip=_ip(lease['ip']), mac_address=lease['mac'].lower(),
                          dhcp_event=lease['event'].lower(),
                          hostname=(lease['name'] or '').strip(' ()')[:255] or None)
            parsed['router_fields']['dhcp_server'] = lease['server']
        else:
            mac = MAC.search(text)
            if mac:
                parsed['mac_address'] = mac[0].lower()
    if parsed is None and 'dns' in topics:
        parsed = {'log_type': 'dns', 'router_fields': fields}
        query = re.search(r'query from\s+(\S+):\s+#(\d+)\s+(\S+)\s+(\S+)', text)
        if query:
            parsed.update(src_ip=_ip(query[1].strip('[]')), dns_query=query[3].rstrip('.')[:255], dns_type=query[4][:10])
            fields['query_id'] = query[2]
        done = re.search(r'done query:\s+#(\d+)\s+(\S+)\s+(\S+)', text)
        if done:
            parsed.update(dns_query=done[2].rstrip('.')[:255], dns_answer=done[3][:255])
            fields['query_id'] = done[1]
        question = re.search(r'question:\s+([^:]+):([A-Z0-9]+):', text)
        if question:
            parsed.update(dns_query=question[1].rstrip('.')[:255], dns_type=question[2][:10])
    if parsed is None and any(t in topics for t in ('wireless', 'wifi', 'caps')):
        parsed = {'log_type': 'wifi', 'router_fields': fields}
        mac = MAC.search(text)
        if mac:
            parsed['mac_address'] = mac[0].lower()
        event = re.search(r'\b(disconnected|connected|rejected|associated|disassociated|authenticated)\b', text)
        parsed['wifi_event'] = event[1] if event else None
        iface = re.search(r'@([^\s:,]+)', text)
        parsed['interface_in'] = iface[1] if iface else None
    if parsed is None:
        parsed = {'log_type': 'system', 'router_fields': fields}
        login = re.search(r'(?:login failure for user\s+\S+\s+from|logged (?:in|out) from)\s+(\S+)', text)
        if login:
            parsed['src_ip'] = _ip(login[1])
        # VPN/system events stay searchable without inventing packet-flow fields.
    mac = parsed.get('mac_address')
    if mac and not MAC.fullmatch(mac):
        parsed['mac_address'] = None
    parsed.update(timestamp=timestamp, raw_log=raw, router_host=host,
                  router_serial=serial, router_topics=topics)
    return parsed

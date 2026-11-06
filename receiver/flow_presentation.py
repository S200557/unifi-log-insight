"""MikroTik flow labels without inventing missing packet fields."""

PORT_LABEL = """COALESCE(dst_port::text, CASE
    WHEN LOWER(protocol) IN ('icmp', 'icmpv6', 'ipv6-icmp', '1', '58')
        THEN CASE WHEN family(src_ip)=6 THEN 'ICMPv6 (no ports)' ELSE 'ICMP (no ports)' END
    WHEN protocol='47' THEN 'GRE (no ports)'
    WHEN protocol='4' THEN 'IP-in-IP (no ports)'
    WHEN protocol='41' THEN 'IPv6 tunnel (no ports)'
    ELSE UPPER(COALESCE(protocol, 'IP')) || ' (port not logged)' END)"""

SERVICE_LABEL = """COALESCE(NULLIF(NULLIF(service_name, 'Unknown'), ''),
    CASE WHEN dst_port IS NOT NULL
        THEN UPPER(COALESCE(protocol, 'IP')) || '/' || dst_port::text
        ELSE """ + PORT_LABEL + " END)"


def dimension_expressions(base, mikrotik):
    expressions = dict(base)
    if mikrotik:
        expressions.update({
            'dst_port': PORT_LABEL,
            'service_name': SERVICE_LABEL,
            'interface_in': "COALESCE(interface_in, 'router')",
            'interface_out': "COALESCE(interface_out, 'router')",
        })
    return expressions


def describe_nodes(nodes, grouped_rows, dimensions, top_n):
    """Explain top-N aggregation; keep raw labels compatible with filters."""
    labels = {'src_ip': 'source IPs', 'dst_ip': 'destination IPs',
              'dst_port': 'ports', 'service_name': 'services',
              'protocol': 'protocols', 'direction': 'directions',
              'interface_in': 'source zones', 'interface_out': 'destination zones'}
    for node in nodes:
        if node['label'] == 'Other':
            index = dimensions.index(node['type'])
            remaining = max(0, len({row[index] for row in grouped_rows}) - top_n)
            node['display_label'] = f"{remaining} more {labels[node['type']]}"
            node['actionable'] = False
        elif node['type'] == 'dst_port' and not node['label'].isdigit():
            # A protocol without ports cannot be used as a numeric port filter.
            node['actionable'] = False
        elif node['type'] == 'service_name' and ('/' in node['label'] or '(' in node['label']):
            # Fallback protocol descriptions are not stored service names.
            node['actionable'] = False
        elif node['type'] in ('interface_in', 'interface_out') and node['label'] == 'router':
            node['display_label'] = 'Router'
            node['actionable'] = False
    return nodes

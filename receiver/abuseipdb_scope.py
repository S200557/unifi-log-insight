"""Fail-closed MikroTik boundary for external reputation lookups."""
import ipaddress
import logging

from db import get_config, get_wan_ips_from_config

logger = logging.getLogger('abuseipdb.scope')


def allowed_remote_ip(db, value):
    """Only a public remote endpoint observed in a blocked WAN packet.

    Exclude configured local networks, inventory, gateway/WAN addresses, and
    locally observed endpoints (including their IPv6 /64). This final check is
    shared by live, queued, stale and manual API calls. No router access.
    """
    try:
        ip = ipaddress.ip_address(value)
        if not ip.is_global or db is None:
            return False
        wans = get_config(db, 'wan_interfaces')
        networks = get_config(db, 'mikrotik_local_networks')
        if not isinstance(wans, list) or not wans or not isinstance(networks, list) or not networks:
            return False
        if any(ip in ipaddress.ip_network(cidr, strict=False) for cidr in networks):
            return False
        owned = list(get_wan_ips_from_config(db)) + list(get_config(db, 'gateway_ips') or [])
        for device in get_config(db, 'mikrotik_device_inventory') or []:
            owned.extend(device.get('addresses', []))
        if any(ip == ipaddress.ip_address(str(address).split('/')[0]) for address in owned):
            return False
        with db.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT EXISTS (
                        SELECT 1 FROM logs WHERE log_type='firewall' AND rule_action='block'
                        AND timestamp >= NOW() - INTERVAL '14 days'
                        AND ((interface_in = ANY(%s) AND src_ip=%s::inet)
                          OR (interface_out = ANY(%s) AND dst_ip=%s::inet))
                    ) AND NOT EXISTS (
                        SELECT 1 FROM logs WHERE log_type='firewall'
                        AND timestamp >= NOW() - INTERVAL '14 days'
                        AND ((interface_in <> ALL(%s) AND (
                            src_ip=%s::inet OR (family(src_ip)=6 AND set_masklen(src_ip,64) >>= %s::inet)))
                          OR (interface_out <> ALL(%s) AND (
                            dst_ip=%s::inet OR (family(dst_ip)=6 AND set_masklen(dst_ip,64) >>= %s::inet))))
                    )
                """, [wans, str(ip), wans, str(ip), wans, str(ip), str(ip), wans, str(ip), str(ip)])
                return cur.fetchone()[0] is True
    except Exception:
        logger.warning('Reputation scope could not be verified; external lookup skipped')
        return False

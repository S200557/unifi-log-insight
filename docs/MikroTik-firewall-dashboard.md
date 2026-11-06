# WAN firewall dashboard

The MikroTik build opens a light network-console overview at `/#dashboard`.
The sidebar retains firewall logs, flow analysis, the geographic map, gateway
telemetry and settings. The upstream UniFi build retains its existing theme and
navigation behavior.

## Scope

All firewall log, export, statistics, flow and threat-map SQL sources use one
WAN predicate: `log_type='firewall'` and either packet interface belongs to the
saved `wan_interfaces` list. This applies to historical events too. Empty or
invalid WAN configuration fails closed. Local/inter-VLAN ICMPv6 does not enter
the dashboard, even when it shares a prefix with WAN ICMPv6. Stored local,
telemetry, DHCP and system history is retained; gateway telemetry still uses its
dedicated endpoints.

The interface list is app-local configuration. The receiver never obtains router
management credentials, adds trust entries, or writes RouterOS configuration.

## Flows, map and external reputation

Traffic flows opens the Zone Matrix for MikroTik. The optional flow graph starts
with source zone, protocol and destination zone; IP and port dimensions remain
available. Portless ICMP/ICMPv6 and tunnel protocols have explicit labels.
Top-N remainder nodes show how many values are grouped rather than implying
unknown identity. Changing dimensions does not discard the underlying events.

The MikroTik world map defaults to **WAN Activity** (all geolocated WAN events),
with separate **Blocked WAN**, **Threats** (score above 70) and **Blocked
Outbound** filters. An unscored IP is not evidence of safety or maliciousness.
Map request failures are visible rather than silently rendered as empty data.

AbuseIPDB uses the existing private `ABUSEIPDB_API_KEY` deployment setting.
Only the remote public endpoint of an observed blocked WAN event is eligible
for an external check. The final API-call guard covers live, queued, stale and
manual lookups. It rejects private/reserved addresses, configured local CIDRs,
router WAN/gateway addresses, inventory addresses and locally observed endpoints
(including their IPv6 /64). Missing scope configuration or database errors fail
closed. `mikrotik_local_networks` must contain reviewed local IPv4 networks and
delegated IPv6 prefixes; refresh it after network/delegation changes. Observed
local-side IPv6 prefixes also protect dynamically learned client addresses.
No hostnames, MAC addresses, private addresses or raw messages are submitted.
Checks do not report IPs or change firewall policy. Existing API quota and cache
handling applies. GeoIP remains local and independent of AbuseIPDB.

## Presentation

Packet rows display **Direction** (`Inbound IPv4`, `Outbound IPv6`, etc.),
**Result** (`Accepted`, `Blocked Traffic`) and **Category** separately. Category
examples are Router-ICMP, Router-Port-Scan, Network-Port-Scan, LAN-Internet,
VLAN-Internet, Unknown-Device and Network-ICMP. Raw prefixes remain unchanged.

Input events label the destination **Router** while preserving the actual
packet destination address. IPv6 family is derived from addresses, not a name
suffix. Custom chains such as ZT4-INTERNET remain intact in packet details.
Network-ICMP can appear as inbound or outbound according to packet interfaces.
An Unknown-Device category describes failed policy admission, not absence of a
known device name. Port-Scan names are categories, not scan-detection claims.

Counts are logged packets, not total bandwidth, complete connection counts or
all Internet traffic. Earlier rules and FastTrack may bypass logging.

## Device labels

Private inventory lives in the app's `mikrotik_device_inventory` setting as a
list of `{mac,name,addresses,interface,vlan,label_source}` objects. Populate it
from reviewed DHCP comments and an existing verified network map, with observed
IPv6-to-MAC/interface correlations. No private inventory should be committed.

DHCP comments take precedence over advertised hostnames. Same-MAC devices with
different per-network labels require an exact address or interface match;
ambiguous matches stay unnamed. A WAN next-hop MAC must not name an external
sender as a local device. Keep labels and device Internet permission separate.

To import a reviewed inventory inside the container:

```sh
python3 /app/mikrotik_maintenance.py --inventory /tmp/device-inventory.json --backfill
```

The input JSON contains `devices`, `wan_interfaces`, `interface_labels` and
`observed_at`. It does not contain router credentials. `--backfill` reparses
existing RouterOS firewall metadata in bounded batches, correcting custom-chain
prefix extraction and direction without deleting events or changing raw logs.
It is optional for fresh installations. Importing is an explicit operator action;
there is no automatic management poller. Later passive DHCP assignments remain
observed by the existing receiver; reviewed MAC names can label new addresses.

Tests cover custom chains, suffix-free IPv6 ICMP, family/direction/result display,
ambiguous MACs, DHCP-comment precedence, WAN sender exclusion and query-source
isolation. A temporary-table PostgreSQL check should prove WAN ingress, WAN
egress and input-to-router inclusion, local/inter-VLAN exclusion, and fail-closed
behavior without writing synthetic logs to the persistent event table.

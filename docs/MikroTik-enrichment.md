# Local GeoIP and ASN enrichment

MikroTik Insights can use either MaxMind GeoLite2 or the free, monthly
[DB-IP City Lite](https://db-ip.com/db/download/ip-to-city-lite) and
[ASN Lite](https://db-ip.com/db/download/ip-to-asn-lite) MMDB databases.
DB-IP Lite needs no account or API key. Locations are approximate; Lite has
reduced accuracy and coverage. It is licensed CC BY 4.0, and the application
displays the required DB-IP attribution link on pages using its data.

For DB-IP, add these non-secret settings to the private Compose environment:

```dotenv
GEOIP_PROVIDER=dbip-lite
GEOIP_DATA_DIR=/absolute/private/path/geoip
```

Create that directory, then recreate the app with the same Compose project
and existing database volume. The directory must be mounted at `/app/maxmind`.
With the app running, install the databases on the Docker host:

```sh
python3 scripts/update-dbip.py --directory /absolute/private/path/geoip \
  --container mikrotik-insights-staging
```

The updater downloads only from the official DB-IP HTTPS endpoint. It checks
gzip integrity, size, and real IPv4/IPv6 City/ASN lookups using the app's reader
before replacing either database. A manifest records provider, release, license,
URLs and SHA-256 hashes. The inherited `GeoLite2-*.mmdb` filenames are compatibility
paths; these remain DB-IP data. After a new release, the updater restarts only
the selected application container so receiver and API readers both reload.
The database volume is retained. Re-running during the same month does not
download or restart. Failed downloads/validation leave existing databases intact.

Schedule a daily check at 07:15 in the app's configured timezone, converting
that to the host cron timezone if different. Preserve unrelated cron entries.
Only new monthly releases cause a download/restart; redirect output to a private
log. Health exposes the active provider, loaded database date and next check.
The original MaxMind credential-based updater remains available when choosing
the MaxMind provider instead.

# Dashboard access and logging

The MikroTik profile opens Router telemetry by default. Other views have direct
hash links: `#dashboard`, `#logs`, `#flow-view`, and `#threat-map`.

Keep the backend HTTP binding on loopback. Authentication requires an HTTPS
reverse proxy with the app's `X-ULI-Proxy-Auth` token; see the upstream
authentication documentation. Store proxy tokens, TLS keys, login credentials
and deployment overrides outside Git with restrictive permissions. Provision
the first administrator before exposing the HTTPS listener. A private CA must
be explicitly trusted by the user's browser; do not disable TLS validation.

For a parallel RouterOS destination, add a separate remote action and logging
rule after approval. Preserve existing destinations. A topic filter such as
`!debug,!packet,!snmp,!dns` excludes DNS/debug/packet/SNMP messages while still
including the Jotne script telemetry. The app does not modify RouterOS itself.

# Optional integrations

AbuseIPDB requires the user's own API key in the private environment's
`ABUSEIPDB_API_KEY`. The retained integration checks public IPs for blocked
firewall events, caches results and respects request budgets. It does not report
IPs or modify router rules. Without a key, scores remain unavailable.

Reverse DNS remains optional and disabled by the MikroTik Compose default.
DNS collection and Pi-hole polling are unnecessary when using a separate
AdGuard Home deployment; configuring GeoIP/ASN does not enable either service.

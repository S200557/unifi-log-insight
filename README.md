# MikroTik Insights Plus

A passive **RouterOS syslog and Jotne exporter** adaptation of [UniFi Insights Plus](https://github.com/jmasarweh/UniFi-Insights-Plus), based on upstream **3.7.2**. It keeps the existing live log stream, dashboard, Sankey flows, interface matrix, host drill-down, filters, threat map, IP enrichment, CSV export, retention, settings backup/restore, authentication, API tokens and MCP.

It adds native RouterOS parsing and a **Router telemetry** page for CPU, memory, disk, uptime, health sensors, interface rates and structured exporter records. Device names come from observed DHCP leases. There is **no router management client** in the MikroTik workflow: setup does not require router credentials and cannot edit router rules or scripts.

[Design and feature mapping](docs/MikroTik-design.md) · [Original upstream README](docs/UPSTREAM_README.md) · [License](LICENSE)

## Run

Requirements: Docker with Compose, and an existing RouterOS syslog source. The supported formats are RouterOS headerless/default, BSD/RFC3164 and ISO8601 syslog over UDP, plus Jotne 5.6 structured messages. TCP/TLS and CEF framing are not implemented.

1. Use the `mikrotik-adaptation` branch.
2. Copy `.env.mikrotik.example` to a private file **outside the checkout**, protect it with mode 600, and replace both secret placeholders with independent random values. Keep that file and captured syslog out of Git.
3. Build and start:

```sh
docker compose -p mikrotik-insights \
  --env-file /private/path/mikrotik.env \
  -f docker-compose.mikrotik.yml up -d --build
```

The default bindings are **127.0.0.1:8091** for the UI and **127.0.0.1:1515/udp** for syslog. The container listens on UDP 514 internally. These loopback bindings suit isolated staging. An SSH tunnel can expose the preview locally:

```sh
ssh -N -L 8091:127.0.0.1:8091 your-staging-server
```

Open `http://127.0.0.1:8091`. Authentication defaults to enabled. Complete the initial local administrator setup, then select the exact WAN interface names and optional labels under **Syslog & networks**. RouterOS names such as `bridge`, `pppoe-out1` and `MGMT-50` are accepted; names do not imply VLAN IDs or trust.

To receive live router logs, deliberately choose the intended private host binding and authorized syslog destination. Do not replace an existing Splunk destination or change router logging without reviewing and approving that separate network change. The software itself never performs that change.

## Data and optional features

- The MikroTik Compose file uses a separate PostgreSQL volume and 14-day event/DNS retention by default. Telemetry follows the same retained event stream. Settings allow retention changes and cleanup.
- Firewall events without an evidenced action remain **unknown**. Known Jotne prefixes are recognized, and exact prefix meanings can be configured locally. Logged-event counts are not bandwidth totals.
- Interface rates use successive exported byte counters. Resets, duplicate timestamps and gaps over 15 minutes produce no rate.
- Every exporter family and field is preserved. Optional routing, VPN, Wi-Fi and UPnP tables can be empty when no corresponding records arrive. Neighbor attributes are assembled from Jotne's separate messages.
- Local MaxMind databases or optional MaxMind account credentials enable country/ASN data. An optional AbuseIPDB key enables threat scores. Reverse DNS is available but defaults off in this Compose file. Credentials can be supplied through the private environment file; the corresponding variables are passed into the container.
- Pi-hole integration remains available. UniFi controller setup, policy-write controls and its browser extension are excluded. No AdGuard integration is claimed.
- External PostgreSQL remains supported through `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASSWORD` and `DB_SSLMODE`; the entrypoint disables embedded PostgreSQL for a remote database. Historical default database/cache names are preserved for compatibility.
- The dashboard is a focused syslog application, not an implementation of the Splunk search language or every custom Splunk dashboard.

## Development and replay

Ubuntu is the development/build/staging environment. The backend runtime is Python 3.12 in the Ubuntu 24.04 image; the UI uses the upstream locked npm dependencies. Run `pytest` from `receiver/`, and `npm test` from `ui/`. For the MikroTik UI use `VITE_ROUTER_PLATFORM=mikrotik npm run build` or `npm run dev` with that variable set.

`tools/replay_syslog.py` sends a private Splunk JSONL export containing `event_epoch`, `host` and `_raw` to the staging UDP listener, preserving original timestamps:

```sh
python3 tools/replay_syslog.py /private/path/sample.jsonl --rate 100
```

Set `INGESTION_MODE=staging-replay` for that environment; the UI then clearly labels replayed history. Do not commit replay data. An isolated loopback-only staging instance may explicitly disable authentication in its private environment file; keep it enabled before broader exposure.

The original UniFi profile remains available for upstream regression work with `ROUTER_PLATFORM=unifi` and the corresponding UI build variable. The Docker build argument selects both stages consistently. Existing upstream attribution and **Business Source License 1.1** remain intact.

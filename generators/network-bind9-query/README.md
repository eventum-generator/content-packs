# BIND 9 query log

Synthetic ISC BIND 9.18 `queries` category records from one recursive resolver serving 24 internal clients (4 servers and 20 workstations), for DNS monitoring and DNS-exfiltration detection testing. Each event carries the native `named` query-log line in `event.original` plus ECS fields parsed from it.

## Event Types

Shares over four days of default output (51,750 events). The traffic mix is a synthetic assumption, not measured resolver traffic.

| Query | Share | Category | Description |
| --- | ---: | --- | --- |
| `A` | 43.8% | network | Host lookups under `example.com`, `example.net`, `example.org`, plus the mail host after an `MX` |
| `AAAA` | 22.0% | network | IPv6 lookups, usually right after the matching `A` |
| `TXT` on analytics zones | 13.8% | network | Workstation runs of high-entropy labels under `metrics.example.net` / `insights.example.org` |
| `PTR` | 7.9% | network | Reverse lookups in `10.in-addr.arpa`, mostly from servers |
| `MX` | 4.8% | network | Mail-exchanger lookups by servers |
| `TXT` on tunnel zones | 3.5% | network | Short workstation runs of high-entropy labels under the tunnel zones, plus the anomaly episodes |
| `TXT` DKIM / DMARC | 3.1% | network | `<selector>._domainkey.<domain>` and `_dmarc.<domain>` lookups by servers |
| `A` / `AAAA` / `NS` on tunnel-zone apex | 1.2% | network | Workstation lookups of the tunnel zones themselves |

About 3% of queries arrive over TCP (`T` flag). Flags follow the BIND order: recursion (`+`/`-`), `E(0)`, `T`, `D`, then cookie `V` or `K`. About 90% of queries carry EDNS (`E(0)`). DO (`D`) and the cookie flags come from the EDNS OPT record, so they appear only together with `E(0)`; a query without EDNS shows only `+`/`-` and `T`.

## Volume and Daily Curve

About 12,900 queries a day; each day's volume varies by up to 3%. Hours are UTC.

- **Workstations** work nine-hour shifts: a quarter 07:00-16:00, half 08:00-17:00, a quarter 09:00-18:00. With every shift in (09:00-16:00) they send 900 queries an hour, about 45 per workstation. About 30% of the workstations stay switched on overnight and send 50 queries an hour between them around the clock.
- **Servers** send 150 queries an hour around the clock.
- The result is about 1.5% of the day's queries per hour at night, 3.3% at 07:00 and 17:00, 6.8% at 08:00 and 16:00, and about 8.5% per hour from 09:00 to 16:00.

## Anomaly Chain

A DNS-exfiltration burst: one workstation sends a run of TXT queries to one tunnel zone, each with a distinct high-entropy first label.

1. `TXT` query for `<hex>.<zone>` from client `C`, where `<zone>` is one of `tunnel_zones`.
2. Seven further `TXT` queries from `C` for new `<hex>.<zone>` names under the same `<zone>`, all within one hour of the first.

- **Linking fields:** `source.ip` and `dns.question.registered_domain`. Every label is new, so `dns.question.name` never repeats.
- **Episode shape:** eight queries a few seconds apart, spanning about 1-5 minutes. The client is a workstation active at that hour (on shift, or left on overnight) that has sent no TXT query to that zone in the preceding hour. Nothing from the episode follows the eighth query. When ordinary tunnel-zone queries of the same client fall inside the episode, the chain completes that many queries earlier and the rest of the episode is not sent.
- **Recurrence:** the first episode starts within the first `anomaly_interval_hours` (at most 24 h) of generation, at a time of day drawn from the workstation hour curve. Each later episode is due `anomaly_interval_hours` after the actual start of the previous one (default 24, minimum 2) and starts within a window centred on that due time, a quarter of the interval wide (at most 6 hours), favouring busier hours. At the default interval, episodes fall mostly in working hours, about 21-27 hours apart; at 8 hours they are 7-9 hours apart and some fall at night, on a workstation left on.
- **Variation:** the client and the tunnel zone both change from one episode to the next, and every label is freshly random.
- **Background overlap:** each part of the chain also occurs on its own in both modes. Every workstation sends high-entropy TXT queries to both tunnel zones in short runs (1-2 queries typical), from a few to about 30 times a day per zone, and also looks up the zone apex. A client reaches seven TXT queries to one tunnel zone within an hour about 7-13 times a day, but outside episodes never eight. Runs of 8 or more high-entropy TXT queries from one client to one analytics zone within an hour occur about 80-100 times a day.
- **Volume:** episodes do not change the total query volume or its hourly curve; an episode's queries take the place of other queries in the same minutes. With `anomaly_mode: true`, the tunnel-zone TXT count is therefore about eight per episode higher than with `anomaly_mode: false`.
- **Detection idea:** alert when a single client sends 8 or more TXT queries with distinct long labels to one watched zone within an hour. Query logs record requests only, with no response codes or answer data, so a match shows the pattern, not that data was actually transferred.

`anomaly_mode` defaults to `true`. Set it to `false` to get background traffic only, with no complete chain.

## Parameters

### Event Parameters

Set under `event.template.params` in `generator.yml`.

| Name | Default | Description |
| --- | --- | --- |
| `anomaly_mode` | `true` | Add the recurring exfiltration episodes |
| `anomaly_interval_hours` | `24` | Hours of source time between episodes (2 to 8760) |
| `server_name` | `ns1.example.test` | Resolver host name (`host.name`, `observer.hostname`) |
| `server_ip` | `10.20.30.53` | Address the queries arrive on, as it appears in the log line |
| `client_prefix` | `10.20.40.` | First three octets of the client addresses |
| `client_first` | `11` | Last octet of the first client |
| `client_count` | `24` | Number of clients, servers included |
| `server_count` | `4` | How many of the first client addresses are servers; the rest are workstations (at least 4) |
| `tunnel_zones` | `telemetry.example.test`, `sync.example.test` | Zones the episodes target, also queried in background (at least 2) |
| `analytics_zones` | `metrics.example.net`, `insights.example.org` | Zones that receive long high-entropy TXT runs in background (at least 2) |

### Output Parameters

The shipped configuration writes to `output/events.json` and needs no parameters or secrets. To send events to a backend instead, replace the `file` output in a local copy and use placeholders for connection values, for example:

```yaml
output:
  - opensearch:
      hosts:
        - ${params.opensearch_host}
      username: ${params.opensearch_user}
      password: ${secrets.opensearch_password}
      index: bind9-query
```

## Usage

```bash
eventum generate --path generators/network-bind9-query/generator.yml --id bind9 --live-mode true
```

For a finite batch, give every file under `patterns/` an explicit window starting at midnight UTC, for example `start: "2026-09-01T00:00:00+00:00"` and `end: "2026-09-05T00:00:00+00:00"`, and run with `--live-mode false`. Without the `+00:00` offset the window is read in the local time zone and the daily curve shifts.

Performance: about 3,000 events per second (14 days of default output, about 180,000 events, in about a minute).

## Sample Output

The query that completes an episode, from default `anomaly_mode: true` output:

```json
{"@timestamp": "2026-09-01T17:21:39.576000+00:00", "bind9": {"query": {"client_object": "@0x7fff9ced1927", "flags": "+E(0)K"}}, "destination": {"ip": "10.20.30.53", "port": 53}, "dns": {"question": {"class": "IN", "name": "bcc9a59a2f23b1879b033c138a3cac4f5746.sync.example.test", "registered_domain": "sync.example.test", "type": "TXT"}, "type": "query"}, "ecs": {"version": "8.17.0"}, "event": {"action": "dns-query", "category": ["network"], "dataset": "bind9.query", "kind": "event", "original": "2026-09-01T17:21:39.576Z queries: info: client @0x7fff9ced1927 10.20.40.33#1195 (bcc9a59a2f23b1879b033c138a3cac4f5746.sync.example.test): query: bcc9a59a2f23b1879b033c138a3cac4f5746.sync.example.test IN TXT +E(0)K (10.20.30.53)", "type": ["protocol", "info"]}, "host": {"name": "ns1.example.test"}, "network": {"protocol": "dns", "transport": "udp"}, "observer": {"hostname": "ns1.example.test", "product": "BIND", "type": "dns", "vendor": "ISC"}, "related": {"ip": ["10.20.40.33", "10.20.30.53"]}, "source": {"ip": "10.20.40.33", "port": 1195}}
```

## Limitations

- The native line follows BIND 9.18 source code (`ns_client_logv`, `log_query`, the file-channel writer and the ISO 8601 time formatter). It assumes a file channel with `print-time iso8601-utc; print-category yes; print-severity yes;`. Other channel settings change the prefix, and syslog adds its own header.
- The ARM publishes only the message part of the line (from `client @0x...` on). The prefix is taken from the source code, not from a published capture.
- Only the default view is modelled, so the `: view <name>` suffix never appears. Signed queries (`S`), `CD` (`C`), EDNS Client Subnet (`[ECS ...]`) and IPv6 clients are not generated.
- `client @0x...` is a random pointer-like value per query. BIND reuses client objects, and that reuse is not modelled.
- `dns.question.registered_domain` holds the delegated service zone (for example `sync.example.test`), not the public-suffix registered domain.
- Query logs contain no responses. Episodes are identified by the request pattern alone.
- Queries that belong together (an `A` and its `AAAA`, an `MX` and the mail host lookup, the queries of a run) are seconds apart rather than milliseconds: an `AAAA` follows its `A` after a median of 3.5 seconds.
- Every day follows the same working-day curve in UTC; weekends, holidays and local time zones are not modelled. Shifts start exactly on the hour.
- Outside episodes no client sends eight TXT queries to one tunnel zone within an hour, while runs of seven occur several times a day.
- Traffic mix, shifts, rates and episode shape are synthetic.

## References

- [BIND 9.18 logging categories: `queries` field description and example lines](https://bind9.readthedocs.io/en/v9.18.28/reference.html#logging-categories)
- [BIND 9.18 `print-time` options](https://bind9.readthedocs.io/en/v9.18.28/reference.html#namedconf-statement-print-time)
- [BIND 9.18.28 `lib/ns/query.c` (`log_query`)](https://gitlab.isc.org/isc-projects/bind9/-/blob/v9.18.28/lib/ns/query.c)
- [BIND 9.18.28 `lib/ns/client.c` (`ns_client_logv`)](https://gitlab.isc.org/isc-projects/bind9/-/blob/v9.18.28/lib/ns/client.c)
- [BIND 9.18.28 `lib/isc/log.c` and `lib/isc/time.c`](https://gitlab.isc.org/isc-projects/bind9/-/tree/v9.18.28/lib/isc)

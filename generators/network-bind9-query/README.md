# BIND 9 query log

Synthetic ISC BIND 9.18 `queries` category records from one recursive resolver serving 24 internal clients, for DNS monitoring and DNS-exfiltration detection testing. Each event carries the native `named` query-log line in `event.original` plus ECS fields parsed from it.

## Event Types

Shares are measured from a 78-hour default-configuration capture (23,525 events, about 300 per hour on average; each client follows its own daily activity window). The traffic mix is a synthetic assumption, not measured resolver traffic.

| Query | Share | Category | Description |
| --- | ---: | --- | --- |
| `A` | 41.8% | network | Host lookups under `example.com`, `example.net`, `example.org`, plus the mail host after an `MX` |
| `AAAA` | 20.9% | network | IPv6 lookups, usually right after the matching `A` |
| `TXT` on analytics zones | 11.8% | network | Runs of high-entropy labels under `metrics.example.net` / `insights.example.org` |
| `PTR` | 11.4% | network | Reverse lookups in `10.in-addr.arpa` |
| `MX` | 5.8% | network | Mail-exchanger lookups |
| `TXT` on tunnel zones | 3.3% | network | Short high-entropy runs under the tunnel zones, plus the anomaly episodes |
| `TXT` DKIM / DMARC | 3.8% | network | `<selector>._domainkey.<domain>` and `_dmarc.<domain>` |
| `A` / `AAAA` / `NS` on tunnel-zone apex | 1.3% | network | Plain lookups of the tunnel zones themselves |

About 3% of queries arrive over TCP (`T` flag). Flags follow the BIND order: recursion (`+`/`-`), `E(0)`, `T`, `D`, then cookie `V` or `K`. About 90% of queries carry EDNS (`E(0)`). DO (`D`) and the cookie flags come from the EDNS OPT record, so they appear only together with `E(0)`; a query without EDNS shows only `+`/`-` and `T`.

## Anomaly Chain

A DNS-exfiltration burst: one client sends a run of TXT queries to one tunnel zone, each with a distinct high-entropy first label.

1. `TXT` query for `<hex>.<zone>` from client `C`, where `<zone>` is one of `tunnel_zones`.
2. Seven or more further `TXT` queries from `C` for new `<hex>.<zone>` names under the same `<zone>`.

- **Linking fields:** `source.ip` and `dns.question.registered_domain`. Every label is new, so `dns.question.name` never repeats.
- **Episode shape:** 10 to 16 queries with random log-normal spacing (median about 12 s), spanning 122-181 s in the measured capture.
- **Recurrence:** an episode becomes due every `anomaly_interval_hours` of source time (default 24, minimum 2). Its start comes after an exponential delay (mean 15 minutes). The next due time counts from the actual start, and missed intervals are never caught up. The measured default capture has 3 episodes with gaps of 25.15 h and 24.05 h, and a 6-hour run has 12 episodes with gaps of 6.04-6.63 h.
- **Variation:** the client and the tunnel zone both change from one episode to the next, and every label is freshly random.
- **Background overlap:** each part of the chain also occurs on its own in both modes. All 24 clients send high-entropy TXT queries to the tunnel zones in short runs (geometric length, 1-2 queries typical), and they also look up the zone apex. Analytics zones get high-entropy TXT runs of 8 or more queries per hour (about 870-1,360 per 78-hour capture). A guard on the final chain step keeps background traffic below 8 tunnel-zone TXT queries per client and zone within an hour (measured maximum: 6). Only an episode completes the chain.
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
| `client_count` | `24` | Number of clients (at least 4) |
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

For a batch capture, set `start` and `end` on the `cron` input and run with `--live-mode false`.

## Sample Output

An episode event copied from the default `anomaly_mode: true` capture:

```json
{"@timestamp": "2026-09-01T21:15:10.279000+00:00", "bind9": {"query": {"client_object": "@0x7fed853a1c48", "flags": "+E(0)K"}}, "destination": {"ip": "10.20.30.53", "port": 53}, "dns": {"question": {"class": "IN", "name": "3e1ce784fc1248e6fad96dfda3b.telemetry.example.test", "registered_domain": "telemetry.example.test", "type": "TXT"}, "type": "query"}, "ecs": {"version": "8.17.0"}, "event": {"action": "dns-query", "category": ["network"], "dataset": "bind9.query", "kind": "event", "original": "2026-09-01T21:15:10.279Z queries: info: client @0x7fed853a1c48 10.20.40.26#8731 (3e1ce784fc1248e6fad96dfda3b.telemetry.example.test): query: 3e1ce784fc1248e6fad96dfda3b.telemetry.example.test IN TXT +E(0)K (10.20.30.53)", "type": ["protocol", "info"]}, "host": {"name": "ns1.example.test"}, "network": {"protocol": "dns", "transport": "udp"}, "observer": {"hostname": "ns1.example.test", "product": "BIND", "type": "dns", "vendor": "ISC"}, "related": {"ip": ["10.20.40.26", "10.20.30.53"]}, "source": {"ip": "10.20.40.26", "port": 8731}}
```

## Limitations

- The native line follows BIND 9.18 source code (`ns_client_logv`, `log_query`, the file-channel writer and the ISO 8601 time formatter). It assumes a file channel with `print-time iso8601-utc; print-category yes; print-severity yes;`. Other channel settings change the prefix, and syslog adds its own header.
- The ARM publishes only the message part of the line (from `client @0x...` on). The prefix is taken from the source code, not from a published capture.
- Only the default view is modelled, so the `: view <name>` suffix never appears. Signed queries (`S`), `CD` (`C`), EDNS Client Subnet (`[ECS ...]`) and IPv6 clients are not generated.
- `client @0x...` is a random pointer-like value per query. BIND reuses client objects, and that reuse is not modelled.
- `dns.question.registered_domain` holds the delegated service zone (for example `sync.example.test`), not the public-suffix registered domain.
- Query logs contain no responses. Episodes are identified by the request pattern alone.
- Traffic mix, client activity windows, rates and episode shape are synthetic.

## References

- [BIND 9.18 logging categories: `queries` field description and example lines](https://bind9.readthedocs.io/en/v9.18.28/reference.html#logging-categories)
- [BIND 9.18 `print-time` options](https://bind9.readthedocs.io/en/v9.18.28/reference.html#namedconf-statement-print-time)
- [BIND 9.18.28 `lib/ns/query.c` (`log_query`)](https://gitlab.isc.org/isc-projects/bind9/-/blob/v9.18.28/lib/ns/query.c)
- [BIND 9.18.28 `lib/ns/client.c` (`ns_client_logv`)](https://gitlab.isc.org/isc-projects/bind9/-/blob/v9.18.28/lib/ns/client.c)
- [BIND 9.18.28 `lib/isc/log.c` and `lib/isc/time.c`](https://gitlab.isc.org/isc-projects/bind9/-/tree/v9.18.28/lib/isc)

# PowerDNS Authoritative query log

Generates the per-query lines of a PowerDNS Authoritative Server 5.0.1 with query logging enabled (`log-dns-queries=yes`, `loglevel` 5 or higher, `log-timestamp=yes`, `loglevel-show=no`, classic unstructured stderr output, packet cache on). One server answers for a few zones; four recursive resolvers and a group of directly connected hosts (admin workstations, monitoring, mail relays, scripts) query it over UDP. Each record keeps the complete native line in `event.original` and parses its fields into ECS.

## Event Types

Approximate shares of all queries at the default configuration. The traffic mix is a synthetic assumption, not measured production traffic.

| Query | Share | Category | Description |
| --- | ---: | --- | --- |
| `A` | 62.6% | network | Host lookups, including stale or mistyped names and short inventory sweeps by direct clients |
| `AAAA` | 18.8% | network | IPv6 host lookups |
| `MX` | 6.7% | network | Mail-exchanger lookups of a zone apex |
| `TXT` | 5.8% | network | Zone-apex TXT (SPF) lookups |
| `NS` | 4.0% | network | Name-server set of a zone apex |
| `SOA` | 2.2% | network | Serial and zone checks by direct clients; resolvers never ask for SOA in this model |

`packetcache HIT` is 5-8% of lines: a question repeated with the same name, type, DO bit and EDNS size within 20 seconds (the default `cache-ttl`) is a HIT, anything else a MISS. EDNS follows the server's parser: a query without EDNS shows `do = 0, bufsize = 512`; with EDNS the logged `bufsize` is the advertised size clamped to 512-1232 (`udp-truncation-threshold`), followed by the advertised size in parentheses when it differs, for example `bufsize = 1232 (4096)`. Resolvers send EDNS with DO set; direct clients use EDNS 1232, EDNS 4096 or no EDNS, and dig-like clients occasionally set DO.

## Volume and Daily Curve

About 21,000 queries a day, following a UTC daily curve:

| UTC hours | Queries per hour |
| --- | ---: |
| 19:00-07:00 | about 340 |
| 07:00-09:00 and 17:00-19:00 | 1,050-1,250 |
| 09:00-17:00 | about 1,560 |

Recursive resolvers send about 69% of the queries, each an independent question for a name, apex MX/TXT/NS or IPv6 address. Direct clients send the rest in short sessions: single lookups repeated a few seconds apart, zone checks (`SOA`, `NS`, `MX`, `TXT` in random order, sometimes followed by a sweep of several host names), inventory sweeps and mail-routing checks. Each client has its own weight and daily activity window, so the mix of clients changes through the day. Daily volume varies by about 3%.

## Anomaly Chain

Zone reconnaissance followed by name enumeration from one directly connected host:

1. `SOA` query for a zone apex from client `C`.
2. `NS` query for the same apex from `C`, often with `MX` and `TXT` apex queries in between.
3. `A` queries from `C` for distinct names in the same zone, drawn from a dictionary of existing hosts and names the zone does not publish, until the tenth distinct name.

- **Linking fields:** `source.ip` and `dns.question.registered_domain`; the enumerated `dns.question.name` values are all distinct within an episode.
- **Episode shape:** queries a few seconds apart; the tenth distinct `A` arrives 40-230 s after the `SOA`, later at night when the server is quiet.
- **Recurrence:** an episode becomes due every `anomaly_interval_hours` of source time (default 24, minimum 2). The first start falls within the first min(interval, 24 h), at a time of day drawn from the direct clients' daily curve. Each later start is drawn from a window of width min(interval / 4, 6 h) centred on the due time, weighted towards busy hours; the next due time counts from the actual start, and missed intervals are never caught up. At intervals of 8 hours or less the windows necessarily cover the whole clock. At the default interval consecutive episodes start about 22-26 h apart, never outside 21-27 h; at a 6-hour interval, about 5.5-6.5 h apart.
- **Variation:** the client changes from one episode to the next and is picked with the same per-client weighting and daily activity as ordinary traffic; the zone and the enumerated names are drawn fresh each time.
- **Background overlap:** every client of an episode also sends `SOA`, `NS`, `MX`, `TXT` and `A` queries for the same zones in ordinary traffic of both modes, and zone checks followed by sweeps of several distinct names occur every day. Background sequences reach `SOA`, `NS` and nine distinct names within five minutes but never the tenth: such a query repeats a name the client already asked for. The same sequence spread over more than five minutes does occur in background.
- **Volume:** episode queries are part of the server's total query volume, which follows the same daily curve in both modes; each episode adds its own `SOA`/`NS` check followed by a name sweep, and the number of such sequences in ordinary traffic also varies from day to day.
- **Detection idea:** alert when one client queries a zone's `SOA` and `NS` and then ten or more distinct names in that zone within five minutes. The query log records questions only, with no response code or answer, so a match shows the pattern, not which names exist.

`anomaly_mode` defaults to `true`. Set it to `false` to get background traffic only, with no complete chain.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Description |
| --- | --- | --- |
| `anomaly_mode` | `true` | Add recurring reconnaissance episodes; `false` gives background only |
| `anomaly_interval_hours` | `24` | Source-time hours between episode due times; 2 to 8760 |
| `host_name` | `ns01.corp.example` | Server name in `host.name` (configured context, not part of the native line) |
| `zones` | `corp.example`, `contoso.example` | Zones served; the first one gets most traffic. Use registrable names, since `dns.question.registered_domain` carries the zone |
| `resolver_ips` | `10.20.30.11`-`10.20.30.14` | Recursive resolvers querying the server |
| `client_prefix` | `10.20.40.` | Prefix of the directly connected clients |
| `client_first` | `21` | Last octet of the first direct client |
| `client_count` | `16` | Number of direct clients (at least 4; resolver and client addresses must not overlap) |

### Output Parameters

The shipped configuration writes to `output/events.json` and needs no parameters or secrets. To send events to a backend instead, replace the `file` output in a local copy and use placeholders for connection values, for example:

```yaml
output:
  - opensearch:
      hosts:
        - ${params.opensearch_host}
      username: ${params.opensearch_user}
      password: ${secrets.opensearch_password}
      index: powerdns-authoritative
```

## Usage

```bash
# Live generation
eventum generate --path generators/network-powerdns-authoritative/generator.yml --id powerdns-auth --live-mode true

# Batch generation
eventum generate --path generators/network-powerdns-authoritative/generator.yml --id powerdns-auth-batch --live-mode false --keep-order true
```

The daily curve comes from the files in `patterns/`, which start on `2026-01-01T00:00:00Z` and never end. For a batch run, set `oscillator.start` and `oscillator.end` in every pattern file to the window you want, for example `start: "2026-10-05T00:00:00Z"` and `end: "2026-10-08T00:00:00Z"`; keep the start at midnight UTC so the daily curve stays aligned. With the default interval, a window of 72 hours contains three episodes.

Host names and the dictionary of unpublished names are listed in `samples/labels.csv` (`published`, and a relative `weight` for published names).

Performance: about 2,600 events per second on one core (14 days, 295,000 events, in 112 s).

## Sample Output

An enumeration query from an episode at the default configuration:

```json
{"@timestamp": "2026-09-01T08:56:21+00:00", "dns": {"question": {"name": "vpn2.corp.example", "registered_domain": "corp.example", "type": "A"}, "type": "query"}, "ecs": {"version": "8.17.0"}, "event": {"action": "dns-query", "category": ["network"], "kind": "event", "original": "Sep 01 08:56:21 Remote 10.20.40.21 wants \u0027vpn2.corp.example|A\u0027, do = 0, bufsize = 1232: packetcache MISS", "type": ["info"]}, "host": {"name": "ns01.corp.example"}, "powerdns": {"dnssec_ok": false, "edns_buffer_size": 1232, "packet_cache": "MISS", "server_type": "authoritative"}, "related": {"ip": ["10.20.40.21"]}, "source": {"ip": "10.20.40.21"}}
```

## Limitations

- The line format follows the 5.0.1 source (`auth-main.cc`, `dnspacket.cc`, `logger.cc`) and one complete captured line in a vendor issue, not a recording of a live daemon.
- The timestamp prefix is the daemon's local time (`%b %d %H:%M:%S`, day zero-padded), here in UTC. There is no syslog or journald wrapper.
- Only UDP queries are modelled, from the resolvers and the directly connected hosts. TCP (`TCP Remote` lines), PROXY protocol and EDNS Client Subnet decorations of the remote address, overload drops, structured logging (5.1+) and PowerDNS Recursor are out of scope.
- The packet cache is approximated by a key of name, type, DO bit and EDNS size with a fixed 20-second lifetime; the real cache hashes the whole query packet and also honours shorter answer TTLs.
- `edns_requested_size` under `powerdns` is present only when the advertised EDNS size differs from the logged buffer size, as in the native line.
- Resolvers never send `SOA` queries in this model, and the traffic mix, rates and client behaviour are synthetic assumptions.
- Each resolver question is independent of the resolver's earlier ones, so a resolver asks for the same name again within five minutes more often than a caching resolver with ordinary TTLs would.
- Timestamps have one-second resolution. Queries of one client session are usually seconds apart, and at night, when the server is quiet, often 10 s or more; a real dig or script session sends its queries in quicker succession.
- In background, a client never asks for ten distinct names of one zone within five minutes of that zone's `SOA` and `NS`; the longest such sweeps repeat an earlier name instead.

## References

- [PowerDNS Authoritative settings: `log-dns-queries`, `log-timestamp`, `loglevel-show`, `udp-truncation-threshold`](https://docs.powerdns.com/authoritative/settings.html)
- [PowerDNS Authoritative performance: packet cache](https://docs.powerdns.com/authoritative/performance.html#packet-cache)
- [PowerDNS 5.0.1 source: query logging in `pdns/auth-main.cc`](https://github.com/PowerDNS/pdns/blob/auth-5.0.1/pdns/auth-main.cc)
- [PowerDNS 5.0.1 source: EDNS buffer size in `pdns/dnspacket.cc`](https://github.com/PowerDNS/pdns/blob/auth-5.0.1/pdns/dnspacket.cc)
- [PowerDNS 5.0.1 source: timestamp prefix in `pdns/logger.cc`](https://github.com/PowerDNS/pdns/blob/auth-5.0.1/pdns/logger.cc)
- [PowerDNS issue 16647: 5.0.1 configuration and a captured query line](https://github.com/PowerDNS/pdns/issues/16647)

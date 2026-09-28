# PowerDNS Authoritative query log

Generates the per-query lines of a PowerDNS Authoritative Server 5.0.1 with query logging enabled (`log-dns-queries=yes`, `loglevel` 5 or higher, `log-timestamp=yes`, `loglevel-show=no`, classic unstructured stderr output, packet cache on). One server answers for a few zones; four recursive resolvers and a group of directly connected hosts (admin workstations, monitoring, mail relays, scripts) query it over UDP. Each record keeps the complete native line in `event.original` and parses its fields into ECS.

## Event Types

Shares are measured from a 54-hour default-configuration capture (35,146 events, about 650 per hour; every client follows its own daily activity window). The traffic mix is a synthetic assumption, not measured production traffic.

| Query | Share | Category | Description |
| --- | ---: | --- | --- |
| `A` | 61.9% | network | Host lookups, including stale or mistyped names and short inventory sweeps by direct clients |
| `AAAA` | 20.4% | network | IPv6 host lookups |
| `MX` | 6.5% | network | Mail-exchanger lookups of a zone apex |
| `TXT` | 5.7% | network | Zone-apex TXT (SPF) lookups |
| `NS` | 4.0% | network | Name-server set of a zone apex |
| `SOA` | 1.5% | network | Serial and zone checks by direct clients; resolvers never ask for SOA in this model |

`packetcache HIT` is 3.8% of lines: a question repeated with the same name, type, DO bit and EDNS size within 20 seconds (the default `cache-ttl`) is a HIT, anything else a MISS. EDNS follows the server's parser: a query without EDNS shows `do = 0, bufsize = 512`; with EDNS the logged `bufsize` is the advertised size clamped to 512-1232 (`udp-truncation-threshold`), followed by the advertised size in parentheses when it differs, for example `bufsize = 1232 (4096)`. Resolvers send EDNS with DO set; direct clients use EDNS 1232, EDNS 4096 or no EDNS, and dig-like clients occasionally set DO.

## Anomaly Chain

Zone reconnaissance followed by name enumeration from one directly connected host:

1. `SOA` query for a zone apex from client `C`.
2. `NS` query for the same apex from `C`, often with `MX` and `TXT` apex queries in between.
3. 12 to 18 `A` queries from `C` for distinct names in the same zone, drawn from a dictionary of existing hosts and names the zone does not publish.

- **Linking fields:** `source.ip` and `dns.question.registered_domain`; the enumerated `dns.question.name` values are all distinct within an episode.
- **Episode shape:** queries a few seconds apart (log-normal spacing); the tenth distinct `A` arrives 29-69 s after the `SOA` in the final captures.
- **Recurrence:** an episode becomes due every `anomaly_interval_hours` of source time (default 24, minimum 2). The first start falls within the first min(interval, 24 h), at a time of day drawn from the direct clients' activity curve. Each later start is drawn from a window of width min(interval / 4, 6 h) centred on the due time, weighted towards busy hours; the next due time counts from the actual start, and missed intervals are never caught up. At intervals of 8 hours or less the windows necessarily cover the whole clock. The default 54-hour capture has 2 episodes 22.38 h apart; a 30-hour capture at a 6-hour interval has 5 episodes 5.36-6.65 h apart.
- **Variation:** the client changes from one episode to the next and is picked with the same per-client weighting and daily activity as ordinary traffic; the zone and the enumerated names are drawn fresh each time.
- **Background overlap:** every client of an episode also sends `SOA`, `NS`, `MX`, `TXT` and `A` queries for the same zones in ordinary traffic of both modes. Direct clients run zone checks (`SOA`, `NS`, `MX`, `TXT` in random order), inventory sweeps of several distinct names a few seconds apart, and lookups of names that do not exist. Partial chains up to `SOA`, `NS` and nine distinct names within five minutes occur in background (2-7 per 54-hour capture in five `false` captures). A guard on the final step keeps background below the full chain: a background `A` query that would be the tenth distinct name within five minutes of a `SOA`/`NS` pair keeps its time and repeats a name the client already asked for (or is dropped when no such name exists). The same sequence spread over more than five minutes still occurs in background.
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

# Batch: add start/end to the cron input first, e.g. start: '2026-10-05T00:00:00Z', end: '2026-10-07T08:00:00Z'
eventum generate --path generators/network-powerdns-authoritative/generator.yml --id powerdns-auth-batch --live-mode false --keep-order true
```

With the default interval, a batch window of 54 hours or more contains at least two episodes.

## Sample Output

An enumeration query from the first episode of the final default-configuration capture:

```json
{"@timestamp": "2026-09-21T11:37:34+00:00", "dns": {"question": {"name": "smtp.corp.example", "registered_domain": "corp.example", "type": "A"}, "type": "query"}, "ecs": {"version": "8.17.0"}, "event": {"action": "dns-query", "category": ["network"], "kind": "event", "original": "Sep 21 11:37:34 Remote 10.20.40.26 wants \u0027smtp.corp.example|A\u0027, do = 0, bufsize = 1232: packetcache MISS", "type": ["info"]}, "host": {"name": "ns01.corp.example"}, "powerdns": {"dnssec_ok": false, "edns_buffer_size": 1232, "packet_cache": "MISS", "server_type": "authoritative"}, "related": {"ip": ["10.20.40.26"]}, "source": {"ip": "10.20.40.26"}}
```

## Limitations

- The line format follows the 5.0.1 source (`auth-main.cc`, `dnspacket.cc`, `logger.cc`) and one complete captured line in a vendor issue; output of a live daemon for every generated case was not compared.
- The timestamp prefix is the daemon's local time (`%b %d %H:%M:%S`, day zero-padded); the generator assumes the process runs in UTC. There is no syslog or journald wrapper.
- Only UDP questions from direct clients are modelled. TCP (`TCP Remote` lines), PROXY protocol and EDNS Client Subnet decorations of the remote address, overload drops, structured logging (5.1+) and PowerDNS Recursor are out of scope.
- The packet cache is approximated by a key of name, type, DO bit and EDNS size with a fixed 20-second lifetime; the real cache hashes the whole query packet and also honours shorter answer TTLs.
- `edns_requested_size` under `powerdns` is present only when the advertised EDNS size differs from the logged buffer size, as in the native line.
- Resolvers never send `SOA` queries in this model, and the traffic mix, rates and client behaviour are synthetic assumptions.
- The guard on the final chain step changes the name (or drops the row) in rare background sequences; this avoids an accidental full chain in background but slightly thins the longest background sweeps right after a `SOA`/`NS` pair.

## References

- [PowerDNS Authoritative settings: `log-dns-queries`, `log-timestamp`, `loglevel-show`, `udp-truncation-threshold`](https://docs.powerdns.com/authoritative/settings.html)
- [PowerDNS Authoritative performance: packet cache](https://docs.powerdns.com/authoritative/performance.html#packet-cache)
- [PowerDNS 5.0.1 source: query logging in `pdns/auth-main.cc`](https://github.com/PowerDNS/pdns/blob/auth-5.0.1/pdns/auth-main.cc)
- [PowerDNS 5.0.1 source: EDNS buffer size in `pdns/dnspacket.cc`](https://github.com/PowerDNS/pdns/blob/auth-5.0.1/pdns/dnspacket.cc)
- [PowerDNS 5.0.1 source: timestamp prefix in `pdns/logger.cc`](https://github.com/PowerDNS/pdns/blob/auth-5.0.1/pdns/logger.cc)
- [PowerDNS issue 16647: 5.0.1 configuration and a captured query line](https://github.com/PowerDNS/pdns/issues/16647)

# PowerDNS Authoritative 5.0.1 classic query log

Generates the timestamped classic text query messages emitted by a directly accessed PowerDNS Authoritative Server 5.0.1 with `log-dns-queries=yes`, `loglevel=7`, `log-timestamp=yes`, `loglevel-show=no`, and unstructured logging. Each complete source message is preserved in `event.original`; ECS fields are parsed or configured alongside it. This is the daemon's stderr-style line, without an added syslog host/process wrapper.

## Event Types

| Query type | Routine selection weight | Meaning |
| --- | ---: | --- |
| `A` | 68% | Address lookup, including occasional new health labels |
| `AAAA` | 14% | IPv6 address lookup |
| `SOA` | 7% | Zone metadata lookup |
| `NS` | 4% | Name-server lookup |
| `MX` | 4% | Mail exchanger lookup |
| `TXT` | 3% | Text-record lookup |

These are synthetic selection weights before a few scheduled ordinary queries that ensure the target client also uses `SOA`, `NS`, and `TXT` in both modes. The one-query-per-second volume is a synthetic test load, not a measured production rate. The background covers five clients, several repeated host names, zone-apex queries, and occasional unique health labels. `packetcache HIT` is emitted only while the same question remains in a bounded 20-second synthetic packet cache. A first or expired question is `MISS`; the cache is keyed by question name, type, DO bit, and buffer size. The selected profile fixes DO to 0 and buffer size to 512, as in the version-matched vendor example.

## Anomaly Chain

Every `anomaly_interval_hours` (default: 2), the same client queries the zone's `SOA`, `NS`, and `TXT` records in three seconds, then twelve distinct health-style `A` names in twelve seconds. The client and zone also occur in ordinary traffic; all six query types and unique health-style names exist in background. The signal is the concentration and ordering of distinct questions from one client. Subsequent episodes use fresh names and are separated by hours. The packet-cache result follows the same state model as background rather than being forced by the chain.

`anomaly_mode` defaults to `true`. With `false`, the stream contains only ordinary queries for the full run. A detector could group by `source.ip` and DNS zone, then require the three apex types followed by a burst of distinct `A` names. A `MISS` is a packet-cache lookup result, not a DNS response code or proof that a name exists.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Purpose |
| --- | --- | --- |
| `anomaly_mode` | `true` | Enable periodic correlated query episodes |
| `anomaly_interval_hours` | `2` | Hours between episode starts; use a positive value |
| `host_name` | `ns01.corp.example` | Configured server identity in the ECS wrapper, not in the selected native line |
| `zone_name` | `corp.example` | Synthetic authoritative zone |
| `suspicious_client_ip` | `192.0.2.91` | Client participating in periodic bursts and ordinary background |

The four other client IPs are synthetic template constants. Keep `suspicious_client_ip` distinct from them. The chosen deployment has no dnsdist proxy; if a proxy fronts the authoritative server, `Remote` can identify that proxy instead of the original client.

### Output Parameters

The shipped configuration writes `output/events.json` and needs no endpoint or credentials. To send records to a SIEM, replace the local `file` output in a copy and supply the output plugin's connection parameters and secrets there. No `${params.*}` or `${secrets.*}` placeholders are required by the shipped file output.

## Usage

From the `content-packs` repository root:

```bash
uv run --project ../eventum eventum generate --path generators/network-powerdns-authoritative/generator.yml --id powerdns-authoritative --live-mode true
```

For a finite batch, copy `generator.yml` within its generator directory, add `start` and `end` to its `cron` input, then run the copy with `--live-mode false --keep-order true`. A window longer than four hours contains two default anomaly episodes. The `log-dns-queries` setting is disabled by default in PowerDNS and the vendor recommends enabling it only for debugging because it logs every query.

## Sample Output

This complete ECS JSON record is copied from the first episode in a four-hour default-on Eventum run. It is synthetic, not a new capture from a PowerDNS daemon.

```json
{
    "@timestamp": "2026-09-25T02:00:04+00:00",
    "dns": {
        "question": {
            "name": "health-07202-88c07cd8.corp.example",
            "type": "A"
        },
        "type": "query"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "event": {
        "action": "dns-query",
        "category": [
            "network"
        ],
        "kind": "event",
        "original": "Sep 25 02:00:04 Remote 192.0.2.91 wants 'health-07202-88c07cd8.corp.example|A', do = 0, bufsize = 512: packetcache MISS",
        "type": [
            "info"
        ]
    },
    "host": {
        "name": "ns01.corp.example"
    },
    "powerdns": {
        "dnssec_ok": false,
        "edns_buffer_size": 512,
        "packet_cache": "MISS",
        "server_type": "authoritative"
    },
    "related": {
        "ip": [
            "192.0.2.91"
        ]
    },
    "source": {
        "ip": "192.0.2.91"
    }
}
```

## Source and Fidelity

A [PowerDNS vendor issue](https://github.com/PowerDNS/pdns/issues/16647) contains a complete query line and the exact Authoritative Server 5.0.1 configuration and version. Its `Dec 15 ... Remote ... wants 'example.com|SOA', do = 0, bufsize = 512: packetcache MISS` line defines this selected classic stderr-style profile. The [logging settings](https://docs.powerdns.com/authoritative/settings.html#log-dns-queries) define how to enable it and distinguish the classic format from structured logging. The [packet-cache documentation](https://docs.powerdns.com/authoritative/performance.html#packet-cache) explains identical-question caching and its default 20-second TTL. A separate [vendor issue](https://github.com/PowerDNS/pdns/issues/5302) demonstrates that a dnsdist deployment can expose the proxy address as `Remote`.

For the selected example, all seven source components are preserved and parsed consistently: log timestamp, remote address, question name, type, DO bit, advertised buffer size, and packet-cache result (7/7). The host name is configured ECS context, not part of that source line. No response code, answer, transport proof, or successful resolution is inferred from a query log. The cache model is deliberately bounded and uses a simple 20-second TTL; actual cache keys and eviction may depend on more packet details and runtime state. Exact live 5.0.1 output for every generated name and cache transition, SIEM collection, and ECS parser behavior remain untested. This generator is not PowerDNS Recursor, TCP's `TCP Remote` profile, or JSON structured logging.

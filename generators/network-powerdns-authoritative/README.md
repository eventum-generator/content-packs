# PowerDNS Authoritative DNS query logs

Synthetic classic PowerDNS Authoritative Server query-log lines, preserving the vendor's `Remote ... wants 'name|type' ... packetcache` message in `event.original`.

## Event Types

| Query | Baseline frequency | Meaning |
| --- | ---: | --- |
| `A` | 75% | Routine address lookup |
| `AAAA` | 12% | Routine IPv6 lookup |
| `SOA` | 8% | Zone metadata lookup |
| `MX` | 5% | Mail exchanger lookup |
| `SOA`, `NS`, `TXT`, then unique `A` labels | Chain only | Zone enumeration-like sequence |

The baseline weights and cache ratios are synthetic assumptions. One source emits each query-log line.

## Anomaly Chain

The same remote IP (`192.0.2.91`) queries a zone's `SOA`, `NS`, and `TXT` records, then requests twelve distinct long hexadecimal hostnames under `corp.example`; all show `packetcache MISS`. A rule can correlate the query-type progression and high distinct-label count per remote and zone. These are query records only: `MISS` is a packet-cache lookup result, not a DNS response code, so the sequence alone does not prove names existed or data was returned.

`anomaly_mode` defaults to `true`. Set it to `false` in `event.template.params` for ordinary DNS queries only.

## Parameters

### Event Parameters

| Name | Default | Purpose |
| --- | --- | --- |
| `anomaly_mode` | `true` | Include reconnaissance and unique-label queries |
| `host_name` | `ns01.corp.example` | Authoritative server name |
| `zone_name` | `corp.example` | Synthetic authoritative zone |
| `suspicious_client_ip` | `192.0.2.91` | Remote IP in the chain |

### Output Parameters

The shipped configuration writes `output/events.json` and needs no connection parameters or secrets. Replace the `file` output in a local copy to deliver to a SIEM, using `${params.siem_host}` and `${secrets.siem_token}` placeholders for that output plugin where applicable.

## Usage

```bash
eventum generate --path generators/network-powerdns-authoritative/generator.yml --id powerdns-authoritative --live-mode false
eventum generate --path generators/network-powerdns-authoritative/generator.yml --id powerdns-authoritative --live-mode true
```

## Sample Output

This event was copied from a real generator run.

```json
{
  "@timestamp": "2026-09-25T12:20:45+00:00",
  "dns": {
    "question": {
      "name": "0195728f0fd622fa4f0d49.corp.example",
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
    "original": "Sep 25 12:20:45 ns01.corp.example pdns_server[2367]: Remote 192.0.2.91 wants '0195728f0fd622fa4f0d49.corp.example|A', do = 0, bufsize = 512: packetcache MISS",
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
  "process": {
    "name": "pdns_server",
    "pid": 2367
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

## Coverage and Limits

The selected classic UDP query message exposes seven data elements, all represented here: timestamp, remote IP, question name/type, DNSSEC OK bit, EDNS buffer size, and packet-cache status (7/7). The example syslog host/process wrapper is synthetic. `log-dns-queries` is disabled by default; PowerDNS documentation requires `loglevel` at least 5 to see these notices and warns of high volume. This pack models the classic text format, not `logging-structured` (added in 5.1), TCP's `TCP Remote` prefix, or PowerDNS Recursor. The syslog path and wrapper depend on packaging and systemd; an Authoritative 4.2.1 report observed missing query lines under one systemd setup while its reporter said 4.3.x worked. A DNSdist proxy can make `Remote` identify the proxy rather than the original client.

## References

- [PowerDNS Authoritative Server logging settings](https://docs.powerdns.com/authoritative/settings.html#log-dns-queries)
- [PowerDNS Authoritative vendor issue with a real query line](https://github.com/PowerDNS/pdns/issues/8913)
- [PowerDNS vendor issue showing packet-cache HIT behind dnsdist](https://github.com/PowerDNS/pdns/issues/5302)
- [PowerDNS Authoritative TCP query logger source](https://github.com/PowerDNS/pdns/blob/master/pdns/tcpreceiver.cc)

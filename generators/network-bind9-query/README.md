# BIND 9 native query log

Synthetic `named` query log records, distinct from Packetbeat-style DNS traffic. The line layout follows the ISC BIND query-logging example and the BIND 9.18.4 query-log field description.

## Event Types

| DNS question type | Baseline weight | Use |
| --- | ---: | --- |
| `A` | 70% | Ordinary host lookups and sequence markers |
| `AAAA` | 20% | Ordinary IPv6 lookups |
| `MX` | 10% | Ordinary mail-domain lookups |
| `TXT` | Chain only | Long encoded-label queries |

Weights are synthetic, not measured DNS traffic. The template plugin uses `fsm` for the ordered query sequence.

## Anomaly Chain

One client sends an `A` query for `start.<id>.telemetry.example.test`, four `TXT` queries with separate 48-character hexadecimal labels under the same `<id>`, then an `A` query for `done.<id>.telemetry.example.test`. Correlate the client IP, shared subdomain ID, suffix, and short time window. A rule can flag a burst of high-entropy TXT labels from one client. Query logs contain requests, not response codes or answer data, so this pattern does not prove successful exfiltration. Sort by `@timestamp` before sequence matching because output line order is not guaranteed.

`event.template.params.anomaly_mode` defaults to `true`. Set it to `false` for ordinary A, AAAA, and MX queries only.

## Parameters

### Event Parameters

| Name | Default | Purpose |
| --- | --- | --- |
| `anomaly_mode` | `true` | Include the TXT-query sequence |
| `host_name` | `ns1.example.test` | BIND server name |
| `server_ip` | `10.20.30.53` | Destination address in query log |
| `tunnel_domain` | `telemetry.example.test` | Query suffix used by the sequence |
| `suspect_ip` | `192.0.2.66` | Client IP used by the sequence |

### Output Parameters

The shipped configuration writes `output/events.json` with no connection parameters or secrets. To send events to a SIEM, replace the file output in a local copy and use `${params.siem_host}` and `${secrets.siem_token}` as required by the selected output plugin.

## Usage

```bash
eventum generate --path generators/network-bind9-query/generator.yml --id bind --live-mode false
eventum generate --path generators/network-bind9-query/generator.yml --id bind --live-mode true
```

## Sample Output

Copied from an `anomaly_mode: true` run:

```json
{
  "@timestamp": "2026-09-25T13:27:38+00:00",
  "bind9": {
    "query": {
      "client_object": "@0xf4dd11c1",
      "flags": "-"
    }
  },
  "destination": {
    "ip": "10.20.30.53",
    "port": 53
  },
  "dns": {
    "question": {
      "class": "IN",
      "name": "b74b9e2822e893f248295b2a582232d35dcdec8980c07488.036a4d7d.telemetry.example.test",
      "type": "TXT"
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
    "original": "2026-09-25T13:27:38.000 client @0xf4dd11c1 192.0.2.66#17882 (b74b9e2822e893f248295b2a582232d35dcdec8980c07488.036a4d7d.telemetry.example.test): query: b74b9e2822e893f248295b2a582232d35dcdec8980c07488.036a4d7d.telemetry.example.test IN TXT - (10.20.30.53)",
    "type": [
      "protocol"
    ]
  },
  "host": {
    "name": "ns1.example.test"
  },
  "network": {
    "protocol": "dns",
    "transport": "udp"
  },
  "related": {
    "ip": [
      "192.0.2.66",
      "10.20.30.53"
    ]
  },
  "source": {
    "ip": "192.0.2.66",
    "port": 17882
  }
}
```

## Coverage and Limits

The nine native query-log elements are represented: timestamp, client object ID, client IP, port, question name, class, type, flags, and destination address. This pack models a log channel with `print-time yes` and the non-recursive `-` flag. Enable query logging in BIND (`rndc querylog on` or a `queries` category logging channel); it is not a DNS packet capture or response stream. ISC's full-line example is from a 2021 BIND 9 logging presentation, while the field contract is documented for BIND 9.18.4. A syslog collector may add its own outer header, and compatibility with a particular KUMA BIND normalizer is unverified.

## References

- [ISC BIND 9 logging webinar with full query-log line](https://www.isc.org/docs/2021BIND9-Logging-webinar.pdf)
- [BIND 9.18.4 query-log category and field format](https://bind9.readthedocs.io/en/v9.18.4/reference.html)
- [KUMA 4.2 source catalog](https://support.kaspersky.ru/kuma/4.2/255782)

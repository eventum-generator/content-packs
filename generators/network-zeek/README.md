# Zeek Network Telemetry Generator

Generates linked Zeek `conn.log`, `dns.log`, `http.log`, and `ssl.log` records as ECS-compatible JSON. Every connection is immediately followed by its protocol record with the same `uid`, 4-tuple, and timestamp. `event.original` contains the corresponding native Zeek JSON record.

## Event Types Covered

| Action | Share of all events in a 1,200-flow validation run | Category |
|---|---:|---|
| Connection (`conn.log`) | 50.0% | network |
| DNS transaction (`dns.log`) | 27.0% | network |
| TLS handshake (`ssl.log`) | 18.3% | network |
| HTTP transaction (`http.log`) | 4.7% | network, web |

`mode: chain` emits `[connection, protocol]` for each input timestamp. The protocol mix is weighted 55% DNS, 35% TLS, and 10% HTTP in background traffic. These are generator settings, not measured Zeek production frequencies.

## Anomaly Chain

Set `event.template.params.anomaly_mode` to `false` to emit only background activity. The default `true` includes this chain among routine events.

Every 120th flow cycle contains eight related flows from one client. It resolves `sync-gw.example.net`, makes repeated TLS connections to its resolved address, resolves it again, makes two more TLS connections, and finishes with a large HTTP POST to `/upload`. Background traffic continues throughout. A detection can use DNS-to-TLS correlation, periodic contact, unusual destination, or the large outbound request, then combine the signals into a sequence. The anomaly is visible in ordinary source fields; no detection label is added to events.

The shared state contains only a monotonic flow counter and the current flow, which is overwritten for every pair. One sensor observes a small client fleet.

## Reference Field Map

| Stream | Source fields | Generation strategy | Coverage |
|---|---|---|---:|
| `connection` | Zeek 4-tuple, `uid`, service, bytes, packets, state | One flow per input timestamp; native values also map to ECS network and endpoint fields | 50/51 |
| `dns` | Zeek query, response, flags, answers, TTLs | Linked to the preceding connection by `uid`; DNS answers reuse the attack destination | 55/56 |
| `http` | Zeek method, URI, status, body sizes, file IDs | Linked to the preceding connection; the anomaly ends with a large POST | 54/55 |
| `ssl` | Zeek SNI, TLS version, cipher, certificate identity | Linked to the preceding connection and DNS name | 69/70 |

Coverage is measured against the four Elastic Zeek `sample_event.json` files. The only missing reference field is `network.community_id`: no approximate hash is emitted because an invalid Community ID would be misleading. Collector metadata from the Elastic examples is represented with synthetic sensor values.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Name | Default | Purpose |
|---|---|---|
| `anomaly_mode` | `true` | Emit the correlated anomaly chain alongside routine events; `false` emits only background |
| `sensor_name` | `zeek-sensor-01` | Zeek sensor and collector name |
| `sensor_id` | `8aaedfb4-c8a3-4dd8-853f-5c270abfd47a` | Stable collector ID |
| `sensor_ephemeral_id` | `d2c2e56b-4915-4dc4-8ad9-6112f1d26e43` | Collector process ID |
| `sensor_version` | `8.7.1` | Collector version in ECS metadata |
| `dns_server_ip` | `10.20.0.53` | Internal DNS server |
| `suspicious_ip` | `198.51.100.77` | Fixed destination for the anomaly |
| `suspicious_name` | `sync-gw.example.net` | DNS query and TLS SNI in the anomaly |
| `suspicious_client_ip` | `10.20.8.44` | Client shared by anomaly events |
| `internal_domain` | `corp.example` | Domain for background internal DNS queries |

### Output Parameters

The shipped generator writes to `output/events.json` and needs no output overrides. To send the same events to OpenSearch, replace the `file` output with an `opensearch` output and use a regular `${params.opensearch_host}` override and keyring-backed `${secrets.opensearch_password}` for credentials. See the [OpenSearch output guide](https://eventum.run/docs/tutorials/delivery/opensearch) for the full configuration.

## Usage

```bash
# Bounded batch run; --live-mode false generates as fast as possible.
timeout 3 eventum generate --path generators/network-zeek/generator.yml --id zeek --live-mode false

# Continuous 5-flow/second run (10 records/second).
eventum generate --path generators/network-zeek/generator.yml --id zeek --live-mode true
```

## Sample Output

This complete connection event was produced by the generator:

```json
{
  "@timestamp": "2026-09-25T10:23:57+00:00",
  "agent": {
    "ephemeral_id": "d2c2e56b-4915-4dc4-8ad9-6112f1d26e43",
    "id": "8aaedfb4-c8a3-4dd8-853f-5c270abfd47a",
    "name": "zeek-sensor-01",
    "type": "filebeat",
    "version": "8.7.1"
  },
  "data_stream": {
    "dataset": "zeek.connection",
    "namespace": "default",
    "type": "logs"
  },
  "destination": {
    "address": "10.20.0.53",
    "bytes": 4987,
    "ip": "10.20.0.53",
    "packets": 7,
    "port": 53
  },
  "ecs": {
    "version": "8.17.0"
  },
  "elastic_agent": {
    "id": "8aaedfb4-c8a3-4dd8-853f-5c270abfd47a",
    "snapshot": false,
    "version": "8.7.1"
  },
  "event": {
    "agent_id_status": "verified",
    "category": [
      "network"
    ],
    "created": "2026-09-25T10:23:57+00:00",
    "dataset": "zeek.connection",
    "duration": 763983000,
    "id": "CteAviHzx48613103",
    "ingested": "2026-09-25T10:23:57+00:00",
    "kind": "event",
    "original": "{\"conn_state\": \"SF\", \"duration\": 0.763983, \"history\": \"Dd\", \"id.orig_h\": \"10.20.8.44\", \"id.orig_p\": 57037, \"id.resp_h\": \"10.20.0.53\", \"id.resp_p\": 53, \"local_orig\": true, \"local_resp\": true, \"missed_bytes\": 0, \"orig_bytes\": 349, \"orig_ip_bytes\": 573, \"orig_pkts\": 8, \"proto\": \"udp\", \"resp_bytes\": 4791, \"resp_ip_bytes\": 4987, \"resp_pkts\": 7, \"service\": \"dns\", \"ts\": 1790331837.0, \"tunnel_parents\": [], \"uid\": \"CteAviHzx48613103\"}",
    "type": [
      "connection",
      "start",
      "end"
    ]
  },
  "host": {
    "name": "zeek-sensor-01"
  },
  "input": {
    "type": "filestream"
  },
  "log": {
    "file": {
      "path": "/opt/zeek/logs/current/conn.log"
    }
  },
  "network": {
    "bytes": 5560,
    "direction": "internal",
    "packets": 15,
    "protocol": "dns",
    "transport": "udp"
  },
  "related": {
    "ip": [
      "10.20.8.44",
      "10.20.0.53"
    ]
  },
  "source": {
    "address": "10.20.8.44",
    "bytes": 573,
    "ip": "10.20.8.44",
    "packets": 8,
    "port": 57037
  },
  "tags": [
    "zeek-connection"
  ],
  "zeek": {
    "connection": {
      "history": "Dd",
      "local_orig": true,
      "local_resp": true,
      "missed_bytes": 0,
      "state": "SF",
      "state_message": "Normal establishment and termination."
    },
    "session_id": "CteAviHzx48613103"
  }
}
```

## References

- [Zeek log documentation](https://docs.zeek.org/en/master/tutorial/logs.html)
- [Elastic Zeek connection integration](https://github.com/elastic/integrations/tree/main/packages/zeek/data_stream/connection)
- [Elastic Zeek DNS integration](https://github.com/elastic/integrations/tree/main/packages/zeek/data_stream/dns)
- [Elastic Zeek HTTP integration](https://github.com/elastic/integrations/tree/main/packages/zeek/data_stream/http)
- [Elastic Zeek SSL integration](https://github.com/elastic/integrations/tree/main/packages/zeek/data_stream/ssl)

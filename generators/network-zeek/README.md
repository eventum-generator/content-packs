# Zeek Network Telemetry Generator

Generates linked Zeek 8.0.0 `conn.log`, `dns.log`, `http.log` and `ssl.log` records as ECS-compatible JSON, as collected by Filebeat from one Zeek sensor watching a fleet of IPv4 clients. `event.original` carries the compact native JSON line. Background traffic runs in both modes; `anomaly_mode` adds a recurring beacon-and-upload episode.

## Source profile

The selected profile uses `LogAscii::use_json=T`, `LogAscii::json_timestamps=JSON::TS_EPOCH`, `LogAscii::json_include_unset_fields=F` and `Site::local_nets={10.0.0.0/8}`. It models completely observed IPv4 traffic without retransmission, truncation, packet loss, tunnels, encryption keys, HTTP compression or chunked messages. Each flow has one DNS transaction, one HTTP transaction or one TLS handshake, and a later connection summary with the same UID and 4-tuple. UIDs and FUIDs are random `C`/`F` plus 16-17 base62 characters, the shape Zeek emits; Zeek's own seeded identifier algorithm is not reproduced.

Native timing follows the source stream. `conn.ts` is the first packet, `dns.ts` the query (positive `rtt` is query-to-answer time), `http.ts` the request after TCP establishment, `ssl.ts` the ClientHello. HTTP logs after the response, DNS after the reply, SSL after establishment is inferred. A closed TCP connection is logged after the five-second close timer; DNS-over-UDP summaries follow the dedicated `dns_session_timeout=10s` timer. TCP `duration` ends at the productive close and excludes the final ACK. All native times are microsecond epoch doubles with at most six decimals, as the Zeek JSON double writer prints them.

The collector polls every two seconds and reads the earliest completed record, so `@timestamp` (native start) can go backwards across the interleaved streams while `event.created` (read time plus up to 1.9 s) increases. `event.ingested` follows `event.created` by a random delay of about one second. Use `--keep-order true` so asynchronous output batches keep collector order. Pending records are capped at 64; a finite run ends with the records still waiting for their timers unread.

## Event Types Covered

Shares are measured in the final 96-hour default-on capture (58,243 records).

| Stream | Native events | Share of records | Category |
|---|---|---:|---|
| `conn.log` | Normally completed TCP/UDP flows, `SF`, byte and packet totals | 50.0% | network |
| `ssl.log` | Successful non-resumed TLS 1.3 handshake with visible SNI | 22.5% | network |
| `dns.log` | Recursive A query: NOERROR answer (96.3%) or NXDOMAIN (3.7%) | 17.5% | network |
| `http.log` | HTTP/1.1 GET 200 (65.1%), 304 (6.7%), 404 (2.0%); POST `/upload` 200 (25.5%), 503 (0.7%) | 10.0% | network, web |

Background clients are independent Poisson processes. Each client has its own random weight and follows an office-hours curve (UTC) shifted by up to three hours per client, so traffic is heavier in the day without a population-wide wave. A client keeps up to three resolved names for their TTL (1,800, 3,600 or 7,200 s) and talks to any of them over TLS (45% of flows once a name is live) or HTTP (20%); the rest are DNS lookups, which re-resolve a known name (20%) or look up a new one. New lookups pick `portal.example.net`, `mail.example.net`, `db.<internal_domain>`, a fresh `node-<hex8>.<suspicious_name>` resolving to one of `suspicious_ips`, or the missing `missing.<internal_domain>` (NXDOMAIN, not cached). Every client therefore resolves watched node names, beacons to them over TLS several times within minutes, re-resolves them and posts to them in ordinary traffic.

DNS uses one A question per UDP flow with recursion desired. In the tagged base script `RA` and `rtt` are assigned through an Answer-section hook, so a negative response with an authority SOA logs `RA=false`, no `rtt`, no `answers` and no `TTLs`. HTTP uses uncompressed Content-Length messages with Host, User-Agent and Connection headers and an IMF-fixdate Date header set after the request body is received and processed. Three GET resources have fixed representations and ETag `"v1"` (`/health` 200 bytes, `/index.html` 14,000 bytes, `/api/items` 8,400 bytes); a conditional GET sends `If-None-Match: "v1"` and gets a bodyless 304; a 404 requests `/missing.json`. POST bodies are 250,000-2,000,000 bytes in both modes; 3% of background POSTs get a 503. Nonempty bodies carry FUIDs and MIME types; the matching `files.log` records are out of scope. TLS 1.3 uses X25519 and one of the two AES-GCM suites, with no PSK, HelloRetryRequest, early data or compatibility CCS; the visible history is `Cs`, and certificates and `next_protocol` stay unset because they are encrypted. The TCP packet model uses 1,448-byte segments, 60-byte SYN and 52-byte later IPv4/TCP headers, one ACK per two data segments and a four-way close; UDP adds 28 bytes per packet.

## Anomaly Chain

A beacon-then-exfiltration episode by one client against one watched host:

1. DNS A query from client `C` for a fresh `node-<hex8>.<suspicious_name>` (NOERROR, answer `D` from `suspicious_ips`).
2. Five to seven TLS 1.3 connections from `C` to `D` with SNI equal to that name.
3. Another DNS query from `C` for the same name.
4. HTTP `POST /upload` from `C` to that host, 250,000-2,000,000-byte body, status 200.

- **Linking fields:** `source.ip`, `dns.question.name` = `tls.client.server_name` = `url.domain`, `dns.answers.data` = `destination.ip`. Every flow has its own UID and source port and a matching `zeek.connection` summary.
- **Episode shape:** log-normal gaps (TLS median 110 s, refresh and upload median about 60-70 s), total span kept under 25 minutes; measured spans 577-951 s (default) and 692-1,053 s (12 h).
- **Recurrence:** `anomaly_interval_hours` (default 24, minimum 6) of source time. The first episode starts within the first min(interval, 24 h) of the run; each later one in a window of min(interval/4, 6 h) centred one interval after the actual previous start, both with the hour weighted by the background curve squared plus a small floor, and then after an exponential delay (mean 4 minutes). Missed episodes are never caught up. Measured: default run first start 6.7 h, gaps 25.28-26.15 h, starts 12-17 UTC (an independent 96 h run gave gaps 21.98-24.97 h, starts 15-18 UTC); 12 h run first start 2.2 h, gaps 11.64-13.36 h. At intervals of 8 h or less the start phase necessarily covers the whole clock; at 12 h every second episode falls in the evening or night.
- **Variation:** the client (weighted like background) and the destination address change from one episode to the next; the name, TLS count, cipher, gaps and body size are drawn fresh each time.
- **Background overlap:** every step, and each client/destination pair the chain uses, also occurs in ordinary traffic of both modes (node names are fresh in both, so a name never links an episode to earlier traffic), including repeated TLS to one node name within minutes, re-resolution and uploads to node names. Only the complete ordered sequence is absent: a background POST that would complete it (DNS answer, five TLS, second DNS, all by the same client for the same name within 1,800 s of the first DNS) keeps its time and body but gets a 503. Across six 96-hour off captures this happened 11 times; across seven off captures (six from this run, one from the independent review), completed prefixes followed by a POST occur 16 times inside the window and 21 times in 1,800-3,600 s, with no step at the edge (4 in 1,500-1,800 s, 2 in 1,800-2,100 s).
- **Detection idea:** correlate DNS answers with SNI and Host per client, flag repeated TLS to a rarely seen host followed by a re-resolution and a large successful upload within half an hour. Any single step, host or body size alone is ordinary.

`anomaly_mode` defaults to `true`. With `false` the generator emits background traffic only, with no complete chain.

## Reference Field Map

| Stream | Selected native fields exercised | ECS/namespace mapping |
|---|---:|---|
| Connection | 21 | UID/endpoints, transport/service, duration, local flags, SF/history, payload/IP bytes, packet totals, `ip_proto` |
| DNS | 24 across positive/negative branches | Query/class/type, transaction ID, optional rtt, response/flags, optional answers/TTLs, rejected |
| HTTP | 21 across GET/POST/304 branches | Request/response, body lengths, status/tags, optional body FUID/MIME vectors |
| SSL | 13 | UID/endpoints, version/cipher/curve, SNI, resumed, established, visible history |

The table above counts the exercised native fields. Separately, exact flattened-path coverage against the four maintained Elastic `sample_event.json` records at the pinned commit is:

| Maintained sample | Covered / reference leaves | Coverage |
|---|---:|---:|
| Connection | 45 /51 | 88.24% |
| DNS | 51 /56 | 91.07% |
| HTTP | 49 /55 | 89.09% |
| SSL | 42 /70 | 60.00% |

Coverage uses the union of final default-on emitted paths, with arrays counted without indices. Missing in all four: `elastic_agent.id`, `elastic_agent.snapshot`, `elastic_agent.version`, `event.agent_id_status`, and `network.community_id`. These collector assertions and computed Community ID are not fabricated. Connection also omits `network.direction`; HTTP omits the parser-derived `user_agent.device.name`. SSL omits twenty certificate, X.509 and validation paths present in its maintained TLS 1.2 example because those facts are unavailable in the selected passive TLS 1.3 traffic. It also omits redundant `client.address` and `server.address` aliases. The reference `zeek.ssl.server.name` is represented here as native `zeek.ssl.server_name` and ECS `tls.client.server_name`, so that exact path is counted missing. This is selected ECS mapping, not full Elastic pipeline equivalence. These documented differences make some streams fall below 90%.

All emitted native fields are parsed into ECS endpoints or `zeek.<stream>`. Connection state is exposed as `zeek.connection.state`, and DNS transaction IDs use strings in ECS/the parsed namespace. No approximate Community ID, fabricated event sequence or verified agent status is emitted. Agent IDs/version represent configurable synthetic Filebeat collector inventory. They are not evidence that Filebeat or Elastic Agent processed these records. `observer.version` is pinned to the Zeek source profile independently of the collector version.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Name | Default | Purpose |
|---|---|---|
| `anomaly_mode` | `true` | Background plus recurring episodes; `false` is background only |
| `anomaly_interval_hours` | `24` | Episode interval in hours, minimum 6 |
| `sensor_name` | `zeek-sensor-01` | Sensor and collector host name |
| `sensor_id` | `8aaedfb4-c8a3-4dd8-853f-5c270abfd47a` | Synthetic collector agent ID |
| `sensor_ephemeral_id` | `d2c2e56b-4915-4dc4-8ad9-6112f1d26e43` | Synthetic collector process ID |
| `sensor_version` | `8.7.1` | Synthetic Filebeat version, not the Zeek version |
| `dns_server_ip` | `10.20.0.53` | Recursive DNS resolver the clients query |
| `suspicious_name` | `sync-gw.example.net` | Parent domain of the watched `node-<hex8>` names |
| `suspicious_ips` | `[198.51.100.77, 198.51.100.140, 203.0.113.201]` | Addresses the watched names resolve to (at least two) |
| `internal_domain` | `corp.example` | Internal zone for `db.` and the NXDOMAIN name |
| `client_ips` | twelve addresses in `10.20.8.0/22` | Client fleet, 4-32 distinct addresses inside `10.0.0.0/8` |

Configured names must be lowercase ASCII labels of at most 63 bytes, 100 bytes in total. An invalid parameter stops the generator before the first record.

### Output Parameters

The shipped file output writes `output/events.json` and needs no parameters. To send records elsewhere, replace `output` with another plugin and put its connection settings in top-level `${params.*}` / `${secrets.*}` placeholders, for example:

```yaml
output:
  - opensearch:
      hosts: ["${params.opensearch_host}"]
      username: ${params.opensearch_user}
      password: ${secrets.opensearch_password}
      index: logs-zeek-default
```

## Usage

```bash
# Live generation
eventum generate --path generators/network-zeek/generator.yml --id zeek --live-mode true --keep-order true

# Batch: add start/end to the cron input first, e.g. start: '2026-09-21T05:37:00Z', end: '2026-09-25T05:37:00Z'
eventum generate --path generators/network-zeek/generator.yml --id zeek-batch --live-mode false --keep-order true
```

## Limitations

- Four streams only (no `files.log`, `x509.log`, `weird.log`); one A question per DNS flow, one transaction per HTTP connection, passive TLS 1.3 without certificates.
- Packet segmentation, ACK policy, link rate, server processing time, TTLs and traffic rates are synthetic assumptions consistent with the tagged source, not a measured trace. The hour curve is synthetic and in UTC.
- Native JSON follows the tagged schemas, writer and baselines; no live Zeek, complete version-matched four-stream JSON capture or RapidJSON byte-for-byte number parity was verified. Filebeat inventory, `event.created`/`event.ingested` lags and ECS mapping are selected, not a run of the Elastic pipeline; Community ID and `network.direction` are not emitted.
- The guard turns about two background POSTs per 96 hours into 503 answers; those POSTs to watched names therefore fail more often than other POSTs, identically in both modes.
- Episode start hours use the curve squared, so episodes sit in busier hours than the average background flow.

## Sample Output

An episode TLS handshake, byte-exact from the final default-on capture:

```json
{"@timestamp": "2026-09-22T14:30:51.391148+00:00", "agent": {"ephemeral_id": "d2c2e56b-4915-4dc4-8ad9-6112f1d26e43", "id": "8aaedfb4-c8a3-4dd8-853f-5c270abfd47a", "name": "zeek-sensor-01", "type": "filebeat", "version": "8.7.1"}, "data_stream": {"dataset": "zeek.ssl", "namespace": "default", "type": "logs"}, "destination": {"address": "203.0.113.201", "ip": "203.0.113.201", "port": 443}, "ecs": {"version": "8.17.0"}, "event": {"category": ["network"], "created": "2026-09-22T14:30:52.943047+00:00", "dataset": "zeek.ssl", "id": "CbuZvt44kjC5iDd5YT", "ingested": "2026-09-22T14:30:54.544987+00:00", "kind": "event", "module": "zeek", "original": "{\"ts\":1790087451.391148,\"uid\":\"CbuZvt44kjC5iDd5YT\",\"id.orig_h\":\"10.20.9.31\",\"id.orig_p\":38573,\"id.resp_h\":\"203.0.113.201\",\"id.resp_p\":443,\"version\":\"TLSv13\",\"cipher\":\"TLS_AES_128_GCM_SHA256\",\"curve\":\"x25519\",\"server_name\":\"node-9ba06b0b.sync-gw.example.net\",\"resumed\":false,\"established\":true,\"ssl_history\":\"Cs\"}", "type": ["connection", "protocol", "info"]}, "host": {"name": "zeek-sensor-01"}, "input": {"type": "filestream"}, "log": {"file": {"path": "/opt/zeek/logs/current/ssl.log"}}, "message": "{\"ts\":1790087451.391148,\"uid\":\"CbuZvt44kjC5iDd5YT\",\"id.orig_h\":\"10.20.9.31\",\"id.orig_p\":38573,\"id.resp_h\":\"203.0.113.201\",\"id.resp_p\":443,\"version\":\"TLSv13\",\"cipher\":\"TLS_AES_128_GCM_SHA256\",\"curve\":\"x25519\",\"server_name\":\"node-9ba06b0b.sync-gw.example.net\",\"resumed\":false,\"established\":true,\"ssl_history\":\"Cs\"}", "network": {"protocol": "tls", "transport": "tcp"}, "observer": {"name": "zeek-sensor-01", "product": "Zeek", "type": "ids", "version": "8.0.0"}, "related": {"ip": ["10.20.9.31", "203.0.113.201"]}, "source": {"address": "10.20.9.31", "ip": "10.20.9.31", "port": 38573}, "tags": ["zeek-ssl"], "tls": {"cipher": "TLS_AES_128_GCM_SHA256", "client": {"server_name": "node-9ba06b0b.sync-gw.example.net"}, "curve": "x25519", "established": true, "resumed": false, "version": "1.3", "version_protocol": "tls"}, "zeek": {"session_id": "CbuZvt44kjC5iDd5YT", "ssl": {"cipher": "TLS_AES_128_GCM_SHA256", "curve": "x25519", "established": true, "resumed": false, "server_name": "node-9ba06b0b.sync-gw.example.net", "ssl_history": "Cs", "version": "TLSv13"}}}
```

## References

- [HTTP 304 response semantics](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4.5), used for conditional requests and zero response bodies.
- [Zeek 8 connection log and native example](https://docs.zeek.org/en/v8.0.0/logs/conn.html), [DNS](https://docs.zeek.org/en/v8.0.0/logs/dns.html), [HTTP](https://docs.zeek.org/en/v8.0.0/logs/http.html), [SSL](https://docs.zeek.org/en/v8.0.0/logs/ssl.html).
- Tagged v8.0.0 schemas and log hooks: [connection](https://github.com/zeek/zeek/blob/v8.0.0/scripts/base/protocols/conn/main.zeek), [DNS](https://github.com/zeek/zeek/blob/v8.0.0/scripts/base/protocols/dns/main.zeek), [HTTP](https://github.com/zeek/zeek/blob/v8.0.0/scripts/base/protocols/http/main.zeek), [HTTP body metadata](https://github.com/zeek/zeek/blob/v8.0.0/scripts/base/protocols/http/entities.zeek), [SSL](https://github.com/zeek/zeek/blob/v8.0.0/scripts/base/protocols/ssl/main.zeek).
- [TLS 1.3 encrypted-state transition](https://github.com/zeek/zeek/blob/v8.0.0/src/analyzer/protocol/ssl/ssl-protocol.pac), [establishment inference](https://github.com/zeek/zeek/blob/v8.0.0/src/analyzer/protocol/ssl/ssl-dtls-analyzer.pac), [tagged native TLS baseline](https://github.com/zeek/zeek/blob/v8.0.0/testing/btest/Baseline/scripts.base.protocols.ssl.tls13/ssl-out.log).
- [Close/DNS timeout defaults](https://github.com/zeek/zeek/blob/v8.0.0/scripts/base/init-bare.zeek), [TCP close timer](https://github.com/zeek/zeek/blob/v8.0.0/src/packet_analysis/protocol/tcp/TCPSessionAdapter.cc), [DNS expiration timer](https://github.com/zeek/zeek/blob/v8.0.0/src/analyzer/protocol/dns/DNS.cc), [zero-answer DNS baseline](https://github.com/zeek/zeek/blob/v8.0.0/testing/btest/Baseline/scripts.base.protocols.dns.zero-responses/dns.log).
- [JSON output configuration](https://github.com/zeek/zeek/blob/v8.0.0/scripts/base/frameworks/logging/writers/ascii.zeek), [JSON formatter](https://github.com/zeek/zeek/blob/v8.0.0/src/threading/formatters/JSON.cc), [JSON double baseline](https://github.com/zeek/zeek/blob/v8.0.0/testing/btest/Baseline/scripts.base.frameworks.logging.ascii-double/json.log).
- [Elastic Zeek integration](https://github.com/elastic/integrations/tree/78fd455d22cdb74bd2a8e53249c25cc060f06010/packages/zeek), used for ECS naming rather than unsupported whole-sample coverage claims.

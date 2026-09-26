# Zeek Network Telemetry Generator

Generates linked Zeek 8.0.0 `conn.log`, `dns.log`, `http.log`, and `ssl.log` records as ECS-compatible JSON. One sensor observes a small IPv4 client fleet. Native `event.original` is compact JSON with epoch timestamps and omitted unset fields, selected from the tagged Zeek 8 schemas. Both background and anomaly modes are supported.

## Source profile

The selected profile uses `LogAscii::use_json=T`, `LogAscii::json_timestamps=JSON::TS_EPOCH`, `LogAscii::json_include_unset_fields=F`, and `Site::local_nets={10.0.0.0/8}`. It models completely observed IPv4 traffic without retransmission, truncation, packet loss, tunnels, encryption keys, HTTP compression or chunked messages. UIDs and FUIDs use selected synthetic opaque identifiers, without reproducing Zeek's seeded identifier algorithm. Each fresh flow has one DNS transaction, one HTTP transaction, or one TLS handshake and a later connection summary with the same UID and 4-tuple. It does not reproduce every Zeek analyzer or a complete packet capture.

Native timing follows the source stream. `conn.ts` is the first packet. `dns.ts` is the query; positive `rtt` is query-to-answer time. `http.ts` is the request after TCP establishment. `ssl.ts` is first detection at ClientHello. HTTP logs after the response, DNS after the reply, and SSL after the analyzer infers establishment. A normally closed TCP connection is removed after the five-second close timer; DNS-over-UDP summaries follow the dedicated `dns_session_timeout=10s` timer, which removes the connection before the generic UDP inactivity timeout. The first timer expires for a single reply received within one second; the selected RTT is at most 120 ms. TCP `duration` ends at the productive close and excludes the final ACK. Timer targets and packet scheduling are synthetic assumptions consistent with the tagged source, not a measured trace.

Use `--keep-order true` to preserve collector order through asynchronous output batches. The renderer starts one flow every ten seconds and reads two ready log records per ten-second collector poll. Protocol records precede their own connection summaries. `event.created` and `event.ingested` are the selected collector read time. `@timestamp` retains the native start time and can go backwards across the interleaved streams when an older connection summary arrives. The compact native serializer follows schema key order and omission rules. Exact RapidJSON floating-point byte parity and a complete version-matched four-stream JSON capture have not been verified.

All source clocks are UTC, including a run whose input is expressed with a different offset. Flow/session times have synthetic microsecond resolution. The shipped input is a selected quiet-fleet cadence, not a measured Zeek deployment rate. Pending records have a hard cap of 20. With two collector slots per ten seconds, the selected profile bounds collector backlog by 100 seconds; the final validation runs observed less than five seconds from connection-summary readiness to collection. Protocol completion-to-poll delay is less than ten seconds in this selected profile. The DNS cache holds one successful mapping per configured client, maximum 32 clients. There is no history of previous episodes in generator state.

A finite run can stop with up to 20 planned records not yet read, including protocol records awaiting collection and DNS flows awaiting timeout. Already completed middle flows are not dropped. Continuing the same generator instance drains these records. A finite end does not invent immediate final summaries.

## Event Types Covered

| Stream | Native events | Share of emitted records | Category |
|---|---|---:|---|
| `conn.log` | Normally completed TCP/UDP flows, `SF`, byte/packet totals | Approximately 50% | network |
| `dns.log` | Recursive A response or NXDOMAIN | Approximately 22.5% | network |
| `ssl.log` | Successful non-resumed TLS 1.3 handshake with visible SNI | Approximately 20% | network |
| `http.log` | Cleartext HTTP/1.1 GET/POST, 200/304/404 response | Approximately 7.5% | network, web |

The background protocol choice is 45% DNS, 40% TLS and 15% HTTP after an initial or expired mapping is resolved. Every configured client, including `suspicious_client_ip`, uses all three protocols. The configured destination and the same `node-<counter>.<suspicious_name>` naming pattern occur independently in background DNS, TLS and POST traffic. The generator does not label an event as malicious.

DNS uses one A question per UDP flow, recursion desired, and a selected recursive resolver. A successful answer populates the cache for 1,800, 3,600 or 7,200 seconds and supplies the destination, TLS SNI and HTTP Host. Negative queries are `missing.<internal_domain>` and carry an authority SOA. They do not overwrite the positive cache. In the tagged base script, `RA` and `rtt` are assigned through an Answer-section hook. A response with no Answer RR therefore logs `RA=false`, no `rtt`, no `answers` and no `TTLs`, even when the actual selected resolver supports recursion. Parsed ECS flags follow the logged fields.

HTTP uses uncompressed Content-Length messages with explicit Host, User-Agent and Connection headers. Every response includes an IMF-fixdate Date header from the selected UTC server response-header origination time, modeled after receiving the complete request and processing it, before transferring the response body. Three pre-existing GET resources have fixed representations and ETag `"v1"`, already known by the modeled clients: `/health` (200 bytes), `/index.html` (14,000-byte HTML), and `/api/items` (8,400-byte JSON). A conditional GET sends `If-None-Match: "v1"` before a 304; its response includes the matching ETag. A 404 requests the separate missing `/missing.json` and returns a 256-byte JSON error. These resource/cache preconditions are selected assumptions, not inferred from Zeek. POST request bodies range from 250,000 to 2,000,000 bytes in both modes. Connection payload counts include headers and bodies. A 304 has no response body, FUID or MIME type. Nonempty bodies have fresh FUIDs and selected MIME metadata; their corresponding `files.log` records are outside this pack's four-stream scope. No file extraction or actual body content is emitted.

TLS 1.3 uses X25519 and one of the two AES-GCM suites, with no PSK resumption, HelloRetryRequest, early data, compatibility CCS or encrypted ClientHello. Tagged analyzer code infers establishment after seeing encrypted records in both directions. The selected visible handshake history is `Cs`, ClientHello and ServerHello. It does not mean that Zeek decoded Finished, certificates or the encrypted ALPN choice. Certificate subjects, issuers, fingerprints, validation results and `next_protocol` are unset. The connection counters include the opaque TLS records, without attributing application contents.

The selected TCP packet model uses 1,448-byte payload segments, IPv4/TCP 60-byte SYN headers, 52-byte subsequent headers with timestamp options, a separate delayed ACK per two data segments, and a four-way close. UDP adds 28 bytes per packet. These explicit synthetic packet assumptions keep bytes and packet counts consistent. They do not claim every real capture uses the same segmentation or ACK policy.

## Anomaly Chain

`anomaly_mode: true` enables recurring episodes alongside background activity. The default interval is 24 hours. `anomaly_interval_hours` selects the interval, clamped to a six-hour minimum. The first episode starts after the interval. Due times are rounded up to the next ten-second flow slot, so recurrence is the configured interval through less than ten additional seconds, without a catch-up burst.

One configured client resolves a fresh ordinary-pattern hostname to the configured destination, makes five short TLS connections at two-minute intervals, refreshes that DNS mapping at minute twelve, and finishes a large cleartext POST to `/upload` at minute fourteen. Each flow has a new UID and source port. DNS and handshake completion precede the next operation. Background traffic continues between the eight selected flows, including independent activity from the same client to the same destination. Subsequent episodes use new hostnames and flow IDs.

A detection can correlate DNS answer, SNI/Host, UID joins and destination, recognize the repeated callback cadence, then combine it with the upload. An isolated hostname, IP, TLS connection or POST size is insufficient to identify the episode because the same features occur in background traffic. Setting `anomaly_mode: false` removes the complete timed sequence while preserving the ordinary classes, clients and targets.

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
| `anomaly_mode` | `true` | Background plus recurring episode; `false` is background only |
| `anomaly_interval_hours` | `24` | Episode interval, six-hour minimum |
| `sensor_name` | `zeek-sensor-01` | Sensor and synthetic collector name |
| `sensor_id` | `8aaedfb4-c8a3-4dd8-853f-5c270abfd47a` | Synthetic collector inventory ID |
| `sensor_ephemeral_id` | `d2c2e56b-4915-4dc4-8ad9-6112f1d26e43` | Synthetic collector process ID |
| `sensor_version` | `8.7.1` | Synthetic Filebeat inventory version, not the Zeek version |
| `dns_server_ip` | `10.20.0.53` | Observed recursive DNS resolver IPv4 address |
| `suspicious_ip` | `198.51.100.77` | Shared ordinary/episode destination IPv4 address |
| `suspicious_name` | `sync-gw.example.net` | Parent of generated ordinary/episode names |
| `suspicious_client_ip` | `10.20.8.44` | Shared ordinary/episode client |
| `client_ips` | `[10.20.8.12, 10.20.8.25, 10.20.9.31, 10.20.9.52]` | Other ordinary clients, deduplicated with the episode client |
| `internal_domain` | `corp.example` | Internal positive and negative DNS zone |

The selected profile supports 2-32 distinct clients inside `10.0.0.0/8`, valid IPv4 endpoints, and lowercase ASCII DNS labels with total configured-name length at most 100 bytes. Standard DNS label limits apply. Keep the shipped ten-second cadence and two collector slots when comparing the documented state/time bounds. No secrets or required output overrides are needed. The default file output is `output/events.json`.

### Output Parameters

The shipped file output needs no parameters. To send records to another backend, replace `output` with the selected plugin configuration and use top-level `${params.*}` or `${secrets.*}` placeholders for its connection settings.

## Usage

From the content-packs repository:

```bash
# Live quiet-fleet generation, up to two records per ten-second poll.
uv run --project ../eventum eventum generate --path generators/network-zeek/generator.yml --id zeek --live-mode true --keep-order true
```

For a finite run, add `start` and `end` to the existing cron input, for example:

```yaml
input:
  - cron:
      expression: '* * * * * */10'
      count: 2
      start: '2026-09-26T00:00:00Z'
      end: '2026-09-29T04:20:00Z'
```

```bash
uv run --project ../eventum eventum generate --path generators/network-zeek/generator.yml --id zeek-batch --live-mode false --keep-order true
```

## Validation

Four finite 76-hour-20-minute runs covered defaults/custom parameters with anomaly mode on/off. Custom sensor identities, resolver, clients, destination, DNS zones, collector version and twelve-hour interval were exercised with a Moscow-offset input and UTC output. Complete episodes were 3/0/6/0. A 97-hour-20-minute six-hour-interval stress run exercised sixteen complete episodes. Streaming checks cover native JSON/key omission, UTC/native clock joins, DNS cache/TTL, TLS passive visibility, byte/packet arithmetic, HTTP 304, all ordinary client/classes, bounded source/join state, periodicity and finite future tails. Meaningful mutations reject raw/parsed-consistent causal and byte errors.

The versioned first-party manuals contain full native JSON examples, but their packet timestamps are older than Zeek 8 and do not identify the emitting build. Tagged v8.0.0 BTest TLS and zero-answer DNS baselines provide full native TSV fixtures. Tagged JSON writer and double baselines specify compact JSON/number behavior. This supports the selected schema and mechanisms. No live Zeek/Elastic parser, tenant trace, complete four-stream v8 JSON capture or full packet-to-log byte parity was run. The PR remains draft within those evidence limits.

## Sample Output

This complete event was copied from the default-on finite generator output. It is an ordinary POST from the same client used by episodes, illustrating that its identity, destination class and body size are not a mode marker.

```json
{
  "@timestamp": "2026-09-26T00:33:10.027235+00:00",
  "agent": {
    "ephemeral_id": "d2c2e56b-4915-4dc4-8ad9-6112f1d26e43",
    "id": "8aaedfb4-c8a3-4dd8-853f-5c270abfd47a",
    "name": "zeek-sensor-01",
    "type": "filebeat",
    "version": "8.7.1"
  },
  "data_stream": {
    "dataset": "zeek.http",
    "namespace": "default",
    "type": "logs"
  },
  "destination": {
    "address": "203.0.113.25",
    "ip": "203.0.113.25",
    "port": 80
  },
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "POST",
    "category": [
      "network",
      "web"
    ],
    "created": "2026-09-26T00:33:20.000000+00:00",
    "dataset": "zeek.http",
    "id": "CvlehC0000000000c8",
    "ingested": "2026-09-26T00:33:20.000000+00:00",
    "kind": "event",
    "module": "zeek",
    "original": "{\"ts\":1790382790.027235,\"uid\":\"CvlehC0000000000c8\",\"id.orig_h\":\"10.20.8.44\",\"id.orig_p\":32968,\"id.resp_h\":\"203.0.113.25\",\"id.resp_p\":80,\"trans_depth\":1,\"method\":\"POST\",\"host\":\"portal.example.net\",\"uri\":\"/upload\",\"version\":\"1.1\",\"user_agent\":\"curl/8.5.0\",\"request_body_len\":441599,\"response_body_len\":127,\"status_code\":200,\"status_msg\":\"OK\",\"tags\":[],\"orig_fuids\":[\"FOCAYr0000000000c8\"],\"orig_mime_types\":[\"application/octet-stream\"],\"resp_fuids\":[\"FRFpsT0000000000c8\"],\"resp_mime_types\":[\"application/json\"]}",
    "outcome": "success",
    "type": [
      "connection",
      "protocol",
      "info"
    ]
  },
  "host": {
    "name": "zeek-sensor-01"
  },
  "http": {
    "request": {
      "body": {
        "bytes": 441599
      },
      "method": "POST"
    },
    "response": {
      "body": {
        "bytes": 127
      },
      "status_code": 200
    },
    "version": "1.1"
  },
  "input": {
    "type": "filestream"
  },
  "log": {
    "file": {
      "path": "/opt/zeek/logs/current/http.log"
    }
  },
  "message": "{\"ts\":1790382790.027235,\"uid\":\"CvlehC0000000000c8\",\"id.orig_h\":\"10.20.8.44\",\"id.orig_p\":32968,\"id.resp_h\":\"203.0.113.25\",\"id.resp_p\":80,\"trans_depth\":1,\"method\":\"POST\",\"host\":\"portal.example.net\",\"uri\":\"/upload\",\"version\":\"1.1\",\"user_agent\":\"curl/8.5.0\",\"request_body_len\":441599,\"response_body_len\":127,\"status_code\":200,\"status_msg\":\"OK\",\"tags\":[],\"orig_fuids\":[\"FOCAYr0000000000c8\"],\"orig_mime_types\":[\"application/octet-stream\"],\"resp_fuids\":[\"FRFpsT0000000000c8\"],\"resp_mime_types\":[\"application/json\"]}",
  "network": {
    "protocol": "http",
    "transport": "tcp"
  },
  "observer": {
    "name": "zeek-sensor-01",
    "product": "Zeek",
    "type": "ids",
    "version": "8.0.0"
  },
  "related": {
    "ip": [
      "10.20.8.44",
      "203.0.113.25"
    ]
  },
  "source": {
    "address": "10.20.8.44",
    "ip": "10.20.8.44",
    "port": 32968
  },
  "tags": [
    "zeek-http"
  ],
  "url": {
    "domain": "portal.example.net",
    "original": "/upload",
    "path": "/upload"
  },
  "user_agent": {
    "name": "curl",
    "original": "curl/8.5.0",
    "version": "8.5.0"
  },
  "zeek": {
    "http": {
      "host": "portal.example.net",
      "method": "POST",
      "orig_fuids": [
        "FOCAYr0000000000c8"
      ],
      "orig_mime_types": [
        "application/octet-stream"
      ],
      "request_body_len": 441599,
      "resp_fuids": [
        "FRFpsT0000000000c8"
      ],
      "resp_mime_types": [
        "application/json"
      ],
      "response_body_len": 127,
      "status_code": 200,
      "status_msg": "OK",
      "tags": [],
      "trans_depth": 1,
      "uri": "/upload",
      "user_agent": "curl/8.5.0",
      "version": "1.1"
    },
    "session_id": "CvlehC0000000000c8"
  }
}
```

## References

- [HTTP 304 response semantics](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4.5), used for conditional requests and zero response bodies.

- [Zeek 8 connection log and native example](https://docs.zeek.org/en/v8.0.0/logs/conn.html), [DNS](https://docs.zeek.org/en/v8.0.0/logs/dns.html), [HTTP](https://docs.zeek.org/en/v8.0.0/logs/http.html), [SSL](https://docs.zeek.org/en/v8.0.0/logs/ssl.html).
- Tagged v8.0.0 schemas and log hooks: [connection](https://github.com/zeek/zeek/blob/v8.0.0/scripts/base/protocols/conn/main.zeek), [DNS](https://github.com/zeek/zeek/blob/v8.0.0/scripts/base/protocols/dns/main.zeek), [HTTP](https://github.com/zeek/zeek/blob/v8.0.0/scripts/base/protocols/http/main.zeek), [HTTP body metadata](https://github.com/zeek/zeek/blob/v8.0.0/scripts/base/protocols/http/entities.zeek), [SSL](https://github.com/zeek/zeek/blob/v8.0.0/scripts/base/protocols/ssl/main.zeek).
- [TLS 1.3 encrypted-state transition](https://github.com/zeek/zeek/blob/v8.0.0/src/analyzer/protocol/ssl/ssl-protocol.pac), [establishment inference](https://github.com/zeek/zeek/blob/v8.0.0/src/analyzer/protocol/ssl/ssl-dtls-analyzer.pac), [tagged native TLS baseline](https://github.com/zeek/zeek/blob/v8.0.0/testing/btest/Baseline/scripts.base.protocols.ssl.tls13/ssl-out.log).
- [Close/DNS timeout defaults](https://github.com/zeek/zeek/blob/v8.0.0/scripts/base/init-bare.zeek), [TCP close timer](https://github.com/zeek/zeek/blob/v8.0.0/src/packet_analysis/protocol/tcp/TCPSessionAdapter.cc), [DNS expiration timer](https://github.com/zeek/zeek/blob/v8.0.0/src/analyzer/protocol/dns/DNS.cc), [zero-answer DNS baseline](https://github.com/zeek/zeek/blob/v8.0.0/testing/btest/Baseline/scripts.base.protocols.dns.zero-responses/dns.log).
- [JSON output configuration](https://github.com/zeek/zeek/blob/v8.0.0/scripts/base/frameworks/logging/writers/ascii.zeek), [JSON formatter](https://github.com/zeek/zeek/blob/v8.0.0/src/threading/formatters/JSON.cc), [JSON double baseline](https://github.com/zeek/zeek/blob/v8.0.0/testing/btest/Baseline/scripts.base.frameworks.logging.ascii-double/json.log).
- [Elastic Zeek integration](https://github.com/elastic/integrations/tree/78fd455d22cdb74bd2a8e53249c25cc060f06010/packages/zeek), used for ECS naming rather than unsupported whole-sample coverage claims.

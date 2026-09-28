# HAProxy HTTP Access Syslog

Generates `option httplog` transactions from one HAProxy instance, preserving the native syslog line in `event.original` and mapping its values to ECS. The file output contains JSON; use `event.original` when forwarding raw syslog to a SIEM.

The native line follows the HAProxy 3.2 HTTP format, including `%TR/%Tw/%Tc/%Tr/%Ta`, status, transmitted bytes, cookies, termination flags, connection counters and request line. A 503 with `<NOSRV>` uses the exact timer and `SC--` combination in Elastic's raw HAProxy fixture. For successful responses, `event.duration` is derived from `%Ta`; HAProxy byte counts include response headers, including for 302 and 304.

## Event Types

| HTTP record | Meaning | Routine share |
| --- | --- | ---: |
| `GET /catalog/item/*` 200 | Catalog response | 66% |
| `POST /api/orders/*` 201 | Order creation | 10% |
| `GET /static/bundle-*.js` 304 | Cache validation response | 10% |
| `POST /login` 401 | Denied login request | 8% (8.3% with retries) |
| `GET /api/report` 503 | No backend server available | 2% |
| `POST /login` 302 | Application redirect | 2% (2.1% with retries) |
| `GET /admin/export` 200 | Large admin response | 2% |

These shares are synthetic workload settings, not a measured deployment. The source pool has 50 ordinary clients plus the IP used in the anomaly. The anomaly IP, redirect and export also occur as independent background traffic. Clients also retry failed logins: 2% of ordinary 401 responses start a burst of one to six more 401 responses from the same client on the next ticks (weights 45/25/14/8/5/3), and 70% of bursts end with a 302 redirect. The shares in parentheses are measured over five background-only 24-hour captures; one of them had 152 runs of two to seven consecutive 401 responses from one client, 93 of them followed by a 302.

## Anomaly Chain

Four `POST /login` 401 responses from one `source.ip` occur one second apart. A `POST /login` 302 and a large `GET /admin/export` 200 follow from that IP. The six records span five seconds at the shipped one-record-per-second cadence. Each episode uses fresh request times and six distinct TCP client ports; the first port differs from the preceding episode. These ports describe separate HTTP connections, not a fabricated session identifier.

Recurrence: with `anomaly_mode: true` (the default) the first episode starts at a time drawn uniformly within the first `min(anomaly_interval_hours, 24 h)` of the run; the background has no hour-of-day curve, so no hour is preferred. Each next episode is due `anomaly_interval_hours` after the actual start of the previous one and starts at a time drawn uniformly within a window of `w = min(interval / 4, 6 h)` centred on that due time. Consecutive starts are therefore `interval ± w/2` apart (2 h ± 15 min by default), start times do not drift, and missed intervals are never caught up. In one 24-hour default capture, 12 episodes started, with gaps of 1.78-2.07 h; with a one-hour interval, 24 episodes had gaps of 0.89-1.12 h.

Only the complete ordered chain is absent from background: an ordinary `GET /admin/export` 200 that would complete four 401 logins and a 302 login from the same client, with the first 401 at most 300 seconds before the export request, is replaced by another request from the ordinary pool (any class except the export) from that client at the same completion time. The export's timers are drawn first, only to place its request time for this check; the replacement then gets the timers, bytes and status of its own class. The guard also applies after an episode, so an ordinary export cannot complete a chain with an episode's own logins. This window of 300 seconds is the chain window to detect with. No other record is changed or moved. In seven background-only 24-hour captures, 312 sequences of four 401 logins and a 302 from one client occurred within 300 seconds; the same client's export followed 0 times inside the window and 30 times in the next 300 seconds, while the share of exports among other clients' records stayed level (1.82-2.04% in the 60-second bins inside the window, 1.84-2.03% after it). Catalog 200 responses of the same client had the same `%Tr` inside and outside the window (median 43 and 41 ms, maximum 75 ms in both).

A detector can combine the short failure burst, redirect and large admin transfer by source IP, frontend/backend and time. HAProxy does not log the user identity or session cookie in this format, so the 302 does not prove login success and IP correlation is weaker behind shared NAT.

`event.template.params.anomaly_mode` defaults to `true`. Set it to `false` to emit only background events. The same actor, paths and response classes also appear independently in background. No single path, IP or status code uniquely identifies the injected sequence.

The cron timestamps represent completed requests. Native `%tr` and ECS `@timestamp` represent the first request byte, computed as completion minus `%Ta`. The BSD-style syslog header represents completion, and `event.ingested` assumes zero collector delay. All dates are normalized to UTC, including runs started in another timezone. Successful requests take less than one second in this synthetic profile, so each chain request starts after its predecessor completed. An exported response of 843,220 transmitted bytes uses a LAN-scale transfer time. There is no `logasap`, TLS-handshake, HTTP/2, keep-alive-session or application-session model. The frontend's name is a label and does not establish TLS transport.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Meaning |
| --- | --- | --- |
| `proxy_name`, `proxy_ip` | `lb-web-01`, `10.60.0.5` | Simulated HAProxy source |
| `frontend_name`, `backend_name` | `https-in`, `app_pool` | HAProxy frontend and backend |
| `anomaly_ip`, `anomaly_path` | `10.99.3.51`, `/admin/export` | Correlated IPv4 source and unescaped absolute path; both also occur in background |
| `anomaly_interval_hours` | `2` | Mean time between episode starts (each start within ± `min(interval / 8, 3 h)` of its due time); values below `0.5` are clamped to `0.5` hours |
| `anomaly_mode` | `true` | Include periodic chains; `false` emits only background |

### Output Parameters

The shipped config writes `output/events.json` and has no `${params.*}` or `${secrets.*}` placeholders. Change `output.file.path` or replace the output plugin to connect a SIEM.

## Usage

From the content-packs repository root:

```bash
uv run --project ../eventum eventum generate --path generators/web-haproxy-http/generator.yml --id web-haproxy-http --live-mode true
```

For a short background sample, use `--live-mode false` and a short `timeout`. For a finite run, copy `generator.yml` beside the original as `finite.yml` and add these fields to its cron input:

```yaml
start: 2026-09-01T00:00:00+00:00
end: 2026-09-02T00:00:00+00:00
```

Then run:

```bash
uv run --project ../eventum eventum generate --path generators/web-haproxy-http/finite.yml --id web-haproxy-finite --live-mode false --keep-order true
```

This emits 86,401 transactions with 11-13 complete default episodes at randomized times. Repeat with `anomaly_mode: false` for the same background window and no injected chain. At a different input cadence, the chain advances one state per record and scheduling rounds up to a routine tick. The documented five-second sequence is for `count: 1` with one-second spacing.

Use ASCII token names for `proxy_name`, `frontend_name` and `backend_name`, a valid IPv4 `anomaly_ip`, and an absolute unescaped `anomaly_path` distinct from the routine routes. Unicode, spaces and quotes in that path are percent-encoded in both the native request line and ECS URL. Query strings are outside this path-only profile.

## Sample Output

This complete event is the export of the first episode of the 24-hour default enabled-mode capture:

```json
{
  "@timestamp": "2026-09-01T01:04:30.165000+00:00",
  "agent": {
    "ephemeral_id": "bb220000-2222-4444-8888-123456789abc",
    "id": "aa110000-1111-4444-8888-123456789abc",
    "name": "lb-web-01",
    "type": "filebeat",
    "version": "8.17.0"
  },
  "data_stream": {
    "dataset": "haproxy.log",
    "namespace": "default",
    "type": "logs"
  },
  "ecs": {
    "version": "8.17.0"
  },
  "elastic_agent": {
    "id": "aa110000-1111-4444-8888-123456789abc",
    "snapshot": false,
    "version": "8.17.0"
  },
  "event": {
    "agent_id_status": "verified",
    "category": [
      "web"
    ],
    "dataset": "haproxy.log",
    "duration": 835000000,
    "ingested": "2026-09-01T01:04:31+00:00",
    "kind": "event",
    "original": "Sep  1 01:04:31 lb-web-01 haproxy[2431]: 10.99.3.51:52473 [01/Sep/2026:01:04:30.165] https-in app_pool/app1 2/0/2/146/835 200 843220 - - ---- 2/1/1/1/0 0/0 \"GET /admin/export HTTP/1.1\"",
    "outcome": "success",
    "timezone": "+00:00"
  },
  "haproxy": {
    "backend_name": "app_pool",
    "backend_queue": 0,
    "bytes_read": 843220,
    "connection_wait_time_ms": 2,
    "connections": {
      "active": 2,
      "backend": 1,
      "frontend": 1,
      "retries": 0,
      "server": 1
    },
    "frontend_name": "https-in",
    "http": {
      "request": {
        "captured_cookie": "-",
        "raw_request_line": "GET /admin/export HTTP/1.1",
        "time_wait_ms": 2,
        "time_wait_without_data_ms": 146
      },
      "response": {
        "captured_cookie": "-"
      }
    },
    "server_name": "app1",
    "server_queue": 0,
    "termination_state": "----",
    "total_waiting_time_ms": 0
  },
  "host": {
    "ip": [
      "10.60.0.5"
    ],
    "name": "lb-web-01"
  },
  "http": {
    "request": {
      "method": "GET"
    },
    "response": {
      "bytes": 843220,
      "status_code": 200
    },
    "version": "1.1"
  },
  "input": {
    "type": "log"
  },
  "log": {
    "file": {
      "path": "/var/log/haproxy.log"
    },
    "offset": 706375
  },
  "message": "10.99.3.51:52473 [01/Sep/2026:01:04:30.165] https-in app_pool/app1 2/0/2/146/835 200 843220 - - ---- 2/1/1/1/0 0/0 \"GET /admin/export HTTP/1.1\"",
  "process": {
    "name": "haproxy",
    "pid": 2431
  },
  "related": {
    "ip": [
      "10.99.3.51"
    ]
  },
  "source": {
    "address": "10.99.3.51",
    "ip": "10.99.3.51",
    "port": 52473
  },
  "tags": [
    "preserve_original_event",
    "haproxy-log"
  ],
  "url": {
    "original": "/admin/export",
    "path": "/admin/export"
  }
}
```

## References and Limits

- [HAProxy 3.2 HTTP log format](https://docs.haproxy.org/3.2/configuration.html#8.2.3) defines the native field order, timers, byte semantics, and optional captures.
- [HAProxy 3.2 termination states](https://docs.haproxy.org/3.2/configuration.html#8.5) defines `SC--` and normal `----` completion.
- [Elastic HAProxy raw HTTP-log fixture](https://github.com/elastic/integrations/blob/main/packages/haproxy/data_stream/log/_dev/test/pipeline/test-httplog-no-headers.log) contains the `<NOSRV>` 503 pattern.
- [HAProxy 3.2.0 logging implementation](https://github.com/haproxy/haproxy/blob/v3.2.0/src/log.c) anchors request/completion timestamps and syslog header time.
- [HAProxy escaping rules](https://docs.haproxy.org/3.2/configuration.html#8.6) describe request-line byte escaping.
- [Elastic HAProxy sample event](https://github.com/elastic/integrations/blob/main/packages/haproxy/data_stream/log/sample_event.json) and [ingest pipeline](https://github.com/elastic/integrations/blob/main/packages/haproxy/data_stream/log/elasticsearch/ingest_pipeline/default.yml) anchor ECS mapping.

Across generated branches, 59 of 61 selected Elastic reference field paths are produced (96.7%). This excludes 18 environment and GeoIP/ASN enrichment paths from the reference. The two missing paths are optional captured request and response headers, absent in the chosen `option httplog` configuration. Filebeat, host and data-stream metadata are simulated collector context, not fields present in the HAProxy line. HTTP behavior, latency ranges, client mix and the anomaly sequence are synthetic assumptions; the references establish format and field meaning, not production frequency.

The retained-file BSD-style prefix omits syslog PRI and is not a complete syslog wire message. Optional header/cookie captures, retries, queueing, reused connections, TLS suffixes and enriched geo/host fields are outside the selected profile. Connection counters are plausible snapshots for one frontend/backend without queueing, not a universally required ordering. The byte offset is calculated from UTF-8 line bytes plus a newline in a single file; log rotation is not modeled. Scheduler state retains one due timestamp, one first port, a six-port list cleared after export and one active retry burst. The guard keeps, per client, the 401 times of the last 300 seconds (at most eight) and one anchor time; stale entries are pruned when the client next appears, so the state is bounded by the client pool. The file offset is a scalar, not an event list. Retry-burst rates and lengths are synthetic assumptions. No live HAProxy/parser end-to-end compatibility run was performed.

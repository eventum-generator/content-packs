# HAProxy HTTP Access Syslog

Generates `option httplog` transactions from one HAProxy instance, preserving the native syslog line in `event.original` and mapping its values to ECS. The file output contains JSON; use `event.original` when forwarding raw syslog to a SIEM.

The native line follows the HAProxy 3.2 HTTP format, including `%TR/%Tw/%Tc/%Tr/%Ta`, status, transmitted bytes, cookies, termination flags, connection counters and request line. A 503 with `<NOSRV>` uses the exact timer and `SC--` combination in Elastic's raw HAProxy fixture. For successful responses, `event.duration` is derived from `%Ta`; HAProxy byte counts include response headers, including for 302 and 304.

## Traffic Model

The proxy logs one completed request per second around the clock (86,400 a day), with no hour-of-day curve. The clients are 50 office workstations (`samples/clients.json`) and the remote-access address in `anomaly_ip`, which carries as much traffic as one workstation. All rates are synthetic workload values, not measured HAProxy traffic.

- **Single requests.** Most records are independent requests of a random client, drawn evenly from `samples/requests.json`: catalog pages, order creation, cache revalidation of script bundles, a report endpoint that has no server available (`503 <NOSRV>`), and the admin export.
- **Login sessions.** About 8,000 logins a day. Most sessions are a single `POST /login` 302. In about 2% of sessions the user is first denied one or more times (one denial in 39% of these sessions, two in 20%, three in 18%, four to seven in the rest) and retries after a pause of 2-45 s (about 7 s between attempts in the median); 75% of these sessions end with a 302, the rest give up. Users behind the remote-access address are denied five times as often (about a fifth of its login requests fail). After the 302 the browser requests the redirect target one second later: the admin export in about a quarter of logins, otherwise a catalog page. Zero to three further requests of the same client follow at pauses of 3-180 s (median 18 s).
- **Day-to-day variation.** The share of sessions with denied logins and the share of logins that land on the export vary from day to day, independently, between about half and twice their usual level.

Across all clients, about 5% of login requests are denied (2-8% on individual days); a workstation typically has 3-11 denied logins a day.

## Event Types

Shares of all records in background-only output (`anomaly_mode: false`), averaged over days:

| HTTP record | Meaning | Share |
| --- | --- | ---: |
| `GET /catalog/item/*` 200 | Catalog response | 66.4% |
| `POST /login` 302 | Login redirect | 9.2% |
| `POST /api/orders/*` 201 | Order creation | 9.0% |
| `GET /static/bundle-*.js` 304 | Cache validation response | 9.0% |
| `GET /admin/export` 200 | Large admin export (843,220 bytes) | 4.1% |
| `GET /api/report` 503 | No backend server available | 1.8% |
| `POST /login` 401 | Denied login | 0.4% |

## Anomaly Chain

`event.template.params.anomaly_mode` defaults to `true`. Every episode is one login session of the `anomaly_ip` client:

1. Four `POST /login` requests answered with 401, with the same retry pauses as ordinary denied logins.
2. A `POST /login` 302.
3. One second later, `GET` of `anomaly_path` (default `/admin/export`) with a 200 and 843,220 transmitted bytes.
4. Zero to three further ordinary requests of the same client, as after any login.

The first denial and the export are typically about 30 s apart (20-70 s) and always within 300 s. Each request uses its own TCP client port; these ports describe separate HTTP connections, not a session identifier.

Recurrence: the first episode starts at a time drawn uniformly within the first `min(anomaly_interval_hours, 24 h)` of the log; the traffic has no hour-of-day curve, so no hour is preferred. Each next episode is due `anomaly_interval_hours` after the actual start of the previous one and starts at a time drawn uniformly within a window of `w = min(interval / 4, 6 h)` centred on that due time: consecutive starts are `interval ± w/2` apart (2 h ± 15 min by default, about 12 episodes a day), start times do not drift, and missed intervals are never caught up. An episode can start a few seconds after its drawn time while other clients' logins are in progress.

Every step and every partial sequence of the chain also occurs in ordinary traffic of both modes, from the same client and from others: denied logins followed by a 302, a 302 followed by the export, denials followed by a 302 and the export. With `anomaly_mode: true` each episode adds its own records, so counts of these partial sequences (per client, within 300 s) are about one per episode higher. For the `anomaly_ip` client alone the episodes are most of such sequences: its ordinary traffic holds only a few a day, and its daily count of denied logins rises by four per episode. Episode records take the place of independent single requests of random clients (about seven per episode, out of 86,400 a day); no client's login session or follow-up requests are cut or moved.

What ordinary traffic never contains is the complete sequence: four 401 logins, a 302 login and an admin export from one client, with the first 401 request at most 300 seconds before the export request. Where an ordinary export would complete it, that client makes another ordinary request (any class except the export) at the same time instead; it has the timers, bytes and status of its own class. This also holds right after an episode, so the `anomaly_ip` client's ordinary exports never complete a second sequence with the episode's logins. Between 300 and 600 seconds, ordinary complete sequences do occur.

A detector can correlate four denied logins, a login redirect and a large admin transfer by source IP within 300 seconds. HAProxy does not log the user identity or session cookie in this format, so the 302 does not prove that the password was accepted, and IP correlation is weaker behind shared NAT, as for the remote-access address here.

Set `anomaly_mode` to `false` to emit only ordinary traffic; the client, paths and response classes of the chain still occur in it.

Time fields: each record's completion is a whole second. Native `%tr` and ECS `@timestamp` are the first request byte, computed as completion minus `%Ta`. The BSD-style syslog header is the completion time, and `event.ingested` assumes zero collector delay. All dates are in UTC. Successful requests take less than one second, so each request of a session starts after its predecessor completed.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Meaning |
| --- | --- | --- |
| `proxy_name`, `proxy_ip` | `lb-web-01`, `10.60.0.5` | Simulated HAProxy source |
| `frontend_name`, `backend_name` | `https-in`, `app_pool` | HAProxy frontend and backend |
| `anomaly_ip`, `anomaly_path` | `10.99.3.51`, `/admin/export` | Episode client and unescaped absolute export path; both also occur in ordinary traffic, and `anomaly_ip` is the remote-access address described above |
| `anomaly_interval_hours` | `2` | Mean time between episode starts (each start within ± `min(interval / 8, 3 h)` of its due time); values below `0.5` are treated as `0.5` hours |
| `anomaly_mode` | `true` | Include the recurring episodes; `false` emits only ordinary traffic |

Use ASCII token names for `proxy_name`, `frontend_name` and `backend_name`, a valid IPv4 `anomaly_ip`, and an absolute unescaped `anomaly_path`. Unicode, spaces and quotes in that path are percent-encoded in both the native request line and the ECS URL. Query strings are outside this path-only profile.

### Output Parameters

The shipped config writes `output/events.json` and has no `${params.*}` or `${secrets.*}` placeholders. Change `output.file.path` or replace the output plugin to connect a SIEM.

## Usage

From the content-packs repository root, live at one request per second:

```bash
eventum generate --path generators/web-haproxy-http/generator.yml --id web-haproxy-http --live-mode true
```

For a finite run, copy `generator.yml` beside the original as `finite.yml` and add these fields to its cron input:

```yaml
start: 2026-09-01T00:00:00+00:00
end: 2026-09-02T00:00:00+00:00
```

Then run:

```bash
eventum generate --path generators/web-haproxy-http/finite.yml --id web-haproxy-finite --live-mode false --keep-order true
```

This emits 86,401 transactions with about 12 episodes. Repeat with `anomaly_mode: false` for the same window without episodes.

Performance: about 2,000-5,000 events per second on one CPU core, depending on machine load; a 14-day log (1.2 million events) takes about 4-11 minutes.

## Sample Output

This complete event is the export of the first episode of a 24-hour default run:

```json
{
  "@timestamp": "2026-09-01T00:00:46.245000+00:00",
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
    "duration": 755000000,
    "ingested": "2026-09-01T00:00:47+00:00",
    "kind": "event",
    "original": "Sep  1 00:00:47 lb-web-01 haproxy[2431]: 10.99.3.51:52650 [01/Sep/2026:00:00:46.245] https-in app_pool/app1 0/0/0/168/755 200 843220 - - ---- 5/5/0/0/0 0/0 \"GET /admin/export HTTP/1.1\"",
    "outcome": "success",
    "timezone": "+00:00"
  },
  "haproxy": {
    "backend_name": "app_pool",
    "backend_queue": 0,
    "bytes_read": 843220,
    "connection_wait_time_ms": 0,
    "connections": {
      "active": 5,
      "backend": 0,
      "frontend": 5,
      "retries": 0,
      "server": 0
    },
    "frontend_name": "https-in",
    "http": {
      "request": {
        "captured_cookie": "-",
        "raw_request_line": "GET /admin/export HTTP/1.1",
        "time_wait_ms": 0,
        "time_wait_without_data_ms": 168
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
    "offset": 8558
  },
  "message": "10.99.3.51:52650 [01/Sep/2026:00:00:46.245] https-in app_pool/app1 0/0/0/168/755 200 843220 - - ---- 5/5/0/0/0 0/0 \"GET /admin/export HTTP/1.1\"",
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
    "port": 52650
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

## References

- [HAProxy 3.2 HTTP log format](https://docs.haproxy.org/3.2/configuration.html#8.2.3) defines the native field order, timers, byte semantics, and optional captures.
- [HAProxy 3.2 termination states](https://docs.haproxy.org/3.2/configuration.html#8.5) defines `SC--` and normal `----` completion.
- [Elastic HAProxy raw HTTP-log fixture](https://github.com/elastic/integrations/blob/main/packages/haproxy/data_stream/log/_dev/test/pipeline/test-httplog-no-headers.log) contains the `<NOSRV>` 503 pattern.
- [HAProxy 3.2.0 logging implementation](https://github.com/haproxy/haproxy/blob/v3.2.0/src/log.c) anchors request/completion timestamps and syslog header time.
- [HAProxy escaping rules](https://docs.haproxy.org/3.2/configuration.html#8.6) describe request-line byte escaping.
- [Elastic HAProxy sample event](https://github.com/elastic/integrations/blob/main/packages/haproxy/data_stream/log/sample_event.json) and [ingest pipeline](https://github.com/elastic/integrations/blob/main/packages/haproxy/data_stream/log/elasticsearch/ingest_pipeline/default.yml) anchor ECS mapping.

Across generated records, 59 of 61 selected Elastic reference field paths are produced (96.7%). This excludes 18 environment and GeoIP/ASN enrichment paths from the reference. The two missing paths are optional captured request and response headers, absent in the chosen `option httplog` configuration.

## Limitations

- JSON events with the native line in `event.original`; the retained-file BSD-style prefix omits syslog PRI and is not a complete syslog wire message. Filebeat, host and data-stream metadata are simulated collector context.
- Exactly one request completes per second. Requests that a browser sends milliseconds apart, such as the redirect target after a 302, are one second apart, and the request rate has no hour-of-day or weekday curve.
- Clients, paths, status mix, latency ranges, login failure rates and session behaviour are synthetic assumptions; the references establish format and field meaning, not production frequency. The remote-access address fails logins much more often than the workstations (about a fifth of its login requests).
- With `anomaly_mode: true`, counts of the chain's partial sequences are about one per episode higher than in ordinary traffic, and most such sequences of the `anomaly_ip` client are episodes.
- Complete sequences of four denied logins, a 302 and an export from one client are absent from ordinary traffic only within 300 seconds of the first denial; a detector with a longer window also finds ordinary ones.
- Optional header and cookie captures, queueing, retries, reused connections, TLS suffixes, HTTP/2, `logasap` and enriched geo/host fields are outside the selected profile. Connection counters are plausible snapshots for one frontend/backend without queueing. `log.offset` counts UTF-8 line bytes plus a newline in a single file; log rotation is not modeled.

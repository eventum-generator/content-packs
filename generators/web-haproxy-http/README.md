# HAProxy HTTP Access Syslog

Generates `option httplog` transactions from one HAProxy instance, preserving the native syslog line in `event.original` and mapping its values to ECS. The file output contains JSON; use `event.original` when forwarding raw syslog to a SIEM.

The native line follows the HAProxy 3.2 HTTP format, including `%TR/%Tw/%Tc/%Tr/%Ta`, status, transmitted bytes, cookies, termination flags, connection counters and request line. A 503 with `<NOSRV>` uses the exact timer and `SC--` combination in Elastic's raw HAProxy fixture. For successful responses, `event.duration` is derived from `%Ta`; HAProxy byte counts include response headers, including for 302 and 304.

## Event Types

| HTTP record | Meaning | Routine share |
| --- | --- | ---: |
| `GET /catalog/item/*` 200 | Catalog response | 66% |
| `POST /api/orders/*` 201 | Order creation | 10% |
| `GET /static/bundle-*.js` 304 | Cache validation response | 10% |
| `POST /login` 401 | Denied login request | 8% |
| `GET /api/report` 503 | No backend server available | 2% |
| `POST /login` 302 | Application redirect | 2% |
| `GET /admin/export` 200 | Large admin response | 2% |

These shares are synthetic workload settings, not a measured deployment. The source pool has 50 ordinary clients plus the IP used in the anomaly. The anomaly IP, redirect and export also occur as independent background traffic.

## Anomaly Chain

After 250 routine transactions, four `POST /login` 401 responses from the same `source.ip` occur one second apart. The next two records from that IP are `POST /login` 302 and a large `GET /admin/export` 200. The chain runs once per generator execution. A detector can combine the short failure burst, redirect and large admin transfer by source IP and time on this proxy. HAProxy does not log the user identity or session cookie in this format, so the 302 does not prove login success and IP correlation is weaker behind shared NAT.

`event.template.params.anomaly_mode` defaults to `true`. Set it to `false` to emit only background events. No single path, IP or status code uniquely identifies the anomaly; both modes contain the same values.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Meaning |
| --- | --- | --- |
| `proxy_name`, `proxy_ip` | `lb-web-01`, `10.60.0.5` | Simulated HAProxy source |
| `frontend_name`, `backend_name` | `https-in`, `app_pool` | HAProxy frontend and backend |
| `anomaly_ip`, `anomaly_path` | `10.99.3.51`, `/admin/export` | Correlated source and target; both also occur in background |
| `anomaly_after_events` | `250` | Routine transactions before the one-time chain |
| `anomaly_mode` | `true` | Include the chain; `false` emits only background |

### Output Parameters

The shipped config writes `output/events.json` and has no `${params.*}` or `${secrets.*}` placeholders. Change `output.file.path` or replace the output plugin to connect a SIEM.

## Usage

From the content-packs repository root:

```bash
uv run --project ../eventum eventum generate --path generators/web-haproxy-http/generator.yml --id web-haproxy-http --live-mode true
```

For a bounded local sample, use `--live-mode false` and a short `timeout`. Change the cron `count` for a different rate.

## Sample Output

This complete event came from an enabled-mode run:

```json
{
  "@timestamp": "2026-09-25T18:10:10+00:00",
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
    "duration": 757000000,
    "ingested": "2026-09-25T18:10:10+00:00",
    "kind": "event",
    "original": "Sep 25 18:10:10 lb-web-01 haproxy[2431]: 10.99.3.51:53758 [25/Sep/2026:18:10:10.000] https-in app_pool/app1 2/0/4/132/757 200 843220 - - ---- 5/5/3/1/0 0/0 \"GET /admin/export HTTP/1.1\"",
    "outcome": "success",
    "timezone": "+00:00"
  },
  "haproxy": {
    "backend_name": "app_pool",
    "backend_queue": 0,
    "bytes_read": 843220,
    "connection_wait_time_ms": 4,
    "connections": {
      "active": 5,
      "backend": 3,
      "frontend": 5,
      "retries": 0,
      "server": 1
    },
    "frontend_name": "https-in",
    "http": {
      "request": {
        "captured_cookie": "-",
        "raw_request_line": "GET /admin/export HTTP/1.1",
        "time_wait_ms": 2,
        "time_wait_without_data_ms": 132
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
    "offset": 46534
  },
  "message": "10.99.3.51:53758 [25/Sep/2026:18:10:10.000] https-in app_pool/app1 2/0/4/132/757 200 843220 - - ---- 5/5/3/1/0 0/0 \"GET /admin/export HTTP/1.1\"",
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
    "port": 53758
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
- [Elastic HAProxy sample event](https://github.com/elastic/integrations/blob/main/packages/haproxy/data_stream/log/sample_event.json) and [ingest pipeline](https://github.com/elastic/integrations/blob/main/packages/haproxy/data_stream/log/elasticsearch/ingest_pipeline/default.yml) anchor ECS mapping.

Across generated branches, 59 of 61 selected Elastic reference field paths are produced. This excludes 18 environment and GeoIP/ASN enrichment paths from the reference. The two missing paths are optional captured request and response headers, absent in the chosen `option httplog` configuration. Filebeat, host and data-stream metadata are simulated collector context, not fields present in the HAProxy line. HTTP behavior, latency ranges, client mix and the anomaly sequence are synthetic assumptions; the references establish format and field meaning, not production frequency.

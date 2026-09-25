# HAProxy HTTP Access Syslog

Generates HAProxy HTTP access records in native syslog format, with ECS fields for SIEM correlation. The complete HAProxy line is preserved in `event.original`; `message` holds its HTTP-log body.

Reference coverage: **57/60 (95%) source-derived fields** in the [Elastic HAProxy sample event](https://github.com/elastic/integrations/blob/main/packages/haproxy/data_stream/log/sample_event.json). The denominator excludes collector host metadata and GeoIP/ASN enrichment, which are not HAProxy log fields. The three omitted fields are optional captured request/response headers and `url.extension`; the default native format does not capture headers.

## Event Types

| HTTP record | Meaning | Routine share |
| --- | --- | ---: |
| `GET` 200 | Ordinary page or catalog request | 70% |
| `POST` 201 | Order API write | 10% |
| `GET` 304 | Static asset cache response | 10% |
| `POST /login` 401 | Denied login request | 8% |
| `GET /api/report` 503 | Backend unavailable (`<NOSRV>`) | 2% |
| `POST /login` 302, `GET /admin/export` 200 | Redirect and large admin response | Anomaly only |

The routine shares come from 50 request samples. They are configured proportions, not a measured HAProxy deployment. One FSM and one template keep each six-event anomaly sequence ordered among routine traffic.

## Anomaly Chain

Four `POST /login` 401 responses from `10.99.3.51` are followed by a 302 response from that IP, then a large 200 response for `GET /admin/export`. Correlate `source.ip`, request path, HTTP status, proxy name and timestamp. A detection can flag repeated login failures followed by a redirect and an unusual admin download. A 302 is only an observed redirect; the log does not prove authentication or identify an account.

`anomaly_mode: true` is the default. Set `event.template.params.anomaly_mode: false` for background only. The anomaly source and export path are absent in background mode.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Meaning |
| --- | --- | --- |
| `proxy_name`, `proxy_ip` | `lb-web-01`, `10.60.0.5` | HAProxy source |
| `frontend_name`, `backend_name` | `https-in`, `app_pool` | HTTP routing names |
| `anomaly_ip`, `anomaly_path` | `10.99.3.51`, `/admin/export` | Chain source and target |
| `anomaly_interval_events` | `250` | Background events between chains |
| `anomaly_mode` | `true` | Include anomaly sequence; `false` emits background only |

### Output Parameters

The shipped config writes `output/events.json` and has no `${params.*}` or `${secrets.*}` placeholders. Change `output.file.path` or replace the output plugin to connect a SIEM.

## Usage

From the content-packs repository root:

```bash
eventum generate --path generators/web-haproxy-http/generator.yml --id web-haproxy-http --live-mode true
```

For a short local sample, use `--live-mode false` and stop the command after enough events. Change the cron `count` for a different rate.

## Sample Output

The following event came from an enabled-mode run:

```json
{
  "@timestamp": "2026-09-25T12:18:45+00:00",
  "agent": {
    "ephemeral_id": "aa110000-1111-4444-8888-123456789abc",
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
    "duration": 19000000,
    "ingested": "2026-09-25T12:18:45+00:00",
    "kind": "event",
    "original": "Sep 25 12:18:45 lb-web-01 haproxy[2431]: 10.99.3.51:45399 [25/Sep/2026:12:18:45.000] https-in app_pool/app1 2/0/1/15/19 200 843220 - - ---- 1/1/1/1/0 0/0 \"GET /admin/export HTTP/1.1\"",
    "outcome": "success",
    "timezone": "+00:00"
  },
  "haproxy": {
    "backend_name": "app_pool",
    "backend_queue": 0,
    "bytes_read": 843220,
    "connection_wait_time_ms": 1,
    "connections": {
      "active": 1,
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
        "time_wait_ms": 0,
        "time_wait_without_data_ms": 2
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
    "offset": 46653
  },
  "message": "10.99.3.51:45399 [25/Sep/2026:12:18:45.000] https-in app_pool/app1 2/0/1/15/19 200 843220 - - ---- 1/1/1/1/0 0/0 \"GET /admin/export HTTP/1.1\"",
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
    "port": 45399
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

- [HAProxy HTTP log format](https://www.haproxy.com/documentation/haproxy-configuration-manual/latest/#8.2.3) defines the native HTTP line and timing fields.
- [Elastic HAProxy HTTP test lines](https://github.com/elastic/integrations/blob/main/packages/haproxy/data_stream/log/_dev/test/pipeline/test-httplog-no-headers.log) anchor the parsed record shape.
- [KUMA 4.0 supported sources](https://support.kaspersky.com/kuma/4.0/en-US/255782.htm) lists HAProxy HTTP syslog.

The file output is JSON containing a native `event.original`. A SIEM expecting raw syslog needs that field extracted or a different formatter/output. No session cookie or username is present, so the chain is linked by source IP and request details only.

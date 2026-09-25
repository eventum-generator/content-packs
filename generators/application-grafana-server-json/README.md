# Grafana OSS JSON server log

Synthetic Grafana OSS 9.5.1 server-log JSON messages based on real 9.5.0/9.5.1 lines in the upstream Grafana issue. The pack models the JSON message body, not a syslog header or Grafana audit log.

## Event types

| Native message | Approximate share with anomaly mode | ECS category | Meaning |
| --- | ---: | --- | --- |
| `Request Completed`, status 200 | 91.4% | `web` | Routine HTTP request using the observed request-log field set |
| `Parsing JSON Web Token` | 2.1% | `authentication` | JWT parser diagnostic |
| `Failed to verify JWT` | 2.1% | `authentication` | JWT verification diagnostic |
| `Invalid JWT` | 2.1% | `authentication` | JWT rejection diagnostic |
| `Request Completed`, status 401 | 2.1% | `web`, `authentication` | Rejected HTTP request |

The template uses FSM mode. It emits 128 routine requests, then three four-message JWT diagnostic/request groups when anomaly mode is enabled. Frequencies, identities, addresses, and timing are synthetic, not measured Grafana production rates. The 200 line varies values within the 401 request-log field set; it is not copied from a captured 200 line.

## Anomaly Chain

With `anomaly_mode: true` (the default), three `Request Completed` 401 events from `198.51.100.24` occur within eight simulated seconds. Each 401 is preceded by nearby `Parsing JSON Web Token`, `Failed to verify JWT`, and `Invalid JWT` messages. A detection rule can group the 401 events by `host.name` and `source.ip`, sort by `@timestamp`, and alert on at least three within a short window. Do not use file row order as the event clock.

The JWT diagnostics have no client IP or request ID in the source example. Their proximity provides context only; it cannot prove they belong to a particular 401 when requests overlap. This sequence also does not prove an attack. With `anomaly_mode: false`, only routine 200 requests appear: no JWT diagnostics or 401 events.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Purpose |
| --- | --- | --- |
| `anomaly_mode` | `true` | Include the repeated JWT rejection sequence; `false` produces background only |
| `grafana_host` | `grafana-01` | ECS host name |
| `routine_requests_before_chain` | `128` | Routine requests between anomaly sequences |
| `suspect_remote_addr` | `198.51.100.24` | Client IP shared by the three anomalous 401 events |
| `jwt_error` | `invalid character 'ÿ' looking for beginning of value` | Diagnostic error text from the source example |

### Output Parameters

No top-level `${params.*}` or `${secrets.*}` are required. Output defaults to `output/events.json`; edit the file output section to deliver elsewhere.

## Usage

From the content-packs repository:

```bash
eventum generate --path generators/application-grafana-server-json/generator.yml --id grafana --live-mode false
```

For continuous generation, use `--live-mode true`. Set `event.template.params.anomaly_mode` to `false` for background only. The file output is overwritten when a run starts.

## Sample output

This complete JSON event was copied from an anomaly-mode run:

```json
{
  "@timestamp": "2026-09-25T15:00:08.003000+00:00",
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "request_completed",
    "category": [
      "web",
      "authentication"
    ],
    "dataset": "grafana.server",
    "duration": 2213017,
    "kind": "event",
    "module": "grafana",
    "original": "{\"duration\": \"2.213017ms\", \"level\": \"info\", \"logger\": \"context\", \"method\": \"GET\", \"msg\": \"Request Completed\", \"orgId\": 0, \"path\": \"/\", \"referer\": \"\", \"remote_addr\": \"198.51.100.24\", \"size\": 39, \"status\": 401, \"t\": \"2026-09-25T15:00:08.003000000Z\", \"time_ms\": 2, \"uname\": \"\", \"userId\": 0}",
    "outcome": "failure",
    "type": [
      "denied"
    ]
  },
  "grafana": {
    "log": {
      "duration": "2.213017ms",
      "level": "info",
      "logger": "context",
      "method": "GET",
      "msg": "Request Completed",
      "orgId": 0,
      "path": "/",
      "referer": "",
      "remote_addr": "198.51.100.24",
      "size": 39,
      "status": 401,
      "t": "2026-09-25T15:00:08.003000000Z",
      "time_ms": 2,
      "uname": "",
      "userId": 0
    }
  },
  "host": {
    "name": "grafana-01"
  },
  "http": {
    "request": {
      "method": "GET"
    },
    "response": {
      "status_code": 401
    }
  },
  "log": {
    "level": "info"
  },
  "message": "Request Completed",
  "related": {
    "hosts": [
      "grafana-01"
    ],
    "ip": [
      "198.51.100.24"
    ]
  },
  "service": {
    "name": "Grafana OSS",
    "version": "9.5.1"
  },
  "source": {
    "ip": "198.51.100.24"
  },
  "url": {
    "path": "/"
  }
}
```

## Format and coverage

`event.original` preserves the native JSON message body; `grafana.log` exposes its fields. Against the real upstream lines, field coverage is 4/4 for `Parsing JSON Web Token`, 5/5 for `Failed to verify JWT`, 6/6 for `Invalid JWT`, and 15/15 for the 401 `Request Completed`. The generated 200 requests use those same 15 request fields with different synthetic values. The source example masks `remote_addr` as `<ip>`; the pack uses a documentation-range address. ECS `@timestamp` and native `t` describe the same synthetic UTC instant. No HTTP body, JWT token, syslog envelope, or Grafana audit record is modeled.

Grafana 9.5.1 defaults to text logging and permits JSON formatting for console, file, and syslog. Enable JSON on the chosen output and debug logging for the two debug JWT lines if you need that exact mix. The upstream example reports a JWT problem in Grafana 9.5.0/9.5.1; this pack reproduces its **log format**, not a known vulnerability. KUMA 4.2 lists a Grafana 9.5.15 syslog-JSON normalizer, but compatibility with that version or its transport envelope has not been tested.

## References

- [KUMA 4.2 supported sources](https://support.kaspersky.ru/kuma/4.2/255782)
- [Grafana upstream issue with real 9.5.0/9.5.1 JSON lines](https://github.com/grafana/grafana/issues/67582)
- [Grafana v9.5.1 logging defaults and JSON output options](https://github.com/grafana/grafana/blob/v9.5.1/conf/defaults.ini)

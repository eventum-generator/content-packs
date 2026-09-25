# Microsoft IIS Fixed-Format Access Logs

Generates ECS-compatible JSON whose `event.original` is the fixed, comma-separated IIS Log File Format with all 15 fields in vendor order. The IIS format must be selected explicitly; current IIS defaults to W3C Extended, which this pack does not emulate.

Reference coverage: **15/15 fixed IIS log columns, including the local date/time, site and server, byte counts, HTTP and Windows status, method, target, and parameters. The line is mirrored as parsed `iis.access.*` fields.**

## Event Types

| Type | Routine weight | Category |
| --- | ---: | --- |
| HTML page, HTTP 200 | 48% | Web access |
| Static asset, HTTP 200 | 31% | Web access |
| API status, HTTP 200 | 13% | Web access |
| Missing file, HTTP 404 | 6% | Web access |
| Admin path, HTTP 403 | 2% | Web access |
| Enumeration and payroll download | Anomaly only | Web access |

Weights are generator design values, not measured vendor production frequencies. One reusable template drives an FSM. The default input emits one event per second, preserving an observable order between anomaly steps.

## Anomaly Chain

With `event.template.params.anomaly_mode: true` (the default), the generator mixes background events with this sequence after every 240 routine events:

1. One unusual client requests `/backup/`, then `/admin/`, receiving 404 and 403.
2. The same client receives 403 on `/exports/`.
3. It then downloads `/exports/payroll.csv` with HTTP 200 and a large response, under an authenticated service user.

A detection can correlate an unusual client IP, multiple sensitive paths and 4xx results with a later large 200 response on the same server. The access log does not prove how the client obtained credentials, so the chain describes an observed web sequence rather than an authentication exploit.

Set `anomaly_mode: false` to emit only background. No anomaly steps or transition into the chain occur in that mode.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Meaning |
| --- | --- | --- |
| `server_name`, `server_ip` | `WEB-IIS-01`, `10.20.0.10` | IIS host identity |
| `site_id` | `W3SVC1` | IIS site/service instance |
| `anomaly_source_ip` | `198.51.100.77` | Client in the anomaly sequence |
| `anomaly_interval_events` | `240` | Routine events between chains |
| `anomaly_mode` | `true` | Enable the chain; `false` emits only background |

### Output Parameters

The shipped configuration writes `output/events.json` relative to the generator. It declares no top-level `${params.*}` or `${secrets.*}` overrides. Change `output.file.path` or replace the output plugin to deliver to a SIEM.

## Usage

Run from the content-packs repository root:

```bash
eventum generate --path generators/web-microsoft-iis/generator.yml --id web-microsoft-iis --live-mode true
```

Use `--live-mode false` for a fast local sample run.

## Sample Output

This complete event was copied from an enabled-mode generator run:

```json
{"@timestamp": "2026-09-25T11:45:58+00:00", "ecs": {"version": "8.17.0"}, "event": {"kind": "event", "module": "iis", "dataset": "iis.access", "category": ["web"], "type": ["access"], "action": "http_request", "outcome": "success", "original": "198.51.100.77, CONTOSO\\svc-reports, 09/25/26, 11:45:58, W3SVC1, WEB-IIS-01, 10.20.0.10, 78, 222, 8341712, 200, 0, GET, /exports/payroll.csv, -"}, "host": {"name": "WEB-IIS-01", "ip": "10.20.0.10"}, "source": {"ip": "198.51.100.77"}, "user": {"name": "CONTOSO\\svc-reports"}, "http": {"request": {"method": "GET", "bytes": 222}, "response": {"status_code": 200, "bytes": 8341712}}, "url": {"path": "/exports/payroll.csv", "query": "-"}, "iis": {"access": {"service": "W3SVC1", "server_name": "WEB-IIS-01", "server_ip": "10.20.0.10", "client_ip": "198.51.100.77", "username": "CONTOSO\\svc-reports", "date": "09/25/26", "time": "11:45:58", "time_taken": 78, "client_bytes_sent": 222, "server_bytes_sent": 8341712, "service_status_code": 200, "windows_status_code": 0, "request_type": "GET", "target": "/exports/payroll.csv", "parameters": "-"}}}
```

## References and Limits

- [Microsoft IIS fixed log format](https://learn.microsoft.com/en-us/windows/win32/http/iis-logging): the exact 15 field order, comma delimiters, local timestamps and hyphen placeholders.
- [IIS logFile settings](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/sites/sitedefaults/logfile/): IIS format selection and W3C default.
- [KUMA 4.0 supported event sources](https://support.kaspersky.com/kuma/4.0/en-US/255782.htm): Microsoft IIS source inventory.

The fixed format has second-resolution local timestamps and no User-Agent, URL host or session ID. The default synthetic host uses UTC local time; change the Eventum process timezone to emulate a different server-local timezone. `event.original` contains a single line without file header.

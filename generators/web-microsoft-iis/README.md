# Microsoft IIS 10 W3C Access Logs

Produces ECS JSON whose `event.original` is one IIS W3C Extended access-log data row. The 15-field profile below matches a published IIS 10.0 log and the IIS integration's supported W3C layout. The output plugin writes JSON events; it does not create a complete IIS log file with headers.

## W3C Profile

The modeled IIS site uses `logFormat=W3C` with these fields selected in this order:

```text
#Software: Microsoft Internet Information Services 10.0
#Version: 1.0
#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken
```

A native file also has a dynamic `#Date` header. Rows are space-delimited, timestamps are UTC, unavailable values are `-`, and `time-taken` is milliseconds. For example, `403 14 0` means directory listing was denied and `404 0 2` represents a missing file. The modeled HTTPS port is 443. A downstream parser that ingests only `event.original` needs this `#Fields` layout configured separately.

The field selection is explicit. Microsoft documents that 2026 Windows updates add byte counters to the default W3C field set on eligible systems, so the generated 15-field rows should not be treated as a universal IIS default. Response size cannot be inferred from this profile.

## Event Types

| Request | Routine pattern | Outcome |
| --- | --- | --- |
| Page `/Default.htm` | 50% of ordinary slots | 200.0 |
| Static asset | 32% of ordinary slots | 200.0 |
| `/api/status` | 12% of ordinary slots | 200.0 |
| Missing `/favicon-old.ico` | 5% of ordinary slots | 404.0, Win32 2 |
| `/admin/` directory | 1% of ordinary slots | 403.14 |
| `/backup/`, `/admin/`, `/exports/`, `/exports/payroll.csv` | One separated request to each per background day | 404.0, 403.14, 403.14, 200.0 |

Weights are synthetic workload values, not measured IIS traffic. One small site emits one request every 30 seconds, about 2,880 requests per day. The fixed background requests use the same client, User-Agent, paths and account as the anomaly but are separated by hours.

## Anomaly Chain

`event.template.params.anomaly_mode` defaults to `true`. After 240 routine requests, approximately two hours, the generator inserts one four-request sequence from `198.51.100.77`, with 30 seconds between requests:

1. `GET /backup/` returns `404 0 2`.
2. `GET /admin/` returns `403 14 0`.
3. `GET /exports/` returns `403 14 0`.
4. `GET /exports/payroll.csv` returns `200 0 0` as `CONTOSO\svc-reports`.

A rule can correlate path enumeration followed by access to a sensitive export from the same `c-ip` within two minutes. The W3C access row does not show how the client acquired credentials or how many bytes were downloaded. No single request distinguishes anomaly mode: all four request shapes also occur in background. This correlation assumes IIS sees the client directly; behind a load balancer, `c-ip` can be the proxy address unless a separate forwarded-client field is logged.

Set `anomaly_mode: false` to generate only background. The close four-request sequence is omitted.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Meaning |
| --- | --- | --- |
| `server_name`, `server_ip` | `WEB-IIS-01`, `10.20.0.10` | IIS host metadata and `s-ip` |
| `server_port` | `443` | `s-port` |
| `anomaly_source_ip` | `198.51.100.77` | Client used in both modes for the four sensitive requests |
| `anomaly_user` | `CONTOSO\svc-reports` | `cs-username` on authorized export requests in both modes |
| `anomaly_delay_events` | `240` | Routine requests before the one enabled-mode chain |
| `anomaly_mode` | `true` | Add the close four-request sequence |

### Output Parameters

The shipped configuration writes `output/events.json` relative to the generator. It has no top-level `${params.*}` or `${secrets.*}` placeholders. Change `output.file.path` or the output plugin to deliver elsewhere.

## Usage

From the content-packs repository root:

```bash
eventum generate --path generators/web-microsoft-iis/generator.yml --id web-microsoft-iis --live-mode true
```

Use `--live-mode false` for a fast local sample run.

## Sample Output

This complete event was copied from the enabled-mode validation run:

```json
{"@timestamp": "2026-09-25T19:19:30+00:00", "ecs": {"version": "8.17.0"}, "event": {"kind": "event", "module": "iis", "dataset": "iis.access", "category": ["web"], "type": ["access"], "action": "http_request", "outcome": "success", "duration": 99000000, "original": "2026-09-25 19:19:30 10.20.0.10 GET /exports/payroll.csv - 443 CONTOSO\\svc-reports 198.51.100.77 curl/8.5.0 - 200 0 0 99"}, "host": {"name": "WEB-IIS-01", "ip": "10.20.0.10"}, "source": {"ip": "198.51.100.77"}, "destination": {"ip": "10.20.0.10", "port": 443}, "http": {"request": {"method": "GET"}, "response": {"status_code": 200}}, "url": {"path": "/exports/payroll.csv"}, "user_agent": {"original": "curl/8.5.0"}, "iis": {"access": {"sub_status": 0, "win32_status": 0}}, "user": {"name": "CONTOSO\\svc-reports"}}
```

## References

- [Microsoft IIS logFile settings](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/sites/sitedefaults/logfile/): W3C format, UTC timestamps, fields, placeholders and the 2026 default-field change.
- [Microsoft IIS 10 W3C raw example](https://learn.microsoft.com/en-au/answers/questions/1080783/site-is-running-locally-but-when-it-is-published-i): firsthand 15-field header and access rows.
- [Microsoft IIS 10 W3C sample with protocol field](https://learn.microsoft.com/en-us/iis/get-started/whats-new-in-iis-10/http2-on-iis): vendor-authored full header and rows, confirming the W3C syntax.
- [Microsoft IIS status code overview](https://learn.microsoft.com/en-us/troubleshoot/developer/webapps/iis/health-diagnostic-performance/http-status-code): 403.14 semantics.
- [Microsoft IIS custom-field guidance](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/sites/sitedefaults/logfile/customfields/add): logging the original client behind a load balancer.
- [Elastic IIS integration](https://www.elastic.co/docs/reference/integrations/iis): parser-supported 15-field W3C layout and ECS mappings.
- [KUMA supported event sources](https://support.kaspersky.com/kuma/4.0/en-US/255782.htm): Microsoft IIS source listing.

# Microsoft IIS 10 W3C Access Logs

Produces ECS JSON whose `event.original` is one IIS W3C Extended access-log data row from a small intranet site. The 15-field profile below matches a published IIS 10.0 log and the IIS integration's supported W3C layout. The output plugin writes JSON events; it does not create a complete IIS log file with headers.

## W3C Profile

The modeled IIS site uses `logFormat=W3C` with these fields selected in this order:

```text
#Software: Microsoft Internet Information Services 10.0
#Version: 1.0
#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken
```

A native file also has a dynamic `#Date` header. Rows are space-delimited, timestamps are UTC with one-second resolution, unavailable values are `-`, spaces in the User-Agent are written as `+`, and `time-taken` is milliseconds. `403 14 0` means directory listing was denied, `404 0 2` a missing file and `304 0 0` a conditional request answered from the browser cache. The modeled HTTPS port is 443. A downstream parser that ingests only `event.original` needs this `#Fields` layout configured separately.

The field selection is explicit. Microsoft documents that 2026 Windows updates add byte counters to the default W3C field set on eligible systems, so the generated 15-field rows should not be treated as a universal IIS default. Response size cannot be inferred from this profile.

## Traffic Model

`samples/clients.json` lists 24 clients. Each one runs its own random processes; no client follows a fixed period, order or script:

- **Monitor** `10.20.9.30` (curl) polls `/api/status?site=main` roughly once a minute with a random gap.
- **Workstations** browse in sessions of one or more page views. A first view loads the page and most static assets within two seconds; later views mostly revalidate them with `304`. Later page views carry the previous page as referer. Two legacy pages link a missing `/favicon-old.ico` and stale URLs, which produce `404 0 2`. iPhone clients also request the two `apple-touch-icon` files, which do not exist.
- **Records users** (HR, finance and two remote users) and **script hosts** (`CONTOSO\svc-reports` with curl, `CONTOSO\svc-etl` with PowerShell) download files from `/exports/` with their own Windows accounts. They also try the `/exports/` listing, `/admin/` and the old `/backup/` path in random combinations and orders. A browser download that carries `/reports.htm` as referer (about 60%) is preceded by a view of that page, and some of its assets, 3-20 seconds earlier; other downloads have no referer. Script hosts retry exports that are not generated yet (`404 0 2`, then `200`), and records users occasionally mistype a file name.
- **IT staff** open `/admin/` and `/backup/`, sometimes followed by `/exports/`.
- **Scanner** `10.20.9.15` (Nmap Scripting Engine) runs a few bursts a day over a shuffled subset of common probe paths.

Interactive clients follow office hours (peak around 11:30 UTC, about 15% of the peak rate at night); the monitor, scanner and script hosts do not. The input fires five renders every five seconds, so the site writes at most five requests in any five-second window. All weights and rates are synthetic workload values, not measured IIS traffic.

## Event Types

Shares were measured over seven 48-hour `anomaly_mode: false` runs with default parameters (2,625-2,857 requests per day). Every row is `event.category: web`, `event.type: access`; `event.outcome` is `failure` for status 400 and above.

| Request | Share | Status | Outcome |
| --- | --- | --- | --- |
| Monitor `/api/status?site=main` | 50.4% | `200 0 0` | success |
| Page (`/Default.htm`, `/news.htm`, `/reports.htm`, ...) | 10.5% | `200 0 0` | success |
| Static asset (`/DeptLogo.gif`, `/styles/site.css`, `/scripts/site.js`) | 10.0% | `200 0 0` | success |
| Static asset revalidation | 8.6% | `304 0 0` | success |
| Authenticated `/exports/<file>` download | 4.3% | `200 0 0` | success |
| Scanner probe | 3.2% | `404 0 2`, `403 14 0` or `200 0 0` | mixed |
| Legacy `/favicon-old.ico` | 3.1% | `404 0 2` | failure |
| `/admin/` directory | 2.2% | `403 14 0` | failure |
| `/exports/` directory | 2.2% | `403 14 0` | failure |
| Page revalidation | 1.4% | `304 0 0` | success |
| iPhone `apple-touch-icon` files | 1.3% | `404 0 2` | failure |
| `/backup/` (removed path) | 1.2% | `404 0 2` | failure |
| Export retry or mistyped file | 0.8% | `404 0 2` | failure |
| Stale link from a legacy page | 0.6% | `404 0 2` | failure |

## Anomaly Chain

`event.template.params.anomaly_mode` defaults to `true`. Every episode is four requests from one client:

1. `GET /backup/` returns `404 0 2`.
2. `GET /admin/` returns `403 14 0`.
3. `GET /exports/` returns `403 14 0`.
4. `GET /exports/<file>` returns `200 0 0` with the client's Windows account in `cs-username`.

The requests link through `c-ip` and time only; the chosen W3C profile has no request or session identifier. Gaps between the steps come from the same distribution as ordinary sensitive-area activity (a few seconds to a few minutes), and episodes are typically under three minutes: 29-161 s in the 50 validation episodes. The gaps have no upper bound, so a longer episode is possible.

Recurrence runs on generated timestamps, so fast sample generation keeps the same event-time schedule. The first episode is due `anomaly_interval_hours` after the first generated timestamp; each episode begins at a random point 0-10 minutes after it is due, and the next one is due one interval after that actual start. Start times therefore drift later by about five minutes per episode on average. There is no catch-up queue: at most one episode is pending, and an episode never overlaps the next. The default interval is 6 hours; values below 3 hours are treated as 3 hours. The floor exists because every episode adds four sensitive-area requests: at intervals of 1-2 hours they measurably raise the `/backup/` share and the night-time sensitive activity of the episode clients compared with the same background without episodes.

Each episode picks a records user or script host other than the previous episode's actor, weighted by that client's current activity, so office-hours users rarely act at night and script hosts carry most night episodes, and one of that client's own export files, different from the previous episode's file when the client has another. The episode uses that client's address, User-Agent and account, and it does not pause or shift the client's ordinary traffic.

Every step, and every partial sequence of the chain, also occurs in ordinary traffic of both modes, from the same clients: over five 48-hour default runs the background held about 18 `/backup/` -> `/admin/` -> `/exports/` and 15 `/admin/` -> `/exports/` -> download sequences per day within 15 minutes, 175 same-client sensitive-area pairs under 10 minutes and 33 runs of three consecutive client errors. What background never contains is the complete ordered sequence ending in a download within 30 minutes from one client: an ordinary download that would complete it inside a window drawn per decision from 30-60 minutes is skipped. Across 15 off runs (48 h each), complete ordinary sequences occurred 0 times under 30 minutes, 85 times between 30 and 60 minutes (shortest 32 minutes) and 120 times between 1 and 2 hours. A detection can therefore correlate `/backup/` 404, `/admin/` 403.14 and `/exports/` 403.14 followed by a successful export download from the same `c-ip` within 15 minutes. The access row does not show how the client obtained its access or how many bytes it downloaded. The correlation assumes IIS sees the client directly; behind a load balancer, `c-ip` can be the proxy address unless a forwarded-client field is logged.

Set `anomaly_mode: false` to generate only background. The episode requests are omitted; the clients, accounts, paths, User-Agents and status combinations of the chain still occur independently.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Meaning |
| --- | --- | --- |
| `server_name` | `WEB-IIS-01` | IIS host name in `host.name` |
| `server_ip` | `10.20.0.10` | `s-ip`, `host.ip` and `destination.ip` |
| `server_port` | `443` | `s-port` and `destination.port` |
| `anomaly_interval_hours` | `6` | Hours between episode starts; values below 3 are treated as 3 |
| `anomaly_mode` | `true` | Add the recurring four-request episodes |

Clients, accounts, User-Agents, export files and per-client rates live in `samples/clients.json`. The template validates parameters and the roster on the first render; an invalid value aborts rendering with a message, visible with `-vv`, and produces no events.

### Output Parameters

The shipped configuration writes `output/events.json` relative to the generator and needs no connection parameters or secrets. To deliver elsewhere, replace the `file` output in a local copy with another output plugin and use top-level placeholders, for example:

```yaml
output:
  - opensearch:
      hosts:
        - ${params.opensearch_host}
      username: ${params.opensearch_user}
      password: ${secrets.opensearch_password}
      index: iis-access
      formatter:
        format: json
```

## Usage

From the content-packs repository root:

```bash
eventum generate --path generators/web-microsoft-iis/generator.yml --id web-microsoft-iis --live-mode true
```

For a fast finite sample, copy `generator.yml` to a file in the same directory, add `start` and `end` to its `input[0].cron` entry, and run the copy with `--live-mode false`. Stateful ordering relies on `--keep-order true`:

```bash
eventum generate --path generators/web-microsoft-iis/finite.yml --id web-microsoft-iis --live-mode false --keep-order true
```

## Limits

- JSON events with one W3C data row each, not a native IIS file with `#Software`, `#Version`, `#Date` and `#Fields` headers. The chosen 15 fields must be configured on IIS; on some builds updated since February 2026 the default set includes `sc-bytes` and `cs-bytes`.
- Timestamps have one-second resolution, as in the native row, so `@timestamp` never carries a fraction.
- Windows authentication is shown only as the account on successful export downloads; the anonymous `401 2 5` challenge that precedes it on a real server is not modeled, and directory probes are anonymous.
- The monitor polls about once a minute with a random gap (16-204 s) rather than on an exact interval, and interactive rates follow one UTC office-hours curve.
- The skipped-download rule guarantees only 30 minutes: a detector with a longer window finds ordinary B-A-E-download sequences (about 4 per day between 30 and 60 minutes).
- Clients, pages, files and rates are synthetic scenario assumptions rather than Microsoft-published traffic.

## Sample Output

An episode download (step 4, without a referer), copied from a default-parameter validation run:

```json
{"@timestamp": "2026-09-25T12:13:37+00:00", "ecs": {"version": "8.17.0"}, "event": {"kind": "event", "module": "iis", "dataset": "iis.access", "category": ["web"], "type": ["access"], "action": "http_request", "outcome": "success", "duration": 392000000, "original": "2026-09-25 12:13:37 10.20.0.10 GET /exports/payroll.csv - 443 CONTOSO\\lwhite 10.20.1.23 Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/150.0.0.0+Safari/537.36+Edg/150.0.0.0 - 200 0 0 392"}, "host": {"name": "WEB-IIS-01", "ip": "10.20.0.10"}, "source": {"ip": "10.20.1.23"}, "destination": {"ip": "10.20.0.10", "port": 443}, "http": {"request": {"method": "GET"}, "response": {"status_code": 200}}, "url": {"path": "/exports/payroll.csv"}, "user_agent": {"original": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36 Edg/150.0.0.0"}, "iis": {"access": {"sub_status": 0, "win32_status": 0}}, "user": {"name": "CONTOSO\\lwhite"}}
```

## References

- [Microsoft IIS logFile settings](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/sites/sitedefaults/logfile/): W3C format, UTC timestamps, fields, placeholders and the 2026 default-field change.
- [Microsoft IIS 10 W3C raw example](https://learn.microsoft.com/en-au/answers/questions/1080783/site-is-running-locally-but-when-it-is-published-i): firsthand 15-field header and access rows.
- [Microsoft IIS 10 W3C sample with protocol field](https://learn.microsoft.com/en-us/iis/get-started/whats-new-in-iis-10/http2-on-iis): vendor-authored full header and rows, confirming the W3C syntax.
- [Microsoft IIS status code overview](https://learn.microsoft.com/en-us/troubleshoot/developer/webapps/iis/health-diagnostic-performance/http-status-code): 403.14 semantics.
- [Microsoft IIS custom-field guidance](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/sites/sitedefaults/logfile/customfields/add): logging the original client behind a load balancer.
- [Elastic IIS integration](https://www.elastic.co/docs/reference/integrations/iis): parser-supported 15-field W3C layout and ECS mappings.
- [KUMA supported event sources](https://support.kaspersky.com/kuma/4.0/en-US/255782.htm): Microsoft IIS source listing.

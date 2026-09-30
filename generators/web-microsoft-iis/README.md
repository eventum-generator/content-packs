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

`samples/clients.json` lists 353 clients. Each one acts on its own random schedule; no client follows a fixed period, order or script:

- **Monitor** `10.20.9.30` (curl) polls `/api/status?site=main` once a minute, within about 15 seconds of the middle of the minute.
- **Workstations** (280 office PCs and 60 iPhones) browse in sessions of one or more page views. A first view loads the page and most static assets; later views mostly revalidate them with `304`. Later page views carry the previous page as referer. Two legacy pages link a missing `/favicon-old.ico` and stale URLs, which produce `404 0 2`. iPhone clients also request the two `apple-touch-icon` files, which do not exist. Rarely a workstation tries `/backup/`, `/admin/` or `/exports/`.
- **Records users** (seven HR and finance users, two of them remote) and **script hosts** (`CONTOSO\svc-reports` with curl, `CONTOSO\svc-etl` with PowerShell) download files from `/exports/` with their own Windows accounts. They also try the `/exports/` listing, `/admin/` and the old `/backup/` path in random combinations and orders; about a third of their visits that do not go through both `/admin/` and `/exports/` start at the old `/backup/` location (a stale bookmark, a script's legacy path). A browser download that carries `/reports.htm` as referer (about 60%) is preceded by a view of that page and some of its assets; other downloads have no referer. Script hosts retry exports that are not generated yet (`404 0 2`, then usually `200`), and records users occasionally mistype a file name.
- **IT staff** (two) browse and open `/admin/` and `/backup/`, sometimes followed by `/exports/`.
- **Scanner** `10.20.9.15` (Nmap Scripting Engine) runs a few bursts a day over a shuffled subset of common probe paths.

Records users, script hosts and IT staff work in `/backup/`, `/admin/` and `/exports/` in sittings of two to four visits a minute or a few apart. Each client's sittings come at a steady pace with random gaps rather than in clumps: about 14 visits a day per records user, 36 per script host and 10 per IT staff member.

All weights and rates are synthetic workload values, not measured IIS traffic.

## Volume and Timing

The site writes about 23,200 requests a day (21,900-24,400; each day varies by up to ±10%). Browser traffic follows one office-hours curve peaking around 11:30 UTC; the monitor, the scanner, the script hosts and part of the records users' work run around the clock. Mean request rate by hour of day, UTC:

| Hours (UTC) | Requests per second |
| --- | ---: |
| 18:00-04:59 | 0.12-0.13 |
| 05:00-07:59 | 0.14-0.26 |
| 08:00-09:59 | 0.39-0.54 |
| 10:00-12:59 | 0.66-0.71 |
| 13:00-14:59 | 0.54-0.39 |
| 15:00-17:59 | 0.26-0.15 |

Sittings in the sensitive area (about 66 a day, two to four visits each) follow the same curve: about two thirds are spread evenly over the day, one third follows the office-hours bell. The monitor's polls are about 6% of all requests.

## Event Types

Shares over 14 days of `anomaly_mode: false` traffic with default parameters. Every row is `event.category: web`, `event.type: access`; `event.outcome` is `failure` for status 400 and above.

| Request | Share | Status | Outcome |
| --- | --- | --- | --- |
| Static asset (`/DeptLogo.gif`, `/styles/site.css`, `/scripts/site.js`) | 26.7% | `200 0 0` | success |
| Page (`/Default.htm`, `/news.htm`, `/reports.htm`, ...) | 26.7% | `200 0 0` | success |
| Static asset revalidation | 20.9% | `304 0 0` | success |
| Legacy `/favicon-old.ico` | 8.6% | `404 0 2` | failure |
| Monitor `/api/status?site=main` | 6.2% | `200 0 0` | success |
| iPhone `apple-touch-icon` files | 4.0% | `404 0 2` | failure |
| Page revalidation | 3.2% | `304 0 0` | success |
| Stale link from a legacy page | 1.7% | `404 0 2` | failure |
| Authenticated `/exports/<file>` download | 0.62% | `200 0 0` | success |
| `/backup/` (removed path) | 0.34% | `404 0 2` | failure |
| `/admin/` directory | 0.33% | `403 14 0` | failure |
| `/exports/` directory | 0.33% | `403 14 0` | failure |
| Scanner probe | 0.28% | `404 0 2`, `403 14 0` or `200 0 0` | mixed |
| Export not there yet, mistyped or withheld | 0.20% | `404 0 2` | failure |

## Anomaly Chain

`event.template.params.anomaly_mode` defaults to `true`. Every episode is four requests from one client:

1. `GET /backup/` returns `404 0 2`.
2. `GET /admin/` returns `403 14 0`.
3. `GET /exports/` returns `403 14 0`.
4. `GET /exports/<file>` returns `200 0 0` with the client's Windows account in `cs-username`.

The requests link through `c-ip` and time only; the chosen W3C profile has no request or session identifier. Gaps between the steps follow the same distribution as ordinary sensitive-area visits, and a browser episode download that names `/reports.htm` as referer is preceded by that page view, as in ordinary traffic. An episode typically lasts one to three minutes; the gaps have no upper bound, so a longer one is possible.

The episode's requests come on top of the client's ordinary traffic: its sessions, downloads and sensitive-area sittings before and after an episode are the same as without it, and the daily request volume does not change with `anomaly_mode`.

Recurrence follows event time. The first episode starts within the first `anomaly_interval_hours` (at most 24 hours), at a moment drawn in proportion to the browser hour curve. Each later episode is due one interval after the previous actual start and begins within a window centred on that due time, `w = min(interval / 4, 6 h)` wide (±45 minutes at the default 6 hours), at a moment weighted by the square of the hour curve plus a small floor, so episodes lean towards busy hours without a fixed clock time. Missed episodes are not made up and episodes never overlap. At the default interval of 6 hours consecutive starts are 5.3-6.8 hours apart. Values below 3 hours are treated as 3 hours: every episode adds four sensitive-area requests, and at intervals of 1-2 hours they visibly raise the `/backup/` share and the night-time sensitive activity of the episode clients.

Each episode picks a records user or script host other than the previous episode's actor, weighted by that client's current sensitive-area activity, so office-hours users rarely act at night and script hosts carry most night episodes, and one of that client's own export files, different from the previous episode's file when the client has another. The episode uses that client's address, User-Agent and account.

Every step, and every partial sequence of the chain, also occurs in ordinary traffic of both modes, from the same clients. Per day, ordinary traffic holds about 32 (21-40) `/backup/` -> `/admin/` -> `/exports/` sequences within 15 minutes from one client, about 45 `/admin/` -> download, 68 `/exports/` -> download and 71 `/backup/` -> download pairs within 15 minutes, and every records user and script host makes each step of the chain in its ordinary traffic; most of them also produce each step pair within two days, but for a given client a particular pair can be absent from a two-day period. With `anomaly_mode: true` each episode adds its own requests, so counts of the chain parts (each step, each step pair, the three-step opening) are about one per episode higher: about 8 more per 48 hours at the default interval and 12 more at a 4-hour interval. Runs of three or more failed requests from one client within 15 minutes rise by about 1.5 per episode.

What ordinary traffic never contains is the complete ordered sequence ending in a successful download within 15 minutes of the `/backup/` request from one client. An ordinary download that would complete it returns `404 0 2` (the export is withheld), at the same time and path, about 27 times a day (19-38); a retry of the episode's own file right after an episode is answered the same way. A detection can therefore correlate `/backup/` 404, `/admin/` 403.14 and `/exports/` 403.14 followed by a successful export download from the same `c-ip` within 15 minutes. The access row does not show how the client obtained its access or how many bytes it downloaded. The correlation assumes IIS sees the client directly; behind a load balancer, `c-ip` can be the proxy address unless a forwarded-client field is logged.

Set `anomaly_mode: false` to generate only ordinary traffic. The episode requests are omitted; the clients, accounts, paths, User-Agents and status combinations of the chain still occur independently.

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

Clients, accounts, User-Agents, export files and each client's share of browsing sessions and sensitive-area visits live in `samples/clients.json`. Invalid parameters or roster entries stop generation with a message, visible with `-vv`, before any event is written.

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

Live generation at the configured rate, from the content-packs repository root:

```bash
eventum generate --path generators/web-microsoft-iis/generator.yml --id web-microsoft-iis --live-mode true
```

Batch generation: set `start` and `end` of the `oscillator` in all five `patterns/*.yml` files to the same range, with `start` at 00:00 UTC so the office-hours curve stays in place (for example `start: "2026-09-01T00:00:00Z"` and `end: "2026-09-03T00:00:00Z"`), then run:

```bash
eventum generate --path generators/web-microsoft-iis/generator.yml --id web-microsoft-iis --live-mode false --keep-order true
```

To change the volume, scale the `ratio` of `patterns/web-floor.yml` and `patterns/web-office.yml` by the same factor; `patterns/sens-floor.yml` and `patterns/sens-office.yml` set the number of sensitive-area sittings a day. Lower ratios stretch the seconds between a page and its assets. Episode start hours follow the shipped office-hours curve even if the patterns are reshaped.

Performance: about 3,800 events per second in batch mode on one core (14 days, 330,601 events, in 87 s on a shared, loaded machine).

## Limits

- JSON events with one W3C data row each, not a native IIS file with `#Software`, `#Version`, `#Date` and `#Fields` headers. The chosen 15 fields must be configured on IIS; on some builds updated since February 2026 the default set includes `sc-bytes` and `cs-bytes`.
- Timestamps have one-second resolution, as in the native row, so `@timestamp` never carries a fraction.
- Requests a browser sends together are seconds apart instead of milliseconds: a page's static assets follow it after a median of 5-6 s (90% within about 23 s, up to about 2.5 minutes at night), and a referer download follows its `/reports.htm` view after a median of 12-16 s (90% within about 45 s).
- Windows authentication is shown only as the account on successful export downloads; the anonymous `401 2 5` challenge that precedes it on a real server is not modeled, and directory probes are anonymous.
- The monitor polls on a one-minute schedule with a few seconds of jitter (gaps of about 43-78 s), and all interactive clients follow one UTC office-hours curve.
- Within 15 minutes after a client's `/backup/` 404, `/admin/` 403 and `/exports/` 403, that client's ordinary export downloads return `404 0 2` (about 27 a day); later ones succeed, so a detection window longer than 15 minutes finds ordinary complete sequences (about 2-3 a day completed between 15 and 30 minutes).
- With `anomaly_mode: true` each episode adds its own four requests, so counts of the chain parts are about one per episode higher than with `false`.
- Clients, pages, files and rates are synthetic scenario assumptions rather than Microsoft-published traffic.

## Sample Output

An episode download (step 4, with the `/reports.htm` referer):

```json
{"@timestamp": "2026-09-02T09:21:15+00:00", "ecs": {"version": "8.17.0"}, "event": {"kind": "event", "module": "iis", "dataset": "iis.access", "category": ["web"], "type": ["access"], "action": "http_request", "outcome": "success", "duration": 223000000, "original": "2026-09-02 09:21:15 10.20.0.10 GET /exports/ap-aging.csv - 443 CONTOSO\\tgarcia 10.20.2.44 Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64;+rv:152.0)+Gecko/20100101+Firefox/152.0 https://intranet.contoso.example/reports.htm 200 0 0 223"}, "host": {"name": "WEB-IIS-01", "ip": "10.20.0.10"}, "source": {"ip": "10.20.2.44"}, "destination": {"ip": "10.20.0.10", "port": 443}, "http": {"request": {"method": "GET"}, "response": {"status_code": 200}}, "url": {"path": "/exports/ap-aging.csv"}, "user_agent": {"original": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:152.0) Gecko/20100101 Firefox/152.0"}, "iis": {"access": {"sub_status": 0, "win32_status": 0}}, "user": {"name": "CONTOSO\\tgarcia"}}
```

## References

- [Microsoft IIS logFile settings](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/sites/sitedefaults/logfile/): W3C format, UTC timestamps, fields, placeholders and the 2026 default-field change.
- [Microsoft IIS 10 W3C raw example](https://learn.microsoft.com/en-au/answers/questions/1080783/site-is-running-locally-but-when-it-is-published-i): firsthand 15-field header and access rows.
- [Microsoft IIS 10 W3C sample with protocol field](https://learn.microsoft.com/en-us/iis/get-started/whats-new-in-iis-10/http2-on-iis): vendor-authored full header and rows, confirming the W3C syntax.
- [Microsoft IIS status code overview](https://learn.microsoft.com/en-us/troubleshoot/developer/webapps/iis/health-diagnostic-performance/http-status-code): 403.14 semantics.
- [Microsoft IIS custom-field guidance](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/sites/sitedefaults/logfile/customfields/add): logging the original client behind a load balancer.
- [Elastic IIS integration](https://www.elastic.co/docs/reference/integrations/iis): parser-supported 15-field W3C layout and ECS mappings.
- [KUMA supported event sources](https://support.kaspersky.com/kuma/4.0/en-US/255782.htm): Microsoft IIS source listing.

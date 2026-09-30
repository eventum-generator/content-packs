# Microsoft SharePoint Server ULS trace log

Synthetic SharePoint Server 2019 Unified Logging Service (ULS) trace rows for SIEM and detection testing: request traces from two web front ends and the legacy workflow timer job on an application server. Each row is ECS JSON that keeps the raw tab-separated ULS line in `event.original`. The pack models ULS diagnostic traces, not SharePoint audit records or Microsoft 365 activity.

The farm serves 348 office accounts (8 of them site owners) on 12 sites, plus the search crawl account `svc_crawl`.

## Volume and Timing

About 151,000 rows per weekday and 39,000 per weekend day, UTC:

| Hours (UTC) | Weekdays, rows per hour | Weekends, rows per hour |
| --- | ---: | ---: |
| 08:00-18:00 | about 11,800 | about 1,600 |
| 07:00-08:00, 18:00-20:00 | about 4,900 | about 1,600 |
| 20:00-07:00 | about 1,600 | about 1,600 |

Office users follow the working-day curve, and so does their presence: on a weekday about 205 accounts make requests in each office hour, about 95 in the shoulder hours and about 16 in a night hour. The search crawl account and the timer job run at a flat rate round the clock (about 1,100 rows per hour between them). A site owner makes about 80 to 115 requests on a weekday, most other accounts 20 to 85, in sessions of a few requests about 40 s apart.

## Event types

Shares are for three weekdays of default output (`anomaly_mode: true`, 24-hour interval), about 450,000 rows.

| ULS tag | Category (Area: SharePoint Foundation) | Level | Share | ECS category | Meaning |
| --- | --- | --- | ---: | --- | --- |
| `xmnv` | Logging Correlation Data | Medium | 30.5% | `process`, `web` | Correlation data: `Name=Request (...)`, `Name=Timer Job job-workflow`, `Site=...` |
| `nasq` | Monitoring | Medium | 16.1% | `process`, `web` | Entering monitored scope (request or timer job) |
| `b4ly` | Monitoring | Medium | 16.1% | `process`, `web` | Leaving monitored scope, with execution time, CPU ms and SQL query count |
| `avwhz` | Asp Runtime | Medium | 15.9% | `web` | SPRequestModule.BeginRequestHandler end, with the build number |
| `agb9s` | Authentication Authorization | Medium | 15.9% | `authentication` | Request identity (`IsAuthenticated`, `UserIdentityName`, claims count) |
| `af32k` | Claims Authentication | Medium | 1.5% | `authentication` | Windows sign-in challenge: 401 for an unauthenticated request |
| `b6p2` | General | Medium | 1.5% | `web` | HTTP 401 response sent |
| `aoxsq` | Runtime | Medium | 1.0% | `web` | HTTP 302 response sent (site-root and access-denied redirects) |
| `ahk8y` | Legacy Workflow Infrastructure | Verbose | 0.5% | `process` | Workflow instance begins processing |
| `b6p4` | Database | VerboseEx | 0.5% | `database` | Workflow-association SQL command |
| `tzkv` | Database | Verbose | 0.5% | `database` | Parameters of that SQL command |

A browser request writes `nasq`, `xmnv Name=Request (...)`, `avwhz`, `agb9s`, `xmnv Site=...`, an optional `aoxsq` redirect row and `b4ly`, in the order of the SharePoint Server 2019 trace published in Microsoft Q&A. The first request of about 70% of sessions is an anonymous NTLM challenge (`agb9s` with `IsAuthenticated=False`, `af32k`, `b6p2`). A timer-job run writes `nasq`, `xmnv Name=Timer Job job-workflow`, one `ahk8y`, `b6p4`, `tzkv` triple per workflow instance it processes, and `b4ly`.

Requests by kind (share of `Name=Request` rows, same run): site home pages 26%, document downloads 22%, search crawl 16%, library views 14%, NTLM challenges 10%, uploads 7%, site-root redirects 5%, access-denied pages 1%, permission grants 0.2%, permission-page views 0.2%, permission removals 0.1%.

- Sessions tend to stay on one site. About 1% of requests go to a site the account cannot open: 302 to `AccessDenied.aspx`, retried up to three more times within minutes; afterwards most users go back to a site they can open.
- Site owners also open the permissions page (`user.aspx`), grant permissions from the share dialog (`POST aclinv.aspx`, about 47 a weekday) and remove a grant later (`POST user.aspx`, planned for 75% of grants: 40% are quick reverts after a lognormal delay with a 15-minute median, the rest follow after a median of three hours; 45% of removals come right after the owner downloads one to six documents of that site). An owner who granted access and then downloaded three or more documents of the site within the hour opens the permissions page (`GET user.aspx`) at that moment instead of removing the grant (about 3 to 13 times a weekday, about 7 on average). So grant-then-download, several downloads then a removal, and grant-then-removal within the hour all occur in ordinary traffic, for every owner.
- Uploads to the six sites with a legacy workflow start workflow instances; the job-workflow timer job runs on a five-minute schedule with a random start latency and processes each instance one to three times.

## Anomaly Chain

With `anomaly_mode: true` (the default), one site owner on one of their sites, in `http.request.method` and `url.path` of the `xmnv Name=Request` rows:

1. `POST <site>/_layouts/15/aclinv.aspx` - permissions granted from the share dialog (sometimes preceded by the NTLM challenge and a `GET user.aspx`);
2. four to nine `GET <site>/Shared%20Documents/<file>` - distinct documents downloaded about 40 s apart, sometimes after a library view;
3. `POST <site>/_layouts/15/user.aspx` - permissions removed again, which restores the site's permission state.

Linking fields: `user.name` (from the `agb9s` identity of each request) and `sharepoint.site.url` (from `xmnv Site=`), within one hour from grant to removal (about 4 to 55 minutes). Each request has its own `sharepoint.uls.correlation_id`. The episode's requests have the same row shapes and pauses as ordinary requests; the owners, sites, pages and documents all appear in ordinary traffic of both modes, and the owner's ordinary sessions go on during the episode as on any other day.

Recurrence: episodes recur by event time every `anomaly_interval_hours` (default 24, minimum 6). The first start is drawn within the first `min(interval, 24 h)`; each later start is drawn in a window of width `w = min(interval / 4, 6 h)` centred on the previous actual start plus the interval, so the random offset from the due time is up to `w / 2` either way. Both draws are weighted by the square of the office-hours curve plus a small floor, so episodes sit mostly in weekday office hours, more tightly than ordinary sessions do. At the default interval consecutive grants are 21 to 27 h apart; at 12 hours they are 11 to 13 h apart and every second start falls in the evening; at 8 hours or less the starts cover the whole clock, nights included. Missed episodes are not replayed, and ordinary traffic is not paused or shifted around an episode. The owner differs from the previous episode's owner and the site from the previous episode's site; the owner is drawn uniformly among site owners and the site uniformly among their sites.

Detection idea: per account and site, a share-dialog grant, three or more document downloads and a permission removal within one hour - an owner widening access, taking documents and reverting the change. ULS carries no permission delta: which principal was granted or removed is only in the SharePoint audit log, so this is a hunting lead, not proof. Ordinary traffic never contains the full ordered sequence within the hour; every shorter part of it does, for every owner.

With `anomaly_mode: false`, the output is ordinary traffic only. With `anomaly_mode: true` each episode adds its own requests, so counts of the chain parts (grants, owner downloads, removals) are about one episode's worth higher.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Purpose |
| --- | --- | --- |
| `anomaly_mode` | `true` | Include the anomaly chain; `false` produces ordinary traffic only |
| `anomaly_interval_hours` | `24` | Hours from one episode start to the next due time (6 to 8760) |
| `web_app_url` | `https://portal.contoso.test` | HTTPS web application URL (scheme and host) in request names and ECS `url.*`; requests always carry port 443 |
| `wfe_hosts` | `[sp-wfe-01, sp-wfe-02]` | The two web front ends that run `w3wp.exe` |
| `app_host` | `sp-app-01` | Application server that runs `OWSTIMER.EXE` |

Sites, their owners and workflow flags are in `samples/sites.json`, accounts in `samples/users.csv` and document names in `samples/documents.csv`; edit these files to model another farm.

### Output Parameters

The shipped `generator.yml` writes to `output/events.json` and needs no `${params.*}` or `${secrets.*}`. To deliver elsewhere, replace the `file` output and pass connection values as placeholders, for example:

```yaml
output:
  - opensearch:
      hosts: ["${params.opensearch_host}"]
      username: ${params.opensearch_user}
      password: ${secrets.opensearch_password}
      index: sharepoint-uls
```

## Usage

Live generation at the configured rate, from the content-packs repository:

```bash
eventum generate --path generators/application-sharepoint-server-uls/generator.yml --id sharepoint-uls --live-mode true --keep-order true
```

Batch generation: set `start` and `end` of the `oscillator` in every `patterns/*.yml` file to the same range, with `start` on a Monday at 00:00 UTC so the weekday bands stay in place (for example `start: "2026-09-21T00:00:00Z"` and `end: "2026-09-24T00:00:00Z"`), then run:

```bash
eventum generate --path generators/application-sharepoint-server-uls/generator.yml --id sharepoint-uls --live-mode false --keep-order true
```

The rate is the sum of the `time_patterns` files under `patterns/`: `office-floor` (office users, every hour of every day), `office-<day>-day` (07:00-20:00 UTC) and `office-<day>-core` (08:00-18:00 UTC) for Monday to Friday, and `service` (crawl and timer job, flat). To change the volume, scale the `ratio` of every office file by the same factor; a lower volume spreads the rows of one request further apart. Episode start hours follow the shipped curve even if you reshape the pattern files. The file output is overwritten when a run starts.

Performance: about 2,500 to 3,700 rows per second in batch mode on one core.

## Sample output

The grant request of an episode, `xmnv Name=Request` row, from default output:

```json
{"@timestamp": "2026-09-21T17:38:22.970Z", "ecs": {"version": "8.17.0"}, "event": {"action": "correlation-data", "category": ["web"], "code": "xmnv", "dataset": "sharepoint.uls", "kind": "event", "module": "sharepoint", "original": "09/21/2026 17:38:22.97\tw3wp.exe (0x83E4)\t0x0FA8\tSharePoint Foundation\tLogging Correlation Data\txmnv\tMedium\tName=Request (POST:https://portal.contoso.test:443/sites/it/_layouts/15/aclinv.aspx)\t90874d28-8cb3-06e6-d2a6-418013147e49", "type": ["info"]}, "host": {"name": "sp-wfe-02"}, "http": {"request": {"method": "POST"}}, "log": {"level": "medium"}, "message": "Name=Request (POST:https://portal.contoso.test:443/sites/it/_layouts/15/aclinv.aspx)", "process": {"name": "w3wp.exe", "pid": 33764, "thread": {"id": 4008}}, "related": {"hosts": ["sp-wfe-02"], "user": ["a.smirnov"]}, "service": {"name": "SharePoint Server", "version": "16.0.10390.20000"}, "sharepoint": {"site": {"url": "/sites/it"}, "uls": {"area": "SharePoint Foundation", "category": "Logging Correlation Data", "correlation_id": "90874d28-8cb3-06e6-d2a6-418013147e49", "event_id": "xmnv", "level": "Medium", "message": "Name=Request (POST:https://portal.contoso.test:443/sites/it/_layouts/15/aclinv.aspx)", "process": "w3wp.exe (0x83E4)", "thread_id": "0x0FA8", "timestamp_local": "09/21/2026 17:38:22.97"}}, "url": {"domain": "portal.contoso.test", "original": "https://portal.contoso.test:443/sites/it/_layouts/15/aclinv.aspx", "path": "/sites/it/_layouts/15/aclinv.aspx", "port": 443, "scheme": "https"}, "user": {"domain": "contoso", "name": "a.smirnov"}}
```

## Format and coverage

`event.original` holds all nine ULS columns separated by tabs: Timestamp (`MM/dd/yyyy HH:mm:ss.ff`), Process (`name (0xPID)`), TID, Area, Category, EventID, Level, Message and Correlation. `sharepoint.uls.*` repeats them one to one; `@timestamp` is the ULS timestamp at its native 10 ms resolution, with the farm in UTC. The `nasq` row that opens a request has an empty Correlation column, as in Microsoft's Tx sample.

ECS enrichment: `user.name`, `url.*`, `http.request.method` and `sharepoint.site.url` are parsed from the `agb9s`, `xmnv Name=` and `xmnv Site=` rows and copied to every row of the same correlation ID, as a SIEM pipeline would join them; they are not ULS columns. `sharepoint.workflow.*` holds the IDs from the workflow rows.

## Limitations

- The rows of one request are about 1.4 s apart in the median (90% within 5.4 s, 99% within 16 s; wider at night) instead of the milliseconds a farm writes; `Execution Time` in `b4ly` still states a request duration of the usual tens to hundreds of milliseconds. Rows of different requests do not interleave.
- Line shapes come from published examples, not from a format specification: Microsoft's Tx sample `ULS.log` (SharePoint 2013 preview), a SharePoint Server 2019 request trace in Microsoft Q&A, and the workflow timer-job article (SharePoint Server 2013-2016). The `b4ly` text for the timer job follows the 2019 request form; Microsoft publishes no 2019 timer-job example.
- Only a filtered subset of tags is emitted. A farm at these trace levels writes many more rows per request (claims, SQL, cache and page rendering); `b6p4` needs the `Database` category at VerboseEx, which Microsoft warns affects farm performance.
- Rows are written unpadded, as in Microsoft's Tx sample; column padding of files written directly by the ULS service is not verified. Correlation IDs follow the shape of Microsoft's samples (a slowly advancing first group, third and fourth groups fixed per process); the exact generation algorithm is undocumented.
- `aoxsq` is written only for 302 responses, the codes shown in Microsoft's samples. Grant targets, permission levels and upload results are not visible in ULS and not modeled.
- Volumes, the hour curve, session behaviour, the flat crawl rate and the five-minute timer schedule are synthetic; there are no holidays and every week has the same shape.
- In ordinary traffic an owner never removes a grant within the hour after downloading three or more documents of the site since the grant; such a case shows as a permission-page view.
- KUMA 4.2 lists a SharePoint Server 2016 diagnostic-log normalizer; compatibility of this output with it is not established.

## References

- [Microsoft Tx: sample SharePoint ULS trace file](https://github.com/microsoft/Tx/blob/master/Traces/ULS.log)
- [Microsoft Q&A: SharePoint Server 2019 ULS request trace (build 16.0.10390.20000)](https://learn.microsoft.com/en-us/answers/questions/1026978/my-sites-do-not-open-after-standard-configuration)
- [Microsoft: SharePoint workflow timer job is stuck at "Pausing", with ULS examples](https://learn.microsoft.com/en-us/troubleshoot/sharepoint/workflows/workflow-timer-job-is-stuck-at-pausing)
- [Microsoft: configure diagnostic logging (trace log levels)](https://learn.microsoft.com/en-us/sharepoint/administration/configure-diagnostic-logging)
- [Microsoft: view SharePoint Server diagnostic logs](https://learn.microsoft.com/en-us/sharepoint/administration/view-diagnostic-logs)
- [Microsoft: ULS trace-file columns and tab delimiter (SharePoint 2010)](https://learn.microsoft.com/en-us/previous-versions/office/developer/sharepoint-2010/gg193966%28v%3Doffice.14%29)
- [KUMA 4.2 supported sources](https://support.kaspersky.ru/kuma/4.2/255782)

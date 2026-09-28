# Microsoft SharePoint Server ULS trace log

Synthetic SharePoint Server 2019 Unified Logging Service (ULS) trace rows for SIEM and detection testing: request traces from two web front ends and the legacy workflow timer job on an application server. Each row is ECS JSON that keeps the raw tab-separated ULS line in `event.original`. The pack models ULS diagnostic traces, not SharePoint audit records or Microsoft 365 activity.

## Event types

Shares are measured on a 96-hour default capture (`anomaly_mode: true`, 24-hour interval, Monday to Friday, 20,957 rows).

| ULS tag | Category (Area: SharePoint Foundation) | Level | Share | ECS category | Meaning |
| --- | --- | --- | ---: | --- | --- |
| `xmnv` | Logging Correlation Data | Medium | 30.7% | `process`, `web` | Correlation data: `Name=Request (...)`, `Name=Timer Job job-workflow`, `Site=...` |
| `nasq` | Monitoring | Medium | 18.8% | `process`, `web` | Entering monitored scope (request or timer job) |
| `b4ly` | Monitoring | Medium | 18.8% | `process`, `web` | Leaving monitored scope, with execution time, CPU ms and SQL query count |
| `avwhz` | Asp Runtime | Medium | 13.3% | `web` | SPRequestModule.BeginRequestHandler end, with the build number |
| `agb9s` | Authentication Authorization | Medium | 13.3% | `authentication` | Request identity (`IsAuthenticated`, `UserIdentityName`, claims count) |
| `af32k` | Claims Authentication | Medium | 1.4% | `authentication` | Windows sign-in challenge: 401 for an unauthenticated request |
| `b6p2` | General | Medium | 1.4% | `web` | HTTP 401 response sent |
| `aoxsq` | Runtime | Medium | 0.8% | `web` | HTTP 302 response sent (site-root and access-denied redirects) |
| `ahk8y` | Legacy Workflow Infrastructure | Verbose | 0.5% | `process` | Workflow instance begins processing |
| `b6p4` | Database | VerboseEx | 0.5% | `database` | Workflow-association SQL command |
| `tzkv` | Database | Verbose | 0.5% | `database` | Parameters of that SQL command |

A browser request writes `nasq`, `xmnv Name=Request (...)`, `avwhz`, `agb9s`, `xmnv Site=...`, an optional `aoxsq` redirect row and `b4ly`, in the order of the SharePoint Server 2019 trace published in Microsoft Q&A. The first request of about 70% of sessions is an anonymous NTLM challenge (`agb9s` with `IsAuthenticated=False`, `af32k`, `b6p2`). A timer-job run writes `nasq`, `xmnv Name=Timer Job job-workflow`, one `ahk8y`, `b6p4`, `tzkv` triple per workflow instance it processes, and `b4ly`.

Background, identical in both modes:

- 37 accounts (8 site owners, the search crawl account `svc_crawl`) open sessions at lognormal intervals thinned by a weekday business-hours curve; a session is a geometric number of requests with lognormal gaps and tends to stay on one site.
- Requests: site home pages, library views, document downloads, uploads, site-root redirects (302), and browsing of sites without access (302 to `AccessDenied.aspx`, retried up to three more times within minutes; afterwards most users go back to a site they can open).
- Site owners also open the permissions page (`user.aspx`), grant permissions from the share dialog (`POST aclinv.aspx`) and remove a grant later (`POST user.aspx`, planned for 75% of grants: 40% are quick reverts after a lognormal delay with a 15-minute median, the rest follow after a median of three hours; 45% of removals come right after the owner downloads one to six documents of that site). So grant-then-download, several downloads then a removal, and grant-then-removal within the hour all occur in background, for every owner and site they own (pooled over several captures; a single 96 h capture misses a few owner-site pairs).
- Uploads to the six sites with a legacy workflow start workflow instances; the job-workflow timer job runs on a five-minute schedule with a random start latency and processes each instance one to three times.

## Anomaly Chain

With `anomaly_mode: true` (the default), one site owner on one of their sites, in `http.request.method` and `url.path` of the `xmnv Name=Request` rows:

1. `POST <site>/_layouts/15/aclinv.aspx` - permissions granted from the share dialog (sometimes preceded by the NTLM challenge and a `GET user.aspx`);
2. four to nine `GET <site>/Shared%20Documents/<file>` - documents downloaded, sometimes after a library view;
3. `POST <site>/_layouts/15/user.aspx` - permissions removed again, which restores the site's permission state.

Linking fields: `user.name` (from the `agb9s` identity of each request) and `sharepoint.site.url` (from `xmnv Site=`), within one hour from grant to removal. Each request has its own `sharepoint.uls.correlation_id`. Every request of the chain is built by the background request builder with background delays; the owners, sites, pages and documents all appear in ordinary traffic of both modes.

Recurrence: episodes recur by event time every `anomaly_interval_hours` (default 24, minimum 6). The first start is drawn within the first `min(interval, 24 h)` of generation; each later start is drawn in a window of width `w = min(interval / 4, 6 h)` centred on the previous actual start plus the interval, so the random offset from the due time is up to `w / 2` either way. Both draws are weighted by the square of the background weekday business-hours curve plus a small floor, so episodes sit mostly in office hours, more tightly than background sessions do. At intervals of 8 hours or less the starts necessarily cover the whole clock, nights included; at 12 hours every second start falls in the evening or night. Missed episodes are not replayed, and background traffic is not paused or shifted around an episode. The owner differs from the previous episode's owner and the site from the previous episode's site; the owner is drawn uniformly among site owners and the site uniformly among their sites, as background grants are spread.

Measured (96-hour Monday-Friday captures): default 4 episodes, first grant 15.1 h after the start (15:07), grants 22.20-25.35 h apart, all between 13:57 and 16:29, grant-to-removal spans 7-20 min; 12-hour interval 8 episodes, grants 10.63-12.83 h apart, alternating 09:36-11:04 and 21:52-22:58, spans 5-33 min. Owner and site rotated every time in both.

Detection idea: per account and site, a share-dialog grant, three or more document downloads and a permission removal within one hour - an owner widening access, taking documents and reverting the change. ULS carries no permission delta: which principal was granted or removed is only in the SharePoint audit log, so this is a hunting lead, not proof. Background never contains the full ordered chain: a planned background removal is decided when it is due, after every earlier request has been built, and when it would complete the chain within the same one-hour window (compared at the 10 ms ULS resolution) the owner opens the permissions page (`GET user.aspx`) at that moment instead; times, account and site stay as they were, in both modes. Every shorter shape still occurs in background: across five 96-hour background captures, per capture 5-10 grant-then-removal pairs within the hour (with up to two downloads in between), 9-12 grants followed by three or more downloads within the hour, and 3-8 removals preceded by three or more downloads within the hour. Just outside the window the full shape does occur (grant to removal of 60-70 min: 0, 70-80 min: 1, 80-90 min: 1 across the five captures) and the counts on either side of the hour change smoothly.

With `anomaly_mode: false`, the output is background only.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Purpose |
| --- | --- | --- |
| `anomaly_mode` | `true` | Include the anomaly chain; `false` produces background only |
| `anomaly_interval_hours` | `24` | Hours from one episode start to the next due time (6 to 8760) |
| `web_app_url` | `https://portal.contoso.test` | Web application URL (scheme and host) in request names and ECS `url.*` |
| `wfe_hosts` | `[sp-wfe-01, sp-wfe-02]` | The two web front ends that run `w3wp.exe` |
| `app_host` | `sp-app-01` | Application server that runs `OWSTIMER.EXE` |

Sites, owners, accounts and document names are in `samples/`.

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

From the content-packs repository:

```bash
eventum generate --path generators/application-sharepoint-server-uls/generator.yml --id sharepoint-uls --live-mode true
```

For a finite batch, add `start` and `end` to the `cron` input (for example `start: "2026-09-21T00:00:00Z"`, `end: "2026-09-25T00:00:00Z"`) and run:

```bash
eventum generate --path generators/application-sharepoint-server-uls/generator.yml --id sharepoint-uls --live-mode false
```

The file output is overwritten when a run starts.

## Sample output

The grant request of the first episode, `xmnv Name=Request` row, from the default 96-hour capture:

```json
{"@timestamp": "2026-09-21T15:07:50.300Z", "ecs": {"version": "8.17.0"}, "event": {"action": "correlation-data", "category": ["web"], "code": "xmnv", "dataset": "sharepoint.uls", "kind": "event", "module": "sharepoint", "original": "09/21/2026 15:07:50.30\tw3wp.exe (0x40B4)\t0x52EC\tSharePoint Foundation\tLogging Correlation Data\txmnv\tMedium\tName=Request (POST:https://portal.contoso.test:443/sites/sales/_layouts/15/aclinv.aspx)\t8fa1f421-f79a-ceed-f2ad-cb626390d8b7", "type": ["info"]}, "host": {"name": "sp-wfe-01"}, "http": {"request": {"method": "POST"}}, "log": {"level": "medium"}, "message": "Name=Request (POST:https://portal.contoso.test:443/sites/sales/_layouts/15/aclinv.aspx)", "process": {"name": "w3wp.exe", "pid": 16564, "thread": {"id": 21228}}, "related": {"hosts": ["sp-wfe-01"], "user": ["o.lebedeva"]}, "service": {"name": "SharePoint Server", "version": "16.0.10390.20000"}, "sharepoint": {"site": {"url": "/sites/sales"}, "uls": {"area": "SharePoint Foundation", "category": "Logging Correlation Data", "correlation_id": "8fa1f421-f79a-ceed-f2ad-cb626390d8b7", "event_id": "xmnv", "level": "Medium", "message": "Name=Request (POST:https://portal.contoso.test:443/sites/sales/_layouts/15/aclinv.aspx)", "process": "w3wp.exe (0x40B4)", "thread_id": "0x52EC", "timestamp_local": "09/21/2026 15:07:50.30"}}, "url": {"domain": "portal.contoso.test", "original": "https://portal.contoso.test:443/sites/sales/_layouts/15/aclinv.aspx", "path": "/sites/sales/_layouts/15/aclinv.aspx", "port": 443, "scheme": "https"}, "user": {"domain": "contoso", "name": "o.lebedeva"}}
```

## Format and coverage

`event.original` holds all nine ULS columns separated by tabs: Timestamp (`MM/dd/yyyy HH:mm:ss.ff`), Process (`name (0xPID)`), TID, Area, Category, EventID, Level, Message and Correlation. `sharepoint.uls.*` repeats them one to one; `@timestamp` is the ULS timestamp at its native 10 ms resolution, with the farm in UTC. The `nasq` row that opens a request has an empty Correlation column, as in Microsoft's Tx sample.

ECS enrichment: `user.name`, `url.*`, `http.request.method` and `sharepoint.site.url` are parsed from the `agb9s`, `xmnv Name=` and `xmnv Site=` rows and copied to every row of the same correlation ID, as a SIEM pipeline would join them; they are not ULS columns. `sharepoint.workflow.*` holds the IDs from the workflow rows.

## Limitations

- Line shapes come from published examples, not from a format specification: Microsoft's Tx sample `ULS.log` (SharePoint 2013 preview), a SharePoint Server 2019 request trace in Microsoft Q&A, and the workflow timer-job article (SharePoint Server 2013-2016). The `b4ly` text for the timer job follows the 2019 request form; Microsoft publishes no 2019 timer-job example.
- Only a filtered subset of tags is emitted. A farm at these trace levels writes many more rows per request (claims, SQL, cache and page rendering); `b6p4` needs the `Database` category at VerboseEx, which Microsoft warns affects farm performance.
- Rows are written unpadded, as in Microsoft's Tx sample; column padding of files written directly by the ULS service is not verified. Correlation IDs follow the shape of Microsoft's samples (a slowly advancing first group, third and fourth groups fixed per process); the exact generation algorithm is undocumented.
- `aoxsq` is written only for 302 responses, the codes shown in Microsoft's samples. Grant targets, permission levels and upload results are not visible in ULS and not modeled.
- Volumes, cadences, session behaviour and the five-minute timer schedule are synthetic.
- The removal guard sees every request that starts before the removal; a download by the same owner on the same site that is queued less than a millisecond before the removal but lands before it could escape it. No such case occurred in the verified captures.
- KUMA 4.2 lists a SharePoint Server 2016 diagnostic-log normalizer; this pack has not been tested against it.

## References

- [Microsoft Tx: sample SharePoint ULS trace file](https://github.com/microsoft/Tx/blob/master/Traces/ULS.log)
- [Microsoft Q&A: SharePoint Server 2019 ULS request trace (build 16.0.10390.20000)](https://learn.microsoft.com/en-us/answers/questions/1026978/my-sites-do-not-open-after-standard-configuration)
- [Microsoft: SharePoint workflow timer job is stuck at "Pausing", with ULS examples](https://learn.microsoft.com/en-us/troubleshoot/sharepoint/workflows/workflow-timer-job-is-stuck-at-pausing)
- [Microsoft: configure diagnostic logging (trace log levels)](https://learn.microsoft.com/en-us/sharepoint/administration/configure-diagnostic-logging)
- [Microsoft: view SharePoint Server diagnostic logs](https://learn.microsoft.com/en-us/sharepoint/administration/view-diagnostic-logs)
- [Microsoft: ULS trace-file columns and tab delimiter (SharePoint 2010)](https://learn.microsoft.com/en-us/previous-versions/office/developer/sharepoint-2010/gg193966%28v%3Doffice.14%29)
- [KUMA 4.2 supported sources](https://support.kaspersky.ru/kuma/4.2/255782)

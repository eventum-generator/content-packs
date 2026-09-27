# Microsoft SharePoint Server ULS trace log

Synthetic SharePoint Server 2019 Unified Logging Service (ULS) trace rows for SIEM and detection testing: request traces from two web front ends and the legacy workflow timer job on an application server. Each row is ECS JSON that keeps the raw tab-separated ULS line in `event.original`. The pack models ULS diagnostic traces, not SharePoint audit records or Microsoft 365 activity.

## Event types

Shares are measured on a 96-hour default capture (`anomaly_mode: true`, 24-hour interval, Monday to Friday, 20,966 rows).

| ULS tag | Category (Area: SharePoint Foundation) | Level | Share | ECS category | Meaning |
| --- | --- | --- | ---: | --- | --- |
| `xmnv` | Logging Correlation Data | Medium | 30.8% | `process`, `web` | Correlation data: `Name=Request (...)`, `Name=Timer Job job-workflow`, `Site=...` |
| `nasq` | Monitoring | Medium | 18.8% | `process`, `web` | Entering monitored scope (request or timer job) |
| `b4ly` | Monitoring | Medium | 18.8% | `process`, `web` | Leaving monitored scope, with execution time, CPU ms and SQL query count |
| `avwhz` | Asp Runtime | Medium | 13.3% | `web` | SPRequestModule.BeginRequestHandler end, with the build number |
| `agb9s` | Authentication Authorization | Medium | 13.3% | `authentication` | Request identity (`IsAuthenticated`, `UserIdentityName`, claims count) |
| `af32k` | Claims Authentication | Medium | 1.2% | `authentication` | Windows sign-in challenge: 401 for an unauthenticated request |
| `b6p2` | General | Medium | 1.2% | `web` | HTTP 401 response sent |
| `aoxsq` | Runtime | Medium | 1.1% | `web` | HTTP 302 response sent (site-root and access-denied redirects) |
| `ahk8y` | Legacy Workflow Infrastructure | Verbose | 0.5% | `process` | Workflow instance begins processing |
| `b6p4` | Database | VerboseEx | 0.5% | `database` | Workflow-association SQL command |
| `tzkv` | Database | Verbose | 0.5% | `database` | Parameters of that SQL command |

A browser request writes `nasq`, `xmnv Name=Request (...)`, `avwhz`, `agb9s`, `xmnv Site=...`, an optional `aoxsq` redirect row and `b4ly`, in the order of the SharePoint Server 2019 trace published in Microsoft Q&A. The first request of about 70% of sessions is an anonymous NTLM challenge (`agb9s` with `IsAuthenticated=False`, `af32k`, `b6p2`). A timer-job run writes `nasq`, `xmnv Name=Timer Job job-workflow`, one `ahk8y`, `b6p4`, `tzkv` triple per workflow instance it processes, and `b4ly`.

Background, identical in both modes:

- 37 accounts (8 site owners, the search crawl account `svc_crawl`) open sessions at lognormal intervals thinned by a weekday business-hours curve; a session is a geometric number of requests with lognormal gaps and tends to stay on one site.
- Requests: site home pages, library views, document downloads, uploads, site-root redirects (302), and browsing of sites without access (302 to `AccessDenied.aspx`, retried up to three more times within minutes).
- Site owners also open the permissions page (`user.aspx`), grant permissions from the share dialog (`POST aclinv.aspx`) and remove a grant later (`POST user.aspx`, planned for 75% of grants: 40% are quick reverts after a lognormal delay with a 15-minute median, the rest follow after a median of three hours; 45% of removals come right after the owner downloads one to six documents of that site). So grant-then-download, several downloads then a removal, and grant-then-removal within the hour all occur in background.
- Uploads to the six sites with a legacy workflow start workflow instances; the job-workflow timer job runs on a five-minute schedule with a random start latency and processes each instance one to three times.

## Anomaly Chain

With `anomaly_mode: true` (the default), one site owner on one of their sites, in `http.request.method` and `url.path` of the `xmnv Name=Request` rows:

1. `POST <site>/_layouts/15/aclinv.aspx` - permissions granted from the share dialog (sometimes preceded by the NTLM challenge and a `GET user.aspx`);
2. four to nine `GET <site>/Shared%20Documents/<file>` - documents downloaded, sometimes after a library view;
3. `POST <site>/_layouts/15/user.aspx` - permissions removed again, which restores the site's permission state.

Linking fields: `user.name` (from the `agb9s` identity of each request) and `sharepoint.site.url` (from `xmnv Site=`), within one hour from grant to removal. Each request has its own `sharepoint.uls.correlation_id`. Every request of the chain is built by the background request builder with background delays; the owners, sites, pages and documents all appear in ordinary traffic of both modes.

Recurrence: the first episode is due one hour after the start of generation; each episode starts after a random delay of up to `min(1 h, interval / 8)` past its due time, and the start is then thinned by the same weekday business-hours curve as background sessions, so a due time at night usually waits for the morning. The next episode is due `anomaly_interval_hours` (default 24, minimum 6) after the actual start; missed episodes are not replayed. The owner differs from the previous episode's owner and the site from the previous episode's site.

Measured: default capture 4 episodes in 96 h, chain starts 24.44-24.93 h apart, grant-to-removal spans 16-23 min, owner and site rotated each time; 12-hour interval capture 6 episodes in 96 h, chain starts 12.19-26.08 h apart, grant-to-removal spans 11-26 min, owner and site rotated each time. Gaps well above the interval come from due times at night that waited for the morning.

Detection idea: per account and site, a share-dialog grant, three or more document downloads and a permission removal within one hour - an owner widening access, taking documents and reverting the change. ULS carries no permission delta: which principal was granted or removed is only in the SharePoint audit log, so this is a hunting lead, not proof. Background never contains the full ordered chain: when a planned background removal would complete it, the owner opens the permissions page (`GET user.aspx`) instead. Every shorter shape still occurs in background: across five 96-hour background captures, per capture 5-14 grant-then-removal pairs within the hour (with up to two downloads in between), 4-11 grants followed by three or more downloads within the hour, and 3-10 removals preceded by three or more downloads within the hour.

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

For a finite batch, add `start` and `end` to the `cron` input and run with `--live-mode false`. The file output is overwritten when a run starts.

## Sample output

The grant request of the first episode, `xmnv Name=Request` row, from the default 96-hour capture:

```json
{"@timestamp": "2026-09-21T08:50:23.880Z", "ecs": {"version": "8.17.0"}, "event": {"action": "correlation-data", "category": ["web"], "code": "xmnv", "dataset": "sharepoint.uls", "kind": "event", "module": "sharepoint", "original": "09/21/2026 08:50:23.88\tw3wp.exe (0x7F1C)\t0x1AE8\tSharePoint Foundation\tLogging Correlation Data\txmnv\tMedium\tName=Request (POST:https://portal.contoso.test:443/sites/hr/_layouts/15/aclinv.aspx)\tda1c0771-4409-3b8d-774b-6a417e11d05d", "type": ["info"]}, "host": {"name": "sp-wfe-01"}, "http": {"request": {"method": "POST"}}, "log": {"level": "medium"}, "message": "Name=Request (POST:https://portal.contoso.test:443/sites/hr/_layouts/15/aclinv.aspx)", "process": {"name": "w3wp.exe", "pid": 32540, "thread": {"id": 6888}}, "related": {"hosts": ["sp-wfe-01"], "user": ["n.sokolova"]}, "service": {"name": "SharePoint Server", "version": "16.0.10390.20000"}, "sharepoint": {"site": {"url": "/sites/hr"}, "uls": {"area": "SharePoint Foundation", "category": "Logging Correlation Data", "correlation_id": "da1c0771-4409-3b8d-774b-6a417e11d05d", "event_id": "xmnv", "level": "Medium", "message": "Name=Request (POST:https://portal.contoso.test:443/sites/hr/_layouts/15/aclinv.aspx)", "process": "w3wp.exe (0x7F1C)", "thread_id": "0x1AE8", "timestamp_local": "09/21/2026 08:50:23.88"}}, "url": {"domain": "portal.contoso.test", "original": "https://portal.contoso.test:443/sites/hr/_layouts/15/aclinv.aspx", "path": "/sites/hr/_layouts/15/aclinv.aspx", "port": 443, "scheme": "https"}, "user": {"domain": "contoso", "name": "n.sokolova"}}
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
- KUMA 4.2 lists a SharePoint Server 2016 diagnostic-log normalizer; this pack has not been tested against it.

## References

- [Microsoft Tx: sample SharePoint ULS trace file](https://github.com/microsoft/Tx/blob/master/Traces/ULS.log)
- [Microsoft Q&A: SharePoint Server 2019 ULS request trace (build 16.0.10390.20000)](https://learn.microsoft.com/en-us/answers/questions/1026978/my-sites-do-not-open-after-standard-configuration)
- [Microsoft: SharePoint workflow timer job is stuck at "Pausing", with ULS examples](https://learn.microsoft.com/en-us/troubleshoot/sharepoint/workflows/workflow-timer-job-is-stuck-at-pausing)
- [Microsoft: configure diagnostic logging (trace log levels)](https://learn.microsoft.com/en-us/sharepoint/administration/configure-diagnostic-logging)
- [Microsoft: view SharePoint Server diagnostic logs](https://learn.microsoft.com/en-us/sharepoint/administration/view-diagnostic-logs)
- [Microsoft: ULS trace-file columns and tab delimiter (SharePoint 2010)](https://learn.microsoft.com/en-us/previous-versions/office/developer/sharepoint-2010/gg193966%28v%3Doffice.14%29)
- [KUMA 4.2 supported sources](https://support.kaspersky.ru/kuma/4.2/255782)

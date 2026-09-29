# Netskope CASB via Cloud Exchange Syslog (CEF)

Netskope tenant events as delivered to a SIEM by the Netskope Cloud Exchange Log Shipper with the Syslog plugin (v4.1.x) in CEF format and its default mapping. Two event types are modeled: application events (user activity in sanctioned cloud apps, steered through the Netskope Client) and admin audit events (admin console logins and inline policy deletions). Each event is one syslog line, kept byte for byte in `event.original`, with the parsed values in ECS and `netskope.*` fields.

Sixty staff work in daily sessions from an office or home egress address, using a few cloud-storage, collaboration and CRM apps each. Six of them are tenant admins who also open the admin console now and then; three of those own the inline policies and delete one on most console visits.

## Event Types

Measured on the default configuration over 96 h with `anomaly_mode: true` (18,738 events).

| CEF class ID | `act` / `auditLogEvent` | Share | ECS category |
| --- | --- | --- | --- |
| `application` | `View` | 44.38% | `file` |
| `application` | `Download` | 18.32% | `file` |
| `application` | `Login Successful` | 13.97% | `authentication` |
| `application` | `Upload` | 8.98% | `file` |
| `application` | `Edit` | 4.11% | `file` |
| `application` | `Join` | 2.91% | `session` |
| `application` | `Logout` | 1.57% | `authentication` |
| `application` | `Share` | 1.26% | `file` |
| `application` | `View All` | 1.22% | `file` |
| `application` | `Move` | 0.99% | `file` |
| `application` | `Rename` | 0.74% | `file` |
| `audit` | `Login Successful` | 0.62% | `authentication` |
| `application` | `Copy` | 0.57% | `file` |
| `audit` | `Deleted Inline Policy` | 0.37% | `configuration` |

## Volume and Daily Curve

About 4,700 events per day (day-to-day variation about 3%), following the working day in UTC:

| UTC hours | Events per hour |
| --- | --- |
| 10:00-15:00 | 475 |
| 09:00-10:00, 15:00-16:00 | 405 |
| 08:00-09:00, 16:00-17:00 | 305 |
| 07:00-08:00, 17:00-18:00 | 151 |
| 06:00-07:00, 18:00-19:00 | 63 |
| 19:00-23:00 | 24 |
| 23:00-06:00 | 54 |

Most staff start between 07:00 and 09:30 UTC (some until 11:00, a few from 06:00) and work 6.5-10.5 h; about one in five adds a short evening session from home. Six staff form an overnight team working from about 22:00 to 07:00 UTC, so the night carries a small, steady volume from a handful of users. Each user produces about 9 events per hour at work. The number of users seen per hour follows the same curve: about 50 at midday, 6 overnight, 4-5 in the evening.

## Anomaly Chain

A tenant admin removes an inline policy and then pulls a batch of files out of cloud storage.

1. `audit` / `auditLogEvent=Login Successful` - the admin (`suser`) signs in to the admin console (sometimes twice within minutes).
2. `audit` / `auditLogEvent=Deleted Inline Policy` - a few minutes later the admin deletes an inline policy; sometimes a second deletion follows within a minute or two.
3. `application` / `act=Download` with `appcategory=Cloud Storage` - a few minutes after the last deletion (median 4 min, at most 15 min) the same `suser` downloads three files from one of their usual cloud-storage apps within seconds to minutes, from their current `src` address, in one `appSessionId`.

- **Linking fields:** `suser` across the audit and application events; `requestClientApplication`, `src` and `appSessionId` tie the downloads together.
- **Actors:** one of the three inline-policy owners, never the same one twice in a row, chosen by how often they use the console; usually one who is at work in the office at that moment. The app, session ID and URLs are new each time. The episode is an extra console visit: the admin's ordinary app activity goes on around it as usual.
- **Recurrence:** every `anomaly_interval_hours` (default 24, minimum 6) of event time. The first episode starts within the first 24 h (or the first interval, if shorter), at an hour drawn from the daily curve. Each later one starts one interval after the previous start, give or take half of `min(interval / 4, 6 h)`, with busy hours far more likely than quiet ones. Missed episodes are not replayed. At the default interval episodes start 21-27 h apart; at 8 h, 7-9 h apart.
- **Background:** every step occurs on its own in both modes, by the same admins, apps and addresses: console logins (sometimes twice within minutes), single and double policy deletions (the three policy owners 2-7 a day each), deletions followed a few minutes later by a check of one or two files (viewed or downloaded) in a storage app, and bursts of many downloads by one user from one app within minutes. Only the complete ordered chain is absent from background: an admin who deleted a policy within the last 30 min makes at most two cloud-storage downloads in that window; an ordinary download burst that would make a third ends at the second (about 1.5 times a day across the tenant).
- **Detection idea:** per `suser`, an audit `Deleted Inline Policy` followed within 30 min by three or more `act=Download` application events in a `Cloud Storage` app.

The default audit mapping carries no policy name or before/after state, so the chain is a temporal correlation on the actor, not proof that the deleted policy was the one blocking those downloads. The source does not log the policy being restored in any documented default event, so no restoring step is emitted.

`anomaly_mode` defaults to `true`. With `false`, the generator emits background only, with no complete chain.

## Parameters

### Event Parameters

| Parameter | Default | Description |
| --- | --- | --- |
| `anomaly_mode` | `true` | Add anomaly chain episodes; `false` emits background only |
| `anomaly_interval_hours` | `24` | Episode interval in hours of event time (6 to 8760) |
| `tenant_name` | `Example Tenant` | CEF Device Product (the plugin's `$tenant_name`) |
| `log_source_identifier` | `netskopece` | Syslog hostname field (the plugin's Log Source Identifier) |
| `email_domain` | `example.com` | Domain of user e-mail addresses in `suser` |

### Samples

| File | Contents |
| --- | --- |
| `samples/users.csv` | One row per user: user name (before `@email_domain`), role (`user`, `admin`, or `policy_admin` for the inline-policy owners; at least two), office and home egress addresses, device, OS, browser, apps synced by a native client, apps with personal weights, usual start hour (UTC), share of sessions from home, activity weight (0.5-2.0), and for admins the share of tasks that are console visits |
| `samples/apps.csv` | Sanctioned apps: name, category, CCI, CCL, URL host and front-end addresses |

Edit these files to change the staff, their addresses or the app catalog. The event volume and its daily curve are set in `patterns/*.yml` (one file per band of the table above); scale the `ratio` values together with the number of users to keep about 9 events per user per working hour. Episode start hours follow the shipped working-day curve even if the pattern files are reshaped.

### Output Parameters

The pack writes to `output/events.json` and uses no `${params.*}` or `${secrets.*}` placeholders. To send events elsewhere, replace the `output` block with another output plugin and put its endpoint and credentials into `${params.*}` / `${secrets.*}` placeholders, for example `host: ${params.opensearch_host}` and `password: ${secrets.opensearch_password}`.

## Usage

Live mode, from the content-packs repository root:

```bash
eventum generate --path generators/cloud-netskope-casb/generator.yml --id netskope --live-mode true
```

Batch mode: in every `patterns/*.yml` file set `oscillator.start` to a UTC midnight and `oscillator.end` to the end of the window (for example `start: "2026-09-01T00:00:00Z"` and `end: "2026-09-05T00:00:00Z"`), then run:

```bash
eventum generate --path generators/cloud-netskope-casb/generator.yml --id netskope --live-mode false --keep-order true
```

For background only, set `event.template.params.anomaly_mode` to `false` in `generator.yml`.

Performance: about 1,900 events/s in batch mode (14 days of default data in 34 s).

## Format Notes and Limitations

- Line layout follows the plugin source (`syslog_cef_generator.py`): `<14>` priority (user.info from the syslog handler), `%b %d %H:%M:%S` time, the Log Source Identifier, then `CEF:0|Netskope|<tenant>|NULL|<class>|NULL|<severity>|` and the extensions as `key=value` pairs sorted by the `key=value` string and joined by spaces. Values carry no `=`, so no escaping is needed.
- Application events carry the 14 keys of Netskope's published application example (`act`, `appcategory`, `applicationType=nspolicy`, `browser`, `cci`, `ccl`, `device`, `dst`, `os`, `requestClientApplication`, `sourceServiceName`, `src`, `suser`, `timestamp`) plus `url` and `appSessionId` from the default mapping. Severity is `Unknown` (the mapping's default). The published example also contains an unlabelled text fragment after `browser=unknown`; it has no key and is not reproduced. Mapping keys that are only filled for other traffic (`IncidentID`, `ja3`, `ja3s`, justification fields) are not emitted.
- Audit events carry the four keys of Netskope's published audit example (`auditLogEvent`, `auditType=admin_audit_logs`, `suser`, `timestamp`). Severity comes from the tenant's severity level through the plugin's audit severity map: `High` for `Deleted Inline Policy` as in the published example, `Medium` for `Login Successful` (level 2 in Elastic's Netskope fixtures). The default mapping's `supportingData` is not emitted, following Netskope's statement that Supporting Data and Details are not part of the default output.
- Only two audit event names are published with raw examples (`Deleted Inline Policy`, `Login Successful`); other admin actions (policy creation or edits, applied changes) are not modeled, so console visits show only logins and deletions, and the three policy owners delete more policies (2-7 a day each) than a typical tenant sees. Application activities come from Netskope's activity vocabulary (REST field descriptions and the Box activity list); the per-app activity mix, CCI/CCL values, URLs and addresses are synthetic.
- The syslog header time is when Cloud Exchange sends the record (local time of the Cloud Exchange host, assumed UTC), a random delay after the event (median about 50 s, 2 s to about 17 min); `timestamp` and `@timestamp` are the event time, in whole seconds. Cloud Exchange sends batches, so real header times are less regular than here.
- Repeated actions of one user in one app come a median 27 s apart at midday and about a minute apart overnight; in real logs such bursts are often only milliseconds to seconds apart.
- `appSessionId` stays the same for a user and app until 15 min of inactivity, as documented for `app_session_id`; `device`, `os` and `browser` are fixed per user (`Native` for some users' sync clients).
- The daily curve is the same every day; there is no weekly cycle (weekends look like weekdays).
- With `anomaly_mode: true` each episode adds its own records, so counts of the chain parts (console logins, policy deletions, storage downloads right after a deletion) are about one per episode higher than with `false`.
- Compatibility with a particular SIEM parser has not been tested; the ECS mapping is enrichment in the style of a CEF ingest pipeline, not a vendor-published mapping. Elastic's Netskope integration collects through a different channel (API / Cloud Exchange JSON), so its sample is not a wire-format reference here.

## Sample Output

The first download of an episode with the default configuration:

```json
{"@timestamp": "2026-09-01T14:38:10Z", "destination": {"ip": "192.0.2.20"}, "ecs": {"version": "8.17.0"}, "event": {"action": "Download", "category": ["file"], "kind": "event", "original": "\u003c14\u003eSep 01 14:39:36 netskopece CEF:0|Netskope|Example Tenant|NULL|application|NULL|Unknown|act=Download appSessionId=4396508595117720143 appcategory=Cloud Storage applicationType=nspolicy browser=Safari cci=92 ccl=excellent device=Mac Device dst=192.0.2.20 os=Sonoma requestClientApplication=Google Drive sourceServiceName=Google Drive src=198.51.100.11 suser=julia.moore@example.com timestamp=1788273490 url=drive.google.com/file/d/u197a6fe47153cd09d12e751f083", "type": ["access"]}, "log": {"syslog": {"hostname": "netskopece", "priority": 14}}, "netskope": {"activity": "Download", "app": "Google Drive", "app_session_id": "4396508595117720143", "appcategory": "Cloud Storage", "browser": "Safari", "cci": "92", "ccl": "excellent", "device": "Mac Device", "os": "Sonoma", "site": "Google Drive", "type": "nspolicy"}, "related": {"ip": ["198.51.100.11", "192.0.2.20"], "user": ["julia.moore@example.com"]}, "source": {"ip": "198.51.100.11"}, "url": {"original": "drive.google.com/file/d/u197a6fe47153cd09d12e751f083"}, "user": {"email": "julia.moore@example.com"}}
```

## References

- [Netskope Syslog plugin for Log Shipper (application CEF example)](https://docs.netskope.com/en/syslog-plugin-for-log-shipper)
- [Netskope Cloud Exchange KB articles (audit CEF example, default audit mapping)](https://docs.netskope.com/en/cloud-exchange-kb-articles)
- [Netskope Log Shipper Syslog mapping](https://docs.netskope.com/en/log-shipper-syslog-mapping/)
- [Netskope REST API events and alerts response descriptions](https://docs.netskope.com/en/rest-api-events-and-alerts-response-descriptions/)
- [Netskope activities (Box activity list)](https://docs.netskope.com/en/activity/)
- [Netskope Cloud Exchange Syslog plugin source and default mappings](https://github.com/netskopeoss/ta_cloud_exchange_plugins/tree/main/syslog)
- [Elastic Netskope integration](https://github.com/elastic/integrations/tree/main/packages/netskope)

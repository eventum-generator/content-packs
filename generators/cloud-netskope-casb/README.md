# Netskope CASB via Cloud Exchange Syslog (CEF)

Netskope tenant events as delivered to a SIEM by the Netskope Cloud Exchange Log Shipper with the Syslog plugin (v4.1.x) in CEF format and its default mapping. Two event types are modeled: application events (user activity in sanctioned cloud apps, steered through the Netskope Client) and admin audit events (admin console logins and inline policy deletions). Each event is one syslog line, kept byte for byte in `event.original`, with the parsed values in ECS and `netskope.*` fields.

Staff work in randomly phased sessions from an office or home egress address, using a few cloud-storage, collaboration and CRM apps each. Tenant admins are ordinary staff who also open the admin console now and then and sometimes delete inline policies.

## Event Types

Measured on the default configuration, 120 h, `anomaly_mode: true` (12,336 events).

| CEF class ID | `act` / `auditLogEvent` | Share | ECS category |
| --- | --- | --- | --- |
| `application` | `View` | 42.50% | `file` |
| `application` | `Download` | 19.07% | `file` |
| `application` | `Login Successful` | 15.53% | `authentication` |
| `application` | `Upload` | 8.43% | `file` |
| `application` | `Edit` | 4.46% | `file` |
| `application` | `Join` | 2.88% | `session` |
| `application` | `Logout` | 1.15% | `authentication` |
| `application` | `Move` | 1.13% | `file` |
| `application` | `Share` | 1.12% | `file` |
| `application` | `View All` | 0.97% | `file` |
| `audit` | `Login Successful` | 0.91% | `authentication` |
| `application` | `Rename` | 0.76% | `file` |
| `audit` | `Deleted Inline Policy` | 0.57% | `configuration` |
| `application` | `Copy` | 0.53% | `file` |

## Anomaly Chain

A tenant admin removes an inline policy and then pulls a batch of files out of cloud storage.

1. `audit` / `auditLogEvent=Deleted Inline Policy` - the admin (`suser`) deletes an inline policy in the admin console, usually a few minutes after `auditLogEvent=Login Successful`; sometimes a second deletion follows within a minute or two.
2. `application` / `act=Download` with `appcategory=Cloud Storage` - a few minutes later (delay median 4 min, redrawn while above 15 min) the same `suser` downloads at least three files from one of their usual cloud-storage apps within seconds to minutes, from their usual `src` address for that session, in one `appSessionId`.

- **Linking fields:** `suser` across the audit and application events; `requestClientApplication`, `src` and `appSessionId` tie the downloads together.
- **How an episode is made:** admins delete inline policies in both modes, and in background about half of them check the change afterwards by viewing or downloading one or two files in a storage app after the same delay law. An episode takes over the next background deletion instead of adding a console visit: the admin's audit records keep their times, and the follow-up becomes a burst of downloads whose size is drawn from the background download-count law, conditioned on at least three.
- **Recurrence:** every `anomaly_interval_hours` (default 24, minimum 6) of source time. The first episode is due 1 h after generation starts, plus a random delay of up to `min(1 h, interval / 8)`; each later one is due one interval after the previous episode's deletion plus a new delay of the same kind. From the due time, the next deletion by an eligible admin becomes the episode. If none comes within `min(interval / 4, 6 h)`, an eligible admin on duty (weighted by how often they use the console) makes an ordinary console visit with a deletion at a random time inside that window, so an episode starts at most about that long after it is due (later only when no eligible admin is on duty at all). Missed episodes are not replayed. Measured spacing in 120 h captures: 24.5-26.4 h at the default 24 h interval (24.5-28.3 h in a later review run) (5 episodes; the first 6.3 h after start, inside its 6 h window), 8.5-10.8 h at 8 h (13 episodes).
- **Variation:** the deletion must belong to an admin other than the previous episode's, so admins take episodes in proportion to how often they delete policies. The app, source address, session ID, number of files and URLs are new each time.
- **Background:** every step occurs on its own in both modes: admin console logins (sometimes twice within minutes), single and double policy deletions, deletions followed by one or two storage downloads or views within minutes, and bursts of many downloads by one user from one app within minutes. Every user pairs with the same source addresses and apps in background as in episodes. Only the complete ordered chain is absent from background: an admin who deleted a policy within the last 30 min makes at most two cloud-storage downloads in that window. The post-deletion check is one or two files, so this rarely matters; when an ordinary download burst would still make a third, the burst ends at the second download and the admin's next activity follows the usual gap law.
- **Detection idea:** per `suser`, an audit `Deleted Inline Policy` followed within 30 min by three or more `act=Download` application events in a `Cloud Storage` app.

The default audit mapping carries no policy name or before/after state, so the chain is a temporal correlation on the actor, not proof that the deleted policy was the one blocking those downloads. The source does not log the policy being restored in any documented default event, so no restoring step is emitted.

`anomaly_mode` defaults to `true`. With `false`, the generator emits background only, with no complete chain.

## Parameters

### Event Parameters

| Parameter | Default | Description |
| --- | --- | --- |
| `anomaly_mode` | `true` | Add anomaly chain episodes; `false` emits background only |
| `anomaly_interval_hours` | `24` | Episode interval in hours of source time (6 to 8760) |
| `tenant_name` | `Example Tenant` | CEF Device Product (the plugin's `$tenant_name`) |
| `log_source_identifier` | `netskopece` | Syslog hostname field (the plugin's Log Source Identifier) |
| `email_domain` | `example.com` | Domain of user e-mail addresses in `suser` |
| `user_count` | `60` | Number of users (10 to 500) |
| `admin_count` | `6` | Number of users who are also tenant admins (2 to 20) |

Apps, office and home egress addresses and app front-end addresses are built in (documentation ranges).

### Output Parameters

The pack writes to `output/events.json` and uses no `${params.*}` or `${secrets.*}` placeholders. To send events elsewhere, replace the `output` block with another output plugin and put its endpoint and credentials into `${params.*}` / `${secrets.*}` placeholders, for example `host: ${params.opensearch_host}` and `password: ${secrets.opensearch_password}`.

## Usage

Live mode, from the content-packs repository root:

```bash
eventum generate --path generators/cloud-netskope-casb/generator.yml --id netskope --live-mode true
```

Batch mode: add `start` and `end` to the `cron` input, then run:

```bash
eventum generate --path generators/cloud-netskope-casb/generator.yml --id netskope --live-mode false --keep-order true
```

For background only, set `event.template.params.anomaly_mode` to `false` in `generator.yml`.

## Format Notes and Limitations

- Line layout follows the plugin source (`syslog_cef_generator.py`): `<14>` priority (user.info from the syslog handler), `%b %d %H:%M:%S` time, the Log Source Identifier, then `CEF:0|Netskope|<tenant>|NULL|<class>|NULL|<severity>|` and the extensions as `key=value` pairs sorted by the `key=value` string and joined by spaces. Values carry no `=`, so no escaping is needed.
- Application events carry the 14 keys of Netskope's published application example (`act`, `appcategory`, `applicationType=nspolicy`, `browser`, `cci`, `ccl`, `device`, `dst`, `os`, `requestClientApplication`, `sourceServiceName`, `src`, `suser`, `timestamp`) plus `url` and `appSessionId` from the default mapping. Severity is `Unknown` (the mapping's default). The published example also contains an unlabelled text fragment after `browser=unknown`; it has no key and is not reproduced. Mapping keys that are only filled for other traffic (`IncidentID`, `ja3`, `ja3s`, justification fields) are not emitted.
- Audit events carry the four keys of Netskope's published audit example (`auditLogEvent`, `auditType=admin_audit_logs`, `suser`, `timestamp`). Severity comes from the tenant's severity level through the plugin's audit severity map: `High` for `Deleted Inline Policy` as in the published example, `Medium` for `Login Successful` (level 2 in Elastic's Netskope fixtures). The default mapping's `supportingData` is not emitted, following Netskope's statement that Supporting Data and Details are not part of the default output.
- Only two audit event names are published with raw examples (`Deleted Inline Policy`, `Login Successful`); other admin actions (policy creation or edits, applied changes) are not modeled. Application activities come from Netskope's activity vocabulary (REST field descriptions and the Box activity list); the per-app activity mix, CCI/CCL values, URLs and addresses are synthetic.
- The syslog header time is when Cloud Exchange sends the record (local time of the Cloud Exchange host, assumed UTC), a random delay after the event (median 51 s, 4 s to about 19 min in the default capture); `timestamp` and `@timestamp` are the event time, in whole seconds. Cloud Exchange sends batches, so real header times are less regular than here.
- `appSessionId` stays the same for a user and app until 15 min of inactivity, as documented for `app_session_id`; `device`, `os` and `browser` are fixed per user (`Native` for some users' sync clients).
- There is no working-hours or weekday cycle; sessions are randomly phased per user. Assumed admin workload: each admin opens the console about every 2 h while on shift and deletes a policy on about half of the visits (35-98 deletions per 120 h across the six admins in the measured off captures, more than a typical tenant sees); this rate is chosen so that most episodes start from a natural deletion soon after their due time.
- Compatibility with a particular SIEM parser has not been tested; the ECS mapping is enrichment in the style of a CEF ingest pipeline, not a vendor-published mapping. Elastic's Netskope integration collects through a different channel (API / Cloud Exchange JSON), so its sample is not a wire-format reference here.

## Sample Output

This line was copied unchanged from the final default-configuration anomaly-mode capture (the first download of an episode):

```json
{"@timestamp": "2026-09-01T06:42:23Z", "destination": {"ip": "192.0.2.20"}, "ecs": {"version": "8.17.0"}, "event": {"action": "Download", "category": ["file"], "kind": "event", "original": "\u003c14\u003eSep 01 06:44:05 netskopece CEF:0|Netskope|Example Tenant|NULL|application|NULL|Unknown|act=Download appSessionId=4954799521857995773 appcategory=Cloud Storage applicationType=nspolicy browser=Chrome cci=92 ccl=excellent device=Windows Device dst=192.0.2.20 os=Windows 10 requestClientApplication=Google Drive sourceServiceName=Google Drive src=198.51.100.11 suser=tom.moore@example.com timestamp=1788244943 url=drive.google.com/file/d/l03b912bd9d25a7e3123797395a2", "type": ["access"]}, "log": {"syslog": {"hostname": "netskopece", "priority": 14}}, "netskope": {"activity": "Download", "app": "Google Drive", "app_session_id": "4954799521857995773", "appcategory": "Cloud Storage", "browser": "Chrome", "cci": "92", "ccl": "excellent", "device": "Windows Device", "os": "Windows 10", "site": "Google Drive", "type": "nspolicy"}, "related": {"ip": ["198.51.100.11", "192.0.2.20"], "user": ["tom.moore@example.com"]}, "source": {"ip": "198.51.100.11"}, "url": {"original": "drive.google.com/file/d/l03b912bd9d25a7e3123797395a2"}, "user": {"email": "tom.moore@example.com"}}
```

## References

- [Netskope Syslog plugin for Log Shipper (application CEF example)](https://docs.netskope.com/en/syslog-plugin-for-log-shipper)
- [Netskope Cloud Exchange KB articles (audit CEF example, default audit mapping)](https://docs.netskope.com/en/cloud-exchange-kb-articles)
- [Netskope Log Shipper Syslog mapping](https://docs.netskope.com/en/log-shipper-syslog-mapping/)
- [Netskope REST API events and alerts response descriptions](https://docs.netskope.com/en/rest-api-events-and-alerts-response-descriptions/)
- [Netskope activities (Box activity list)](https://docs.netskope.com/en/activity/)
- [Netskope Cloud Exchange Syslog plugin source and default mappings](https://github.com/netskopeoss/ta_cloud_exchange_plugins/tree/main/syslog)
- [Elastic Netskope integration](https://github.com/elastic/integrations/tree/main/packages/netskope)

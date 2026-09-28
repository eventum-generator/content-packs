# Cisco ISE 3.4 Administrative Audit Syslog

Generates Cisco ISE `CISE_Administrative_and_Operational_Audit` remote syslog and matching ECS-style JSON for one Policy Administration Node (PAN), for teams building detections on ISE administrator activity. This is the administrator-audit stream, not RADIUS or TACACS AAA traffic. The complete emitted syslog record is in `event.original`.

The modeled deployment has five GUI administrators, each with an own workstation address and a shared jump host, a failed-login lockout threshold of five and four editable logging categories (`Passed Authentications`, `Failed Attempts`, `RADIUS Accounting`, `System Statistics`) plus two editable remote targets (`RemoteCollector`, `BackupCollector`). All start enabled. The records are received by a separate, always-enabled `AuditCollector` target assigned to Administrative and Operational Audit (LOCAL6/NOTICE, 1,024-byte limit, `Comply to RFC 3164` unchecked so delimiters stay escaped as in the raw fixtures). Disabling `RemoteCollector` or `BackupCollector` therefore does not cut off this stream. This is not an ISE localStore export.

## Event Types

| Code | Action | Share | Category |
| --- | --- | ---: | --- |
| 51001 | Administrator login succeeded | 26.4% | `iam`, `authentication` |
| 51002 | Administrator logged off | 26.3% | `iam`, `authentication` |
| 52001 | Configuration changed: logging category (`UPSCategory`) - severity change, disable, enable | 25.3% | `iam`, `configuration` |
| 52001 | Configuration changed: remote target (`UPSLogTarget`) - status `ENABLED`/`DISABLED` | 9.8% | `iam`, `configuration` |
| 51000 | Administrator login failed | 12.2% | - |

Shares are measured over the final default five-day capture (868 records). They are scenario rates, not measured Cisco rates.

Each administrator works independently. Session starts follow a random process on an office-hour curve (UTC, lower at night and at weekends) with per-administrator rates. A session may begin with one to four mistyped passwords a few seconds apart, and after failures the administrator sometimes gives up without logging in. Consecutive failures stay below the lockout threshold. A logged-in session lasts a log-normally distributed time and holds configuration edits at random moments before the logout. Routine sessions make zero to three edits: a category severity change, a category disable (local logging off, targets cleared), re-enabling a disabled category, or switching a remote target's status. About 30% of sessions are logging maintenance: the administrator disables a category and/or a target and often re-enables them before logging out. Disabled objects are re-enabled by later ordinary edits after a random delay. Each session uses the administrator's workstation or the jump host.

Message number and payload sequence advance together by one plus a random count of other audit records of the node, keeping the constant per-node offset seen in the raw fixtures. `ConfigVersionId` advances with every edit and with occasional other deployment changes. `AdminSession=AdminGUI_Session` is the captured literal, not a unique session ID.

## Anomaly Chain

Scenario: an administrator account is taken over by password guessing and used to switch off log forwarding.

Sequence, one administrator and source address (`user.name` + `client.ip`), within 30 minutes:

1. Three `51000` failed logins, seconds apart.
2. `51001` successful login.
3. `52001` `UPSCategory` edit with `Local Logging = disable` and cleared targets for one of `Passed Authentications`, `Failed Attempts`, `RADIUS Accounting`.
4. `52001` `UPSLogTarget` edit `Old status = ENABLED New status = DISABLED` for `RemoteCollector` or `BackupCollector`.
5. `51002` logout.

Linking fields: `user.name`, `client.ip` (`AdminName`, `AdminIPAddress`), the native sequence order and time. The session boundaries are the matching login and logout of the same administrator and address.

Recurrence: the first episode starts within the first `min(anomaly_interval_hours, 24 h)` of the run, at an hour drawn from the office-hour curve. Each later one is due `anomaly_interval_hours` after the actual start of the previous one and starts in a window centred on the due time (width `min(interval / 4, 6 h)`), weighted towards busy hours, plus a random delay (exponential, mean 3 minutes). If no administrator is offline for the whole episode, or no chain category or target is enabled, the start moves a random 5-60 minutes later. There is no catch-up. At intervals of 8 hours or less, episodes necessarily fall at all hours of the day, including the night. The minimum supported interval is 2 hours; lower values are clamped.

Variation: the administrator rotates between episodes (never the previous one), weighted like background activity, among administrators who are offline for the whole episode; the address is the workstation or the jump host with the same odds as in background. The disabled category and target rotate as well. Gaps between steps are random. The disabled objects are restored later by ordinary administrators through visible enable edits.

Detection idea: repeated failed GUI logins followed by a successful login and, in the same session, disabling a logging category and a remote log target.

Every code, administrator, administrator/address pair, object and disable/enable action of the chain also occurs in background: repeated failures of one account within minutes, failure runs of three or four, give-ups, logins after failures and sessions that disable categories and targets. Background sessions that would complete the whole ordered chain within 30 minutes skip their final target disable, so only the complete chain is absent from background.

`anomaly_mode: true` (default) adds the episodes on top of an unchanged background. `anomaly_mode: false` emits the realistic background only, with no complete chain.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Meaning |
| --- | --- | --- |
| `ise_name` | `ise-01.corp.example` | PAN hostname in the syslog header |
| `admins` | `[iseops, admin, netadmin, secops, helpdesk-l2]` | GUI administrator accounts |
| `admin_ips` | `[10.40.1.20, 10.40.1.21, 10.40.1.22, 10.40.1.23, 10.40.1.24]` | Workstation address of each administrator |
| `admin_weights` | `[32, 26, 20, 13, 9]` | Relative session rate of each administrator |
| `jump_host_ip` | `10.99.2.41` | Shared jump host, used for about 22% of sessions |
| `remote_collector_ip` | `10.40.0.20` | Address of `RemoteCollector` |
| `backup_collector_ip` | `10.40.0.21` | Address of `BackupCollector` |
| `anomaly_interval_hours` | `24` | Episode interval, at least 2 hours |
| `anomaly_mode` | `true` | Add anomaly episodes; `false` emits background only |

`admins`, `admin_ips` and `admin_weights` must have the same length (at least two administrators, so the episode actor can rotate). Use ASCII names without commas, backslashes or line breaks.

### Output Parameters

The shipped configuration writes `output/events.json` and needs no `${params.*}` or `${secrets.*}` values. To deliver events elsewhere, replace the `output` section, for example with `${params.*}` placeholders for a host and port passed at run time.

## Usage

Live:

```bash
eventum generate --path generators/identity-cisco-ise/generator.yml --id identity-cisco-ise --live-mode true
```

Batch sample: add `start: "2026-09-28T00:00:00Z"` and `end: "2026-10-03T04:00:00Z"` under `input[0].cron`, then run:

```bash
eventum generate --path generators/identity-cisco-ise/generator.yml --id identity-cisco-ise --live-mode false --keep-order true
```

The input ticks once per second and most ticks are dropped; the template emits a record only when one is due.

## Sample Output

The `RemoteCollector` disable of the first episode (line 42) of the final default capture, as written by the JSON formatter:

```json
{"@timestamp": "2026-09-28T08:47:56.218+00:00", "cisco_ise": {"log": {"admin": {"interface": "GUI"}, "category": {"name": "CISE_Administrative_and_Operational_Audit"}, "config_change": {"data": "Object modified:\\,Port = 514\\,IP Address = 10.40.0.20\\,Facility Code = LOCAL6\\,Length = 1024\\,Description = Remote UDP Collector\\,Include Alarms = FALSE\\,Old status = ENABLED New status = DISABLED\\,"}, "config_version": {"id": 1699}, "failure": {"flag": false}, "message": {"code": "52001", "description": "Configuration-Changes: Changed configuration", "id": "0000255796"}, "object": {"name": "RemoteCollector", "type": "UPSLogTarget"}, "operation_message": {"text": "LoggingTargets \"RemoteCollector\" has been edited successfully."}, "request_response": {"type": "initial"}, "segment": {"number": 0, "total": 1}}}, "client": {"ip": "10.99.2.41", "user": {"name": "secops"}}, "ecs": {"version": "8.17.0"}, "event": {"action": "configuration-changes", "category": ["iam", "configuration"], "code": "52001", "dataset": "cisco_ise.log", "kind": "event", "original": "\u003c181\u003eSep 28 08:47:56 ise-01.corp.example CISE_Administrative_and_Operational_Audit 0000255796 1 0 2026-09-28 08:47:56.218 +00:00 0000255857 52001 NOTICE Configuration-Changes: Changed configuration, ConfigVersionId=1699, FailureFlag=false, RequestResponseType=initial, AdminInterface=GUI, AdminIPAddress=10.99.2.41, AdminName=secops, ConfigChangeData=Object modified:\\,Port = 514\\,IP Address = 10.40.0.20\\,Facility Code = LOCAL6\\,Length = 1024\\,Description = Remote UDP Collector\\,Include Alarms = FALSE\\,Old status = ENABLED New status = DISABLED\\,, ObjectType=UPSLogTarget, ObjectName=RemoteCollector, OperationMessageText=LoggingTargets \"RemoteCollector\" has been edited successfully.,", "sequence": 255857, "timezone": "+00:00", "type": ["change", "info"]}, "host": {"hostname": "ise-01.corp.example"}, "log": {"level": "notice", "syslog": {"priority": 181, "severity": {"name": "notice"}}}, "message": "2026-09-28 08:47:56.218 +00:00 0000255857 52001 NOTICE Configuration-Changes: Changed configuration, ConfigVersionId=1699, FailureFlag=false, RequestResponseType=initial, AdminInterface=GUI, AdminIPAddress=10.99.2.41, AdminName=secops, ConfigChangeData=Object modified:\\,Port = 514\\,IP Address = 10.40.0.20\\,Facility Code = LOCAL6\\,Length = 1024\\,Description = Remote UDP Collector\\,Include Alarms = FALSE\\,Old status = ENABLED New status = DISABLED\\,, ObjectType=UPSLogTarget, ObjectName=RemoteCollector, OperationMessageText=LoggingTargets \"RemoteCollector\" has been edited successfully.,", "observer": {"name": "ise-01.corp.example", "product": "Identity Services Engine", "vendor": "Cisco", "version": "3.4"}, "related": {"hosts": ["ise-01.corp.example"], "ip": ["10.99.2.41"], "user": ["secops"]}, "user": {"name": "secops"}}
```

## Limitations

- No complete ISE 3.4 appliance capture of these records was obtained. Login/logout/failure and `UPSCategory` shapes follow the Elastic raw fixtures (appliance versions unspecified); the `UPSLogTarget` status payload follows Cisco's ISE 3.1 Common Criteria guidance. The inverse `DISABLED -> ENABLED` target form and severity values other than those in the fixtures are extrapolated from the same grammar.
- Only the four codes above are emitted; other administrative codes (51020/51021, 52000/52002, CLI/SSH, system management) and RADIUS/TACACS categories are out of scope.
- `observer.version` is profile context, not read from the wire. Rates, the office-hour curve, the administrator pool and the initial enabled state are scenario assumptions. The time zone is UTC.
- Concurrent sessions of one administrator are not modeled, and an episode is placed only when its administrator is offline for its duration.
- A finite capture can end inside an open session; no closing record is fabricated.

## References

- [Cisco ISE syslog catalog](https://www.cisco.com/c/en/us/td/docs/security/ise/syslog/Cisco_ISE_Syslogs/m_SyslogsList.html) - remote envelope, category, codes 51000/51001/51002/52001, NOTICE severity.
- [Cisco ISE 3.4 Basic Setup](https://www.cisco.com/c/en/us/td/docs/security/ise/3-4/admin_guide/b_ise_admin_3_4/b_ISE_admin_basic_setup.html) - administrator lockout and session controls; [Installation guide](https://www.cisco.com/c/en/us/td/docs/security/ise/3-4/install_guide/b_ise_installationGuide34/b_ise_InstallationGuide_chapter_5.html) - lockout after five incorrect admin passwords; [Maintain and Monitor](https://www.cisco.com/c/en/us/td/docs/security/ise/3-4/admin_guide/b_ise_admin_3_4/b_ISE_admin_maintain_monitor.html) - logging categories and remote targets.
- [Cisco ISE 3.1 Common Criteria operational guidance](https://www.niap-ccevs.org/MMO/Product/st_vid11407-agd1.pdf), pp. 124-125 - `UPSCategory` and `UPSLogTarget` 52001 payloads.
- Elastic Cisco ISE integration, pinned at `78fd455d22cdb74bd2a8e53249c25cc060f06010`: [raw administrative fixtures](https://github.com/elastic/integrations/blob/78fd455d22cdb74bd2a8e53249c25cc060f06010/packages/cisco_ise/data_stream/log/_dev/test/pipeline/test-pipeline-administrative-and-operational-audit.log) and [ingest pipeline](https://github.com/elastic/integrations/blob/78fd455d22cdb74bd2a8e53249c25cc060f06010/packages/cisco_ise/data_stream/log/elasticsearch/ingest_pipeline/pipeline_administrative_and_operational_audit.yml).

# Cisco ISE 3.4 Administrative Audit Syslog

Generates Cisco ISE `CISE_Administrative_and_Operational_Audit` remote syslog and matching ECS-style JSON for one Policy Administration Node (PAN), for teams building detections on ISE administrator activity. This is the administrator-audit stream, not RADIUS or TACACS AAA traffic. The complete emitted syslog record is in `event.original`.

The modeled deployment has five full-access GUI administrators, each with an own workstation address and a shared jump host, and 120 read-only operator accounts (network operations and help desk, `samples/operators.csv`) who look up endpoints and live logs but change no configuration. The failed-login lockout threshold is five. Four logging categories (`Passed Authentications`, `Failed Attempts`, `RADIUS Accounting`, `System Statistics`) and two remote targets (`RemoteCollector`, `BackupCollector`) are editable by the administrators; all start enabled. The records are received by a separate, always-enabled `AuditCollector` target assigned to Administrative and Operational Audit (LOCAL6/NOTICE, 1,024-byte limit, `Comply to RFC 3164` unchecked so delimiters stay escaped as in the raw fixtures). Disabling `RemoteCollector` or `BackupCollector` therefore does not cut off this stream. This is not an ISE localStore export.

## Event Types

| Code | Action | Share | Category |
| --- | --- | ---: | --- |
| 51001 | Administrator login succeeded | 48.4% | `iam`, `authentication` |
| 51002 | Administrator logged off | 48.4% | `iam`, `authentication` |
| 51000 | Administrator login failed | 2.2% | - |
| 52001 | Configuration changed: logging category (`UPSCategory`) - severity change, disable, enable | 0.85% | `iam`, `configuration` |
| 52001 | Configuration changed: remote target (`UPSLogTarget`) - status `ENABLED`/`DISABLED` | 0.06% | `iam`, `configuration` |

Shares are typical of 30 days of default output (about 79,000 records). They are scenario rates, not measured Cisco rates.

## Volume and Timing

The node writes about 2,640 records per day on a fixed daily curve (UTC): 30 per hour round the clock (night shift), 60 per hour at 06-07 and 18-21, 120 per hour at 07-08 and 17-18, and 210 per hour at 08-17. Weekdays and weekends look the same.

Sessions of different accounts interleave; each account has at most one session at a time. The five administrators open about 4% of sessions (about 47 logins per day together, weighted `admin_weights`); operators share the rest with random weights between 0.7 and 1.3. Operators sign in from their workstation or, in 10% of sessions, from the jump host; administrators use the jump host for 15% of ordinary sessions and 80% of logging-maintenance sessions.

A session may begin with one to four mistyped passwords; one failure is more common than two, two than three. Administrators mistype the local ISE password more often on the shared jump host (8.5% of sessions start with failures) than on their own workstation (2.8%); operators 3%. After failures the account sometimes gives up without logging in. Consecutive failures stay below the lockout threshold. Failed logins are about 4% of all login attempts (administrators about 7%, operators about 4%). A logged-in session lasts a log-normally distributed time (median about 15 minutes for administrators, 7 minutes for operators).

Ordinary administrator sessions hold zero to three logging-category edits at random moments before the logout (a severity change, a disable with targets cleared, or re-enabling a disabled category). About 6% of administrator sessions are logging maintenance: the administrator disables a category (85%), in a quarter of them then detaches a remote target, and re-enables each object before logging out in 60% of cases. Remote targets change only in these sessions, about five target disables per week. Objects left disabled are re-enabled by later ordinary edits: a disabled remote target usually within minutes to an hour during working hours (median about 4 minutes), a category within hours.

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

Recurrence: the first episode starts within the first `min(anomaly_interval_hours, 24 h)` of the run, at an hour drawn from the hourly volume curve (squared, plus a small floor, so starts favour busy hours). Each later one is due `anomaly_interval_hours` after the actual start of the previous one and starts in a window centred on the due time (width `min(interval / 4, 6 h)`) with the same weighting, plus a random delay (exponential, mean 3 minutes). If no eligible administrator is idle, or no chain category or target is enabled, the start moves a random 5-60 minutes later, as often as needed; this occasionally stretches a gap by several hours. There is no catch-up. At intervals of 8 hours or less, episodes necessarily fall at all hours of the day, including the night. The minimum supported interval is 2 hours; lower values are clamped.

Episode records interleave with ordinary traffic. The episode is the administrator's only session while it lasts; the volume and hour curve of the node and the activity of the other accounts are the same as without episodes.

Variation: the administrator rotates between episodes (never the previous one), weighted like background activity; the address is the jump host (80%) or the administrator's workstation, with the same odds as a logging-maintenance session. The disabled category rotates as well; with the two default remote targets, the disabled target alternates between them. Gaps between steps are random; if every candidate category or target is already disabled when the episode reaches that step, the administrator waits until an ordinary administrator restores one, within the 30 minutes. Before logging out, the administrator re-enables each disabled object with the same odds as in a maintenance session; objects left disabled are restored by later ordinary edits on the same schedule as in background.

Detection idea: repeated failed GUI logins followed by a successful login and, in the same session, disabling a logging category and a remote log target.

Every code, administrator, administrator/address pair, object and disable/enable action of the chain also occurs in background: repeated failures of one account within minutes, failure runs of three or four, give-ups, logins after failures, and maintenance sessions that disable a category and then a remote target. Only the complete ordered chain within 30 minutes is absent from background: where an administrator's session would complete it, that administrator makes another routine edit at that moment instead of the target disable.

`anomaly_mode: true` (default) adds the episodes on top of the background. `anomaly_mode: false` emits the realistic background only, with no complete chain.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Meaning |
| --- | --- | --- |
| `ise_name` | `ise-01.corp.example` | PAN hostname in the syslog header |
| `admins` | `[iseops, admin, netadmin, secops, helpdesk-l2]` | Full-access GUI administrator accounts (chain actors) |
| `admin_ips` | `[10.40.1.20, 10.40.1.21, 10.40.1.22, 10.40.1.23, 10.40.1.24]` | Workstation address of each administrator |
| `admin_weights` | `[32, 26, 20, 13, 9]` | Relative session rate of each administrator |
| `jump_host_ip` | `10.99.2.41` | Shared jump host (administrators: 15% of ordinary and 80% of maintenance sessions; operators: 10%) |
| `remote_collector_ip` | `10.40.0.20` | Address of `RemoteCollector` |
| `backup_collector_ip` | `10.40.0.21` | Address of `BackupCollector` |
| `anomaly_interval_hours` | `168` | Episode interval (weekly), at least 2 hours |
| `anomaly_mode` | `true` | Add anomaly episodes; `false` emits background only |

`admins`, `admin_ips` and `admin_weights` must have the same length (at least two administrators, so the episode actor can rotate). Use ASCII names without commas, backslashes or line breaks, distinct from the operator names in `samples/operators.csv` (columns `name`, `ip`), which can be edited the same way.

### Output Parameters

The shipped configuration writes `output/events.json` and needs no `${params.*}` or `${secrets.*}` values. To deliver events elsewhere, replace the `output` section, for example with `${params.*}` placeholders for a host and port passed at run time.

## Usage

Live:

```bash
eventum generate --path generators/identity-cisco-ise/generator.yml --id identity-cisco-ise --live-mode true
```

The volume and hour curve are set by `ratio` (records per day) and `low`/`high` (fractions of the day) in the four files under `patterns/`.

Batch: the pattern files start on 2026-01-01 and never end. For a finite sample, set `start` to a midnight (UTC) and `end` under `oscillator` in all four files under `patterns/`, for example `start: "2026-09-01T00:00:00Z"` and `end: "2026-09-07T00:00:00Z"`, then run:

```bash
eventum generate --path generators/identity-cisco-ise/generator.yml --id identity-cisco-ise --live-mode false --keep-order true
```

A finite run can end inside an open session; no closing record is fabricated.

Performance: a 14-day default batch (36,936 records) takes about 15 s of CPU time on one core, about 2,400 records per second.

## Sample Output

The `RemoteCollector` disable of the first episode (line 1412) of 30 days of default output, as written by the JSON formatter:

```json
{"@timestamp": "2026-09-01T12:55:38.182+00:00", "cisco_ise": {"log": {"admin": {"interface": "GUI"}, "category": {"name": "CISE_Administrative_and_Operational_Audit"}, "config_change": {"data": "Object modified:\\,Port = 514\\,IP Address = 10.40.0.20\\,Facility Code = LOCAL6\\,Length = 1024\\,Description = Remote UDP Collector\\,Include Alarms = FALSE\\,Old status = ENABLED New status = DISABLED\\,"}, "config_version": {"id": 1277}, "failure": {"flag": false}, "message": {"code": "52001", "description": "Configuration-Changes: Changed configuration", "id": "0000185982"}, "object": {"name": "RemoteCollector", "type": "UPSLogTarget"}, "operation_message": {"text": "LoggingTargets \"RemoteCollector\" has been edited successfully."}, "request_response": {"type": "initial"}, "segment": {"number": 0, "total": 1}}}, "client": {"ip": "10.99.2.41", "user": {"name": "secops"}}, "ecs": {"version": "8.17.0"}, "event": {"action": "configuration-changes", "category": ["iam", "configuration"], "code": "52001", "dataset": "cisco_ise.log", "kind": "event", "original": "\u003c181\u003eSep  1 12:55:38 ise-01.corp.example CISE_Administrative_and_Operational_Audit 0000185982 1 0 2026-09-01 12:55:38.182 +00:00 0000186009 52001 NOTICE Configuration-Changes: Changed configuration, ConfigVersionId=1277, FailureFlag=false, RequestResponseType=initial, AdminInterface=GUI, AdminIPAddress=10.99.2.41, AdminName=secops, ConfigChangeData=Object modified:\\,Port = 514\\,IP Address = 10.40.0.20\\,Facility Code = LOCAL6\\,Length = 1024\\,Description = Remote UDP Collector\\,Include Alarms = FALSE\\,Old status = ENABLED New status = DISABLED\\,, ObjectType=UPSLogTarget, ObjectName=RemoteCollector, OperationMessageText=LoggingTargets \"RemoteCollector\" has been edited successfully.,", "sequence": 186009, "timezone": "+00:00", "type": ["change", "info"]}, "host": {"hostname": "ise-01.corp.example"}, "log": {"level": "notice", "syslog": {"priority": 181, "severity": {"name": "notice"}}}, "message": "2026-09-01 12:55:38.182 +00:00 0000186009 52001 NOTICE Configuration-Changes: Changed configuration, ConfigVersionId=1277, FailureFlag=false, RequestResponseType=initial, AdminInterface=GUI, AdminIPAddress=10.99.2.41, AdminName=secops, ConfigChangeData=Object modified:\\,Port = 514\\,IP Address = 10.40.0.20\\,Facility Code = LOCAL6\\,Length = 1024\\,Description = Remote UDP Collector\\,Include Alarms = FALSE\\,Old status = ENABLED New status = DISABLED\\,, ObjectType=UPSLogTarget, ObjectName=RemoteCollector, OperationMessageText=LoggingTargets \"RemoteCollector\" has been edited successfully.,", "observer": {"name": "ise-01.corp.example", "product": "Identity Services Engine", "vendor": "Cisco", "version": "3.4"}, "related": {"hosts": ["ise-01.corp.example"], "ip": ["10.99.2.41"], "user": ["secops"]}, "user": {"name": "secops"}}
```

## Limitations

- No complete ISE 3.4 appliance capture of these records was obtained. Login/logout/failure and `UPSCategory` shapes follow the Elastic raw fixtures (appliance versions unspecified); the `UPSLogTarget` status payload follows Cisco's ISE 3.1 Common Criteria guidance. The inverse `DISABLED -> ENABLED` target form and severity values other than those in the fixtures are extrapolated from the same grammar.
- Only the four codes above are emitted; other administrative codes (51020/51021, 52000/52002, CLI/SSH, system management) and RADIUS/TACACS categories are out of scope. All modeled configuration edits are logging settings, so their rate stands in for the administrators' configuration work as a whole.
- `observer.version` is profile context, not read from the wire. Rates, the hour curve, the account pools and the initial enabled state are scenario assumptions. The time zone is UTC, and weekdays and weekends are not distinguished.
- Retries after a failed login are a median of about 32 seconds apart (10-90%: 9-190 s), longer at night.
- With `anomaly_mode: true` each episode adds its own records, so counts of the chain parts (repeated failures of one administrator, failures followed by a login and a category or target disable) are about one per episode higher than with `anomaly_mode: false`; at short `anomaly_interval_hours` the excess grows accordingly.
- Concurrent sessions of one account are not modeled.
- All configuration edits are logging settings, so logging categories change more often than on a typical production node (about seven category disables per day, most reversed the same day); remote-target changes are rare (about five disables per week).

## References

- [Cisco ISE syslog catalog](https://www.cisco.com/c/en/us/td/docs/security/ise/syslog/Cisco_ISE_Syslogs/m_SyslogsList.html) - remote envelope, category, codes 51000/51001/51002/52001, NOTICE severity.
- [Cisco ISE 3.4 Basic Setup](https://www.cisco.com/c/en/us/td/docs/security/ise/3-4/admin_guide/b_ise_admin_3_4/b_ISE_admin_basic_setup.html) - administrator lockout and session controls; [Installation guide](https://www.cisco.com/c/en/us/td/docs/security/ise/3-4/install_guide/b_ise_installationGuide34/b_ise_InstallationGuide_chapter_5.html) - lockout after five incorrect admin passwords; [Maintain and Monitor](https://www.cisco.com/c/en/us/td/docs/security/ise/3-4/admin_guide/b_ise_admin_3_4/b_ISE_admin_maintain_monitor.html) - logging categories and remote targets.
- [Cisco ISE 3.1 Common Criteria operational guidance](https://www.niap-ccevs.org/MMO/Product/st_vid11407-agd1.pdf), pp. 124-125 - `UPSCategory` and `UPSLogTarget` 52001 payloads.
- Elastic Cisco ISE integration, pinned at `78fd455d22cdb74bd2a8e53249c25cc060f06010`: [raw administrative fixtures](https://github.com/elastic/integrations/blob/78fd455d22cdb74bd2a8e53249c25cc060f06010/packages/cisco_ise/data_stream/log/_dev/test/pipeline/test-pipeline-administrative-and-operational-audit.log) and [ingest pipeline](https://github.com/elastic/integrations/blob/78fd455d22cdb74bd2a8e53249c25cc060f06010/packages/cisco_ise/data_stream/log/elasticsearch/ingest_pipeline/pipeline_administrative_and_operational_audit.yml).

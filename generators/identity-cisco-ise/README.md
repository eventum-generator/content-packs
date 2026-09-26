# Cisco ISE 3.4 Administrative Audit Syslog

Generates Cisco ISE `CISE_Administrative_and_Operational_Audit` remote syslog and matching ECS-style JSON for one Policy Administration Node. This is the existing administrator-audit stream, not RADIUS or TACACS AAA traffic. The complete emitted syslog record is in `event.original`.

The selected pre-existing configuration has two privileged GUI administrators, a failed-login lockout threshold of five, and a 60-minute GUI idle timeout. `Passed Authentications` local logging is initially enabled as a deliberate profile setting, although Cisco disables it by default. `System Statistics`, `RemoteCollector` and `BackupCollector` also exist before capture. The modeled receiver is a separate always-enabled `AuditCollector`, assigned to Administrative and Operational Audit, with LOCAL6/NOTICE and a 1,024-byte limit. It stores received remote records in a local capture file. `RemoteCollector` serves other, unmodeled categories, so disabling it does not cut off the audit records in this pack. The Cisco remote-target `Comply to RFC 3164` checkbox is unchecked so delimiters remain escaped as in the raw fixtures. This is not an ISE localStore export, whose native format has only the inner timestamp/sequence payload.

## Event Types

| Code | Action | Category | Background behavior |
| --- | --- | --- | --- |
| 51000 | Administrator login failed | Administrative and Operational Audit | Isolated invalid-password GUI login |
| 51001 | Administrator login succeeded | Administrative and Operational Audit | Opens a GUI session |
| 51002 | Administrator logged off | Administrative and Operational Audit | Closes the same actor/IP session |
| 52001 | Configuration changed | Administrative and Operational Audit | Toggles logging categories and remote targets |

The background is a synthetic active administration workload, approximately 46% successful logins, 46% logouts, 2% failures and 6% configuration changes in the validated multi-day captures. These are scenario weights, not measured Cisco rates. Each isolated routine failure is followed by that account's successful login. An active routine GUI session has at most two edits before logout. Both administrators can edit both category and target objects. Disables and enables of all four objects occur independently in background. No edit or logout is emitted without a matching earlier login.

One event is scheduled every five minutes. Up to 9.999 seconds of millisecond jitter varies event timing within its slot. Source timestamps are converted to UTC before both syslog timestamp fields and ECS `@timestamp` are built. Native message-ID and payload-sequence counters advance independently from different initial positions. `AdminSession=AdminGUI_Session` is the captured literal, not a unique session ID.

## Anomaly Chain

`anomaly_mode: true` is the default. Episodes recur every `anomaly_interval_hours`, 24 hours by default. One administrator/IP emits three 51000 failures, a 51001 success, a 52001 disabling local logging and clearing targets for `Passed Authentications`, a 52001 changing `RemoteCollector` from ENABLED to DISABLED, then a 51002 logout. The seven records span about 30 minutes. Three failures remain below the selected five-attempt lockout threshold. Correlate actor, source IP, PAN, message order and a roughly 35-minute window. The account, IP, codes and object names also occur in background.

Each episode has new native message/sequence numbers and advancing configuration versions. The object names persist because these are modifications of the same existing settings. The native `AdminGUI_Session` value cannot distinguish sessions, so use actor/IP, login/logout boundaries, ordered counters and time. No UUID session field is invented.

Only a closed routine session with both affected settings enabled can arm an episode. Disabled settings are restored through a visible ordinary administrator login, one or two 52001 enable changes and logout. A restoration becomes eligible about an hour after a disable in either mode, or when an enabled-mode episode is due. Eligibility is not an exact execution deadline: an existing GUI session or pending failed-login retry finishes first. No hidden state reset reenables logging. The recurrence clock resets at the actual first failed attempt. Delays extend the actual interval without catch-up bursts. The minimum supported interval is two hours; lower values are clamped to two. Changing the five-minute input cadence also changes session and episode timing.

`anomaly_mode: false` retains the same actors, isolated failures, ordinary sessions, disable/enable changes and restoration activity, with zero complete seven-record episodes. A finite capture may end in an ordinary active session; no closing record is fabricated at the boundary.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Meaning |
| --- | --- | --- |
| `ise_name` | `ise-01.corp.example` | PAN hostname in native syslog |
| `normal_admin`, `normal_admin_ip` | `iseops`, `10.40.1.20` | Routine and restoration administrator/IP |
| `anomaly_admin`, `anomaly_admin_ip` | `admin`, `10.99.2.41` | Episode administrator/IP, also used in background |
| `remote_collector_ip` | `10.40.0.20` | Address of the existing editable `RemoteCollector` |
| `backup_collector_ip` | `10.40.0.21` | Address of the existing editable `BackupCollector` |
| `anomaly_interval_hours` | `24` | Positive recurrence interval, at least two hours |
| `anomaly_mode` | `true` | Include repeated episodes; `false` emits background only |

Use distinct administrator names, valid IPv4 addresses and short ASCII hostname/user tokens without commas, backslashes or line breaks. The modeled audit receiver remains separate from the two editable target addresses. Object names, GUI access, ISE version and native message grammar are fixed by this source profile.

### Output Parameters

The shipped configuration writes `output/events.json` locally and requires no top-level `${params.*}` or `${secrets.*}` overrides. Change `output.file.path` or the output plugin to deliver events to a SIEM.

## Usage

From the content-packs repository root:

```bash
uv run --project ../eventum eventum generate --path generators/identity-cisco-ise/generator.yml --id identity-cisco-ise --live-mode true
```

For a finite sample, copy `generator.yml` next to the original, set `input[0].cron.start` to `2026-09-26T00:00:00Z` and `end` to `2026-09-29T04:20:00Z`, then run the copied path with `--live-mode false --keep-order true`. The 76h20 window covers multiple daily episodes. `--live-mode false` alone does not bound an open-ended schedule. Heavy sample runs share `flock -x /tmp/eventum-generator-heavy.lock`.

## Sample Output

A complete 52001 event copied from the final default enabled finite capture:

```json
{
  "@timestamp": "2026-09-27T00:30:02.919+00:00",
  "cisco_ise": {
    "log": {
      "admin": {
        "interface": "GUI"
      },
      "assigned_targets": [],
      "category": {
        "name": "CISE_Administrative_and_Operational_Audit"
      },
      "config_change": {
        "data": "Object modified:\\, Log Severity Level = INFO\\,Local Logging = disable\\,Assigned Targets = {}"
      },
      "config_version": {
        "id": 2761
      },
      "failure": {
        "flag": false
      },
      "local_logging": "disable",
      "message": {
        "code": "52001",
        "description": "Configuration-Changes: Changed configuration",
        "id": "0000027679"
      },
      "object": {
        "name": "Passed Authentications",
        "type": "UPSCategory"
      },
      "operation_message": {
        "text": "LoggingCategories \"Passed Authentications\" has been edited successfully."
      },
      "request_response": {
        "type": "initial"
      },
      "segment": {
        "number": 0,
        "total": 1
      }
    }
  },
  "client": {
    "ip": "10.99.2.41",
    "user": {
      "name": "admin"
    }
  },
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "configuration-changes",
    "category": [
      "iam",
      "configuration"
    ],
    "code": "52001",
    "dataset": "cisco_ise.log",
    "kind": "event",
    "original": "<181>Sep 27 00:30:02 ise-01.corp.example CISE_Administrative_and_Operational_Audit 0000027679 1 0 2026-09-27 00:30:02.919 +00:00 0000188565 52001 NOTICE Configuration-Changes: Changed configuration, ConfigVersionId=2761, FailureFlag=false, RequestResponseType=initial, AdminInterface=GUI, AdminIPAddress=10.99.2.41, AdminName=admin, ConfigChangeData=Object modified:\\, Log Severity Level = INFO\\,Local Logging = disable\\,Assigned Targets = {}, ObjectType=UPSCategory, ObjectName=Passed Authentications, OperationMessageText=LoggingCategories \"Passed Authentications\" has been edited successfully.,",
    "sequence": 188565,
    "timezone": "+00:00",
    "type": [
      "change",
      "info"
    ]
  },
  "host": {
    "hostname": "ise-01.corp.example"
  },
  "log": {
    "level": "notice",
    "syslog": {
      "priority": 181,
      "severity": {
        "name": "notice"
      }
    }
  },
  "message": "2026-09-27 00:30:02.919 +00:00 0000188565 52001 NOTICE Configuration-Changes: Changed configuration, ConfigVersionId=2761, FailureFlag=false, RequestResponseType=initial, AdminInterface=GUI, AdminIPAddress=10.99.2.41, AdminName=admin, ConfigChangeData=Object modified:\\, Log Severity Level = INFO\\,Local Logging = disable\\,Assigned Targets = {}, ObjectType=UPSCategory, ObjectName=Passed Authentications, OperationMessageText=LoggingCategories \"Passed Authentications\" has been edited successfully.,",
  "observer": {
    "name": "ise-01.corp.example",
    "product": "Identity Services Engine",
    "vendor": "Cisco",
    "version": "3.4"
  },
  "related": {
    "hosts": [
      "ise-01.corp.example"
    ],
    "ip": [
      "10.99.2.41"
    ],
    "user": [
      "admin"
    ]
  },
  "user": {
    "name": "admin"
  }
}
```

## References and Limits

- [Cisco ISE syslog catalog](https://www.cisco.com/c/en/us/td/docs/security/ise/syslog/Cisco_ISE_Syslogs/m_SyslogsList.html) documents the remote envelope, selected category, 51000/51001/51002/52001 codes and NOTICE severity.
- [Cisco ISE 3.4 Basic Setup](https://www.cisco.com/c/en/us/td/docs/security/ise/3-4/admin_guide/b_ise_admin_3_4/b_ISE_admin_basic_setup.html) documents administrator lock/suspend controls, GUI session timeout and target/category settings. [Installation guidance](https://www.cisco.com/c/en/us/td/docs/security/ise/3-4/install_guide/b_ise_installationGuide34/b_ise_InstallationGuide_chapter_5.html) describes lockout after five incorrect admin-password attempts. [Maintain and Monitor](https://www.cisco.com/c/en/us/td/docs/security/ise/3-4/admin_guide/b_ise_admin_3_4/b_ISE_admin_maintain_monitor.html) documents independent logging-category targets and default-disabled local logging for Passed Authentications.
- [Cisco-authored ISE 3.1 Common Criteria operational guidance](https://www.niap-ccevs.org/MMO/Product/st_vid11407-agd1.pdf), pp. 124-125, supplies 52001 category and target status-disable shapes. Its older examples do not prove ISE 3.4 byte-level fidelity.
- Elastic administrative fixtures pinned at `78fd455d22cdb74bd2a8e53249c25cc060f06010`: [full native raw records](https://github.com/elastic/integrations/blob/78fd455d22cdb74bd2a8e53249c25cc060f06010/packages/cisco_ise/data_stream/log/_dev/test/pipeline/test-pipeline-administrative-and-operational-audit.log) and [administrative ingest pipeline](https://github.com/elastic/integrations/blob/78fd455d22cdb74bd2a8e53249c25cc060f06010/packages/cisco_ise/data_stream/log/elasticsearch/ingest_pipeline/pipeline_administrative_and_operational_audit.yml) establish selected raw field shapes, escaping and parsed field names. Fixture appliance versions are unspecified.

No complete ISE 3.4 appliance trace of the final Passed Authentications/RemoteCollector disable and restoration sequence was obtained. Generated configuration edits use Cisco's published older object shapes with documented 3.4 controls; exact release-specific bytes and the inverse enable form remain unverified. `observer.version` is synthetic profile context, not a version extracted from the wire. Role assignment, initial enabled state, collector routing, cadence, jitter and restoration policy are explicit scenario assumptions. No collector agent or source-address metadata is fabricated. The Elastic pipeline was inspected, not executed against a live cluster. This PR remains draft without a claim of full 3.4 native raw parity.

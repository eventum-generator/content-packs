# Cisco ISE 3.4 Administrative Audit Syslog

Generates Cisco ISE `CISE_Administrative_and_Operational_Audit` remote syslog with the original wire record and ECS-style fields. This pack covers administrator activity on one ISE node, not RADIUS or TACACS authentication traffic.

## Event Types

| Code | Action | Category | Background behavior |
| --- | --- | --- | --- |
| 51000 | Administrator login failed | Administrative and Operational Audit | Occasional failed GUI login |
| 51001 | Administrator login succeeded | Administrative and Operational Audit | Opens a GUI session |
| 51002 | Administrator logged off | Administrative and Operational Audit | Closes the same administrator's session |
| 52001 | Configuration changed | Administrative and Operational Audit | Edits logging categories and remote targets |

The routine model produces about 47% successful logins, 47% logouts, 3% failed logins, and 3% configuration edits in a multi-day sample. These are generator distributions, not measured Cisco ISE rates. A session must open before its logout. Routine edits include both `Passed Authentications` and `System Statistics` (`UPSCategory`), and `RemoteCollector` and `BackupCollector` (`UPSLogTarget`). Both administrators and their IP addresses appear in the background.

One event is scheduled every five minutes using Eventum's six-field cron expression. Millisecond timing varies by up to ten seconds within each minute. The shipped file output contains a JSON document per line; `event.original` contains the native Cisco syslog record. The syslog message number and payload sequence are independent counters, as in the vendor examples.

## Anomaly Chain

After at least 100 routine events, one `admin` GUI session from `10.99.2.41` produces three 51000 failures, then a 51001 success, a 52001 edit disabling local logging and clearing assigned targets for `Passed Authentications`, a 52001 edit disabling `RemoteCollector`, and a 51002 logout. These seven events span about 30 minutes. Correlate administrator, source IP, ISE node, order, and time window. The individual message codes, account, source IP, and object names also occur in the background, so a rule should detect the sequence rather than a marker.

The audit category is assumed to use a separate target, so its later configuration-change records can still reach the SIEM after `RemoteCollector` is disabled. The chain models audit-routing changes, not an ISE authorization-policy change. `anomaly_mode: true` is the default. Set it to `false` for background only. The chain runs once per generator process.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Meaning |
| --- | --- | --- |
| `ise_name` | `ise-01.corp.example` | ISE hostname in the native syslog header |
| `normal_admin`, `normal_admin_ip` | `iseops`, `10.40.1.20` | Primary routine administrator and address |
| `anomaly_admin`, `anomaly_admin_ip` | `admin`, `10.99.2.41` | Administrator and address correlated across the chain; also used in background |
| `anomaly_after_events` | `100` | Minimum routine events before the one-time chain |
| `anomaly_mode` | `true` | Include the chain when `true`; background only when `false` |

### Output Parameters

The shipped configuration writes `output/events.json` locally and requires no top-level `${params.*}` or `${secrets.*}` overrides. Change `output.file.path` or the output plugin to deliver the events to a SIEM.

## Usage

From the content-packs repository root, generate a bounded batch or run continuously:

```bash
eventum generate --path generators/identity-cisco-ise/generator.yml --id identity-cisco-ise --live-mode false --keep-order true
eventum generate --path generators/identity-cisco-ise/generator.yml --id identity-cisco-ise --live-mode true
```

For background only, change `event.template.params.anomaly_mode` to `false` in a copy of `generator.yml`. To change the event cadence, edit `input[0].cron.expression`.

## Sample Output

Complete 52001 event copied from an enabled-mode Eventum run:

```json
{
  "@timestamp": "2026-09-26T16:35:05.757+00:00",
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
        "id": 2742
      },
      "failure": {
        "flag": false
      },
      "local_logging": "disable",
      "message": {
        "code": "52001",
        "description": "Configuration-Changes: Changed configuration",
        "id": "0000027657"
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
    "original": "<181>Sep 26 16:35:05 ise-01.corp.example CISE_Administrative_and_Operational_Audit 0000027657 1 0 2026-09-26 16:35:05.757 +00:00 0000188543 52001 NOTICE Configuration-Changes: Changed configuration, ConfigVersionId=2742, FailureFlag=false, RequestResponseType=initial, AdminInterface=GUI, AdminIPAddress=10.99.2.41, AdminName=admin, ConfigChangeData=Object modified:\\, Log Severity Level = INFO\\,Local Logging = disable\\,Assigned Targets = {}, ObjectType=UPSCategory, ObjectName=Passed Authentications, OperationMessageText=LoggingCategories \"Passed Authentications\" has been edited successfully.,",
    "sequence": 188543,
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
  "message": "2026-09-26 16:35:05.757 +00:00 0000188543 52001 NOTICE Configuration-Changes: Changed configuration, ConfigVersionId=2742, FailureFlag=false, RequestResponseType=initial, AdminInterface=GUI, AdminIPAddress=10.99.2.41, AdminName=admin, ConfigChangeData=Object modified:\\, Log Severity Level = INFO\\,Local Logging = disable\\,Assigned Targets = {}, ObjectType=UPSCategory, ObjectName=Passed Authentications, OperationMessageText=LoggingCategories \"Passed Authentications\" has been edited successfully.,",
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

- [Cisco ISE syslog catalog](https://www.cisco.com/c/en/us/td/docs/security/ise/syslog/Cisco_ISE_Syslogs/m_SyslogsList.html): native envelope, category, codes, and severity.
- [Cisco ISE 3.4 administration guide](https://www.cisco.com/c/en/us/td/docs/security/ise/3-4/admin_guide/b_ise_admin_3_4/b_ISE_admin_deployment.html): remote logging targets and logging-category controls.
- [Cisco ISE 3.1 Common Criteria operational guidance](https://www.niap-ccevs.org/MMO/Product/st_vid11407-agd1.pdf), pp. 124-125: Cisco-authored 52001 examples for category edits and `UPSLogTarget` status disable.
- [Elastic Cisco ISE raw administrative fixtures](https://github.com/elastic/integrations/blob/main/packages/cisco_ise/data_stream/log/_dev/test/pipeline/test-pipeline-administrative-and-operational-audit.log) and [administrative ingest pipeline](https://github.com/elastic/integrations/blob/main/packages/cisco_ise/data_stream/log/elasticsearch/ingest_pipeline/pipeline_administrative_and_operational_audit.yml): 51000/51001/51002 and 52001 wire shapes, escaping, and parser fields.

The profile targets ISE 3.4, but no full 3.4 appliance capture of a disabled `Passed Authentications` category or `RemoteCollector` was available. Those two records follow Cisco's published 52001 shapes and 3.4 UI controls; exact 3.4 byte-level equivalence remains unverified. The normalized JSON is provided alongside the original syslog record; an Elastic ingest pipeline was inspected for compatibility but not executed against a live cluster.

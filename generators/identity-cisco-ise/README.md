# Cisco ISE Administrative Audit Syslog

Produces ECS-compatible Cisco ISE remote syslog for Administrative and Operational Audit, including administrator login, logout and configuration changes.

Reference field coverage: **45/45 fields across selected 51000, 51001, 52001 and 52002 [Elastic Cisco ISE parsed administrative test events](https://github.com/elastic/integrations/blob/main/packages/cisco_ise/data_stream/log/_dev/test/pipeline/test-pipeline-administrative-and-operational-audit.log-expected.json). The separate RADIUS Failed Attempts category is not mixed into this administrator-audit pack.**

## Event Types

| Message code | Meaning | Routine weight |
| --- | --- | ---: |
| 51001 | Administrator authentication succeeded | 65% |
| 51002 | Administrator logged off | 20% |
| 51000 | Administrator authentication failed | 10% |
| 52001 | Configuration changed | 5% |
| 52002 | Configuration deleted | Anomaly only |

Routine percentages are configured selection weights, not measured vendor frequencies. One reusable Jinja template covers the FSM states; the source-specific native records are emitted alongside normalized ECS fields. The `event.sequence` and device counters are bounded.

## Anomaly Chain

Three 51000 failures for `admin` from `10.99.2.41` lead to a 51001 success on the same ISE node. The same name/IP then produce 52001 for logging category `Passed Authentications`, setting `Local Logging=disable` and clearing assigned targets, followed by 52002 deleting `RemoteCollector` (`UPSLogTarget`). Correlate `AdminName`, `AdminIPAddress`, host, message code and increasing sequence. Rules can detect administrator password guessing followed by success, a change to authentication logging, and removal of a remote log target. The latter two records carry explicit admin identity in the native Cisco ISE format. This is an audit-routing policy change, not a RADIUS authorization-policy change.

`anomaly_mode: true` is the default. Set `event.template.params.anomaly_mode: false` to generate routine background only. The anomaly identities and targeted objects do not appear in background mode.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Meaning |
| --- | --- | --- |
| `ise_name`, `ise_ip` | `ise-01.corp.example`, `10.40.0.11` | ISE node identity |
| `normal_admin`, `normal_admin_ip` | `iseops`, `10.40.1.20` | Routine administrator |
| `anomaly_admin`, `anomaly_admin_ip` | `admin`, `10.99.2.41` | Correlated chain identity |
| `anomaly_interval_events` | `250` | Routine events between chains; counter is bounded |
| `anomaly_mode` | `true` | Include chain; `false` emits background only |

### Output Parameters

The shipped configuration writes `output/events.json` locally and needs no `${params.*}` or `${secrets.*}` overrides. Change `output.file.path` or replace the output plugin when connecting to a SIEM.

## Usage

From the content-packs repository root:

```bash
eventum generate --path generators/identity-cisco-ise/generator.yml --id identity-cisco-ise --live-mode true
```

Adjust the cron expression and count in `generator.yml` for a different event rate.

## Sample Output

Copied from a real enabled-mode generator run:

```json
{
  "@timestamp": "2026-09-25T14:07:17+00:00",
  "agent": {
    "ephemeral_id": "15e00000-1111-4444-8888-123456789abc",
    "id": "15e00000-1111-4444-8888-123456789abc",
    "name": "syslog-collector",
    "type": "filebeat",
    "version": "8.17.0"
  },
  "cisco_ise": {
    "log": {
      "acs": {
        "instance": "ise-01.corp.example"
      },
      "admin": {
        "interface": "GUI"
      },
      "assigned_targets": [],
      "category": {
        "name": "CISE_Administrative_and_Operational_Audit"
      },
      "component": "Administration",
      "config_change": {
        "attributes": [
          {
            "name": "Local Logging",
            "value": "disable"
          },
          {
            "name": "Assigned Targets",
            "value": []
          }
        ],
        "data": "Object modified: Local Logging = disable; Assigned Targets = {}"
      },
      "config_version": {
        "id": 3177
      },
      "failure": {
        "flag": false
      },
      "local_logging": "disable",
      "message": {
        "code": "52001",
        "description": "Configuration-Changes: Changed configuration",
        "id": "0000108191"
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
  "data_stream": {
    "dataset": "cisco_ise.log",
    "namespace": "default",
    "type": "logs"
  },
  "ecs": {
    "version": "8.17.0"
  },
  "elastic_agent": {
    "id": "15e00000-1111-4444-8888-123456789abc",
    "snapshot": false,
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
    "original": "<181>Sep 25 14:07:17 ise-01.corp.example CISE_Administrative_and_Operational_Audit 0000108191 1 0 2026-09-25 14:07:17.000 +00:00 0000108191 52001 NOTICE Configuration-Changes: Changed configuration, ConfigVersionId=3177, AdminInterface=GUI, AdminIPAddress=10.99.2.41, AdminName=admin, FailureFlag=false, RequestResponseType=initial, ConfigChangeData=Object modified: Local Logging = disable; Assigned Targets = {}, ObjectType=UPSCategory, ObjectName=Passed Authentications, OperationMessageText=LoggingCategories \"Passed Authentications\" has been edited successfully.,",
    "outcome": "success",
    "sequence": 108191,
    "timezone": "+00:00",
    "type": [
      "change",
      "info"
    ]
  },
  "host": {
    "hostname": "ise-01.corp.example",
    "ip": [
      "10.40.0.11"
    ]
  },
  "input": {
    "type": "udp"
  },
  "log": {
    "level": "notice",
    "source": {
      "address": "10.40.0.11:514"
    },
    "syslog": {
      "priority": 181,
      "severity": {
        "name": "notice"
      }
    }
  },
  "message": "2026-09-25 14:07:17.000 +00:00 0000108191 52001 NOTICE Configuration-Changes: Changed configuration, ConfigVersionId=3177, AdminInterface=GUI, AdminIPAddress=10.99.2.41, AdminName=admin, FailureFlag=false, RequestResponseType=initial, ConfigChangeData=Object modified: Local Logging = disable; Assigned Targets = {}, ObjectType=UPSCategory, ObjectName=Passed Authentications, OperationMessageText=LoggingCategories \"Passed Authentications\" has been edited successfully.,",
  "related": {
    "hosts": [
      "ise-01.corp.example"
    ],
    "ip": [
      "10.99.2.41",
      "10.40.0.11"
    ],
    "user": [
      "admin"
    ]
  },
  "tags": [
    "preserve_original_event",
    "cisco-ise",
    "forwarded"
  ],
  "user": {
    "name": "admin"
  }
}
```

## References and Limits

- [Cisco ISE syslog message catalog](https://www.cisco.com/c/en/us/td/docs/security/ise/syslog/Cisco_ISE_Syslogs/m_SyslogsList.html): 51000/51001/51002/52001/52002 and remote target envelope.
- [Cisco ISE external syslog configuration](https://www.cisco.com/c/en/us/support/docs/security/identity-services-engine/222223-configure-external-syslog-server-on-ise.html): Administrative and Operational Audit category.
- [Elastic Cisco ISE raw administrative tests](https://github.com/elastic/integrations/blob/main/packages/cisco_ise/data_stream/log/_dev/test/pipeline/test-pipeline-administrative-and-operational-audit.log): native details and object types.
- [KUMA 4.0 supported sources](https://support.kaspersky.com/kuma/4.0/en-US/255782.htm): ISE normalizer.

The generated administrative stream does not model RADIUS authentication or endpoint authorization traffic. It does not imply that deleting a remote target disables every ISE log route; the explicit 52001 and 52002 changes should be reviewed together.

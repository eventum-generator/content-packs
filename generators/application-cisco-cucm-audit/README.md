# Cisco Unified Communications Manager audit log

Synthetic Cisco Unified Communications Manager 14.0.1.10000-20 application audit-file records in the `Audit00000001.log` `|LogMessage` format shown by Cisco DevNet. This pack models the file's audit event rows, not CUCM syslog alarms, CDRs, or Linux auditd.

## Event types

| Native EventType / detail | Approximate share with anomaly mode | ECS category | Meaning |
| --- | ---: | --- | --- |
| `UserLogging` / login | 43.1% | `authentication` | Successful CUCM Administration login |
| `UserLogging` / logout | 43.1% | `authentication` | Successful Administration logout |
| `GeneralConfigurationUpdate` / `processnode` updated | 12.1% | `configuration` | Existing processnode record updated |
| `GeneralConfigurationUpdate` / `processnode` added | 1.7% | `configuration` | New processnode record added in the anomaly chain |

The template uses FSM mode and emits one event per simulated minute from one CUCM publisher. A routine cycle has 24 administrator sessions; every fourth session updates an existing `processnode` record. An anomaly cycle adds one four-event session. Frequencies and timing are synthetic, not Cisco production telemetry.

## Anomaly Chain

With `anomaly_mode: true` (the default), `breakglass-admin` connects from `198.51.100.45`, an address outside the routine admin pool, and logs into CUCM Administration. The same user and client address then add and update `cimp-shadow-<n>.example.test` in the `processnode` table before logging out. The four steps occur within three simulated minutes; the two configuration records share the record key. A rule can group by `user.name` and `source.ip`, sort by `@timestamp`, and alert on an unusual client followed by a `processnode` add and update. Output row order is not a reliable clock.

This is a synthetic high-interest administrative sequence, not proof of compromise. Cisco's primary sample shows the same four native event forms and record-key linkage. `CorrelationID` is empty for these short rows; it is used by CUCM to join fragments of one oversized audit message, not to identify this admin session. With `anomaly_mode: false`, only routine login, update, and logout records appear. The break-glass actor, off-pool client, and `processnode` additions are absent.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Purpose |
| --- | --- | --- |
| `anomaly_mode` | `true` | Include the four-event admin sequence; `false` produces background only |
| `cucm_node` | `cucm-pub-01` | Native Node ID and ECS host name |
| `routine_sessions_before_chain` | `24` | Routine sessions between anomaly sessions |
| `suspect_user` | `breakglass-admin` | User in the anomaly chain |
| `suspect_client_ip` | `198.51.100.45` | Unusual documentation-range client address |
| `suspect_node_prefix` | `cimp-shadow` | Prefix of the newly added processnode record key |

### Output Parameters

No top-level `${params.*}` or `${secrets.*}` are required. Output defaults to `output/events.json`; edit the file output section to deliver elsewhere.

## Usage

From the content-packs repository:

```bash
eventum generate --path generators/application-cisco-cucm-audit/generator.yml --id cucm --live-mode false
```

For continuous generation, use `--live-mode true`. Set `event.template.params.anomaly_mode` to `false` for background only. The file output is overwritten when a run starts.

## Sample output

This JSON event was copied from an anomaly-mode run:

```json
{
  "@timestamp": "2026-09-25T15:28:00+00:00",
  "cucm": {
    "audit": {
      "app_id": "Cisco Tomcat",
      "audit_category": "AdministrativeEvent",
      "audit_details": "record in table processnode with key field name = cimp-shadow-1.example.test added",
      "client_address": "198.51.100.45",
      "cluster_id": "",
      "component_id": "Cisco CUCM Administration",
      "compulsory_event": "No",
      "correlation_id": "",
      "event_status": "Success",
      "event_type": "GeneralConfigurationUpdate",
      "node_id": "cucm-pub-01",
      "processnode_name": "cimp-shadow-1.example.test",
      "resource_accessed": "CUCMAdmin",
      "severity": 5,
      "timestamp_local": "15:28:00.000",
      "user_id": "breakglass-admin"
    }
  },
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "processnode_added",
    "category": [
      "configuration"
    ],
    "code": "GeneralConfigurationUpdate",
    "dataset": "cucm.audit",
    "kind": "event",
    "module": "cucm",
    "original": "15:28:00.000 |LogMessage   UserID : breakglass-admin  ClientAddress : 198.51.100.45  Severity : 5  EventType : GeneralConfigurationUpdate  ResourceAccessed: CUCMAdmin  EventStatus : Success  CompulsoryEvent : No  AuditCategory : AdministrativeEvent  ComponentID : Cisco CUCM Administration  CorrelationID :   AuditDetails : record in table processnode with key field name = cimp-shadow-1.example.test added App ID: Cisco Tomcat Cluster ID:  Node ID: cucm-pub-01",
    "outcome": "success",
    "type": [
      "creation"
    ]
  },
  "host": {
    "name": "cucm-pub-01"
  },
  "message": "record in table processnode with key field name = cimp-shadow-1.example.test added",
  "related": {
    "hosts": [
      "cucm-pub-01"
    ],
    "ip": [
      "198.51.100.45"
    ],
    "user": [
      "breakglass-admin"
    ]
  },
  "service": {
    "name": "Cisco Unified Communications Manager",
    "version": "14.0.1.10000-20"
  },
  "source": {
    "ip": "198.51.100.45"
  },
  "user": {
    "name": "breakglass-admin"
  }
}
```

## Format and coverage

`event.original` preserves the vendor sample's time prefix, `|LogMessage` marker, and all 14 named fields: `UserID`, `ClientAddress`, `Severity`, `EventType`, `ResourceAccessed`, `EventStatus`, `CompulsoryEvent`, `AuditCategory`, `ComponentID`, `CorrelationID`, `AuditDetails`, `App ID`, `Cluster ID`, and `Node ID`. The `cucm.audit` object mirrors these values, giving 14/14 field coverage against the Cisco DevNet event rows. The complete line is synthetically assembled from those vendor rows; it is not a captured line. The separate file `HDR` line is not emitted as an event. Native event rows carry only a time of day; ECS `@timestamp` supplies the synthetic date in UTC.

Cisco's example identifies build 14.0.1.10000-20 and `/var/log/active/audit/AuditApp/Audit00000001.log`. Application audit logging must be enabled; configuration detail depends on its logging settings. KUMA 4.2 lists a CUCM normalizer for 11.5.1, whereas this pack follows the 14.0.1 file example. Compatibility with that older normalizer or CUCM remote-syslog transport is not claimed.

## References

- [KUMA 4.2 supported sources](https://support.kaspersky.ru/kuma/4.2/255782)
- [Cisco DevNet: Log Collection API with complete CUCM 14 audit-file sample](https://developer.cisco.com/docs/sxml/log-collection-api/)
- [Cisco CUCM 14 administration guide: audit event classes and logging settings](https://www.cisco.com/c/en/us/td/docs/voice_ip_comm/cucm/admin/14SU2/adminGd/cucm_b_administration-guide-14su2/cucm_b_test-adminguide_chapter_010100.html)
- [Cisco CUCM 11.5(1) release notes: short and split audit messages](https://www.cisco.com/c/en/us/td/docs/voice_ip_comm/cucm/rel_notes/11_5_1/cucm_b_release-notes-cucm-imp-1151.pdf)

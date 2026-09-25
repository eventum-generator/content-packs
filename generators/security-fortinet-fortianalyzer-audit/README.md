# Fortinet FortiAnalyzer application audit

FortiAnalyzer 7.2.4 local `appevent` incident-management audit messages. The generator emits ECS JSON and preserves a Fortinet-style raw key-value message in `event.original`. It models FortiAnalyzer's own application log, not FortiGate device logs forwarded through FortiAnalyzer.

## Event types

| Fortinet message | Message ID | Synthetic background weight | ECS type |
| --- | --- | --- | --- |
| `New_Incident_Create` | `100001` | 35 | creation |
| `Incident_Update` | `100002` | 50 | change |
| `Incident_Attachment_Add` | `100005` | 15 | creation |
| `Incident_Attachment_Delete` | `100006` | Anomaly only | deletion |
| `Incident_Delete` | `100003` | Anomaly only | deletion |

Weights and one-record-per-second input are synthetic demo settings, not measured FortiAnalyzer frequencies. Fortinet lists these names and IDs for the `APPEVENT` / `INCIDENT` subtype in version 7.2.4.

## Anomaly Chain

After 60 background records, FortiAnalyzer records a new high-severity incident and an evidence attachment. A different account, `audit_admin`, deletes that attachment and then deletes the incident within seconds. All four records share `fortinet.fortianalyzer.incident_id` and `observer.name`; the attachment events also share `fortinet.fortianalyzer.attachment`. A SIEM rule can correlate the two deletions following creation and flag the account switch. The records show audit actions, not an independently verified attacker identity or proof that the underlying evidence was lost.

`anomaly_mode: true` is the default. `false` emits only routine create, update, and attachment-add records. Sort events by `@timestamp` when correlating: output line order may differ from event time.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`.

| Name | Default | Purpose |
| --- | --- | --- |
| `anomaly_mode` | `true` | Enable the four-record incident suppression sequence. |
| `anomaly_interval_events` | `60` | Background records before each sequence. |
| `analyzer_id` | `FAZ-VM-LAB-01` | Synthetic FortiAnalyzer identifier. |
| `adom` | `root` | Administrative domain in raw and normalized records. |
| `suspicious_analyst` | `audit_admin` | Account deleting the attachment and incident. |
| `incident_prefix` | `INC-2026` | Prefix for synthetic incident identifiers. |

### Output Parameters

The shipped file output needs no overrides. Replace `output.file` with another output plugin and use top-level `${params.*}` or `${secrets.*}` substitutions for destination settings when needed.

## Usage

From the content-packs repository:

```bash
eventum generate --path generators/security-fortinet-fortianalyzer-audit/generator.yml --id faz --live-mode false
eventum generate --path generators/security-fortinet-fortianalyzer-audit/generator.yml --id faz --live-mode true
```

Output: `generators/security-fortinet-fortianalyzer-audit/output/events.json`. Extract `event.original` when a collector expects the Fortinet-style raw message body.

## Sample output

Copied from an actual anomaly-mode run:

```json
{
  "@timestamp": "2026-09-25T14:32:20+00:00",
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "Incident_Attachment_Delete",
    "code": "100006",
    "dataset": "fortinet.fortianalyzer.appevent",
    "kind": "event",
    "original": "id=6826113487000000063 itime=2026-09-25 14:32:19 vd=root logid=100006 type=appevent subtype=incident level=information date=2026-09-25 time=14:32:20 user=audit_admin desc=Incident_Attachment_Delete msg=Attachment deleted from incident INC-2026-9000001 incident_id=INC-2026-9000001 incident_severity=high attachment=evidence-INC-2026-9000001.json adom=root devid=FAZ-VM-LAB-01 dtime=2026-09-25 14:32:19 itime_t=1790346739",
    "type": [
      "deletion"
    ]
  },
  "fortinet": {
    "fortianalyzer": {
      "adom": "root",
      "attachment": "evidence-INC-2026-9000001.json",
      "desc": "Incident_Attachment_Delete",
      "incident_id": "INC-2026-9000001",
      "incident_severity": "high",
      "logid": "100006",
      "subtype": "incident",
      "type": "appevent"
    }
  },
  "observer": {
    "name": "FAZ-VM-LAB-01",
    "product": "FortiAnalyzer",
    "vendor": "Fortinet"
  },
  "related": {
    "user": [
      "audit_admin"
    ]
  },
  "user": {
    "name": "audit_admin"
  }
}
```

## Scope and validation

The Fortinet 7.2.4 reference supplies a complete `appevent` raw example for a playbook action and the field catalog and message IDs for incident actions. This pack uses the documented key-value layout, `INCIDENT` field names, and message IDs; incident IDs, accounts, messages, and timestamps are synthetic. Fortinet does not provide a complete raw incident-action example for each of the five modeled IDs, so this is a documented-format approximation rather than a byte-for-byte replay. Optional catalog fields requiring an actual external connector, playbook, or task context are omitted.

Both modes were generated and parsed as JSON. The four-step chain appeared only in anomaly mode. KUMA 4.2 lists FortiAnalyzer CEF over Syslog; this pack produces local `appevent` key-value messages in `event.original`, not CEF. Compatibility with KUMA's out-of-the-box CEF normalizer is not established. No network Syslog header or collector-specific envelope is generated.

## References

- [Fortinet 7.2.4 FortiAnalyzer application log example](https://docs.fortinet.com/document/fortimanager/7.2.4/log-message-reference/395380/fortianalyzer-application-log-message-example)
- [Fortinet 7.2.4 `APPEVENT` fields and incident message catalog](https://docs.fortinet.com/document/fortimanager/7.2.4/log-message-reference/100001/appevent)
- [Fortinet 7.2.4 log type and message ID format](https://docs.fortinet.com/document/fortimanager/7.2.4/log-message-reference/425476/log-types-and-subtypes)
- [KUMA 4.2 supported sources](https://support.kaspersky.ru/kuma/4.2/255782)

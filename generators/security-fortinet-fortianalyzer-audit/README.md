# Fortinet FortiAnalyzer application audit

Models FortiAnalyzer 7.2.4 local `appevent` incident-management audit messages as ECS JSON. The `event.original` field is reconstructed from Fortinet's field catalog and application-log layout; Fortinet does not publish a complete raw `INCIDENT` example. This is FortiAnalyzer's own application log, not FortiGate logs forwarded through it.

## Event types

| Fortinet message | Message ID | Synthetic selection weight | ECS type |
| --- | --- | ---: | --- |
| `New_Incident_Create` | `100001` | 8 | creation |
| `Incident_Update` | `100002` | 54 | change |
| `Incident_Attachment_Add` | `100005` | 24 | creation |
| `Incident_Attachment_Delete` | `100006` | 9 | deletion |
| `Incident_Delete` | `100003` | 5 | deletion |

Weights are synthetic choices, not measured FortiAnalyzer frequencies. Invalid lifecycle choices become updates, so output shares differ from these weights. Fortinet documents all five IDs for the `APPEVENT` / `INCIDENT` subtype in 7.2.4.

## Anomaly Chain

After 60 ordinary records, FortiAnalyzer records creation of a high-severity incident and addition of an evidence attachment. At the next two 30-second ticks, `audit_admin` removes the attachment and deletes the incident. The four events span 90 seconds and share `fortinet.fortianalyzer.incident_id` and `observer.name`; both attachment events also share `fortinet.fortianalyzer.attachment`. A detection can join the four actions by incident ID within two minutes and flag the change from the creating analyst to the deleting analyst. The records show audit actions, not proof of an attack or of destruction of the underlying evidence.

`anomaly_mode: true` is the default. With `false`, all five action types, `audit_admin`, and high-severity incidents still occur. Ordinary incident deletion is allowed only at least 30 minutes after creation, so the rapid four-step sequence does not occur. No single action, actor, severity, or incident-ID pattern identifies the anomaly. Sort by `@timestamp` when correlating because output line order can differ from event time.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`.

| Name | Default | Purpose |
| --- | --- | --- |
| `anomaly_mode` | `true` | Enable the four-record rapid incident-deletion sequence. |
| `anomaly_interval_events` | `60` | Ordinary records before each sequence. |
| `analyzer_id` | `FAZ-VM-LAB-01` | Synthetic FortiAnalyzer identifier. |
| `adom` | `root` | Administrative domain in raw and normalized records. |
| `suspicious_analyst` | `audit_admin` | Account deleting the attachment and incident; also appears in background. |
| `incident_prefix` | `INC` | Prefix for synthetic `<prefix>-<year>-<serial>` incident IDs. |

### Output Parameters

The shipped file output needs no overrides. Replace `output.file` with another output plugin and use top-level `${params.*}` or `${secrets.*}` substitutions for destination settings when needed.

## Usage

From the content-packs repository:

```bash
timeout 2 eventum generate --path generators/security-fortinet-fortianalyzer-audit/generator.yml --id faz-sample --live-mode false --keep-order true
eventum generate --path generators/security-fortinet-fortianalyzer-audit/generator.yml --id faz-live --live-mode true
```

Output: `generators/security-fortinet-fortianalyzer-audit/output/events.json`. Extract `event.original` when a collector expects the Fortinet-style raw message body.

## Sample output

Copied from an actual anomaly-mode run:

```json
{
  "@timestamp": "2026-09-25T17:03:30+00:00",
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "Incident_Attachment_Delete",
    "code": "100006",
    "dataset": "fortinet.fortianalyzer.appevent",
    "kind": "event",
    "original": "id=6826113487000000063 itime=2026-09-25 17:03:29 vd=root logid=100006 type=appevent subtype=incident level=information date=2026-09-25 time=17:03:30 user=audit_admin desc=Incident_Attachment_Delete msg=Attachment deleted from incident INC-2026-1006 incident_id=INC-2026-1006 incident_severity=high attachment=evidence-INC-2026-1006.json adom=root devid=FAZ-VM-LAB-01 dtime=2026-09-25 17:03:29 itime_t=1790355809",
    "type": [
      "deletion"
    ]
  },
  "fortinet": {
    "fortianalyzer": {
      "adom": "root",
      "attachment": "evidence-INC-2026-1006.json",
      "desc": "Incident_Attachment_Delete",
      "incident_id": "INC-2026-1006",
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

Fortinet's 7.2.4 reference supplies the incident field catalog and message IDs, plus one complete application raw example for a `playbook` event. It does not show a complete raw incident-action record. The native incident lines here are therefore a documented-format approximation, not a verified byte-for-byte reproduction. Optional fields needing connector, playbook, or task context are omitted. Treat this generator as a draft for integrations requiring an exact native parser.

The input emits one event every 30 seconds in live mode. Up to 80 ordinary incidents remain open at once; selection weights, incident rate, actors, and IDs are synthetic lab settings. Final bounded runs produced 4,696 anomaly-mode and 4,230 background-mode JSON records. The anomaly-mode run contained 73 complete 90-second chains. The background run included every action type but no deletion within 90 seconds of incident creation; its shortest create-to-delete interval was 1,830 seconds.

KUMA 4.2 lists FortiAnalyzer CEF over Syslog. This pack models local `appevent` key-value bodies in `event.original`, not CEF. Compatibility with KUMA's out-of-the-box CEF normalizer is unverified; no network Syslog header or collector-specific envelope is generated.

## References

- [Fortinet 7.2.4 Log Reference PDF](https://fortinetweb.s3.amazonaws.com/docs.fortinet.com/v2/attachments/1582da54-5713-11ee-8e6d-fa163e15d75b/FortiManager_%26_FortiAnalyzer_7.2.4_Log_Reference.pdf)
- [Fortinet 7.2.4 FortiAnalyzer application log example](https://docs.fortinet.com/document/fortimanager/7.2.4/log-message-reference/395380/fortianalyzer-application-log-message-example)
- [Fortinet 7.2.4 `APPEVENT` fields and incident message catalog](https://docs.fortinet.com/document/fortimanager/7.2.4/log-message-reference/100001/appevent)
- [Fortinet 7.2.4 log type and message ID format](https://docs.fortinet.com/document/fortimanager/7.2.4/log-message-reference/425476/log-types-and-subtypes)
- [KUMA 4.2 supported sources](https://support.kaspersky.ru/kuma/4.2/255782)

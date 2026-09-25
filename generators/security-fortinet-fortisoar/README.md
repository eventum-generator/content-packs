# Fortinet FortiSOAR Alert Deletion Audit

FortiSOAR alert-deletion audit records based on the complete CEF syslog example in Fortinet's FortiSOAR 7.2.0 administration guide. Eventum emits ECS JSON with the native line in `event.original`.

## Event types

| CEF event class | Action | Frequency in this scoped stream | ECS category |
| --- | --- | --- | --- |
| `Alert Deleted` | Delete an alert record | 100% | api |

This generator covers only alert-deletion audit records, not the full FortiSOAR audit log. The one-record-per-second rate is an accelerated demo setting, not a measured FortiSOAR workload.

## Anomaly Chain

After 60 routine records, the same `CS Admin` actor at `192.0.2.40` deletes five different alerts over five seconds. Each deletion has a unique alert ID; `user.id`, `source.ip`, and `host.name` remain stable. A detection can count five `alert_deleted` records for that actor and source in a ten-second window. The sequence is a burst worth review; it does not itself prove malicious activity.

`anomaly_mode: true` is the default and mixes this sequence with ordinary deletions by other actors. Set it to `false` for background only. Sort output by `@timestamp` before checking the chain because concurrent output can reorder lines.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`.

| Name | Default | Purpose |
| --- | --- | --- |
| `anomaly_mode` | `true` | Enable the five-deletion burst. |
| `anomaly_interval_events` | `60` | Routine records between bursts. |
| `device_name` | `fsrprimary` | FortiSOAR source hostname. |
| `device_id` | `FSRVMPTM20000061` | FortiSOAR serial value in `devid`. |
| `device_version` | `7.0.0` | CEF header version from Fortinet's published sample. |
| `target_user` | `CS Admin` | Burst actor name. |
| `target_user_id` | `f18a07d3-cc76-464b-8664-abd922b68281` | Burst actor UUID. |
| `target_source_ip` | `192.0.2.40` | Burst source IP. |

### Output Parameters

The shipped file output needs no overrides. Replace `output.file` with another output plugin and use top-level `${params.*}` or `${secrets.*}` substitutions for destination settings when needed.

## Usage

From the content-packs repository:

```bash
eventum generate --path generators/security-fortinet-fortisoar/generator.yml --id fortisoar --live-mode false
eventum generate --path generators/security-fortinet-fortisoar/generator.yml --id fortisoar --live-mode true
```

Output: `generators/security-fortinet-fortisoar/output/events.json`. A CEF/syslog collector needs the value of `event.original`, not the enclosing ECS JSON.

## Sample output

Copied from an actual anomaly-mode run:

```json
{
  "@timestamp": "2026-09-25T13:43:58+00:00",
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "alert_deleted",
    "category": [
      "api"
    ],
    "code": "Alert Deleted",
    "dataset": "fortinet.fortisoar.audit",
    "kind": "event",
    "original": "2026-09-25T13:43:58.000000+00:00 fsrprimary fortisoar-audit-log: CEF:0|Fortinet Inc|FortiSOAR|7.0.0|Alert Deleted|Alert Deleted|1|devid=\"FSRVMPTM20000061\" vd=\"enterprise\" level=\"warning\" type=\"Audit Log\" msg=\"Alert [100001] Deleted \" src=\"192.0.2.40\" suid=\"f18a07d3-cc76-464b-8664-abd922b68281\" suser=\"CS Admin\" end=1790343838000 playbookName=\"\" playbookId=\"\" eventTimeStr=\"25 Sep 2026 13:43:58.000\"",
    "type": [
      "deletion"
    ]
  },
  "fortinet": {
    "fortisoar": {
      "alert_id": 100001,
      "device_id": "FSRVMPTM20000061",
      "level": "warning",
      "log_type": "Audit Log",
      "virtual_domain": "enterprise"
    }
  },
  "host": {
    "name": "fsrprimary"
  },
  "related": {
    "ip": [
      "192.0.2.40"
    ],
    "user": [
      "CS Admin"
    ]
  },
  "source": {
    "ip": "192.0.2.40"
  },
  "user": {
    "id": "f18a07d3-cc76-464b-8664-abd922b68281",
    "name": "CS Admin"
  }
}
```

## Scope and validation

The native line retains the CEF header and all 12 extension keys in Fortinet's published alert-deletion example: `devid`, `vd`, `level`, `type`, `msg`, `src`, `suid`, `suser`, `end`, `playbookName`, `playbookId`, and `eventTimeStr` (12/12). Both modes were generated and parsed as JSON; the chain appeared only with `anomaly_mode: true`.

The Fortinet 7.2.0 guide publishes a sample whose CEF device-version field is `7.0.0`; this pack uses that exact header version. Other FortiSOAR actions and their CEF class names are outside this pack. KUMA 4.2 lists a generic Syslog-CEF normalizer for FortiSOAR, but compatibility with this generated stream has not been tested.

## References

- [FortiSOAR 7.2.0 system configuration and audit CEF sample](https://docs.fortinet.com/document/fortisoar/7.2.0/administration-guide/304946)
- [KUMA 4.2 supported sources](https://support.kaspersky.ru/kuma/4.2/255782)

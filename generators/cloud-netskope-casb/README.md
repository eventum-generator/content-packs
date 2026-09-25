# Netskope CASB Cloud Exchange CEF

Synthetic Netskope tenant audit and application events forwarded by Cloud Exchange Log Shipper to syslog in CEF format. The pack follows Netskope's documented default audit output and an application event example from the Syslog plugin documentation.

## Event types

| CEF signature | Approximate share with anomaly mode | ECS category | Meaning |
| --- | ---: | --- | --- |
| `application` / `Download` | 86.4% | `file` | Box cloud-storage download |
| `audit` / `Deleted Inline Policy` | 13.6% | `configuration` | Administrator deletes an inline policy |

The template uses FSM mode for one tenant and one Cloud Exchange syslog shipper. Background mode keeps both event types at about 87.5% and 12.5%, respectively.

## Anomaly Chain

With `anomaly_mode: true` (the default), the same `suser` (`rpatel@example.test`) deletes an inline policy and then downloads from Box three times within seconds. A detection can join the audit and application CEF events on `suser`, sort by `@timestamp`, and look for several `act=Download` events after `auditLogEvent=Deleted Inline Policy`. File row order should not be used as a clock. With `anomaly_mode: false`, routine policy administration is done by `policy.admin@example.test` and routine downloads by `employee@example.test`; the linked actor never appears.

The default CEF audit mapping contains the action and actor but not the deleted policy's identifier or before/after settings. This sequence is suspicious temporal correlation, not proof that deleting that specific policy allowed the downloads. Use a custom Log Shipper mapping with supporting details if a real deployment needs policy-level attribution.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Purpose |
| --- | --- | --- |
| `anomaly_mode` | `true` | Include the linked policy-deletion-to-download sequence; `false` produces background only |
| `tenant_name` | `Example Tenant` | CEF product value for the tenant |
| `shipper_host` | `netskopece` | Cloud Exchange syslog hostname |
| `suspect_user` | `rpatel@example.test` | Shared actor in the anomaly chain |
| `routine_user` | `employee@example.test` | Background download actor |
| `policy_admin` | `policy.admin@example.test` | Background audit actor |
| `source_ip` | `2001:db8::10` | Example client IPv6 address |
| `destination_ip` | `2001:db8::20` | Example destination IPv6 address |

### Output Parameters

No top-level `${params.*}` or `${secrets.*}` are required. Output defaults to `output/events.json`; edit the file output section for another Eventum destination.

## Usage

From the content-packs repository:

```bash
eventum generate --path generators/cloud-netskope-casb/generator.yml --id netskope --live-mode false
```

For continuous generation, use `--live-mode true`. Set `event.template.params.anomaly_mode` to `false` for background only. The file output is overwritten when a run starts.

## Sample output

This JSON event was copied from an anomaly-mode run, not handwritten:

```json
{
  "@timestamp": "2026-09-25T13:48:16+00:00",
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "Deleted Inline Policy",
    "category": [
      "configuration"
    ],
    "kind": "event",
    "original": "<14>Sep 25 13:48:16 netskopece CEF:0|Netskope|Example Tenant|NULL|audit|NULL|High|auditLogEvent=Deleted Inline Policy auditType=admin_audit_logs suser=policy.admin@example.test timestamp=1790344096",
    "outcome": "success",
    "type": [
      "deletion"
    ]
  },
  "host": {
    "name": "netskopece"
  },
  "netskope": {
    "audit_log_event": "Deleted Inline Policy",
    "audit_type": "admin_audit_logs",
    "type": "audit"
  },
  "related": {
    "user": [
      "policy.admin@example.test"
    ]
  },
  "user": {
    "email": "policy.admin@example.test"
  }
}
```

## Format and coverage

The audit branch reproduces every named field in Netskope's default Cloud Exchange CEF audit example: syslog priority/time/host, CEF header, `auditLogEvent`, `auditType`, `suser`, and `timestamp` (9/9 parts). The application branch includes all 14 named extension keys in Netskope's Syslog plugin example, plus the syslog and CEF headers. The vendor example contains an unlabelled escaped text fragment after `browser=unknown`; the pack omits it because it has no documented key. Values are synthetic, and `event.original` is generated, not a captured tenant line.

The application example is in Netskope's Cloud Exchange Syslog plugin v4.1.2 documentation. The audit example is an unversioned Netskope Cloud Exchange KB. Both use the Log Shipper to Syslog CEF channel; exact field availability can vary with plugin version and mapping. The default audit mapping omits `Supporting_Data` and `Details`. KUMA 4.2 lists Netskope CASB with its generic Syslog-CEF normalizer, but compatibility with this synthetic stream has not been tested. Elastic's Netskope API integration is a different collection channel, so its API sample is not the reference here.

## References

- [KUMA 4.2 supported sources](https://support.kaspersky.ru/kuma/4.2/255782)
- [Netskope Cloud Exchange audit CEF examples](https://docs.netskope.com/en/cloud-exchange-kb-articles)
- [Netskope Syslog plugin v4.1.2 and application CEF example](https://docs.netskope.com/en/syslog-plugin-for-log-shipper)

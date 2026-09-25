# Netwrix Auditor CEF Export: Active Directory user creation

Eventum content pack for the `Added user` CEF event documented by the Netwrix Auditor CEF Export Add-on. Output is ECS JSON with the native CEF body in `event.original`. `anomaly_mode: true` is the default; `false` emits background only.

## Run

From the content-packs repository root:

```bash
eventum generate --path generators/identity-netwrix-auditor-cef/generator.yml --id identity-netwrix-auditor-cef --live-mode true
```

For a bounded batch, run `timeout 3s eventum generate --path generators/identity-netwrix-auditor-cef/generator.yml --id identity-netwrix-auditor-cef-batch --live-mode false`. Exit code 124 is expected for this continuous source. Output is written to `generators/identity-netwrix-auditor-cef/output/events.json`.

## Events

| CEF class ID | Meaning | Background frequency | ECS category |
| --- | --- | --- | --- |
| `Added` | Active Directory user created | All events | `iam` |

The pack is deliberately limited to the one complete raw CEF example published in the Netwrix Auditor 10.8 Add-on documentation. It preserves all five published extension fields: `shost`, `cat`, `suser`, `filePath`, and `start`. The CEF header's `1.0` follows the vendor example and is not a claim about Auditor software version. Routine actor and target names, and the chain interval, are synthetic workload choices, not measured rates. This is **Netwrix Auditor Add-on CEF export**, not native Windows Security XML event 4720 from the separate `windows-active-directory` pack. KUMA 4.2 lists Netwrix Auditor with the generic Syslog-CEF normalizer; forward `event.original` via syslog to test that parser, as the shipped file contains ECS JSON.

## Anomaly Chain

One operator, `EXAMPLE\svc-provision`, creates five distinct accounts, `contractor01` through `contractor05`, in the same `\local\example\users` path on `dc-01.example.test` within seconds. Correlate `netwrix.auditor.extension.suser`, `filePath`, `host.name`, and `@timestamp` to flag unusually rapid account provisioning. The CEF sample identifies `suser` as the acting account; the chain represents a burst, not a known compromise. Sort by `@timestamp`; file-line order is not guaranteed under concurrent generation.

`anomaly_mode: false` keeps routine account creation by helpdesk actors, but never emits the chain operator or contractor accounts.

## Parameters

### Event Parameters

| Parameter | Default | Meaning |
| --- | --- | --- |
| `domain_controller` | `dc-01.example.test` | Native `shost` and ECS host |
| `anomaly_mode` | `true` | Include the five-event chain; `false` emits background only |
| `anomaly_interval_events` | `80` | Routine pairs between chain injections |
| `chain_operator` | `EXAMPLE\svc-provision` | Stable chain actor |

### Output Parameters

No top-level `${params.*}` or `${secrets.*}` placeholders are shipped. File output works without credentials. Replace the `output` block and configure the selected plugin to forward to a SIEM.

## Sample output

This complete anomaly event was captured with `anomaly_mode: true`:

```json
{
  "@timestamp": "2026-09-25T14:09:57+00:00",
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "added-user",
    "category": [
      "iam"
    ],
    "code": "Added",
    "dataset": "netwrix_auditor.cef",
    "kind": "event",
    "original": "CEF:0|Netwrix|Active Directory|1.0|Added|Added user|0|shost=dc-01.example.test cat=user suser=EXAMPLE\\svc-provision filePath=\\local\\example\\users\\contractor01 start=Sep 25 2026 14:09:57",
    "type": [
      "creation"
    ]
  },
  "host": {
    "name": "dc-01.example.test"
  },
  "netwrix": {
    "auditor": {
      "class_id": "Added",
      "device_version": "1.0",
      "extension": {
        "cat": "user",
        "filePath": "\\local\\example\\users\\contractor01",
        "shost": "dc-01.example.test",
        "start": "Sep 25 2026 14:09:57",
        "suser": "EXAMPLE\\svc-provision"
      },
      "name": "Added user",
      "product": "Active Directory",
      "severity": 0,
      "vendor": "Netwrix",
      "version": 0
    }
  },
  "related": {
    "user": [
      "EXAMPLE\\svc-provision",
      "contractor01"
    ]
  },
  "user": {
    "name": "EXAMPLE\\svc-provision",
    "target": {
      "name": "contractor01"
    }
  }
}
```

## References

- [Netwrix Auditor 10.8 CEF Export Add-on sample](https://docs.netwrix.com/docs/auditor/10_8/addon/siemcefexport/collecteddata)
- [Netwrix Auditor 10.8 CEF export process](https://docs.netwrix.com/docs/auditor/10_8/addon/siemcefexport/overview)
- [Netwrix Auditor Activity Record actor field](https://docs.netwrix.com/docs/auditor/10_7/api/activityrecordreference)
- [KUMA 4.2 supported event sources](https://support.kaspersky.ru/kuma/4.2/255782)

# Sophos Central SIEM CEF

CEF threat events as emitted by Sophos Central SIEM Integration, including cleanup failure and recovery. The generator writes ECS JSON with the native CEF record in `event.original`.

## Event types

| Event code | Meaning | Approximate frequency | ECS category |
| --- | --- | --- | --- |
| `Event::Endpoint::Threat::Detected` | Threat found | ~10% routine | malware |
| `Event::Endpoint::Threat::CleanedUp` | Threat removed | ~80% routine | malware |
| `Event::Endpoint::Threat::HIPSDetected` | HIPS detection | ~10% routine | malware |
| `Event::Endpoint::Threat::CleanupFailed` | Cleanup failed | Anomaly chain only | malware |

Frequencies are synthetic scenario weights, not measured production rates.

## Anomaly Chain

After about 80 routine records, the same host and file produce Detected → CleanupFailed → Detected → CleanedUp. Correlate on `host.name`, `file.path` and the Sophos threat name. The failure and repeat detection make a useful retry or persistence rule.

`anomaly_mode: true` is the default and mixes this chain into ordinary traffic. Set it to `false` for background records only. Correlate by `@timestamp` because output-line order can differ under concurrent generation.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`.

| Name | Default | Purpose |
| --- | --- | --- |
| `anomaly_mode` | `true` | Enable cleanup-retry chain. |
| `anomaly_interval_events` | `80` | Routine records between chains. |
| `target_host` | `linux-fin-07.example.test` | Chain endpoint. |
| `target_file` | `/home/analyst/Downloads/invoice.js` | Chain file. |
| `threat_name` | `Mal/Generic-S` | Chain threat name. |

### Output Parameters

The shipped file output works without overrides. To send records elsewhere, replace `output.file` with the desired output plugin and use top-level `params`/`secrets` substitutions for destination and credentials. No top-level placeholders are required by this pack.

## Usage

From the content-packs repository:

```bash
eventum generate --path generators/security-sophos-central/generator.yml --id sophos-central --live-mode false
eventum generate --path generators/security-sophos-central/generator.yml --id sophos-central --live-mode true
```

The file output is `generators/security-sophos-central/output/events.json`. Extract `event.original` when a collector requires raw CEF rather than ECS JSON.

## Sample output

Copied from an actual Eventum anomaly-mode run:

```json
{
  "@timestamp": "2026-09-25T13:04:30+00:00",
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "Detected",
    "category": [
      "malware"
    ],
    "code": "Event::Endpoint::Threat::Detected",
    "dataset": "sophos.central",
    "kind": "alert",
    "module": "sophos",
    "original": "CEF:0|sophos|sophos central|1.0|Event::Endpoint::Threat::Detected|Mal/Generic-S|8|rt=2026-09-25T13:04:30+00:00 end=2026-09-25T13:04:30+00:00 dhost=linux-fin-07.example.test filePath=/home/analyst/Downloads/invoice.js suser=analyst@example.test",
    "type": [
      "info"
    ]
  },
  "file": {
    "path": "/home/analyst/Downloads/invoice.js"
  },
  "host": {
    "name": "linux-fin-07.example.test"
  },
  "sophos": {
    "central": {
      "event_type": "Event::Endpoint::Threat::Detected",
      "severity": 8,
      "threat_name": "Mal/Generic-S"
    }
  },
  "user": {
    "email": "analyst@example.test"
  }
}
```

## Scope and validation

12/12 selected script-defined CEF header and extension fields are present. Optional Central API fields not needed for this threat chain are omitted. Both modes were generated and parsed; a time-sorted complete chain was found in anomaly mode and no chain records appeared in background mode.

The official script maps Central API event fields into CEF; this pack models those CEF records, not direct endpoint syslog. The CEF header retains the script’s fixed product version 1.0, even though the script release is 2.1.0. Output is JSON with native CEF in event.original.

## References

- [Sophos Central SIEM Integration repository](https://github.com/sophos/Sophos-Central-SIEM-Integration)
- [Official siem.py CEF format and mappings](https://github.com/sophos/Sophos-Central-SIEM-Integration/blob/master/siem.py)
- [Official threat event type mapping](https://github.com/sophos/Sophos-Central-SIEM-Integration/blob/master/name_mapping.py)
- [KUMA 4.2 supported sources](https://support.kaspersky.ru/kuma/4.2/255782)

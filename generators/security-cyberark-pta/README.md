# CyberArk Privileged Threat Analytics CEF

Synthetic CyberArk PTA 12.6 credential-theft alert notifications for SIEM correlation testing.

## Event types

| Native alert | Reference CEF class | Approximate frequency | ECS category/kind |
| --- | --- | --- | --- |
| `Suspected credentials theft` | `1` in the tested 12.6 raw sample | 100%; independent alert subjects dominate, four linked alerts recur in anomaly mode | `threat` / `alert` |

PTA emits detections, so even background events are individual **alerts**, not benign user actions. The generator models one PTA instance, with four fixed source/target pairs in the background.

## Anomaly Chain

With `anomaly_mode: true` (the default), four separate suspected-credential-theft incidents identify the same source user, source host and source IP against four different destination users and hosts over four event timestamps. Every alert has a distinct `cs2` EventID and `cs3` PTA incident link. Correlate `suser`, `src`, and distinct `duser` or `dst` values within a short window to prioritize a concentrated campaign. Eventum may interleave output lines; sort by `@timestamp` before sequence analysis.

With `anomaly_mode: false`, only independent source-target alert pairs remain. It removes the linked source user and IP but does not suppress alert-class telemetry. The series represents multiple PTA detections; it is not a sequence of underlying login or credential-retrieval events.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Purpose |
| --- | --- | --- |
| `pta_host` | `pta-01.example.test` | PTA instance in ECS observer fields |
| `pta_version` | `12.6` | Pinned CEF header version |
| `pta_link_host` | `10.20.1.5` | Synthetic host for incident links |
| `anomaly_mode` | `true` | Include the four-alert series |
| `anomaly_interval_events` | `80` | Routine pairs between series |
| `chain_source_user` | `svc-backup@corp.example.test` | Linked source user |
| `chain_source_host` | `backup-01.corp.example.test` | Linked source host |
| `chain_source_ip` | `10.20.30.77` | Linked source address |

### Output Parameters

The supplied config writes JSON Lines to `output/events.json`; it defines no top-level `params` or `secrets`. To deliver to a backend, replace `output.file` with its output plugin and define that plugin's `${params.*}` and `${secrets.*}` values. For a CEF/syslog collector, forward `event.original` as the CEF message body.

## Usage

Run from the content-packs repository root:

```bash
eventum generate --path generators/security-cyberark-pta/generator.yml --id pta --live-mode false
eventum generate --path generators/security-cyberark-pta/generator.yml --id pta-live --live-mode true
```

For background-only mode, set `anomaly_mode: false` in `generator.yml`.

## Sample output event

This event was copied from an anomaly-mode run:

```json
{
  "@timestamp": "2026-09-25T14:50:40+00:00",
  "cef": {
    "device": {
      "event_class_id": "1",
      "product": "PTA",
      "vendor": "CyberArk",
      "version": "12.6"
    },
    "extensions": {
      "cs1": "None",
      "cs1Label": "ExtraData",
      "cs2": "d016e2a8cf1b3935fc9d8711",
      "cs2Label": "EventID",
      "cs3": "https://10.20.1.5/incidents/d016e2a8cf1b3935fc9d8711",
      "cs3Label": "PTAlink",
      "cs4": "None",
      "cs4Label": "ExternalLink",
      "deviceCustomDate1": "1790347840000",
      "deviceCustomDate1Label": "detectionDate",
      "dhost": "dc-01.example.test",
      "dst": "10.20.2.11",
      "duser": "domain-admin@dc-01.example.test",
      "shost": "backup-01.corp.example.test",
      "src": "10.20.30.77",
      "suser": "svc-backup@corp.example.test"
    },
    "name": "Suspected credentials theft",
    "severity": "8",
    "version": 0
  },
  "cyberark_pta": {
    "log": {
      "event_type": "1"
    }
  },
  "destination": {
    "domain": "dc-01.example.test",
    "ip": "10.20.2.11",
    "user": {
      "email": "domain-admin@dc-01.example.test",
      "name": "domain-admin"
    }
  },
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "category": [
      "threat"
    ],
    "code": "1",
    "dataset": "cyberark_pta.events",
    "id": "d016e2a8cf1b3935fc9d8711",
    "kind": "alert",
    "original": "CEF:0|CyberArk|PTA|12.6|1|Suspected credentials theft|8|suser=svc-backup@corp.example.test shost=backup-01.corp.example.test src=10.20.30.77 duser=domain-admin@dc-01.example.test dhost=dc-01.example.test dst=10.20.2.11 cs1Label=ExtraData cs1=None cs2Label=EventID cs2=d016e2a8cf1b3935fc9d8711 deviceCustomDate1Label=detectionDate deviceCustomDate1=1790347840000 cs3Label=PTAlink cs3=https://10.20.1.5/incidents/d016e2a8cf1b3935fc9d8711 cs4Label=ExternalLink cs4=None",
    "reason": "Suspected credentials theft",
    "reference": "https://10.20.1.5/incidents/d016e2a8cf1b3935fc9d8711",
    "severity": 8,
    "type": [
      "info"
    ]
  },
  "observer": {
    "hostname": "pta-01.example.test",
    "product": "PTA",
    "vendor": "CyberArk",
    "version": "12.6"
  },
  "related": {
    "hosts": [
      "backup-01.corp.example.test",
      "dc-01.example.test"
    ],
    "ip": [
      "10.20.30.77",
      "10.20.2.11"
    ],
    "user": [
      "svc-backup@corp.example.test",
      "domain-admin@dc-01.example.test"
    ]
  },
  "source": {
    "domain": "backup-01.corp.example.test",
    "ip": "10.20.30.77",
    "user": {
      "email": "svc-backup@corp.example.test",
      "name": "svc-backup"
    }
  }
}
```

## Format and coverage

The complete Elastic integration raw fixture for PTA `12.6` supplies the CEF header, `Suspected credentials theft` class `1`, severity `8` and all 16 extension keys. The generator emits all 16: `suser`, `shost`, `src`, `duser`, `dhost`, `dst`, `cs1Label`, `cs1`, `cs2Label`, `cs2`, `deviceCustomDate1Label`, `deviceCustomDate1`, `cs3Label`, `cs3`, `cs4Label`, `cs4`. Its bare CEF record is in `event.original`; ECS and `cef.*` expose parsed values.

This is a version-specific, single-alert profile. CyberArk's current CEF example still shows class `1`, while its current detection catalog lists ID `21` for the same alert name. That inconsistency prevents asserting that this code is valid for newer PTA releases. Other PTA alert classes, aggregation settings and transport-level syslog headers are not modeled.

## References

- [Elastic CyberArk PTA integration](https://www.elastic.co/docs/reference/integrations/cyberark_pta) - full 12.6 CEF raw example and parsed event.
- [CyberArk CEF-Based Format Definition](https://docs.cyberark.com/pam-self-hosted/latest/en/content/pta/cef-based-format-definition.htm) - extension meanings and current example.
- [CyberArk PTA detection catalog](https://docs.cyberark.com/pam-self-hosted/latest/en/content/pta/what-does-pta-detect.htm) - current detection descriptions and IDs.
- [CyberArk PTA syslog to SIEM](https://docs.cyberark.com/pam-self-hosted/latest/en/content/pta/outbound-sending-%20pta-syslog-records-to-siem.htm) - export configuration and aggregation behavior.

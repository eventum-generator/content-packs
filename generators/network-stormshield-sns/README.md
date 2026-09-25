# Stormshield SNS SSH alarm logs

Stormshield Network Security 4.8.18 WELF audit records for interactive SSH connection alarms. Eventum emits ECS JSON and keeps the native WELF message body in `event.original`.

## Event types

| Alarm | Action | Synthetic background frequency | ECS category |
| --- | --- | --- | --- |
| `85` | Interactive connection detected, `action=pass` | 100% | network, intrusion_detection |

The generator deliberately covers one documented alarm record shape. The one-record-per-second sample rate and source distribution are demo settings, not measured SNS frequencies.

## Anomaly Chain

After 55 routine SSH alarm records to a bastion, the same external source causes four `alarmid=85` interactive-connection records to four different internal hosts within four seconds. Correlate by `source.ip`, `observer.name`, `destination.port=22`, and time. A rule can flag one external address reaching several internal SSH destinations in a short interval.

The WELF action is `pass`; the alarm does not prove SSH authentication, lateral movement, or compromise. `anomaly_mode: true` is the default. Set it to `false` to emit only bastion background records. Sort by `@timestamp` when checking the chain because output lines may be reordered.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`.

| Name | Default | Purpose |
| --- | --- | --- |
| `anomaly_mode` | `true` | Enable the four-host SSH alarm sequence. |
| `anomaly_interval_events` | `55` | Routine records before each sequence. |
| `firewall_name` | `sns-fw-01` | Synthetic firewall identifier. |
| `scanner_ip` | `198.51.100.44` | Synthetic source correlated across the sequence. |

### Output Parameters

The shipped file output needs no overrides. Replace `output.file` with another output plugin and use top-level `${params.*}` or `${secrets.*}` substitutions for destination settings if needed.

## Usage

From the content-packs repository:

```bash
eventum generate --path generators/network-stormshield-sns/generator.yml --id stormshield --live-mode false
eventum generate --path generators/network-stormshield-sns/generator.yml --id stormshield --live-mode true
```

Output: `generators/network-stormshield-sns/output/events.json`. Extract `event.original` when the collector expects the WELF message body.

## Sample output

Copied from an actual anomaly-mode run:

```json
{
  "@timestamp": "2026-09-25T14:06:27+00:00",
  "destination": {
    "domain": "app-01",
    "ip": "10.20.0.11",
    "port": 22
  },
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "interactive_connection_detected",
    "category": [
      "network",
      "intrusion_detection"
    ],
    "code": "85",
    "dataset": "stormshield.sns",
    "kind": "alert",
    "original": "id=firewall time=\"2026-09-25 14:06:27\" fw=\"sns-fw-01\" tz=+0000 startime=\"2026-09-25 14:06:27\" pri=4 srcif=\"Ethernet0\" srcifname=\"out\" ipproto=tcp proto=ssh src=198.51.100.44 srcport=54000 srcportname=ephemeral_fw dst=10.20.0.11 dstport=22 dstportname=ssh dstname=app-01 action=pass msg=\"Interactive connection detected\" class=protocol classification=0 alarmid=85",
    "type": [
      "info"
    ]
  },
  "network": {
    "protocol": "ssh",
    "transport": "tcp"
  },
  "observer": {
    "name": "sns-fw-01",
    "product": "SNS",
    "vendor": "Stormshield"
  },
  "related": {
    "ip": [
      "198.51.100.44",
      "10.20.0.11"
    ]
  },
  "source": {
    "ip": "198.51.100.44",
    "port": 54000
  },
  "stormshield": {
    "sns": {
      "action": "pass",
      "alarm_id": 85,
      "classification": 0,
      "priority": 4,
      "source_interface": "Ethernet0",
      "source_interface_name": "out"
    }
  }
}
```

## Scope and validation

The raw body follows the complete `id=firewall ... alarmid=85` vendor example and the documented SNS v4 WELF key-value layout. Dynamic addresses, identifiers, ports, and times are synthetic. Both modes were parsed as JSON; the four-host sequence appeared only with anomaly mode enabled. The sampled source fields in the vendor WELF line are all represented in `event.original` and mapped where meaningful to ECS or `stormshield.sns`.

SNS supports several Syslog envelopes. This pack stores the WELF message body rather than inventing a LEGACY or RFC5424 transport header. KUMA 4.2 lists Stormshield firewall 4.8/5.0 key-value Syslog, but compatibility with its out-of-the-box normalizer has not been tested. The specific vendor example is from SNS 4.8.18 documentation; SNS 5.0 is not claimed as validated.

## References

- [Stormshield SNS 4.8.18 audit-log format and full sample](https://documentation.stormshield.eu/SNS/v4/en/Content/Description_of_Audit_logs/Understand_log_files.htm)
- [Stormshield SNS syslog WELF and transport formats](https://documentation.stormshield.eu/SNS/v4/en/Content/User_Configuration_Manual_SNS_v4.3_LTSB/Logs-syslog/Syslog_tab.htm)
- [KUMA 4.2 supported sources](https://support.kaspersky.ru/kuma/4.2/255782)

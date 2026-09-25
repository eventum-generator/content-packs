# Kaspersky NGFW 1.0 CEF sessions

Kaspersky NGFW Firewall CEF session records with paired start and end events and transfer volumes. The generator writes ECS JSON with the native CEF record in `event.original`.

## Event types

| Event code | Meaning | Approximate frequency | ECS category |
| --- | --- | --- | --- |
| `Session start` | Session opened | ~2.5% in anomaly mode | network |
| `Firewall` | Session ended | ~97.5% in anomaly mode | network |

Frequencies are synthetic scenario weights, not measured production rates.

## Anomaly Chain

After about 80 routine session-end records, two start/end pairs target TCP/445 from 10.20.1.87 to 10.20.2.14. Match each pair on `kaspersky.ngfw.session_id`, then correlate the pairs on source and destination. Each end record reports more than 70 MB sent by the server. A rule can detect repeated large SMB transfers to one client.

`anomaly_mode: true` is the default and mixes this chain into ordinary traffic. Set it to `false` for background records only. Correlate by `@timestamp` because output-line order can differ under concurrent generation.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`.

| Name | Default | Purpose |
| --- | --- | --- |
| `anomaly_mode` | `true` | Enable the SMB transfer chain. |
| `anomaly_interval_events` | `80` | Routine records between chains. |
| `device_host` | `ngfw-01.example.test` | NGFW hostname. |
| `device_version` | `1.0.0.0` | CEF device version. |
| `unusual_source_ip` | `10.20.1.87` | Chain client. |
| `sensitive_destination_ip` | `10.20.2.14` | Chain server. |

### Output Parameters

The shipped file output works without overrides. To send records elsewhere, replace `output.file` with the desired output plugin and use top-level `params`/`secrets` substitutions for destination and credentials. No top-level placeholders are required by this pack.

## Usage

From the content-packs repository:

```bash
eventum generate --path generators/network-kaspersky-ngfw/generator.yml --id kaspersky-ngfw --live-mode false
eventum generate --path generators/network-kaspersky-ngfw/generator.yml --id kaspersky-ngfw --live-mode true
```

The file output is `generators/network-kaspersky-ngfw/output/events.json`. Extract `event.original` when a collector requires raw CEF rather than ECS JSON.

## Sample output

Copied from an actual Eventum anomaly-mode run:

```json
{
  "@timestamp": "2026-09-25T13:04:04+00:00",
  "destination": {
    "bytes": 0,
    "ip": "10.20.2.14",
    "port": 445
  },
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "Session start",
    "category": [
      "network"
    ],
    "dataset": "kaspersky.ngfw",
    "kind": "event",
    "original": "CEF:0|Kaspersky|NGFW|1.0.0.0|Firewall|Session start|Unknown|rt=2026-09-25T13:04:04Z dtz=UTC+00:00 cs4=Low cs4Label=Priority devicePayloadId=911 cs1=Internal SMB inspection cs1Label=SecurityRule act=Inspect FullMatch=yes start=2026-09-25T13:04:04Z cn1=0 cn1Label=Duration cn2=1 cn2Label=ClientPackets cn3=0 cn3Label=ServerPackets in=64 out=0 dvchost=ngfw-01.example.test src=10.20.1.87 dst=10.20.2.14 proto=TCP spt=49220 dpt=445 KasperskyNGFWTCPRedir=no app=Unknown",
    "type": [
      "start"
    ]
  },
  "kaspersky": {
    "ngfw": {
      "action": "Inspect",
      "rule": "Internal SMB inspection",
      "session_id": "911"
    }
  },
  "network": {
    "protocol": "smb",
    "transport": "tcp"
  },
  "observer": {
    "hostname": "ngfw-01.example.test",
    "product": "NGFW",
    "vendor": "Kaspersky",
    "version": "1.0.0.0"
  },
  "source": {
    "bytes": 64,
    "ip": "10.20.1.87",
    "port": 49220
  }
}
```

## Scope and validation

27/27 selected documented CEF keys are represented across start and end records. Optional protocol-specific and security-profile fields are outside this focused session stream. Both modes were generated and parsed; a time-sorted complete chain was found in anomaly mode and no chain records appeared in background mode.

The schema follows NGFW 1.0. KUMA also lists NGFW 1.2, but this pack does not claim byte-for-byte 1.2 compatibility. Routine traffic is modeled as session-end records; start records occur in the anomaly chain.

## References

- [Kaspersky NGFW 1.0 CEF header](https://support.kaspersky.com/ngfw/1.0/274361)
- [Kaspersky NGFW 1.0 Firewall fields](https://support.kaspersky.com/ngfw/1.0/274840)
- [KUMA 4.2 supported sources](https://support.kaspersky.ru/kuma/4.2/255782)

# Kaspersky Industrial CyberSecurity for Networks 4.2 CEF

KICS for Networks asset and network-alert messages modeled from its CEF 20 field specification. Eventum writes ECS JSON with the CEF record in `event.original`.

## Event types

| Event type ID | Meaning | Approximate background frequency |
| --- | --- | --- |
| `4000005003` | New device detected on network | 60% |
| `4000005007` | New device IP address detected | 30% |
| `4000005005` | IP address conflict detected | 10% |
| `4000004001` | ARP spoofing signs in replies | Chain only |

These are synthetic scenario weights, not measured rates. Severity follows the documented KICS score bands: 3 below score 4, 6 from score 4 to 7.9, and 9 from score 8.

## Anomaly Chain

After 60 routine records, an unfamiliar device appears at `10.20.30.15`, its IP conflicts with another MAC, and ARP spoofing signs are detected for the same IP and target. Link the first two records by `ownerIp`, then the ARP record by `substitutedIpAddress`, together with the server and time window. A rule can raise priority when device discovery is followed by an address conflict and ARP spoofing evidence.

`anomaly_mode: true` is the default and mixes this sequence with background. Set it to `false` for background only. Sort by `@timestamp` when reconstructing the sequence; concurrent output may reorder lines.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`.

| Name | Default | Purpose |
| --- | --- | --- |
| `anomaly_mode` | `true` | Enable the device-conflict-ARP sequence. |
| `anomaly_interval_events` | `60` | Routine records between chains. |
| `server_host` | `kics-srv-01.example.test` | KICS server address. |
| `target_ip` | `10.20.30.15` | Device IP in the chain. |
| `challenger_mac` | `02:42:ac:11:00:99` | Conflicting MAC. |
| `owner_mac` | `02:42:ac:11:00:15` | Device's known MAC. |

### Output Parameters

The shipped file output needs no overrides. Replace `output.file` with another output plugin and use top-level `${params.*}` or `${secrets.*}` substitutions for destination settings when needed.

## Usage

From the content-packs repository:

```bash
eventum generate --path generators/security-kaspersky-kics4net/generator.yml --id kics-networks --live-mode false
eventum generate --path generators/security-kaspersky-kics4net/generator.yml --id kics-networks --live-mode true
```

Output: `generators/security-kaspersky-kics4net/output/events.json`. Extract `event.original` for a CEF collector.

## Sample output

Copied from an actual anomaly-mode run:

```json
{
  "@timestamp": "2026-09-25T13:21:10+00:00",
  "destination": {
    "ip": "10.20.30.1"
  },
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "New device detected on network",
    "category": [
      "host"
    ],
    "code": "4000005003",
    "dataset": "kaspersky.kics_networks",
    "kind": "event",
    "original": "CEF:0|Kaspersky Lab|Kaspersky Industrial CyberSecurity for Networks|4.2.0.335|4000005003|New device detected on network|3|dateTime=2026-09-25T13:21:10.000Z hostname=kics-srv-01.example.test messageType=Event score=2.1 eventIdentifier=30060 src=10.20.30.15 dst=10.20.30.1 ownerIp=10.20.30.15 ownerMac=02:42:ac:11:00:15 assetName=example-device-60",
    "type": [
      "info"
    ]
  },
  "host": {
    "name": "kics-srv-01.example.test"
  },
  "kaspersky": {
    "kics_networks": {
      "challenger_mac": null,
      "event_identifier": 30060,
      "owner_mac": "02:42:ac:11:00:15",
      "score": 2.1
    }
  },
  "related": {
    "ip": [
      "10.20.30.15",
      "10.20.30.1"
    ]
  },
  "source": {
    "ip": "10.20.30.15"
  }
}
```

## Scope and validation

The selected CEF header and event-specific fields are covered 23/23. Other KICS technologies and optional asset metadata are outside this pack. Both modes were parsed and checked for the complete chain or its absence.

KICS documentation specifies CEF 20 messages and says they are not converted to syslog. The documented field map is reconstructed as a CEF text record here; byte-for-byte framing with a live KICS installation has not been verified. KUMA 4.2 lists a syslog normalizer, so compatibility with that out-of-the-box normalizer is not established. Use a CEF parser or an appropriate transport adapter.

## References

- [KICS for Networks 4.2 SIEM message format](https://support.kaspersky.com/KICSforNetworks/4.2/en-US/283821.htm)
- [KICS for Networks 4.2 event type IDs](https://support.kaspersky.com/KICSforNetworks/4.2/en-us/177537.htm)
- [KUMA 4.2 supported sources](https://support.kaspersky.ru/kuma/4.2/255782)

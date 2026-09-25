# S-Terra VPN Gate IKE security associations

S-Terra VPN Gate 4.1 IKE SA created and closed messages from the vendor event catalog. Eventum emits ECS JSON and stores the vendor message body in `event.original`.

## Event types

| Vendor MSG ID | Message | Synthetic background frequency | ECS category |
| --- | --- | --- | --- |
| `10000005` | ISAKMP connection created | 50% | network |
| `10000006` | ISAKMP connection closed | 50% | network |

The one-record-per-second demonstration rate and peer distribution are synthetic, not measured VPN Gate frequencies.

## Anomaly Chain

After 56 routine records among four branch peers, the same peer creates and closes three distinct IKE security associations in six successive records. Correlate each pair by `s_terra.vpn_gate.connection_id`, then aggregate the three short-lived pairs by `destination.ip`, `s_terra.vpn_gate.peer_id`, `observer.name`, and time. A rule can flag rapid IKE SA churn for one peer.

The chain identifies instability worth investigating; the two messages do not establish a failure reason or prove malicious activity. `anomaly_mode: true` is the default. Set it to `false` for background peers only. Sort by `@timestamp` when examining the chain because output lines may be reordered.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`.

| Name | Default | Purpose |
| --- | --- | --- |
| `anomaly_mode` | `true` | Enable repeated short-lived IKE associations. |
| `anomaly_interval_events` | `56` | Routine records before each six-record sequence. Keep this even so create/close pairs align. |
| `gateway_name` | `vpn-gate-01` | Synthetic VPN Gate identifier. |
| `unstable_peer_ip` | `198.51.100.44` | Synthetic peer correlated across the sequence. |

### Output Parameters

The shipped file output needs no overrides. Replace `output.file` with another output plugin and use top-level `${params.*}` or `${secrets.*}` substitutions for destination settings if needed.

## Usage

From the content-packs repository:

```bash
eventum generate --path generators/vpn-s-terra-gate/generator.yml --id s-terra --live-mode false
eventum generate --path generators/vpn-s-terra-gate/generator.yml --id s-terra --live-mode true
```

Output: `generators/vpn-s-terra-gate/output/events.json`.

## Sample output

Copied from an actual anomaly-mode run:

```json
{
  "@timestamp": "2026-09-25T14:10:07+00:00",
  "destination": {
    "domain": "unstable-branch.example",
    "ip": "198.51.100.44",
    "port": 500
  },
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "ike_sa_created",
    "category": [
      "network"
    ],
    "code": "10000005",
    "dataset": "s_terra.vpn_gate",
    "kind": "event",
    "original": "ISAKMP connection 810000 created, peer 198.51.100.44:500, id \"unstable-branch.example\"",
    "type": [
      "start"
    ]
  },
  "network": {
    "protocol": "isakmp",
    "transport": "udp"
  },
  "observer": {
    "name": "vpn-gate-01",
    "product": "VPN Gate",
    "vendor": "S-Terra"
  },
  "related": {
    "ip": [
      "198.51.100.44"
    ]
  },
  "s_terra": {
    "vpn_gate": {
      "connection_id": 810000,
      "peer_id": "unstable-branch.example",
      "severity": "INFO"
    }
  }
}
```

## Scope and validation

The `10000005` and `10000006` message bodies, IDs, and INFO severity follow the VPN Gate 4.1 vendor event catalog. The peer, identifier, SA number, and timestamp are synthetic. Both modes were generated and parsed as JSON; the six-record sequence appeared only with anomaly mode enabled. All fields in the selected vendor message template are represented in `event.original` and mapped to ECS or `s_terra.vpn_gate` where meaningful.

The public vendor catalog specifies the message bodies but does not provide a complete wire-level Syslog frame for these two events. Accordingly `event.original` contains only the message body; the collector or output integration must add its chosen Syslog header if required. Compatibility with KUMA 4.2's out-of-the-box S-Terra normalizer has not been tested. This pack models VPN Gate 4.1, not the Client product or later firmware.

## References

- [S-Terra VPN Gate 4.1 logged event catalog](https://doc.s-terra.ru/rh_output/4.1/Gate/output/mergedProjects/Syslog/%D0%A1%D0%BF%D0%B8%D1%81%D0%BE%D0%BA_%D0%BF%D1%80%D0%BE%D1%82%D0%BE%D0%BA%D0%BE%D0%BB%D0%B8%D1%80%D1%83%D0%B5%D0%BC%D1%8B%D1%85_%D1%81%D0%BE%D0%B1%D1%8B%D1%82%D0%B8%D0%B9.htm)
- [S-Terra VPN Gate 4.1 syslog-client configuration](https://doc.s-terra.ru/rh_output/4.1/Gate/output/mergedProjects/Syslog/log_mgr_set.htm)
- [KUMA 4.2 supported sources](https://support.kaspersky.ru/kuma/4.2/255782)

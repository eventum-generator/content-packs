# WatchGuard Firebox Traffic Logs

Synthetic Firebox traffic log bodies based on WatchGuard's published Traffic Monitor and SSL VPN troubleshooting examples. WatchGuard says the same log messages can be sent to a Syslog server. Eventum emits ECS JSON and keeps the native body in `event.original`.

## Event types

| Event | Message ID | Approximate background frequency | ECS category |
| --- | --- | --- | --- |
| HTTP proxy Allow | `3000-0176` | 85% | network |
| ICMP Deny to Firebox | `3000-0148` | 15% | network |
| TCP Deny to SSL VPN port | `3000-0148` | Anomaly chain only | network |

The background weights and one-record-per-second rate are synthetic demo settings, not measured Firebox frequencies. `3000-0148` is shared by distinct firewall allow/deny traffic, so detection must also inspect disposition, protocol, and destination.

## Anomaly Chain

After 60 routine records, one external source makes five TCP attempts to the Firebox's SSL VPN port in five seconds. All five are denied as `Unhandled External Packet`, with changing source ports and stable `source.ip`, `destination.ip`, `destination.port`, and `observer.name`. A rule can flag repeated `traffic_deny` events for that tuple over ten seconds.

WatchGuard's documentation shows this log when the SSL VPN policy is missing, disabled, or misconfigured. The chain can also represent repeated connection attempts; these records do not contain a username or authentication result, so they cannot establish password guessing. Investigate policy state before treating the burst as hostile activity.

`anomaly_mode: true` is the default. Set it to `false` for routine HTTP and ICMP traffic only. Sort by `@timestamp` when checking the chain; output line order can differ under concurrency.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`.

| Name | Default | Purpose |
| --- | --- | --- |
| `anomaly_mode` | `true` | Enable repeated SSL VPN-port denies. |
| `anomaly_interval_events` | `60` | Routine records between bursts. |
| `device_name` | `firebox-edge` | Synthetic Firebox name in ECS. |
| `vpn_source_ip` | `192.0.2.99` | External source in the chain. |
| `vpn_firebox_ip` | `203.0.113.250` | Firebox destination in the chain. |
| `vpn_port` | `9007` | SSL VPN listening port used by the vendor example. |

### Output Parameters

The shipped file output needs no overrides. Replace `output.file` with another output plugin and use top-level `${params.*}` or `${secrets.*}` substitutions for destination settings when needed.

## Usage

From the content-packs repository:

```bash
eventum generate --path generators/network-watchguard-firebox/generator.yml --id firebox --live-mode false
eventum generate --path generators/network-watchguard-firebox/generator.yml --id firebox --live-mode true
```

Output: `generators/network-watchguard-firebox/output/events.json`. Extract `event.original` if the collector expects the Firebox log body. A Syslog transport can prepend its own envelope according to the Firebox configuration.

## Sample output

Copied from an actual anomaly-mode run:

```json
{
  "@timestamp": "2026-09-25T13:52:38+00:00",
  "destination": {
    "ip": "203.0.113.250",
    "port": 9007
  },
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "traffic_deny",
    "category": [
      "network"
    ],
    "code": "3000-0148",
    "dataset": "watchguard.firebox.traffic",
    "kind": "event",
    "original": "2026-09-25 13:52:38 Deny 192.0.2.99 203.0.113.250 9007/tcp 31069 9007 External1 Firebox Denied 52 51 (Unhandled External Packet-00) proc_id=\"firewall\" rc=\"101\" msg_id=\"3000-0148\" tcp_info=\"offset 8 S 2192251295 win 65535\"",
    "type": [
      "denied"
    ]
  },
  "network": {
    "transport": "tcp"
  },
  "observer": {
    "name": "firebox-edge",
    "product": "Firebox",
    "vendor": "WatchGuard"
  },
  "related": {
    "ip": [
      "192.0.2.99",
      "203.0.113.250"
    ]
  },
  "rule": {
    "name": "Unhandled External Packet-00"
  },
  "source": {
    "ip": "192.0.2.99",
    "port": 31069
  },
  "watchguard": {
    "firebox": {
      "reason": "Unhandled External Packet-00",
      "return_code": "101"
    }
  }
}
```

## Scope and validation

The raw HTTP Allow, ICMP Deny, and SSL VPN TCP Deny shapes preserve every key-value field in their respective WatchGuard examples (10/10, 9/9, and 4/4). The output also includes the positional fields in those examples. Both modes were generated and parsed, and the five-step chain was absent from background-only output.

WatchGuard's HTML examples do not establish one exact Fireware version for all three records. This pack models the documented current log bodies, without a numbered-version compatibility claim. The Syslog envelope and KUMA 4.2 Firebox normalizer were not tested together; the page documents message bodies that WatchGuard says match Traffic Monitor output.

## References

- [WatchGuard: Read a Log Message](https://www.watchguard.com/help/docs/help-center/en-us/Content/en-US/Fireware/logging/read_log-msg.html)
- [WatchGuard: Missing or Misconfigured SSL VPN Policy](https://www.watchguard.com/help/docs/help-center/en-US/Content/en-US/Fireware/mvpn/ssl/troubleshoot/mvpn_ssl_wg-sslvpn-policy.html)
- [WatchGuard: Configure Syslog Server Settings](https://www.watchguard.com/help/docs/help-center/en-us/Content/en-US/Fireware/logging/send_logs_to_syslog_c.html)
- [KUMA 4.2 supported sources](https://support.kaspersky.ru/kuma/4.2/255782)

# MikroTik RouterOS Syslog

Generates ECS-compatible JSON with `event.original` resembling RFC 3164 remote syslog and documented RouterOS topic/message text. One router produces DHCP, firewall and account events.

Reference coverage: **7/7 selected native log elements: timestamp, router, topics, message, remote syslog priority, facility and severity. The message families come from RouterOS vendor examples. The BSD syslog envelope is a configured transport choice; exact framing can vary by device version and remote-log-format.**

## Event Types

| Type | Routine weight | Category |
| --- | ---: | --- |
| DHCP assigned | 45% | Network |
| DHCP deassigned | 22% | Network |
| Firewall packet | 25% | Network |
| Normal Winbox login | 5% | Authentication |
| Normal Winbox logout | 3% | Authentication |
| Unusual login and mangle-rule edits | Anomaly only | Authentication/configuration |

Weights are generator design values, not measured vendor production frequencies. One reusable template drives an FSM. The default input emits one event per second, preserving an observable order between anomaly steps.

## Anomaly Chain

With `event.template.params.anomaly_mode: true` (the default), the generator mixes background events with this sequence after every 240 routine events:

1. `admin` logs in from an unusual IP over Winbox.
2. The same router logs a mangle rule added by `admin`.
3. It then logs the rule moved and changed by `admin`.

Rules can detect first-time administrator access followed by several configuration changes. RouterOS configuration messages shown in the vendor example identify the user but not the client IP or a rule ID. Correlate by router, user and a short time window; do not claim that an individual login line proves which session made the edits.

Set `anomaly_mode: false` to emit only background. No anomaly steps or transition into the chain occur in that mode.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Meaning |
| --- | --- | --- |
| `router_name`, `router_ip` | `mt-edge-01`, `10.30.0.1` | Router identity |
| `normal_user`, `normal_source_ip` | `netops`, `10.30.1.12` | Routine Winbox account |
| `anomaly_user`, `anomaly_source_ip` | `admin`, `198.51.100.83` | Anomaly login identity |
| `anomaly_interval_events` | `240` | Routine events between chains |
| `anomaly_mode` | `true` | Enable the chain; `false` emits only background |

### Output Parameters

The shipped configuration writes `output/events.json` relative to the generator. It declares no top-level `${params.*}` or `${secrets.*}` overrides. Change `output.file.path` or replace the output plugin to deliver to a SIEM.

## Usage

Run from the content-packs repository root:

```bash
eventum generate --path generators/network-mikrotik-routeros/generator.yml --id network-mikrotik-routeros --live-mode true
```

Use `--live-mode false` for a fast local sample run.

## Sample Output

This complete event was copied from an enabled-mode generator run:

```json
{"@timestamp": "2026-09-25T11:46:14+00:00", "ecs": {"version": "8.17.0"}, "event": {"kind": "event", "module": "mikrotik", "dataset": "mikrotik.routeros.syslog", "category": ["configuration"], "type": ["info"], "action": "mangle_rule_changed", "original": "\u003c134\u003eSep 25 11:46:14 mt-edge-01 system,info mangle rule changed by admin"}, "message": "mangle rule changed by admin", "observer": {"hostname": "mt-edge-01", "ip": "10.30.0.1", "vendor": "MikroTik", "product": "RouterOS", "type": "router"}, "log": {"syslog": {"priority": 134, "facility": {"code": 16}, "severity": {"code": 6}}}, "mikrotik": {"topics": ["system", "info"]}, "user": {"name": "admin"}, "source": {"ip": null}}
```

## References and Limits

- [MikroTik RouterOS Log documentation](https://help.mikrotik.com/docs/spaces/ROS/pages/328094/Log): native topic/message examples, remote syslog settings and RFC 3164 transport.
- [KUMA 4.0 supported event sources](https://support.kaspersky.com/kuma/4.0/en-US/255782.htm): MikroTik syslog inventory.

RouterOS 7.18 also supports CEF, but this generator models the configured BSD syslog path. Firewall messages require matching logging rules. The documented mangle messages do not expose the changed rule ID or source IP.

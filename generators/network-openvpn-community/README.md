# OpenVPN Community server log

Generates ECS-enriched OpenVPN server-file log lines for certificate verification, peer connection, tunnel assignment, and data-channel setup. `event.original` is the timestamped native line; the other fields make correlation easier.

## Event types

| Native message | Routine frequency | ECS category | Meaning |
| --- | --- | --- | --- |
| `VERIFY OK: depth=0` | Once per routine connection | network | Client certificate CN verified |
| `Peer Connection Initiated` | Once per routine connection | network | New peer connection |
| `MULTI_sva: pool returned IPv4` | Once per routine connection | network | Tunnel address assigned |
| `Data Channel: using negotiated cipher` | Once per routine connection | network | Data channel established |
| `MULTI: new connection by client` | Chain only | network | Previous session with the same CN dropped |

One `any` template renders the ordered session records. Routine sessions rotate across client CNs and public addresses, with a new port for each session.

## Anomaly Chain

`anomaly_mode` defaults to `true`. After 80 ordinary records, `finance-admin` connects from `198.51.100.31`, receives `10.8.0.50`, and then reconnects from `203.0.113.74` seconds later. OpenVPN logs the same-CN session replacement and reassigns the tunnel address. Correlate `user.name`/native CN across two `Peer Connection Initiated` lines with different source IPs and the `MULTI: new connection` warning. This may indicate reused credentials or a stolen client certificate; legitimate roaming is a possible explanation. With `anomaly_mode: false`, no same-CN replacement chain is emitted.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`.

| Name | Default | Purpose |
| --- | --- | --- |
| `anomaly_mode` | `true` | Include the same-CN source-switch chain |
| `anomaly_interval_events` | `80` | Ordinary records between chains |
| `vpn_host` | `vpn-01.example.test` | OpenVPN server host |
| `suspicious_common_name` | `finance-admin` | Chain certificate CN |
| `first_public_ip` | `198.51.100.31` | First chain source address |
| `second_public_ip` | `203.0.113.74` | Replacement source address |
| `tunnel_ip` | `10.8.0.50` | Chain tunnel address |

### Output Parameters

The shipped configuration writes `output/events.json` and requires no output overrides. For a remote SIEM output, replace `output.file` and use top-level `${params.*}` for endpoint settings and `${secrets.*}` for credentials.

## Usage

```bash
eventum generate --path generators/network-openvpn-community/generator.yml --id openvpn --live-mode false
eventum generate --path generators/network-openvpn-community/generator.yml --id openvpn --live-mode true
```

## Sample output

Copied from an anomaly-mode run:

```json
{"@timestamp": "2026-09-25T12:37:51+00:00", "ecs": {"version": "8.17.0"}, "event": {"kind": "event", "module": "openvpn", "dataset": "openvpn.server", "action": "duplicate-cn-drop", "category": ["network"], "type": ["info"], "original": "Fri Sep 25 12:37:51 2026 MULTI: new connection by client \u0027finance-admin\u0027 will cause previous active sessions by this client to be dropped. Remember to use the --duplicate-cn option if you want multiple clients using the same certificate or username to concurrently connect."}, "host": {"name": "vpn-01.example.test"}, "source": {"ip": "203.0.113.74", "port": 59021}, "user": {"name": "finance-admin"}, "openvpn": {"common_name": "finance-admin", "source_address": "203.0.113.74:59021", "tunnel_ip": "10.8.0.50"}, "message": "MULTI: new connection by client \u0027finance-admin\u0027 will cause previous active sessions by this client to be dropped. Remember to use the --duplicate-cn option if you want multiple clients using the same certificate or username to concurrently connect."}
```

## Compatibility and references

The [OpenVPN 2.6 manual](https://openvpn.net/community-docs/community-articles/openvpn-2-6-manual.html) documents `--log-append`, log verbosity, certificate CN behavior, and the fact that a new same-CN client disconnects the old one unless `--duplicate-cn` is enabled. The line shapes are grounded in [upstream server-log examples](https://github.com/OpenVPN/openvpn/issues/403). This pack models a server file log, not a syslog envelope; exact lines can vary by server version and verbosity. Set `--verb` high enough to emit the selected messages.

[KUMA 4.2 lists an OpenVPN file/regexp normalizer](https://support.kaspersky.ru/kuma/4.2/255782), but this pack has not been tested against that normalizer. The ECS envelope around `event.original` is Eventum output, not native OpenVPN text. No Elastic OpenVPN server-log sample was used as a source reference.

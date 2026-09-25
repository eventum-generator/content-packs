# pfSense Firewall and IPsec Generator

Produces ECS JSON with native RFC 5424 pfSense `filterlog` CSV and `charon` IPsec messages in `event.original`. The firewall event fields follow Netgate's raw filter format; the IPsec messages follow its troubleshooting examples.

## Event Types

| Event | Baseline weight | Category |
|---|---:|---|
| `filterlog` pass | 72% | Firewall traffic |
| `filterlog` block | 28% | Firewall traffic |
| `charon` peer lookup / no peer config | Chain only | IPsec negotiation |
| `charon` IKE_SA / CHILD_SA established | Chain only | IPsec negotiation |
| `filterlog` permitted VPN traffic | Chain only | Firewall traffic |

Baseline traffic is 55% UDP DNS, 25% internal HTTPS, 15% external HTTPS and 5% SSH, each then passed or blocked by the above weights. These are synthetic proportions, not measured pfSense production rates. The FSM adds a chain after every 100 routine events.

## Anomaly Chain

Three `charon` peer-config lookups for `198.51.100.77` are followed by `no peer config found` messages. A subsequent `IKE_SA` and `CHILD_SA` for the same peer and tunnel establish successfully. The CHILD_SA covers the remote `10.42.42.0/24` subnet; three `filterlog` passes from `10.42.42.17` then reach an internal server on SMB, RDP and WinRM ports. A detection can correlate repeated failed peer negotiation, later tunnel establishment and access to administrative ports. The `no peer config found` line contains no peer IP by itself: join it to the preceding lookup by firewall host and time, then link established tunnel and traffic by peer, tunnel name, remote subnet and time.

The chain does not imply a firewall rule change or admin login; neither is present in the selected raw logs. Set `anomaly_mode: false` for only ordinary pass/block firewall traffic.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Purpose |
|---|---|---|
| `anomaly_mode` | `true` | Include the VPN chain; `false` emits only background |
| `hostname` | `fw01.corp.example` | Firewall host |
| `wan_ip` | `203.0.113.1` | Local VPN endpoint |
| `remote_peer_ip` | `198.51.100.77` | External peer in the chain |
| `remote_tunnel_ip` | `10.42.42.17` | Remote host inside the tunnel |
| `internal_target_ip` | `10.20.0.10` | Internal host reached by VPN traffic |
| `tunnel_name` | `corp-remote` | IPsec connection name |
| `suspicious_rule_tracker` | `1534283903` | Existing pass-rule tracker on `enc0` |

### Output Parameters

The shipped configuration writes to `output/events.json` and needs no output parameters or secrets. To send events to a SIEM, replace the `file` output with the required output plugin and configure its endpoint and credentials there.

## Usage

Run from the content-packs repository root:

```bash
eventum generate --path generators/network-pfsense/generator.yml --id pfsense --live-mode false
eventum generate --path generators/network-pfsense/generator.yml --id pfsense --live-mode true
```

The first command generates as fast as possible until interrupted. Live mode emits one event per second.

## Sample Output

This complete event was copied from the generated `output/events.json`:

```json
{
  "@timestamp": "2026-09-25T11:59:46+00:00",
  "data_stream": {
    "dataset": "pfsense.log",
    "namespace": "default",
    "type": "logs"
  },
  "destination": {
    "ip": "10.20.0.53",
    "port": 53
  },
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "block",
    "category": [
      "network"
    ],
    "dataset": "pfsense.log",
    "kind": "event",
    "original": "<134>1 2026-09-25T11:59:46+00:00 fw01.corp.example filterlog 72237 - - 115,,,1000000103,igb1.12,match,block,in,4,0x0,,63,48379,0,DF,17,udp,69,10.20.7.32,10.20.0.53,63575,53,49",
    "type": [
      "connection"
    ]
  },
  "host": {
    "name": "fw01.corp.example"
  },
  "log": {
    "syslog": {
      "priority": 134
    }
  },
  "message": "115,,,1000000103,igb1.12,match,block,in,4,0x0,,63,48379,0,DF,17,udp,69,10.20.7.32,10.20.0.53,63575,53,49",
  "network": {
    "bytes": 69,
    "direction": "inbound",
    "transport": "udp"
  },
  "observer": {
    "name": "fw01.corp.example",
    "product": "pfSense",
    "type": "firewall",
    "vendor": "Netgate"
  },
  "pfsense": {
    "ip": {
      "flags": "DF",
      "offset": 0,
      "tos": "0x0",
      "ttl": 63
    },
    "udp": {
      "length": 49
    }
  },
  "process": {
    "name": "filterlog",
    "pid": 72237
  },
  "related": {
    "ip": [
      "10.20.7.32",
      "10.20.0.53"
    ]
  },
  "rule": {
    "id": "1000000103"
  },
  "source": {
    "ip": "10.20.7.32",
    "port": 63575
  },
  "syslog": {
    "facility": {
      "code": 16
    },
    "priority": 134,
    "severity": {
      "code": 6
    }
  }
}
```

## Source and Scope

Netgate's [raw filter-log format](https://docs.netgate.com/pfsense/en/latest/monitoring/logs/raw-filter-format.html) defines the CSV positions, tracker and protocol-specific fields. Its [IPsec troubleshooting guide](https://docs.netgate.com/pfsense/en/latest/troubleshooting/ipsec-logs.html) shows peer lookup/failure and successful IKE/CHILD messages. Elastic's [pfSense syslog fixture](https://github.com/elastic/integrations/blob/main/packages/pfsense/data_stream/log/_dev/test/pipeline/test-pfsense-syslog.log) corroborates the RFC 5424 envelope and raw filter lines.

Coverage: 29/29 selected IPv4 TCP CSV positions and 23/23 IPv4 UDP positions are present in `event.original`; the RFC 5424 header is also present. Parsed ECS fields expose the main IPs, ports, action, tracker and IP/TCP/UDP details. The native raw record is the authoritative copy. IPv6, ICMP, DHCP, OpenVPN and pfSense administration logs are separate shapes and outside this generator. Remote log forwarding must enable firewall and IPsec streams to observe the complete chain.

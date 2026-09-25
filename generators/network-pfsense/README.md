# pfSense Firewall and IPsec Generator

Generates ECS JSON for a pfSense CE 2.9.0 firewall. `event.original` contains a complete RFC 5424 syslog record with native `filterlog` CSV or `charon` text. The selected profile uses an IKEv1 PSK tunnel-mode site-to-site IPsec connection, default `enc0` filtering, and explicitly logged LAN and IPsec pass rules. The firewall's default IPv4 deny rule logs WAN probes.

## Modes and traffic

`anomaly_mode: true` is the default. Both modes emit the same individual event types: LAN DNS and HTTPS passes, WAN HTTPS/SSH blocks, ordinary `charon` peer lookups, failed and successful negotiations, and passed IPsec traffic including separate SMB, RDP and WinRM access. `false` omits only the compact anomaly sequence.

| ECS action | Background occurrence | ECS category | Native process |
|---|---|---|---|
| `pass` | About 80% of randomly selected firewall records, plus three isolated administrative connections | network | `filterlog` |
| `block` | About 20% of randomly selected firewall records | network | `filterlog` |
| `ipsec-peer-lookup` | Three scheduled lookups before event 1,203 | network | `charon` |
| `ipsec-peer-not-found` | One scheduled mismatch | network | `charon` |
| `ipsec-ike-established` | Two scheduled successes | network | `charon` |
| `ipsec-child-established` | Two scheduled successes | network | `charon` |


| Firewall profile | Approximate ordinary-event weight | Interface | Action | Rule tracker |
|---|---:|---|---|---|
| LAN DNS | 30% | `igb1.12` | pass | `1690001001` |
| LAN internal HTTPS | 25% | `igb1.12` | pass | `1690001001` |
| LAN internet HTTPS | 20% | `igb1.12` | pass | `1690001001` |
| Unsolicited WAN HTTPS | 15% | `igb0` | block | `1000000103` |
| Unsolicited WAN SSH | 5% | `igb0` | block | `1000000103` |
| Remote IPsec DNS/HTTPS | 5% | `enc0` | pass | `1534283903` |

These weights are synthetic, not measured production rates. A separate low-rate maintenance pattern emits a failed peer lookup, later successful IKE and CHILD negotiation, and isolated administrative connections over the tunnel. Its native event kinds, IPs, ports, actions, and rule tracker are also present in the anomaly mode. Timestamps are monotonic at roughly one event per second, with randomized microseconds; real firewalls are usually burstier.

## Anomaly chain

Once, after 720 ordinary events, the peer `198.51.100.77` offers the mismatched Phase 1 ID `vpn-ext` three times. Each `charon` lookup is followed by `no peer config found`. It then offers the configured peer-IP identity `198.51.100.77`, establishing `IKE_SA` and `CHILD_SA` for `corp-remote`. Within the next three seconds, `10.42.42.17` connects through `enc0` to `10.20.0.10` on SMB 445, RDP 3389, and WinRM 5985. The 12 records occur within about 12 seconds. Netgate's troubleshooting guide ties `no peer config found` to a Phase 1 identifier mismatch; the changed offered ID explains the subsequent successful negotiation. This is a synthetic scenario assumption, not evidence of a firewall configuration change or compromise.

A detection can group the failed lookups by `host.name` and the peer address in the preceding `charon` lookup, then join the successful IKE/CHILD connection and the remote subnet's `enc0` traffic within a short window. The failure line itself has no peer IP: join it to the lookup by the native `<IKE-SA-ID>` context. Successful SA lines use `<connection|IKE-SA-ID>`. `CHILD_SA` reports traffic selectors rather than endpoint IPs. A single `pass`, `block`, IPsec success, or administrative port does not identify the anomaly.

## Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Purpose |
|---|---|---|
| `anomaly_mode` | `true` | Include the one-time 12-record chain |
| `hostname` | `fw01.corp.example` | Firewall host |
| `wan_ip` | `203.0.113.1` | Local IPsec endpoint and WAN address |
| `remote_peer_ip` | `198.51.100.77` | Remote IPsec endpoint |
| `remote_tunnel_ip` | `10.42.42.17` | Remote host inside the tunnel |
| `internal_target_ip` | `10.20.0.10` | Internal service host |
| `tunnel_name` | `corp-remote` | IPsec connection name |
| `ipsec_pass_rule_tracker` | `1534283903` | Existing logged IPsec-tab pass rule |

The default file output writes `output/events.json`. To deliver to a SIEM, replace it with the desired output plugin and configure its endpoint. A real pfSense collector needs both **Firewall Events** and **VPN Events** enabled under Remote Syslog Contents. Select the optional **syslog (RFC 5424)** log format; BSD format is the pfSense default. Native `syslogd` forwarding uses UDP. Logged pass traffic requires logging enabled on those firewall rules; pfSense normally logs blocks but not passes.

Run from the content-packs repository root:

```bash
eventum generate --path generators/network-pfsense/generator.yml --id pfsense --live-mode false
eventum generate --path generators/network-pfsense/generator.yml --id pfsense --live-mode true
```

Sample mode generates as fast as possible until interrupted. Live mode schedules one event per second with subsecond timestamp variation.

## Sample output

This complete JSON event was copied from a generator run:

```json
{
  "@timestamp": "2026-09-25T16:54:42.909019+00:00",
  "data_stream": {
    "dataset": "pfsense.log",
    "namespace": "default",
    "type": "logs"
  },
  "destination": {
    "ip": "203.0.113.1",
    "port": 22
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
    "original": "<134>1 2026-09-25T16:54:42.909019+00:00 fw01.corp.example filterlog 72237 - - 5,16777216,,1000000103,igb0,match,block,in,4,0x0,,51,55152,0,DF,6,tcp,60,198.51.100.91,203.0.113.1,57361,22,0,S,1636984417,,64240,,mss;sackOK;TS;nop;wscale",
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
  "message": "5,16777216,,1000000103,igb0,match,block,in,4,0x0,,51,55152,0,DF,6,tcp,60,198.51.100.91,203.0.113.1,57361,22,0,S,1636984417,,64240,,mss;sackOK;TS;nop;wscale",
  "network": {
    "direction": "inbound",
    "transport": "tcp"
  },
  "observer": {
    "name": "fw01.corp.example",
    "product": "pfSense",
    "type": "firewall",
    "vendor": "Netgate",
    "version": "2.9.0"
  },
  "pfsense": {
    "direction": "in",
    "interface": "igb0",
    "ip": {
      "flags": "DF",
      "id": 55152,
      "length": 60,
      "offset": 0,
      "tos": "0x0",
      "ttl": 51
    },
    "tcp": {
      "flags": "S",
      "length": 0,
      "window": 64240
    }
  },
  "process": {
    "name": "filterlog",
    "pid": 72237
  },
  "related": {
    "ip": [
      "198.51.100.91",
      "203.0.113.1"
    ]
  },
  "rule": {
    "id": "1000000103"
  },
  "source": {
    "ip": "198.51.100.91",
    "port": 57361
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

## Source and scope

- Netgate [pfSense CE release versions](https://docs.netgate.com/pfsense/en/latest/releases/versions.html), [raw filter-log grammar](https://docs.netgate.com/pfsense/en/latest/monitoring/logs/raw-filter-format.html), [firewall log and default deny example](https://docs.netgate.com/pfsense/en/latest/monitoring/logs/firewall.html), and [IPsec troubleshooting examples](https://docs.netgate.com/pfsense/en/latest/troubleshooting/ipsec-logs.html) define the selected native bodies and their interpretation. The IPsec examples are edited for brevity in Netgate's own guide.
- Netgate's [RFC 5424 log setting](https://docs.netgate.com/pfsense/en/latest/monitoring/logs/settings.html), [remote logging options](https://docs.netgate.com/pfsense/en/latest/monitoring/logs/remote.html), [IPsec filter mode](https://docs.netgate.com/pfsense/en/latest/vpn/ipsec/advanced.html), and [IPsec firewall rules](https://docs.netgate.com/pfsense/en/latest/vpn/ipsec/firewall-rules.html) define the assumed setup. [Raw pfSense `charon` records](https://redmine.pfsense.org/issues/11761) show the attempt context and SA identifiers; a [syslog `charon` capture](https://redmine.pfsense.org/attachments/4375) and [published `filterlog` fixture](https://github.com/elastic/integrations/blob/main/packages/pfsense/data_stream/log/_dev/test/pipeline/test-pfsense-syslog.log) corroborate the syslog envelope.
- Netgate's [NAT processing order](https://docs.netgate.com/pfsense/en/latest/nat/process-order.html) explains why a LAN ingress pass shows the pre-outbound-NAT private source. These records make no claim that translation occurred. The WAN blocks target the firewall's public IP, without a port-forward translation.

The selected IPv4 UDP/TCP records include all 23/29 documented CSV positions in `event.original`. `pfsense.direction` is PF's `in` interface direction; `network.direction` describes the traffic's broader network orientation. `pfsense.ip.length` is the logged packet length, not a flow byte total. IPv6, ICMP, DHCP, NAT-translation events, and administrative login logs are outside this profile.

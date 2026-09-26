# pfSense Firewall and IPsec Generator

Generates ECS JSON for a pfSense CE 2.9.0 firewall. `event.original` contains a complete RFC 5424 syslog record with native `filterlog` CSV or `charon` text. The selected profile uses an IKEv1 PSK tunnel-mode site-to-site IPsec connection, default `enc0` filtering, and explicitly logged LAN and IPsec pass rules. The firewall's default IPv4 deny rule logs WAN probes.

## Modes and traffic

`anomaly_mode: true` is the default. Both modes emit the same individual event types: LAN DNS and HTTPS passes, WAN HTTPS/SSH blocks, ordinary `charon` peer lookups, failed and successful negotiations, and passed IPsec traffic including separate SMB, RDP and WinRM access. `false` omits only the compact anomaly sequence.

| ECS action | Selected background occurrence | Native process |
| --- | --- | --- |
| `pass`, `block` | Weighted LAN/WAN packet profiles and active-tunnel packets | `filterlog` |
| `ipsec-peer-lookup`, `ipsec-peer-not-found` | One failed identity lookup pair per maintenance cycle | `charon` |
| `ipsec-ike-established`, `ipsec-child-established` | Correct peer identity lookup followed by establishment | `charon` |
| `ipsec-child-closed`, `ipsec-ike-deleting` | Existing CHILD and IKE cleanup before the next negotiation | `charon` |

| Firewall profile | Approximate ordinary-event weight | Interface | Action | Rule tracker |
|---|---:|---|---|---|
| LAN DNS | 30% | `igb1.12` | pass | `1690001001` |
| LAN internal HTTPS | 25% | `igb1.12` | pass | `1690001001` |
| LAN internet HTTPS | 20% | `igb1.12` | pass | `1690001001` |
| Unsolicited WAN HTTPS | 15% | `igb0` | block | `1000000103` |
| Unsolicited WAN SSH | 5% | `igb0` | block | `1000000103` |
| Remote IPsec DNS/HTTPS | 5% | `enc0` | pass | `1534283903` |

These weights are synthetic, not measured production rates. VPN selection is conditioned on an active CHILD_SA; while the tunnel is down, that weight uses LAN HTTPS instead. Administrative ports are also emitted independently during ordinary active-tunnel traffic in both modes. A pass record means that a packet matched a pass rule, not that a connection or authentication succeeded.

The source profile emits one selected record every five seconds with microsecond log timestamps. Ordinary maintenance has a bounded 720-routine-record phase, roughly one hour, and pauses during an episode. It emits a failed peer lookup near phase100s, a valid lookup/IKE/CHILD sequence near phase490-500s when no tunnel exists, individual 445/3389/5985 packets at phases1495/2245/2995s, and CHILD/IKE cleanup near phase3245-3250s. An episode can establish the tunnel earlier, in which case ordinary establishment is skipped until cleanup. No tunnel is assumed active at capture start, and every emitted `enc0` pass requires a modeled active CHILD_SA. The stream is a sparse training subset, rather than every packet or every IKE exchange.

## Anomaly Chain

Every six hours of generated time by default, the peer `198.51.100.77` offers the mismatched Phase 1 ID `vpn-ext` three times. Each `charon` lookup is followed by `no peer config found`. It then offers the configured peer-IP identity `198.51.100.77`, establishing `IKE_SA` and `CHILD_SA` for `corp-remote`. On the next three five-second ticks, `10.42.42.17` connects through `enc0` to `10.20.0.10` on SMB 445, RDP 3389, and WinRM 5985. The 12 core records span about 55 seconds. If an earlier tunnel is still active, the generator first logs its CHILD closure and IKE deletion using its current native IDs and SPIs. Each new episode uses fresh IKE attempt IDs, a new CHILD ID and fresh nonzero SPIs. Cleanup is emitted in both modes, and successful tunnel traffic cannot continue after closure without another establishment. The configured interval is measured from the first mismatched lookup; due scheduling waits for the current ordinary native pair and any needed cleanup. Default observed first lookups are at 6h00m05s, 12h00m10s, 18h00m15s and 24h00m20s. In the tested custom three-hour run, cleanup increases one interval by ten seconds. The next episode is not replayed in a catch-up burst. Netgate's troubleshooting guide ties `no peer config found` to a Phase 1 identifier mismatch; the changed offered ID explains the subsequent successful negotiation. This is a synthetic scenario assumption, not evidence of a firewall configuration change or compromise.

A detection can group the failed lookups by `host.name` and the peer address in the preceding `charon` lookup, then join the successful IKE/CHILD connection and the remote subnet's `enc0` traffic within a two-minute window at the shipped cadence. The failure line itself has no peer IP: join it to the lookup by the native `<IKE-SA-ID>` context. Successful SA lines use `<connection|IKE-SA-ID>`. `CHILD_SA` reports traffic selectors rather than endpoint IPs. A single `pass`, `block`, IPsec success, or administrative port does not identify the anomaly.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Purpose |
|---|---|---|
| `anomaly_mode` | `true` | Include recurring 12-record core chains amid background |
| `anomaly_interval_hours` | `6` | Generated-time recurrence; finite numeric values below one hour clamp to one |
| `hostname` | `fw01.corp.example` | Firewall host |
| `wan_ip` | `203.0.113.1` | Local IPsec endpoint and WAN address |
| `remote_peer_ip` | `198.51.100.77` | Remote IPsec endpoint |
| `remote_tunnel_ip` | `10.42.42.17` | Remote host inside the tunnel |
| `internal_target_ip` | `10.20.0.10` | Internal service host |
| `tunnel_name` | `corp-remote` | IPsec connection name |
| `ipsec_pass_rule_tracker` | `1534283903` | Existing logged IPsec-tab pass rule |

Use IPv4 addresses with the internal and remote hosts in distinct /24 traffic-selector networks. Keep ASCII hostname and tunnel-name tokens without spaces or syslog delimiters. Keep the shipped five-second/count-one cadence for the documented chain and maintenance timing.

### Output Parameters

The default file output writes `output/events.json`. To deliver to a SIEM, replace it with the desired output plugin and configure its endpoint. A real pfSense collector needs both **Firewall Events** and **VPN Events** enabled under Remote Syslog Contents. Select the optional **syslog (RFC 5424)** log format; BSD format is the pfSense default. Native `syslogd` forwarding uses UDP. Logged pass traffic requires logging enabled on those firewall rules; pfSense normally logs blocks but not passes. The selected IPsec diagnostic profile sets IKE SA, IKE Child SA, and Configuration Backend to Diag, and all other IPsec log settings to Control, following Netgate's troubleshooting instructions.

## Usage

Run from the content-packs repository root:

```bash
uv run --project ../eventum eventum generate --path generators/network-pfsense/generator.yml --id pfsense --live-mode true --keep-order true
```

Sample mode generates as fast as possible until interrupted. For a finite batch, copy the config beside the original and set cron `start: 2026-09-25T00:00:00Z` and `end: 2026-09-26T01:00:00Z`, then run that path with `--live-mode false --keep-order true`. The 25-hour window emits 18,001 records and four complete default episodes; background mode has zero. Custom three-hour recurrence yields eight episodes in the same window. Raw and ECS clocks normalize to UTC even with non-UTC CLI input. A finite window can end with one established ordinary tunnel still active.

## Sample Output

This complete JSON event was copied from a generator run:

```json
{
  "@timestamp": "2026-09-25T06:00:45.172919+00:00",
  "data_stream": {
    "dataset": "pfsense.log",
    "namespace": "default",
    "type": "logs"
  },
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "ipsec-child-established",
    "category": [
      "network"
    ],
    "dataset": "pfsense.log",
    "kind": "event",
    "original": "<30>1 2026-09-25T06:00:45.172919+00:00 fw01.corp.example charon 18610 - - 16[IKE] <corp-remote|33> CHILD_SA corp-remote{7} established with SPIs 98e17ba1_i acf2193c_o and TS 10.20.0.0/24|/0 === 10.42.42.0/24|/0",
    "type": [
      "info"
    ]
  },
  "host": {
    "name": "fw01.corp.example"
  },
  "log": {
    "syslog": {
      "priority": 30
    }
  },
  "message": "16[IKE] <corp-remote|33> CHILD_SA corp-remote{7} established with SPIs 98e17ba1_i acf2193c_o and TS 10.20.0.0/24|/0 === 10.42.42.0/24|/0",
  "observer": {
    "name": "fw01.corp.example",
    "product": "pfSense",
    "type": "firewall",
    "vendor": "Netgate",
    "version": "2.9.0"
  },
  "process": {
    "name": "charon",
    "pid": 18610
  },
  "syslog": {
    "facility": {
      "code": 3
    },
    "priority": 30,
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


The selected close/delete bodies also follow the upstream strongSwan 5.9.14 [IKEv1 CHILD deletion source](https://github.com/strongswan/strongswan/blob/5.9.14/src/libcharon/sa/ikev1/tasks/quick_delete.c) and [IKE deletion source](https://github.com/strongswan/strongswan/blob/5.9.14/src/libcharon/sa/ikev1/tasks/isakmp_delete.c). These source formats are not proof of the library build bundled with CE 2.9.0. Closing records retain the established CHILD ID, IKE context, SPIs and selectors. Their synthetic SA counters include unlogged traffic and replies, so they cannot be derived from this filtered `filterlog` subset. No packet or SA history grows: state retains at most one IKE and one CHILD plus scalar native counters, a bounded routine phase and fixed transition slots. Closed CHILD payloads and deleted IKE IDs are cleared.

The [maintained pfSense filterlog IPv4 formatter](https://github.com/pfsense/FreeBSD-ports/blob/devel/sysutils/filterlog/files/print-ip.c) prints the UDP header's `uh_ulen` as the final UDP length, including its eight-byte header. Thus a selected 69-byte IPv4 packet with a 20-byte IP header has UDP length49 and payload41. TCP packet60 has zero application payload and twenty bytes of TCP options. Packet lengths are not bidirectional flow totals.

Older real pfSense captures and current field-complete vendor documents support this selected format. A complete CE2.9.0 raw capture of every modeled class, the exact bundled strongSwan build and live SIEM/parser compatibility remain unverified. No administrator authentication, IPv6, ICMP, DHCP, full IPsec handshake, cryptographic validation or NAT-translation event is asserted. Native23/29 CSV positions are all retained; no source-specific Elastic normalized reference percentage is claimed for this intentionally limited dual stream.

# F5 BIG-IP Advanced Firewall Manager

Generates F5 BIG-IP AFM (Advanced Firewall Module) layer 3/4 firewall and Network DoS messages in the ArcSight CEF format as ECS JSON, for training SIEM content on perimeter firewall telemetry. `event.original` holds the CEF message body without a syslog envelope. The source is one BIG-IP that publishes five virtual servers on four internet-facing addresses and logs through a remote logging profile with the ArcSight formatter. This is the AFM stream, not BIG-IP ASM / Advanced WAF HTTP request logging.

## Event Types

Shares measured on the final default capture (156 h, `anomaly_mode: true`, 68,853 records).

| CEF signature / `act` | Record | Share | Category |
|---|---|---:|---|
| `23003137` / `Accept` | Allowed connection on a rule-logging virtual server | 52.62% (36230) | Network |
| `23003137` / `Open` | Flow start on a flow-logging virtual server | 16.69% (11495) | Network |
| `23003137` / `Closed` | Flow end on a flow-logging virtual server | 16.63% (11449) | Network |
| `23003137` / `Drop` | Global-policy drop on a closed port | 13.42% (9237) | Network |
| attack name / `Drop` | Network DoS `Attack Sampled` | 0.42% (286) | Network, Intrusion Detection |
| attack name / `None` | Network DoS `Attack Started` | 0.11% (78) | Network, Intrusion Detection |
| attack name / `None` | Network DoS `Attack Stopped` | 0.11% (78) | Network, Intrusion Detection |

Network Event records (signature `23003137`) carry `act=Accept` with the matched ACL rule name on the three rule-logging virtual servers (HTTPS, SMTP, DNS), and `act=Open` / `act=Closed` with an empty rule name on the two flow-logging virtual servers (HTTP, VPN), as in the guide's examples; an `Open` and its `Closed` share the source and destination address and port. Traffic to a port no virtual server listens on matches the global policy (`cs1Label=Global`, empty `cs1`) and is logged as `act=Drop` with `drop_reason` `Policy`. Network DoS records use the attack name as signature and the action as name: `Attack Started` and `Attack Stopped` with action `None` and empty addresses, `Attack Sampled` with action `Drop` and the sampled packet's addresses, all sharing `cn1` (`attack_id`). Every client, address, port and record type used by the chain occurs in ordinary background in both modes. No field labels an episode.

## Background Model

Each one-second tick emits at most one record: the earliest due record, otherwise nothing. Three independent Poisson streams feed the queue:

- **Service use** (0.055 per second, scaled by an hour-of-day factor: 07:00-19:00 UTC 1.38, 19:00-23:00 0.92, night 0.46): a client picks one virtual server by weight (HTTPS 50, DNS 18, HTTP 12, VPN 12, SMTP 8) and opens 1-4 connections to it with log-normal gaps. HTTP flows last seconds, VPN flows about 25 minutes (log-normal).
- **Closed-port hits** (0.0055 per second, flat over the day, as internet scanning is): a client hits 1-5 closed ports (21, 22, 23, 445, 1433, 3306, 3389, 5900, 8080, 8443, in random order) of one public address, 1-3 attempts per port, gaps between ports log-normal with median 20 s; in half of the cases it then uses a virtual server on that address about 90 s later.
- **Network DoS attacks** (one per two hours on average): a start, 1-12 dropped samples about 40 s apart (log-normal), then a stop. Attack names are drawn from the guide's DoS attack tables; attack IDs are random 32-bit values.

Clients are 160 documentation-range addresses (`198.51.100.0/24`, `192.0.2.0/24`) with fixed random log-normal activity weights, shared by all three streams, so every client acts independently and a busy client is busy everywhere. Source ports are random ephemeral ports.

## Anomaly Chain

`anomaly_mode` defaults to `true`. With `false` the generator emits the background only and the complete chain never occurs.

Sequence, all for one client C (`source.ip`) and one public address A (`destination.ip`):

1. `act=Drop` (global policy, `drop_reason` `Policy`), TCP from C to A on closed port P1.
2. `act=Drop` from C to A on a second closed port P2.
3. `act=Drop` from C to A on a third closed port P3 (four or five ports in about four episodes in ten); each port gets 1-3 attempts.
4. `act=Accept` or `act=Open` from C to a virtual server on A (HTTPS or HTTP on the web address, SMTP, VPN, DNS), followed by `act=Closed` on flow-logging virtual servers.

Linking fields: `source.ip` / `src` (C) and `destination.ip` / `dst` (A) in all steps, distinct `destination.port` / `dpt` in steps 1-3.

Recurrence: the first episode starts within the first `anomaly_interval_hours` (at most 24 h) of generation, at a time of day drawn from the hour-of-day factor of service use. Each later episode is due `anomaly_interval_hours` after the actual start of the previous one (default 24, minimum 2) and starts within a window centred on that due time, a quarter of the interval wide (at most 6 hours), favouring busier hours. A 156-hour default capture has 6 episodes, the first after 14.2 h, with gaps of 24.0-26.8 h; a 156-hour run at 6 hours has 26 episodes with gaps of 5.2-6.7 h. Each start is weighted towards busy hours only within its own window, so at the 24-hour default consecutive starts can drift into the evening (14:00 to 20:00 UTC in one measured capture, 18:00 to 22:44 UTC in another) before busy hours pull them back. Episodes typically span 1-9 minutes from the first drop to the allowed connection, occasionally longer (17 minutes in one capture).

Variation: the client and the address differ from the previous episode's; both are drawn with the background weights. Ports, attempt counts and gaps come from the same law as the background closed-port hits.

Detection idea: one source is dropped on three or more distinct ports of one address and then gets through to a service on that address within an hour (a port scan that finds an open service). Every fragment occurs in background: a 156 h background capture holds 810-920 sets of drops on three or more distinct ports of one address and 4,400-6,200 allowed connections within an hour of drops on one or two ports of the same address. Only the complete sequence is kept out of the background, by a guard on the final step: an ordinary allowed connection that would complete the chain with any earlier records (drops of the same client on three or more distinct ports of that address in the preceding hour) is not made; the drops stay as generated. In six 156-hour background captures (6,047 sets of drops on three distinct ports), an allowed connection from the same client to that address follows at 2.0-2.2 per hour just after the one-hour window, with no gap beyond it; connections from that client to other addresses (2.6-3.0 per hour) and from other clients to that address (129-136 per hour) keep the same rate inside and outside the window.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Meaning |
|---|---|---|
| `anomaly_mode` | `true` | Add periodic episodes to the background |
| `anomaly_interval_hours` | `24` | Episode interval in source hours, 2-8760 |
| `bigip_host` | `bigip-afm.lab.example` | `dvchost` and `observer.name` |
| `bigip_management_ip` | `10.0.0.5` | `dvc` and `observer.ip` |
| `product_version` | `11.3.0.2790.300` | CEF device version (the guide's DoS example build) |
| `vlan` | `/Common/external` | `cs2` (`vlan`) |
| `route_domain` | `0` | `cn4` (`route_domain`) |
| `client_count` | `160` | Number of internet clients, 20-500 |
| `virtual_servers` | 5 virtual servers | List of `name`, `address`, `port`, `protocol` (`TCP`/`UDP`), `logging` (`rule` logs `Accept`, `flow` logs `Open`/`Closed`), `rule` (ACL rule name for `rule` logging), `weight`; at least two distinct addresses |
| `deny_rule` | `deny_inbound` | `cs5` (`acl_rule_name`) of global-policy drops |
| `closed_ports` | 10 ports | Ports hit by closed-port attempts and episodes; no virtual server may use them, and at least five are needed for episodes to vary |

### Output Parameters

The shipped config writes `output/events.json` with the `json` formatter and needs no `${params.*}` or `${secrets.*}`. To send events elsewhere, replace the `output` section, for example:

```yaml
output:
  - opensearch:
      hosts: ["${params.opensearch_url}"]
      username: ${params.opensearch_user}
      password: ${secrets.opensearch_password}
      index: f5-bigip-afm
```

A CEF collector that parses the native format needs `event.original` rather than the surrounding JSON.

## Usage

Live mode:

```bash
eventum generate --path generators/network-f5-bigip-afm/generator.yml --id f5-afm --live-mode true
```

Batch mode needs a bounded input: add `start` and `end` to the `cron` input, then run:

```bash
eventum generate --path generators/network-f5-bigip-afm/generator.yml --id f5-afm --live-mode false
```

## Limitations

- The F5 External Monitoring Implementations 13.0.0 guide gives full CEF lines for Network Event `Accept`, `Open` and `Closed` (IPv4) and `Accept` (IPv6), and for a Network DoS `Attack Sampled` record, all from BIG-IP 11.3.0. Key order follows those lines. There is no CEF example for a Network Event `Drop`, for Network DoS `Attack Started` / `Attack Stopped`, or for the global context: `Drop` uses the Network Event layout with `drop_reason` `Policy` (a value from the field table), start/stop records use the DoS layout with action `None` and empty addresses and VLAN (as in the guide's Reporting Server start example), and the global context reuses the IPv6 example's `cs1= cs1Label=Global`. Later BIG-IP versions add fields not modeled here.
- Only IPv4 TCP/UDP traffic on one VLAN and route domain is modeled: no IPv6 (`c6a2`/`c6a3` stay empty), ICMP, `Reject`, `Accept decisively`, `Established`, IP intelligence, DNS or SIP DoS, or application DoS records. Drops always come from one global deny rule; hardware-detected errors such as bad checksums appear only as DoS attack names.
- Virtual server names, rule names, weights, rates, flow durations and DoS attack mix are training assumptions, not measured production values. The device time zone is UTC. `rt` has one-second resolution, and the generator emits at most one record per second.
- The ECS document has no Elastic integration counterpart for AFM CEF; `f5.afm` keys follow the CEF labels (`virtual_name`, `vlan`, `drop_reason`, `route_domain`, `acl_rule_name`, `attack_id`, `attack_status`), plus `attack_name`, `action` and `context_type`.
- Episode start times follow the hour-of-day factor of service use, while background closed-port hits are flat over the day, so drop bursts are somewhat more frequent in daytime episodes than in background.
- KUMA 4.2 lists F5 BIG-IP AFM CEF over Syslog as a supported source; compatibility with its normalizer has not been tested.
- DoS attack start and stop records carry `cn4=0` (route domain); the guide's Reporting Server start example leaves the route domain empty.

## Sample Output

The `Accept` that completes the first episode (step 4: `198.51.100.156` reaches the HTTPS virtual server on `203.0.113.10` after drops on three closed ports), copied byte for byte from the final default capture (line 5920):

```json
{"@timestamp": "2026-09-01T14:13:03+00:00", "destination": {"ip": "203.0.113.10", "port": 443}, "ecs": {"version": "8.17.0"}, "event": {"action": "accept", "category": ["network"], "code": "23003137", "kind": "event", "original": "CEF:0|F5|Advanced Firewall Module|11.3.0.2790.300|23003137|Network Event|8|rt=Sep 01 2026 14:13:03 dvchost=bigip-afm.lab.example dvc=10.0.0.5 src=198.51.100.156 spt=20809 dst=203.0.113.10 dpt=443 proto=TCP cs1=/Common/www_https_vs cs1Label=virtual_name cs2=/Common/external cs2Label=vlan act=Accept c6a2= c6a2Label=source_address c6a3= c6a3Label=destination_address cs3= cs3Label=drop_reason cn4=0 cn4Label=route_domain cs5=allow_https cs5Label=acl_rule_name", "severity": 8, "type": ["connection", "allowed"]}, "f5": {"afm": {"acl_rule_name": "allow_https", "action": "Accept", "drop_reason": "", "route_domain": 0, "virtual_name": "/Common/www_https_vs", "vlan": "/Common/external"}}, "network": {"transport": "tcp", "type": "ipv4"}, "observer": {"ip": ["10.0.0.5"], "name": "bigip-afm.lab.example", "product": "Advanced Firewall Module", "type": "firewall", "vendor": "F5", "version": "11.3.0.2790.300"}, "related": {"ip": ["198.51.100.156", "203.0.113.10", "10.0.0.5"]}, "rule": {"name": "allow_https"}, "source": {"ip": "198.51.100.156", "port": 20809}}
```

## References

- [F5 External Monitoring Implementations 13.0.0: AFM, Network DoS and DNS event fields and CEF examples](https://techdocs.f5.com/kb/en-us/products/big-ip_ltm/manuals/product/bigip-external-monitoring-implementations-13-0-0/15.html)
- [KUMA 4.2 supported sources](https://support.kaspersky.ru/kuma/4.2/255782)
- [Elastic ECS field reference](https://www.elastic.co/docs/reference/ecs/ecs-field-reference)

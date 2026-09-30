# F5 BIG-IP Advanced Firewall Manager

Generates F5 BIG-IP AFM (Advanced Firewall Module) layer 3/4 firewall and Network DoS messages in the ArcSight CEF format as ECS JSON, for training SIEM content on perimeter firewall telemetry. `event.original` holds the CEF message body without a syslog envelope. The source is one BIG-IP that publishes five virtual servers on four internet-facing addresses and logs through a remote logging profile with the ArcSight formatter. This is the AFM stream, not BIG-IP ASM / Advanced WAF HTTP request logging.

## Event Types

Shares of default output (`anomaly_mode: true`), about 28,400 records a day.

| CEF signature / `act` | Record | Share | Category |
|---|---|---:|---|
| `23003137` / `Accept` | Allowed connection on a rule-logging virtual server | 52.49% (59115) | Network |
| `23003137` / `Open` | Flow start on a flow-logging virtual server | 16.69% (18800) | Network |
| `23003137` / `Closed` | Flow end on a flow-logging virtual server | 16.67% (18777) | Network |
| `23003137` / `Drop` | Global-policy drop on a closed port | 13.99% (15760) | Network |
| attack name / `Drop` | Network DoS `Attack Sampled` | 0.10% (109) | Network, Intrusion Detection |
| attack name / `None` | Network DoS `Attack Started` | 0.02% (26) | Network, Intrusion Detection |
| attack name / `None` | Network DoS `Attack Stopped` | 0.02% (26) | Network, Intrusion Detection |

Network Event records (signature `23003137`) carry `act=Accept` with the matched ACL rule name on the three rule-logging virtual servers (HTTPS, SMTP, DNS), and `act=Open` / `act=Closed` with an empty rule name on the two flow-logging virtual servers (HTTP, VPN), as in the guide's examples; an `Open` and its `Closed` share the source and destination address and port. Traffic to a port no virtual server listens on matches the global policy (`cs1Label=Global`, empty `cs1`) and is logged as `act=Drop` with `drop_reason` `Policy`. Network DoS records use the attack name as signature and the action as name: `Attack Started` and `Attack Stopped` with action `None` and empty addresses, `Attack Sampled` with action `Drop` and the sampled packet's addresses, all sharing `cn1` (`attack_id`). Every client, address, port and record type used by the chain occurs in ordinary traffic in both modes. No field labels an episode.

## Traffic Model

The device logs about 28,400 records a day. Volume follows the day: about 360 records an hour at 03:00-04:00 UTC, rising to about 1,900 an hour at 13:00-14:00 UTC. Service use carries the daily curve; scanners stay flat over the day at about 180 records an hour, about 150 of them closed-port hits. Day totals vary by about 3%.

Clients are 400 documentation-range addresses (`198.51.100.0/24`, `192.0.2.0/24`) listed in `samples/clients.csv`, each with a role and a fixed activity weight:

- **Users** (360, log-normal weights between 0.2 and 8): service sessions to one virtual server picked by weight (HTTPS 50, DNS 18, HTTP 12, VPN 12, SMTP 8), 1-4 connections each with log-normal gaps (median 15 s). HTTP flows last seconds, VPN flows about 25 minutes (log-normal). About one session start in sixty is instead a hit on one or two closed ports of an address (another protocol tried, a misconfigured tool), followed by use of a virtual server on that address in about two cases in three.
- **Scanners** (40, weights between 0.6 and 1.6): hits on 1-5 closed ports (21, 22, 23, 445, 1433, 3306, 3389, 5900, 8080, 8443, in random order) of one public address drawn uniformly, 1-3 attempts per port. After hits on one or two ports, a scanner reaches a virtual server on that address about 100 s later (median) in four cases in five; after hits on three or more ports it does not reach a service on that address within the next hour. A client returns to closed ports of the same address no sooner than an hour after its previous attempt there. Scanners make about 1,150 of these hits a day, users about 200.
- **Network DoS attacks** (about six a day, at random times): a start, 1-12 dropped samples about 40 s apart (log-normal) from one scanner address to one virtual server, then a stop. Attack names come from the guide's DoS attack tables; attack IDs are random 32-bit values.

Repeated attempts on one port are a median 5 s apart (90% within 15 s), consecutive ports a median 23 s apart. Source ports are random ephemeral ports; a port in use by an open flow of the same client is not reused.

## Anomaly Chain

`anomaly_mode` defaults to `true`. With `false` the output holds ordinary traffic only and the complete chain never occurs.

Sequence, all for one client C (`source.ip`) and one public address A (`destination.ip`):

1. `act=Drop` (global policy, `drop_reason` `Policy`), TCP from C to A on closed port P1.
2. `act=Drop` from C to A on a second closed port P2.
3. `act=Drop` from C to A on a third closed port P3 (four or five ports in about four episodes in ten); each port gets 1-3 attempts.
4. `act=Accept` or `act=Open` from C to a virtual server on A (HTTPS or HTTP on the web address, SMTP, VPN, DNS), followed by `act=Closed` on flow-logging virtual servers.

Linking fields: `source.ip` / `src` (C) and `destination.ip` / `dst` (A) in all steps, distinct `destination.port` / `dpt` in steps 1-3. An episode spans a median of about 3 minutes from the first drop to the allowed connection (43 s to 18 minutes).

Recurrence: the first episode starts within the first `anomaly_interval_hours` (at most 24 h) of output, at a time of day drawn from the volume curve. Each later episode is due `anomaly_interval_hours` after the actual start of the previous one (default 24, minimum 2) and starts within a window centred on that due time, a quarter of the interval wide (at most 6 hours), favouring busier hours. At the default interval episodes are 21-27 h apart, at 6 hours 5.25-6.75 h. Each start is weighted towards busy hours only within its own window, so consecutive starts can stay in the evening or night for several days before busy hours pull them back.

Variation: C is one of the scanners that hit closed ports of A at least five times a day on average, A one of the four public addresses; both differ from the previous episode's, and C has not tried A in the preceding hour. Ports, attempt counts and gaps follow the scanners' ordinary law.

Detection idea: one source is dropped on three or more distinct ports of one address and then gets through to a service on that address within an hour (a port scan that finds an open service). Every fragment occurs in ordinary traffic: four days hold about 1,200 sets of drops on three or more distinct ports of one address and about 4,500 allowed connections within an hour of drops on one or two ports of the same address. With `anomaly_mode: true` each episode adds its own records (about seven), so the drop count and the number of three-port sets are about one episode's worth higher.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Meaning |
|---|---|---|
| `anomaly_mode` | `true` | Add periodic episodes to the ordinary traffic |
| `anomaly_interval_hours` | `24` | Episode interval in hours, 2-8760 |
| `bigip_host` | `bigip-afm.lab.example` | `dvchost` and `observer.name` |
| `bigip_management_ip` | `10.0.0.5` | `dvc` and `observer.ip` |
| `product_version` | `11.3.0.2790.300` | CEF device version (the guide's DoS example build) |
| `vlan` | `/Common/external` | `cs2` (`vlan`) |
| `route_domain` | `0` | `cn4` (`route_domain`) |
| `virtual_servers` | 5 virtual servers | List of `name`, `address`, `port`, `protocol` (`TCP`/`UDP`), `logging` (`rule` logs `Accept`, `flow` logs `Open`/`Closed`), `rule` (ACL rule name for `rule` logging), `weight`; at least two distinct addresses |
| `deny_rule` | `deny_inbound` | `cs5` (`acl_rule_name`) of global-policy drops |
| `closed_ports` | 10 ports | Ports hit by closed-port attempts and episodes; no virtual server may use them, at least five are needed |

Client addresses, roles (`user` or `scanner`) and weights are in `samples/clients.csv`; edit that file to change the client population (at least 50 users and 4 scanners).

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

Batch mode needs a finite window: set `start` and `end` in every file under `patterns/` (keep the start at 04:00 UTC so the daily curve stays in place, for example `start: "2026-09-01T04:00:00Z"` and `end: "2026-09-05T04:00:00Z"`), then run:

```bash
eventum generate --path generators/network-f5-bigip-afm/generator.yml --id f5-afm --live-mode false
```

Daily volumes are the `multiplier.ratio` values in `patterns/svc-floor.yml`, `patterns/svc-day.yml` (service use) and `patterns/scan.yml` (closed-port hits); `patterns/dos.yml` sets the DoS attack rate.

Performance: about 2,100 records per second of CPU time (14 days, 397,777 records, in 187 s of CPU time).

## Limitations

- The F5 External Monitoring Implementations 13.0.0 guide gives full CEF lines for Network Event `Accept`, `Open` and `Closed` (IPv4) and `Accept` (IPv6), and for a Network DoS `Attack Sampled` record, all from BIG-IP 11.3.0. Key order follows those lines. There is no CEF example for a Network Event `Drop`, for Network DoS `Attack Started` / `Attack Stopped`, or for the global context: `Drop` uses the Network Event layout with `drop_reason` `Policy` (a value from the field table), start/stop records use the DoS layout with action `None` and empty addresses and VLAN (as in the guide's Reporting Server start example), and the global context reuses the IPv6 example's `cs1= cs1Label=Global`. Later BIG-IP versions add fields not modeled here.
- Only IPv4 TCP/UDP traffic on one VLAN and route domain is modeled: no IPv6 (`c6a2`/`c6a3` stay empty), ICMP, `Reject`, `Accept decisively`, `Established`, IP intelligence, DNS or SIP DoS, or application DoS records. Drops always come from one global deny rule; hardware-detected errors such as bad checksums appear only as DoS attack names.
- Virtual server names, rule names, weights, rates, flow durations and DoS attack mix are training assumptions, not measured production values. The device time zone is UTC and `rt` has one-second resolution.
- Records that a real device would log milliseconds apart are seconds apart: repeated attempts on one closed port are a median 5 s apart.
- In ordinary traffic, a source that hits three or more closed ports of an address never reaches a service on that address within the next hour, and no source returns to closed ports of the same address within an hour; real scanners are less regular.
- Closed-port hits come mostly from 40 scanner addresses that use services only right after such hits; ordinary users hit at most two closed ports at a time.
- Episode start times follow the volume curve, while scanners' closed-port hits are flat over the day, so episodes fall into daytime more often than ordinary three-port sets do.
- The ECS document has no Elastic integration counterpart for AFM CEF; `f5.afm` keys follow the CEF labels (`virtual_name`, `vlan`, `drop_reason`, `route_domain`, `acl_rule_name`, `attack_id`, `attack_status`), plus `attack_name`, `action` and `context_type`.
- KUMA 4.2 lists F5 BIG-IP AFM CEF over Syslog as a supported source; compatibility with its normalizer has not been tested.
- DoS attack start and stop records carry `cn4=0` (route domain); the guide's Reporting Server start example leaves the route domain empty.

## Sample Output

The `Accept` that completes an episode (step 4: scanner `192.0.2.175` reaches the HTTPS virtual server on `203.0.113.10` after drops on ports 22, 21 and 3306 within 82 s), copied byte for byte from default output:

```json
{"@timestamp": "2026-09-04T10:49:54+00:00", "destination": {"ip": "203.0.113.10", "port": 443}, "ecs": {"version": "8.17.0"}, "event": {"action": "accept", "category": ["network"], "code": "23003137", "kind": "event", "original": "CEF:0|F5|Advanced Firewall Module|11.3.0.2790.300|23003137|Network Event|8|rt=Sep 04 2026 10:49:54 dvchost=bigip-afm.lab.example dvc=10.0.0.5 src=192.0.2.175 spt=38537 dst=203.0.113.10 dpt=443 proto=TCP cs1=/Common/www_https_vs cs1Label=virtual_name cs2=/Common/external cs2Label=vlan act=Accept c6a2= c6a2Label=source_address c6a3= c6a3Label=destination_address cs3= cs3Label=drop_reason cn4=0 cn4Label=route_domain cs5=allow_https cs5Label=acl_rule_name", "severity": 8, "type": ["connection", "allowed"]}, "f5": {"afm": {"acl_rule_name": "allow_https", "action": "Accept", "drop_reason": "", "route_domain": 0, "virtual_name": "/Common/www_https_vs", "vlan": "/Common/external"}}, "network": {"transport": "tcp", "type": "ipv4"}, "observer": {"ip": ["10.0.0.5"], "name": "bigip-afm.lab.example", "product": "Advanced Firewall Module", "type": "firewall", "vendor": "F5", "version": "11.3.0.2790.300"}, "related": {"ip": ["192.0.2.175", "203.0.113.10", "10.0.0.5"]}, "rule": {"name": "allow_https"}, "source": {"ip": "192.0.2.175", "port": 38537}}
```

## References

- [F5 External Monitoring Implementations 13.0.0: AFM, Network DoS and DNS event fields and CEF examples](https://techdocs.f5.com/kb/en-us/products/big-ip_ltm/manuals/product/bigip-external-monitoring-implementations-13-0-0/15.html)
- [KUMA 4.2 supported sources](https://support.kaspersky.ru/kuma/4.2/255782)
- [Elastic ECS field reference](https://www.elastic.co/docs/reference/ecs/ecs-field-reference)

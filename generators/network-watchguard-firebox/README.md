# WatchGuard Firebox Traffic Logs

Generates the traffic log messages of one WatchGuard Firebox as ECS JSON, for training SIEM content on perimeter firewall telemetry. `event.original` holds the native message in the form Traffic Monitor shows it; WatchGuard states that messages sent to a Syslog server are the same, so a Syslog collector receives this body behind its own envelope. The source is one Firebox between a trusted LAN (`Trusted`, 10.0.1.0/24) and the internet (`External`), with the Mobile VPN with SSL portal on its external address.

## Event Types

Shares in 4 days of default output (`anomaly_mode: true`, 28,706 records).

| `msg_id` | Record | Policy | Share | Category |
|---|---|---|---:|---|
| `3000-0148` | Allow, first packet, TCP/443 to the internet with source NAT | `Outgoing-00` | 52.01% (14929) | Network |
| `3000-0148` | Deny, TCP from the internet to the Firebox | `Unhandled External Packet-00` | 28.44% (8163) | Network |
| `3000-0176` | Allow, HTTP proxy connection terminated | `HTTP-proxy-00` | 9.24% (2653) | Network |
| `3000-0148` | Allow, first packet, TCP/443 from the internet to the Firebox | `WatchGuard SSLVPN-00` | 6.45% (1852) | Network |
| `3000-0148` | Deny, ICMP echo request from the LAN to the Firebox | `Ping-00` | 3.86% (1109) | Network |

`3000-0148` Allow records mark the first packet of a connection and carry packet length, TTL and `tcp_info`, as in the vendor example; they have no duration or counters. The `3000-0176` record closes an HTTP proxy connection with `flags`, `duration`, packet and byte counters. Every external address, port and record type used by the chain occurs in ordinary background in both modes. No field labels an episode.

## Volume and Daily Curve

About 7,100 records a day, 140 an hour at night and 660-680 an hour around 12:00-13:00 UTC. Four populations set the volume, each with its own curve:

- **LAN clients during the working day** (3,500 records a day, ±5% per day): a curve that rises from 07:00, peaks at 12:00-13:00 UTC and falls off by 19:00. Any of the `client_count` clients takes part.
- **Always-on LAN hosts** (1,100 a day, flat): about a quarter of the clients (servers, printers, machines left running); they carry all LAN traffic at night.
- **SSL VPN portal** (460 connections a day): 400 on the working-day curve plus 60 spread over the day, so 50-60 an hour at midday and 2-3 an hour at night.
- **Unsolicited packets from the internet** (85 an hour, ±10% per hour, flat).

With `anomaly_mode: true` the hourly volume of each population is the same as with `false`: an episode's records stand in for the same number of ordinary unsolicited-packet and portal records.

## Background Model

A LAN record is HTTPS to one of 40 internet servers (skewed popularity) allowed by `Outgoing-00` with source NAT to the Firebox address (82.5%), HTTP through `HTTP-proxy-00` logged when the connection ends (log-normal duration, median 4 s; 14.6%), or 1, 2 or 4 echo requests to the Firebox denied by `Ping-00` (2.9%). Clients differ in activity by a fixed log-normal weight, so a few clients carry most of the traffic.

External addresses come from `samples/remote_addresses.csv`, one row per address with its role, operating system, hop count and two activity weights (probes and portal connections):

| Role | Addresses | Portal connections | Unsolicited packets |
|---|---:|---|---|
| `user`: remote users behind home routers | 97 | the bulk of them | stray packets from other devices behind the address, one or two ports (65:35) |
| `shared`: carrier-grade NAT and cloud NAT egress | 15 | several users behind each address, a few connections a day per address | infected devices behind the address, one to five ports (52:28:12:5:3) |
| `scan`: hosting and scanning ranges | 38 | a tenth of a user's rate (a VPS or jump host of a user) | most multi-port probes, one to five ports (39:21:20:12:8) |

One- and two-port probes keep the same 65:35 ratio in every role. A probe sends 1-3 SYNs to each port (65:25:10), 60% of probes use a stateless-scanner stack (TTL 255, no TCP options), and all are denied as `Unhandled External Packet-00`. A portal connection is allowed by `WatchGuard SSLVPN-00` and followed by 0-2 further connections of the same address (60:28:12). TTLs, window sizes and TCP header offsets follow the address's operating system; packet length is 20 + 4 x offset.

## Anomaly Chain

`anomaly_mode` defaults to `true`. With `false` the generator emits the background only and the complete chain never occurs.

Sequence, for one external address A (`source.ip`) and the Firebox external address F (`destination.ip`):

1. `3000-0148` Deny, `Unhandled External Packet-00`, TCP from A to F on port P1.
2. Deny from A to F on a second port P2.
3. Deny from A to F on a third port P3 (a fourth or fifth port in 40% of episodes); each port gets 1-3 attempts, as in background probes.
4. `3000-0148` Allow from A to F on TCP/443 by `WatchGuard SSLVPN-00`, a few minutes after the last denied packet (log-normal, median 3 min), as a single connection.

Linking fields: `source.ip` (A) and `destination.ip` (F) in all steps, distinct `destination.port` in steps 1-3, `rule.name` in step 4. All steps fall within one hour; in 4 days of default output the portal connection followed the last denied packet by 2.7-8.1 minutes.

Recurrence: the first episode starts within the first `anomaly_interval_hours` (at most 24 h) of the data, each later one within a window of a quarter interval (at most 6 h) centred one interval after the previous start. Start times favour the hours when portal connections are frequent (weighted by the square of the portal curve), so default episodes mostly start between about 09:00 and 16:00 UTC, occasionally earlier in the morning. A late start never causes catch-up. Default interval 24 h (minimum 2).

Variation: A is a `shared` address other than the previous episode's, drawn by its probe weight. Every such address probes the Firebox and connects to the portal in ordinary background as well. Ports, their order, attempt counts and gaps come from the background probe law.

Detection idea: an external address is denied on three or more distinct ports of the Firebox and then reaches the SSL VPN portal within an hour (a port scan that finds the VPN, the usual prelude to credential attacks on it). Every fragment occurs in background: probes over three or more ports from `shared` and `scan` addresses, and portal connections of the same addresses at other times. Only the complete sequence never occurs in background: in the hour after an address is denied on three or more ports it does not reach the portal, and such an address often sends a lone denied SYN to the former portal port 9007 in that hour instead (about 7 a day in both modes; after episodes as often as after any such probe).

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Meaning |
|---|---|---|
| `anomaly_mode` | `true` | Add periodic episodes to the background |
| `anomaly_interval_hours` | `24` | Episode interval in source hours, 2-8760 |
| `device_name` | `firebox-edge` | `observer.name` (not part of the native message) |
| `firebox_external_ip` | `203.0.113.250` | Firebox external address: source NAT, portal and denied destination |
| `firebox_trusted_ip` | `10.0.1.1` | Firebox trusted address, destination of denied pings |
| `external_interface` | `External` | External interface name in the message |
| `trusted_interface` | `Trusted` | Trusted interface name in the message |
| `client_prefix` | `10.0.1.` | Client addresses are this prefix plus a host number |
| `client_first` | `20` | First client host number |
| `client_count` | `120` | Number of LAN clients (at least 8; `client_first + client_count` at most 255) |

External addresses live in `samples/remote_addresses.csv` (columns `ip`, `role`, `os`, `hops`, `probe_weight`, `portal_weight`); edit it to use other addresses or a different mix of roles. Episodes need at least two `shared` rows.

Volumes and daily curves live in `patterns/*.yml` (`multiplier.ratio` is records per day, or per hour for `wan.yml`).

### Output Parameters

The shipped config writes `output/events.json` with the `json` formatter and needs no `${params.*}` or `${secrets.*}`. To send events elsewhere, replace the `output` section, for example:

```yaml
output:
  - opensearch:
      hosts: ["${params.opensearch_url}"]
      username: ${params.opensearch_user}
      password: ${secrets.opensearch_password}
      index: watchguard-firebox
```

A Syslog collector that parses the native format needs `event.original` rather than the surrounding JSON.

## Usage

Live mode:

```bash
eventum generate --path generators/network-watchguard-firebox/generator.yml --id firebox --live-mode true
```

Batch mode needs a bounded window: set `oscillator.start` and `oscillator.end` in every file under `patterns/` (for example `start: "2026-09-01T00:00:00+00:00"`, `end: "2026-09-05T00:00:00+00:00"`; start at midnight to keep the daily curves aligned), then run:

```bash
eventum generate --path generators/network-watchguard-firebox/generator.yml --id firebox --live-mode false
```

Performance: about 2,700 records per second on one core in batch mode (14 days, about 99,000 records, in 38 s).

## Limitations

- WatchGuard publishes no complete field specification for the Traffic Monitor form. Each record copies the positional fields and the key order of one vendor example: the `3000-0148` Allow with `tcp_info` and NAT (Read a Log Message, first example), the `3000-0176` HTTP proxy record and the `3000-0148` ICMP Deny (same page), and the `3000-0148` TCP Deny of an unhandled external packet (SSL VPN troubleshooting page). The Log Catalog lists further optional fields (`route_type`, `src_user`, application control, proxy request details) that are not generated.
- The TCP Deny shape comes from a 2022 example without `flags`, `duration` or counters; Fireware 12.10.3 and later may add them to deny records. Service names for ports without a vendor example (`ssh`, `telnet`, `smtp`, `microsoft-ds`, `ms-sql-s`, `mysql`, `ms-wbt-server`) are the IANA names that the documented `http`, `https` and `webcache` also follow; port 9007 appears as a number, as in the vendor example.
- Only traffic messages are modeled: no FireCluster member field, no event, alarm, authentication or VPN tunnel messages, no IPv6, no Syslog header or serial number option, no IBM LEEF. The Firebox time zone is UTC.
- `Ping-00`, `Unhandled External Packet-00` and `HTTP-proxy-00` appear in the vendor examples and Log Catalog; `WatchGuard SSLVPN-00` and `Outgoing-00` apply the documented `-00` suffix to the SSL VPN policy and the default outgoing policy. Rates, sizes, durations and address pools are training assumptions, not measured production values. Traffic Monitor timestamps have one-second resolution, so every `@timestamp` is a whole second.
- The ECS document has no published Elastic mapping to follow; `watchguard.firebox.*` keeps the disposition, process, return code, interfaces and flags from the message.
- Records that belong to one moment are seconds apart rather than milliseconds: repeated SYNs to one port are 7 s apart at the median during the day and about 18 s at night (a real TCP stack retries after 1-3 s), and the gaps between the ports of one probe grow by the same amount.
- An address never reaches the portal within an hour after being denied on three or more ports outside an episode, and lone denied SYNs to port 9007 are more common in that hour than at other times (about 7 a day).
- With `anomaly_mode: true` each episode adds its own records, so counts of chain parts (probes over three or more ports from `shared` addresses, their portal connections) are about one per episode higher, while total volumes stay the same.
- A `shared` address probes over three or more ports about once in two days, so in a 4-day window an episode address may show no other such probe.

## Sample Output

The portal connection that completes the first episode, copied byte for byte from 4 days of default output (line 4138):

```json
{"@timestamp": "2026-09-01T13:22:48+00:00", "destination": {"ip": "203.0.113.250", "port": 443}, "ecs": {"version": "8.17.0"}, "event": {"action": "traffic_allow", "category": ["network"], "code": "3000-0148", "dataset": "watchguard.firebox.traffic", "kind": "event", "original": "2026-09-01 13:22:48 Allow 192.0.2.216 203.0.113.250 https/tcp 61293 443 External Firebox Allowed 64 42 (WatchGuard SSLVPN-00) proc_id=\"firewall\" rc=\"100\" tcp_info=\"offset 11 S 944686688 win 65535\" msg_id=\"3000-0148\"", "type": ["connection", "allowed"]}, "network": {"transport": "tcp"}, "observer": {"egress": {"interface": {"name": "Firebox"}}, "ingress": {"interface": {"name": "External"}}, "name": "firebox-edge", "product": "Firebox", "type": "firewall", "vendor": "WatchGuard"}, "related": {"ip": ["192.0.2.216", "203.0.113.250"]}, "rule": {"name": "WatchGuard SSLVPN-00"}, "source": {"ip": "192.0.2.216", "port": 61293}, "watchguard": {"firebox": {"disposition": "Allow", "dst_interface": "Firebox", "process": "firewall", "return_code": "100", "src_interface": "External"}}}
```

## References

- [WatchGuard: Read a Log Message](https://www.watchguard.com/help/docs/help-center/en-us/Content/en-US/Fireware/logging/read_log-msg.html): Traffic Monitor examples and field descriptions.
- [WatchGuard: Missing, Disabled, or Misconfigured WatchGuard SSLVPN Policy](https://www.watchguard.com/help/docs/help-center/en-US/Content/en-US/Fireware/mvpn/ssl/troubleshoot/mvpn_ssl_wg-sslvpn-policy.html): unhandled external packet Deny example.
- [WatchGuard: Configure Syslog Server Settings](https://www.watchguard.com/help/docs/help-center/en-us/Content/en-US/Fireware/logging/send_logs_to_syslog_c.html)
- [Fireware v12.10.x Log Message Catalog](https://www.watchguard.com/help/docs/fireware/12/en-US/log_catalog/12_10_Log-Catalog.pdf): message IDs `3000-0148` and `3000-0176`.
- [Elastic ECS field reference](https://www.elastic.co/docs/reference/ecs/ecs-field-reference)

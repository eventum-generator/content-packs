# WatchGuard Firebox Traffic Logs

Generates the traffic log messages of one WatchGuard Firebox as ECS JSON, for training SIEM content on perimeter firewall telemetry. `event.original` holds the native message in the form Traffic Monitor shows it; WatchGuard states that messages sent to a Syslog server are the same, so a Syslog collector receives this body behind its own envelope. The source is one Firebox between a trusted LAN (`Trusted`, 10.0.1.0/24) and the internet (`External`), with the Mobile VPN with SSL portal on its external address.

## Event Types

Shares measured on the final default capture (78 h, `anomaly_mode: true`, 22,084 records).

| `msg_id` | Record | Policy | Share | Category |
|---|---|---|---:|---|
| `3000-0148` | Allow, first packet, TCP/443 to the internet with source NAT | `Outgoing-00` | 51.53% (11380) | Network |
| `3000-0148` | Deny, TCP from the internet to the Firebox | `Unhandled External Packet-00` | 29.44% (6501) | Network |
| `3000-0176` | Allow, HTTP proxy connection terminated | `HTTP-proxy-00` | 9.05% (1998) | Network |
| `3000-0148` | Allow, first packet, TCP/443 from the internet to the Firebox | `WatchGuard SSLVPN-00` | 5.88% (1298) | Network |
| `3000-0148` | Deny, ICMP echo request from the LAN to the Firebox | `Ping-00` | 4.11% (907) | Network |

`3000-0148` Allow records mark the first packet of a connection and carry packet length, TTL and `tcp_info`, as in the vendor example; they have no duration or counters. The `3000-0176` record closes an HTTP proxy connection with `flags`, `duration`, packet and byte counters. Every external address, port and record type used by the chain occurs in ordinary background in both modes. No field labels an episode.

## Background Model

Each one-second tick emits at most one record: the earliest due record of a queue, otherwise nothing. Activity arrives as independent Poisson streams; each arrival picks its host by a fixed per-host weight (log-normal quantiles assigned to hosts in random order), so hosts act independently and a few hosts carry most of the traffic.

- **Outbound web** (0.05 per second, office-hours factor 07:00-17:00 UTC 1.70, 17:00-21:00 0.91, night 0.34): one of `client_count` LAN clients connects to one of 40 internet servers (skewed popularity). 85% are HTTPS allowed by `Outgoing-00` with source NAT to the Firebox address; 15% are HTTP through `HTTP-proxy-00`, logged when the connection ends (log-normal duration, median 4 s).
- **Ping to the Firebox** (0.0015 per second, flat): a client sends 1, 2 or 4 echo requests, denied by `Ping-00`.
- **Unsolicited inbound packets** (0.009 per second, flat): an external address sends SYNs to distinct ports of the Firebox (22, 23, 25, 80, 445, 1433, 3306, 3389, 8080, 9007, weighted), 1-3 attempts per port, gaps between ports log-normal (median 15 s); 60% of these bursts use a stateless-scanner stack (TTL 255, no TCP options). All are denied as `Unhandled External Packet-00`.
- **SSL VPN portal** (0.0035 per second, office-hours factor): an external address connects to TCP/443 on the Firebox, allowed by `WatchGuard SSLVPN-00`, with 0-2 follow-up connections.

The `remote_count` external addresses fall into two classes, assigned at random. About 70% are remote users behind home routers and carrier NAT: they carry the portal logins, and other devices behind the same address send about half of the unsolicited bursts, on one or two ports (65:35). The other 30% are hosting and scanning ranges: they send the other half, on one to five ports (39:21:20:12:8, so one- and two-port bursts keep the same ratio in both classes), and log in to the portal at a tenth of a user's rate (a VPS or jump host of a user). In a 78 h background capture about two thirds of the addresses that scan three or more ports within an hour also log in to the portal at some time. TTLs, window sizes and TCP header offsets follow a per-host operating system; packet length is 20 + 4 x offset.

## Anomaly Chain

`anomaly_mode` defaults to `true`. With `false` the generator emits the background only and the complete chain never occurs.

Sequence, for one external address A (`source.ip`) and the Firebox external address F (`destination.ip`):

1. `3000-0148` Deny, `Unhandled External Packet-00`, TCP from A to F on port P1.
2. Deny from A to F on a second port P2.
3. Deny from A to F on a third port P3 (a fourth or fifth port in about 40% of episodes); each port gets 1-3 attempts.
4. `3000-0148` Allow from A to F on TCP/443 by `WatchGuard SSLVPN-00`, a few minutes later (log-normal, median 3 min), with 0-2 follow-up connections.

Linking fields: `source.ip` (A) and `destination.ip` (F) in all steps, distinct `destination.port` in steps 1-3, `rule.name` in step 4.

Recurrence: an episode becomes due every `anomaly_interval_hours` of source time (default 24, minimum 2), first one interval after generation starts. It starts after a random delay (exponential, mean 20 min). The next due time counts from the actual start, so a late episode never causes catch-up. In the final default capture (three episodes) the portal connection followed the third denied port by 1.4-3.3 minutes; a detector that starts the window at the address's first denial also counts earlier background denials of the same address, which can stretch a chain to most of the hour.

Variation: the address is a scanning-range address other than the previous episode's, drawn with the background burst weights; like its background peers it may or may not log in to the portal at other times. Ports, their order, attempt counts and gaps come from the background law for denied bursts.

Detection idea: an external address is denied on three or more distinct ports of the Firebox and then reaches the SSL VPN portal within an hour (a port scan that finds the VPN, the usual prelude to credential attacks on it). Every fragment occurs in background: a 78 h background capture holds about 420-650 bursts over three or more ports and about 60 one-port and 30 two-port bursts followed by a portal login of the same address within an hour. Pooled over six background captures, the share of bursts followed by a login of the same address is 0.6-1.1% per 10-minute lag bin for both one- and two-port bursts, without a step at 60 minutes. Only the complete sequence is kept out of the background. Because multi-port bursts come from scanning ranges, a login within the hour after one is rare; when an ordinary login would still complete the sequence, it keeps its time and address and becomes a denied SYN to the former portal port 9007, which such addresses send anyway (a few per 78 h, about 6 expected from the rate just outside the window); its follow-up connections are not made.

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
| `client_count` | `120` | Number of LAN clients (at least 8) |
| `remote_count` | `150` | Number of external addresses (at least 20) |

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

Batch mode needs a bounded input: add `start` and `end` to the `cron` input, then run:

```bash
eventum generate --path generators/network-watchguard-firebox/generator.yml --id firebox --live-mode false
```

## Limitations

- WatchGuard publishes no complete field specification for the Traffic Monitor form. Each record copies the positional fields and the key order of one vendor example: the `3000-0148` Allow with `tcp_info` and NAT (Read a Log Message, first example), the `3000-0176` HTTP proxy record and the `3000-0148` ICMP Deny (same page), and the `3000-0148` TCP Deny of an unhandled external packet (SSL VPN troubleshooting page). The Log Catalog lists further optional fields (`route_type`, `src_user`, application control, proxy request details) that are not generated.
- The TCP Deny shape comes from a 2022 example without `flags`, `duration` or counters; Fireware 12.10.3 and later may add them to deny records. Service names for ports without a vendor example (`ssh`, `telnet`, `smtp`, `microsoft-ds`, `ms-sql-s`, `mysql`, `ms-wbt-server`) are the IANA names that the documented `http`, `https` and `webcache` also follow; port 9007 appears as a number, as in the vendor example.
- Only traffic messages are modeled: no FireCluster member field, no event, alarm, authentication or VPN tunnel messages, no IPv6, no Syslog header or serial number option, no IBM LEEF. The Firebox time zone is UTC.
- `Ping-00`, `Unhandled External Packet-00` and `HTTP-proxy-00` appear in the vendor examples and Log Catalog; `WatchGuard SSLVPN-00` and `Outgoing-00` apply the documented `-00` suffix to the SSL VPN policy and the default outgoing policy. Rates, sizes, durations and address pools are training assumptions, not measured production values. Traffic Monitor timestamps have one-second resolution, so every `@timestamp` is a whole second.
- The ECS document has no published Elastic mapping to follow; `watchguard.firebox.*` keeps the disposition, process, return code, interfaces and flags from the message.
- Episodes start at any hour, while background portal connections follow office hours; a night-time portal connection right after a scan therefore stands out more than a daytime one.
- After a burst over three or more ports, a login of the same address occurs 0.1-0.3% per 10-minute bin at 60-120 minutes and never within 60 minutes in background; the step is the chain's own window and involves a few records per 78 h.
- A background portal login that would complete the chain is written as a lone denied SYN to port 9007 at the same time. Over about 780 h this makes a lone 9007 SYN in the first hour after a 3+ port burst about twice as common as in the second hour (roughly 4-5 records per 78 h, the same in both modes).

## Sample Output

The portal connection that completes the first episode, copied byte for byte from the final default capture (line 7299):

```json
{"@timestamp": "2026-09-27T00:39:53+00:00", "destination": {"ip": "203.0.113.250", "port": 443}, "ecs": {"version": "8.17.0"}, "event": {"action": "traffic_allow", "category": ["network"], "code": "3000-0148", "dataset": "watchguard.firebox.traffic", "kind": "event", "original": "2026-09-27 00:39:53 Allow 198.51.100.36 203.0.113.250 https/tcp 63786 443 External Firebox Allowed 52 109 (WatchGuard SSLVPN-00) proc_id=\"firewall\" rc=\"100\" tcp_info=\"offset 8 S 3210695985 win 65535\" msg_id=\"3000-0148\"", "type": ["connection", "allowed"]}, "network": {"transport": "tcp"}, "observer": {"egress": {"interface": {"name": "Firebox"}}, "ingress": {"interface": {"name": "External"}}, "name": "firebox-edge", "product": "Firebox", "type": "firewall", "vendor": "WatchGuard"}, "related": {"ip": ["198.51.100.36", "203.0.113.250"]}, "rule": {"name": "WatchGuard SSLVPN-00"}, "source": {"ip": "198.51.100.36", "port": 63786}, "watchguard": {"firebox": {"disposition": "Allow", "dst_interface": "Firebox", "process": "firewall", "return_code": "100", "src_interface": "External"}}}
```

## References

- [WatchGuard: Read a Log Message](https://www.watchguard.com/help/docs/help-center/en-us/Content/en-US/Fireware/logging/read_log-msg.html): Traffic Monitor examples and field descriptions.
- [WatchGuard: Missing, Disabled, or Misconfigured WatchGuard SSLVPN Policy](https://www.watchguard.com/help/docs/help-center/en-US/Content/en-US/Fireware/mvpn/ssl/troubleshoot/mvpn_ssl_wg-sslvpn-policy.html): unhandled external packet Deny example.
- [WatchGuard: Configure Syslog Server Settings](https://www.watchguard.com/help/docs/help-center/en-us/Content/en-US/Fireware/logging/send_logs_to_syslog_c.html)
- [Fireware v12.10.x Log Message Catalog](https://www.watchguard.com/help/docs/fireware/12/en-US/log_catalog/12_10_Log-Catalog.pdf): message IDs `3000-0148` and `3000-0176`.
- [Elastic ECS field reference](https://www.elastic.co/docs/reference/ecs/ecs-field-reference)

# Sophos Firewall Firewall Rule Log

Generates the Firewall Rule log of one Sophos Firewall (SFOS 20) in the Central Reporting Format as ECS JSON, for training SIEM content on firewall connection telemetry. `event.original` holds the native key=value message without a syslog envelope. The source is one firewall between a user LAN (`Port1`), a server DMZ (`Port3`) and the internet (`Port2`, source NAT).

## Event Types

Shares measured on the final default capture (156 h, `anomaly_mode: true`, 73,427 records).

| `log_id` | Record | Traffic | Share | Category |
|---|---|---|---:|---|
| `010101600001` | Allowed, `con_event` Start | HTTPS (TCP/443) | 21.67% (15913) | Network |
| `010101600001` | Allowed, `con_event` Stop | HTTPS (TCP/443) | 21.67% (15910) | Network |
| `010101600001` | Allowed, `con_event` Start | DNS (UDP/53) | 11.87% (8715) | Network |
| `010101600001` | Allowed, `con_event` Stop | DNS (UDP/53) | 11.87% (8713) | Network |
| `010101600001` | Allowed, `con_event` Start | SMB (TCP/445) | 7.69% (5647) | Network |
| `010101600001` | Allowed, `con_event` Stop | SMB (TCP/445) | 7.69% (5647) | Network |
| `010102600002` | Denied | TCP to a closed port of a DMZ server | 7.73% (5679) | Network |
| `010102600002` | Denied | QUIC (UDP/443) to the internet | 2.35% (1722) | Network |
| `010101600001` | Allowed, `con_event` Start | HTTP (TCP/80) | 1.81% (1330) | Network |
| `010101600001` | Allowed, `con_event` Stop | HTTP (TCP/80) | 1.81% (1330) | Network |
| `010101600001` | Allowed, `con_event` Start | RDP (TCP/3389) | 1.74% (1277) | Network |
| `010101600001` | Allowed, `con_event` Stop | RDP (TCP/3389) | 1.73% (1271) | Network |
| `010101600001` | Allowed, `con_event` Start | WinRM (TCP/5985) | 0.11% (79) | Network |
| `010101600001` | Allowed, `con_event` Stop | WinRM (TCP/5985) | 0.11% (78) | Network |
| `010101600001` | Allowed, `con_event` Start | SSH (TCP/22) | 0.08% (58) | Network |
| `010101600001` | Allowed, `con_event` Stop | SSH (TCP/22) | 0.08% (58) | Network |

`Allowed` records carry `con_event="Start"` when a connection is created and `con_event="Stop"` when it ends, with `duration`, directional packet and byte counters; both share `con_id`. `Denied` records have no connection, zones or counters, as in the vendor samples. Every client, server, port and record type used by the chain occurs in ordinary background in both modes. No field labels an episode.

## Background Model

Each one-second tick emits at most one record: the earliest due connection start, connection stop or denied packet, otherwise nothing. New client activity arrives as one merged Poisson stream (0.045 per second, scaled by an office-hours factor: 06:00-16:00 UTC 1.70, 16:00-20:00 0.91, night 0.34); each arrival picks a client by a fixed random per-client weight, so clients act independently. Activity types, by arrival weight:

- **Web** (45%): HTTPS to one of 40 internet addresses (skewed popularity), preceded in half of the cases by a DNS query to a DMZ resolver; 15% start with a QUIC attempt (UDP/443) that the `Block QUIC` rule denies. **HTTP** (5%) and **DNS only** (8%).
- **Intranet** (14%): HTTPS to an intranet or Linux server. **File** (11%): a burst of 1-5 SMB connections to one file server. **Terminal** (4%): RDP to a terminal server, durations log-normal (median 25 min).
- **Denied attempts** (9% of ordinary clients' activity): a client hits 1-4 ports of one DMZ server that its rules do not open (22, 135, 445, 1433, 3389, 5985, 8080 minus the server's open port), 1-3 attempts per port, then in half of the cases connects to the server's open port about two minutes later. **Admin** (22% of the activity of the first `admin_count` clients): SSH, RDP, WinRM, SMB or HTTPS to servers; ports that the all-client rules do not open match `Admins to servers`.
- Durations follow the transferred volume and log-normal throughputs. DNS connections stop after an assumed idle timeout of 30 s plus a random delay. `con_id` values are 64-aligned slots from a pool, reused after a connection stops, as in the vendor fixtures.

## Anomaly Chain

`anomaly_mode` defaults to `true`. With `false` the generator emits the background only and the complete chain never occurs.

Sequence, all for one ordinary client C (`source.ip`) and one DMZ server S (`destination.ip`):

1. `Denied` (`log_id` `010102600002`, rule `Drop LAN to DMZ`), TCP from C to S on port P1.
2. `Denied` from C to S on a second port P2.
3. `Denied` from C to S on a third port P3 (a fourth port in about one episode in three); each port gets 1-3 attempts.
4. `Allowed` `con_event="Start"` from C to S on the port S opens to all clients (445 file, 443 intranet and Linux, 3389 terminal), followed later by its `Stop`.

Linking fields: `source.ip`/`src_ip` (C) and `destination.ip`/`dst_ip` (S) in all steps, distinct `destination.port` in steps 1-3; step 4's Start and Stop share `con_id`.

Recurrence: the first episode starts within the first `anomaly_interval_hours` (at most 24 h) of generation, at a time drawn from the office-hours load curve, so it does not sit at a fixed offset from the generation start. Each next episode is due `anomaly_interval_hours` (default 24, minimum 2) after the actual start of the previous one and starts in a window of a quarter of the interval (at most 6 h) centred on the due time, weighted by the square of the load curve plus a small floor, so most episodes fall in office hours. There is no catch-up. In the final 156 h captures the default configuration produced 6 episodes, starting between 13:00 and 18:00 UTC, 21.9-25.9 h apart; a 6 h interval produced 26, 5.3-6.7 h apart. Episodes spanned 39 s to 13 minutes from the first denial to the allowed connection (1.7-13 minutes at the default interval).

Variation: the client and the server differ from the previous episode's. Ports, attempt counts and gaps come from the same laws as the background denied attempts (ports in random order, gaps between ports log-normal with median 25 s, the allowed connection about two minutes after the last denial).

Detection idea: a client is denied on three or more distinct ports of one server and then reaches that server through an open port within an hour (port probing that finds a way in). Every fragment occurs in background: a 156 h background capture holds 439-490 sets of denials on three or more distinct ports of one server within an hour and 1195-1339 allowed connections within an hour of denials on one or two ports of the same server. Only the complete sequence is kept out of the background: an ordinary allowed connection that would complete the chain (denials on three distinct ports of the server, the first at most one hour earlier) is not made. The guard uses the chain window exactly, so a connection more than an hour after the first denial is left as is.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Meaning |
|---|---|---|
| `anomaly_mode` | `true` | Add periodic episodes to the background |
| `anomaly_interval_hours` | `24` | Episode interval in source hours, 2-8760 |
| `device_model` | `XGS2300` | `device_model` |
| `device_serial_id` | `X23001EXAMPLE01` | `device_serial_id` and `observer.serial_number` (synthetic) |
| `wan_ip` | `203.0.113.2` | Source NAT address (`src_trans_ip`) |
| `client_prefix` | `10.20.1.` | Client addresses are this prefix plus a host number |
| `client_first` | `20` | First client host number |
| `client_count` | `80` | Number of clients (at least 8) |
| `admin_count` | `4` | The first clients form the admin group |
| `web_policy_id`, `ips_policy_id`, `app_filter_policy_id` | `2`, `5`, `3` | Policy IDs on records of the `LAN to Internet` rule |
| `servers` | 11 DMZ servers | Map of address to role: `file`, `intranet`, `terminal`, `linux`, `dns` (at least two non-DNS servers and one DNS server) |

### Output Parameters

The shipped config writes `output/events.json` with the `json` formatter and needs no `${params.*}` or `${secrets.*}`. To send events elsewhere, replace the `output` section, for example:

```yaml
output:
  - opensearch:
      hosts: ["${params.opensearch_url}"]
      username: ${params.opensearch_user}
      password: ${secrets.opensearch_password}
      index: sophos-firewall
```

A syslog collector that parses the native format needs `event.original` rather than the surrounding JSON.

## Usage

Live mode:

```bash
eventum generate --path generators/network-sophos-firewall/generator.yml --id sophos-fw --live-mode true
```

Batch mode needs a bounded input: add `start` and `end` to the `cron` input, then run:

```bash
eventum generate --path generators/network-sophos-firewall/generator.yml --id sophos-fw --live-mode false
```

## Limitations

- Key order and field presence follow the SFOS 20 guide sample 00001 (Firewall Rule, Allowed) and the 50 Central Reporting Format lines in the Elastic integration fixtures (Start/Stop, Denied). The guide publishes no Central Reporting Format sample for a denied Firewall Rule record; its shape comes from the Elastic fixtures (captured 2021). The double space before `packets_received`, uppercase MACs on allowed and lowercase on denied records are copied from those samples.
- Only the Firewall Rule component (`010101600001`, `010102600002`) over IPv4 TCP/UDP is modeled: no `Interim` records, ICMP, IPv6, SD-WAN gateway fields, user identity, Heartbeat, invalid traffic or other SFOS log types. Application fields appear only for the four application names found in the samples (DNS, HTTP, Secure Socket Layer Protocol, Youtube Website). `log_occurrence` is always 1 and `hb_status` always `No Heartbeat`.
- Rule names and IDs, policy IDs, zones, the DNS idle timeout, rates, sizes and durations are training assumptions, not measured production values. The device time zone is UTC. Countries of the documentation-range internet addresses are synthetic.
- The ECS document follows the Elastic Sophos XG ingest mapping without GeoIP, community ID or syslog-header fields; `rule.name`, `event.type` and `sophos.xg` keys `fw_rule_section`, `log_occurrence` and `app_*` are additions.
- Episodes pick their client uniformly, while background activity follows per-client activity weights; a rarely active client is relatively more visible in an episode.

## Sample Output

The allowed connection that completes the first episode, copied byte for byte from the final default capture (line 9919):

```json
{"@timestamp": "2026-09-26T17:58:20+00:00", "destination": {"ip": "10.20.10.32", "mac": "00-0C-29-CE-3A-48", "port": 3389}, "ecs": {"version": "8.17.0"}, "event": {"action": "allowed", "category": ["network"], "code": "00001", "kind": "event", "original": "device_name=\"SFW\" timestamp=\"2026-09-26T17:58:20+0000\" device_model=\"XGS2300\" device_serial_id=\"X23001EXAMPLE01\" log_id=\"010101600001\" log_type=\"Firewall\" log_component=\"Firewall Rule\" log_subtype=\"Allowed\" log_version=1 severity=\"Information\" fw_rule_id=\"5\" fw_rule_name=\"LAN to terminal servers\" fw_rule_section=\"Local rule\" nat_rule_id=\"0\" fw_rule_type=\"USER\" ether_type=\"Unknown (0x0000)\" in_interface=\"Port1\" out_interface=\"Port3\" src_mac=\"3C:D9:2B:8A:4F:26\" dst_mac=\"00:0C:29:CE:3A:48\" src_ip=\"10.20.1.38\" src_country=\"R1\" dst_ip=\"10.20.10.32\" dst_country=\"R1\" protocol=\"TCP\" src_port=55151 dst_port=3389 src_zone_type=\"LAN\" src_zone=\"LAN\" dst_zone_type=\"DMZ\" dst_zone=\"DMZ\" con_event=\"Start\" con_id=\"2929646720\" hb_status=\"No Heartbeat\" app_resolved_by=\"Signature\" app_is_cloud=\"FALSE\" qualifier=\"New\" in_display_interface=\"Port1\" out_display_interface=\"Port3\" log_occurrence=\"1\"", "outcome": "success", "severity": 6, "timezone": "+00:00", "type": ["connection", "start"]}, "log": {"level": "Information"}, "network": {"transport": "tcp"}, "observer": {"egress": {"interface": {"name": "Port3"}, "zone": "DMZ"}, "ingress": {"interface": {"name": "Port1"}, "zone": "LAN"}, "product": "XG", "serial_number": "X23001EXAMPLE01", "type": "firewall", "vendor": "Sophos"}, "related": {"ip": ["10.20.1.38", "10.20.10.32"]}, "rule": {"id": "5", "name": "LAN to terminal servers"}, "sophos": {"xg": {"app_is_cloud": "FALSE", "app_resolved_by": "Signature", "con_event": "Start", "con_id": "2929646720", "device_model": "XGS2300", "device_name": "SFW", "dst_zone_type": "DMZ", "ether_type": "Unknown (0x0000)", "fw_rule_section": "Local rule", "fw_rule_type": "USER", "hb_status": "No Heartbeat", "log_component": "Firewall Rule", "log_id": "010101600001", "log_occurrence": "1", "log_subtype": "Allowed", "log_type": "Firewall", "log_version": "1", "qualifier": "New", "src_zone_type": "LAN"}}, "source": {"ip": "10.20.1.38", "mac": "3C-D9-2B-8A-4F-26", "port": 55151}}
```

## References

- [Sophos Firewall syslog guide for SFOS 20.0](https://docs.sophos.com/nsg/sophos-firewall/20.0/syslog/index.html): log ID structure, Firewall field table and sample logs.
- [Elastic Sophos integration, Central Reporting Format firewall fixtures](https://github.com/elastic/integrations/blob/main/packages/sophos/data_stream/xg/_dev/test/pipeline/test-xg-firewall-new.log) and [expected ECS output](https://github.com/elastic/integrations/blob/main/packages/sophos/data_stream/xg/_dev/test/pipeline/test-xg-firewall-new.log-expected.json)
- [Elastic ECS field reference](https://www.elastic.co/docs/reference/ecs/ecs-field-reference)

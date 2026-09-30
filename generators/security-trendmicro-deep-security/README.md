# Trend Micro Deep Security Agent CEF

Firewall and intrusion prevention events of Trend Micro Deep Security 20 Agents on protected servers, relayed by Deep Security Manager over syslog in CEF. Each record is ECS JSON with the native syslog line in `event.original`; field names follow the Elastic Trend Micro integration.

The protected estate is 40 servers (16 web, 16 application and 8 database servers, Linux or Windows) and 180 internal source addresses, listed in `samples/hosts.csv` and `samples/sources.csv`. Every server and source has its own activity weight, so a few sources and servers carry most of the traffic.

## Volume and Timing

About 8,500 records a day: about 140 an hour at night, rising on a working-day curve to about 640 an hour at 10:00-12:00 UTC.

- Ordinary connections matched by log-only rules follow the working day: about 110 an hour at night and 550-590 an hour in the late morning, with the number of active sources rising and falling with them. A source opens one to four connections to one service of a server, tens of seconds apart.
- Denied connection attempts come half from tools that run around the clock and half from misconfigured clients during the working day: about 30 an hour at night and 60-75 in the late morning. One source tries one to five blocked ports of one server (one port in half of the cases, three or more in about a quarter), one to three attempts per port. After a scan of a web server the same source makes an ordinary logged connection to it within ten minutes in about 30% of cases, or, after a scan of one or two ports, triggers an intrusion prevention rule on it in about 15%.
- Intrusion prevention detections are flat over the day, about 70 a day across the web servers: false positives on ordinary web traffic and exploit checks of vulnerability scans. A burst holds one to four detections of one source against one web service.

## Event types

Shares from a four-day default run (`anomaly_mode: true`, 34,377 events).

| CEF signature ID | Event | `act` | Share | ECS category |
|---|---|---|---|---|
| `20` | Log-only firewall rule (`Log Inbound HTTP`, `HTTPS`, `SSH`, `RDP`) | `Log` | 86.7% | `network` |
| `21` | Deny firewall rule (`Deny Inbound SMB`, `Telnet`, `MSSQL` and 7 more) | `Deny` | 12.5% | `network` |
| `1000000`-`1999999` | Intrusion prevention rule (11 Trend Micro rules, rule ID = signature ID) | `IDS:Reset` | 0.8% | `intrusion_detection` |

The shares are synthetic workload weights, not vendor-measured rates. Log-only and deny rule names are customer-defined in Deep Security; the shipped ones are examples. The intrusion prevention rule IDs and names are real Trend Micro rules, taken from a Deep Security Manager rule update record.

## Anomaly Chain

`anomaly_mode` defaults to `true`. With `false` the generator emits the background only and the complete chain never occurs.

Sequence, all for one source S (`src` / `source.ip`) and one protected web server H (`cn1` / `dvchost` / `host.name`, `dst`):

1. Deny firewall event (signature `21`, `act=Deny`, TCP SYN) from S to H on blocked port P1.
2. Deny from S to H on a second blocked port P2.
3. Deny from S to H on a third blocked port P3 (four or five ports in about half of episodes); each port gets one to three attempts.
4. One intrusion prevention event (`act=IDS:Reset`) from S to H on HTTP or HTTPS: a port scan followed by an exploit attempt against the service it found.

Linking fields: `src` / `source.ip`, `cn1` / `host.id`, `dvchost` / `host.name` and `dst` / `destination.ip` in all steps; distinct `dpt` / `destination.port` in steps 1-3. An episode spans about one to ten minutes, occasionally up to half an hour, from the first deny to the intrusion prevention event.

Recurrence: episodes recur every `anomaly_interval_hours` (default 24, minimum 2). The first one starts within the first min(interval, 24 h); each later one within a window of min(interval / 4, 6 h) centred one interval after the previous start. Within these windows the start hour follows the denied-attempt curve (squared, with a small floor), so episodes lean toward the working day without avoiding the night. A late start moves the following ones; missed episodes are not replayed.

Variation: S and H differ from the previous episode's. They are drawn, weighted by their traffic, from the source and web server pairs that exchange ordinary logged connections several times a day, so the pair also meets in the background. Ports, attempt counts and gaps, rules and the HTTP/HTTPS split come from the same law as the background. The episode's records come on top of the background; the source's and the server's other activity continues unchanged.

Detection idea: one source is denied on three or more distinct ports of one host and then triggers an intrusion prevention rule on that host within an hour. Every fragment occurs in the background of both modes: about 40 scans a day of a web server on three or more ports, and same-source intrusion prevention detections within ten minutes of a scan of one or two ports. What follows a scan does not depend on its port count otherwise: within ten minutes of a scan on 1-2 or 3+ ports, the same source makes a logged connection in about 30% of cases either way, and another source triggers an intrusion prevention rule on the host in 1-4%. Only the complete sequence is kept out of the background: a background scan on three or more ports never gets an intrusion prevention follow-up from its source within the hour, and a source denied on three or more distinct ports of a host makes only ordinary logged connections to that host's web port for the rest of the hour.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`. Host names, the domain, source addresses and networks are set in `samples/hosts.csv` and `samples/sources.csv`; edit those files to match your environment.

| Parameter | Default | Meaning |
|---|---|---|
| `anomaly_mode` | `true` | Add periodic episodes to the background |
| `anomaly_interval_hours` | `24` | Episode interval in hours, 2-8760 |
| `manager_host` | `dsm-01.corp.example` | Syslog header host (the relaying manager) |
| `product_version` | `20.0.877` | CEF Device Version (the manager version for relayed events) |
| `tenant` | `Primary` | `TrendMicroDsTenant` |
| `tenant_id` | `0` | `TrendMicroDsTenantId` |
| `gateway_mac` | `00:1C:73:4A:0E:01` | `smac` of routed traffic |
| `log_rules` | 4 rules | Log-only rules (`name`, `port`); ports 80, 443, 22 and 3389 are required |
| `deny_rules` | 10 rules | Deny rules (`name`, `port`), at least five |
| `ips_action` | `IDS:Reset` | `act` of intrusion prevention events (detect-only policy) |

Sample files under `samples/`:

| File | Columns | Content |
|---|---|---|
| `hosts.csv` | `name`, `ip`, `id`, `mac`, `role`, `os`, `weight` | Protected servers; `role` `web` serves HTTP and HTTPS, `os` `linux` SSH, `windows` RDP; at least two web servers |
| `sources.csv` | `ip`, `weight` | Internal source addresses |
| `ips_rules.csv` | `id`, `name`, `severity`, `weight`, `request` | Intrusion prevention rules: rule ID, name, CEF severity, relative frequency and the request line used for the packet data |

### Output Parameters

The shipped `generator.yml` writes to a local file and uses no `${params.*}` or `${secrets.*}` placeholders. To send events to a backend, replace the `output` block and parameterize its endpoint and credentials, for example `hosts: ["${params.opensearch_host}"]` and `password: ${secrets.opensearch_password}`, then pass `--params '{"opensearch_host": "..."}'` and store the secret in the Eventum keyring.

## Usage

Live mode:

```bash
eventum generate --path generators/security-trendmicro-deep-security/generator.yml --id deep-security --live-mode true
```

Batch mode:

```bash
eventum generate --path generators/security-trendmicro-deep-security/generator.yml --id deep-security --live-mode false
```

Events go to `generators/security-trendmicro-deep-security/output/events.json`. The daily volume is set by the files in `patterns/`: `floor.yml` (records spread evenly over the day) and `workday.yml` (records on the working-day curve). They run from midnight today with no end, so a batch run keeps going; for a finite run, set `start` and `end` of the `oscillator` in both files to a window that begins at midnight, with an explicit offset, for example `start: "2026-09-01T00:00:00+00:00"` and `end: "2026-09-05T00:00:00+00:00"`. Scaling both `ratio` values changes the volume without changing the mix.

Performance: about 2,400 events per second in batch mode (a 14-day default run takes under a minute).

## Limitations

- Only Agent firewall (signature `20`, `21`) and intrusion prevention events. Anti-malware, integrity monitoring, log inspection, web reputation, application control, device control, policy firewall (`100`-`199`) and manager system events are not modeled, nor LEEF or basic syslog.
- Vendor documentation gives the CEF extension tables and truncated samples, not complete captured records. Extension order follows the Deep Security 20 samples; `TrendMicroDsTenant` / `TrendMicroDsTenantId` are placed after `dvchost` as in the documented manager-relayed samples. The documentation states that the order and presence of extensions may vary.
- CEF severity: `0` for log-only and `5` for deny events as in the documented samples; intrusion prevention severities (`6`, `8` and `10` in the default rules) are assigned per rule and are not taken from the vendor rule catalog.
- Packet data (`TrendMicroDsPacketData`, `cs6=8`) is present only for HTTP detections and holds the request line and `Host` header; HTTPS detections carry no packet data (`cs6=0`). Log-only and deny events carry no packet data.
- Timestamps are whole seconds as in the RFC 3164 header; the header carries no year and no time zone (UTC is used). Records of one scan or session follow each other seconds apart: the denied attempts of one scan are 3-65 s apart (median about 15 s), where a real scanner often sends them within a second.
- All traffic is inbound TCP to protected servers, so only `in` (never `out`) is set.
- Every day has the same working-day curve; there is no weekly cycle.
- The estate, the source addresses and their activity weights are the same in every run.
- With `anomaly_mode: true` each episode adds its own records: three to fifteen denied attempts and one intrusion prevention event, so scans of a web server on three or more ports are about one per episode more frequent than with `false`.

## Sample output

The intrusion prevention event of an episode from a default run (HTTP, with packet data):

```json
{"@timestamp": "2026-09-04T12:00:36+00:00", "destination": {"ip": "10.50.20.161", "mac": "00-50-56-1E-3F-F5", "port": 80}, "ecs": {"version": "8.17.0"}, "event": {"action": "ids:reset", "category": ["intrusion_detection"], "code": "1011163", "dataset": "trendmicro.deep_security", "kind": "event", "original": "Sep  4 12:00:36 dsm-01.corp.example CEF:0|Trend Micro|Deep Security Agent|20.0.877|1011163|Spring Boot Actuator Directory Traversal Vulnerability (CVE-2021-21234)|8|cn1=122 cn1Label=Host ID dvchost=web-05.corp.example TrendMicroDsTenant=Primary TrendMicroDsTenantId=0 dmac=00:50:56:1E:3F:F5 smac=00:1C:73:4A:0E:01 TrendMicroDsFrameType=IP src=10.20.236.146 dst=10.50.20.161 in=575 cs3=DF cs3Label=Fragmentation Bits proto=TCP spt=59425 dpt=80 cs2=0x18 ACK PSH cs2Label=TCP Flags cnt=1 act=IDS:Reset cn3=178 cn3Label=Intrusion Prevention Packet Position cs5=2274 cs5Label=Intrusion Prevention Stream Position cs6=8 cs6Label=Intrusion Prevention Flags TrendMicroDsPacketData=R0VUIC9tYW5hZ2UvbG9nL3ZpZXc/ZmlsZW5hbWU9L2V0Yy9wYXNzd2QmYmFzZT0uLi8uLi8uLi8uLi8gSFRUUC8xLjENCkhvc3Q6IHdlYi0wNS5jb3JwLmV4YW1wbGUNCg\\=\\=", "severity": 8, "type": ["info"]}, "host": {"id": "122", "ip": ["10.50.20.161"], "name": "web-05.corp.example"}, "network": {"transport": "tcp", "type": "ipv4"}, "observer": {"hostname": "web-05.corp.example", "product": "Deep Security Agent", "vendor": "Trend Micro", "version": "20.0.877"}, "related": {"hosts": ["122", "web-05.corp.example"], "ip": ["10.20.236.146", "10.50.20.161"]}, "rule": {"id": "1011163", "name": "Spring Boot Actuator Directory Traversal Vulnerability (CVE-2021-21234)"}, "source": {"ip": "10.20.236.146", "mac": "00-1C-73-4A-0E-01", "port": 59425}, "trendmicro": {"deep_security": {"action": "IDS:Reset", "bytes_in": 575, "event_category": "intrusion-prevention-event", "name": "Spring Boot Actuator Directory Traversal Vulnerability (CVE-2021-21234)", "severity": "8", "signature_id": 1011163, "tenant_id": "0", "tenant_name": "Primary"}}}
```

## References

- [Deep Security 20: Syslog message formats](https://help.deepsecurity.trendmicro.com/20_0/on-premise/event-syslog-message-formats.html)
- [Elastic Trend Micro integration](https://github.com/elastic/integrations/tree/main/packages/trendmicro)

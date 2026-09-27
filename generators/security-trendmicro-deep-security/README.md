# Trend Micro Deep Security Agent CEF

Firewall and intrusion prevention events of Trend Micro Deep Security 20 Agents on protected servers, relayed by Deep Security Manager over syslog in CEF. Each record is ECS JSON with the native syslog line in `event.original`; field names follow the Elastic Trend Micro integration.

The protected estate is 40 servers (web, application and database roles, Linux or Windows) and 180 internal source addresses. Every source has its own activity weight; traffic is a superposition of independent random processes: ordinary connections matched by log-only firewall rules (busier during the working day), denied connection attempts on one to five blocked ports of one host (flat over the day), and intrusion prevention detections against web services.

## Event types

Shares measured on a 78-hour default capture (`anomaly_mode: true`, 27,201 events, 3 episodes).

| CEF signature ID | Event | `act` | Share | ECS category |
|---|---|---|---|---|
| `20` | Log-only firewall rule (`Log Inbound HTTP`, `HTTPS`, `SSH`, `RDP`) | `Log` | 84.2% | `network` |
| `21` | Deny firewall rule (`Deny Inbound SMB`, `Telnet`, `MSSQL` and 7 more) | `Deny` | 12.6% | `network` |
| `1000000`-`1999999` | Intrusion prevention rule (11 Trend Micro rules, rule ID = signature ID) | `IDS:Reset` | 3.2% | `intrusion_detection` |

The shares are synthetic workload weights, not vendor-measured rates. Log-only and deny rule names are customer-defined in Deep Security; the shipped ones are examples. The intrusion prevention rule IDs and names are real Trend Micro rules, taken from a Deep Security Manager rule update record.

## Anomaly Chain

`anomaly_mode` defaults to `true`. With `false` the generator emits the background only and the complete chain never occurs.

Sequence, all for one source S (`src` / `source.ip`) and one protected web server H (`cn1` / `dvchost` / `host.name`, `dst`):

1. Deny firewall event (signature `21`, `act=Deny`, TCP SYN) from S to H on blocked port P1.
2. Deny from S to H on a second blocked port P2.
3. Deny from S to H on a third blocked port P3 (four or five ports in about four episodes in ten); each port gets one to three attempts.
4. One to four intrusion prevention events (`act=IDS:Reset`) from S to H on HTTP or HTTPS: a port scan followed by exploit attempts against the service it found.

Linking fields: `src` / `source.ip`, `cn1` / `host.id`, `dvchost` / `host.name` and `dst` / `destination.ip` in all steps; distinct `dpt` / `destination.port` in steps 1-3.

Recurrence: an episode becomes due every `anomaly_interval_hours` of source time (default 24, minimum 2), first one interval after generation starts. It starts after a random delay (exponential, mean 20 minutes, flat over the day like the background denies). The next due time counts from the actual start, so a late episode never causes catch-up. Episodes in the final captures spanned 68 s to 14 minutes from the first deny to the first intrusion prevention event.

Variation: the source and the web server differ from the previous episode's; both are drawn with the background weights. Ports, attempt counts, gaps, rules and the HTTP/HTTPS split come from the same law as the background.

Detection idea: one source is denied on three or more distinct ports of one host and then triggers an intrusion prevention rule on that host within an hour. Every fragment occurs in background of both modes: five 78-hour background captures hold about 130 scans of a web server on three or more ports each, and after a scan of one or two ports the same source triggers an intrusion prevention rule within ten minutes in 28% of cases. What follows a scan does not depend on its port count otherwise: within ten minutes of a scan on 1-2 vs 3+ ports, the same source makes a logged connection in 32% vs 32% of cases and another source triggers an intrusion prevention rule on the host in 9% vs 10%. Only the complete sequence is kept out of the background: a background scan on three or more ports never gets the intrusion prevention follow-up (the other outcomes keep their shares), and an independent intrusion prevention event whose source was denied on three or more distinct ports of the same host within the last 3600 s (the chain window) becomes a logged connection of that source to the same web port at the same time.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Meaning |
|---|---|---|
| `anomaly_mode` | `true` | Add periodic episodes to the background |
| `anomaly_interval_hours` | `24` | Episode interval in source hours, 2-8760 |
| `manager_host` | `dsm-01.corp.example` | Syslog header host (the relaying manager) |
| `product_version` | `20.0.877` | CEF Device Version (the manager version for relayed events) |
| `tenant` | `Primary` | `TrendMicroDsTenant` |
| `tenant_id` | `0` | `TrendMicroDsTenantId` |
| `gateway_mac` | `00:1C:73:4A:0E:01` | `smac` of routed traffic |
| `domain` | `corp.example` | Domain of the protected host names |
| `host_count` | `40` | Protected servers, 10-200 (at least two must get the web role) |
| `source_count` | `180` | Source addresses, 20-1000 |
| `source_networks` | 3 networks | Networks the sources are drawn from |
| `server_network` | `10.50.20.0/24` | Network of the protected servers |
| `log_rules` | 4 rules | Log-only rules (`name`, `port`); ports 80, 443, 22 and 3389 are required |
| `deny_rules` | 10 rules | Deny rules (`name`, `port`), at least five |
| `ips_action` | `IDS:Reset` | `act` of intrusion prevention events (detect-only policy) |
| `ips_rules` | 11 rules | Intrusion prevention rules (`id`, `name`, CEF `severity`, `weight`, `request` line used for the packet data) |

### Output Parameters

The shipped `generator.yml` writes to a local file and uses no `${params.*}` or `${secrets.*}` placeholders. To send events to a backend, replace the `output` block and parameterize its endpoint and credentials, for example `hosts: ["${params.opensearch_host}"]` and `password: ${secrets.opensearch_password}`, then pass `--params '{"opensearch_host": "..."}'` and store the secret in the Eventum keyring.

## Usage

Live mode:

```bash
eventum generate --path generators/security-trendmicro-deep-security/generator.yml --id deep-security --live-mode true
```

Batch mode (bound the run with `start` / `end` on the `cron` input for a finite capture):

```bash
eventum generate --path generators/security-trendmicro-deep-security/generator.yml --id deep-security --live-mode false
```

Events go to `generators/security-trendmicro-deep-security/output/events.json`.

## Limitations

- Only Agent firewall (signature `20`, `21`) and intrusion prevention events. Anti-malware, integrity monitoring, log inspection, web reputation, application control, device control, policy firewall (`100`-`199`) and manager system events are not modeled, nor LEEF or basic syslog.
- Vendor documentation gives the CEF extension tables and truncated samples, not complete captured records. Extension order follows the Deep Security 20 samples; `TrendMicroDsTenant` / `TrendMicroDsTenantId` are placed after `dvchost` as in the documented manager-relayed samples. The documentation states that the order and presence of extensions may vary.
- CEF severity: `0` for log-only and `5` for deny events as in the documented samples; intrusion prevention severities `3`, `6`, `8`, `10` are assigned per rule and are not taken from the vendor rule catalog.
- Packet data (`TrendMicroDsPacketData`, `cs6=8`) is present only for HTTP detections and holds the request line and `Host` header; HTTPS detections carry no packet data (`cs6=0`). Log-only and deny events carry no packet data.
- One event per second at most, with whole-second timestamps as in the RFC 3164 header; the header carries no year and no time zone (UTC is used).
- All traffic is inbound TCP to protected servers, so only `in` (never `out`) is set.

## Sample output

The first intrusion prevention event of an episode from the final default capture (HTTP, with packet data):

```json
{"@timestamp": "2026-09-27T00:13:42+00:00", "destination": {"ip": "10.50.20.41", "mac": "00-50-56-1E-E4-CB", "port": 80}, "ecs": {"version": "8.17.0"}, "event": {"action": "ids:reset", "category": ["intrusion_detection"], "code": "1011143", "dataset": "trendmicro.deep_security", "kind": "event", "original": "Sep 27 00:13:42 dsm-01.corp.example CEF:0|Trend Micro|Deep Security Agent|20.0.877|1011143|WordPress \u0027ProfilePress\u0027 Plugin Privilege Escalation Vulnerability (CVE-2021-34621)|8|cn1=1035 cn1Label=Host ID dvchost=web-07.corp.example TrendMicroDsTenant=Primary TrendMicroDsTenantId=0 dmac=00:50:56:1E:E4:CB smac=00:1C:73:4A:0E:01 TrendMicroDsFrameType=IP src=10.40.8.228 dst=10.50.20.41 in=283 cs3=DF cs3Label=Fragmentation Bits proto=TCP spt=53439 dpt=80 cs2=0x18 ACK PSH cs2Label=TCP Flags cnt=1 act=IDS:Reset cn3=34 cn3Label=Intrusion Prevention Packet Position cs5=1046 cs5Label=Intrusion Prevention Stream Position cs6=8 cs6Label=Intrusion Prevention Flags TrendMicroDsPacketData=UE9TVCAvd3AtYWRtaW4vYWRtaW4tYWpheC5waHA/YWN0aW9uPXBwX2FqYXhfc2lnbnVwIEhUVFAvMS4xDQpIb3N0OiB3ZWItMDcuY29ycC5leGFtcGxlDQo\\=", "severity": 8, "type": ["info"]}, "host": {"id": "1035", "ip": ["10.50.20.41"], "name": "web-07.corp.example"}, "network": {"transport": "tcp", "type": "ipv4"}, "observer": {"hostname": "web-07.corp.example", "product": "Deep Security Agent", "vendor": "Trend Micro", "version": "20.0.877"}, "related": {"hosts": ["1035", "web-07.corp.example"], "ip": ["10.40.8.228", "10.50.20.41"]}, "rule": {"id": "1011143", "name": "WordPress \u0027ProfilePress\u0027 Plugin Privilege Escalation Vulnerability (CVE-2021-34621)"}, "source": {"ip": "10.40.8.228", "mac": "00-1C-73-4A-0E-01", "port": 53439}, "trendmicro": {"deep_security": {"action": "IDS:Reset", "bytes_in": 283, "event_category": "intrusion-prevention-event", "name": "WordPress \u0027ProfilePress\u0027 Plugin Privilege Escalation Vulnerability (CVE-2021-34621)", "severity": "8", "signature_id": 1011143, "tenant_id": "0", "tenant_name": "Primary"}}}
```

## References

- [Deep Security 20: Syslog message formats](https://help.deepsecurity.trendmicro.com/20_0/on-premise/event-syslog-message-formats.html)
- [Elastic Trend Micro integration](https://github.com/elastic/integrations/tree/main/packages/trendmicro)

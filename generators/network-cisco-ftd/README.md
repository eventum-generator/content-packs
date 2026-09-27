# Cisco Secure Firewall Threat Defense security events

Generates Cisco Secure Firewall Threat Defense (FTD) 6.6+ security event syslog messages as ECS JSON, for training SIEM content on perimeter IPS and connection telemetry. The source is one FTD device in front of three DMZ web servers, logging connection start and end events and intrusion events for inbound internet traffic directly from the device. `event.original` holds the syslog line: an RFC 3339 UTC timestamp, the device hostname, then `%FTD-<severity>-<id>:` and the comma-separated `Key: Value` fields.

## Event Types

Shares measured on the final default capture (78 h, `anomaly_mode: true`, 33,477 records).

| Message ID | Record | Share | Category |
|---|---|---:|---|
| `430002` | Connection start, `AccessControlRuleAction: Allow` | 39.12% (13097) | Network |
| `430003` | Connection end, `Allow` (no IPS drop) | 32.28% (10808) | Network |
| `430002` | Connection start, `Block` by the access policy (closed port) | 10.54% (3530) | Network |
| `430001` | Intrusion event, `InlineResult: Dropped` | 6.83% (2287) | Intrusion Detection |
| `430003` | Connection end, `Block` (IPS dropped the connection) | 6.83% (2287) | Network |
| `430001` | Intrusion event from a generate-only rule (no `InlineResult`) | 4.39% (1468) | Intrusion Detection |

Every allowed connection has a `430002` and a `430003` that share the correlation key the Cisco guide defines: `DeviceUUID`, `InstanceID` (Snort instance), `FirstPacketSecond` and `ConnectionID` (connection counter of that instance). Intrusion events carry the same key and fall between the start and end of their connection. A connection whose packets hit a Drop and Generate rule ends with `AccessControlRuleAction: Block`; any connection with an intrusion event ends with `EventPriority: High`, as the guide defines. Connections blocked by the access policy are logged at the beginning only, with zero counters. `ConnectionDuration` is the syslog time minus `FirstPacketSecond`.

Signatures: `1:17279` (from the Elastic fixture) and nine Snort 3 `http_inspect` built-in events (GID 119). Five are in the Drop and Generate state (`1:17279`, `119:2`, `119:4`, `119:11`, `119:18`); five only generate events (`119:6`, `119:8`, `119:13`, `119:31`, `119:33`). IPS events occur only on HTTP (port 80), since HTTPS is not decrypted.

## Background Model

Each one-second tick emits at most one record: the earliest due record, otherwise nothing. Three independent random streams feed the queue:

- **Visits** (0.02 per second, scaled by an hour-of-day factor: 07:00-19:00 UTC 1.38, 19:00-23:00 0.92, night 0.46): a client opens 1-4 connections to one server (weights 55/30/15) with log-normal gaps, 82% HTTPS. An HTTP connection triggers a generate-only signature with probability 5% and a dropping one with 1.2%.
- **Probing** (0.004 per second, flat over the day): a client sends HTTP requests to one server that trigger 1-5 distinct signatures of all ten, 1-3 connections per signature, gaps log-normal with median 25 s; then it opens an ordinary HTTPS (30%) or HTTP (20%) connection to that server about 90 s later, or stops (50%).
- **Closed ports** (0.008 per second, flat): 1-3 attempts from a client to a closed port of one server, blocked by `Block-Inbound-Other`.

Clients are 200 documentation-range addresses (`198.51.100.0/24`, `203.0.113.0/24`, `192.0.2.0/24`), each with a fixed log-normal activity weight and a fixed HTTP client (Chrome, Firefox or cURL), shared by all streams. Source ports, Snort instances and counter increments are random.

## Anomaly Chain

`anomaly_mode` defaults to `true`. With `false` the generator emits the background only and the complete chain never occurs.

Sequence, all for one client C (`source.ip`) and one DMZ web server W (`destination.ip`):

1. `430002` Allow, HTTP from C to W; `430001` with signature S1 and `InlineResult: Dropped` on that connection; `430003` `Block`, `EventPriority: High`.
2. The same on a new connection with a second dropping signature S2.
3. The same with a third dropping signature S3 (four or five signatures in about four episodes in ten). Each signature gets 1-3 connections.
4. `430002` Allow, HTTPS (port 443) from C to W, followed by its `430003` `Allow`.

Linking fields: `source.ip` / `SrcIP` and `destination.ip` / `DstIP` in all steps; distinct `cisco.ftd.security.sid` / `SID` with `InlineResult: Dropped` in steps 1-3; each step's records share `DeviceUUID`, `InstanceID`, `FirstPacketSecond`, `ConnectionID`.

Recurrence: an episode becomes due every `anomaly_interval_hours` of source time (default 24, minimum 2), first one interval after generation starts. It starts after a random delay (exponential, mean 20 min, flat over the day like background probing). The next due time counts from the actual start, so a late episode never causes catch-up. Measured: default captures 24.02-24.03 h apart, 6-hour captures 6.00-6.57 h apart; 69 s to 17 minutes from the first drop to the HTTPS connection.

Variation: the client and the server differ from the previous episode's; both are drawn with the background weights. Signatures, connection counts and gaps come from the same law as background probing.

Detection idea: the IPS drops three or more distinct exploit signatures from one source against one server over HTTP, and the source then opens an HTTPS connection to the same server within an hour, where the IPS cannot see the payload. Every fragment occurs in background: a 78 h background capture holds 79-106 client-server pairs with three or more distinct dropped signatures within an hour and 560-720 HTTPS connections that follow drops of one or two distinct signatures. After a pair reaches three distinct dropped signatures, the same client keeps opening HTTP connections to that server and HTTPS connections to the other servers at its usual rate, and HTTPS connections to that server resume at their usual rate once the drops are an hour old. Every episode client also talks to its server outside the episode. Only the complete sequence is kept out of the background: an ordinary HTTPS connection that would follow drops of three or more distinct signatures from the same client to the same server within the last hour keeps its time and server and is made by another client, drawn by the background weights.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Meaning |
|---|---|---|
| `anomaly_mode` | `true` | Add periodic episodes to the background |
| `anomaly_interval_hours` | `24` | Episode interval in source hours, 2-8760 |
| `ftd_hostname` | `ftd-dmz-01` | Syslog hostname and `observer.hostname` |
| `device_uuid` | `6c1d2f3a-7b8e-11ee-9f4a-5a1b2c3d4e5f` | `DeviceUUID` |
| `syslog_severity` | `1` | Severity in `%FTD-<severity>-<id>` and `event.severity` |
| `snort_instances` | `8` | Number of Snort instances (`InstanceID` range) |
| `ac_policy` | `DMZ-Access-Policy` | `ACPolicy` |
| `prefilter_policy` | `Default Prefilter Policy` | `Prefilter Policy` |
| `intrusion_policy` | `DMZ-IPS-Policy` | `IntrusionPolicy` |
| `nap_policy` | `Balanced Security and Connectivity` | `NAPPolicy` |
| `allow_rule` | `Allow-Inbound-Web` | Access rule for web traffic |
| `block_rule` | `Block-Inbound-Other` | Access rule for closed ports |
| `client_count` | `200` | Number of internet clients, 20-1000 |
| `web_servers` | 3 servers | List of `ip`, `host` (`ReferencedHost`, `URL`), `weight`; at least two |
| `closed_ports` | 10 ports | Destination ports of blocked attempts |

### Output Parameters

The shipped config writes `output/events.json` with the `json` formatter and needs no `${params.*}` or `${secrets.*}`. To send events elsewhere, replace the `output` section, for example:

```yaml
output:
  - opensearch:
      hosts: ["${params.opensearch_url}"]
      username: ${params.opensearch_user}
      password: ${secrets.opensearch_password}
      index: cisco-ftd
```

A syslog collector that parses the native format needs `event.original` rather than the surrounding JSON.

## Usage

Live mode:

```bash
eventum generate --path generators/network-cisco-ftd/generator.yml --id cisco-ftd --live-mode true
```

Batch mode needs a bounded input: add `start` and `end` to the `cron` input, then run:

```bash
eventum generate --path generators/network-cisco-ftd/generator.yml --id cisco-ftd --live-mode false
```

## Limitations

- Field names, meanings and the correlation key come from the Cisco security event syslog guide; key order follows the raw FTD lines in the Elastic `cisco_ftd` test fixtures (6.6+ lines with `DeviceUUID` for all three IDs). The guide has no complete 430001/430003 example of its own. The header layout (`<timestamp> <hostname>  %FTD-...`) is the fixtures' form; a syslog PRI and relay header are not added.
- Only inbound IPv4 TCP to three web servers is modeled: no outbound users, identity (`User` is always `No Authentication Required`), DNS, ICMP, UDP, NAT, SSL, Security Intelligence, file or malware events (430004/430005), `Trust`/`Fastpath`/`Monitor` actions or `AccessControlRuleReason`. `IPSCount`, `UserAgent`, `ClientVersion` and `WebApplication` are omitted.
- Signature tuples: `1:17279` revision, message and classification are from the fixture; the GID 119 messages and SIDs are from the Snort 3 `http_inspect` source, `119:6` revision 3 and classification `Not Suspicious Traffic` / priority 3 are from the fixture and reused for the other GID 119 events, whose revision is set to 1. Which rules drop is a policy assumption.
- Counters, durations, rates, weights and the HTTP response mix are training assumptions, not measured values. The device time zone is UTC; timestamps have one-second resolution, and the generator emits at most one record per second, so busy periods queue records by a few seconds.
- ECS mapping follows the Elastic integration's expected output (`event.action`, `event.type`, `observer.*`, `cisco.ftd.security_event.*`), except that `@timestamp` is the syslog time for `430003` too (Elastic uses the first packet time) and `event.type` of a dropped intrusion event is `["info", "denied"]` (inferred).
- Episodes start at any hour, like background probing; ordinary visits follow the hour-of-day factor, so a night-time step 4 falls into quieter traffic.
- KUMA 4.2 lists FTD under its Cisco ASA/IOS syslog normalizer; handling of these security event fields has not been tested.

## Sample Output

The HTTPS connection start that completes the first episode (step 4: `203.0.113.38` reaches `172.16.10.11` after drops of three distinct signatures), copied byte for byte from the final default capture (line 10790):

```json
{"@timestamp": "2026-09-27T00:29:58+00:00", "cisco": {"ftd": {"security_event": {"ac_policy": "DMZ-Access-Policy", "access_control_rule_action": "Allow", "access_control_rule_name": "Allow-Inbound-Web", "connection_id": 53601, "device_uuid": "6c1d2f3a-7b8e-11ee-9f4a-5a1b2c3d4e5f", "dst_ip": "172.16.10.11", "dst_port": 443, "egress_interface": "dmz", "egress_vrf": "Global", "egress_zone": "DMZ", "event_priority": "Low", "first_packet_second": "2026-09-27T00:29:58Z", "ingress_interface": "outside", "ingress_vrf": "Global", "ingress_zone": "Outside", "initiator_bytes": 74, "initiator_packets": 1, "instance_id": 8, "nap_policy": "Balanced Security and Connectivity", "prefilter_policy": "Default Prefilter Policy", "protocol": "tcp", "responder_bytes": 0, "responder_packets": 0, "src_ip": "203.0.113.38", "src_port": 4121, "user": "No Authentication Required"}}}, "destination": {"bytes": 0, "ip": "172.16.10.11", "packets": 0, "port": 443}, "ecs": {"version": "8.17.0"}, "event": {"action": "connection-started", "category": ["network"], "code": "430002", "kind": "event", "original": "2026-09-27T00:29:58Z ftd-dmz-01  %FTD-1-430002: EventPriority: Low, DeviceUUID: 6c1d2f3a-7b8e-11ee-9f4a-5a1b2c3d4e5f, InstanceID: 8, FirstPacketSecond: 2026-09-27T00:29:58Z, ConnectionID: 53601, AccessControlRuleAction: Allow, SrcIP: 203.0.113.38, DstIP: 172.16.10.11, SrcPort: 4121, DstPort: 443, Protocol: tcp, IngressInterface: outside, EgressInterface: dmz, IngressZone: Outside, EgressZone: DMZ, IngressVRF: Global, EgressVRF: Global, ACPolicy: DMZ-Access-Policy, AccessControlRuleName: Allow-Inbound-Web, Prefilter Policy: Default Prefilter Policy, User: No Authentication Required, InitiatorPackets: 1, ResponderPackets: 0, InitiatorBytes: 74, ResponderBytes: 0, NAPPolicy: Balanced Security and Connectivity", "severity": 1, "timezone": "UTC", "type": ["connection", "start", "allowed"]}, "network": {"direction": "inbound", "iana_number": "6", "transport": "tcp"}, "observer": {"egress": {"interface": {"name": "dmz"}, "zone": "DMZ"}, "hostname": "ftd-dmz-01", "ingress": {"interface": {"name": "outside"}, "zone": "Outside"}, "product": "ftd", "type": "idps", "vendor": "Cisco"}, "related": {"hosts": ["ftd-dmz-01"], "ip": ["203.0.113.38", "172.16.10.11"]}, "rule": {"name": "Allow-Inbound-Web", "ruleset": "DMZ-Access-Policy"}, "source": {"bytes": 74, "ip": "203.0.113.38", "packets": 1, "port": 4121}}
```

## References

- [Cisco Secure Firewall Threat Defense syslog messages: security event syslog messages (IDs, intrusion and connection field descriptions)](https://www.cisco.com/c/en/us/td/docs/security/firepower/Syslogs/fptd_syslog_guide/security-event-syslog-messages.html)
- [Elastic cisco_ftd integration and pipeline test fixtures](https://github.com/elastic/integrations/tree/main/packages/cisco_ftd)
- [Snort 3 http_inspect built-in event messages](https://github.com/snort3/snort3/blob/master/src/service_inspectors/http_inspect/http_tables.cc) and [event IDs](https://github.com/snort3/snort3/blob/master/src/service_inspectors/http_inspect/http_enum.h)
- [KUMA 4.2 supported event sources](https://support.kaspersky.ru/kuma/4.2/255782)

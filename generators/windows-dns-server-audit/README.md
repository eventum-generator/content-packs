# Microsoft DNS Server Audit and Analytical Logs

Generates the query-policy records of a Windows DNS Server as parsed ECS JSON: Audit channel policy creation and deletion (577/580) and ETW Analytical query records (256/257/259). The selected profile is a Windows Server 2022 authoritative IPv4/UDP server for one zone, with recursion disabled and the Analytical channel enabled. Records follow the shape that the Elastic `microsoft_dnsserver` ingest pipeline produces (parsed test fixtures pinned below): native event data renamed under `microsoft_dnsserver.*`, ECS fields set by the pipeline (`network.*`, `dns.question.*` including `registered_domain`, `event.outcome`, `event.reason`, `related.*`), rendered `message`, with `preserve_duplicate_custom_fields` so duplicate custom fields are kept. It is not a Windows XML, EVTX or ETL export.

## Event Types

Shares are measured on a 96-hour default capture with `anomaly_mode: true`. The category is `event.category`; the parsed Audit records carry none.

| Native ID | Channel | Category | Share | Meaning |
| --- | --- | --- | ---: | --- |
| 256 `QUERY_RECEIVED` | Analytical | network | 49.9% | Incoming A query: source IP and port, XID, RD and DNS packet bytes |
| 257 `RESPONSE_SUCCESS` | Analytical | network | 36.5% | Authoritative A answer with the same client, port, XID and GUID |
| 259 `IGNORED_QUERY` | Analytical | network | 13.5% | A query dropped by an `Ignore` policy; no 257 follows |
| 577 `POLICY_OP` | Audit | - | 0.06% | An administrator creates a server-level `Ignore` query policy |
| 580 `POLICY_OP` | Audit | - | 0.05% | An administrator deletes a policy |

### Background

- **Clients.** 60 workstations resolve names from `samples/queries.json`. Lookups arrive at random, thinned by a UTC hour-of-day curve (busy 08:00-17:00). A lookup covers one name, or up to six names resolved in parallel within a few milliseconds. Each client has its own random activity level.
- **Answers.** A name without a matching policy gets a 257 answer after a fraction of a millisecond, with QR/AA/RD flags, RA clear, one A record and TTL 300.
- **Drops.** A name that matches an active policy is dropped (259). The Windows DNS client then retransmits the query after 1, 1, 2 and 4 seconds, as documented for a client with one configured server. Each retransmission is dropped again while the policy is active and answered once it is gone.
- **Administrators.** Five accounts in `samples/admins.json` open sessions at random, at different rates, thinned by the same hour curve. A session performs one to four operations about a minute apart. Most create a policy for a target in `samples/targets.json` that has no active policy; about one in four deletes an active policy picked at random (cleanup). A policy lives a few minutes (a test or a mistake), an hour or two, or several hours. Its creator deletes it in most short cases and in half of the longer ones; another administrator deletes the rest.

Every feature the chain uses occurs in this background in both modes: every administrator, target, client and name; policies created and deleted by one account within minutes; policies dropping queries from the same client several times within seconds; policies deleted by another account within an hour after drops.

## Anomaly Chain

`anomaly_mode: true` (the default) adds recurring short-lived blackhole episodes. `anomaly_mode: false` produces only the background above, with no complete chain.

1. `577`: an administrator creates an `Ignore` policy for one of the targets.
2. `259` x3 or more: ordinary client queries for the target are dropped by that policy.
3. `580`: the same administrator deletes the policy, restoring resolution. The whole sequence stays within one hour of the creation.

**Linking fields.** The policy name joins all three steps (`microsoft_dnsserver.audit.policy` on 577/580, `microsoft_dnsserver.analytical.policy_name` on 259). The account is `winlog.user.name` on 577 and 580. A drop joins its 256 by `source.ip`, `dns.id` and `dns.question.name`.

**Recurrence.** Episodes repeat every `anomaly_interval_hours` (default 24, minimum 2) of source time. The first episode falls within the first `min(interval, 24 h)` of the capture, at an hour drawn from the activity curve. Each later one falls in a window of `min(interval / 4, 6 h)` centred one interval after the previous actual start, with its hour weighted by the curve squared plus a small floor, so it lands in busy hours. A missed episode is not replayed. The creation follows its drawn start after a random delay of about a minute. Because each window is centred one interval after the previous start, an interval far from a multiple of 24 hours moves episodes into quieter hours: with 12 hours, every other episode falls in the evening or at night. At intervals of 8 hours or less, the windows cover the whole clock.

**Variation.** Each episode uses an administrator other than the previous episode's and a target other than the previous episode's. The administrator weights are set so that, over many episodes, each administrator's share of episodes equals its share of background self-deletions; the target is weighted like background policy creation. The drops come from whatever client traffic reaches the target. The deletion follows the third drop after a random delay of a few minutes. When fewer than three queries reach the target before a random deadline 24 to 58 minutes after creation, the administrator deletes the policy anyway, and the episode stays incomplete. This happens mostly for rarely queried targets at night.

**Detection idea.** Alert when one account creates a query-resolution policy and deletes it again within an hour, after the policy has dropped client queries. Neither part is unusual alone: short test policies and long-lived blocks both occur daily.

**Background guard.** A background deletion that would complete the chain (by the creator, within one hour of the creation, after three or more drops) is not performed. The policy stays active until a later ordinary deletion by a cleanup operation. This keeps the complete chain out of the background.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Meaning |
| --- | --- | --- |
| `server_name` | `dns-01.corp.example.com` | DNS server host name (`host.name`, `winlog.computer_name`, `name_server`) |
| `server_ip` | `10.20.0.53` | Server interface address (`interface_ip` on 256/257) |
| `zone` | `corp.example.com` | Authoritative zone reported on 257/259 |
| `domain` | `CORP` | Domain of the administrator accounts |
| `domain_sid` | `S-1-5-21-1004336348-1177238915-682003330` | Domain SID; each account adds its RID |
| `policy_name` | `QueryFilter` | Policy name stem; names are `<stem>-<target label>-<4 hex>` |
| `anomaly_mode` | `true` | Enables the recurring episodes |
| `anomaly_interval_hours` | `24` | Episode interval in hours, 2 to 8760 |

Names, answer addresses and query weights live in `samples/queries.json`, policy targets and their `FQDN=EQ` criteria in `samples/targets.json`, administrators with their RIDs and session rates in `samples/admins.json`, and client addresses in `samples/clients.json`. Keep names and criteria inside `zone` when changing it. `dns.question.registered_domain` is derived as the pipeline's public-suffix lookup does for a zone under a single-label suffix such as `com`; for other zones adjust it in the template.

### Output Parameters

The shipped configuration writes `output/events.json` with the `json` formatter and has no `${params.*}` or `${secrets.*}` placeholders. Override `output` in `generator.yml`, for example with a `file` path of your own or a SIEM output plugin.

## Usage

Live, one record at most per second of wall clock:

```bash
eventum generate --path generators/windows-dns-server-audit/generator.yml --id windows-dns-server-audit --live-mode true
```

Batch: add `start` and `end` to the `cron` input (for example `2026-09-21T00:00:00Z` and `2026-09-25T00:00:00Z` for four days with four episodes), then run:

```bash
eventum generate --path generators/windows-dns-server-audit/generator.yml --id windows-dns-server-audit --live-mode false --keep-order true
```

## Sample Output

A 259 record of an episode, copied byte for byte from the default 96-hour capture:

```json
{"@timestamp": "2026-09-21T08:27:37.812Z", "data_stream": {"dataset": "microsoft_dnsserver.analytical", "namespace": "default", "type": "logs"}, "dns": {"id": "14084", "question": {"name": "print-old.corp.example.com", "registered_domain": "example.com", "subdomain": "print-old.corp", "top_level_domain": "com", "type": "A"}}, "ecs": {"version": "8.17.0"}, "event": {"action": "LOOK_UP", "category": ["network"], "code": "259", "dataset": "microsoft_dnsserver.analytical", "kind": "event", "provider": "Microsoft-Windows-DNSServer", "reason": "Policy", "severity": 2, "type": ["protocol"]}, "host": {"name": "dns-01.corp.example.com"}, "input": {"type": "etw"}, "log": {"file": {"path": "Microsoft-Windows-DNSServer-Analytical.etl"}, "level": "error"}, "message": "IGNORED_QUERY: TCP=0; InterfaceIP=; Source=10.20.5.112; Reason=Policy; QNAME=print-old.corp.example.com.; QTYPE=1; XID=14084; Zone=corp.example.com; PolicyName=QueryFilter-print-old-4703; AdditionalInfo = VirtualizationInstance: .", "microsoft_dnsserver": {"analytical": {"additional_info": ".", "description": "Ignored query", "policy_name": "QueryFilter-print-old-4703", "question_name": "print-old.corp.example.com.", "question_type": "A", "reason": "Policy", "source": {"ip": "10.20.5.112"}, "xid": "14084", "zone": "corp.example.com"}}, "network": {"direction": "ingress", "protocol": "dns", "transport": "udp"}, "process": {"pid": 3688, "thread": {"id": 5696}}, "related": {"ip": ["10.20.5.112"]}, "source": {"ip": "10.20.5.112"}, "tags": ["preserve_duplicate_custom_fields"], "user": {"id": "NT AUTHORITY\\SYSTEM"}, "winlog": {"channel": "Microsoft-Windows-DNS-Server/Analytical", "flags": ["64_BIT_HEADER", "EXTENDED_INFO", "PROCESSOR_INDEX"], "flags_raw": "0x241", "keywords": ["IGNORED_QUERY"], "keywords_raw": "0x8000000000000008", "level": "Error", "level_raw": 2, "opcode_raw": 0, "provider_guid": "{EB79061A-A566-4698-9119-3ED2807060E7}", "provider_message": "Microsoft-Windows-DNS-Server", "session": "Microsoft-Windows-DNSServer-Analytical.etl", "task": "LOOK_UP", "task_raw": 1, "version": 0}}
```

## Limitations

- The field shapes follow the pinned Elastic parsed fixtures, not a version-matched Windows Server 2022 capture. Differences from those fixtures: `data_stream.*` and `host.name` are always present (the fixtures carry them only in some records), and agent, cloud, geo/AS enrichment, `event.created`, `event.ingested` and `event.agent_id_status` are omitted.
- The published 259 examples carry `Reason=System` and `PolicyName=NULL`; `Reason=Policy`, the policy name and the zone on a policy drop are inferred. The 259 interface address is left empty as in the newest published 259 record, so no `interface_ip` is set; the older record shows `0.0.0.0`. No complete 580 record was found; its two fields follow the documented message placeholders.
- `ElapsedTime` is written as whole milliseconds of the modeled answer time; the fixtures do not establish its unit.
- Retransmissions reuse the XID and source port of the original query; the Microsoft article documents the timing, not the packet identity.
- Only A queries for existing records are modeled: no NXDOMAIN, other record types, TCP, recursion or zone and record changes. Audit record numbers skip values for those unmodeled Audit events.
- Query volume (about 0.1 queries per second on average), policy churn (about 13 policies per day) and lifetimes are synthetic. A real enterprise DNS server answers far more queries.
- The hour curve is in UTC and applies to clients and administrators alike; background deletions are not tied to working hours.
- The background guard skips a few background deletions inside the window, so those policies stay active longer, until a cleanup deletes them.
- `process.pid` is one random DNS service PID per run and `process.thread.id` is drawn from a small random pool. `event.original` is omitted.

## References

- [DNS logging and diagnostics](https://learn.microsoft.com/en-us/windows-server/networking/dns/dns-logging-and-diagnostics) - Audit 577/580 and Analytical 257/259 messages, channels and provider GUID.
- [Add-DnsServerQueryResolutionPolicy](https://learn.microsoft.com/en-us/powershell/module/dnsserver/add-dnsserverqueryresolutionpolicy?view=windowsserver2025-ps) and [Remove-DnsServerQueryResolutionPolicy](https://learn.microsoft.com/en-us/powershell/module/dnsserver/remove-dnsserverqueryresolutionpolicy?view=windowsserver2025-ps) - server-level FQDN criteria, processing order, `Ignore` drops a query without a response.
- [DNS client resolution timeouts](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/dns-client-resolution-timeouts) - Windows DNS client retransmission after 1, 1, 2 and 4 seconds.
- Elastic `microsoft_dnsserver` integration pinned at `78fd455d22cdb74bd2a8e53249c25cc060f06010`: parsed fixtures [Audit](https://github.com/elastic/integrations/blob/78fd455d22cdb74bd2a8e53249c25cc060f06010/packages/microsoft_dnsserver/data_stream/audit/_dev/test/pipeline/test-events.json-expected.json) and [Analytical](https://github.com/elastic/integrations/blob/78fd455d22cdb74bd2a8e53249c25cc060f06010/packages/microsoft_dnsserver/data_stream/analytical/_dev/test/pipeline/test-events.json-expected.json), their [Audit](https://github.com/elastic/integrations/blob/78fd455d22cdb74bd2a8e53249c25cc060f06010/packages/microsoft_dnsserver/data_stream/audit/_dev/test/pipeline/test-events.json) and [Analytical](https://github.com/elastic/integrations/blob/78fd455d22cdb74bd2a8e53249c25cc060f06010/packages/microsoft_dnsserver/data_stream/analytical/_dev/test/pipeline/test-events.json) inputs, and the [Analytical ingest pipeline](https://github.com/elastic/integrations/blob/78fd455d22cdb74bd2a8e53249c25cc060f06010/packages/microsoft_dnsserver/data_stream/analytical/elasticsearch/ingest_pipeline/default.yml).

# Microsoft DNS Server Audit and Analytical Logs

Generates the query-policy records of a Windows DNS Server as parsed ECS JSON: Audit channel policy creation and deletion (577/580) and ETW Analytical query records (256/257/259). The selected profile is a Windows Server 2022 authoritative IPv4/UDP server for one zone, with recursion disabled and the Analytical channel enabled. Records follow the shape that the Elastic `microsoft_dnsserver` ingest pipeline produces (parsed test fixtures pinned below): native event data renamed under `microsoft_dnsserver.*`, ECS fields set by the pipeline (`network.*`, `dns.question.*` including `registered_domain`, `event.outcome`, `event.reason`, `related.*`), rendered `message`, with `preserve_duplicate_custom_fields` so duplicate custom fields are kept. It is not a Windows XML, EVTX or ETL export.

## Volume and Timing

About 57,000 records a day, varying by about ±3% from day to day, following an hour-of-day curve in the generator time zone (UTC by default):

| Hours | Records/s |
| --- | ---: |
| 08-17 | 1.20 |
| 06-08, 17-20 | 0.54 |
| 20-06 | 0.24 |

A 257 or 259 follows its 256 after a median of 1.1 s (99th percentile 17 s, at most about 80 s at night). A retransmission of a dropped query follows the previous attempt after a median of 1.2 s (90th percentile 5-6 s). Episode records are interleaved with this traffic, taking the place of a few dozen client lookups per episode; they never pause or shift administrator sessions.

## Event Types

Shares over 15 days with `anomaly_mode: true` and the default interval, and the range over 7- to 15-day spans without episodes. The category is `event.category`; the parsed Audit records carry none.

| Native ID | Channel | Category | Share | Range without episodes | Meaning |
| --- | --- | --- | ---: | ---: | --- |
| 256 `QUERY_RECEIVED` | Analytical | network | 50.00% | 50.00% | Incoming A query: source IP and port, XID, RD and DNS packet bytes |
| 257 `RESPONSE_SUCCESS` | Analytical | network | 49.17% | 46.9-49.1% | Authoritative A answer with the same client, port, XID and GUID |
| 259 `IGNORED_QUERY` | Analytical | network | 0.82% | 0.6-3.1% | A query dropped by an `Ignore` policy; no 257 follows |
| 577 `POLICY_OP` | Audit | - | 0.004% | 0.003% | An administrator creates a server-level `Ignore` query policy |
| 580 `POLICY_OP` | Audit | - | 0.004% | 0.003% | An administrator deletes a policy |

About 0.2-1.3% of client lookups are dropped, the higher values in weeks where a policy stays in place for days; each dropped lookup brings up to five 259 records with its retransmissions. Policies are created about twice a day, 22-38 in 15 days without episodes.

### Background

- **Clients.** 60 workstations resolve names from `samples/queries.json`, about 28,000 queries a day (retransmissions included) following the hour curve above. A lookup covers one name, or up to six names resolved in parallel. Each client has its own random activity level.
- **Answers.** A name without a matching policy gets a 257 answer with QR/AA/RD flags, RA clear, one A record and TTL 300. `ElapsedTime` is the modeled answer time, a fraction of a millisecond.
- **Drops.** A name that matches an active policy is dropped (259). The Windows DNS client then retransmits the query after 1, 1, 2 and 4 seconds, as documented for a client with one configured server. Each retransmission is dropped again while the policy is active and answered once it is gone.
- **Administrators.** Five accounts in `samples/admins.json` change query policies occasionally, mostly during office hours in the generator time zone (busy 08:00-17:00); together they create about two policies a day. A session performs one policy operation, sometimes two a minute apart; about one in eight deletes an active policy picked at random (cleanup), the rest create one. Three accounts own a name they block from time to time, each about once every two days: `a.petrov` is retiring `legacy-crm` and blocks it to find the clients that still use it (a scream test), `dns.ops` blocks `wpad` and `m.sokolova` vendor `telemetry`. 90% of their policies are on their own name. `i.volkov` and `adm.kuznetsov` act only every few days and block any target of `samples/targets.json` (`isatap`, `print-old`, `ftp`, lab and test names, the other accounts' names). A target with an active policy is not blocked twice; an owner whose own name is already blocked blocks another target instead. A fifth of the policies are mistakes undone by their creator within a minute or so, and half of those are added again a minute later; about 40% are rolled back by a colleague after roughly half an hour because users complain; the rest are temporary blocks of about two hours or kept for several hours, deleted by their creator or another administrator. The creator never deletes a policy within an hour after it dropped three or more queries: that deletion removes another active policy instead, or does not happen if no other policy is active, and the policy stays until a later deletion.

Every part of the chain occurs in this background in both modes: each of the three name owners with its own name, every client and name; policies created and deleted by one account within minutes; policies dropping queries from the same client several times within seconds; policies deleted by another account within an hour after drops (the rollbacks). Each name owner creates and deletes policies on its own name several times a week. Only the combination is missing: a self-deletion within an hour after drops. A dropped query is always retransmitted, so a policy that drops anything drops at least three records.

## Anomaly Chain

`anomaly_mode: true` (the default) adds recurring short-lived blackhole episodes. `anomaly_mode: false` produces only the background above, with no complete chain.

1. `577`: an administrator creates an `Ignore` policy for one of the targets.
2. `259` x3 or more: ordinary client queries for the target are dropped by that policy.
3. `580`: the same administrator deletes the policy, restoring resolution. The whole sequence stays within one hour of the creation.

**Linking fields.** The policy name joins all three steps (`microsoft_dnsserver.audit.policy` on 577/580, `microsoft_dnsserver.analytical.policy_name` on 259). The account is `winlog.user.name` on 577 and 580. A drop joins its 256 by `source.ip`, `dns.id` and `dns.question.name`.

**Recurrence.** Episodes repeat every `anomaly_interval_hours` (default 72, minimum 2) of source time. The first episode falls within the first `min(interval, 24 h)` of the run. Each later one falls in a window of `min(interval / 4, 6 h)` centred one interval after the previous actual start. In both cases the hour is weighted by the administrator curve squared plus a small floor, so episodes land in busy hours. The three-day default keeps episodes as occasional as the administrators' own policy work. A missed episode is not replayed. The creation follows its drawn start after a random delay of about a minute. Because each window is centred one interval after the previous start, an interval far from a multiple of 24 hours moves episodes into quieter hours: with 12 hours, every other episode falls in the evening or at night. At intervals of 8 hours or less, the windows cover the whole clock.

**Variation.** Each episode is run by one of the three name owners (`a.petrov`, `dns.ops`, `m.sokolova`), never by the account of the previous episode, on that account's own name, so the target also differs from the previous episode's. `i.volkov` and `adm.kuznetsov` never run an episode. Over many episodes, each owner's share of episodes equals its share of the owners' background activity. An owner whose name already has an active policy is skipped. The drops come from whatever client traffic reaches the target. The deletion follows the third drop after a random delay of a few minutes. When fewer than three queries reach the target before a random deadline 24 to 58 minutes after creation, the administrator deletes the policy anyway, and the episode stays incomplete. This happens mostly for rarely queried targets at night.

**Detection idea.** Alert when one account creates a query-resolution policy and deletes it again within an hour, after the policy has dropped client queries. Neither part is unusual alone: mistakes undone within a minute, rollbacks by a colleague and blocks kept for hours all occur several times a week.


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
| `anomaly_interval_hours` | `72` | Episode interval in hours, 2 to 8760 |

Names, answer addresses and query weights live in `samples/queries.json`, policy targets and their `FQDN=EQ` criteria in `samples/targets.json`, administrators with their RIDs, session rates and own area (a target label) in `samples/admins.json`, and client addresses in `samples/clients.json`. Keep names and criteria inside `zone` when changing it. `dns.question.registered_domain` is derived as the pipeline's public-suffix lookup does for a zone under a single-label suffix such as `com`; for other zones adjust it in the template.

### Output Parameters

The shipped configuration writes `output/events.json` with the `json` formatter and has no `${params.*}` or `${secrets.*}` placeholders. Override `output` in `generator.yml`, for example with a `file` path of your own or a SIEM output plugin.

## Usage

Live, following the hour curve from the current time:

```bash
eventum generate --path generators/windows-dns-server-audit/generator.yml --id windows-dns-server-audit --live-mode true
```

Batch: in each of the three files under `patterns/`, set the oscillator `start` to a midnight and `end` to the end of the window (for example `2026-09-01T00:00:00Z` and `2026-09-16T00:00:00Z` for 15 days with five episodes at the default interval), then run:

```bash
eventum generate --path generators/windows-dns-server-audit/generator.yml --id windows-dns-server-audit --live-mode false --keep-order true
```

Start the window at midnight: the hour bands are placed relative to the oscillator start. To change the volume, scale the `ratio` of every file under `patterns/` by the same factor; lower volumes stretch the delay between a query and its answer or drop.

Performance: about 1,400-2,100 records per second on one core; 15 days (860,000 records) take about 7 minutes of CPU time.

## Sample Output

A 259 record of an episode:

```json
{"@timestamp": "2026-09-04T08:34:28.653Z", "data_stream": {"dataset": "microsoft_dnsserver.analytical", "namespace": "default", "type": "logs"}, "dns": {"id": "31426", "question": {"name": "legacy-crm.corp.example.com", "registered_domain": "example.com", "subdomain": "legacy-crm.corp", "top_level_domain": "com", "type": "A"}}, "ecs": {"version": "8.17.0"}, "event": {"action": "LOOK_UP", "category": ["network"], "code": "259", "dataset": "microsoft_dnsserver.analytical", "kind": "event", "provider": "Microsoft-Windows-DNSServer", "reason": "Policy", "severity": 2, "type": ["protocol"]}, "host": {"name": "dns-01.corp.example.com"}, "input": {"type": "etw"}, "log": {"file": {"path": "Microsoft-Windows-DNSServer-Analytical.etl"}, "level": "error"}, "message": "IGNORED_QUERY: TCP=0; InterfaceIP=; Source=10.20.5.100; Reason=Policy; QNAME=legacy-crm.corp.example.com.; QTYPE=1; XID=31426; Zone=corp.example.com; PolicyName=QueryFilter-legacy-crm-e3e7; AdditionalInfo = VirtualizationInstance: .", "microsoft_dnsserver": {"analytical": {"additional_info": ".", "description": "Ignored query", "policy_name": "QueryFilter-legacy-crm-e3e7", "question_name": "legacy-crm.corp.example.com.", "question_type": "A", "reason": "Policy", "source": {"ip": "10.20.5.100"}, "xid": "31426", "zone": "corp.example.com"}}, "network": {"direction": "ingress", "protocol": "dns", "transport": "udp"}, "process": {"pid": 5868, "thread": {"id": 9992}}, "related": {"ip": ["10.20.5.100"]}, "source": {"ip": "10.20.5.100"}, "tags": ["preserve_duplicate_custom_fields"], "user": {"id": "NT AUTHORITY\\SYSTEM"}, "winlog": {"channel": "Microsoft-Windows-DNS-Server/Analytical", "flags": ["64_BIT_HEADER", "EXTENDED_INFO", "PROCESSOR_INDEX"], "flags_raw": "0x241", "keywords": ["IGNORED_QUERY"], "keywords_raw": "0x8000000000000008", "level": "Error", "level_raw": 2, "opcode_raw": 0, "provider_guid": "{EB79061A-A566-4698-9119-3ED2807060E7}", "provider_message": "Microsoft-Windows-DNS-Server", "session": "Microsoft-Windows-DNSServer-Analytical.etl", "task": "LOOK_UP", "task_raw": 1, "version": 0}}
```

## Limitations

- The field shapes follow the pinned Elastic parsed fixtures, not a version-matched Windows Server 2022 capture. Differences from those fixtures: `data_stream.*` and `host.name` are always present (the fixtures carry them only in some records), and agent, cloud, geo/AS enrichment, `event.created`, `event.ingested` and `event.agent_id_status` are omitted.
- The published 259 examples carry `Reason=System` and `PolicyName=NULL`; `Reason=Policy`, the policy name and the zone on a policy drop are inferred. The 259 interface address is left empty as in the newest published 259 record, so no `interface_ip` is set; the older record shows `0.0.0.0`. No complete 580 record was found; its two fields follow the documented message placeholders.
- `ElapsedTime` is written as whole milliseconds of the modeled answer time; the fixtures do not establish its unit.
- An answer or drop follows its query by about a second in office hours and up to about 80 seconds at night, not within milliseconds as on a real server, and retransmission gaps are stretched the same way.
- Retransmissions reuse the XID and source port of the original query; the Microsoft article documents the timing, not the packet identity.
- Only A queries for existing records are modeled: no NXDOMAIN, other record types, TCP, recursion or zone and record changes. Audit record numbers skip values for those unmodeled Audit events.
- Query volume (about 0.3 queries per second on average), policy activity and lifetimes are synthetic. A real enterprise DNS server answers far more queries.
- Background deletions are not tied to working hours.
- Outside episodes, an account never deletes its own policy within an hour after it dropped three or more queries. Such a deletion removes another active policy instead, or does not happen when no other policy is active, so now and then a policy stays active for hours or days longer than its owner intended.
- With `anomaly_mode: true` each episode adds its own records, so counts of the chain parts are about one per episode higher than without episodes: policies of an owner on its own name, self-deletions within an hour, and policies deleted within an hour after three or more drops. At the default interval that is five more of each in 15 days; at short intervals episodes make up a large part of the owners' policy work (at 24 hours, 15 of about 36 policies in 15 days).
- `process.pid` is one random DNS service PID per run and `process.thread.id` is drawn from a small random pool. `event.original` is omitted.

## References

- [DNS logging and diagnostics](https://learn.microsoft.com/en-us/windows-server/networking/dns/dns-logging-and-diagnostics) - Audit 577/580 and Analytical 257/259 messages, channels and provider GUID.
- [Add-DnsServerQueryResolutionPolicy](https://learn.microsoft.com/en-us/powershell/module/dnsserver/add-dnsserverqueryresolutionpolicy?view=windowsserver2025-ps) and [Remove-DnsServerQueryResolutionPolicy](https://learn.microsoft.com/en-us/powershell/module/dnsserver/remove-dnsserverqueryresolutionpolicy?view=windowsserver2025-ps) - server-level FQDN criteria, processing order, `Ignore` drops a query without a response.
- [DNS client resolution timeouts](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/dns-client-resolution-timeouts) - Windows DNS client retransmission after 1, 1, 2 and 4 seconds.
- Elastic `microsoft_dnsserver` integration pinned at `78fd455d22cdb74bd2a8e53249c25cc060f06010`: parsed fixtures [Audit](https://github.com/elastic/integrations/blob/78fd455d22cdb74bd2a8e53249c25cc060f06010/packages/microsoft_dnsserver/data_stream/audit/_dev/test/pipeline/test-events.json-expected.json) and [Analytical](https://github.com/elastic/integrations/blob/78fd455d22cdb74bd2a8e53249c25cc060f06010/packages/microsoft_dnsserver/data_stream/analytical/_dev/test/pipeline/test-events.json-expected.json), their [Audit](https://github.com/elastic/integrations/blob/78fd455d22cdb74bd2a8e53249c25cc060f06010/packages/microsoft_dnsserver/data_stream/audit/_dev/test/pipeline/test-events.json) and [Analytical](https://github.com/elastic/integrations/blob/78fd455d22cdb74bd2a8e53249c25cc060f06010/packages/microsoft_dnsserver/data_stream/analytical/_dev/test/pipeline/test-events.json) inputs, and the [Analytical ingest pipeline](https://github.com/elastic/integrations/blob/78fd455d22cdb74bd2a8e53249c25cc060f06010/packages/microsoft_dnsserver/data_stream/analytical/elasticsearch/ingest_pipeline/default.yml).

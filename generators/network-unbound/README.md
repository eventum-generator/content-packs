# Unbound 1.26.1 DNS query and reply logs

Generates the query and reply log of one Unbound 1.26.1 recursive resolver serving an office network: native `query:` and `reply:` lines from Unbound's own logfile in `event.original`, with ECS fields derived from each line. Built for DNS analytics and for testing detections of DNS tunnelling through TXT lookups.

## Event Types

Shares are measured over the queries of the final default-parameter capture (54 hours, `anomaly_mode: true`). Every query has exactly one reply, so replies follow the same mix.

| Line | Question | Share of queries | Category |
| --- | --- | --- | --- |
| `query:` / `reply:` | `A` for corporate names and `host-NNN` | 71.3% | network |
| `query:` / `reply:` | `AAAA` | 8.3% | network |
| `query:` / `reply:` | `MX` / corporate `TXT` (DMARC, DKIM, ACME) | 7.1% | network |
| `query:` / `reply:` | `A` for a telemetry zone apex | 1.3% | network |
| `query:` / `reply:` | `TXT` for a 32-hex label under a telemetry zone | 12.0% | network |

Reply outcomes in the same capture: NOERROR 92.5%, NXDOMAIN 7.5%. 34.6% of replies come from cache.

## Unbound Profile Assumed

The source profile is pinned to [Unbound 1.26.1](https://github.com/NLnetLabs/unbound/releases/tag/release-1.26.1) on a UTC host, with these settings:

```text
server:
    logfile: "/var/log/unbound/unbound.log"
    use-syslog: no
    log-time-ascii: yes
    log-time-iso: yes
    log-queries: yes
    log-replies: yes
    log-tag-queryreply: yes
    log-destaddr: no
    num-threads: 4
```

With this profile, Unbound's own logfile carries `YYYY-MM-DDTHH:MM:SS.mmm+00:00 unbound[pid:thread] query: <client> <name> <type> <class>` and `... reply: <client> <name> <type> <class> <rcode> <seconds>.<microseconds> <from_cache> <response_size>`. The `log-queries`, `log-replies`, and `log-tag-queryreply` options default to `no`; the first two can significantly slow a busy resolver.

## Traffic Model

- **Clients.** `client_count` workstations (`10.20.30.11`-`10.20.30.80` by default). Each client is an independent Poisson source of lookups with its own fixed, log-normally skewed activity weight, so a few clients are much busier than most.
- **Hour of day.** The lookup rate follows an office-hours curve in UTC: 1.6x the daily mean from 07:00 to 17:00, 0.9x until 21:00, 0.33x overnight. `sessions_per_second` sets the daily mean of client lookup sessions.
- **Ordinary lookups.** 96% of sessions look up names from `samples/questions.json` (weighted) or `host-001`-`host-100.corp.example`; 30% of them are followed within seconds by a second lookup.
- **Telemetry zones.** The three `tunnel_domains` stand for vendor services that answer TXT lookups of hashed 32-hex labels, as endpoint telemetry and reputation services do. 2% of sessions look up a zone's A record and, in 60% of those, continue with a run of hex-label TXT lookups under it; another 2% of sessions are such runs without the A lookup. A run is 1-10 bursts (40% single). A burst holds a few lookups seconds apart (log-normal gaps, median 2.5 s); 3% of bursts are scans of a batch of hashes (median 8 lookups, up to 40), except the first burst after an A lookup. Bursts are separated by pauses of log-normal length (median 40 minutes). Most labels are new; 15% repeat a recent label of the same zone. The zone answers a label either with TXT data (60%) or NXDOMAIN, and keeps that answer for the label.
- **Resolution and cache.** An answer is cached from its arrival until its TTL (60 s for A/AAAA and zone apex, 180 s for corporate MX/TXT, 10 s for telemetry TXT data, 45-60 s for NXDOMAIN); the cache holds at most 256 entries. A cached reply carries the native `0.000000 1`; an uncached one a log-normal resolution time (median 12 ms for corporate names, 45 ms for the telemetry zones). The reply line follows its query by the resolution time plus 40-900 microseconds and keeps the query's worker thread.
- **Response sizes** are computed from the DNS message layout (header, question, answer or SOA authority, EDNS OPT) for the synthetic zone data. They are plausible values, not captured packet sizes.

## Anomaly Chain

A DNS-tunnelling episode: one client looks up a telemetry zone and then pushes data out through eight TXT lookups of new hex labels under it.

1. `A` query for a zone apex `<zone>.` from client `C`, where `<zone>` is one of `tunnel_domains`.
2. Eight `TXT` queries from `C` for `<32-hex>.<zone>.` names under the same zone, each with its reply.

- **Linking fields:** `source.ip` and `dns.question.registered_domain`; the zone name in `dns.question.name`. Unbound logs no query ID, so a reply is linked to its query by client, question, and worker thread.
- **Episode shape:** one burst of eight lookups at the background burst pace, right after the A lookup; its gaps are scaled down only if the burst would exceed 560 seconds, so the chain fits in the 10-minute detection window. Measured spans from the A lookup to the eighth TXT: 30 s and 20 s in the default capture, 17-139 s in the 6-hour capture.
- **Recurrence:** an episode is due every `anomaly_interval_hours` of source time (default 24, minimum 2). The first starts within the first min(interval, 24 h), at a time drawn from the hour-of-day curve. Each later one starts at a random time in a window of min(interval / 4, 6 h) centred on its due time (the previous actual start plus the interval), weighted by the squared hour curve plus a small floor, so episodes stay in busy hours. Missed intervals are never caught up. At intervals of 8 hours or less the window cannot stay in office hours, and episode start hours cover the whole clock. Measured: the default 54-hour capture has 2 episodes, the first 22.4 h after capture start and the second 22.4 h later; a 54-hour capture with a 6-hour interval has 9 episodes with gaps of 5.37-6.66 h.
- **Variation:** the client is drawn with the same activity weights as background among clients that already sent telemetry-zone lookups, and the zone is one that client already used; both differ from the previous episode. Labels and TXT answers come from the same process as background runs.
- **Background overlap:** each part of the chain occurs on its own in both modes: every client looks up the zone apexes and sends hex-label TXT lookups to the same zones, with NXDOMAIN and data answers, lookups seconds apart, scans of 8 or more distinct labels, and runs that start with the zone A lookup. Reaching eight hex TXT lookups within 10 minutes of the same client's A lookup of the zone is rare in background, because an A lookup is never followed directly by a scan and later bursts come after long pauses. A guard on the final chain step removes the remaining cases: a background TXT lookup that would be the eighth under a zone within 600 seconds of the same client's A lookup of that zone is not logged. The guard window equals the chain window and the guard changes nothing else. In five 54-hour background-only captures there are 0 complete chains and 17-20 hex TXT lookups by one client under one zone within some 10-minute span. From each zone A lookup, the eighth logged hex TXT lookup falls 0, 0 times in the last two 2-minute bins before the window edge and 2, 1 times in the first two after it (pooled); the seventh falls 2, 1 and 2, 2 times.
- **Detection idea:** alert when one client looks up a zone and then sends eight or more TXT queries for distinct long labels under that zone within 10 minutes. The logs carry no answer data, so a match shows the pattern, not that data left the network.

`anomaly_mode` defaults to `true`. Set it to `false` to get background traffic only, with no complete chain.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Name | Default | Purpose |
| --- | --- | --- |
| `anomaly_mode` | `true` | Emit recurring tunnelling episodes; `false` gives background only |
| `anomaly_interval_hours` | `24` | Source-time hours between episodes; minimum 2 |
| `sessions_per_second` | `0.15` | Daily mean of client lookup sessions per second |
| `host_name` | `dns01.corp.example` | Resolver host name in ECS enrichment |
| `process_id` | `2137` | Unbound process ID in the log lines |
| `worker_count` | `4` | Resolver threads (`num-threads`); at least 1 |
| `client_prefix` | `10.20.30.` | Client address prefix |
| `client_first` | `11` | Last octet of the first client |
| `client_count` | `70` | Number of clients |
| `tunnel_domains` | `sync-updates.example.net`, `telemetry.example.org`, `cdn-check.example.com` | Telemetry zones used by background TXT runs and by episodes; at least two, on distinct registered domains |

### Output Parameters

The shipped pack writes `output/events.json` and needs no credentials. To send events to a SIEM, replace the file output with the matching output plugin in a local copy and pass its connection settings through top-level `${params.*}` and `${secrets.*}` placeholders.

## Usage

```bash
# Real-time generation, one second of source time per second
eventum generate --path generator.yml --id unbound --live-mode true

# Batch: as fast as possible, keeping event order
eventum generate --path generator.yml --id unbound --live-mode false --keep-order true
```

Each line in `output/events.json` is one ECS JSON event. To generate a finite batch, set `start` and `end` on the `cron` input.

## Sample Output

The first TXT reply of an episode in the final default-parameter capture:

```json
{"@timestamp": "2026-09-26T22:22:28.983317+00:00", "dns": {"question": {"class": "IN", "name": "067c0defc48278b4acedd7992889e798.cdn-check.example.com.", "registered_domain": "example.com", "type": "TXT"}, "response_code": "NOERROR", "type": "answer"}, "ecs": {"version": "8.17.0"}, "event": {"action": "dns-reply", "category": ["network"], "kind": "event", "original": "2026-09-26T22:22:28.983+00:00 unbound[2137:1] reply: 10.20.30.69 067c0defc48278b4acedd7992889e798.cdn-check.example.com. TXT IN NOERROR 0.018928 0 118", "type": ["end"]}, "host": {"name": "dns01.corp.example"}, "process": {"name": "unbound", "pid": 2137}, "related": {"ip": ["10.20.30.69"]}, "source": {"ip": "10.20.30.69"}, "unbound": {"reply": {"from_cache": 0, "response_size": 118, "time_to_resolve": 0.018928}, "worker_id": 1}}
```

## Limitations

- The line grammar follows the Unbound 1.26.1 source formatter for the stated profile. No first-party runtime capture of this exact profile was found, so byte-level fidelity against a running resolver is unverified; the [issue #451](https://github.com/NLnetLabs/unbound/issues/451) cited earlier contains no complete query/reply line and is not used as evidence.
- `log-destaddr` is off, so replies carry no destination address or transport. Host name, `dns.question.registered_domain` (the last two labels), and the other ECS fields are collector enrichment, not Unbound tokens.
- `@timestamp` keeps microseconds; `event.original` has the millisecond precision of Unbound's logfile. A cached reply reports `0.000000` although its line follows the query slightly later, as in the native cached path.
- Zone data, TTLs, resolution times, and response sizes are synthetic. The telemetry zones use reserved `example.*` domains.
- Queries and replies of one resolver only; no forwarding, DNSSEC validation failures, SERVFAIL, or rate limiting.
- An episode burst whose random gaps would exceed 560 seconds is compressed to fit the detection window.

## References

- [Unbound 1.26.1 `unbound.conf` logging options](https://github.com/NLnetLabs/unbound/blob/release-1.26.1/doc/unbound.conf.rst)
- [Unbound 1.26.1 logfile framing and timestamps (`util/log.c`)](https://github.com/NLnetLabs/unbound/blob/release-1.26.1/util/log.c)
- [Unbound 1.26.1 query line (`util/net_help.c`)](https://github.com/NLnetLabs/unbound/blob/release-1.26.1/util/net_help.c)
- [Unbound 1.26.1 reply line (`util/data/msgreply.c`)](https://github.com/NLnetLabs/unbound/blob/release-1.26.1/util/data/msgreply.c)
- [Unbound 1.26.1 cached and recursive reply paths (`daemon/worker.c`)](https://github.com/NLnetLabs/unbound/blob/release-1.26.1/daemon/worker.c), [mesh timing (`services/mesh.c`)](https://github.com/NLnetLabs/unbound/blob/release-1.26.1/services/mesh.c)
- [ECS DNS fields](https://www.elastic.co/guide/en/ecs/current/ecs-dns.html), used for the ECS projection

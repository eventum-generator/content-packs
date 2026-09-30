# Unbound 1.26.1 DNS query and reply logs

Generates the query and reply log of one Unbound 1.26.1 recursive resolver serving an office network: native `query:` and `reply:` lines from Unbound's own logfile in `event.original`, with ECS fields derived from each line. Built for DNS analytics and for testing detections of DNS tunnelling through TXT lookups.

## Event Types

Shares of queries over six days at default parameters with `anomaly_mode: true`. Every query has exactly one reply, so replies follow the same mix.

| Line | Question | Share of queries | Category |
| --- | --- | --- | --- |
| `query:` / `reply:` | `A` for corporate names and `host-NNN` | 71.0% | network |
| `query:` / `reply:` | `AAAA` | 8.6% | network |
| `query:` / `reply:` | `MX` / corporate `TXT` (DMARC, DKIM, ACME) | 7.1% | network |
| `query:` / `reply:` | `A` for a telemetry zone apex | 1.4% | network |
| `query:` / `reply:` | `TXT` for a 32-hex label under a telemetry zone | 12.0% | network |

Reply outcomes over the same days: NOERROR 92.2%, NXDOMAIN 7.8%. 34.7% of replies come from cache.

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

## Volume and Timing

About 36,000 lines a day (queries and replies together) in three daily bands of the UTC clock, each band's daily count varying by up to 3%:

- **00:00-24:00** - 12,450 lines a day spread evenly, about 520 an hour;
- **07:00-21:00** - another 12,550, so evenings (17:00-21:00) carry about 1,430 lines an hour;
- **07:00-17:00** - another 11,000, so office hours carry about 2,530 lines an hour.

Night hours (21:00-07:00) carry about 520 lines an hour. A reply follows its query by the resolution time plus 40-900 microseconds (8 ms in median, 43 ms at the 90th percentile), usually on the next line. The lookups of one burst are 5 s apart in median, 90% within 16 s.

## Traffic Model

- **Clients.** `client_count` workstations (`10.20.30.11`-`10.20.30.80` by default). Each client starts lookup sessions in proportion to its own fixed, log-normally skewed activity weight, bounded to 0.4-3 times the typical client, so a few clients are much busier than most and every client is active every day.
- **Ordinary lookups.** 96% of sessions look up names from `samples/questions.json` (weighted) or `host-001`-`host-100.corp.example`; 30% of them are followed within seconds by a second lookup.
- **Telemetry zones.** The three `tunnel_domains` stand for vendor services that answer TXT lookups of hashed 32-hex labels, as endpoint telemetry and reputation services do. 2% of sessions look up a zone's A record and, in 60% of those, continue with a run of hex-label TXT lookups under it; another 2% of sessions are such runs without the A lookup. A run is 1-10 bursts (40% single). A burst holds one to a few lookups; 3% of bursts are scans of a batch of hashes (median 8 lookups, up to 40), except the first burst after an A lookup. Bursts are separated by pauses of log-normal length (median 40 minutes). Most labels are new; 15% repeat a recent label of the same zone. The zone answers a label either with TXT data (60%) or NXDOMAIN, and keeps that answer for the label.
- **Resolution and cache.** An answer is cached from its arrival until its TTL (60 s for A/AAAA and zone apex, 180 s for corporate MX/TXT, 10 s for telemetry TXT data, 45-60 s for NXDOMAIN); the cache holds at most 256 entries. A cached reply carries the native `0.000000 1`; an uncached one a log-normal resolution time (median 12 ms for corporate names, 45 ms for the telemetry zones). A reply keeps the worker thread of its query.
- **Response sizes** are computed from the DNS message layout (header, question, answer or SOA authority, EDNS OPT) for the synthetic zone data. They are plausible values, not captured packet sizes.

## Anomaly Chain

A DNS-tunnelling episode: one client looks up a telemetry zone and then pushes data out through eight TXT lookups of new hex labels under it.

1. `A` query for a zone apex `<zone>.` from client `C`, where `<zone>` is one of `tunnel_domains`.
2. Eight `TXT` queries from `C` for `<32-hex>.<zone>.` names under the same zone, each with its reply.

- **Linking fields:** `source.ip` and `dns.question.registered_domain`; the zone name in `dns.question.name`. Unbound logs no query ID, so a reply is linked to its query by client, question, and worker thread.
- **Episode shape:** the A lookup is followed by a first burst of TXT lookups of the same size law as the first burst of a background run (usually one to three), then by a second burst of the same client and zone that starts 1-6 minutes after the A lookup and lasts until the eighth TXT lookup. The chain spans about 1.5 to 7 minutes from the A lookup to the eighth TXT lookup. After the chain the client's run goes on like any background run: its remaining bursts, if any, follow after the usual pauses.
- **Volume:** the line count is the same in both modes; an episode's lines take the place of lookups other clients would have started at those moments.
- **Recurrence:** an episode is due every `anomaly_interval_hours` of event time (default 24, minimum 2). The first starts within the first min(interval, 24 h), at a time drawn from the hourly line rate. Each later one starts at a random time in a window of min(interval / 4, 6 h) centred on its due time (the previous actual start plus the interval), weighted by the squared hourly line rate plus a small floor, so episodes stay in busy hours: at the default interval consecutive episodes are 21-27 h apart, at a 6-hour interval 5.25-6.75 h. Missed intervals are never caught up. At intervals of 8 hours or less the window cannot stay in office hours, and episode start hours cover the whole clock.
- **Variation:** the client is drawn with the same activity weights as background among clients that have already sent telemetry-zone lookups, and the zone is one that client has already used; the client and zone differ from the previous episode's, and the client has made no lookup under that zone in the last 10 minutes. Labels and TXT answers come from the same process as background runs.
- **Background overlap:** each part of the chain occurs on its own in both modes: every client looks up the zone apexes and sends hex-label TXT lookups to the same zones, with NXDOMAIN and data answers, lookups seconds apart, scans of 8 or more distinct labels, runs that start with the zone A lookup, and A lookups followed by several TXT lookups of overlapping runs within 10 minutes. Every client and zone pair of an episode also has its own background TXT lookups, and usually its own background A lookups.
- **Background without the chain:** ordinary traffic never contains eight hex TXT lookups by one client under one zone within 10 minutes of that client's A lookup of the zone. Where ordinary traffic would reach such an eighth lookup, that lookup is for another telemetry zone the same client uses (about once a day in total). This also holds in the 10 minutes after an episode, so each episode forms the chain exactly once.
- **Detection idea:** alert when one client looks up a zone and then sends eight or more TXT queries for distinct long labels under that zone within 10 minutes. The logs carry no answer data, so a match shows the pattern, not that data left the network.

`anomaly_mode` defaults to `true`. Set it to `false` to get background traffic only, with no complete chain.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Name | Default | Purpose |
| --- | --- | --- |
| `anomaly_mode` | `true` | Emit recurring tunnelling episodes; `false` gives background only |
| `anomaly_interval_hours` | `24` | Event-time hours between episodes; 2 to 8760 |
| `host_name` | `dns01.corp.example` | Resolver host name in ECS enrichment |
| `process_id` | `2137` | Unbound process ID in the log lines |
| `worker_count` | `4` | Resolver threads (`num-threads`); at least 1 |
| `client_prefix` | `10.20.30.` | Client address prefix |
| `client_first` | `11` | Last octet of the first client |
| `client_count` | `70` | Number of clients |
| `tunnel_domains` | `sync-updates.example.net`, `telemetry.example.org`, `cdn-check.example.com` | Telemetry zones used by background TXT runs and by episodes; at least two, on distinct registered domains |

The line volume and its daily curve are set by the three files under `patterns/` (`multiplier.ratio` is the band's lines a day).

### Output Parameters

The shipped pack writes `output/events.json` and needs no credentials. To send events to a SIEM, replace the file output with the matching output plugin in a local copy and pass its connection settings through top-level `${params.*}` and `${secrets.*}` placeholders.

## Usage

From the content-packs repository root, live:

```bash
eventum generate --path generators/network-unbound/generator.yml --id network-unbound --live-mode true
```

The patterns start at midnight of the current day and never end. For a finite batch, set `start` and `end` in the three files under `patterns/` (for example `start: "2026-09-01T00:00:00Z"`, `end: "+6d"`); the second episode can start up to 51 hours after the start, so use at least 52 hours to see two at the default interval:

```bash
eventum generate --path generators/network-unbound/generator.yml --id network-unbound --live-mode false --keep-order true
```

Each line in `output/events.json` is one ECS JSON event.

## Sample Output

The first TXT reply of the first episode of a six-day default run:

```json
{"@timestamp": "2026-09-01T12:16:57.811304+00:00", "dns": {"question": {"class": "IN", "name": "16ad8c7e4fe9e9a6d4cb8a64afc0d5e9.telemetry.example.org.", "registered_domain": "example.org", "type": "TXT"}, "response_code": "NXDOMAIN", "type": "answer"}, "ecs": {"version": "8.17.0"}, "event": {"action": "dns-reply", "category": ["network"], "kind": "event", "original": "2026-09-01T12:16:57.811+00:00 unbound[2137:0] reply: 10.20.30.33 16ad8c7e4fe9e9a6d4cb8a64afc0d5e9.telemetry.example.org. TXT IN NXDOMAIN 0.034614 0 146", "type": ["end"]}, "host": {"name": "dns01.corp.example"}, "process": {"name": "unbound", "pid": 2137}, "related": {"ip": ["10.20.30.33"]}, "source": {"ip": "10.20.30.33"}, "unbound": {"reply": {"from_cache": 0, "response_size": 146, "time_to_resolve": 0.034614}, "worker_id": 0}}
```

## Limitations

- The line grammar follows the Unbound 1.26.1 source formatter for the stated profile. No first-party runtime capture of this exact profile was found, so byte-level fidelity against a running resolver is unverified.
- `log-destaddr` is off, so replies carry no destination address or transport. Host name, `dns.question.registered_domain` (the last two labels), and the other ECS fields are collector enrichment, not Unbound tokens.
- `@timestamp` keeps microseconds; `event.original` has the millisecond precision of Unbound's logfile. A cached reply reports `0.000000` although its line follows the query slightly later, as in the native cached path.
- Zone data, TTLs, resolution times, response sizes and client activity rates are synthetic. The telemetry zones use reserved `example.*` domains.
- Queries and replies of one resolver only; no forwarding, DNSSEC validation failures, SERVFAIL, or rate limiting.
- Lookups a real client sends within milliseconds of each other (the lookups of one burst, a lookup and its follow-up) are seconds apart here: 5 s in median within a burst, more at night.
- With `anomaly_mode: true` each episode adds its own lookups, so counts of zone A lookups followed by many hex TXT lookups within 10 minutes are about one per episode higher than with `anomaly_mode: false`.

## Performance

About 3,200 lines per second on one core: 14 days at default parameters (505,066 lines) take 156 s of CPU time.

## References

- [Unbound 1.26.1 `unbound.conf` logging options](https://github.com/NLnetLabs/unbound/blob/release-1.26.1/doc/unbound.conf.rst)
- [Unbound 1.26.1 logfile framing and timestamps (`util/log.c`)](https://github.com/NLnetLabs/unbound/blob/release-1.26.1/util/log.c)
- [Unbound 1.26.1 query line (`util/net_help.c`)](https://github.com/NLnetLabs/unbound/blob/release-1.26.1/util/net_help.c)
- [Unbound 1.26.1 reply line (`util/data/msgreply.c`)](https://github.com/NLnetLabs/unbound/blob/release-1.26.1/util/data/msgreply.c)
- [Unbound 1.26.1 cached and recursive reply paths (`daemon/worker.c`)](https://github.com/NLnetLabs/unbound/blob/release-1.26.1/daemon/worker.c), [mesh timing (`services/mesh.c`)](https://github.com/NLnetLabs/unbound/blob/release-1.26.1/services/mesh.c)
- [ECS DNS fields](https://www.elastic.co/guide/en/ecs/current/ecs-dns.html), used for the ECS projection

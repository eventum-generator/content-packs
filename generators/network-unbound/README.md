# Unbound 1.26.1 DNS query and reply logs

Generates Unbound 1.26.1 `log-queries` and `log-replies` lines in `event.original`, with ECS fields derived from each line. The modeled transport is Unbound's own logfile with ISO millisecond timestamps, not a host syslog wrapper.

## Event Types

| Line | Question mix | Meaning |
| --- | --- | --- |
| `query:` | Mostly `A`; also `AAAA`, `MX`, and `TXT` | Client question received by one resolver |
| `reply:` | Same question as preceding query | Resolver result, resolution time, cache flag, and DNS response size |
| Long `TXT` query/reply | Present in background and anomaly mode | Routine fixed lookups or concentrated unique-label episode |

The question weights in `samples/questions.json`, the 20% pool of `host-001` through `host-100` A names, and all response sizes are synthetic workload assumptions. Each query is paired with one reply from the same resolver worker. The generator samples roughly 70 routine client addresses plus the configurable client that also appears in anomaly episodes.

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

Unbound's own logfile then has `YYYY-MM-DDTHH:MM:SS.mmm+00:00 unbound[pid:worker] query: ...` or `reply: ...`. The actual process ID and worker count vary by installation. The `log-queries`, `log-replies`, and `log-tag-queryreply` options default to `no`; the first two can significantly slow a busy resolver.

The modeled unsigned corporate zone is `corp.example.`. A synthetic upstream at `192.0.2.53` answers the names listed in `samples/questions.json`, the generated `host-NNN` names, and `sync-updates.corp.example.` A. It also answers `status` and one fixed 32-hex TXT name under that suffix. Unknown names, including the unique episode TXT names, return NXDOMAIN. A second fixed 32-hex TXT name returns NXDOMAIN in background. This zone behavior and the reply packet sizes are test fixtures, not claims about public DNS. It avoids treating the reserved `.example` TLD as a live domain with a successful answer.

The cache model follows repeated question name and type with synthetic TTLs: 60 seconds for successful A/AAAA, 180 seconds for successful MX/TXT, and 45 seconds for NXDOMAIN. Unbound's source emits `0.000000 1` for an immediate cached reply. Uncached replies have a varied 18–92 ms resolution time. The cache retains at most 128 keys; unique episode names are never reused.

## Anomaly Chain

`anomaly_mode` defaults to `true`. After the first `anomaly_interval_seconds` (default 900 seconds), and at the same interval thereafter, one client asks for the tunnel suffix's A record and then sends eight distinct 32-hex-label TXT questions under it. Each TXT question receives NXDOMAIN. Every episode gets a fresh random 16-hex prefix, so labels from separate episodes do not repeat. The query/reply pairs remain linked by client IP, question, type, worker, and subsecond time; Unbound does not expose a request ID in this log format.

A detection can count distinct long TXT labels under one suffix per client within a short window, optionally preceded by the A lookup. The same client, suffix, query types, long-label form, and NXDOMAIN responses occur independently in background traffic; concentration and sequence distinguish the episode. The logs do not contain answer RDATA and cannot prove exfiltration. `anomaly_mode: false` emits background only, with zero episodes.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Name | Default | Purpose |
| --- | --- | --- |
| `anomaly_mode` | `true` | Emit recurring anomaly episodes |
| `anomaly_interval_seconds` | `900` | Seconds between episode starts; use at least 60 |
| `host_name` | `dns01.corp.example` | Resolver hostname in ECS enrichment |
| `process_id` | `2137` | Unbound process ID in native logfile lines |
| `worker_count` | `4` | Number of resolver workers; use at least 1 |
| `suspicious_client_ip` | `10.20.30.91` | Client in ordinary traffic and episodes |
| `tunnel_domain` | `sync-updates.corp.example` | Synthetic DNS suffix, without final dot |

### Output Parameters

The shipped pack writes `output/events.json` and requires no credentials. For a SIEM destination, replace the file output with the appropriate plugin in a local copy, using top-level `${params.*}` and `${secrets.*}` substitutions for that plugin's connection settings.

## Usage

From the `content-packs` repository:

```bash
uv run --project ../eventum eventum generate --path generators/network-unbound/generator.yml --id unbound --live-mode false --keep-order true
uv run --project ../eventum eventum generate --path generators/network-unbound/generator.yml --id unbound --live-mode true --keep-order true
```

The first command runs as fast as possible until stopped; the second follows the configured one-pair-per-second rate. `--keep-order true` preserves the emitted query/reply order when writing to the output. Each line in `output/events.json` is one ECS JSON event.

## Sample Output

This complete reply is copied from the first TXT question of the first anomaly episode in a 31-minute default-parameter run:

```json
{"@timestamp": "2026-09-27T00:15:01.026914+00:00", "dns": {"question": {"class": "IN", "name": "37b3ec48645c835d0c1fb0258b4c13c5.sync-updates.corp.example.", "type": "TXT"}, "response_code": "NXDOMAIN", "type": "answer"}, "ecs": {"version": "8.17.0"}, "event": {"action": "dns-reply", "category": ["network"], "kind": "event", "original": "2026-09-27T00:15:01.026+00:00 unbound[2137:3] reply: 10.20.30.91 37b3ec48645c835d0c1fb0258b4c13c5.sync-updates.corp.example. TXT IN NXDOMAIN 0.026661 0 177", "type": ["end"]}, "host": {"name": "dns01.corp.example"}, "process": {"name": "unbound", "pid": 2137}, "related": {"ip": ["10.20.30.91"]}, "source": {"ip": "10.20.30.91"}, "unbound": {"reply": {"from_cache": 0, "response_size": 177, "time_to_resolve": 0.026661}, "worker_id": 3}}
```

## Coverage and Limits

The raw query line models 9/9 fields in the selected 1.26.1 logfile profile: timestamp, identity, PID, worker ID, tag, client IP, question name, type, and class. The reply line adds RCODE, resolution seconds, cache flag, and response size (13/13). `log-destaddr` is disabled in this profile; host name and ECS fields are collector enrichment, not raw Unbound tokens. Query records have no reply-only data.

The 1.26.1 source defines the complete payload and logfile formatting used here, including six decimal places for resolution time and three for the ISO logfile timestamp. The ECS `@timestamp` retains microseconds, while `event.original` reflects the millisecond precision of Unbound's file line. Cached replies can report `0.000000` despite a small positive wall-clock gap between the two log lines because the native cached path passes a zero duration. Reply sizes represent plausible DNS packets from the declared synthetic zone; exact bytes depend on real RRsets, EDNS, DNSSEC, and transport. No complete production capture of this exact 1.26.1 logfile profile was available, so byte-level fidelity against a running resolver remains unverified. The older [issue #451](https://github.com/NLnetLabs/unbound/issues/451) previously cited by this pack does not contain a query/reply example and is not used as format evidence.

## References

- [Unbound 1.26.1 example configuration](https://github.com/NLnetLabs/unbound/blob/release-1.26.1/doc/example.conf.in)
- [Unbound 1.26.1 logfile framing and timestamps](https://github.com/NLnetLabs/unbound/blob/release-1.26.1/util/log.c)
- [Unbound 1.26.1 query formatting](https://github.com/NLnetLabs/unbound/blob/release-1.26.1/util/net_help.c)
- [Unbound 1.26.1 reply formatting](https://github.com/NLnetLabs/unbound/blob/release-1.26.1/util/data/msgreply.c)
- [Unbound 1.26.1 cached and recursive reply paths](https://github.com/NLnetLabs/unbound/blob/release-1.26.1/daemon/worker.c), [mesh timing](https://github.com/NLnetLabs/unbound/blob/release-1.26.1/services/mesh.c)

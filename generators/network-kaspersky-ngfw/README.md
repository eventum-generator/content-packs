# Kaspersky NGFW Firewall Session Log

Generates the Kaspersky NGFW 1.0 Firewall session log (CEF) of one device as ECS JSON, for training SIEM content on session telemetry. `event.original` holds the CEF message (header and key=value body) without a syslog envelope. The source is one NGFW between a user segment, two internal file servers, an internal DNS server and the internet.

## Event Types

Shares measured on the final default capture (78 h, `anomaly_mode: true`, 43,364 records).

| CEF name | Traffic | Share | Category |
|---|---|---:|---|
| `Session start` | HTTPS (TCP/443) | 21.82% (9463) | Network |
| `Firewall` | HTTPS (TCP/443) | 21.82% (9463) | Network |
| `Session start` | DNS (UDP/53) | 15.94% (6913) | Network |
| `Firewall` | DNS (UDP/53) | 15.94% (6913) | Network |
| `Session start` | SMB (TCP/445) | 10.45% (4531) | Network |
| `Firewall` | SMB (TCP/445) | 10.45% (4531) | Network |
| `Session start` | HTTP (TCP/80) | 1.79% (775) | Network |
| `Firewall` | HTTP (TCP/80) | 1.79% (775) | Network |

`Session start` is logged when a session is created, `Firewall` when it is removed, with duration, directional packet and byte counters. Every client, file server, cloud destination and every session type used by the chain occurs in ordinary background in both modes. No field labels an episode.

## Background Model

Each one-second tick emits at most one record: the earliest due session start or end, otherwise nothing. New client activity arrives as one merged Poisson stream (0.05 per second, scaled by an office-hours factor: 06:00-16:00 UTC 1.64, 16:00-20:00 0.91, night 0.40); each arrival picks a client by a fixed random per-client weight, so clients act independently.

- **Web** (62%): HTTPS to one of 40 internet addresses (skewed popularity), preceded in 60% of cases by a DNS query. **Cloud** (8%): HTTPS to one of the cloud-storage addresses; 18% of these are uploads (client bytes log-normal, median 35 MB). **HTTP** (6%) and **DNS-only** (6%).
- **SMB** (18%): a burst of 1-7 file transfers from one file server, gaps log-normal (median 40 s). Transfer size is a per-burst scale (log-normal, median 300 kB, sigma 2.2) times per-file variation, so a burst of large files produces several reads above 50 MB within minutes. After any SMB read above 50 MB, the same client uploads to a cloud destination with probability 0.25, about 10 minutes later.
- Durations follow the transferred volume and a log-normal throughput (LAN median 20 MB/s, internet 2 MB/s). UDP sessions end after an assumed 30 s idle timeout plus a random sweep delay. Session IDs grow by a random 1-40 per session.

## Anomaly Chain

`anomaly_mode` defaults to `true`. With `false` the generator emits the background only and the complete chain never occurs.

Sequence, all for one client C (`source.ip`):

1. `Firewall` (session end) of an SMB session C -> file server F on port 445 with `out` (bytes from the server) above 50 MB.
2. A second SMB session C -> F ending with `out` above 50 MB.
3. `Firewall` of an HTTPS session C -> cloud destination D on port 443 with `in` (bytes from the client) above 50 MB.

Linking fields: `source.ip` (C) in all steps, `destination.ip` (F) in steps 1-2; each session's start and end share `devicePayloadId` (`kaspersky.ngfw.session_id`), addresses, ports and `start`.

Recurrence: an episode becomes due every `anomaly_interval_hours` of source time (default 24, minimum 2), first one interval after generation starts. It starts after a random delay (exponential, mean 20 min). The next due time counts from the actual start, so a late episode never causes catch-up. Episodes in the final captures spanned 5-22 minutes (8-14 minutes at the default interval).

Variation: the client differs from the previous episode's, the cloud destination too, and the file server is random. Read sizes come from the upper tail of the background SMB size distribution, the upload size from the background upload distribution, raised to at least 55-75 MB (so episode uploads never fall at 50-55 MB); the episode client is picked uniformly among clients other than the previous one and its start time ignores the day/night load curve, so night-time episodes are relatively more visible against the lower night background; gaps (read to read median 2 min, read to upload median 7 min) are random. Firewall sessions carry no state that the chain changes, so there is nothing to restore.

Detection idea: a client reads two large files from one server over SMB and then uploads more than 50 MB to an external address within an hour (staging and exfiltration). Each fragment occurs in background: bursts of large SMB reads, large cloud uploads, and uploads after a single large read. Only the complete sequence is kept out of the background: an ordinary upload that would follow two large reads from one server within two hours is reduced below 50 MB.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Meaning |
|---|---|---|
| `anomaly_mode` | `true` | Add periodic episodes to the background |
| `anomaly_interval_hours` | `24` | Episode interval in source hours, 2-8760 |
| `device_host` | `ngfw-01.example.test` | `dvchost` and `observer.hostname` |
| `device_version` | `1.0.0.0` | CEF header version (1.0.0.x) |
| `client_prefix` | `10.20.1.` | Client addresses are this prefix plus a host number |
| `client_first` | `21` | First client host number |
| `client_count` | `24` | Number of clients (at least 4; `client_first + client_count` at most 255) |
| `file_servers` | `10.20.2.14`, `10.20.2.15` | SMB servers |
| `dns_server` | `10.20.0.53` | DNS resolver |
| `cloud_destinations` | `203.0.113.10`-`203.0.113.13` | Cloud-storage addresses (at least 2) |

### Output Parameters

The shipped config writes `output/events.json` with the `json` formatter and needs no `${params.*}` or `${secrets.*}`. To send events elsewhere, replace the `output` section, for example:

```yaml
output:
  - opensearch:
      hosts: ["${params.opensearch_url}"]
      username: ${params.opensearch_user}
      password: ${secrets.opensearch_password}
      index: kaspersky-ngfw
```

A CEF collector needs `event.original` rather than the surrounding JSON.

## Usage

Live mode:

```bash
eventum generate --path generators/network-kaspersky-ngfw/generator.yml --id ngfw --live-mode true
```

Batch mode needs a bounded input: add `start` and `end` to the `cron` input, then run:

```bash
eventum generate --path generators/network-kaspersky-ngfw/generator.yml --id ngfw --live-mode false
```

## Limitations

- Kaspersky documents the CEF header, the Firewall event names and the key/meaning table of the Firewall log, but publishes no complete raw Firewall message. Key order after `rt dtz` (taken from a truncated vendor CLI example), the label literals (`Priority`, `SecurityRule`, `Duration`, `ClientPackets`, `ServerPackets`) and optional-field omission are assumptions.
- `app` and `sproc` are always `Unknown` (the documented value for unrecognised traffic), because Application Control names are not enumerated. `reason`, decryption fields (`cs2`/`cs3`/`cs5`), profile fields, `KasperskyNGFWAppName`/`AppCat` and `DestinationDnsDomain` are omitted; their values are not documented.
- All sessions match a rule with the documented `Inspect` action (`FullMatch=yes`); denied traffic, ICMP, NAT and the other NGFW logs (DNS Security, Web Control, Anti-Virus, IDPS, SSL inspection) are out of scope. The 30 s UDP idle timeout is an assumption; the device time zone is UTC.
- Rates, sizes and throughputs are training assumptions, not measured production volume. One record per second at most, so this is a sampled view of a small office. No Elastic integration exists for this source, so the ECS mapping (including `network.protocol` inferred from the port) is an assumption.

## Sample Output

The upload that completes the first episode, copied byte for byte from the final default capture (line 13753):

```json
{"@timestamp": "2026-09-27T00:17:20+00:00", "destination": {"bytes": 7086664, "ip": "203.0.113.10", "packets": 136282, "port": 443}, "ecs": {"version": "8.17.0"}, "event": {"action": "Firewall", "category": ["network"], "dataset": "kaspersky.ngfw", "duration": 153000000000, "end": "2026-09-27T00:17:20+00:00", "kind": "event", "original": "CEF:0|Kaspersky|NGFW|1.0.0.0|Firewall|Firewall|Unknown|rt=2026-09-27T00:17:20Z dtz=UTC+00:00 cs4=Low cs4Label=Priority devicePayloadId=941162 cs1=Users to Internet cs1Label=SecurityRule act=Inspect FullMatch=yes start=2026-09-27T00:14:47Z end=2026-09-27T00:17:20Z cn1=153 cn1Label=Duration cn2=257829 cn2Label=ClientPackets cn3=136282 cn3Label=ServerPackets in=360111992 out=7086664 dvchost=ngfw-01.example.test src=10.20.1.38 dst=203.0.113.10 proto=TCP spt=62411 dpt=443 KasperskyNGFWTCPRedir=no app=Unknown sproc=Unknown", "start": "2026-09-27T00:14:47+00:00", "type": ["connection", "end"]}, "kaspersky": {"ngfw": {"action": "Inspect", "full_match": "yes", "session_id": "941162"}}, "network": {"bytes": 367198656, "packets": 394111, "protocol": "tls", "transport": "tcp"}, "observer": {"hostname": "ngfw-01.example.test", "product": "NGFW", "vendor": "Kaspersky", "version": "1.0.0.0"}, "related": {"ip": ["10.20.1.38", "203.0.113.10"]}, "rule": {"name": "Users to Internet"}, "source": {"bytes": 360111992, "ip": "10.20.1.38", "packets": 257829, "port": 62411}}
```

## References

- [Kaspersky NGFW 1.0: CEF message format](https://support.kaspersky.com/ngfw/1.0/274361): header, event classes and names.
- [Kaspersky NGFW 1.0: Firewall log](https://support.kaspersky.com/ngfw/1.0/274840): key/value table of Firewall messages.
- [Kaspersky NGFW 1.0: SIEM export](https://support.kaspersky.com/ngfw/1.0/269371)
- [Kaspersky NGFW 1.1 CLI reference: system](https://support.kaspersky.com/help/NGFW/1.1/cli_reference/en-US/system.html): truncated `Session start` example.
- [Kaspersky NGFW 1.1: IDPS](https://support.kaspersky.com/ngfw/1.1/269833): security rules with the `Inspect` action.
- [Elastic ECS field reference](https://www.elastic.co/docs/reference/ecs/ecs-field-reference)

# Kaspersky NGFW Firewall Session Log

Generates the Kaspersky NGFW 1.0 Firewall session log (CEF) of one device as ECS JSON, for training SIEM content on session telemetry. `event.original` holds the CEF message (header and key=value body) without a syslog envelope. The source is one NGFW between a user segment, two internal file servers, an internal DNS server and the internet.

## Event Types

Shares over five days of generated data with `anomaly_mode: true` (69,344 records).

| CEF name | Traffic | Share | Category |
|---|---|---:|---|
| `Session start` | HTTPS (TCP/443) | 21.69% (15042) | Network |
| `Firewall` | HTTPS (TCP/443) | 21.69% (15041) | Network |
| `Session start` | DNS (UDP/53) | 15.81% (10961) | Network |
| `Firewall` | DNS (UDP/53) | 15.81% (10960) | Network |
| `Session start` | SMB (TCP/445) | 10.69% (7410) | Network |
| `Firewall` | SMB (TCP/445) | 10.69% (7410) | Network |
| `Session start` | HTTP (TCP/80) | 1.82% (1260) | Network |
| `Firewall` | HTTP (TCP/80) | 1.82% (1260) | Network |

`Session start` is logged when a session is created, `Firewall` when it is removed, with duration, directional packet and byte counters. Every client, file server, cloud destination and every session type used by the chain occurs in ordinary background in both modes. No field labels an episode.

## Volume

About 14,000 records a day (+/- 3% from day to day), on a UTC hour-of-day curve set by the three files in `patterns/`:

| UTC hours | Records per second | Records per hour |
|---|---:|---:|
| 06:00-16:00 | 0.266 | about 960 |
| 16:00-20:00 | 0.147 | about 530 |
| 20:00-06:00 | 0.064 | about 230 |

Each record is one session start or one session end; half of the volume is session starts. The activity mix below is the same at every hour; only the volume changes.

## Background Model

Each new activity picks a client by a fixed random per-client weight, so clients act independently.

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

Recurrence: the first episode starts within the first `anomaly_interval_hours` (at most 24 h) of generation, at a time drawn from the hour-of-day volume curve, so it does not sit at a fixed offset from the generation start. Each next episode is due `anomaly_interval_hours` (default 24, minimum 2) after the actual start of the previous one and starts in a window of a quarter of the interval (at most 6 h) centred on the due time, weighted by the square of the volume curve plus a small floor, so most episodes fall in office hours and few at night. There is no catch-up. At the default interval episodes start 21-27 h apart, mostly in office hours (06:00-16:00 UTC); at a 6 h interval they start 5.4-6.5 h apart around the clock. An episode spans 5-40 minutes from the end of the first read to the end of the upload.

Variation: the client differs from the previous episode's, the cloud destination too, and the file server is random. Read sizes come from the upper tail of the background SMB size distribution, the upload size from the background upload distribution, raised to at least 55-75 MB (so episode uploads never fall at 50-55 MB); the episode client is picked by the same per-client weights as background activity, excluding the previous episode's client; gaps (read to read median 2 min, read to upload median 7 min) are random. The episode's three sessions are interleaved with the log; the chosen client's own background sessions continue as usual, before, during and after the episode. As after any large read, an episode read is followed by an ordinary cloud upload about one time in four; such an upload within the hour after the episode is 5-45 MB. With `anomaly_mode: true` each episode adds its own records, so counts of the chain parts (large SMB reads, large uploads) are about two reads and one upload per episode higher than with `false`.

Detection idea: a client reads two large files from one server over SMB and then uploads more than 50 MB to an external address within an hour (staging and exfiltration). Each fragment occurs in background: bursts of large SMB reads, large cloud uploads, and uploads after a single large read. Only the complete sequence is kept out of the background: an ordinary upload above 50 MB that would complete the chain (two large reads from one server by the same client, the first at most one hour before the upload) is reduced to 5-45 MB. The reduction uses the chain window exactly, so an upload more than an hour after the first read is left as is, and it also applies to ordinary uploads that follow an episode's reads within that hour.

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

Batch mode needs a bounded time range: set `start` and `end` of the `oscillator` in all three `patterns/*.yml` files to the same range, with `start` at 00:00 UTC so the hour bands stay in place (for example `start: "2026-09-01T00:00:00Z"` and `end: "2026-09-06T00:00:00Z"`), then run:

```bash
eventum generate --path generators/network-kaspersky-ngfw/generator.yml --id ngfw --live-mode false --keep-order true
```

Performance: about 1,700 records per second in batch mode (14 days, 196,000 records, in under 2 minutes).

## Limitations

- Kaspersky documents the CEF header, the Firewall event names and the key/meaning table of the Firewall log, but publishes no complete raw Firewall message. Key order after `rt dtz` (taken from a truncated vendor CLI example), the label literals (`Priority`, `SecurityRule`, `Duration`, `ClientPackets`, `ServerPackets`) and optional-field omission are assumptions.
- `app` and `sproc` are always `Unknown` (the documented value for unrecognised traffic), because Application Control names are not enumerated. `reason`, decryption fields (`cs2`/`cs3`/`cs5`), profile fields, `KasperskyNGFWAppName`/`AppCat` and `DestinationDnsDomain` are omitted; their values are not documented.
- All sessions match a rule with the documented `Inspect` action (`FullMatch=yes`); denied traffic, ICMP, NAT and the other NGFW logs (DNS Security, Web Control, Anti-Virus, IDPS, SSL inspection) are out of scope. The 30 s UDP idle timeout is an assumption; the device time zone is UTC.
- Rates, sizes and throughputs are training assumptions, not measured production volume. At about 14,000 records a day this is a sampled view of a small office.
- Records that a real device logs within milliseconds of each other are seconds apart and stay adjacent: a DNS query and the connection it resolves start a median 5 s apart (90% within 20 s, longest at night), and session ends are logged a few seconds after the session's last packet, so `cn1` includes that delay (DNS sessions: median 45 s instead of about 34 s).
- No Elastic integration exists for this source, so the ECS mapping (including `network.protocol` inferred from the port) is an assumption.

## Sample Output

The upload that completes the first episode (`anomaly_mode: true`), byte for byte:

```json
{"@timestamp": "2026-09-01T06:12:30+00:00", "destination": {"bytes": 1616836, "ip": "203.0.113.13", "packets": 31093, "port": 443}, "ecs": {"version": "8.17.0"}, "event": {"action": "Firewall", "category": ["network"], "dataset": "kaspersky.ngfw", "duration": 130000000000, "end": "2026-09-01T06:12:30+00:00", "kind": "event", "original": "CEF:0|Kaspersky|NGFW|1.0.0.0|Firewall|Firewall|Unknown|rt=2026-09-01T06:12:30Z dtz=UTC+00:00 cs4=Low cs4Label=Priority devicePayloadId=2537811 cs1=Users to Internet cs1Label=SecurityRule act=Inspect FullMatch=yes start=2026-09-01T06:10:20Z end=2026-09-01T06:12:30Z cn1=130 cn1Label=Duration cn2=53191 cn2Label=ClientPackets cn3=31093 cn3Label=ServerPackets in=61463722 out=1616836 dvchost=ngfw-01.example.test src=10.20.1.33 dst=203.0.113.13 proto=TCP spt=57094 dpt=443 KasperskyNGFWTCPRedir=no app=Unknown sproc=Unknown", "start": "2026-09-01T06:10:20+00:00", "type": ["connection", "end"]}, "kaspersky": {"ngfw": {"action": "Inspect", "full_match": "yes", "session_id": "2537811"}}, "network": {"bytes": 63080558, "packets": 84284, "protocol": "tls", "transport": "tcp"}, "observer": {"hostname": "ngfw-01.example.test", "product": "NGFW", "vendor": "Kaspersky", "version": "1.0.0.0"}, "related": {"ip": ["10.20.1.33", "203.0.113.13"]}, "rule": {"name": "Users to Internet"}, "source": {"bytes": 61463722, "ip": "10.20.1.33", "packets": 53191, "port": 57094}}
```

## References

- [Kaspersky NGFW 1.0: CEF message format](https://support.kaspersky.com/ngfw/1.0/274361): header, event classes and names.
- [Kaspersky NGFW 1.0: Firewall log](https://support.kaspersky.com/ngfw/1.0/274840): key/value table of Firewall messages.
- [Kaspersky NGFW 1.0: SIEM export](https://support.kaspersky.com/ngfw/1.0/269371)
- [Kaspersky NGFW 1.1 CLI reference: system](https://support.kaspersky.com/help/NGFW/1.1/cli_reference/en-US/system.html): truncated `Session start` example.
- [Kaspersky NGFW 1.1: IDPS](https://support.kaspersky.com/ngfw/1.1/269833): security rules with the `Inspect` action.
- [Elastic ECS field reference](https://www.elastic.co/docs/reference/ecs/ecs-field-reference)

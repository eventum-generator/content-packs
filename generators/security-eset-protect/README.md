# ESET PROTECT On-Prem CEF events

Generates ESET PROTECT On-Prem 11.1 detection events as exported to a Syslog server in CEF: Threat, Firewall and HIPS events from 48 fictional Windows workstations. Each record is ECS JSON with the bare CEF payload in `event.original`, for SIEM parser development, detection testing and demonstrations.

## Event types

Every record is one detection of an endpoint. Shares over 14 days with default settings; the rates themselves are synthetic, not ESET production ratios.

| CEF category | Class ID | Event | Share | ECS category |
| --- | ---: | --- | ---: | --- |
| `ESET Firewall Event` | 209 | Inbound TCP port scan blocked; one to four probes from one scanner within minutes | 44.4% | network, intrusion_detection |
| `ESET Threat Event` | 183 | File cleaned by deleting: by real-time protection when a file is created, or by either scanner after HIPS blocks | 31.5% | malware, file |
| `ESET HIPS Event` | 303 | Attempt to run a suspicious object blocked; one to four attempts of the same file minutes apart | 24.1% | intrusion_detection |

Incidents start on the 48 endpoints in proportion to each endpoint's weight in `samples/endpoints.csv` (the busiest endpoint about eleven times the quietest). Of new incidents, 45% are port scans, 36% real-time cleanups and 18% HIPS incidents. A HIPS incident blocks one file one to four times (45/27/17/11%), launched by one application (Explorer, cmd, wscript, PowerShell, Word or svchost); 40% of them end with the file cleaned later, 60% of those by the on-demand scanner. 15% of real-time cleanups are repeated for the same file when the user downloads it again.

## Volume and timing

About 340 records a day in four bands of the UTC clock, each band's daily count varying by up to 3%:

| UTC hours | Records an hour |
| --- | ---: |
| 00:00-05:00, 21:00-24:00 | about 5.5 |
| 05:00-06:00, 19:00-21:00 | about 8 |
| 06:00-07:00, 18:00-19:00 | about 14 |
| 07:00-18:00 | about 22 |

Weekends carry the same volume as weekdays. The records of one incident are spaced by random delays: HIPS retries 30 s to 15 min after the previous block (3 min in median), the cleanup 1-40 min after the last block and usually within an hour of the first, further port probes 5 s to 15 min apart, a repeated download cleanup 1 min to 2 h later. At night, when records are sparse, these gaps are often 10-30 minutes.

## Anomaly Chain

With `anomaly_mode: true` (the default), the generator adds a recurring episode on one endpoint:

1. **HIPS block**: an attempt to run a suspicious executable is blocked (`303`, `cs5` = target file).
2. **HIPS block again**: minutes later, the same application tries to run the same file and is blocked again.
3. **HIPS block again**: a third attempt (in 39% of episodes also a fourth) is blocked.
4. **Threat cleanup**: minutes later, the on-demand (60%) or real-time scanner cleans that file by deleting it (`183`, `filePath` = the same file as a `file:///` URI, `cs8` = SHA-1).

**Linking fields**: `deviceExternalId` (`host.id`), `dvchost` and `dvc` identify the endpoint; HIPS `cs5` and the decoded Threat `filePath` (`file.path`) identify the file. HIPS events carry no hash, so `cs8` cannot join the steps.

**Timing**: the gaps between the steps follow the law of ordinary HIPS incidents, so an episode usually spans 20-70 minutes. When a long quiet spell at night would leave fewer than three blocks within the two hours before the cleanup, the application tries again (up to three more blocks, rarely stretching the episode to about five hours) before the file is cleaned, so every episode ends with three blocks within two hours of its cleanup.

**Recurrence**: an episode is due every `anomaly_interval_hours` of event time (default 24, minimum 3). The first starts within the first min(interval, 24 h), at a time drawn from the hourly record rate. Each later one starts at a random time in a window of min(interval / 4, 6 h) centred on its due time (the previous actual start plus the interval), weighted by the squared hourly record rate plus a small floor, so episodes favour office hours: at the default interval consecutive episodes are 21-27 h apart. At night a start can slip past its window by up to a few hours when other records are due; at short intervals this can rarely make two episodes overlap. Missed intervals are never caught up.

**Variation**: each episode picks an endpoint with the same weights as ordinary incidents and a file, both different from the previous episode's; the folder, the launching application and the scanner are drawn like those of ordinary HIPS incidents.

**Volume**: the record count is the same in both modes; the four to seven records of an episode take the place of ordinary incidents that other endpoints would have started at those moments. The endpoint keeps its ordinary incidents during the episode.

**Background**: every event type, endpoint, file, folder and application of the episode also occurs in ordinary traffic in both modes, including runs of three or four blocks of one file within minutes, one or two blocks followed by a cleanup of that file, and cleanups without any block. Only the complete sequence is absent: when an ordinary cleanup follows three or more blocks of the same file on that endpoint within two hours, it removes a copy of that file from another user folder instead (about four a day). This also holds after an episode, so each episode forms the chain exactly once. With `anomaly_mode: false` the generator produces this background only.

**Detection idea**: per endpoint and file path, alert when HIPS blocks the launch of a file at least three times and the file is then cleaned as malware within two hours. Repeated launch attempts of one blocked file point to an autorun entry, scheduled task or script retrying a dropper until signatures catch up; the deletion removes the file but not the mechanism that keeps starting it.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`.

| Name | Default | Description |
| --- | --- | --- |
| `anomaly_mode` | `true` | Add the recurring HIPS-to-cleanup episode; `false` produces background only |
| `anomaly_interval_hours` | `24` | Hours from one episode start to the next due time (minimum 3) |
| `protect_version` | `11.1.20.0` | ESET PROTECT On-Prem build in the CEF header (`Device Version`) and `observer.version` |
| `protect_host` | `protect-01.example.test` | Management server name in `observer.name` |

Endpoints (UUID, hostname, IP, user, OS, static group, relative incident weight) are in `samples/endpoints.csv`; malicious files with SHA-1 and detection name in `samples/objects.json`. Changing `protect_version` does not change the 11.1 field profile.

### Output Parameters

The shipped configuration writes `output/events.json` and needs no top-level parameters or secrets. To send events to a backend, replace the file output and reference top-level parameters for the endpoint and secrets for credentials, for example `hosts: ["${params.opensearch_host}"]` and `password: ${secrets.opensearch_password}`, then pass them at run time (`--params '{"opensearch_host": "https://localhost:9200"}'`, secrets from the Eventum keyring). Top-level `${params.*}` and `${secrets.*}` are separate from `event.template.params`.

## Usage

Run from the content-packs root, live:

```bash
eventum generate --path generators/security-eset-protect/generator.yml --id eset-protect --live-mode true
```

The record volume and its daily curve are set by the four files under `patterns/` (`multiplier.ratio` is a band's records a day); the episode start hours follow the hour table in the template, so keep both in step when changing the curve. The patterns start at midnight of the current day and never end. For a finite batch, set `start` and `end` in the four files (for example `start: "2026-09-01T00:00:00Z"`, `end: "+6d"`); the second episode can start up to 27 hours after the first, which itself starts within 24 hours, so use at least 52 hours to see two at the default interval:

```bash
eventum generate --path generators/security-eset-protect/generator.yml --id eset-protect --live-mode false --keep-order true
```

## Sample output

The last step of an episode (one line of `output/events.json`):

```json
{"@timestamp": "2026-09-03T15:46:37Z", "ecs": {"version": "8.17.0"}, "event": {"kind": "alert", "module": "eset", "dataset": "eset.protect", "code": "183", "action": "Cleaned by deleting", "category": ["malware", "file"], "type": ["info", "deletion"], "severity": 5, "original": "CEF:0|ESET|Protect|11.1.20.0|183|File scanner cleaned a virus|5|dvc=10.20.1.63 dvchost=ws-dev-03 deviceExternalId=edb0d239-3061-4ba5-a149-1307e5ff1ced ESETProtectDeviceGroupName=All/Workstations/Development ESETProtectDeviceOsName=Microsoft Windows 11 Enterprise ESETProtectDeviceGroupDescription=Developer workstations cat=ESET Threat Event rt=Sep 03 2026 15:46:37 cs1=Win32/Agent.Gen cs1Label=Threat Name cs2=34052 (20260903) cs2Label=Engine Version cs3=Virus cs3Label=Threat Type cs4=On-demand scanner cs4Label=Scanner ID act=Cleaned by deleting fileType=File filePath=file:///C:/Users/dev03/Downloads/task-helper.exe cn1=1 cn1Label=Handled cn2=0 cn2Label=Restart Needed suser=EXAMPLE\\\\dev03 deviceCustomDate1=Sep 03 2026 15:46:37 deviceCustomDate1Label=FirstSeen cs8=3ccf83ba204b33d808b3c663b82bb8b3eb57d073 cs8Label=Hash"}, "observer": {"name": "protect-01.example.test", "vendor": "ESET", "product": "Protect", "version": "11.1.20.0"}, "host": {"name": "ws-dev-03", "id": "edb0d239-3061-4ba5-a149-1307e5ff1ced", "ip": ["10.20.1.63"], "os": {"name": "Microsoft Windows 11 Enterprise"}}, "eset": {"protect": {"category": "threat", "class_id": "183", "group": "All/Workstations/Development", "threat_name": "Win32/Agent.Gen", "scanner": "On-demand scanner", "engine_version": "34052 (20260903)"}}, "related": {"ip": ["10.20.1.63"], "hosts": ["ws-dev-03"], "user": ["dev03"], "hash": ["3ccf83ba204b33d808b3c663b82bb8b3eb57d073"]}, "file": {"path": "C:\\Users\\dev03\\Downloads\\task-helper.exe", "name": "task-helper.exe", "hash": {"sha1": "3ccf83ba204b33d808b3c663b82bb8b3eb57d073"}}, "user": {"name": "dev03", "domain": "EXAMPLE"}}
```

## Limitations

- **Firewall class ID**: the On-Prem 11.1 reference lists 200-299 for firewall events but prints `109` in its firewall example. The generator uses `209`, consistent with that range and ESET's PROTECT Cloud example; the ID has not been confirmed from an On-Prem 11.1 export.
- **No live capture**: fields and their order follow the vendor raw examples and field tables. The examples print `CEF:O` (letter O); the generator emits `CEF:0`. Class IDs and event names are limited to the documented ones (183, 209, 303), so the pack emits only cleaned threats, blocked port scans and blocked launches; failed cleanups (`cs6`), quarantine actions and other Threat, Firewall and HIPS event names are not modeled. The on-demand variant (no `cs5`, `cs7`, `sprod`) follows the PROTECT Cloud example.
- **Synthetic values**: event rates, the diurnal curve, detection names, file names and hashes, scanner addresses, the Firewall `cs3` threat name (taken from both vendor examples) and the detection engine build in `cs2` (about five builds per day, endpoints up to two builds behind) are synthetic. `cnt` varies between 1 and 5 without modeling agent replication batches.
- **Envelope**: the output is ECS JSON with a bare CEF payload, not a Syslog frame; the ECS projection is this pack's own. Audit, ESET Inspect, Blocked File and Filtered Website events are not generated.
- KUMA lists an ESET PROTECT 11.0 CEF normalizer; parsing of this 11.1 payload with it has not been verified.
- **Timing**: `@timestamp` and `rt` carry whole seconds. Records a real agent would send in one replication batch (the probes of one scan, the retries of one blocked launch) are seconds to minutes apart here, at night often 10-30 minutes. The volume has a daily curve but no weekly or holiday cycle.
- **Repeated blocks**: outside episodes, a cleanup that follows three or more blocks of the same file on the same endpoint within two hours always removes a copy in another folder, never the blocked file itself.
- **Episode records**: with `anomaly_mode: true` each episode adds its own records, so runs of three or more blocks of one file are about one per episode more frequent than with `anomaly_mode: false`, and ordinary incidents correspondingly fewer.

## Performance

About 2,400 records per second on one core: a year at default parameters (122,585 records) takes 51 s of CPU time.

## References

- [ESET PROTECT On-Prem 11.1: events exported to CEF format](https://help.eset.com/protect_admin/11.1/en-US/events_exported_to_cef_format.html)
- [ESET PROTECT On-Prem 11.1: export logs to Syslog](https://help.eset.com/protect_admin/11.1/en-US/admin_server_settings_export_to_syslog.html)
- [ESET PROTECT Cloud: events exported to CEF format](https://help.eset.com/protect_cloud/en-US/events_exported_to_cef_format.html)
- [ESET build versions](https://help.eset.com/latestVersions/)
- [KUMA 4.2 supported event sources](https://support.kaspersky.ru/kuma/4.2/255782)
- [Elastic ESET PROTECT integration](https://github.com/elastic/integrations/tree/main/packages/eset_protect)

The Elastic integration parses the JSON Syslog export and the ESET Connect API, not CEF, so this pack cannot mirror its sample event; the ECS projection here is the pack's own.

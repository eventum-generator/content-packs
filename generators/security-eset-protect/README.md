# ESET PROTECT On-Prem CEF events

Generates ESET PROTECT On-Prem 11.1 detection events as exported to a Syslog server in CEF: Threat, Firewall and HIPS events from 48 fictional Windows workstations. Each record is ECS JSON with the bare CEF payload in `event.original`, for SIEM parser development, detection testing and demonstrations.

## Event types

Every endpoint produces its own incidents at random intervals, with fewer incidents outside office hours (UTC). Shares were measured on a 10-day capture with default settings (3364 events, about 335 per day); the rates themselves are synthetic, not ESET production ratios.

| CEF category | Class ID | Event | Share | ECS category |
| --- | ---: | --- | ---: | --- |
| `ESET Firewall Event` | 209 | Inbound TCP port scan blocked; one to four probes from one scanner within minutes | 47.3% | network, intrusion_detection |
| `ESET Threat Event` | 183 | File cleaned by deleting: by real-time protection when a file is created, or by either scanner after HIPS blocks | 30.3% | malware, file |
| `ESET HIPS Event` | 303 | Attempt to run a suspicious object blocked; one to four attempts of the same file minutes apart | 22.4% | intrusion_detection |

Background HIPS incidents block one file one to four times, launched by one application (Explorer, cmd, wscript, PowerShell, Word or svchost); up to 40% end with the file cleaned later. Real-time cleanups are sometimes repeated for the same file when a user downloads it again.

## Anomaly Chain

With `anomaly_mode: true` (the default), the generator adds a recurring episode on one endpoint:

1. **HIPS block**: an attempt to run a suspicious executable is blocked (`303`, `cs5` = target file).
2. **HIPS block again**: minutes later, the same application tries to run the same file and is blocked again.
3. **HIPS block again**: a third attempt (sometimes also a fourth) is blocked.
4. **Threat cleanup**: minutes later, the on-demand or real-time scanner cleans that file by deleting it (`183`, `filePath` = the same file as a `file:///` URI, `cs8` = SHA-1).

**Linking fields**: `deviceExternalId` (`host.id`), `dvchost` and `dvc` identify the endpoint; HIPS `cs5` and the decoded Threat `filePath` (`file.path`) identify the file. HIPS events carry no hash, so `cs8` cannot join the steps. An episode spans about 10-45 minutes in the measured captures; the random gaps allow longer ones.

**Recurrence**: the first episode is due one hour after the generator starts. Each episode starts after a random delay of up to one hour after its due time, or up to one eighth of the interval when that is shorter; the next episode is due `anomaly_interval_hours` (default 24, minimum 3) after the actual start. Episodes are scheduled on event time, and a missed episode is not caught up.

**Variation**: each episode picks another endpoint and another file than the previous one, a folder, the launching application and the scanner at random. Gaps between the steps are random and drawn from the same distributions as the ordinary HIPS incidents. The endpoint keeps its ordinary events during the episode.

**Background**: every event type, endpoint, file, folder and application of the episode also occurs in ordinary traffic in both modes, including runs of three or four blocks of one file within minutes, one or two blocks followed by a cleanup of that file, and cleanups without any block. Only the complete sequence is absent: an ordinary cleanup of a file that the same endpoint blocked three or more times in the preceding three hours is not reported. With `anomaly_mode: false` the generator produces this background only.

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

Run from the content-packs root:

```bash
# Live stream on wall-clock time
eventum generate --path generators/security-eset-protect/generator.yml --id eset-protect --live-mode true

# Sample mode: generate as fast as possible (stop with Ctrl+C; set start/end on the cron input for a bounded window)
eventum generate --path generators/security-eset-protect/generator.yml --id eset-protect --live-mode false
```

## Sample output

The last step of an episode from a default capture (one line of `output/events.json`):

```json
{"@timestamp": "2026-09-01T02:08:39Z", "ecs": {"version": "8.17.0"}, "event": {"kind": "alert", "module": "eset", "dataset": "eset.protect", "code": "183", "action": "Cleaned by deleting", "category": ["malware", "file"], "type": ["info", "deletion"], "severity": 5, "original": "CEF:0|ESET|Protect|11.1.20.0|183|File scanner cleaned a virus|5|dvc=10.20.1.57 dvchost=ws-hr-07 deviceExternalId=ceaf535f-9788-4dc2-ab65-ef20909e6fad ESETProtectDeviceGroupName=All/Workstations/HR ESETProtectDeviceOsName=Microsoft Windows 11 Enterprise ESETProtectDeviceGroupDescription=HR department workstations cat=ESET Threat Event rt=Sep 01 2026 02:08:39 cs1=Win32/Agent.Gen cs1Label=Threat Name cs2=34040 (20260901) cs2Label=Engine Version cs3=Virus cs3Label=Threat Type cs4=On-demand scanner cs4Label=Scanner ID act=Cleaned by deleting fileType=File filePath=file:///C:/Users/hr07/Downloads/task-helper.exe cn1=1 cn1Label=Handled cn2=0 cn2Label=Restart Needed suser=EXAMPLE\\\\hr07 deviceCustomDate1=Sep 01 2026 02:08:39 deviceCustomDate1Label=FirstSeen cs8=3ccf83ba204b33d808b3c663b82bb8b3eb57d073 cs8Label=Hash"}, "observer": {"name": "protect-01.example.test", "vendor": "ESET", "product": "Protect", "version": "11.1.20.0"}, "host": {"name": "ws-hr-07", "id": "ceaf535f-9788-4dc2-ab65-ef20909e6fad", "ip": ["10.20.1.57"], "os": {"name": "Microsoft Windows 11 Enterprise"}}, "eset": {"protect": {"category": "threat", "class_id": "183", "group": "All/Workstations/HR", "threat_name": "Win32/Agent.Gen", "scanner": "On-demand scanner", "engine_version": "34040 (20260901)"}}, "related": {"ip": ["10.20.1.57"], "hosts": ["ws-hr-07"], "user": ["hr07"], "hash": ["3ccf83ba204b33d808b3c663b82bb8b3eb57d073"]}, "file": {"path": "C:\\Users\\hr07\\Downloads\\task-helper.exe", "name": "task-helper.exe", "hash": {"sha1": "3ccf83ba204b33d808b3c663b82bb8b3eb57d073"}}, "user": {"name": "hr07", "domain": "EXAMPLE"}}
```

## Limitations

- **Firewall class ID**: the On-Prem 11.1 reference lists 200-299 for firewall events but prints `109` in its firewall example. The generator uses `209`, consistent with that range and ESET's PROTECT Cloud example; the ID has not been confirmed from an On-Prem 11.1 export.
- **No live capture**: fields and their order follow the vendor raw examples and field tables. The examples print `CEF:O` (letter O); the generator emits `CEF:0`. Class IDs and event names are limited to the documented ones (183, 209, 303), so the pack emits only cleaned threats, blocked port scans and blocked launches; failed cleanups (`cs6`), quarantine actions and other Threat, Firewall and HIPS event names are not modeled. The on-demand variant (no `cs5`, `cs7`, `sprod`) follows the PROTECT Cloud example.
- **Synthetic values**: event rates, the diurnal curve, detection names, file names and hashes, scanner addresses, the Firewall `cs3` threat name (taken from both vendor examples) and the detection engine build in `cs2` (about five builds per day, endpoints up to two builds behind) are synthetic. `cnt` varies between 1 and 5 without modeling agent replication batches.
- **Envelope**: the output is ECS JSON with a bare CEF payload, not a Syslog frame; the ECS projection is this pack's own. Audit, ESET Inspect, Blocked File and Filtered Website events are not generated.
- KUMA lists an ESET PROTECT 11.0 CEF normalizer; parsing of this 11.1 payload with it has not been verified.

## References

- [ESET PROTECT On-Prem 11.1: events exported to CEF format](https://help.eset.com/protect_admin/11.1/en-US/events_exported_to_cef_format.html)
- [ESET PROTECT On-Prem 11.1: export logs to Syslog](https://help.eset.com/protect_admin/11.1/en-US/admin_server_settings_export_to_syslog.html)
- [ESET PROTECT Cloud: events exported to CEF format](https://help.eset.com/protect_cloud/en-US/events_exported_to_cef_format.html)
- [ESET build versions](https://help.eset.com/latestVersions/)
- [KUMA 4.2 supported event sources](https://support.kaspersky.ru/kuma/4.2/255782)
- [Elastic ESET PROTECT integration](https://github.com/elastic/integrations/tree/main/packages/eset_protect)

The Elastic integration parses the JSON Syslog export and the ESET Connect API, not CEF, so this pack cannot mirror its sample event; the ECS projection here is the pack's own.

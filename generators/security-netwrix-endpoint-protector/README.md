# Netwrix Endpoint Protector Device Control SIEM export

Synthetic Netwrix Endpoint Protector 5.9.4 Device Control events as sent to a SIEM in Netwrix's documented Standard format with `Exclude Headers` on, wrapped in ECS JSON. It suits DLP and USB-control detection work: an office of staff plugging approved company storage, reading and writing files, and occasionally trying personal phones or flash drives that the policy blocks.

## Event types

| Native event | Share (default, 120 h) | ECS category / type | Meaning |
| --- | ---: | --- | --- |
| `File Write` | 34.6% | `file` / `change` | File written to the device |
| `File Read` | 30.4% | `file` / `access` | File read from the device |
| `Connected` | 14.7% | `host` / `start` | Approved device connected |
| `Disconnected` | 14.7% | `host` / `end` | Device disconnected |
| `File Delete` | 4.4% | `file` / `deletion` | File deleted from the device |
| `Blocked` | 1.2% | `host` / `denied` | Unapproved device blocked (`event.outcome: failure`) |

Shares were measured on the default-config capture used for the sample below. Volumes and rates are synthetic, not measured Endpoint Protector production rates.

Background: `staff_count` users in eight departments, each with an own workstation (name, IP, MAC, hardware serial, OS, client version, time zone). About 70% own an approved company stick or portable SSD; every department also shares two approved devices. About 65% of users carry one or two personal devices (iPhone, Android phone, personal flash drive) that the policy blocks. Each user works randomly phased shifts (about 9 h on, 14.5 h off, sometimes longer absences) and, while at work, starts device activities at lognormal gaps scaled by a per-user pace. An activity is either an approved-device session (`Connected`, then browsing reads, a few writes, a mixed read/write/delete session, a bulk copy of many files, or nothing, then `Disconnected`) or, at a per-user rate, a personal device plugged in: `Blocked`, re-plugged and blocked again within a minute or two in 40% of cases per attempt, and in half of the attempts followed a few minutes later by an approved-device session. Files come from a per-department pool with skewed popularity, so the same user writes the same file repeatedly; reads and deletes act on what is actually on the device, and shared devices carry other users' files.

## Anomaly Chain

**Sequence** (per `Client User` and `Client Computer`): `Blocked` for a personal device D, then `Connected` for an approved device S (S different from D), then at least five `File Write` records on S, all within one hour of the `Blocked` record, then `Disconnected` of S, which restores the device state. The reading: after the policy stopped a personal device, the user switched to an approved one and bulk-copied department files to it.

**Linking fields:** `Client User`, `Client Computer`, `IP Address`, `MAC Address`, `Device Serial` (D on the `Blocked` record, S on the session), `File Name` and `File Hash` of the copied files.

**Recurrence:** `anomaly_interval_hours` (default 24, minimum 6) in source time. The first episode is armed 1 h after the start plus a random delay of up to min(1 h, interval / 8). Once armed, the next background blocked attempt that is naturally followed by an approved device, by a user other than the previous episode's, becomes the episode: its approved-device session is a bulk copy with at least five writes. The next episode is due one interval after this episode's first `Blocked` record and is armed after a new random delay. Missed episodes are not replayed. Because an episode waits for a natural blocked-then-approved attempt (several per day across the office), actual spacing is the interval plus that wait: in the default 120 h capture 5 episodes 25.2-29.5 h apart; with an 8 h interval 10 episodes 8.8-19.3 h apart.

**Variation:** the user, workstation, personal device, approved device (own or department-shared), files and timing change between episodes; measured spans from `Blocked` to the fifth write were 2.3-11.8 min. Users take episodes in proportion to their own rate of blocked-then-approved attempts; episodes follow the same shifts and hour-of-day as the background because they are background attempts.

**Background overlap:** every step occurs in ordinary traffic of both modes: blocked personal devices by the same users (repeated within minutes), approved sessions that start minutes after a block (with up to four writes), bulk copies of five or more files (not after a block), and the same user, workstation, IP and device pairs. Only the complete sequence is absent from background: within 2 h after a `Blocked` record, a background session of that user is never a bulk copy and writes at most four files in total.

**Detection idea:** per user and computer, alert when `Blocked` is followed within an hour by `Connected` of a different device serial and five or more `File Write` records to that serial; enrich with the files' department folders and sizes. The sequence is a detection exercise, not proof of data theft; the export does not state whether a transfer was authorized.

`anomaly_mode` defaults to `true`. With `anomaly_mode: false` the generator emits the same background without any complete chain.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Description |
| --- | --- | --- |
| `anomaly_mode` | `true` | Add recurring anomaly chain episodes; `false` emits background only |
| `anomaly_interval_hours` | `24` | Hours between episodes (6 to 8760), counted from the previous episode's start |
| `epp_server` | `epp-01` | Endpoint Protector server name in `observer.name` |
| `staff_count` | `80` | Number of users and workstations (20 to 1000) |
| `utc_offset_hours` | `3` | Server time zone (hours from UTC, -12 to 14) for `Date/Time(Server)`; head-office workstations use it for `Date/Time(Client)` too |

### Output Parameters

The shipped `generator.yml` writes to `output/events.json` and needs no `${params.*}` or `${secrets.*}`. To deliver to OpenSearch or Elasticsearch, replace the output section:

```yaml
output:
  - opensearch:
      hosts:
        - ${params.opensearch_host}
      username: ${params.opensearch_user}
      password: ${secrets.opensearch_password}
      index: ${params.opensearch_index}
```

| Parameter | Description |
| --- | --- |
| `${params.opensearch_host}` | OpenSearch/Elasticsearch host URL |
| `${params.opensearch_user}` | Username for authentication |
| `${secrets.opensearch_password}` | Password (from Eventum keyring) |
| `${params.opensearch_index}` | Target index name |

## Usage

From the content-packs repository:

```bash
# Live generation, one input tick per second
eventum generate --path generators/security-netwrix-endpoint-protector/generator.yml --id epp --live-mode true

# Batch generation as fast as possible
eventum generate --path generators/security-netwrix-endpoint-protector/generator.yml --id epp --live-mode false
```

Each input tick emits at most one record (the earliest due one), so during bulk copies a record can be emitted a few seconds after its own event time in `@timestamp`. Sort by `@timestamp`, not by output row order. For a finite batch window, add `start` and `end` to the `cron` input.

## Sample output

The fifth `File Write` of an anomaly episode, copied byte for byte from the default-config capture (one line per record):

```json
{"@timestamp": "2026-09-04T12:44:53Z", "ecs": {"version": "8.17.0"}, "endpoint_protector": {"device_control": {"fields": {"Client Computer": "FIN-WS-256", "Client User": "psorokin", "Date/Time(Client UTC)": "2026-09-04 12:44:53", "Date/Time(Client)": "2026-09-04 15:44:53", "Date/Time(Server UTC)": "2026-09-04 12:44:55", "Date/Time(Server)": "2026-09-04 15:44:55", "Device": "Kingston DataTraveler 3.0", "Device PID": "1666", "Device Serial": "160DD8A45DB0EEF5", "Device Type": "Removable Storage Devices", "Device VID": "0951", "EPP Client Version": "5.9.4", "Event Name": "File Write", "File Hash": "2b715c2633308664c7a2382d82e9fc2e", "File Name": "D:\\Finance\\Work\\Payroll 2026.csv", "File Size": "578866", "File Type": "CSV", "IP Address": "10.20.3.120", "Justification": "", "Log ID": "46d60465370d4501b39027677534ae92", "MAC Address": "F8-B4-6A-4B-46-57", "OS": "Windows 10 Enterprise", "Repository Type": "", "Serial Number": "MXLVLUEKGH", "Shadow Exists": "No", "Time Interval": ""}}}, "event": {"action": "file_write", "category": ["file"], "dataset": "endpoint_protector.device_control", "id": "46d60465370d4501b39027677534ae92", "kind": "event", "module": "endpoint_protector", "original": "Device Control \u2013 File Write: [Log ID] 46d60465370d4501b39027677534ae92 | [Event Name] File Write | [Client Computer] FIN-WS-256 | [IP Address] 10.20.3.120 | [MAC Address] F8-B4-6A-4B-46-57 | [Serial Number] MXLVLUEKGH | [OS] Windows 10 Enterprise | [Client User] psorokin | [Device Type] Removable Storage Devices | [Device] Kingston DataTraveler 3.0 | [Device VID] 0951 | [Device PID] 1666 | [Device Serial] 160DD8A45DB0EEF5 | [EPP Client Version] 5.9.4 | [File Name] D:\\Finance\\Work\\Payroll 2026.csv | [File Hash] 2b715c2633308664c7a2382d82e9fc2e | [File Type] CSV | [File Size] 578866 | [Justification]  | [Time Interval]  | [Date/Time(Server)] 2026-09-04 15:44:55 | [Date/Time(Client)] 2026-09-04 15:44:53 | [Date/Time(Server UTC)] 2026-09-04 12:44:55 | [Date/Time(Client UTC)] 2026-09-04 12:44:53 | [Shadow Exists] No | [Repository Type] ", "outcome": "success", "type": ["change"]}, "file": {"extension": "csv", "name": "Payroll 2026.csv", "path": "D:\\Finance\\Work\\Payroll 2026.csv", "size": 578866}, "host": {"ip": ["10.20.3.120"], "mac": ["F8-B4-6A-4B-46-57"], "name": "FIN-WS-256", "os": {"name": "Windows 10 Enterprise"}}, "message": "Device Control \u2013 File Write", "observer": {"name": "epp-01", "product": "Endpoint Protector", "vendor": "Netwrix", "version": "5.9.4"}, "related": {"hosts": ["FIN-WS-256"], "ip": ["10.20.3.120"], "user": ["psorokin"]}, "source": {"ip": "10.20.3.120"}, "user": {"name": "psorokin"}}
```

## Format and coverage

Netwrix documents the Standard format as `log_type: [field_name] field_value | [field_name] field_value | ...`, with `log_type` combining "Device Control" and the event name (`Device Control – Connected`). `event.original` carries that body with all 26 documented Device Control columns in the documented order; `endpoint_protector.device_control.fields` keeps the same names and values. Columns that do not apply stay empty. Event names are taken from the Endpoint Protector event catalog; device type names from the documented device-type list.

Not published by Netwrix and therefore synthetic or inferred: the exact value formats of the four date columns (rendered here as `YYYY-MM-DD HH:MM:SS`), of `OS`, `Device Type`, `Log ID` (32 hex characters) and `File Hash` (32 hex characters, algorithm not stated), the file path style, and whether a blocked device also emits `Connected`/`Disconnected` (here it emits `Blocked` only). The MAC Address hyphen style follows the Google SecOps parser for this source. `Date/Time(Server)` trails the client time by a few seconds. `Date/Time(Client)` is in the workstation's zone: head office at `utc_offset_hours` (75% of workstations), branch offices 2 h, 4 h or -1 h away. `@timestamp` is the client event time at second precision. Justification, Time Interval, Shadow Exists and Repository Type are left at their no-remediation, no-shadow values.

## Limitations

- No vendor-captured raw Device Control record was available; the format follows the documented field list only. Parser compatibility (for example KUMA's Endpoint Protector normalizer) was not tested.
- Only six Device Control events are modeled; File Copy, File Rename, Unblocked, Trusted Device, remediation, Content Aware Protection, eDiscovery and Admin Action logs are not.
- No syslog header (`Exclude Headers` on); no weekday or business-hours cycle; one workstation per user and static IPs.
- The guard that keeps the complete chain out of background also removes bulk copies from the two hours after a user's blocked device.

## References

- [Netwrix Endpoint Protector: SIEM Integration and SIEM Export log formats](https://docs.netwrix.com/docs/endpointprotector/admin/appliance)
- [Netwrix Endpoint Protector: Events Types and Descriptions](https://docs.netwrix.com/docs/endpointprotector/admin/systempar)
- [Netwrix Endpoint Protector: Device Control module and device types](https://docs.netwrix.com/docs/endpointprotector/admin/dc_module/dcmodule)
- [Netwrix Endpoint Protector: Set Up a SIEM Integration (Exclude Headers)](https://docs.netwrix.com/docs/endpointprotector/kb/administration-security-and-monitoring/set_up_a_siem_integration)
- [Google SecOps: Endpoint Protector DLP parser field mapping](https://docs.cloud.google.com/chronicle/docs/ingestion/default-parsers/endpoint-protector-dlp)
- [KUMA 4.2 supported sources](https://support.kaspersky.ru/kuma/4.2/255782)

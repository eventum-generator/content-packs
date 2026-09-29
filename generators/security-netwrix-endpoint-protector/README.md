# Netwrix Endpoint Protector Device Control SIEM export

Synthetic Netwrix Endpoint Protector 5.9.4 Device Control events as sent to a SIEM in Netwrix's documented Standard format with `Exclude Headers` on, wrapped in ECS JSON. It suits DLP and USB-control detection work: an organisation of 1,000 staff plugging approved company storage, reading and writing files, and trying personal phones or flash drives that the policy blocks.

## Event types

| Native event | Share | ECS category / type | Meaning |
| --- | ---: | --- | --- |
| `File Write` | 34.7% | `file` / `change` | File written to the device |
| `File Read` | 29.2% | `file` / `access` | File read from the device |
| `Connected` | 14.4% | `host` / `start` | Approved device connected |
| `Disconnected` | 14.4% | `host` / `end` | Device disconnected |
| `File Delete` | 4.4% | `file` / `deletion` | File deleted from the device |
| `Blocked` | 3.0% | `host` / `denied` | Unapproved device blocked (`event.outcome: failure`) |

Shares over four days of the default configuration. Volumes and rates are synthetic, not measured Endpoint Protector production rates.

### Volume and population

About 15,000 records per day (14,650-15,270 per day over two weeks), following the working day of the head office (`utc_offset_hours`, UTC+3 by default): about 0.3% of the daily volume per hour at night, a rise in steps from 05:00 (about 190 records an hour until 07:30, about 530 until 08:00 and about 390 until 08:30), about 9.8% per hour from 09:00 to 17:00, and a fall through 17:00-19:00.

The organisation has 1,000 staff in eight departments, each with an own workstation (name, IP, MAC, hardware serial, OS, client version, time zone). About a tenth are Operations and IT duty staff who work alternating 12-hour day or night shifts at head office and carry the night-time records. The rest work a single office day of about nine hours in their own office's zone (head office for three quarters of them, branch offices 2 h or 4 h east or 1 h west), start within about 20 minutes of their usual time and are away on about 4% of days. Users differ in how often they use USB storage.

About 70% own an approved company stick or portable SSD; every department also shares two approved devices. About 65% carry one or two personal devices (iPhone, Android phone, personal flash drive) that the policy blocks. A small group of about 40 users (five duty staff per shift and about 2% of office staff) plug their own phone into the workstation several times a day, mostly to charge it, and use their own company stick often; they read from it more and bulk-copy less than others.

A device activity is either an approved-device session or a personal device plugged in. A session is `Connected`, then browsing reads, a few writes, a mixed read/write/delete session, a bulk copy of many files written seconds apart, or nothing, then `Disconnected`; the median session lasts about six minutes. A personal device gives `Blocked`, is re-plugged and blocked again within a minute or two in 40% of cases per attempt, and in half of the attempts an approved device follows a few minutes later. `Blocked` makes up about 3% of records (about 420 per day): about half of all users are blocked at least once in two weeks, and the 40 most frequent carry about 55% of blocks. Files come from a per-department pool with skewed popularity, so the same user writes the same file repeatedly; reads and deletes act on what is actually on the device, and shared devices carry other users' files.

## Anomaly Chain

**Sequence** (per `Client User` and `Client Computer`): `Blocked` for a personal device D, then `Connected` for an approved device S (S different from D), then five `File Write` records on S, all within one hour of the `Blocked` record, then `Disconnected` of S. The reading: after the policy stopped a personal device, the user switched to an approved one and bulk-copied department files to it.

**Linking fields:** `Client User`, `Client Computer`, `IP Address`, `MAC Address`, `Device Serial` (D on the `Blocked` record, S on the session), `File Name` and `File Hash` of the copied files.

**Actor:** one of the phone-charging users who is at work at that hour and had no `Blocked` record in the previous hour; D is the user's own phone and S the user's own company stick. The same user never takes two episodes in a row.

**Recurrence:** `anomaly_interval_hours` (default 24, minimum 6), counted in record time. The first episode starts within min(interval, 24 h) of the start of the data, at an hour that follows the daily volume curve. Each later episode starts within ±min(interval / 4, 6 h) / 2 of one interval after the previous episode's start, weighted toward the busiest hours. Missed episodes are not replayed. At the default interval episodes are 21-27 h apart, mostly between 09:00 and 17:00; at an 8 h interval they are 7-9 h apart and include night hours.

**Variation:** the user, workstation, phone, stick, files and timing change between episodes; the `Blocked` record is re-plugged like any other, and the span from the first `Blocked` record to the fifth write is usually under 12 minutes, up to about 20 minutes at night. Every episode writes exactly five files.

**Background overlap:** every step occurs in ordinary traffic of both modes: the same users are blocked on the same phones and use the same sticks many times a day (each such phone and stick appears several times in any four days of background), approved sessions start minutes after a block (with up to four writes to that device within the hour), and bulk copies of five or more files happen outside the hour after a block. Only the complete sequence is absent from background: within one hour after a `Blocked` record, a user writes at most four files to each approved device connected after it.

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
| `staff_count` | `1000` | Number of users and workstations (100 to 5000) |
| `utc_offset_hours` | `3` | Head-office and server time zone (hours from UTC, -12 to 14) for `Date/Time(Server)` and head-office `Date/Time(Client)` |

The daily volume and its hour curve are set in `patterns/*.yml` (`multiplier.ratio` is the number of records per day of each part of the curve). When changing `staff_count`, scale all four `ratio` values by the same factor to keep the per-user rate. When changing `utc_offset_hours`, change the offset in each pattern's `start` too, so that the curve follows the new local day.

### Sample files

- `samples/departments.json` - department codes, folder names, file-name words, extensions and head-count weights.
- `samples/device_models.csv` - device models with `policy` `approved` (company storage) or `personal` (blocked devices) and a weight.
- `samples/file_types.csv` - median file size per extension.
- `samples/surnames.csv` - surnames used for user names.

The staff, workstations, devices and files are built from these files the same way in every run; only behaviour differs between runs.

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
# Live generation at the real rate
eventum generate --path generators/security-netwrix-endpoint-protector/generator.yml --id epp --live-mode true

# Batch generation as fast as possible
eventum generate --path generators/security-netwrix-endpoint-protector/generator.yml --id epp --live-mode false
```

To generate background only, set `anomaly_mode: false` in `generator.yml` before running.

The patterns run from 2026-01-01 with no end, so live generation starts at the current moment. For a finite batch window, set `start` and `end` in each `patterns/*.yml` to the same local midnights, for example `start: "2026-09-01T00:00:00+03:00"` and `end: "2026-09-05T00:00:00+03:00"` for four days.

Performance: about 1,800 records per second in batch mode (two weeks, 210,000 records, in about two minutes).

## Sample output

The fifth `File Write` of an anomaly episode, copied byte for byte from a default-configuration run (one line per record):

```json
{"@timestamp": "2026-09-02T08:30:54Z", "ecs": {"version": "8.17.0"}, "endpoint_protector": {"device_control": {"fields": {"Client Computer": "ENG-WS-252", "Client User": "dkovaleva2", "Date/Time(Client UTC)": "2026-09-02 08:30:54", "Date/Time(Client)": "2026-09-02 10:30:54", "Date/Time(Server UTC)": "2026-09-02 08:30:55", "Date/Time(Server)": "2026-09-02 11:30:55", "Device": "WD My Passport 25E2", "Device PID": "25E2", "Device Serial": "C4942DEB0E08EFF2", "Device Type": "External HDDs / portable hard disks", "Device VID": "1058", "EPP Client Version": "5.9.4", "Event Name": "File Write", "File Hash": "b98ea0a0c945413292b19310ba2d5493", "File Name": "E:\\Engineering\\Archive\\Firmware mar.bin", "File Size": "5673101", "File Type": "BIN", "IP Address": "10.20.26.156", "Justification": "", "Log ID": "a72942a6c95848e3b1d1b0b485afae9b", "MAC Address": "00-1B-21-72-25-56", "OS": "Windows 10 Enterprise", "Repository Type": "", "Serial Number": "CZCDEDGJTA", "Shadow Exists": "No", "Time Interval": ""}}}, "event": {"action": "file_write", "category": ["file"], "dataset": "endpoint_protector.device_control", "id": "a72942a6c95848e3b1d1b0b485afae9b", "kind": "event", "module": "endpoint_protector", "original": "Device Control \u2013 File Write: [Log ID] a72942a6c95848e3b1d1b0b485afae9b | [Event Name] File Write | [Client Computer] ENG-WS-252 | [IP Address] 10.20.26.156 | [MAC Address] 00-1B-21-72-25-56 | [Serial Number] CZCDEDGJTA | [OS] Windows 10 Enterprise | [Client User] dkovaleva2 | [Device Type] External HDDs / portable hard disks | [Device] WD My Passport 25E2 | [Device VID] 1058 | [Device PID] 25E2 | [Device Serial] C4942DEB0E08EFF2 | [EPP Client Version] 5.9.4 | [File Name] E:\\Engineering\\Archive\\Firmware mar.bin | [File Hash] b98ea0a0c945413292b19310ba2d5493 | [File Type] BIN | [File Size] 5673101 | [Justification]  | [Time Interval]  | [Date/Time(Server)] 2026-09-02 11:30:55 | [Date/Time(Client)] 2026-09-02 10:30:54 | [Date/Time(Server UTC)] 2026-09-02 08:30:55 | [Date/Time(Client UTC)] 2026-09-02 08:30:54 | [Shadow Exists] No | [Repository Type] ", "outcome": "success", "type": ["change"]}, "file": {"extension": "bin", "name": "Firmware mar.bin", "path": "E:\\Engineering\\Archive\\Firmware mar.bin", "size": 5673101}, "host": {"ip": ["10.20.26.156"], "mac": ["00-1B-21-72-25-56"], "name": "ENG-WS-252", "os": {"name": "Windows 10 Enterprise"}}, "message": "Device Control \u2013 File Write", "observer": {"name": "epp-01", "product": "Endpoint Protector", "vendor": "Netwrix", "version": "5.9.4"}, "related": {"hosts": ["ENG-WS-252"], "ip": ["10.20.26.156"], "user": ["dkovaleva2"]}, "source": {"ip": "10.20.26.156"}, "user": {"name": "dkovaleva2"}}
```

## Format and coverage

Netwrix documents the Standard format as `log_type: [field_name] field_value | [field_name] field_value | ...`, with `log_type` combining "Device Control" and the event name (`Device Control – Connected`). `event.original` carries that body with all 26 documented Device Control columns in the documented order; `endpoint_protector.device_control.fields` keeps the same names and values. Columns that do not apply stay empty. Event names are taken from the Endpoint Protector event catalog; device type names from the documented device-type list.

Not published by Netwrix and therefore synthetic or inferred: the exact value formats of the four date columns (rendered here as `YYYY-MM-DD HH:MM:SS`), of `OS`, `Device Type`, `Log ID` (32 hex characters) and `File Hash` (32 hex characters, algorithm not stated), the file path style, and whether a blocked device also emits `Connected`/`Disconnected` (here it emits `Blocked` only). The MAC Address hyphen style follows the Google SecOps parser for this source. `Date/Time(Server)` trails the client time by a few seconds. `Date/Time(Client)` is in the workstation's zone: head office at `utc_offset_hours` (about three quarters of workstations), branch offices 2 h, 4 h or -1 h away. `@timestamp` is the client event time at second precision. Justification, Time Interval, Shadow Exists and Repository Type are left at their no-remediation, no-shadow values.

## Limitations

- No vendor-captured raw Device Control record was available; the format follows the documented field list only. Parser compatibility (for example KUMA's Endpoint Protector normalizer) was not tested.
- Only six Device Control events are modeled; File Copy, File Rename, Unblocked, Trusted Device, remediation, Content Aware Protection, eDiscovery and Admin Action logs are not.
- No syslog header (`Exclude Headers` on). Every day is a working day: there is no weekday or weekend cycle. One workstation per user and static IPs.
- Records of one session are seconds to minutes apart, not milliseconds: a bulk copy of 20 or more files takes about five minutes in office hours, and at night, when only duty staff are at work, consecutive records of one session are often minutes apart.
- Within one hour after a `Blocked` record, a user writes at most four files to each approved device connected after it (outside episodes). About one in ten copies of five or more files falls into such an hour and stops at four files, so in that hour sessions with exactly four writes are about twice as common as elsewhere and sessions with five or more are almost absent.
- With `anomaly_mode: true` each episode adds its own records (a blocked phone, one session with five writes to the user's stick), so counts of these records and of the chain parts are about one per episode higher than with `anomaly_mode: false`.

## References

- [Netwrix Endpoint Protector: SIEM Integration and SIEM Export log formats](https://docs.netwrix.com/docs/endpointprotector/admin/appliance)
- [Netwrix Endpoint Protector: Events Types and Descriptions](https://docs.netwrix.com/docs/endpointprotector/admin/systempar)
- [Netwrix Endpoint Protector: Device Control module and device types](https://docs.netwrix.com/docs/endpointprotector/admin/dc_module/dcmodule)
- [Netwrix Endpoint Protector: Set Up a SIEM Integration (Exclude Headers)](https://docs.netwrix.com/docs/endpointprotector/kb/administration-security-and-monitoring/set_up_a_siem_integration)
- [Google SecOps: Endpoint Protector DLP parser field mapping](https://docs.cloud.google.com/chronicle/docs/ingestion/default-parsers/endpoint-protector-dlp)
- [KUMA 4.2 supported sources](https://support.kaspersky.ru/kuma/4.2/255782)

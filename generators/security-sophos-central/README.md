# Sophos Central SIEM CEF events

Synthetic Sophos Central endpoint events in the CEF that the Sophos Central SIEM Integration script (`siem.py` 2.1.0, `format = cef`, `endpoint = event`) writes from the SIEM API `/siem/v1/events`, for SIEM detection engineering and parser testing. Eventum writes ECS JSON and places the CEF line in `event.original`.

## Event Types Covered

| Event type (CEF header class) | Description | Share | ECS `event.category` |
| --- | --- | --- | --- |
| `Event::Endpoint::UpdateSuccess` | Update succeeded | 68.8% | `host` |
| `Event::Endpoint::WebControlViolation` | Website blocked by web control | 17.8% | `web` |
| `Event::Endpoint::Device::AlertedOnly` | Peripheral allowed (device control in alert-only mode) | 6.0% | `host` |
| `Event::Endpoint::SavScanComplete` | Scheduled scan completed | 3.9% | `host` |
| `Event::Endpoint::Threat::Detected` | Malware detected | 1.1% | `malware` |
| `Event::Endpoint::Threat::CleanedUp` | Malware cleaned up | 0.8% | `malware` |
| `Event::Endpoint::UpdateFailure` | Update failed | 0.7% | `host` |
| `Event::Endpoint::UserAutoCreated` | New user added automatically | 0.4% | `iam` |
| `Event::Endpoint::Threat::CleanupFailed` | Manual cleanup required | 0.2% | `malware` |
| `Event::Endpoint::Threat::PuaDetected` | PUA detected | 0.2% | `malware` |
| `Event::Endpoint::Threat::PuaCleanupFailed` | Manual PUA cleanup required | 0.1% | `malware` |

Shares are those of the default configuration, anomaly episodes included. The rate and shares are scenario assumptions, not Sophos measurements.

74 endpoints (`samples/endpoints.csv`: 64 workstations with one user each, 10 servers) report independently. The tenant writes about 640 events a day:

- **Workstations** (about 545 a day) follow the office day in UTC: about 10 events an hour from 20:00 to 05:00, rising through 05:00-07:00 to about 35 an hour from 07:00 to 17:00, and falling back by 20:00. At night workstations send mostly update checks and scans; web control blocks, peripheral alerts and new users fall almost entirely in the office day.
- **Servers** (about 95 a day) report evenly around the clock, about 4 events an hour.

In total the volume runs at about 14 events an hour at night and 40 an hour in business hours; each day differs from the base volume by up to 3%. Weekends carry the same volume as weekdays.

Most records are routine. Every endpoint checks for updates several times a day, and the endpoints of one kind take turns in random order; about 1% of the checks fail. Each endpoint completes a scheduled scan about twice a week. Workstation users hit blocked web categories (games, streaming, social networking, gambling and others; about 110 blocks a day, more for users who browse a lot) and connect USB drives and phones that device control allows with an alert (about 37 a day). A new user is added automatically two or three times a day.

Threat activity is a normal baseline rather than an outbreak. Ordinary activity has about 5 malware detections and fewer than one PUA detection a day, and about one failed cleanup a day. Most detections fall on three busy endpoints - two workstations whose users download a lot (`WS-MKT-798`, `WS-ENG-679`) and a terminal server (`SRV-RDS-05`) - which each report detections several times a week; the other endpoints report one rarely, so in a typical week about 9-17 endpoints have a detection and 3-7 a failed cleanup; on a busy endpoint a day with an episode can reach 8-9 detections. The generic detections `Mal/Generic-S` and `ML/PE-A` make up about 60% of the malware detections. A detection incident is one of the following:

- detected and cleaned up automatically, sometimes detected and cleaned again a few minutes later;
- the same file detected two to four times within minutes, usually cleaned up after the last detection;
- cleanup failed: the file is left for the administrator, cleaned up manually after a median of about 1.5 hours (about a third within the first hour), or detected again minutes later (sometimes with another failure);
- a PUA detection, often followed by a failed PUA cleanup and sometimes by a repeat detection an hour later.

Spacing between consecutive records of one file on one endpoint: detection to automatic cleanup 30 s to 6 min (median about 2 min), detection to failed cleanup 45 s to 7 min (median about 2.5 min), repeat detections 4-36 min apart (median 12 min).

Threat names and file names come from `samples/threats.json`; file paths are built from the endpoint user's profile folders or server folders. Blocked sites come from `samples/web_sites.json` (fictional domains under `.example`) and peripherals from `samples/devices.json`. All names, addresses (RFC 1918) and identifiers are synthetic.

## Anomaly Chain

With `anomaly_mode: true` (the default), the generator adds a recurring episode on one endpoint:

1. **Detected**: a malware file is detected (`Event::Endpoint::Threat::Detected`).
2. **Cleanup failed**: one to a few minutes later, cleanup of the same file fails (`Event::Endpoint::Threat::CleanupFailed`).
3. **Detected again**: several minutes later, the same threat is detected again at the same path.
4. **Cleaned up**: a minute or two later, the same file is cleaned up (`Event::Endpoint::Threat::CleanedUp`).

**Linking fields**: CEF `dhost` (`host.name`), `threat`/`detection_identity_name` (`sophos_central.event.threat`) and `filePath` (`file.path`); `endpoint_id` and `suser` identify the same endpoint and user. An episode spans from a few minutes to about an hour and a half and always stays within two hours.

**Recurrence**: the first episode starts at a random time within the first `anomaly_interval_hours` (default 24, minimum 3) or the first 24 hours, whichever is shorter; its hour of day follows the detection rate of the busy endpoints, so business hours are more likely than the night. Each next episode starts within a window centred on `anomaly_interval_hours` after the actual start of the previous one; the window is a quarter of the interval wide, at most six hours, and inside it hours with more detections are preferred (squared detection rate plus a small floor). Start times therefore drift through the day from one episode to the next: consecutive episodes are 21-27 hours apart at the default interval and 7-9 hours apart at 8 hours.

**Variation**: each episode picks another endpoint and another malware threat than the previous one, a file of that threat, and a folder at random. The endpoint is one of the three busy endpoints, in proportion to their detection rates at that hour, so every episode endpoint also reports ordinary detections every week; the threat is `Mal/Generic-S` or `ML/PE-A`, the two most common ones. Gaps between the steps are random and drawn from the same distributions as the ordinary incidents.

**Volume**: the four records of an episode are part of the same event volume, so the total volume and its hour curve are the same in both modes; with `anomaly_mode: true` the tenant sends about four fewer routine records per episode. Threat records are not reduced, so each episode adds its own two detections, one failed cleanup and one cleanup: at the default interval the tenant has about two more detections and one more failed cleanup a day than with `anomaly_mode: false`. The episode endpoint keeps its ordinary events during and after the episode.

**Background**: every step, endpoint and threat of the episode also occurs in ordinary traffic in both modes, as do cleanup failures, repeat detections of the same file within minutes, repeated failures, detection after a failed cleanup, and manual cleanup after a failure; episode file paths come from the same folders and file names as ordinary detections. Only the complete ordered sequence is absent: an ordinary cleanup that would complete Detected, CleanupFailed, Detected, CleanedUp for the same endpoint, threat and file within two hours of the first detection is reported as `CleanupFailed` at the same time. This also applies after an episode, so an ordinary cleanup cannot complete the sequence together with episode events. Any later cleanup of that file inside the same two-hour window is reported the same way; cleanups after the window are not changed. This is very rare: less than one ordinary cleanup a month. With `anomaly_mode: false` the generator produces this background only.

**Detection idea**: per endpoint, threat and file path, alert when a detection is followed by a failed cleanup, a new detection of the same file and then a cleanup within two hours. It points to malware that was not removed at first and came back (a persistence mechanism or a re-drop) before the retry succeeded; the host deserves a check for the dropper.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`.

| Name | Default | Description |
| --- | --- | --- |
| `anomaly_mode` | `true` | Add the recurring Detected, CleanupFailed, Detected, CleanedUp episode. `false` produces background only. |
| `anomaly_interval_hours` | `24` | Hours from the start of one episode to the time the next is due. Minimum 3, maximum 8760. |
| `customer_id` | `6f1c2a9e-3b7d-4c58-9e21-0d4b8a7f5c13` | Sophos Central tenant (customer) ID in `customer_id`. |
| `domain` | `CONTOSO` | Windows domain in `suser` (`DOMAIN\user`) for workstation users. |

### Output Parameters

The shipped `generator.yml` writes to a local file and needs no top-level `params` or `secrets`. To send events to a backend, replace `output` and reference top-level placeholders, for example:

```yaml
output:
  - opensearch:
      hosts:
        - ${params.opensearch_host}
      username: ${params.opensearch_user}
      password: ${secrets.opensearch_password}
      index: sophos-central
```

A CEF collector needs the `event.original` line rather than the ECS JSON document.

## Usage

```bash
# Batch: generate as fast as possible
eventum generate --path generators/security-sophos-central/generator.yml --id sophos-central --live-mode false

# Live: events at their event times
eventum generate --path generators/security-sophos-central/generator.yml --id sophos-central --live-mode true
```

Events are written to `generators/security-sophos-central/output/events.json`.

The files in `patterns/` start at midnight of the current day and never end. For a finite batch window, set `start` and `end` in each of them, for example `start: "2026-09-01T00:00:00Z"` and `end: "+120h"`; start the window at midnight so that the hour curve stays in place.

**Performance**: about 2,000 events/s in batch mode (14 days, about 8,900 events, in about 4 s).

## Sample Output

The first detection of an anomaly episode, copied byte for byte from a default-configuration run (one JSON document per line):

```json
{"@timestamp": "2026-09-02T20:12:30.847Z", "ecs": {"version": "8.11.0"}, "event": {"kind": "event", "dataset": "sophos_central.event", "module": "sophos_central", "category": ["malware"], "type": ["info"], "code": "Event::Endpoint::Threat::Detected", "action": "Malware detected: 'ML/PE-A' at 'C:\\Users\\yuri.smith\\Desktop\\crack_keygen.exe'", "id": "42559af0-b52a-4079-b3eb-60c7479a04ad", "created": "2026-09-02T20:12:35.761Z", "severity": 8, "original": "CEF:0|sophos|sophos central|1.0|Event::Endpoint::Threat::Detected|ML/PE-A|8|source_info_ip=10.20.15.139 customer_id=6f1c2a9e-3b7d-4c58-9e21-0d4b8a7f5c13 threat=ML/PE-A endpoint_id=595864a4-07e6-42be-8e14-f2deb6c1b27d endpoint_type=computer group=MALWARE id=42559af0-b52a-4079-b3eb-60c7479a04ad datastream=event detection_identity_name=ML/PE-A filePath=C:\\\\Users\\\\yuri.smith\\\\Desktop\\\\crack_keygen.exe suser=CONTOSO\\\\yuri.smith rt=2026-09-02T20:12:35.761Z duid=4cc74ae9af9f2e66038ff7e7 end=2026-09-02T20:12:30.847Z dhost=WS-ENG-679"}, "observer": {"vendor": "Sophos", "product": "Sophos Central"}, "organization": {"id": "6f1c2a9e-3b7d-4c58-9e21-0d4b8a7f5c13"}, "host": {"name": "WS-ENG-679", "id": "595864a4-07e6-42be-8e14-f2deb6c1b27d"}, "source": {"ip": "10.20.15.139"}, "related": {"ip": ["10.20.15.139"], "hosts": ["WS-ENG-679"], "user": ["yuri.smith"]}, "sophos_central": {"event": {"type": "Event::Endpoint::Threat::Detected", "group": "MALWARE", "severity": "high", "source": "CONTOSO\\yuri.smith", "location": "WS-ENG-679", "when": "2026-09-02T20:12:30.847Z", "created_at": "2026-09-02T20:12:35.761Z", "endpoint": {"id": "595864a4-07e6-42be-8e14-f2deb6c1b27d", "type": "computer"}, "datastream": "event", "user_id": "4cc74ae9af9f2e66038ff7e7", "threat": "ML/PE-A", "detection_identity_name": "ML/PE-A"}}, "user": {"name": "yuri.smith", "domain": "CONTOSO", "id": "4cc74ae9af9f2e66038ff7e7"}, "file": {"path": "C:\\Users\\yuri.smith\\Desktop\\crack_keygen.exe", "name": "crack_keygen.exe"}}
```

## Format and Limitations

- **CEF construction** follows `siem.py` 2.1.0 and `name_mapping.py`: header `CEF:0|sophos|sophos central|1.0|<type>|<name>|<severity>|`, where threat descriptions of the form `<text>: '<threat>' at '<path>'` are split into `detection_identity_name` and `filePath` and the header name becomes the threat name; API severity is mapped `low` 1, `medium` 5, `high` 8; nested `source_info.ip` is flattened to `source_info_ip`; `source`, `created_at`, `user_id`, `when` and `location` are renamed to `suser`, `rt`, `duid`, `end` and `dhost` and, as the script does, move to the end of the extension; `=` and `\` in values are escaped with a backslash. The script's header version stays `1.0` although the script is 2.1.0.
- **API item**: only fields of the SIEM API event schema are used (`id`, `customer_id`, `severity`, `source`, `source_info`, `location`, `when`, `created_at`, `name`, `type`, `user_id`, `threat`, `group`, `endpoint_type`, `endpoint_id`) plus `datastream`, which the script adds. The key order of the API response is not documented; it follows the order seen in the Elastic `sophos_central` test fixture. Severity is lowercase as in every published example (the schema page lists uppercase values, which `siem.py` would map to 0).
- **Descriptions**: `Manual PUA cleanup required: '<threat>' at '<path>'` is taken from the script's changelog example; the other threat descriptions, the texts of update and scan events (web control and peripheral texts follow published SIEM samples: `'<URL>' blocked due to category '<Category>'` and `Peripheral allowed: <device>`), the per-type severities and the groups of `UserAutoCreated`, `SavScanComplete` and `Device::AlertedOnly` are modeled, not copied from a live tenant. The routine event types are the ones the script lists as noisy. No complete raw CEF line from a live tenant was found, so byte parity with production output is established only against the script's code.
- **Time**: `end` is when the endpoint reported the event and `rt` when Central recorded it (seconds later, occasionally tens of minutes for an offline endpoint). `@timestamp` is `end`. Records that a real endpoint sends seconds apart (a detection and its automatic cleanup, a detection and its failed cleanup) are one to several minutes apart here, at night up to about half an hour.
- **Volume**: the hour curve is fixed in UTC and has no weekly or holiday cycle; the counts of routine events per endpoint are scenario assumptions.
- **Scope**: events endpoint only; no `/siem/v1/alerts` records, no IPS, AMSI, core detection, web filtering, application control, compliance or DLP events, and no `core_remedy_items`, `appCerts` or `whitelist_properties` objects. `convert_dhost_field_to_valid_fqdn` has no effect because every host name is already valid.
- **Transport**: the script prints to stdout, a file or syslog; the shipped file output writes ECS JSON documents instead.

## References

- [Sophos Central SIEM Integration repository](https://github.com/sophos/Sophos-Central-SIEM-Integration)
- [siem.py: CEF format, field mapping, severity map, escaping](https://github.com/sophos/Sophos-Central-SIEM-Integration/blob/master/siem.py)
- [name_mapping.py: threat description split and event types](https://github.com/sophos/Sophos-Central-SIEM-Integration/blob/master/name_mapping.py)
- [CHANGELOG.md: datastream field and a PUA cleanup example](https://github.com/sophos/Sophos-Central-SIEM-Integration/blob/master/CHANGELOG.md)
- [Sophos SIEM API schema reference (event fields and enums)](https://developer.sophos.com/siem-api-schemas/)
- [Elastic sophos_central integration (event data stream)](https://github.com/elastic/integrations/tree/main/packages/sophos_central)

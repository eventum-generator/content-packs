# Sophos Central SIEM CEF events

Synthetic Sophos Central endpoint events in the CEF that the Sophos Central SIEM Integration script (`siem.py` 2.1.0, `format = cef`, `endpoint = event`) writes from the SIEM API `/siem/v1/events`, for SIEM detection engineering and parser testing. Eventum writes ECS JSON and places the CEF line in `event.original`.

## Event Types Covered

| Event type (CEF header class) | Description | Share | ECS `event.category` |
| --- | --- | --- | --- |
| `Event::Endpoint::UpdateSuccess` | Update succeeded | 60.9% | `host` |
| `Event::Endpoint::Threat::Detected` | Malware detected | 18.6% | `malware` |
| `Event::Endpoint::Threat::CleanedUp` | Malware cleaned up | 11.8% | `malware` |
| `Event::Endpoint::Threat::PuaDetected` | PUA detected | 3.5% | `malware` |
| `Event::Endpoint::Threat::CleanupFailed` | Manual cleanup required | 3.4% | `malware` |
| `Event::Endpoint::Threat::PuaCleanupFailed` | Manual PUA cleanup required | 1.6% | `malware` |
| `Event::Endpoint::UserAutoCreated` | New user added automatically | 0.3% | `iam` |

Shares were measured over 14 synthetic days of the default configuration (about 650 events per day, 150 detection incidents per day). The rate and shares are scenario assumptions, not Sophos measurements.

74 endpoints (`samples/endpoints.csv`: 64 workstations with one user each, 10 servers) report independently. Each endpoint has its own activity level, and the gaps between its detection incidents follow a skewed random distribution; workstations are about four times as active in UTC business hours as at night, servers are active around the clock. Update checks arrive every few hours per endpoint at random gaps. A detection incident is one of the following:

- detected and cleaned up automatically within seconds, sometimes detected and cleaned again a few minutes later;
- the same file detected two to four times within minutes, usually cleaned up after the last detection;
- cleanup failed: the file is left for the administrator, cleaned up manually after a median of about 1.5 hours (about a third within the first hour), or detected again minutes later (sometimes with another failure);
- a PUA detection, often followed by a failed PUA cleanup and sometimes by a repeat detection an hour later.

Threat names and file names come from `samples/threats.json`; file paths are built from the endpoint user's profile folders or server folders. All names, addresses (RFC 1918) and identifiers are synthetic.

## Anomaly Chain

With `anomaly_mode: true` (the default), the generator adds a recurring episode on one endpoint:

1. **Detected**: a malware file is detected (`Event::Endpoint::Threat::Detected`).
2. **Cleanup failed**: tens of seconds later, cleanup of the same file fails (`Event::Endpoint::Threat::CleanupFailed`).
3. **Detected again**: several minutes later, the same threat is detected again at the same path.
4. **Cleaned up**: seconds later, the same file is cleaned up (`Event::Endpoint::Threat::CleanedUp`).

**Linking fields**: CEF `dhost` (`host.name`), `threat`/`detection_identity_name` (`sophos_central.event.threat`) and `filePath` (`file.path`); `endpoint_id` and `suser` identify the same endpoint and user. An episode spans about 3-66 minutes (measured) and always stays within two hours.

**Recurrence**: the first episode starts at a random time within the first `anomaly_interval_hours` (default 24, minimum 3) or the first 24 hours, whichever is shorter; its hour of day follows the detection rate, so business hours are more likely than the night. Each next episode starts within a window centred on `anomaly_interval_hours` after the actual start of the previous one; the window is a quarter of the interval wide, at most six hours, and inside it hours with more detections are preferred (squared detection rate plus a small floor). Episodes are scheduled on event time, and a missed episode is not caught up. Measured: 14 episodes in 14 days at the default interval (gaps 21.8-26.8 hours), 41 at 8 hours (gaps 7.1-9.0 hours).

**Variation**: each episode picks another endpoint and another malware threat than the previous one, a file of that threat, and a folder at random. Gaps between the steps are random and drawn from the same distributions as the ordinary incidents. The endpoint keeps its ordinary events during the episode.

**Background**: every step, endpoint, threat and path of the episode also occurs in ordinary traffic in both modes, including cleanup failures, repeat detections of the same file within minutes, repeated failures, detection after a failed cleanup, and manual cleanup after a failure. Only the complete ordered sequence is absent: an ordinary cleanup that would complete Detected, CleanupFailed, Detected, CleanedUp for the same endpoint, threat and file within two hours of the first detection is reported as `CleanupFailed` at the same time. This also applies after an episode, so an ordinary cleanup cannot complete the sequence together with episode events. Any later cleanup of that file inside the same two-hour window is reported the same way; cleanups after the window are not changed. With `anomaly_mode: false` the generator produces this background only.

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

## Sample Output

The failed cleanup of an anomaly episode, copied byte for byte from a default-configuration run (one JSON document per line):

```json
{"@timestamp": "2026-09-01T18:36:13.534Z", "ecs": {"version": "8.11.0"}, "event": {"kind": "event", "dataset": "sophos_central.event", "module": "sophos_central", "category": ["malware"], "type": ["info"], "code": "Event::Endpoint::Threat::CleanupFailed", "action": "Manual cleanup required: 'EICAR-AV-Test' at 'C:\\Users\\vlad.jensen\\Downloads\\eicar_test.txt'", "id": "c07f64f3-61d1-4842-8ce0-4863b2888781", "created": "2026-09-01T18:36:18.439Z", "severity": 8, "original": "CEF:0|sophos|sophos central|1.0|Event::Endpoint::Threat::CleanupFailed|EICAR-AV-Test|8|source_info_ip=10.20.36.54 customer_id=6f1c2a9e-3b7d-4c58-9e21-0d4b8a7f5c13 threat=EICAR-AV-Test endpoint_id=ef81a040-ab4e-4620-8a24-710ab2a116cc endpoint_type=computer group=MALWARE id=c07f64f3-61d1-4842-8ce0-4863b2888781 datastream=event detection_identity_name=EICAR-AV-Test filePath=C:\\\\Users\\\\vlad.jensen\\\\Downloads\\\\eicar_test.txt suser=CONTOSO\\\\vlad.jensen rt=2026-09-01T18:36:18.439Z duid=b7d3b36e2925155c0b4966b7 end=2026-09-01T18:36:13.534Z dhost=WS-HR-285"}, "observer": {"vendor": "Sophos", "product": "Sophos Central"}, "organization": {"id": "6f1c2a9e-3b7d-4c58-9e21-0d4b8a7f5c13"}, "host": {"name": "WS-HR-285", "id": "ef81a040-ab4e-4620-8a24-710ab2a116cc"}, "source": {"ip": "10.20.36.54"}, "related": {"ip": ["10.20.36.54"], "hosts": ["WS-HR-285"], "user": ["vlad.jensen"]}, "sophos_central": {"event": {"type": "Event::Endpoint::Threat::CleanupFailed", "group": "MALWARE", "severity": "high", "source": "CONTOSO\\vlad.jensen", "location": "WS-HR-285", "when": "2026-09-01T18:36:13.534Z", "created_at": "2026-09-01T18:36:18.439Z", "endpoint": {"id": "ef81a040-ab4e-4620-8a24-710ab2a116cc", "type": "computer"}, "datastream": "event", "user_id": "b7d3b36e2925155c0b4966b7", "threat": "EICAR-AV-Test", "detection_identity_name": "EICAR-AV-Test"}}, "user": {"name": "vlad.jensen", "domain": "CONTOSO", "id": "b7d3b36e2925155c0b4966b7"}, "file": {"path": "C:\\Users\\vlad.jensen\\Downloads\\eicar_test.txt", "name": "eicar_test.txt"}}
```

## Format and Limitations

- **CEF construction** follows `siem.py` 2.1.0 and `name_mapping.py`: header `CEF:0|sophos|sophos central|1.0|<type>|<name>|<severity>|`, where threat descriptions of the form `<text>: '<threat>' at '<path>'` are split into `detection_identity_name` and `filePath` and the header name becomes the threat name; API severity is mapped `low` 1, `medium` 5, `high` 8; nested `source_info.ip` is flattened to `source_info_ip`; `source`, `created_at`, `user_id`, `when` and `location` are renamed to `suser`, `rt`, `duid`, `end` and `dhost` and, as the script does, move to the end of the extension; `=` and `\` in values are escaped with a backslash. The script's header version stays `1.0` although the script is 2.1.0.
- **API item**: only fields of the SIEM API event schema are used (`id`, `customer_id`, `severity`, `source`, `source_info`, `location`, `when`, `created_at`, `name`, `type`, `user_id`, `threat`, `group`, `endpoint_type`, `endpoint_id`) plus `datastream`, which the script adds. The key order of the API response is not documented; it follows the order seen in the Elastic `sophos_central` test fixture. Severity is lowercase as in every published example (the schema page lists uppercase values, which `siem.py` would map to 0).
- **Descriptions**: `Manual PUA cleanup required: '<threat>' at '<path>'` is taken from the script's changelog example; the other threat descriptions, `Update succeeded` and the per-type severities and `UserAutoCreated` group are modeled, not copied from a live tenant. No complete raw CEF line from a live tenant was found, so byte parity with production output is established only against the script's code.
- **Time**: `end` is when the endpoint reported the event and `rt` when Central recorded it (seconds later, occasionally tens of minutes for an offline endpoint). `@timestamp` is `end`.
- **Scope**: events endpoint only; no `/siem/v1/alerts` records, no IPS, AMSI, core detection, web control, device control or DLP events, and no `core_remedy_items`, `appCerts` or `whitelist_properties` objects. `convert_dhost_field_to_valid_fqdn` has no effect because every host name is already valid.
- **Transport**: the script prints to stdout, a file or syslog; the shipped file output writes ECS JSON documents instead.

## References

- [Sophos Central SIEM Integration repository](https://github.com/sophos/Sophos-Central-SIEM-Integration)
- [siem.py: CEF format, field mapping, severity map, escaping](https://github.com/sophos/Sophos-Central-SIEM-Integration/blob/master/siem.py)
- [name_mapping.py: threat description split and event types](https://github.com/sophos/Sophos-Central-SIEM-Integration/blob/master/name_mapping.py)
- [CHANGELOG.md: datastream field and a PUA cleanup example](https://github.com/sophos/Sophos-Central-SIEM-Integration/blob/master/CHANGELOG.md)
- [Sophos SIEM API schema reference (event fields and enums)](https://developer.sophos.com/siem-api-schemas/)
- [Elastic sophos_central integration (event data stream)](https://github.com/elastic/integrations/tree/main/packages/sophos_central)

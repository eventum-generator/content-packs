# Dr.Web Enterprise Security Suite generator

Generates ECS JSON modeled on Dr.Web Enterprise Security Suite 13.0.1 administrator notifications. The Dr.Web Server receives station reports and can forward selected notifications to a SIEM over Syslog in RFC 5424, RFC 3164 or CEF format.

## Event types

The `chain` picker repeats a 40-event mix with either mode. At one event every ten minutes, this is 144 notifications per day; these are synthetic demo weights, not measured production frequencies. The linked episodes occur once after startup in anomaly mode. Later cycles use the same seven notification types as background mode without repeating the linked episodes.

| Notification | Events per cycle | Frequency | Category |
|---|---:|---:|---|
| Scan statistics | 23 | 57.5% | Malware |
| Application Control blocked the process | 8 | 20% | Process |
| Security threat detected | 4 | 10% | Malware |
| Critical error of station update | 2 | 5% | Package |
| Report of Preventive protection | 1 | 2.5% | Process |
| Station authorization failed | 1 | 2.5% | Authentication |
| Station already logged in | 1 | 2.5% | Authentication |

The pack uses ten event templates for seven notification types.

## Anomaly Chain

With `anomaly_mode: true`, the first cycle includes two linked episodes:

1. Application Control blocks an executable launch. PowerShell is then allowed to access the protected HOSTS file under Preventive Protection. A scan detects a threat in the blocked executable, and scan statistics record one infected object moved. The four notifications share a station ID; the block and detection share the executable path. A SIEM rule can join them by `drweb.ess.station.id`, then match the block's `MSG.Path` to the detection's `MSG.ObjectName` within a 30-minute window. The allowed HOSTS access is a separate suspicious action, not a reversal of the blocked launch.
2. A station fails authorization and then a connection attempt with the same station ID encounters an already connected station. A SIEM rule can join the pair by `MSG.ID` within ten minutes to flag a possible station identity collision; it does not prove cloning on its own.

With `anomaly_mode: false`, all seven notification types still occur at the same positions, but each file-access notification uses a different station from the preceding Application Control block, and each duplicate-ID notification uses a different ID from the preceding authorization failure. The same independence applies after the first cycle in anomaly mode. Station identities are drawn from 48 fictional endpoints. `event.sequence` is absent because the documented notification variables do not provide a per-station sequence number.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Purpose |
|---|---|---|
| `anomaly_mode` | `true` | Set to `false` to remove the two linked episodes while retaining all notification types |
| `server_name` | `drweb-srv-01.example.test` | Dr.Web Server name |
| `server_id` | `9f0ca284-b95a-4cc8-8338-f253a30ab001` | Dr.Web Server ID in duplicate-station notifications |
| `server_ip` | `10.20.0.10` | Dr.Web Server IP address |
| `server_version` | `13.0.1` | Product version |
| `station_group` | `Workstations` | Primary group in station context |
| `ecs_version` | `8.17.0` | ECS schema version carried by output |

### Output Parameters

The shipped configuration writes to `output/events.json` and requires no top-level `params` or `secrets`. To make the file path overridable, declare a top-level parameter and replace the output path with a substitution:

```yaml
params:
  output_path: output/events.json
output:
  - file:
      path: ${params.output_path}
      write_mode: overwrite
      formatter:
        format: json
```

A backend output can use the same `${params.*}` pattern for its address and `${secrets.*}` for credentials. Keep those substitutions at the top level; `event.template.params` supplies Jinja constants only.

## Usage

Run from the content-packs root:

```bash
# Short batch sample; sample mode runs continuously until stopped.
timeout 2 eventum generate --path generators/security-drweb-ess/generator.yml --id drweb-sample --live-mode false

# Continuous stream, one notification every ten minutes.
eventum generate --path generators/security-drweb-ess/generator.yml --id drweb-live --live-mode true
```

## Sample output

This event was copied from a validation run's `output/events.json`:

```json
{
  "@timestamp": "2026-09-25T20:30:00+00:00",
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "kind": "event",
    "module": "drweb",
    "dataset": "drweb.ess",
    "action": "security-threat-detected",
    "category": [
      "malware"
    ],
    "type": [
      "info"
    ],
    "outcome": "success",
    "severity": 6
  },
  "message": "Trojan.DownLoader detected in C:\\Users\\Public\\Downloads\\invoice.pdf.exe on WS-SALES-06.",
  "observer": {
    "vendor": "Doctor Web",
    "product": "Enterprise Security Suite",
    "version": "13.0.1",
    "hostname": "drweb-srv-01.example.test",
    "ip": [
      "10.20.0.10"
    ]
  },
  "host": {
    "id": "10a56af1-2be3-4381-927f-4d7b1e02c040",
    "name": "WS-SALES-06",
    "hostname": "WS-SALES-06",
    "ip": [
      "10.20.14.106"
    ]
  },
  "user": {
    "name": "user40"
  },
  "related": {
    "hosts": [
      "WS-SALES-06"
    ],
    "ip": [
      "10.20.14.106"
    ],
    "user": [
      "user40"
    ]
  },
  "drweb": {
    "ess": {
      "notification": "Security threat detected",
      "station": {
        "id": "10a56af1-2be3-4381-927f-4d7b1e02c040",
        "name": "WS-SALES-06",
        "ip": "10.20.14.106",
        "primary_group": "Workstations"
      },
      "variables": {
        "MSG.Action": "moved to quarantine",
        "MSG.Component": "Dr.Web Scanner",
        "MSG.InfectionType": "Trojan",
        "MSG.ObjectName": "C:\\Users\\Public\\Downloads\\invoice.pdf.exe",
        "MSG.ObjectOwner": "user40",
        "MSG.RunBy": "user40",
        "MSG.ServerTime": "2026-09-25T20:30:00+00:00",
        "MSG.Virus": "Trojan.DownLoader"
      }
    }
  }
}
```

## Fidelity and references

The event types and `MSG.*` names come from the vendor's notification-template catalog. The Preventive Protection episode uses HOSTS because the vendor identifies it as a protected object. These names are substitution variables for editable notification text, not a documented native Syslog/CEF field map. The output is synthetic normalized ECS JSON, not a captured Dr.Web message or a wire-format emulator. The cited vendor material documents selectable RFC 5424, RFC 3164 and CEF transport but gives no representative raw notification or fixed field mapping. Exact native parsing, emitted values and production notification rates remain unverified. ECS fields, severities and English messages are generator choices. Neighbor-server routing variables and licensed known-hash notifications are outside this single-server profile.

- [Dr.Web ESS 13.0.1 notification types and variables](https://cdn-download.drweb.com/pub/drweb/esuite/13.0.1/documentation/html/en/appendices/app_notifications_templates.htm)
- [Dr.Web ESS 13.0.1 Syslog notification configuration](https://cdn-download.drweb.com/pub/drweb/esuite/13.0.1/documentation/html/en/admin_manual/notifications_configure.htm)
- [Dr.Web ESS 13.0.1 Behavior Analysis protected objects](https://cdn-download.drweb.com/pub/drweb/esuite/13.0.1/documentation/html/ru/user_manual_agent/preventive_behavior.html)
- [Dr.Web ESS 13.0.1 release notes](https://st.drweb.com/static/new-www/news/2023/may/drweb-13.0-esuite-release-notes-en.pdf)

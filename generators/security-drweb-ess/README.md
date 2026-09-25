# Dr.Web Enterprise Security Suite generator

Generates ECS JSON modeled on Dr.Web Enterprise Security Suite 13.0.1 administrator notifications. The Dr.Web Server receives station reports and can forward selected notifications to a SIEM over Syslog in RFC 5424, RFC 3164 or CEF format.

## Event types

The `chain` picker repeats a 40-event cycle with `anomaly_mode: true`. These proportions make both detection scenarios appear in a short sample; they are synthetic demo weights, not measured production frequencies.

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

With `anomaly_mode: true`, one cycle includes two linked episodes:

1. Application Control blocks an object, a user allows suspicious access to the same object in Preventive protection, a scan detects the threat in that object, and scan statistics record one infected object moved. The four notifications share a station ID. The first three also share the object path. A SIEM rule can join them by `drweb.ess.station.id`, then match `MSG.Path`, `MSG.Target` and `MSG.ObjectName` within a short window.
2. A station fails authorization and then a connection attempt with the same station ID encounters an already connected station. A SIEM rule can join the pair by `MSG.ID` within a short window to flag a possible station identity collision; it does not prove cloning on its own.

With `anomaly_mode: false`, special positions emit independent scan statistics. Only ordinary scans, blocks, threats and update failures remain; neither linked episode is generated. Station identities are drawn from 48 fictional endpoints. `event.sequence` is absent because the documented notification variables do not provide a per-station sequence number.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Purpose |
|---|---|---|
| `anomaly_mode` | `true` | Set to `false` for independent background notifications only |
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
timeout 3 eventum generate --path generators/security-drweb-ess/generator.yml --id drweb-sample --live-mode false

# Continuous 5 events/second stream.
eventum generate --path generators/security-drweb-ess/generator.yml --id drweb-live --live-mode true
```

## Sample output

This event was copied from a validation run's `output/events.json`:

```json
{
  "@timestamp": "2026-09-25T10:24:58+00:00",
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
    "severity": 7
  },
  "message": "Exploit.CVE detected in C:\\Users\\Public\\Documents\\macro_template.docm on WS-HR-02.",
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
    "id": "10a56af1-2be3-4381-927f-4d7b1e02c004",
    "name": "WS-HR-02",
    "hostname": "WS-HR-02",
    "ip": [
      "10.20.11.32"
    ]
  },
  "user": {
    "name": "d.kuznetsov"
  },
  "related": {
    "hosts": [
      "WS-HR-02"
    ],
    "ip": [
      "10.20.11.32"
    ],
    "user": [
      "d.kuznetsov"
    ]
  },
  "drweb": {
    "ess": {
      "notification": "Security threat detected",
      "station": {
        "id": "10a56af1-2be3-4381-927f-4d7b1e02c004",
        "name": "WS-HR-02",
        "ip": "10.20.11.32",
        "primary_group": "Workstations"
      },
      "variables": {
        "MSG.Action": "moved to quarantine",
        "MSG.Component": "Dr.Web Scanner",
        "MSG.InfectionType": "Exploit",
        "MSG.ObjectName": "C:\\Users\\Public\\Documents\\macro_template.docm",
        "MSG.ObjectOwner": "d.kuznetsov",
        "MSG.RunBy": "d.kuznetsov",
        "MSG.ServerTime": "2026-09-25T10:24:58+00:00",
        "MSG.Virus": "Exploit.CVE"
      }
    }
  }
}
```

## Fidelity and references

The event types and `MSG.*` variables follow the vendor's notification catalog. The output is normalized ECS JSON, not a captured Dr.Web CEF message or an exact wire-format emulator. The vendor documents selectable Syslog/CEF transport and editable notification text, but does not publish a fixed CEF field map or representative CEF event in the cited material. No product-specific Elastic integration sample was found, so field coverage was checked against the applicable vendor variables instead: 54/54 fields across the seven notification types. Neighbor-server routing variables and licensed known-hash notifications are outside this single-server profile.

- [Dr.Web ESS 13.0.1 notification types and variables](https://cdn-download.drweb.com/pub/drweb/esuite/13.0.1/documentation/html/en/appendices/app_notifications_templates.htm)
- [Dr.Web ESS 13.0.1 Syslog notification configuration](https://cdn-download.drweb.com/pub/drweb/esuite/13.0.1/documentation/html/en/admin_manual/notifications_configure.htm)
- [Dr.Web ESS 13.0.1 release notes](https://st.drweb.com/static/new-www/news/2023/may/drweb-13.0-esuite-release-notes-en.pdf)

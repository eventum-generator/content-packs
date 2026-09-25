# Windows Service Control Manager System XML

Synthetic Windows `System` channel XML from the `Service Control Manager` provider for service-state, installation and start-type correlation.

## Event types

| Event ID | Native meaning | Approximate frequency | ECS category/type |
| --- | --- | --- | --- |
| 7036 | Service entered `running` or `stopped` state | 96% | `configuration` / `start` or `end` |
| 7045 | Service installed | 2% | `configuration` / `change` |
| 7040 | Service start type changed | 2% | `configuration` / `change` |

Each event retains complete Event Viewer XML in `event.original` and parsed fields under `winlog.*`. The generator models six routine endpoints, including the two that also participate in the correlated series. EventRecordID increases per host.

## Anomaly Chain

With `anomaly_mode: true` (the default), the same `ContosoTelemetry` service is installed on two endpoints from a `C:\ProgramData` executable, changed from `demand start` to `auto start` and then observed entering the `running` state on each host. The six events are `7045 → 7040 → 7036` on `chain_host_a`, followed by the same sequence on `chain_host_b`. Correlate the service name and image path across hosts, then check start-type and state transitions within 10 seconds. The validated one-second cadence produced a five-second span from the first to last event. Sort by `@timestamp` before sequence analysis because output lines may be interleaved.

With `anomaly_mode: false`, ordinary service-state changes and independent installation/configuration pairs continue. `ContosoTelemetry` appears in 7036, 7045 and 7040 on both series hosts, with the same image path; only the rapid six-step cross-host sequence disappears. In the validated 10-second rule, the anomaly run had nine complete matches and the background run had none, even though each had ordinary three-step same-host matches. The SCM XML contains no reliable remote operator identity, so the chain does not attribute the installations to one user.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Purpose |
| --- | --- | --- |
| `anomaly_mode` | `true` | Include the six-event cross-host series |
| `anomaly_interval_events` | `20` | Routine install/config pairs between series |
| `chain_host_a` | `WS-FIN-01.corp.example.test` | First series endpoint |
| `chain_host_b` | `WS-OPS-02.corp.example.test` | Second series endpoint |
| `chain_service_name` | `ContosoTelemetry` | Shared service name |
| `chain_image_path` | `C:\ProgramData\Contoso\telemetry-svc.exe` | Shared service binary path |

### Output Parameters

The supplied config writes ECS JSON Lines to `output/events.json`; it has no top-level `params` or `secrets`. To send the events to a SIEM, replace `output.file` with the chosen output plugin and configure its `${params.*}` and `${secrets.*}` values. Forward `event.original` when the receiver expects Windows Event XML.

## Usage

Run from the content-packs repository root:

```bash
eventum generate --path generators/windows-service-control-manager/generator.yml --id scm --live-mode false
eventum generate --path generators/windows-service-control-manager/generator.yml --id scm-live --live-mode true
```

Set `anomaly_mode: false` in `generator.yml` for background-only output.

## Sample output event

This service installation event was copied from an anomaly-mode run:

```json
{
  "@timestamp": "2026-09-25T14:59:36+00:00",
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "service-installed",
    "category": [
      "configuration"
    ],
    "code": "7045",
    "dataset": "windows.service_control_manager",
    "kind": "event",
    "original": "<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"><System><Provider Name=\"Service Control Manager\" Guid=\"{555908d1-a6d7-4695-8e1e-26931d2012f4}\" EventSourceName=\"Service Control Manager\" /><EventID Qualifiers=\"16384\">7045</EventID><Version>0</Version><Level>4</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x8080000000000000</Keywords><TimeCreated SystemTime=\"2026-09-25T14:59:36Z\" /><EventRecordID>1038</EventRecordID><Correlation /><Execution ProcessID=\"738\" ThreadID=\"1138\" /><Channel>System</Channel><Computer>WS-FIN-01.corp.example.test</Computer><Security UserID=\"S-1-5-18\" /></System><EventData><Data Name=\"ServiceName\">ContosoTelemetry</Data><Data Name=\"ImagePath\">C:\\ProgramData\\Contoso\\telemetry-svc.exe</Data><Data Name=\"ServiceType\">user mode service</Data><Data Name=\"StartType\">demand start</Data><Data Name=\"AccountName\">LocalSystem</Data></EventData></Event>",
    "provider": "Service Control Manager",
    "type": [
      "change"
    ]
  },
  "file": {
    "path": "C:\\ProgramData\\Contoso\\telemetry-svc.exe"
  },
  "host": {
    "name": "WS-FIN-01.corp.example.test",
    "os": {
      "family": "windows",
      "type": "windows"
    }
  },
  "log": {
    "level": "information"
  },
  "related": {
    "hosts": [
      "WS-FIN-01.corp.example.test"
    ]
  },
  "service": {
    "name": "ContosoTelemetry"
  },
  "user": {
    "id": "S-1-5-18"
  },
  "windows": {
    "service_control_manager": {
      "start_type": "demand start"
    }
  },
  "winlog": {
    "channel": "System",
    "computer_name": "WS-FIN-01.corp.example.test",
    "event_data": {
      "AccountName": "LocalSystem",
      "ImagePath": "C:\\ProgramData\\Contoso\\telemetry-svc.exe",
      "ServiceName": "ContosoTelemetry",
      "ServiceType": "user mode service",
      "StartType": "demand start"
    },
    "event_id": 7045,
    "keywords": [
      "Classic"
    ],
    "level": "information",
    "provider_guid": "{555908d1-a6d7-4695-8e1e-26931d2012f4}",
    "provider_name": "Service Control Manager",
    "record_id": 1038,
    "time_created": "2026-09-25T14:59:36+00:00"
  }
}
```

## Format and coverage

The generated XML preserves every payload position in the selected complete Event Viewer examples: `7036` has `param1`, `param2` and the UTF-16LE service/state `Binary` (3/3); `7040` has `param1` through `param4` (4/4); `7045` has `ServiceName`, `ImagePath`, `ServiceType`, `StartType` and `AccountName` (5/5). The common `System` envelope includes the SCM provider GUID, `System` channel, EventID qualifier, record ID, computer and time. The XML is parsed and checked for every generated event.

This is a separate stream from Security-channel 4697 in `windows-security`: 4697 uses provider `Microsoft-Windows-Security-Auditing` and carries a different payload, while 7045 is a `Service Control Manager` event in `System`. The XML profile is based on Microsoft-hosted Event Viewer exports from different Windows releases and a newer vendor collector example for 7036; compatibility of every field with each current Windows build is unverified. Other SCM IDs, localized state strings, driver service variants and transport wrappers are outside scope.

## References

- [Microsoft Security: StilachiRAT analysis](https://www.microsoft.com/en-us/security/blog/2025/03/17/stilachirat-analysis-from-system-reconnaissance-to-cryptocurrency-theft/) - identifies System/SCM 7045 and 7040 as service-persistence signals.
- [Microsoft: troubleshoot unexpected reboots](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs) - 7045 field meanings.
- [Microsoft Learn Q&A: 7045 Event Viewer XML](https://learn.microsoft.com/en-us/answers/questions/2798711/need-help-pc-keeps-freezing?page=2) - user-supplied complete XML export.
- [Microsoft Learn Q&A: 7040 Event Viewer XML](https://learn.microsoft.com/en-us/answers/questions/3270425/something-keeps-enabling-remote-registry?page=2) - user-supplied complete XML export.
- [Microsoft Learn Q&A: 7036 Event Viewer XML](https://learn.microsoft.com/en-us/answers/questions/2430070/system-wakes-itself-up-when-put-to-sleep-or-hibern) - user-supplied complete XML export and binary shape.
- [Fortinet FortiSIEM Windows agent sample](https://docs.fortinet.com/document/fortisiem/7.2.6/user-guide/229261/sample-windows-agent-logs) - later full 7036 XML example.
- [Microsoft: Security 4697](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4697) - distinct Security-channel service installation audit.
- [KUMA 4.2 supported data sources](https://support.kaspersky.ru/kuma/4.2/255782) - Service Control Manager System XML normalizer.

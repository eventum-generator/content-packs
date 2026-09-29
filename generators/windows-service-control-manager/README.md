# Windows Service Control Manager

Selected System-channel service events from 18 workstations and six servers, represented as ECS JSON with rendered native XML in `event.original`. The profile covers service runs, start-type changes, installation and unexpected termination.

## Event types

About 7,500 records/day represent a synthetic Windows fleet. Activity rises from about 88 records/hour outside 07:00–21:00 UTC to 473 records/hour during that window. Workstations are less active at night; servers continue throughout the day.

| Event ID | Meaning | Approximate share |
| --- | --- | ---: |
| 7036 | Service running or stopped | 88.7% |
| 7040 | Start type changed | 9.4% |
| 7045 | Service installed | 1.7% |
| 7034 | Unexpected termination | 0.2% |

Nineteen Windows services and eight third-party services share a fixed fleet. Four administrators each maintain a subset of hosts and service packages; SYSTEM also performs ordinary deployment. Service runs end with a stop, or occasionally an unexpected termination. Temporary automatic-start changes usually return to demand start within about 5–18 minutes; another configuration change may return them sooner. Restoration timing is the same for ordinary work and correlated episodes.

Deployments install one service on several hosts over minutes or hours. Only one deployment of a given package is active across the fleet at a time. Another deployment waits at least 30 minutes after its last installation. Deployment targets have stopped services; pending installations reserve their target until installation. Reinstallation assumes the previous stopped instance has been removed. Each installation may be followed by a change to automatic start and a service run. Host names, administrator SIDs, service image paths and these individual actions occur in ordinary work in both modes. System-channel record numbers increase per host with gaps for other System-channel events.

## Anomaly Chain

With `anomaly_mode: true`, one administrator installs the same service image on two hosts. On each host, installation (7045) is followed by automatic-start configuration (7040) and the running state (7036). All six steps occur within 30 minutes. Service display name, image path, administrator SID and host names join the records.

The first episode starts within `min(interval,24 hours)`, weighted by daily activity. Subsequent starts fall within half of `min(interval/4,6 hours)` around the preceding actual start plus the interval, with stronger preference for busy hours. The administrator, service and two hosts change between episodes. Default recurrence is 24 hours. Ordinary runs continue during episodes, and missed historical episodes are not replayed.

With `anomaly_mode: false`, the complete six-step sequence is absent. The individual actions and administrator/host and administrator/service pairs remain in ordinary work. Episode services later stop or terminate like ordinary runs, and temporary automatic-start settings return to demand start. The selected SCM feed has no service-deletion record; removals between package deployments are not visible.

## Parameters

Edit `event.template.params` in `generator.yml`.

| Parameter | Default | Meaning |
| --- | --- | --- |
| `anomaly_mode` | `true` | Include recurring correlated service deployments |
| `anomaly_interval_hours` | `24` | Episode interval in hours, from 2 to 8760 |
| `dns_domain` | `corp.contoso.com` | Hostname DNS suffix |
| `ad_domain` | `CONTOSO` | Administrator account domain |

Fleet names, service packages and administrator names are in `samples/`. All values are synthetic; no credentials are required.

## Usage

From the content-packs root:

```bash
eventum generate --path generators/windows-service-control-manager/generator.yml --id scm --live-mode true --keep-order true
```

For a finite batch, copy the directory, set both `patterns/*.yml` oscillator start/end to UTC midnight boundaries, and run the copy with `--live-mode false --keep-order true`. Output defaults to `output/events.json`. Pattern ratios and office-hour ranges control volume and schedule.

## Source fidelity and limitations

Only 7036, 7034, 7040 and 7045 are represented, in English rendering. Other SCM events, driver installations, failed start requests and recovery actions are omitted. Fleet size, rates and deployment frequency are synthetic workload assumptions.

XML fields and order follow saved Event Viewer exports and the FortiSIEM rendered 7036 sample. Exact whitespace of the rendered 7045 message is not established. A service key appears in 7040 and Binary fields; 7045 carries its display name. The ECS envelope follows selected Winlogbeat System fields and omits collector/ingest metadata. A live downstream parser has not been exercised.

## Sample output

One complete synthetic service-installation event:

```json
{"@timestamp": "2026-09-21T01:30:58.391Z", "ecs": {"version": "8.11.0"}, "event": {"code": "7045", "dataset": "system.system", "kind": "event", "original": "\u003cEvent xmlns=\u0027http://schemas.microsoft.com/win/2004/08/events/event\u0027\u003e\u003cSystem\u003e\u003cProvider Name=\u0027Service Control Manager\u0027 Guid=\u0027{555908d1-a6d7-4695-8e1e-26931d2012f4}\u0027 EventSourceName=\u0027Service Control Manager\u0027/\u003e\u003cEventID Qualifiers=\u002716384\u0027\u003e7045\u003c/EventID\u003e\u003cVersion\u003e0\u003c/Version\u003e\u003cLevel\u003e4\u003c/Level\u003e\u003cTask\u003e0\u003c/Task\u003e\u003cOpcode\u003e0\u003c/Opcode\u003e\u003cKeywords\u003e0x8080000000000000\u003c/Keywords\u003e\u003cTimeCreated SystemTime=\u00272026-09-21T01:30:58.391607000Z\u0027/\u003e\u003cEventRecordID\u003e433609\u003c/EventRecordID\u003e\u003cCorrelation/\u003e\u003cExecution ProcessID=\u0027880\u0027 ThreadID=\u00273632\u0027/\u003e\u003cChannel\u003eSystem\u003c/Channel\u003e\u003cComputer\u003eWS-HR-01.corp.contoso.com\u003c/Computer\u003e\u003cSecurity UserID=\u0027S-1-5-18\u0027/\u003e\u003c/System\u003e\u003cEventData\u003e\u003cData Name=\u0027ServiceName\u0027\u003eLitware Remote Support\u003c/Data\u003e\u003cData Name=\u0027ImagePath\u0027\u003eC:\\ProgramData\\Litware\\lrsvc.exe\u003c/Data\u003e\u003cData Name=\u0027ServiceType\u0027\u003euser mode service\u003c/Data\u003e\u003cData Name=\u0027StartType\u0027\u003edemand start\u003c/Data\u003e\u003cData Name=\u0027AccountName\u0027\u003eLocalSystem\u003c/Data\u003e\u003c/EventData\u003e\u003cRenderingInfo Culture=\u0027en-US\u0027\u003e\u003cMessage\u003eA service was installed in the system.\n\nService Name:  Litware Remote Support\nService File Name:  C:\\ProgramData\\Litware\\lrsvc.exe\nService Type:  user mode service\nService Start Type:  demand start\nService Account:  LocalSystem\u003c/Message\u003e\u003cLevel\u003eInformation\u003c/Level\u003e\u003cTask\u003e\u003c/Task\u003e\u003cOpcode\u003e\u003c/Opcode\u003e\u003cChannel\u003e\u003c/Channel\u003e\u003cProvider\u003eMicrosoft-Windows-Service Control Manager\u003c/Provider\u003e\u003cKeywords\u003e\u003cKeyword\u003eClassic\u003c/Keyword\u003e\u003c/Keywords\u003e\u003c/RenderingInfo\u003e\u003c/Event\u003e", "provider": "Service Control Manager"}, "host": {"name": "WS-HR-01.corp.contoso.com"}, "log": {"level": "information"}, "message": "A service was installed in the system.\n\nService Name:  Litware Remote Support\nService File Name:  C:\\ProgramData\\Litware\\lrsvc.exe\nService Type:  user mode service\nService Start Type:  demand start\nService Account:  LocalSystem", "winlog": {"api": "wineventlog", "channel": "System", "computer_name": "WS-HR-01.corp.contoso.com", "event_data": {"AccountName": "LocalSystem", "ImagePath": "C:\\ProgramData\\Litware\\lrsvc.exe", "ServiceName": "Litware Remote Support", "ServiceType": "user mode service", "StartType": "demand start"}, "event_id": "7045", "keywords": ["Classic"], "opcode": "Info", "process": {"pid": 880, "thread": {"id": 3632}}, "provider_guid": "{555908d1-a6d7-4695-8e1e-26931d2012f4}", "provider_name": "Service Control Manager", "record_id": "433609", "user": {"domain": "NT AUTHORITY", "identifier": "S-1-5-18", "name": "SYSTEM", "type": "Well Known Group"}}}
```

## References

- [Microsoft Learn Q&A: 7045 and 7034 Event Viewer XML](https://learn.microsoft.com/en-us/answers/questions/2798711/need-help-pc-keeps-freezing?page=2) - complete exports, installing user's SID in 7045, empty `Security` and key-name `Binary` in 7034.
- [Microsoft Learn Q&A: 7040 Event Viewer XML](https://learn.microsoft.com/en-us/answers/questions/3270425/something-keeps-enabling-remote-registry?page=2) - complete export, display name in `param1`, key name in `param4`.
- [Microsoft Learn Q&A: 7036 Event Viewer XML](https://learn.microsoft.com/en-us/answers/questions/2430070/system-wakes-itself-up-when-put-to-sleep-or-hibern) - complete exports and the `Binary` layout (key name, `/4` or `/1`).
- [Fortinet FortiSIEM Windows agent sample](https://docs.fortinet.com/document/fortisiem/7.2.6/user-guide/229261/sample-windows-agent-logs) - rendered 7036 XML with `RenderingInfo`.
- [Microsoft: troubleshoot unexpected reboots](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs) - 7045 field meanings.
- [Elastic integrations: system data stream fields](https://github.com/elastic/integrations/blob/main/packages/system/data_stream/system/fields/winlog.yml) - `winlog.*` projection.
- [Microsoft Security: StilachiRAT analysis](https://www.microsoft.com/en-us/security/blog/2025/03/17/stilachirat-analysis-from-system-reconnaissance-to-cryptocurrency-theft/) - 7045 and 7040 as service-persistence signals.
- [MITRE ATT&CK T1543.003](https://attack.mitre.org/techniques/T1543/003/) - Create or Modify System Process: Windows Service.

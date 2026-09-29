# Windows Group Policy Operational

Synthetic `Microsoft-Windows-GroupPolicy/Operational` events from a fleet of 1,000 domain members (800 workstations, 200 servers), for SIEM content that watches whether Group Policy - and security policy in particular - is actually applied. Each event is Winlogbeat-style ECS JSON with the native Event XML in `event.original`.

The generator models computer policy refreshes (periodic and manual `gpupdate`) and the client-side extension (CSE) processing inside them. Every host runs its own refresh schedule; each refresh has one Activity ID shared by all of its events.

## Event Types

Shares measured over 14 days with the default configuration (`anomaly_mode: true`), 561,350 events.

| Event ID | Level | Message (manifest) | Share | ECS category / type |
| --- | --- | --- | --- | --- |
| 4006 | Information | Starting periodic policy processing for computer `<account>`. Activity id: `<GUID>` | 19.40% | configuration / info |
| 8006 | Information | Completed periodic policy processing for computer `<account>` in `<n>` seconds. | 19.39% | configuration / change |
| 7006 | Error | Periodic policy processing failed for computer `<account>` in `<n>` seconds. | 0.012% | configuration / info |
| 4004 | Information | Starting manual processing of policy for computer `<account>`. Activity id: `<GUID>` | 0.17% | configuration / info |
| 8004 | Information | Completed manual processing of policy for computer `<account>` in `<n>` seconds. | 0.17% | configuration / change |
| 7004 | Error | Manual processing of policy failed for computer `<account>` in `<n>` seconds. | 0.001% | configuration / info |
| 4016 | Information | Starting `<CSE>` Extension Processing. List of applicable Group Policy objects: (No changes were detected.) `<GPO names>` | 30.43% | configuration / info |
| 5016 | Information | Completed `<CSE>` Extension Processing in `<n>` milliseconds. | 30.42% | configuration / change |
| 7016 | Error | Completed `<CSE>` Extension Processing in `<n>` milliseconds. | 0.013% | configuration / info |

## Volume and Daily Curve

About 40,000 events a day (+/- 3% from day to day), with a working-day curve in the generator timezone (UTC by default):

- Servers (200) and the 120 workstations left on overnight produce about 900 events an hour around the clock.
- The other 680 workstations are switched on between about 07:25 and 08:35 and shut down between about 17:20 and 18:40, a little differently every day. Their first periodic refresh comes 90-120 minutes after start-up, so from 09:00 to 18:00 the volume rises to about 2,950 events an hour.
- A workstation gets a new Group Policy service process ID at every start-up; its `EventRecordID` keeps counting.

## Background Behaviour

Per host:

- Periodic refresh every 90 minutes plus a random 0-30 minute offset (the Windows default); intervals have a median of 104-112 minutes; about one in ten is shorter than 90 minutes (down to about 70) and about one in twenty longer than two hours (up to about 150), and there are no refreshes while a workstation is switched off.
- Each refresh runs the extensions of the host's GPOs that have work: Registry, Security, Audit Policy Configuration, Group Policy Registry, Group Policy Folders, Group Policy Scheduled Tasks, EFS recovery. Registry runs first, the rest in extension-GUID order. A manual refresh runs all of them. A refresh is 5.1 events on average.
- Audit Policy Configuration completes with `ErrorCode` 2147483658 (E_PENDING), which Microsoft documents as expected.

Fleet-wide:

- Administrators run `gpupdate` on hosts that are on about 60 times a day, mostly between 09:00 and 18:00; one run in five is repeated within minutes.
- Security extension errors (7016, `ErrorCode` 1252) come in short spells, about three errors a day in total: one host fails once (65%) or twice (35%) before the fault clears, or one shared cause breaks the next Security run of two hosts that apply the same Security-bearing GPO. The Security run after the spell succeeds. A failed refresh ends with 7006/7004 and is often followed within minutes by a manual `gpupdate`.
- Background never holds Security errors on three distinct hosts within 6 hours.

## Anomaly Chain

A change to one Security-bearing GPO (Default Domain Policy, Workstation Security Baseline or Server Security Baseline) breaks the security settings on the computers that apply it. The security baseline - user rights, audit policy, restricted groups - silently stops being enforced there.

Sequence, per episode:

1. Three hosts that apply the changed GPO and are on fail at the next Security extension run of their own refresh schedule: the Security extension starts (4016) and ends in error (7016, `ErrorCode` 1252); the refresh ends with 7006, or 7004 when it is a manual `gpupdate`.
2. An administrator may rerun `gpupdate` on a failed host within minutes, as in the background.
3. The next Security run of each failed host succeeds (5016, `ErrorCode` 0): the fault is fixed and the restored state is visible.

The chain is complete at the first episode error that has errors of two other hosts within the 6 hours before it. When background errors of other hosts shortly precede an episode, that is its first or second host, and the episode's remaining hosts keep working settings. Each episode therefore completes exactly one chain. Episode errors occur inside the hosts' ordinary scheduled refreshes: an episode adds no refresh and moves none.

Linking fields: `winlog.event_data.CSEExtensionId` `{827D319E-6EAC-11D2-A4EA-00C04F79F83A}` (Security), `host.name`, and `winlog.activity_id`, which ties each 7016 to the 4016 that lists the applicable GPOs (`winlog.event_data.DescriptionString`, `ApplicableGPOList`) and to the refresh start/end.

Recurrence: one episode every `anomaly_interval_hours` (default 24, minimum 12) of source time. The first starts within min(interval, 24 h) of the beginning; each later one within a window of min(interval / 4, 6 h) centred one interval after the previous start. The first start hour follows the daily curve, favouring working hours; later episodes stay within about three hours of the previous start, so a first start at night keeps the following ones near night hours. Missed episodes are not replayed. The hosts change every episode; hosts of the previous episode are excluded. The chain usually completes within two hours of the start, depending on the hosts' next refreshes.

Detection idea: Security extension errors (7016, Security `CSEExtensionId`) on three or more distinct hosts within 6 hours, each preceded in the same Activity ID by a 4016 listing a common GPO - a fleet-level failure that points to a GPO change rather than a single broken host. Pair it with the GPO modification audit (Security 5136) on the domain controllers.

The chain is not recognisable from any single event: every event type, error code, host, GPO and the pattern "two hosts fail, then recover" occur in ordinary background of both modes. Only the third distinct host within the window is withheld from background.

`anomaly_mode` defaults to `true`. With `false` the generator produces the same background without episodes.

## Parameters

### Event Parameters

| Parameter | Default | Description |
| --- | --- | --- |
| `anomaly_mode` | `true` | Mix recurring anomaly episodes into the background; `false` emits background only. |
| `anomaly_interval_hours` | `24` | Hours of source time between episode starts; 12 to 8760. |

Hosts (`samples/hosts.json`: FQDN, SAM account, role) and GPOs (`samples/gpos.json`: GUID, name, scope, extensions) are sample files; edit them to match a lab domain. The daily volume and its curve are set in `patterns/` (`servers.yml`, `workstations-left-on.yml`, `workstations-office-hours.yml`); scale their `ratio` values together with the number of hosts.

### Output Parameters

The shipped `generator.yml` writes to `output/events.json` and needs no parameters. To send events to a backend, replace the `output` block and keep credentials in Eventum secrets, for example:

```yaml
output:
  - opensearch:
      hosts:
        - ${params.opensearch_host}
      username: ${params.opensearch_user}
      password: ${secrets.opensearch_password}
      index: logs-windows.group_policy
```

## Usage

```bash
# Live mode
eventum generate --path generators/windows-group-policy-operational/generator.yml --id gpo --live-mode true

# Batch mode over a fixed window
eventum generate --path generators/windows-group-policy-operational/generator.yml --id gpo --live-mode false
```

The three files in `patterns/` start at today's midnight and never end. For a finite batch window, set `oscillator.start` to a midnight (for example `"2026-09-01T00:00:00+00:00"`) and `oscillator.end` (for example `"+72h"`) in all three files; a start at midnight keeps the working-day hours in place.

Performance: about 1,800 events per second in batch mode (14 days, 561,350 events, in 5.1 minutes).

## Sample Output

The Security error that completes the first episode, copied from a default capture:

```json
{"@timestamp": "2026-09-01T20:16:30.552Z", "ecs": {"version": "8.17.0"}, "event": {"action": "cse-processing-failed", "category": ["configuration"], "code": "7016", "kind": "event", "original": "\u003cEvent xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"\u003e\u003cSystem\u003e\u003cProvider Name=\"Microsoft-Windows-GroupPolicy\" Guid=\"{AEA1B4FA-97D1-45F2-A64C-4D69FFFD92C9}\"/\u003e\u003cEventID\u003e7016\u003c/EventID\u003e\u003cVersion\u003e0\u003c/Version\u003e\u003cLevel\u003e2\u003c/Level\u003e\u003cTask\u003e0\u003c/Task\u003e\u003cOpcode\u003e2\u003c/Opcode\u003e\u003cKeywords\u003e0x4000000000000000\u003c/Keywords\u003e\u003cTimeCreated SystemTime=\"2026-09-01T20:16:30.5526290Z\"/\u003e\u003cEventRecordID\u003e124365\u003c/EventRecordID\u003e\u003cCorrelation ActivityID=\"{EBC0C866-9163-41BD-BDD1-215F596AF73B}\"/\u003e\u003cExecution ProcessID=\"6804\" ThreadID=\"10936\"/\u003e\u003cChannel\u003eMicrosoft-Windows-GroupPolicy/Operational\u003c/Channel\u003e\u003cComputer\u003esrv-rds06.corp.contoso.com\u003c/Computer\u003e\u003cSecurity UserID=\"S-1-5-18\"/\u003e\u003c/System\u003e\u003cEventData\u003e\u003cData Name=\"CSEElaspedTimeInMilliSeconds\"\u003e3024\u003c/Data\u003e\u003cData Name=\"ErrorCode\"\u003e1252\u003c/Data\u003e\u003cData Name=\"CSEExtensionName\"\u003eSecurity\u003c/Data\u003e\u003cData Name=\"CSEExtensionId\"\u003e{827D319E-6EAC-11D2-A4EA-00C04F79F83A}\u003c/Data\u003e\u003c/EventData\u003e\u003c/Event\u003e", "outcome": "failure", "provider": "Microsoft-Windows-GroupPolicy", "type": ["info"]}, "host": {"name": "srv-rds06.corp.contoso.com"}, "log": {"level": "error"}, "message": "Completed Security Extension Processing in 3024 milliseconds.", "winlog": {"activity_id": "{EBC0C866-9163-41BD-BDD1-215F596AF73B}", "channel": "Microsoft-Windows-GroupPolicy/Operational", "computer_name": "srv-rds06.corp.contoso.com", "event_data": {"CSEElaspedTimeInMilliSeconds": "3024", "CSEExtensionId": "{827D319E-6EAC-11D2-A4EA-00C04F79F83A}", "CSEExtensionName": "Security", "ErrorCode": "1252"}, "event_id": "7016", "opcode": "Stop", "process": {"pid": 6804, "thread": {"id": 10936}}, "provider_guid": "{AEA1B4FA-97D1-45F2-A64C-4D69FFFD92C9}", "provider_name": "Microsoft-Windows-GroupPolicy", "record_id": "124365", "user": {"identifier": "S-1-5-18"}, "version": 0}}
```

## Format Notes and Limitations

- Field names, types, versions, levels, opcodes and message texts follow the Microsoft-Windows-GroupPolicy manifest of Windows Server 2022 (gpsvc.dll 10.0.20348). The System block, `Keywords` 0x4000000000000000, the `Correlation ActivityID`, the 4016 EventData layout and the decimal `ErrorCode` rendering follow Microsoft's published Event XML of 4016 and 7016.
- Inferred, not quoted from a raw record: Version 1 for 4004/4006/8004/8006/7004/7006 (the newer of the two manifest versions), the values of `IsBackgroundProcessing`, `IsAsyncProcessing` and `ReasonForSyncProcessing`, the concatenation of several GPOs in `ApplicableGPOList`, and a failed refresh ending with 7006/7004 carrying the extension's error code. Extension GUIDs other than Security and Group Policy Folders are the Windows `GPExtensions` registrations.
- `GPOListStatusString` is always `%%4101` ("No changes were detected.") with `IsGPOListChanged` false: no rendering of the other values was found.
- Only computer policy and these nine event IDs are modelled. Other Operational events of a refresh (5340, 5326, 5312, 5313, 4017/5017, ...) are not emitted; they appear as gaps in `EventRecordID`. User logon policy, boot and start-up policy processing, scripts and connectivity failures are out of scope.
- Events of one refresh are further apart than on a real host: consecutive events of a refresh are a median 1.8 s apart between 09:00 and 18:00 and 4.4 s at night, so a refresh takes a median 15 s by day and 27 s at night, and extension run times (`CSEElaspedTimeInMilliSeconds`, which matches the event times) are mostly 1-2 s (Security about 4 s) instead of the tens of milliseconds in Microsoft's examples.
- Security errors always carry `ErrorCode` 1252, the code in Microsoft's examples; other CSE failures are not modelled. Failed refreshes are about 0.07% of refreshes, as in a healthy domain.
- With `anomaly_mode: true` each episode adds its own Security errors (one to three), so on a day with an episode 7016 and 7006/7004 counts are one to three higher than without episodes.
- Every day follows the same working-day curve; weekends and holidays are not distinguished. Hourly volume changes in steps at 09:00 and 18:00 rather than following each workstation's start-up and shutdown time.
- Rates, extension run shares, durations and the fleet are synthetic. `TimeCreated` has seven fractional digits as on current Windows builds; `@timestamp` is milliseconds.
- `event.category`, `event.type`, `event.action` and `event.outcome` are ECS normalisation, not native fields.

## References

- [Microsoft-Windows-GroupPolicy manifest, Windows Server 2022 20348 (nasbench/EVTX-ETW-Resources)](https://github.com/nasbench/EVTX-ETW-Resources/blob/main/ETWProvidersManifests/WindowsServer/2022/WindowsServer2022_21H2_Standard_20230321_20348.1607/WEPExplorer/Microsoft-Windows-GroupPolicy.xml)
- [Microsoft: Applying Group Policy troubleshooting guidance (Activity ID, 4016/5016)](https://learn.microsoft.com/en-us/troubleshoot/windows-server/group-policy/applying-group-policy-troubleshooting-guidance)
- [Microsoft: Group Policy error events 7016, 1091, 1202 (Security CSE, ErrorCode 1252)](https://learn.microsoft.com/en-us/troubleshoot/windows-server/group-policy/group-policy-error-7016-1091-1202)
- [Microsoft AskDS: Troubleshooting Event ID 1085 and 7016 (full 7016 XML)](https://learn.microsoft.com/en-us/archive/blogs/askds/a-test-case-for-troubleshooting-group-policy-application-event-id-1085-and-7016)
- [Microsoft Q&A: full 4016 Event XML](https://learn.microsoft.com/en-us/answers/questions/2651746/windows-7-sp1-event-7011-timeout-gpsvc-service-wel)
- [Elastic Windows integration (Winlogbeat `winlog.*` fields)](https://github.com/elastic/integrations/tree/main/packages/windows)

# Windows Group Policy Operational

Synthetic `Microsoft-Windows-GroupPolicy/Operational` events from a fleet of 48 domain members (36 workstations, 12 servers), for SIEM content that watches whether Group Policy - and security policy in particular - is actually applied. Each event is Winlogbeat-style ECS JSON with the native Event XML in `event.original`.

The generator models computer policy refreshes (periodic and manual `gpupdate`) and the client-side extension (CSE) processing inside them. Every host runs its own refresh schedule; each refresh has one Activity ID shared by all of its events.

## Event Types

Shares measured over 144 hours with the default configuration (`anomaly_mode: true`), 19,790 events.

| Event ID | Level | Message (manifest) | Share | ECS category / type |
| --- | --- | --- | --- | --- |
| 4006 | Information | Starting periodic policy processing for computer `<account>`. Activity id: `<GUID>` | 17.56% | configuration / info |
| 8006 | Information | Completed periodic policy processing for computer `<account>` in `<n>` seconds. | 17.28% | configuration / change |
| 7006 | Error | Periodic policy processing failed for computer `<account>` in `<n>` seconds. | 0.28% | configuration / info |
| 4004 | Information | Starting manual processing of policy for computer `<account>`. Activity id: `<GUID>` | 0.85% | configuration / info |
| 8004 | Information | Completed manual processing of policy for computer `<account>` in `<n>` seconds. | 0.83% | configuration / change |
| 7004 | Error | Manual processing of policy failed for computer `<account>` in `<n>` seconds. | 0.02% | configuration / info |
| 4016 | Information | Starting `<CSE>` Extension Processing. List of applicable Group Policy objects: (No changes were detected.) `<GPO names>` | 31.59% | configuration / info |
| 5016 | Information | Completed `<CSE>` Extension Processing in `<n>` milliseconds. | 31.29% | configuration / change |
| 7016 | Error | Completed `<CSE>` Extension Processing in `<n>` milliseconds. | 0.30% | configuration / info |

Background behaviour, per host:

- Periodic refresh every 90 minutes plus a random 0-30 minute offset (the Windows default); a refresh is skipped when the host is asleep or off the network.
- Each refresh runs the extensions of the host's GPOs that have work: Registry, Security, Audit Policy Configuration, Group Policy Registry, Group Policy Folders, Group Policy Scheduled Tasks, EFS recovery. Registry runs first, the rest in extension-GUID order. A manual refresh runs all of them.
- Audit Policy Configuration completes with `ErrorCode` 2147483658 (E_PENDING), which Microsoft documents as expected.
- Security extension errors (7016, `ErrorCode` 1252) come in short spells: one host fails once or twice before the fault clears, or one shared cause breaks the next Security run of two hosts that apply the same GPO. A failed refresh ends with 7006/7004 and is often followed within minutes by a manual `gpupdate` that fails again or succeeds.
- Administrators run `gpupdate` on individual hosts at random intervals, sometimes twice in a row.

## Anomaly Chain

A change to one Security-bearing GPO (Default Domain Policy, Workstation Security Baseline or Server Security Baseline) breaks the security settings on the computers that apply it. The security baseline - user rights, audit policy, restricted groups - silently stops being enforced there.

Sequence, per episode:

1. Three hosts that apply the changed GPO each run their next refresh on their own schedule. In that refresh the Security extension starts (4016) and ends in error (7016, `ErrorCode` 1252); the refresh ends with 7006, or 7004 when it is a manual `gpupdate`.
2. An administrator may rerun `gpupdate` on a failed host within minutes, as in the background.
3. The next Security run of each host succeeds (5016, `ErrorCode` 0): the fault is fixed and the restored state is visible.

Linking fields: `winlog.event_data.CSEExtensionId` `{827D319E-6EAC-11D2-A4EA-00C04F79F83A}` (Security), `host.name`, and `winlog.activity_id`, which ties each 7016 to the 4016 that lists the applicable GPOs (`winlog.event_data.DescriptionString`, `ApplicableGPOList`) and to the refresh start/end.

Recurrence: one episode every `anomaly_interval_hours` (default 24, minimum 12) of source time. The first is due one hour after the start; each start is delayed by a random 0 to min(1 h, interval / 8), and the next is due one interval after the actual start. Missed episodes are not replayed. Each host fails at its own next refresh, so the three errors spread over minutes to a few hours.

Variation: the GPO and the three hosts change every episode; hosts of the previous episode are excluded. Up to two background errors of other hosts shortly before an episode may complete the chain earlier.

Detection idea: Security extension errors (7016, Security `CSEExtensionId`) on three or more distinct hosts within 6 hours, each preceded in the same Activity ID by a 4016 listing a common GPO - a fleet-level failure that points to a GPO change rather than a single broken host. Pair it with the GPO modification audit (Security 5136) on the domain controllers.

The chain is not recognisable from any single event: every event type, error code, host, GPO and the pattern "two hosts fail, then recover" occur in ordinary background of both modes. Only the third distinct host within the window is withheld from background.

`anomaly_mode` defaults to `true`. With `false` the generator produces the same background without episodes.

## Parameters

### Event Parameters

| Parameter | Default | Description |
| --- | --- | --- |
| `anomaly_mode` | `true` | Mix recurring anomaly episodes into the background; `false` emits background only. |
| `anomaly_interval_hours` | `24` | Hours of source time between episode starts; 12 to 8760. |

Hosts (`samples/hosts.json`: FQDN, SAM account, role) and GPOs (`samples/gpos.json`: GUID, name, scope, extensions) are sample files; edit them to match a lab domain.

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
# Live mode, one input tick per second
eventum generate --path generators/windows-group-policy-operational/generator.yml --id gpo --live-mode true

# Batch mode over a fixed window (set input[0].cron.start and end first)
eventum generate --path generators/windows-group-policy-operational/generator.yml --id gpo --live-mode false
```

The template needs one input tick per second; each tick emits at most one event, stamped with its own microsecond time.

## Sample Output

The Security error that completes the first episode (third host), copied from the default capture:

```json
{"@timestamp": "2026-09-01T05:51:30.152Z", "ecs": {"version": "8.17.0"}, "event": {"action": "cse-processing-failed", "category": ["configuration"], "code": "7016", "kind": "event", "original": "\u003cEvent xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"\u003e\u003cSystem\u003e\u003cProvider Name=\"Microsoft-Windows-GroupPolicy\" Guid=\"{AEA1B4FA-97D1-45F2-A64C-4D69FFFD92C9}\"/\u003e\u003cEventID\u003e7016\u003c/EventID\u003e\u003cVersion\u003e0\u003c/Version\u003e\u003cLevel\u003e2\u003c/Level\u003e\u003cTask\u003e0\u003c/Task\u003e\u003cOpcode\u003e2\u003c/Opcode\u003e\u003cKeywords\u003e0x4000000000000000\u003c/Keywords\u003e\u003cTimeCreated SystemTime=\"2026-09-01T05:51:30.1526675Z\"/\u003e\u003cEventRecordID\u003e695272\u003c/EventRecordID\u003e\u003cCorrelation ActivityID=\"{27F303D3-BEF7-4C1A-8C35-047EAC6E8195}\"/\u003e\u003cExecution ProcessID=\"10744\" ThreadID=\"3132\"/\u003e\u003cChannel\u003eMicrosoft-Windows-GroupPolicy/Operational\u003c/Channel\u003e\u003cComputer\u003ews-1159.corp.contoso.com\u003c/Computer\u003e\u003cSecurity UserID=\"S-1-5-18\"/\u003e\u003c/System\u003e\u003cEventData\u003e\u003cData Name=\"CSEElaspedTimeInMilliSeconds\"\u003e911\u003c/Data\u003e\u003cData Name=\"ErrorCode\"\u003e1252\u003c/Data\u003e\u003cData Name=\"CSEExtensionName\"\u003eSecurity\u003c/Data\u003e\u003cData Name=\"CSEExtensionId\"\u003e{827D319E-6EAC-11D2-A4EA-00C04F79F83A}\u003c/Data\u003e\u003c/EventData\u003e\u003c/Event\u003e", "outcome": "failure", "provider": "Microsoft-Windows-GroupPolicy", "type": ["info"]}, "host": {"name": "ws-1159.corp.contoso.com"}, "log": {"level": "error"}, "message": "Completed Security Extension Processing in 911 milliseconds.", "winlog": {"activity_id": "{27F303D3-BEF7-4C1A-8C35-047EAC6E8195}", "channel": "Microsoft-Windows-GroupPolicy/Operational", "computer_name": "ws-1159.corp.contoso.com", "event_data": {"CSEElaspedTimeInMilliSeconds": "911", "CSEExtensionId": "{827D319E-6EAC-11D2-A4EA-00C04F79F83A}", "CSEExtensionName": "Security", "ErrorCode": "1252"}, "event_id": "7016", "opcode": "Stop", "process": {"pid": 10744, "thread": {"id": 3132}}, "provider_guid": "{AEA1B4FA-97D1-45F2-A64C-4D69FFFD92C9}", "provider_name": "Microsoft-Windows-GroupPolicy", "record_id": "695272", "user": {"identifier": "S-1-5-18"}, "version": 0}}
```

## Format Notes and Limitations

- Field names, types, versions, levels, opcodes and message texts follow the Microsoft-Windows-GroupPolicy manifest of Windows Server 2022 (gpsvc.dll 10.0.20348). The System block, `Keywords` 0x4000000000000000, the `Correlation ActivityID`, the 4016 EventData layout and the decimal `ErrorCode` rendering follow Microsoft's published Event XML of 4016 and 7016.
- Inferred, not quoted from a raw record: Version 1 for 4004/4006/8004/8006/7004/7006 (the newer of the two manifest versions), the values of `IsBackgroundProcessing`, `IsAsyncProcessing` and `ReasonForSyncProcessing`, the concatenation of several GPOs in `ApplicableGPOList`, and a failed refresh ending with 7006/7004 carrying the extension's error code. Extension GUIDs other than Security and Group Policy Folders are the Windows `GPExtensions` registrations.
- `GPOListStatusString` is always `%%4101` ("No changes were detected.") with `IsGPOListChanged` false: no rendering of the other values was found.
- Only computer policy and these nine event IDs are modelled. Other Operational events of a refresh (5340, 5326, 5312, 5313, 4017/5017, ...) are not emitted; they appear as gaps in `EventRecordID`. User logon policy, boot policy, scripts and connectivity failures are out of scope.
- Security errors always carry `ErrorCode` 1252, the code in Microsoft's examples; other CSE failures are not modelled.
- Rates, extension run shares, durations and the fleet are synthetic. `TimeCreated` has seven fractional digits as on current Windows builds; `@timestamp` is milliseconds.
- `event.category`, `event.type`, `event.action` and `event.outcome` are ECS normalisation, not native fields.

## References

- [Microsoft-Windows-GroupPolicy manifest, Windows Server 2022 20348 (nasbench/EVTX-ETW-Resources)](https://github.com/nasbench/EVTX-ETW-Resources/blob/main/ETWProvidersManifests/WindowsServer/2022/WindowsServer2022_21H2_Standard_20230321_20348.1607/WEPExplorer/Microsoft-Windows-GroupPolicy.xml)
- [Microsoft: Applying Group Policy troubleshooting guidance (Activity ID, 4016/5016)](https://learn.microsoft.com/en-us/troubleshoot/windows-server/group-policy/applying-group-policy-troubleshooting-guidance)
- [Microsoft: Group Policy error events 7016, 1091, 1202 (Security CSE, ErrorCode 1252)](https://learn.microsoft.com/en-us/troubleshoot/windows-server/group-policy/group-policy-error-7016-1091-1202)
- [Microsoft AskDS: Troubleshooting Event ID 1085 and 7016 (full 7016 XML)](https://learn.microsoft.com/en-us/archive/blogs/askds/a-test-case-for-troubleshooting-group-policy-application-event-id-1085-and-7016)
- [Microsoft Q&A: full 4016 Event XML](https://learn.microsoft.com/en-us/answers/questions/2651746/windows-7-sp1-event-7011-timeout-gpsvc-service-wel)
- [Elastic Windows integration (Winlogbeat `winlog.*` fields)](https://github.com/elastic/integrations/tree/main/packages/windows)

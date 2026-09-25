# Windows Group Policy Operational

Eventum content pack for the `Microsoft-Windows-GroupPolicy/Operational` Windows Event Log channel. Emits ECS JSON with the native XML event in `event.original`. Default `anomaly_mode: true` mixes background and a repeatable anomaly chain; `false` emits background only.

## Run

From the content-packs repository root:

```bash
eventum generate --path generators/windows-group-policy-operational/generator.yml --id windows-group-policy-operational --live-mode true
```

For a bounded batch sample, run `timeout 3s eventum generate --path generators/windows-group-policy-operational/generator.yml --id windows-group-policy-operational-batch --live-mode false` (exit code 124 is expected for this continuous source). The file output is `generators/windows-group-policy-operational/output/events.json`.

## Events

| Event ID | Meaning | Frequency | ECS category |
| --- | --- | --- | --- |
| `4016` | CSE processing started | Routine and chain | `configuration` |
| `7016` | CSE processing failed | 3 per chain | `configuration` |

## Anomaly Chain

Three Security CSE processing cycles start with Event 4016 and fail with Event 7016/error 1252, each with its own Activity ID. Join 4016 and 7016 by winlog.activity_id and CSEExtensionId; count repeated Security CSE errors across distinct refresh Activity IDs on one host.

This is an explicitly selected 4016/7016 subset of the Group Policy Operational channel, not a complete refresh trace. Background mode emits 4016 starts; it does not synthesize undocumented completion XML or imply those starts failed. The chain models Security CSE processing failures, not an attacker modifying a GPO.

## Parameters

### Event Parameters

| Parameter | Default | Meaning |
| --- | --- | --- |
| `host_name` | `ws-gp-01.corp.example` | Windows endpoint name |
| `host_ip` | `10.150.0.21` | Endpoint address |
| `anomaly_interval_cycles` | `50` | Routine CSE cycles between chains |
| `anomaly_mode` | `true` | Enable chain; false emits background only |

### Output Parameters

No top-level `${params.*}` or `${secrets.*}` placeholders are shipped. Local file output works without credentials. Replace the `output` block with a destination plugin and keep credentials in Eventum secrets when forwarding events.

## Sample output

This complete event was captured from a run with `anomaly_mode: true`:

```json
{
  "@timestamp": "2026-09-25T13:09:35+00:00",
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "cse-processing-failed",
    "category": [
      "configuration"
    ],
    "code": "7016",
    "dataset": "windows.group_policy_operational",
    "kind": "event",
    "original": "<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"><System><Provider Name=\"Microsoft-Windows-GroupPolicy\" Guid=\"{AEA1B4FA-97D1-45F2-A64C-4D69FFFD92C9}\"/><EventID>7016</EventID><Version>0</Version><Level>2</Level><Task>0</Task><Opcode>2</Opcode><Keywords>0x4000000000000000</Keywords><TimeCreated SystemTime=\"2026-09-25T13:09:35.0000000Z\"/><EventRecordID>20052</EventRecordID><Correlation ActivityID=\"{743f24f2-dadc-40e4-8345-bb35659d8d86}\"/><Execution ProcessID=\"1260\" ThreadID=\"1404\"/><Channel>Microsoft-Windows-GroupPolicy/Operational</Channel><Computer>ws-gp-01.corp.example</Computer><Security UserID=\"S-1-5-18\"/></System><EventData><Data Name=\"CSEElaspedTimeInMilliSeconds\">20984</Data><Data Name=\"ErrorCode\">1252</Data><Data Name=\"CSEExtensionName\">Security</Data><Data Name=\"CSEExtensionId\">{827D319E-6EAC-11D2-A4EA-00C04F79F83A}</Data></EventData></Event>",
    "outcome": "failure",
    "type": [
      "error"
    ]
  },
  "group_policy": {
    "cse": {
      "CSEElaspedTimeInMilliSeconds": 20984,
      "CSEExtensionId": "{827D319E-6EAC-11D2-A4EA-00C04F79F83A}",
      "CSEExtensionName": "Security",
      "ErrorCode": 1252
    },
    "gpo_name": "Corp Security Baseline"
  },
  "host": {
    "ip": [
      "10.150.0.21"
    ],
    "name": "ws-gp-01.corp.example"
  },
  "message": "Security extension processing failed",
  "tags": [
    "group-policy-operational",
    "preserve_original_event"
  ],
  "winlog": {
    "activity_id": "{743f24f2-dadc-40e4-8345-bb35659d8d86}",
    "channel": "Microsoft-Windows-GroupPolicy/Operational",
    "event_id": 7016,
    "provider_name": "Microsoft-Windows-GroupPolicy",
    "record_id": 20052
  }
}
```

## Format and references

Selected reference-field coverage: 7/7 Event 4016 fields and 4/4 Event 7016 fields. Event 4016 retains all seven EventData fields in the Microsoft XML example; Event 7016 retains its four documented fields. Each start/failure pair shares an Activity ID; distinct refreshes use distinct IDs, as Microsoft documents. Fifty GPO-name samples vary routine start events.

- [Microsoft Group Policy troubleshooting and Activity ID](https://learn.microsoft.com/en-us/troubleshoot/windows-server/group-policy/applying-group-policy-troubleshooting-guidance)
- [Microsoft-published Event 4016 XML](https://learn.microsoft.com/en-us/answers/questions/2651746/windows-7-sp1-event-7011-timeout-gpsvc-service-wel)
- [Microsoft Event 7016 fields and error 1252](https://learn.microsoft.com/en-us/troubleshoot/windows-server/group-policy/group-policy-error-7016-1091-1202)
- [Kaspersky KUMA 4.2 supported sources](https://support.kaspersky.ru/kuma/4.2/255782)

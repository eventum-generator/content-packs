# Windows AppLocker EXE/DLL

Eventum content pack for the `Microsoft-Windows-AppLocker/EXE and DLL` Windows Event Log channel. Emits ECS JSON with the native XML event in `event.original`. Default `anomaly_mode: true` mixes background and a repeatable anomaly chain; `false` emits background only.

## Run

From the content-packs repository root:

```bash
eventum generate --path generators/windows-applocker/generator.yml --id windows-applocker --live-mode true
```

For a bounded batch sample, run `timeout 3s eventum generate --path generators/windows-applocker/generator.yml --id windows-applocker-batch --live-mode false` (exit code 124 is expected for this continuous source). The file output is `generators/windows-applocker/output/events.json`.

## Events

| Event ID | Meaning | Frequency | ECS category |
| --- | --- | --- | --- |
| `8004` | EXE/DLL execution blocked | 1 per routine tick; 4 per chain | `process` |

## Anomaly Chain

The same user SID and logon ID attempts updater.exe from four paths and each launch is blocked by AppLocker Event 8004. Group by host.name, user.id and windows.applocker.TargetLogonId; look for repeated Event 8004 with the same executable basename but multiple distinct file.path values.

Only enforced EXE/DLL block Event 8004 is modeled. The generator does not claim to cover allowed Event 8002, audit-only Event 8003, script/MSI channels or a real policy change. Repeated blocks with one executable basename can also arise from legitimate retry behavior.

## Parameters

### Event Parameters

| Parameter | Default | Meaning |
| --- | --- | --- |
| `host_name` | `ws-01.corp.example` | Windows endpoint name |
| `host_ip` | `10.140.0.21` | Endpoint address |
| `normal_user_sid` | `S-1-5-21-111111111-222222222-333333333-1101` | Background user SID |
| `anomaly_user_sid` | `S-1-5-21-111111111-222222222-333333333-1199` | Chain user SID |
| `anomaly_interval_events` | `250` | Routine events between chains |
| `anomaly_mode` | `true` | Enable chain; false emits background only |

### Output Parameters

No top-level `${params.*}` or `${secrets.*}` placeholders are shipped. Local file output works without credentials. Replace the `output` block with a destination plugin and keep credentials in Eventum secrets when forwarding events.

## Sample output

This complete event was captured from a run with `anomaly_mode: true`:

```json
{
  "@timestamp": "2026-09-25T13:02:17+00:00",
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "executable-blocked",
    "category": [
      "process"
    ],
    "code": "8004",
    "dataset": "windows.applocker",
    "kind": "event",
    "original": "<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"><System><Provider Name=\"Microsoft-Windows-AppLocker\" Guid=\"{cbda4dbf-8d5d-4f69-9578-be14aa540d22}\"/><EventID>8004</EventID><Version>0</Version><Level>2</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime=\"2026-09-25T13:02:17.0000000Z\"/><EventRecordID>10251</EventRecordID><Correlation/><Execution ProcessID=\"10660\" ThreadID=\"4064\"/><Channel>Microsoft-Windows-AppLocker/EXE and DLL</Channel><Computer>ws-01.corp.example</Computer><Security UserID=\"S-1-5-21-111111111-222222222-333333333-1199\"/></System><UserData><RuleAndFileData xmlns=\"http://schemas.microsoft.com/schemas/event/Microsoft.Windows/1.0.0.0\"><PolicyNameLength>3</PolicyNameLength><PolicyName>Exe</PolicyName><RuleId>{00000000-0000-0000-0000-000000000000}</RuleId><RuleNameLength>1</RuleNameLength><RuleName>-</RuleName><RuleSddlLength>1</RuleSddlLength><RuleSddl>-</RuleSddl><TargetUser>S-1-5-21-111111111-222222222-333333333-1199</TargetUser><TargetProcessId>15210</TargetProcessId><FilePathLength>27</FilePathLength><FilePath>C:\\Users\\Public\\updater.exe</FilePath><FileHashLength>0</FileHashLength><FileHash></FileHash><FqbnLength>1</FqbnLength><Fqbn>-</Fqbn><TargetLogonId>0x3e7a9</TargetLogonId><FullFilePathLength>27</FullFilePathLength><FullFilePath>C:\\Users\\Public\\updater.exe</FullFilePath></RuleAndFileData></UserData></Event>",
    "outcome": "failure",
    "type": [
      "denied"
    ]
  },
  "file": {
    "path": "C:\\Users\\Public\\updater.exe"
  },
  "host": {
    "ip": [
      "10.140.0.21"
    ],
    "name": "ws-01.corp.example"
  },
  "message": "C:\\Users\\Public\\updater.exe was prevented from running.",
  "process": {
    "pid": 15210
  },
  "related": {
    "user": [
      "S-1-5-21-111111111-222222222-333333333-1199"
    ]
  },
  "tags": [
    "applocker",
    "preserve_original_event"
  ],
  "user": {
    "id": "S-1-5-21-111111111-222222222-333333333-1199"
  },
  "windows": {
    "applocker": {
      "FileHash": "",
      "FileHashLength": 0,
      "FilePath": "C:\\Users\\Public\\updater.exe",
      "FilePathLength": 27,
      "Fqbn": "-",
      "FqbnLength": 1,
      "FullFilePath": "C:\\Users\\Public\\updater.exe",
      "FullFilePathLength": 27,
      "PolicyName": "Exe",
      "PolicyNameLength": 3,
      "RuleId": "{00000000-0000-0000-0000-000000000000}",
      "RuleName": "-",
      "RuleNameLength": 1,
      "RuleSddl": "-",
      "RuleSddlLength": 1,
      "TargetLogonId": "0x3e7a9",
      "TargetProcessId": 15210,
      "TargetUser": "S-1-5-21-111111111-222222222-333333333-1199"
    }
  },
  "winlog": {
    "channel": "Microsoft-Windows-AppLocker/EXE and DLL",
    "event_id": 8004,
    "provider_name": "Microsoft-Windows-AppLocker",
    "record_id": 10251
  }
}
```

## Format and references

Selected reference-field coverage: 18/18 selected Event 8004 RuleAndFileData fields. Event 8004 UserData/RuleAndFileData retains all 18 fields in the Microsoft-published XML example. Fifty routine blocked paths vary the background. TargetUser and TargetLogonId stay stable across a chain; target process ID changes with each attempt.

- [AppLocker Event Viewer ID catalog](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/using-event-viewer-with-applocker)
- [Microsoft-published Event 8004 XML](https://learn.microsoft.com/en-us/answers/questions/884797/win11-home-applocker-prevents-an-app-from-starting)
- [Kaspersky KUMA 4.2 supported sources](https://support.kaspersky.ru/kuma/4.2/255782)

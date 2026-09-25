# Windows TaskScheduler Operational

Eventum content pack for the `Microsoft-Windows-TaskScheduler/Operational` Windows Event Log channel. Emits ECS JSON with the native XML event in `event.original`. Default `anomaly_mode: true` mixes background and a repeatable anomaly chain; `false` emits background only.

## Run

From the content-packs repository root:

```bash
eventum generate --path generators/windows-task-scheduler-operational/generator.yml --id windows-task-scheduler-operational --live-mode true
```

For a bounded batch sample, run `timeout 3s eventum generate --path generators/windows-task-scheduler-operational/generator.yml --id windows-task-scheduler-operational-batch --live-mode false` (exit code 124 is expected for this continuous source). The file output is `generators/windows-task-scheduler-operational/output/events.json`.

## Events

| Event ID | Meaning | Frequency | ECS category |
| --- | --- | --- | --- |
| `201` | Action completed with result code | 1 per run | `process` |
| `102` | Task instance finished | 1 per run | `process` |

## Anomaly Chain

The same PayrollDaily task produces three Event 201 nonzero action result codes, each followed by Event 102 task completion; a fourth run returns zero. Group Event 201 by host.name and TaskName across distinct TaskInstanceId values; find three nonzero ResultCode values followed by zero in a short window. Event 102 links to each run by InstanceId.

Only action completion (201) and task instance completion (102) are modeled. Event 102 means the task instance finished; it does not override a nonzero action ResultCode. This pack does not model registration Event 106 or a task definition change.

## Parameters

### Event Parameters

| Parameter | Default | Meaning |
| --- | --- | --- |
| `host_name` | `tasks-01.corp.example` | Scheduler host name |
| `host_ip` | `10.160.0.21` | Host address |
| `anomaly_task` | `\Corp\PayrollDaily` | Task path in chain |
| `anomaly_action` | `C:\Program Files\Corp\payroll-sync.exe` | Action executable in chain |
| `anomaly_user` | `CORP\svc_payroll` | Task user in chain |
| `anomaly_interval_runs` | `50` | Routine task runs between chains |
| `anomaly_mode` | `true` | Enable chain; false emits background only |

### Output Parameters

No top-level `${params.*}` or `${secrets.*}` placeholders are shipped. Local file output works without credentials. Replace the `output` block with a destination plugin and keep credentials in Eventum secrets when forwarding events.

## Sample output

This complete event was captured from a run with `anomaly_mode: true`:

```json
{
  "@timestamp": "2026-09-25T13:03:01+00:00",
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "action-completed",
    "category": [
      "process"
    ],
    "code": "201",
    "dataset": "windows.task_scheduler_operational",
    "kind": "event",
    "original": "<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"><System><Provider Name=\"Microsoft-Windows-TaskScheduler\" Guid=\"{DE7B24EA-73C8-4A09-985D-5BDADCFA9017}\"/><EventID>201</EventID><Version>2</Version><Level>4</Level><Task>201</Task><Opcode>2</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime=\"2026-09-25T13:03:01.0000000Z\"/><EventRecordID>30101</EventRecordID><Correlation ActivityID=\"{8a7958c0-fde4-440b-b81b-4ac9be23fe22}\"/><Execution ProcessID=\"884\" ThreadID=\"5524\"/><Channel>Microsoft-Windows-TaskScheduler/Operational</Channel><Computer>tasks-01.corp.example</Computer><Security UserID=\"S-1-5-18\"/></System><EventData Name=\"ActionSuccess\"><Data Name=\"TaskName\">\\Corp\\PayrollDaily</Data><Data Name=\"TaskInstanceId\">{8a7958c0-fde4-440b-b81b-4ac9be23fe22}</Data><Data Name=\"ActionName\">C:\\Program Files\\Corp\\payroll-sync.exe</Data><Data Name=\"ResultCode\">5</Data><Data Name=\"EnginePID\">1060</Data></EventData></Event>",
    "outcome": "failure",
    "type": [
      "error"
    ]
  },
  "host": {
    "ip": [
      "10.160.0.21"
    ],
    "name": "tasks-01.corp.example"
  },
  "message": "\\Corp\\PayrollDaily: action-completed",
  "process": {
    "executable": "C:\\Program Files\\Corp\\payroll-sync.exe"
  },
  "related": {
    "user": [
      "CORP\\svc_payroll"
    ]
  },
  "tags": [
    "task-scheduler-operational",
    "preserve_original_event"
  ],
  "user": {
    "name": "CORP\\svc_payroll"
  },
  "windows": {
    "task_scheduler": {
      "event_data": {
        "ActionName": "C:\\Program Files\\Corp\\payroll-sync.exe",
        "EnginePID": 1060,
        "ResultCode": 5,
        "TaskInstanceId": "{8a7958c0-fde4-440b-b81b-4ac9be23fe22}",
        "TaskName": "\\Corp\\PayrollDaily"
      },
      "task_instance_id": "{8a7958c0-fde4-440b-b81b-4ac9be23fe22}",
      "task_name": "\\Corp\\PayrollDaily"
    }
  },
  "winlog": {
    "activity_id": "{8a7958c0-fde4-440b-b81b-4ac9be23fe22}",
    "channel": "Microsoft-Windows-TaskScheduler/Operational",
    "event_id": 201,
    "provider_name": "Microsoft-Windows-TaskScheduler",
    "record_id": 30101
  }
}
```

## Format and references

Selected reference-field coverage: 5/5 Event 201 and 3/3 Event 102 fields. Event 201 retains the five documented ActionSuccess fields; Event 102 retains the three TaskSuccessEvent fields. Each 201/102 pair shares a task instance GUID; successive runs get distinct GUIDs. Fifty task/action/user samples vary routine runs.

- [Microsoft-published Events 201 and 102 XML](https://learn.microsoft.com/en-us/answers/questions/2664914/task-scheduler-on-server-2012)
- [Microsoft Windows Event Forwarding TaskScheduler IDs](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/use-windows-event-forwarding-to-assist-in-intrusion-detection)
- [Kaspersky KUMA 4.2 supported sources](https://support.kaspersky.ru/kuma/4.2/255782)

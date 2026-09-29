# Windows Task Scheduler Operational

Synthetic `Microsoft-Windows-TaskScheduler/Operational` records from ten Windows servers. Each event is Winlogbeat-style ECS JSON with native Windows event XML in `event.original`. The selected provider profile follows build 17763, the Windows Server 2019 base.

## Event Types

About 2,600 records occur per day, with a small office-hours increase from 08:00 to 18:00 UTC and approximately 3% daily volume variation. Most records describe successful recurring maintenance, backups and monitoring.

| Event ID | Action | Typical frequency | Category |
|---|---|---|---|
| 129 | Task process created | One per run | process |
| 100 | Task started | One per run | process |
| 200 | Action started | One per run | process |
| 201 | Action completed | One per run, usually return code 0 | process |
| 102 | Task completed | One per run | process |
| 106 | Task registered | Temporary work and policy replacements | configuration |
| 141 | Task deleted | Temporary cleanup and policy replacements | configuration |
| 140 | Task updated | Occasional administrative changes | configuration |

Each server carries the recurring tasks appropriate to its role. Hourly backup and monitoring work is more common than daily scans or weekly maintenance. One run has a single instance GUID, and ProcessID in 129 equals EnginePID in 200/201. Action durations vary by task; approximately 1-6% return a nonzero code. Event 201 still describes completion when the action's return code is nonzero.

Six administrators manage assigned servers. Together they perform about 36 operations per day, mainly in office hours: register temporary tasks, run them, remove unused registrations, or update recurring tasks. About 30% of temporary registrations are checks that are deleted without a run. Other temporary tasks run once as SYSTEM, their registrant or `CORP\svc_deploy`. Names and executables come from common pools in both modes.

Temporary tasks have an independent SYSTEM cleanup after about two to three hours. Successful earlier deletion removes the task immediately. Some registrant deletion attempts after a run have no successful 141 record; those tasks remain until SYSTEM cleanup. At most 30 temporary tasks can be registered on one server. Four servers also show Group Policy Preferences replacement, a 141/106 pair by `NT AUTHORITY\System` approximately every 90-120 minutes. Record numbers increase per host, with gaps for omitted trigger events and other unmodeled records.

## Anomaly Chain

`anomaly_mode` defaults to `true`. An episode registers a temporary task (106), runs it (129, 100, 200, 201, 102), then successfully deletes it (141) using the registering account within one hour. The deletion restores the task list. Episode administrators, server assignments, names, executables, run-as accounts, failure rates and task limits are shared with ordinary activity. Existing work continues during the episode.

Link the lifecycle by `host.name` and `winlog.event_data.TaskName`; the 106 `UserContext` must equal the 141 `UserName`. Join records of one run by `InstanceId`/`TaskInstanceId` and `winlog.activity_id`. Task names and instance GUIDs identify individual objects and runs, rather than persistent actors.

With `anomaly_mode: false`, no complete registration/run/deletion chain by one account occurs within an hour. Individual registrations, runs, deletions and administrator/server pairs still occur. Ordinary tasks may be deleted without running, removed by SYSTEM after running, or removed by their registrant later.

The first episode starts within `min(anomaly_interval_hours, 24)` hours, following the administrator activity curve. Later starts lie within a window of `min(interval/4, 6 hours)` centered one interval after the preceding actual registration, with hour weights proportional to the squared activity curve plus a small floor. Administrators and their servers rotate between episodes. Missed episodes are not replayed. Short intervals can place episodes in quiet hours. Each enabled episode contributes its own records.

## Parameters

Edit `event.template.params` in `generator.yml`.

| Parameter | Default | Meaning |
|---|---|---|
| `anomaly_mode` | `true` | Include recurring correlated episodes |
| `anomaly_interval_hours` | `24` | Hours between episode starts, from 6 to 8760 |

The inventories in `samples/` define hosts, recurring tasks, administrators and assigned host indexes, temporary-task name stems, and executables. At least two administrators assigned to different servers are needed for rotation. Output defaults to `output/events.json`; no secrets or substitution parameters are required. Consumers of native Windows records should read `event.original`.

## Usage

From the content-packs root:

```bash
eventum generate --path generators/windows-task-scheduler-operational/generator.yml --id tasks --live-mode true --keep-order true
```

For a finite batch, copy the generator directory and set `start` and `end` in every `patterns/*.yml` oscillator to midnight UTC dates:

```bash
eventum generate --path /tmp/tasks-batch/generator.yml --id tasks-batch --live-mode false --keep-order true
```

Change the output path in the copied configuration as needed. Pattern ratios control daily volume and the office-hours increment.

## Source Fidelity and Limitations

- Eight event IDs are included. Trigger records 107/110/118/119, startup failures 101/103/202/203, queueing records 322/325 and service records are omitted. Unsuccessful task-deletion attempts have no corresponding success record in this profile.
- EventData layouts follow published Event Viewer XML and provider manifests. The selected run order is 129, 100, 200, 201, 102; Windows does not promise this order for every build and workload. Related records can be tens of seconds apart rather than milliseconds.
- The Operational channel does not contain task definitions, command-line arguments or a remote registration's source address. Those require Security 4698/4699 events or task XML.
- ECS categories, actions, user and process projections are normalization. They are not native EventData fields. Timing, action frequencies, task limits and cleanup policy are synthetic; the data was not calibrated against a live fleet.
- Instance GUIDs use uppercase braces in XML and lowercase in rendered messages. Native TimeCreated has seven fractional digits; the final digit is synthetic.

## Sample Output

One complete synthetic event:

```json
{"@timestamp": "2026-09-01T00:54:26.472Z", "ecs": {"version": "8.17.0"}, "event": {"action": "task-deleted", "category": ["configuration"], "code": "141", "kind": "event", "original": "\u003cEvent xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"\u003e\u003cSystem\u003e\u003cProvider Name=\"Microsoft-Windows-TaskScheduler\" Guid=\"{DE7B24EA-73C8-4A09-985D-5BDADCFA9017}\"/\u003e\u003cEventID\u003e141\u003c/EventID\u003e\u003cVersion\u003e0\u003c/Version\u003e\u003cLevel\u003e4\u003c/Level\u003e\u003cTask\u003e141\u003c/Task\u003e\u003cOpcode\u003e0\u003c/Opcode\u003e\u003cKeywords\u003e0x8000000000000000\u003c/Keywords\u003e\u003cTimeCreated SystemTime=\"2026-09-01T00:54:26.4724655Z\"/\u003e\u003cEventRecordID\u003e785173\u003c/EventRecordID\u003e\u003cCorrelation/\u003e\u003cExecution ProcessID=\"1472\" ThreadID=\"400\"/\u003e\u003cChannel\u003eMicrosoft-Windows-TaskScheduler/Operational\u003c/Channel\u003e\u003cComputer\u003eAPP02.corp.contoso.test\u003c/Computer\u003e\u003cSecurity UserID=\"S-1-5-18\"/\u003e\u003c/System\u003e\u003cEventData Name=\"TaskDeleted\"\u003e\u003cData Name=\"TaskName\"\u003e\\Collect-Logs-56bfd7c2-f27c-4394-9252-c845e446b1d5\u003c/Data\u003e\u003cData Name=\"UserName\"\u003eCORP\\adm_rpatel\u003c/Data\u003e\u003c/EventData\u003e\u003c/Event\u003e", "provider": "Microsoft-Windows-TaskScheduler", "type": ["deletion"]}, "host": {"ip": ["10.20.2.32"], "name": "APP02.corp.contoso.test"}, "log": {"level": "information"}, "message": "User \"CORP\\adm_rpatel\"  deleted Task Scheduler task \"\\Collect-Logs-56bfd7c2-f27c-4394-9252-c845e446b1d5\"", "related": {"user": ["adm_rpatel"]}, "user": {"domain": "CORP", "name": "adm_rpatel"}, "winlog": {"channel": "Microsoft-Windows-TaskScheduler/Operational", "computer_name": "APP02.corp.contoso.test", "event_data": {"TaskName": "\\Collect-Logs-56bfd7c2-f27c-4394-9252-c845e446b1d5", "UserName": "CORP\\adm_rpatel"}, "event_id": "141", "process": {"pid": 1472, "thread": {"id": 400}}, "provider_guid": "{DE7B24EA-73C8-4A09-985D-5BDADCFA9017}", "provider_name": "Microsoft-Windows-TaskScheduler", "record_id": 785173, "user": {"identifier": "S-1-5-18"}, "version": 0}}
```

## References

- [Microsoft Q&A: Task Scheduler on Server 2012 (Event Viewer XML for 102 and 201)](https://learn.microsoft.com/en-us/answers/questions/2664914/task-scheduler-on-server-2012)
- [Microsoft TechNet archive: scheduled task triggered by an event (XML for 100 and 201)](https://learn.microsoft.com/en-us/archive/msdn-technet-forums/fac16f3c-d088-4d66-83d8-7139261dea83)
- [Microsoft Q&A: tasks deleted and registered by NT AUTHORITY\System (141/106 on Group Policy refresh)](https://learn.microsoft.com/en-us/answers/questions/5587921/user-nt-authoritysystem-deleted-task-scheduler-tas)
- [Use Windows Event Forwarding to help with intrusion detection (TaskScheduler events)](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/use-windows-event-forwarding-to-assist-in-intrusion-detection)
- [TaskScheduler provider manifest dump, build 17763 (EVTX-ETW-Resources)](https://github.com/nasbench/EVTX-ETW-Resources/blob/main/ETWEventsList/CSV/Windows10/1809/W10_1809_Pro_20201013_17763.1518/Providers/Microsoft-Windows-TaskScheduler.csv)
- [EvtxECmd TaskScheduler maps with example XML](https://github.com/EricZimmerman/evtx/tree/master/evtx/Maps)
- [Splunk data source: TaskScheduler 200](https://research.splunk.com/sources/f8c777f8-e88a-4bba-ae8a-79b250212f23/)
- [Winlogbeat field definitions](https://github.com/elastic/beats/blob/main/winlogbeat/_meta/fields.common.yml)

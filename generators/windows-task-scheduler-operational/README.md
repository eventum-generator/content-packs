# Windows Task Scheduler Operational

Synthetic `Microsoft-Windows-TaskScheduler/Operational` records from ten Windows servers, for testing detections on scheduled-task persistence and remote execution. Each record is Winlogbeat-style ECS JSON with the raw Windows event XML in `event.original`. Event IDs, versions, opcodes, keywords and message text follow the TaskScheduler provider manifest (build 17763, Windows Server 2019 base); the XML shape and EventData fields follow Event Viewer XML published on Microsoft Q&A and real examples in the EvtxECmd maps.

## Event Types

| Event ID | Action (`event.action`) | Share | Category |
| --- | --- | ---: | --- |
| `129` | Created task process (`task-process-created`) | 18.9% | process |
| `100` | Task started (`task-started`) | 18.9% | process |
| `200` | Action started (`action-started`) | 18.9% | process |
| `201` | Action completed, with return code (`action-completed`) | 18.9% | process |
| `102` | Task completed (`task-completed`) | 18.9% | process |
| `106` | Task registered (`task-registered`) | 2.6% | configuration |
| `141` | Task registration deleted (`task-deleted`) | 2.5% | configuration |
| `140` | Task registration updated (`task-updated`) | 0.3% | configuration |

Shares were measured on the default `anomaly_mode: true` capture (10,713 records in 96 hours, about 2,700 per day).

Background, per host and per admin, each on its own random schedule:

- **Scheduled runs.** Every host runs 13 to 14 recurring tasks from `samples/tasks.json` (Windows maintenance tasks and corporate agents), each with its own gap around its nominal interval (1 hour to 1 week, lognormal jitter). A run logs `129`, `100`, `200`, `201` and `102` with one instance GUID; `129` ProcessID equals `200`/`201` EnginePID. Durations are lognormal around each task's typical duration; 1-8% of runs return a nonzero code in `201`, which Task Scheduler still reports as completed.
- **Admin sessions.** Six admins open sessions at lognormal gaps (median 8 hours) and perform one to eight operations within minutes on one or more hosts: register an ad-hoc task (`106`), often run it at once, once or twice (`129` to `102`, running as SYSTEM, the admin or `CORP\svc_deploy`); update a task (`140`); delete an ad-hoc task (`141`); register and delete a task again without running it; or run a recurring task by hand. About 65% of ad-hoc tasks get deleted later, by the registrant, another admin or SYSTEM, after a lognormal delay (median 15 minutes, long tail).
- **Group Policy.** Four hosts carry a Group Policy Preferences task with the Replace action, so each policy refresh (every 90 minutes plus a random offset of up to 30) logs `141` and `106` for that task by `NT AUTHORITY\System`.

Record numbers rise per host and skip one number before each run for the trigger record (`107` or `110`) that is not modeled, plus occasional random gaps.

## Anomaly Chain

`anomaly_mode` defaults to `true`. With `false` the generator emits only the background above, which never holds the complete chain. Every step and every value the chain uses occur there: per 96 hours of background, about 13 ad-hoc tasks registered and deleted by the same admin within an hour without a run, 4 to 8 tasks registered, run and deleted within an hour by a different account, about 10 tasks registered, run and later deleted by their registrant after more than an hour, and 35 or so pairs of configuration changes by one admin within 5 minutes. Episode admins, hosts, task names, actions and run-as accounts are drawn from the same pools and generators as the background.

Sequence, one episode (an ad-hoc task used for one-shot remote execution, as schtasks or atexec do):

1. `106`: an admin account registers a new task on a server.
2. `129`, `100`, `200`, `201`, `102`: the task runs once (in 20% of episodes twice), with the same run-now delay and duration distributions as the background.
3. `141`: the same account deletes the task, restoring the host's task list.

Linking fields: `host.name` and `winlog.event_data.TaskName` across all steps; `UserContext` of `106` equals `UserName` of `141`; `InstanceId`/`TaskInstanceId` (and `winlog.activity_id`) join the rows of one run. Measured chain spans: 13 to 44 minutes (default), 5 to 48 minutes (12-hour interval); the deletion is always inside one hour of the registration.

Recurrence: the first episode starts 1 to 2 hours after the first event, then `anomaly_interval_hours` after the actual start of the previous one (default 24, minimum 6) plus a random delay of up to 1 hour (up to an eighth of the interval). Missed episodes are not replayed. Each episode uses a different admin and a different host than the previous one. Background schedules continue unchanged during episodes. Measured: 4 episodes in 96 hours at 24 hours (start gaps 24.42 to 24.92 hours) and 8 at 12 hours (12.03 to 12.82 hours).

Detection idea: on one host and task, a registration, at least one run and a deletion by the registering account within one hour. Registration and deletion without a run, a run followed by a deletion by another account, or a registrant's cleanup hours later are ordinary here. The background never plans a deletion by the registrant inside the hour after a run: that delay is redrawn from the same distribution until it falls beyond the hour. Because the delay is redrawn, a registrant's post-run deletions cluster just after the hour (about a third fall at 60-77 minutes in the validation captures), so a detector window slightly longer than one hour also matches background.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Description |
| --- | --- | --- |
| `anomaly_mode` | `true` | Include periodic anomaly episodes; `false` gives background only |
| `anomaly_interval_hours` | `24` | Hours between episode starts; 6 to 8760, other values fail validation |

Inventories come from `samples/`: `hosts.json` (name, IP, role, optional Group Policy task), `tasks.json` (recurring tasks with action, principal, interval, duration, failure rate and host role), `admins.json`, `adhoc_names.json` and `adhoc_actions.json` (ad-hoc task names and executables). Each host gets a random stable Schedule service process ID, thread pool and starting record number. Episode rotation needs at least two admins and two hosts.

### Output Parameters

The shipped output writes `output/events.json` and needs no credentials. To send events elsewhere, replace the output and pass values through placeholders, for example:

```yaml
output:
  - opensearch:
      hosts:
        - ${params.opensearch_host}
      username: ${params.opensearch_user}
      password: ${secrets.opensearch_password}
      index: windows-task-scheduler
```

A collector that expects the raw Windows event should read `event.original`.

## Usage

Live mode:

```bash
eventum generate --path generators/windows-task-scheduler-operational/generator.yml --id task-scheduler --live-mode true
```

Batch mode, as fast as possible (the cron input runs until stopped unless `start` and `end` are set on it):

```bash
eventum generate --path generators/windows-task-scheduler-operational/generator.yml --id task-scheduler --live-mode false
```

## Sample Output

The deletion that completes the first episode, copied from the default capture:

```json
{"@timestamp": "2026-09-20T01:42:49.433Z", "ecs": {"version": "8.17.0"}, "event": {"action": "task-deleted", "category": ["configuration"], "code": "141", "kind": "event", "original": "\u003cEvent xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"\u003e\u003cSystem\u003e\u003cProvider Name=\"Microsoft-Windows-TaskScheduler\" Guid=\"{DE7B24EA-73C8-4A09-985D-5BDADCFA9017}\"/\u003e\u003cEventID\u003e141\u003c/EventID\u003e\u003cVersion\u003e0\u003c/Version\u003e\u003cLevel\u003e4\u003c/Level\u003e\u003cTask\u003e141\u003c/Task\u003e\u003cOpcode\u003e0\u003c/Opcode\u003e\u003cKeywords\u003e0x8000000000000000\u003c/Keywords\u003e\u003cTimeCreated SystemTime=\"2026-09-20T01:42:49.4338544Z\"/\u003e\u003cEventRecordID\u003e59724\u003c/EventRecordID\u003e\u003cCorrelation/\u003e\u003cExecution ProcessID=\"1036\" ThreadID=\"4932\"/\u003e\u003cChannel\u003eMicrosoft-Windows-TaskScheduler/Operational\u003c/Channel\u003e\u003cComputer\u003eFS01.corp.contoso.test\u003c/Computer\u003e\u003cSecurity UserID=\"S-1-5-18\"/\u003e\u003c/System\u003e\u003cEventData Name=\"TaskDeleted\"\u003e\u003cData Name=\"TaskName\"\u003e\\Reset-IIS-f57e\u003c/Data\u003e\u003cData Name=\"UserName\"\u003eCORP\\adm_jsmith\u003c/Data\u003e\u003c/EventData\u003e\u003c/Event\u003e", "provider": "Microsoft-Windows-TaskScheduler", "type": ["deletion"]}, "host": {"ip": ["10.20.1.21"], "name": "FS01.corp.contoso.test"}, "log": {"level": "information"}, "message": "User \"CORP\\adm_jsmith\"  deleted Task Scheduler task \"\\Reset-IIS-f57e\"", "related": {"user": ["adm_jsmith"]}, "user": {"domain": "CORP", "name": "adm_jsmith"}, "winlog": {"channel": "Microsoft-Windows-TaskScheduler/Operational", "computer_name": "FS01.corp.contoso.test", "event_data": {"TaskName": "\\Reset-IIS-f57e", "UserName": "CORP\\adm_jsmith"}, "event_id": "141", "process": {"pid": 1036, "thread": {"id": 4932}}, "provider_guid": "{DE7B24EA-73C8-4A09-985D-5BDADCFA9017}", "provider_name": "Microsoft-Windows-TaskScheduler", "record_id": 59724, "user": {"identifier": "S-1-5-18"}, "version": 0}}
```

## Limitations

- Only eight event IDs are modeled. Trigger records (`107`, `110`, `118`, `119`), failures (`101`, `103`, `202`, `203`), `322`/`325` queueing and service records are not emitted; record numbers skip for the trigger records only.
- EventData layouts come from published examples: `100`, `102` and `201` (Microsoft Q&A and TechNet XML), `200` v1 (Splunk example), `106`, `129`, `140` and `141` (EvtxECmd map examples from real logs). Microsoft does not document these layouts. The order `129`, `100`, `200` inside a run follows the usual Task Scheduler history view and is not documented either.
- Instance GUIDs are uppercase with braces in XML and lowercase in `message`, as in the Microsoft Q&A example for `102`. `message` renders the manifest templates with double quotes; spacing follows the manifest dump.
- The Operational log does not show the task definition, command-line arguments or the source of a remote registration; those need Security events 4698/4699 or the task XML.
- The ECS projection follows Winlogbeat field names; `event.category`/`event.type`/`event.action`, `user.*`, `related.user` and `process.*` are normalization, not source fields. `winlog.task`, `winlog.opcode` and `winlog.keywords` are omitted.
- Task intervals, durations, failure rates, admin behavior and process and thread IDs are synthetic, not measured. The seventh fractional digit of `TimeCreated` is random.

## References

- [Microsoft Q&A: Task Scheduler on Server 2012 (Event Viewer XML for 102 and 201)](https://learn.microsoft.com/en-us/answers/questions/2664914/task-scheduler-on-server-2012)
- [Microsoft TechNet archive: scheduled task triggered by an event (XML for 100 and 201)](https://learn.microsoft.com/en-us/archive/msdn-technet-forums/fac16f3c-d088-4d66-83d8-7139261dea83)
- [Microsoft Q&A: tasks deleted and registered by NT AUTHORITY\System (141/106 on Group Policy refresh)](https://learn.microsoft.com/en-us/answers/questions/5587921/user-nt-authoritysystem-deleted-task-scheduler-tas)
- [Use Windows Event Forwarding to help with intrusion detection (TaskScheduler events)](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/use-windows-event-forwarding-to-assist-in-intrusion-detection)
- [TaskScheduler provider manifest dump, build 17763 (EVTX-ETW-Resources)](https://github.com/nasbench/EVTX-ETW-Resources/blob/main/ETWEventsList/CSV/Windows10/1809/W10_1809_Pro_20201013_17763.1518/Providers/Microsoft-Windows-TaskScheduler.csv)
- [EvtxECmd TaskScheduler maps with example XML](https://github.com/EricZimmerman/evtx/tree/master/evtx/Maps)
- [Splunk data source: TaskScheduler 200](https://research.splunk.com/sources/f8c777f8-e88a-4bba-ae8a-79b250212f23/)
- [Winlogbeat field definitions](https://github.com/elastic/beats/blob/main/winlogbeat/_meta/fields.common.yml)

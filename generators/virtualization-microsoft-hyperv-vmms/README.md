# Microsoft Hyper-V VMMS checkpoint and merge failures

Synthetic `Microsoft-Windows-Hyper-V-VMMS-Admin` error records for failed VM checkpoints and background disk merges on four Hyper-V hosts (60 VMs), for testing detections on virtualization storage and backup faults. Each record is Winlogbeat-style ECS JSON with the raw Windows event XML in `event.original`. The XML shape, IDs and message text follow Event Viewer XML for 18014, 18012 and 19100 from Windows Server 2022/2025 posted on Microsoft Q&A.

## Event Types

| Event ID | Action (`event.action`) | Share | Category |
| --- | --- | ---: | --- |
| `18012` | Checkpoint operation failed (`checkpoint-failed`) | 45.5% | host |
| `19100` | Background disk merge failed, 0x80070020 (`disk-merge-failed`) | 29.3% | host |
| `18014` | Checkpoint operation cancelled (`checkpoint-cancelled`) | 25.2% | host |

Shares were measured on the default `anomaly_mode: true` capture (2,940 records in 120 hours, about 590 per day). Successful checkpoints write nothing to the Admin channel, so the stream holds failures only.

Background: every VM has its own random schedule of failing checkpoint series (lognormal gaps, median 4 hours). A failed attempt logs `18012`, preceded by `18014` in 55% of attempts (tens of microseconds apart, on the same VMMS worker thread) and followed by `19100` in 40% (about 20 ms later). After a failure the backup job retries in 60% of cases (median 6 minutes, up to 2 hours); a retry fails again in half of them. In 15% of series the merge of an earlier checkpoint fails on its own and VMMS may retry it several times. Record numbers rise per host with gaps for Admin records that are not modeled.

## Anomaly Chain

`anomaly_mode` defaults to `true`. With `false` the generator emits only the background above, which never holds the complete chain. Every step occurs there, including repeated failures of one VM within minutes: per 120 hours of background, about 110 runs of cancel, fail, merge failure, fail, merge failure on one VM, about 65 runs of three merge failures on one VM within an hour, and about 160 pairs of failed checkpoints on one VM within 5 minutes.

Sequence, one episode (a checkpoint stuck behind a locked differencing disk):

1. `18014` and `18012` for one VM: a checkpoint is cancelled and fails.
2. `19100` for the same VM: the background disk merge fails with 0x80070020 (file in use).
3. The backup job retries; the retry fails (`18012`, sometimes preceded by `18014`) and the merge fails again (`19100`).
4. A third retry fails the same way (`18012`, `19100`). In 30% of episodes a fourth failed attempt follows, with or without a merge failure; after that the series ends as a background series would.

Linking fields: `winlog.user_data.VmId` (also `VmName`, `host.name`). Retry delays and within-attempt delays are drawn from the same distributions as the background. Measured chain spans: 4 to 104 minutes. The source logs no successful checkpoint or merge, so recovery is not visible; a later failure series on the same VM is ordinary background.

Recurrence: the first episode is due 1 hour after the first event, then `anomaly_interval_hours` after the actual start of the previous one (default 24, minimum 6). Each episode starts at a random delay of up to 1 hour (up to an eighth of the interval) after it is due, on the first moment a VM qualifies: idle, no Admin record within the last 6 hours, and neither the previous episode's VM nor on its host. Missed episodes are not replayed. The VM's own schedule continues; an arrival that finds a series running is skipped, as in the background. Measured: 5 episodes in 120 hours at 24 hours (start gaps 24.04 to 24.68 hours) and 10 at 12 hours (12.05 to 12.88 hours), each on a different VM and host than the previous one.

Detection idea: on one VM within 6 hours, a cancelled checkpoint followed by three failed checkpoint attempts, each followed by a merge failure. A single failure, a recovered retry, a pure merge-retry loop or two failing rounds are ordinary here. The background withholds only the merge failure that would complete the full chain.

The VMMS record runs as SYSTEM (`S-1-5-18`) and does not name the user or backup product that started the checkpoint. This pattern points to storage or backup trouble, not to an intrusion.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Description |
| --- | --- | --- |
| `anomaly_mode` | `true` | Include periodic anomaly episodes; `false` gives background only |
| `anomaly_interval_hours` | `24` | Hours between episode starts; 6 to 8760, other values fail validation |

The VM inventory comes from `samples/vms.json` (`vm_name`, `vm_id`, `host`). Hosts are derived from it; each host gets a random stable VMMS process ID, worker thread pool and starting record number. Episode rotation needs VMs on at least two hosts.

### Output Parameters

The shipped output writes `output/events.json` and needs no credentials. To send events elsewhere, replace the output and pass values through placeholders, for example:

```yaml
output:
  - opensearch:
      hosts:
        - ${params.opensearch_host}
      username: ${params.opensearch_user}
      password: ${secrets.opensearch_password}
      index: hyperv-vmms
```

A collector that expects the raw Windows event should read `event.original`.

## Usage

Live mode:

```bash
eventum generate --path generators/virtualization-microsoft-hyperv-vmms/generator.yml --id hyperv --live-mode true
```

Batch mode, as fast as possible (the cron input runs until stopped unless `start` and `end` are set on it):

```bash
eventum generate --path generators/virtualization-microsoft-hyperv-vmms/generator.yml --id hyperv --live-mode false
```

## Sample Output

The merge failure that completes the first episode, copied from the default capture:

```json
{"@timestamp": "2026-09-20T01:13:26.260Z", "ecs": {"version": "8.17.0"}, "event": {"action": "disk-merge-failed", "category": ["host"], "code": "19100", "kind": "event", "original": "\u003cEvent xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"\u003e\u003cSystem\u003e\u003cProvider Name=\"Microsoft-Windows-Hyper-V-VMMS\" Guid=\"{6066f867-7ca1-4418-85fd-36e3f9c0600c}\"/\u003e\u003cEventID\u003e19100\u003c/EventID\u003e\u003cVersion\u003e0\u003c/Version\u003e\u003cLevel\u003e2\u003c/Level\u003e\u003cTask\u003e0\u003c/Task\u003e\u003cOpcode\u003e0\u003c/Opcode\u003e\u003cKeywords\u003e0x8000000000000000\u003c/Keywords\u003e\u003cTimeCreated SystemTime=\"2026-09-20T01:13:26.2601309Z\"/\u003e\u003cEventRecordID\u003e214592\u003c/EventRecordID\u003e\u003cCorrelation/\u003e\u003cExecution ProcessID=\"4324\" ThreadID=\"760\"/\u003e\u003cChannel\u003eMicrosoft-Windows-Hyper-V-VMMS-Admin\u003c/Channel\u003e\u003cComputer\u003eHV-NODE04.corp.contoso.test\u003c/Computer\u003e\u003cSecurity UserID=\"S-1-5-18\"/\u003e\u003c/System\u003e\u003cUserData\u003e\u003cVmlEventLog xmlns=\"http://www.microsoft.com/Windows/Virtualization/Events\"\u003e\u003cVmName\u003eERP-03\u003c/VmName\u003e\u003cVmId\u003eA1A699FE-9A97-4591-9C43-F9E1104985BA\u003c/VmId\u003e\u003cErrorMessage\u003e%%2147942432\u003c/ErrorMessage\u003e\u003cErrorCode\u003e0x80070020\u003c/ErrorCode\u003e\u003c/VmlEventLog\u003e\u003c/UserData\u003e\u003c/Event\u003e", "outcome": "failure", "provider": "Microsoft-Windows-Hyper-V-VMMS", "type": ["change"]}, "host": {"name": "HV-NODE04.corp.contoso.test"}, "log": {"level": "error"}, "message": "\u0027ERP-03\u0027 background disk merge failed to complete: The process cannot access the file because it is being used by another process. (0x80070020). (Virtual machine ID A1A699FE-9A97-4591-9C43-F9E1104985BA)", "related": {"hosts": ["HV-NODE04.corp.contoso.test"]}, "winlog": {"channel": "Microsoft-Windows-Hyper-V-VMMS-Admin", "computer_name": "HV-NODE04.corp.contoso.test", "event_id": "19100", "process": {"pid": 4324, "thread": {"id": 760}}, "provider_guid": "{6066f867-7ca1-4418-85fd-36e3f9c0600c}", "provider_name": "Microsoft-Windows-Hyper-V-VMMS", "record_id": 214592, "user": {"identifier": "S-1-5-18"}, "user_data": {"ErrorCode": "0x80070020", "ErrorMessage": "%%2147942432", "VmId": "A1A699FE-9A97-4591-9C43-F9E1104985BA", "VmName": "ERP-03"}, "version": 0}}
```

## Limitations

- Only three event IDs are modeled. Microsoft publishes no current VMMS event catalog with XML shapes; the Q&A post is the only raw example found. Other Admin events (VM start/stop, 19070/19080 on checkpoint deletion) are not emitted, which is why record numbers skip.
- `19100` always carries 0x80070020 (sharing violation), the one error documented in the example; other HRESULTs are not modeled.
- The ECS projection follows Winlogbeat field names; `event.category`/`event.type`/`event.action` are normalization, not source fields. `winlog.user_data` mirrors the XML UserData. It is Winlogbeat-style, not a full Winlogbeat document: `winlog.keywords`, `winlog.opcode`, `winlog.task` and `user_data.xml_name` are omitted.
- Failure rates, retry behavior and VMMS thread IDs are synthetic, not measured. The Q&A author reports the failure repeating on every attempt until a reboot; the episode models three to four rounds.
- The host clock of `TimeCreated` is synthetic; its seventh fractional digit is random.

## References

- [Microsoft Q&A: Hyper-V Checkpoint Error (Event Viewer XML for 18014, 18012, 19100)](https://learn.microsoft.com/en-us/answers/questions/2203089/hyper-v-checkpoint-error)
- [Microsoft TechNet archive: events logged when a VM checkpoint is taken and deleted](https://learn.microsoft.com/en-us/archive/msdn-technet-forums/85a21c88-b18e-48b7-a04a-ade7204f5066)
- [Troubleshoot Hyper-V VM backup, checkpoint and storage issues](https://learn.microsoft.com/en-us/troubleshoot/windows-server/virtualization/hyper-v-virtual-machine-backup-checkpoint-storage)
- [Winlogbeat field definitions](https://github.com/elastic/beats/blob/main/winlogbeat/_meta/fields.common.yml)

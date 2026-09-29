# Microsoft Hyper-V VMMS checkpoint and merge failures

Synthetic `Microsoft-Windows-Hyper-V-VMMS-Admin` error records for failed VM checkpoints and background disk merges on four Hyper-V hosts (60 VMs), for testing detections on virtualization storage and backup faults. Each record is Winlogbeat-style ECS JSON with the raw Windows event XML in `event.original`. The XML shape, IDs and message text follow Event Viewer XML for 18014, 18012 and 19100 from Windows Server 2022/2025 posted on Microsoft Q&A.

## Event Types

| Event ID | Action (`event.action`) | Share | Category |
| --- | --- | ---: | --- |
| `18012` | Checkpoint operation failed (`checkpoint-failed`) | 45.0% | host |
| `19100` | Background disk merge failed, 0x80070020 (`disk-merge-failed`) | 29.1% | host |
| `18014` | Checkpoint operation cancelled (`checkpoint-cancelled`) | 25.8% | host |

Shares are for the default parameters (`anomaly_mode: true`). Successful checkpoints and merges write nothing to the Admin channel, so the stream holds failures only.

## Volume and Timing

About 120 records a day, each day's count varying by up to 3%: about 2 an hour from 05:00 to 22:00 and about 12 an hour in the nightly backup window from 22:00 to 05:00 of the generator time zone (UTC by default).

Each record belongs to a failing checkpoint series of one VM; a new series starts on a VM that has none running. Ten VMs with recurring checkpoint trouble (two or three per host, marked `checkpoint_trouble: true` in `samples/vms.json`: the SQL and Exchange servers, two ERP and two file servers) log three to four failing series a day and fail on almost every night; each of the other 50 VMs fails about once in six days. On a typical night about 15 of the 60 VMs log a failure (nine or ten of the troubled ones and about six others), about 18 over a whole day, and over 12 days about 7 of the other VMs log nothing at all. A failed attempt logs `18012`, preceded by `18014` in 55% of attempts (median 68 microseconds earlier, on the same VMMS worker thread) and followed by `19100` in 40% (median 22 ms later). After a failure the backup job retries in 60% of cases (median 6 minutes, up to 2 hours); a retry fails again in half of them, so a series of one failed attempt is more common than two, and two more common than three. In 15% of series the merge of an earlier checkpoint fails on its own and VMMS may retry it several times. Record numbers rise per host with gaps for Admin records that are not modeled.

## Anomaly Chain

`anomaly_mode` defaults to `true`. With `false` the generator emits only the background above, which never holds the complete chain. Every step occurs there, including repeated failures of one VM within minutes, cancelled attempts followed by failures and merge failures, and merge-retry loops.

Sequence, one episode (a checkpoint stuck behind a locked differencing disk):

1. `18014` and `18012` for one VM: a checkpoint is cancelled and fails.
2. `19100` for the same VM: the background disk merge fails with 0x80070020 (file in use).
3. The backup job retries; the retry fails (`18012`, sometimes preceded by `18014`) and the merge fails again (`19100`).
4. The third attempt fails the same way (`18012`, `19100`). In 30% of episodes a fourth failed attempt without a merge failure follows; after that the series ends as a background series would.

Linking fields: `winlog.user_data.VmId` (also `VmName`, `host.name`). Retry delays and within-attempt delays follow the background distributions. The chain spans a few minutes to over 2 hours, about 15 minutes in the median.

**Volume.** The record count is the same in both modes: an episode's records take the place of background failures that would have come at those moments. The VM has no other failing series while the episode runs, as with any background series.

**Recurrence.** `anomaly_interval_hours` (default `24`, minimum `6`) is measured in event time. The first episode starts within the first min(interval, 24 h) of the run, its hour weighted by the squared hourly volume (relative to the backup-window rate, plus a floor of 0.02); each later start is drawn in a window of min(interval / 4, 6 h) centred one interval after the previous actual start, with the same weighting, so most episodes fall in the backup window. When no VM qualifies (see Variation) at the drawn moment, a later moment in the same window is drawn. Missed episodes are not replayed. Consecutive episodes start 21 to 27 hours apart at the default interval and 7 to 9 hours apart at 8 hours.

**Variation.** Each episode picks one of the ten VMs with recurring checkpoint trouble, by the same failure propensity as the background: one that has no failing series running, is neither the previous episode's VM nor on its host, and whose records of the last 6 hours hold no cancelled checkpoint followed by a failure and a merge failure.

**Background without the chain.** In the background, a merge failure that would complete the full chain on one VM within 6 hours is not logged (that merge succeeds), so a VM whose records of the last 6 hours already hold a cancelled checkpoint followed by three failed attempts with two merge failures logs no merge failure until that cancelled checkpoint is 6 hours old. The same holds after an episode, so each episode completes the chain exactly once; no other record is missing or delayed.

**Detection idea.** On one VM within 6 hours, a cancelled checkpoint followed by three failed checkpoint attempts, each followed by a merge failure. A single failure, a recovered retry, a pure merge-retry loop or two failing rounds are ordinary here.

The VMMS record runs as SYSTEM (`S-1-5-18`) and does not name the user or backup product that started the checkpoint. This pattern points to storage or backup trouble, not to an intrusion.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Description |
| --- | --- | --- |
| `anomaly_mode` | `true` | Include periodic anomaly episodes; `false` gives background only |
| `anomaly_interval_hours` | `24` | Hours between episode starts; 6 to 8760, other values fail validation |

The VM inventory comes from `samples/vms.json` (`vm_name`, `vm_id`, `host`, `checkpoint_trouble`). Hosts are derived from it; each host gets a random stable VMMS process ID, worker thread pool and starting record number. VMs with `checkpoint_trouble: true` fail a few times a day and carry the episodes; episode rotation needs such VMs on at least two hosts.

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

From the content-packs repository root, live:

```bash
eventum generate --path generators/virtualization-microsoft-hyperv-vmms/generator.yml --id hyperv --live-mode true
```

The three files under `patterns/` set the volume: `floor.yml` the around-the-clock rate, `backup-evening.yml` and `backup-night.yml` the backup window. They start at midnight of the current day and never end. In live mode a record that follows another within milliseconds (for example `18012` after `18014`) is written together with the next record of the stream, which in the daytime comes about every 30 minutes; its own `@timestamp` is kept. For a finite batch, set `start` and `end` in the three pattern files (for example `start: "2026-09-01T00:00:00Z"`, `end: "+5d"`); the second episode can start up to 51 hours after the run start, so use at least 52 hours to see two at the default interval:

```bash
eventum generate --path generators/virtualization-microsoft-hyperv-vmms/generator.yml --id hyperv --live-mode false --keep-order true
```

## Sample Output

The merge failure that completes the first episode of a default run:

```json
{"@timestamp": "2026-09-01T03:44:12.027Z", "ecs": {"version": "8.17.0"}, "event": {"action": "disk-merge-failed", "category": ["host"], "code": "19100", "kind": "event", "original": "\u003cEvent xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"\u003e\u003cSystem\u003e\u003cProvider Name=\"Microsoft-Windows-Hyper-V-VMMS\" Guid=\"{6066f867-7ca1-4418-85fd-36e3f9c0600c}\"/\u003e\u003cEventID\u003e19100\u003c/EventID\u003e\u003cVersion\u003e0\u003c/Version\u003e\u003cLevel\u003e2\u003c/Level\u003e\u003cTask\u003e0\u003c/Task\u003e\u003cOpcode\u003e0\u003c/Opcode\u003e\u003cKeywords\u003e0x8000000000000000\u003c/Keywords\u003e\u003cTimeCreated SystemTime=\"2026-09-01T03:44:12.0279698Z\"/\u003e\u003cEventRecordID\u003e101312\u003c/EventRecordID\u003e\u003cCorrelation/\u003e\u003cExecution ProcessID=\"2616\" ThreadID=\"9912\"/\u003e\u003cChannel\u003eMicrosoft-Windows-Hyper-V-VMMS-Admin\u003c/Channel\u003e\u003cComputer\u003eHV-NODE02.corp.contoso.test\u003c/Computer\u003e\u003cSecurity UserID=\"S-1-5-18\"/\u003e\u003c/System\u003e\u003cUserData\u003e\u003cVmlEventLog xmlns=\"http://www.microsoft.com/Windows/Virtualization/Events\"\u003e\u003cVmName\u003eSQL-02\u003c/VmName\u003e\u003cVmId\u003eD5C4A602-CC4A-41B7-BFCB-85359B37E457\u003c/VmId\u003e\u003cErrorMessage\u003e%%2147942432\u003c/ErrorMessage\u003e\u003cErrorCode\u003e0x80070020\u003c/ErrorCode\u003e\u003c/VmlEventLog\u003e\u003c/UserData\u003e\u003c/Event\u003e", "outcome": "failure", "provider": "Microsoft-Windows-Hyper-V-VMMS", "type": ["change"]}, "host": {"name": "HV-NODE02.corp.contoso.test"}, "log": {"level": "error"}, "message": "\u0027SQL-02\u0027 background disk merge failed to complete: The process cannot access the file because it is being used by another process. (0x80070020). (Virtual machine ID D5C4A602-CC4A-41B7-BFCB-85359B37E457)", "related": {"hosts": ["HV-NODE02.corp.contoso.test"]}, "winlog": {"channel": "Microsoft-Windows-Hyper-V-VMMS-Admin", "computer_name": "HV-NODE02.corp.contoso.test", "event_id": "19100", "process": {"pid": 2616, "thread": {"id": 9912}}, "provider_guid": "{6066f867-7ca1-4418-85fd-36e3f9c0600c}", "provider_name": "Microsoft-Windows-Hyper-V-VMMS", "record_id": 101312, "user": {"identifier": "S-1-5-18"}, "user_data": {"ErrorCode": "0x80070020", "ErrorMessage": "%%2147942432", "VmId": "D5C4A602-CC4A-41B7-BFCB-85359B37E457", "VmName": "SQL-02"}, "version": 0}}
```

## Limitations

- Only three event IDs are modeled. Microsoft publishes no current VMMS event catalog with XML shapes; the Q&A post is the only raw example found. Other Admin events (VM start/stop, 19070/19080 on checkpoint deletion) are not emitted, which is why record numbers skip.
- `19100` always carries 0x80070020 (sharing violation), the one error documented in the example; other HRESULTs are not modeled.
- The ECS projection follows Winlogbeat field names; `event.category`/`event.type`/`event.action` are normalization, not source fields. `winlog.user_data` mirrors the XML UserData. It is Winlogbeat-style, not a full Winlogbeat document: `winlog.keywords`, `winlog.opcode`, `winlog.task` and `user_data.xml_name` are omitted.
- The ten troubled VMs fail three to four times a day, more often than a cluster whose checkpoint problems get fixed; the other VMs fail about once in six days. Failure rates, retry behavior, the backup window and VMMS thread IDs are synthetic, not measured.
- The Q&A author reports the failure repeating on every attempt until a reboot; the episode models three to four rounds.
- After an episode its VM logs no merge failure (`19100`) at all until 6 hours after the episode's last cancelled checkpoint that still has three failed attempts with two merge failures after it, which is 6 to about 8 hours after the episode starts; its cancelled and failed checkpoints (`18014`, `18012`) go on as usual. A background VM that logs a cancelled checkpoint followed by three failed attempts with two merge failures shows the same pause.
- The host clock of `TimeCreated` is synthetic; its seventh fractional digit is random.

## Performance

About 2,800 records per second on one core: a 14-day default run (about 1,700 records) takes about 1.5 s.

## References

- [Microsoft Q&A: Hyper-V Checkpoint Error (Event Viewer XML for 18014, 18012, 19100)](https://learn.microsoft.com/en-us/answers/questions/2203089/hyper-v-checkpoint-error)
- [Microsoft TechNet archive: events logged when a VM checkpoint is taken and deleted](https://learn.microsoft.com/en-us/archive/msdn-technet-forums/85a21c88-b18e-48b7-a04a-ade7204f5066)
- [Troubleshoot Hyper-V VM backup, checkpoint and storage issues](https://learn.microsoft.com/en-us/troubleshoot/windows-server/virtualization/hyper-v-virtual-machine-backup-checkpoint-storage)
- [Winlogbeat field definitions](https://github.com/elastic/beats/blob/main/winlogbeat/_meta/fields.common.yml)

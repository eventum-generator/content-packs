# Veeam Backup & Replication Syslog

Generates Veeam Backup & Replication 13.1 syslog records for a backup server operated by a small team: web UI logons, user-started backup job sessions, restore point creation and removal, and one planned repository retirement. Each event is ECS-enriched JSON with the native syslog record in `event.original`. Record bodies and parameter names follow Veeam's event reference for build 13.1.1.18.

Every event carries exactly the parameters documented for its ID, in the documented order: 35 distinct parameter names across seven IDs. The syslog envelope mirrors Veeam's published examples, which omit the PRI prefix. ECS fields are a generator mapping, not a vendor or Elastic parser contract.

## Event Types

Shares measured on a seven-day default capture with `anomaly_mode: true` (565 records).

| Event ID | Veeam event | Category | Share |
| --- | --- | --- | ---: |
| 44003 | User authorization granted | authentication | 30.3% |
| 10010 | Restore point created | file | 21.1% |
| 10050 | Restore point deleted (SYSTEM retention or an operator) | file | 16.6% |
| 110 | Backup job started by a user | process | 8.8% |
| 190 | Backup job finished | process | 8.8% |
| 44002 | User authorization denied | authentication | 14.2% |
| 28200 | Backup repository deleted | configuration | 0.2% (one event) |

Background activity is a set of independent random processes:

- **Logons.** Six operators (`samples/operators.json`) open web UI sessions at lognormal intervals, thinned by a UTC working-hours curve, from one of their own workstation or VPN addresses. A mistyped password produces one or more 44002 denials (Reason 1) seconds apart before the 44003 grant; some attempts are abandoned after the denials.
- **Job sessions.** After logon an operator may start an idle job (`samples/jobs.json`, four jobs, eleven VMs). The session emits 110 (`Flags=1`), one 10010 per VM with the VM snapshot time as `DateTime`, and 190 with the same `JobSessionID`. A job that is already running is not started again.
- **Retention.** When a VM holds more restore points than its job's retention count, SYSTEM removes the oldest one (10050).
- **Manual cleanup.** After logon an operator sometimes removes one to three finished restore points of random VMs (10050).
- **Repository retirement.** Once per run, at a random working-hours time within the first three days, an operator logs on, removes the pre-existing point on the unused secondary repository and then the repository itself (28200). It happens in both modes and is not part of the anomaly.

## Anomaly Chain

`anomaly_mode` defaults to `true`. With `false` the output is background only and never contains the complete chain.

**Sequence.** Within 30 minutes of the first denial, one operator:

1. fails authorization at least twice (44002, two to five denials) from one address,
2. is granted access (44003) from the same address,
3. removes a finished restore point (10050 by that user), sometimes followed by one or two more removals.

**Linking fields.** `user.name` (`FriendlyName`, `UserFullInfo`) on all steps; `source.ip` (`SourceIpAddress`) on the denials and the grant. The 10050 record carries no address or session ID, so the join to the logon is user and time. The removed point's `OibID`, `VmRef`, `RepositoryID`, `DateTime` and `StorageSize` match its earlier 10010 in a finished job session, or a point that predates the stream.

**Recurrence.** Episodes recur by source time every `anomaly_interval_hours` (default 24, minimum 2). The first episode starts within the first min(interval, 24 h); each later one within a window of width min(interval / 4, 6 h) centred one interval after the previous actual start. The start hour is weighted by the square of the working-hours curve plus a small floor, then delayed by a random lognormal delay (median two minutes). A missed episode is not replayed. At intervals of 8 hours or less the windows necessarily cover the whole clock; at other intervals that are not a multiple of 24 hours the due time drifts through the day and the window can fall at night (a 16-hour test run placed 4 of 10 starts between 23:00 and 02:00 UTC).

**Variation.** Each episode picks an operator other than the previous episode's (weighted by logon activity), one of that operator's usual addresses, and a VM other than the previous episode's. The number of denials, the gaps between attempts, the delay before the removal and the chance that the logon also starts a backup job follow the same distributions as ordinary logons and cleanup.

**Changed state.** A removed point is gone; the VM's next job session creates a new one, and retention continues from the reduced count.

**Detection idea.** Correlate per `user.name`: two or more 44002 from one `SourceIpAddress`, a 44003 from it, then a user-initiated 10050 within 30 minutes of the first denial. A valid session after a guessed password immediately destroying backups is a ransomware-preparation pattern.

**Background overlap.** Every event ID, operator, operator/address pair, VM and repository used by the chain appears in ordinary activity of both modes, as do repeated denials by one operator within minutes, grants after denials, and point removals shortly after logon. Only the complete ordered sequence is exclusive to episodes: an ordinary removal that would complete it is dropped at its own time (the point stays until retention or a later cleanup removes it). The event times, the operator and every other event are unchanged, and other operators' removals in the same window are unaffected.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Description |
| --- | --- | --- |
| `server_name` | `VBRSRV01` | Syslog hostname and `host.name` |
| `server_fqdn` | `vbrsrv01.contoso.test` | `VbrHostName` |
| `version` | `13.1.1.18` | `VbrVersion` |
| `user_domain` | `TECH` | Domain prefix in `Description`, `UserName` and `UserFullInfo` |
| `hypervisor_server` | `pdcsrv01.contoso.test` | `ServerName` of the protected VMs |
| `active_repository_id` | `88788f9e-d8f5-4eb4-bc4f-9b3f5403bcec` | Repository used by all jobs |
| `repository_id` | `ed8c61cc-77f0-4f40-b73e-8c92d4a6fb11` | Secondary repository retired once |
| `repository_name` | `Backup Repository 01` | Name of the secondary repository |
| `retired_point_id` | `882ace9a-6308-4f2b-bd12-88f004de0162` | Pre-existing point on the secondary repository |
| `anomaly_interval_hours` | `24` | Episode interval in source hours, 2 to 8760 |
| `anomaly_mode` | `true` | `true` adds recurring episodes; `false` emits background only |

Operators (names, addresses, logon rate, typo rate) and jobs (names, IDs, retention, VMs) live in `samples/operators.json` and `samples/jobs.json`.

### Output Parameters

The shipped configuration writes `output/events.json` relative to the generator. It has no `${params.*}` or `${secrets.*}` placeholders; change `output.file.path` or replace the output plugin to deliver elsewhere.

## Usage

Live stream:

```bash
eventum generate --path generators/backup-veeam-vbr/generator.yml --id vbr --live-mode true
```

Batch: add `start` and `end` to the cron input (for example `start: "2026-09-25T00:00:00+00:00"` and `end: "2026-10-02T00:00:00+00:00"`), then

```bash
eventum generate --path generators/backup-veeam-vbr/generator.yml --id vbr --live-mode false --keep-order true
```

## Sample Output

The first episode's restore point removal (after two denials and a grant for `backup.ops` from 10.40.2.14) from the seven-day default capture, as written by the file output:

```json
{"@timestamp": "2026-09-25T09:14:40.652952+00:00", "ecs": {"version": "8.17.0"}, "event": {"kind": "event", "module": "veeam", "dataset": "veeam.vbr.syslog", "code": "10050", "category": ["file"], "action": "restore_point_deleted", "type": ["deletion"], "outcome": "success", "original": "1 2026-09-25T09:14:40.652952+00:00 VBRSRV01 Veeam_MP - - [origin enterpriseId=\"31023\"] [categoryId=0 instanceId=10050 OibID=\"2e0fef24-7842-41d7-93c6-a49c4d2e0058\" OriginalOibID=\"2e0fef24-7842-41d7-93c6-a49c4d2e0058\" VmRef=\"vm-402\" VmName=\"SRV-WEB02\" ServerName=\"pdcsrv01.contoso.test\" DateTime=\"09/23/2026 13:18:54\" IsCorrupted=\"False\" Platform=\"0\" StorageSize=\"24993189888\" RepositoryID=\"88788f9e-d8f5-4eb4-bc4f-9b3f5403bcec\" IsFull=\"True\" UserFullInfo=\"\u003cModifiedUserInfo fullName=\"TECH\\backup.ops\" loginType=\"0\" /\u003e\" VbrHostName=\"vbrsrv01.contoso.test\" VbrVersion=\"13.1.1.18\" Version=\"1\" Description=\"Restore point for VM \u0027SRV-WEB02\u0027 has been removed by user TECH\\backup.ops.\"]"}, "message": "Restore point for VM \u0027SRV-WEB02\u0027 has been removed by user TECH\\backup.ops.", "host": {"name": "VBRSRV01"}, "user": {"name": "backup.ops"}, "veeam": {"event_id": 10050, "app": "Veeam_MP", "severity": "warning", "enterprise_id": 31023, "category_id": 0, "parameters": {"DateTime": "09/23/2026 13:18:54", "Description": "Restore point for VM \u0027SRV-WEB02\u0027 has been removed by user TECH\\backup.ops.", "IsCorrupted": "False", "IsFull": "True", "OibID": "2e0fef24-7842-41d7-93c6-a49c4d2e0058", "OriginalOibID": "2e0fef24-7842-41d7-93c6-a49c4d2e0058", "Platform": "0", "RepositoryID": "88788f9e-d8f5-4eb4-bc4f-9b3f5403bcec", "ServerName": "pdcsrv01.contoso.test", "StorageSize": "24993189888", "UserFullInfo": "\u003cModifiedUserInfo fullName=\"TECH\\backup.ops\" loginType=\"0\" /\u003e", "VbrHostName": "vbrsrv01.contoso.test", "VbrVersion": "13.1.1.18", "Version": "1", "VmName": "SRV-WEB02", "VmRef": "vm-402"}}}
```

## Limitations

- Only user-started job sessions are modeled: Veeam documents 110 only for sessions started by a user (`Flags=1`), and scheduled sessions are not generated. Every session succeeds (`JobResult=0`, `WillBeRetried=False`) and every point is a full backup (`IsFull=True`).
- Rates, retention counts, session lengths and the working-hours curve are design choices, not production measurements.
- Timestamps are UTC with microseconds; Veeam's examples use the server's local offset. `DateTime` is written in UTC.
- Byte-for-byte parity with a real capture and compatibility with a specific SIEM parser are not verified. XML-valued parameters keep the literal inner quotes shown in Veeam's examples, so a strict RFC 5424 parser may reject them.
- 44002 always uses Reason 1 (unauthenticated). Veeam's raw 44002 example omits `Reason`, which its parameter table documents.
- The secondary repository and its point predate the stream and are retired once; their creation is not modeled.

## References

- Veeam B&R 13.1 event reference: [110 Backup Job Started](https://helpcenter.veeam.com/docs/vbr/events/event_110.html), [190 Backup Job Finished](https://helpcenter.veeam.com/docs/vbr/events/event_190.html), [10010 Restore Point Created](https://helpcenter.veeam.com/docs/vbr/events/event_10010.html), [10050 Restore Point Deleted](https://helpcenter.veeam.com/docs/vbr/events/event_10050.html), [28200 Backup Repository Deleted](https://helpcenter.veeam.com/docs/vbr/events/event_28200.html), [44002 User Authorization Denied](https://helpcenter.veeam.com/docs/vbr/events/event_44002.html), [44003 User Authorization Granted](https://helpcenter.veeam.com/docs/vbr/events/event_44003.html).
- [Removing backup repositories](https://helpcenter.veeam.com/docs/vbr/userguide/repo_delete.html).

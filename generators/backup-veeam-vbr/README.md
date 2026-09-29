# Veeam Backup & Replication Syslog

Generates Veeam Backup & Replication 13.1 syslog records for one backup server: nightly and ad-hoc backup job sessions over 400 VMs, restore point creation and retention, web UI logons of a sixteen-person backup team (six Backup Administrators), manual point removals, and one planned repository retirement. Each event is ECS-enriched JSON with the native syslog record in `event.original`. Record bodies and parameter names follow Veeam's event reference for build 13.1.1.18.

Every event carries exactly the parameters documented for its ID, in the documented order: 35 distinct parameter names across seven IDs. The syslog envelope mirrors Veeam's published examples, which omit the PRI prefix. ECS fields are a generator mapping, not a vendor or Elastic parser contract.

## Input Design

The input sets the rate: two tagged `time_patterns` inputs whose files under `patterns/` add up to UTC hour-of-day curves, and every timestamp becomes exactly one record (no event is dropped).

| Input tag | UTC hours | Timestamps/h | Pattern files |
|---|---|---:|---|
| `ops` | 08-17 | 9.7 | `ops-baseline` + `ops-daytime` + `ops-workday` + `ops-core` |
| `ops` | 07-08, 17-19 | 5.6 | `ops-baseline` + `ops-daytime` + `ops-workday` |
| `ops` | 06-07, 19-21 | 2.5 | `ops-baseline` + `ops-daytime` |
| `ops` | 21-06 | 0.8 | `ops-baseline` |
| `backup` | 20-06 | 144 | `backup-floor` + `backup-evening` / `backup-night` |
| `backup` | 06-20 | 54 | `backup-floor` |

About 2,300 records per day, with a ±10% day-to-day variation from each pattern's randomizer. Timestamps fall at random inside each band.

Every timestamp first takes the earliest due operator step: further denials, the grant, a job start, point removals, the repository removal, and every episode step. Otherwise an `ops` timestamp starts a web UI logon of an operator drawn by logon weight among those not already in a session, and a `backup` timestamp writes the next record of the backup lane: the oldest user-started job session first, else the current scheduled session, else a new scheduled session of an idle job, drawn with a weight that grows with the square of the time since its last session. A session writes one 10010 per VM in turn, a SYSTEM 10050 for the VM's oldest point right after a new one when the job's retention count is exceeded, and 190 at the end. The backup lane therefore runs at the speed of its input: a VM takes a median 39 s in the night window and 110 s by day.

Gaps between the steps of one logon are minimum delays; the actual gap is the wait for the next timestamp of either input (measured between repeated denials: median 91 s, 10th-90th percentile 30-220 s). To change the volume, scale the `ratio` of every file of one input by the same factor.

## Event Types

Shares measured on the seven-day default capture with `anomaly_mode: true` (16,141 records).

| Event ID | Veeam event | Category | Share |
| --- | --- | --- | ---: |
| 10010 | Restore point created | file | 49.0% |
| 10050 | Restore point deleted (SYSTEM retention and user removals) | file | 43.8% |
| 44003 | User authorization granted | authentication | 4.8% |
| 190 | Backup job finished | process | 1.5% |
| 44002 | User authorization denied | authentication | 0.8% |
| 110 | Backup job started by a user | process | 0.2% |
| 28200 | Backup repository deleted | configuration | 0.01% |

Background activity:

- **Backup sessions.** Twelve jobs protect 400 VMs (`samples/jobs.json`). Scheduled sessions follow one another on the backup lane; Veeam sends 110 only for sessions started by a user, so a scheduled session begins with its first 10010. VMs are processed in parallel, so they finish in a random order within each session. Each 10010 carries the VM snapshot time as `DateTime`, a few seconds after the session's previous record and before the 10010 itself (median 47 s before).
- **Retention.** When a VM holds more restore points than its job's retention count, SYSTEM removes the oldest one (10050) right after the new point.
- **Logons.** Sixteen operators (`samples/operators.json`) log on to the web UI, mostly from their own workstation and sometimes over VPN, one session at a time (median 20 minutes): six Backup Administrators about 10 times a day each, ten Backup Operators about 5 times. A mistyped password produces one or more 44002 denials (Reason 1) before the 44003 grant (8-9% of an administrator's logons, 3-5% of an operator's). The PAM vault rotates an administrator's password about once a week and other operators' passwords expire about every 60 days; the next logon from each address where the browser saved the old password submits it first, which gives two or more denials before the new one is typed (the same distribution as an episode's). Some attempts are abandoned after the denials. In the default capture 8% of logon attempts include a denial and 5% two or more.
- **User-started sessions.** After 4% of logons the operator starts an idle job: 110 (`Flags=1`), then the session's points on the backup lane ahead of scheduled work, and 190 with the same `JobSessionID`. A running job is not started again.
- **Manual cleanup.** Only Backup Administrators remove restore points: after 8% of their sessions they remove one to three finished points of random VMs (10050).
- **Repository retirement.** Once per run, at a working-hours time 6-72 hours after the first timestamp, a Backup Administrator logs on, removes the pre-existing point on the unused secondary repository and then the repository itself (28200). It happens in both modes and is not part of the anomaly.

## Anomaly Chain

`anomaly_mode` defaults to `true`. With `false` the output is background only and never contains the complete chain.

**Sequence.** Within 30 minutes of the first denial, one Backup Administrator:

1. fails authorization at least twice (44002, two to five denials) from one address,
2. is granted access (44003) from the same address,
3. removes one finished restore point (10050 by that user).

**Linking fields.** `user.name` (`FriendlyName`, `UserFullInfo`) on all steps; `source.ip` (`SourceIpAddress`) on the denials and the grant. The 10050 record carries no address or session ID, so the join to the logon is user and time. The removed point's `OibID`, `VmRef`, `RepositoryID`, `DateTime` and `StorageSize` match its earlier 10010 in a finished job session, or a point that predates the stream.

**Recurrence.** Episodes recur by source time every `anomaly_interval_hours` (default 24, minimum 2). The first episode starts within the first min(interval, 24 h), its hour drawn from the logon curve; each later one within a window of width min(interval / 4, 6 h) centred one interval after the previous actual start, weighted by the square of the logon curve plus a small floor. A missed episode is not replayed. At the default 24 h the first start falls between 20:00 and 06:00 UTC in about 8% of runs; the squared weighting then moves later starts toward office hours by at most 3 h a day, so a run can keep several episodes at night (simulated: about 1% of runs have all of their first eight episodes between 20:00 and 06:00 UTC). At intervals that divide 24 hours the starts settle into fixed daily phases (simulated at 8 h: around 08:00, 16:00 and 00:00 UTC, so one episode in three runs near midnight; about 37% of starts fall between 20:00 and 06:00 UTC). At other intervals the due time drifts through the day and the window can fall at night (16-hour test: 3 of 10 starts between 22:00 and 01:00 UTC; simulated about a third).

**Episode timestamps.** An episode is one more logon pushed into the queue of operator steps, exactly like an ordinary logon: at each timestamp of either input the earliest due step is written first. Its four to eight records (denials, grant, optional job start, one removal) therefore occupy timestamps that would otherwise have started a new logon or written the next backup-lane record, which then moves to the following timestamp. No timestamp is discarded, the record count does not depend on the mode, and no background logon, session or retention step of the episode's operator or anyone else is cancelled or re-timed beyond that one-record shift.

**Variation.** Each episode picks a Backup Administrator other than the previous episode's who is not in a web UI session (weighted by logon weight, like the background cleanup; the episode then holds a session like any logon), that operator's primary (workstation) address, and a VM other than the previous episode's. The number of denials, the gaps between attempts, the delay before the removal and the chance that the logon also starts a backup job follow the same distributions as ordinary logons and cleanup.

**Changed state.** A removed point is gone; the VM's next job session creates a new one, and retention continues from the reduced count.

**Detection idea.** Correlate per `user.name`: two or more 44002 from one `SourceIpAddress`, a 44003 from it, then a user-initiated 10050 within 30 minutes of the first denial. A valid session after a guessed password immediately destroying backups is a ransomware-preparation pattern.

**Background overlap.** Every event ID, operator, operator/address pair, VM and repository used by the chain appears in ordinary activity of both modes, as do repeated denials by one operator within minutes, grants after denials, and point removals shortly after logon. Only the complete ordered sequence is exclusive to episodes: an ordinary removal that would complete it, including a later removal by the episode's operator inside the episode's window, is skipped at its own time and the point stays until retention or a later cleanup removes it (3-4 per seven days in the debug captures; Veeam has no failed-removal event in this profile, so there is no outcome to change). The timestamp goes to the next record; event times, the operator and every other event are unchanged, and other operators' removals in the same window are unaffected.

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

Operators (names, addresses, logon weight, typo rate) and jobs (names, IDs, retention, VMs) live in `samples/operators.json` and `samples/jobs.json`.

### Output Parameters

The shipped configuration writes `output/events.json` relative to the generator. It has no `${params.*}` or `${secrets.*}` placeholders; change `output.file.path` or replace the output plugin to deliver elsewhere.

## Usage

Live generation at the configured rate:

```bash
eventum generate --path generators/backup-veeam-vbr/generator.yml --id vbr --live-mode true
```

Batch generation: set `start` and `end` of the `oscillator` in all seven `patterns/*.yml` files to the same range, with `start` at 00:00 UTC so the hour bands stay in place (for example `start: "2026-09-01T00:00:00Z"` and `end: "2026-09-08T00:00:00Z"`), then run:

```bash
eventum generate --path generators/backup-veeam-vbr/generator.yml --id vbr --live-mode false --keep-order true
```

Performance: a 14-day batch run writes about 32,000 records in 10-13 s on one core (about 2,500-3,100 events/s, including start-up).

## Sample Output

The removal that completes the first episode of the seven-day default capture (`anomaly_mode: true`), one line of `output/events.json`:

```json
{"@timestamp": "2026-09-01T18:42:20.609177+00:00", "ecs": {"version": "8.17.0"}, "event": {"kind": "event", "module": "veeam", "dataset": "veeam.vbr.syslog", "code": "10050", "category": ["file"], "action": "restore_point_deleted", "type": ["deletion"], "outcome": "success", "original": "1 2026-09-01T18:42:20.609177+00:00 VBRSRV01 Veeam_MP - - [origin enterpriseId=\"31023\"] [categoryId=0 instanceId=10050 OibID=\"b7c7dc10-4901-46d1-a938-5c3ab7492ee2\" OriginalOibID=\"b7c7dc10-4901-46d1-a938-5c3ab7492ee2\" VmRef=\"vm-218\" VmName=\"SRV-INF18\" ServerName=\"pdcsrv01.contoso.test\" DateTime=\"08/27/2026 07:11:45\" IsCorrupted=\"False\" Platform=\"0\" StorageSize=\"19150786560\" RepositoryID=\"88788f9e-d8f5-4eb4-bc4f-9b3f5403bcec\" IsFull=\"True\" UserFullInfo=\"\u003cModifiedUserInfo fullName=\"TECH\\veeamadmin\" loginType=\"0\" /\u003e\" VbrHostName=\"vbrsrv01.contoso.test\" VbrVersion=\"13.1.1.18\" Version=\"1\" Description=\"Restore point for VM \u0027SRV-INF18\u0027 has been removed by user TECH\\veeamadmin.\"]"}, "message": "Restore point for VM \u0027SRV-INF18\u0027 has been removed by user TECH\\veeamadmin.", "host": {"name": "VBRSRV01"}, "user": {"name": "veeamadmin"}, "veeam": {"event_id": 10050, "app": "Veeam_MP", "severity": "warning", "enterprise_id": 31023, "category_id": 0, "parameters": {"DateTime": "08/27/2026 07:11:45", "Description": "Restore point for VM \u0027SRV-INF18\u0027 has been removed by user TECH\\veeamadmin.", "IsCorrupted": "False", "IsFull": "True", "OibID": "b7c7dc10-4901-46d1-a938-5c3ab7492ee2", "OriginalOibID": "b7c7dc10-4901-46d1-a938-5c3ab7492ee2", "Platform": "0", "RepositoryID": "88788f9e-d8f5-4eb4-bc4f-9b3f5403bcec", "ServerName": "pdcsrv01.contoso.test", "StorageSize": "19150786560", "UserFullInfo": "\u003cModifiedUserInfo fullName=\"TECH\\veeamadmin\" loginType=\"0\" /\u003e", "VbrHostName": "vbrsrv01.contoso.test", "VbrVersion": "13.1.1.18", "Version": "1", "VmName": "SRV-INF18", "VmRef": "vm-218"}}}
```

## Limitations

- Scheduled sessions carry no 110: Veeam documents 110 only for sessions started by a user (`Flags=1`). Every session succeeds (`JobResult=0`, `WillBeRetried=False`), and every point is a full backup (`IsFull=True`).
- Records ride on input timestamps, so steps of one logon are seconds to minutes apart rather than milliseconds (repeated denials: median 91 s), and a VM's processing time is the wait for the next backup timestamp. Lowering the pattern ratios stretches both.
- Episodes add their own records on top of the background, so counts of the chain's parts are higher with `anomaly_mode: true` by the episodes' own records only: one per episode for each part (seven a week at the default interval), and one to four repeated denials per episode. Measured over 22 background-only and 9 default captures (7 days each), as background mean, default mean and the difference in background standard deviations: two denials followed by a grant from one address 32.7 vs 37.8 (+0.8); repeated denials within 10 minutes 58.6 vs 69.3 (+0.8); a grant followed by a removal by that user within 30 minutes 35.2 vs 41.2 (+1.2); user removals 45.1 vs 49.6 (+0.5). An independent review over 22 background-only and 16 default captures measured larger shifts for the first two, +1.6 and +1.8 standard deviations (+8 and +18 counts), and +0.7 for the other two; with the episodes' own records removed the default captures match the background. Shorter intervals add proportionally more (16 h: ten episodes a week; at 8 h the episodes' own short gaps between attempts can make a single comparison flag short same-user gaps).
- Episodes are carried out by Backup Administrators from their primary address only, never over VPN. Every such operator/address pair logs on and is denied at least once in each background-only capture (22 captures: at least 43 logons and 1 to 5 denials per pair); the full two-denials-then-grant pattern of a given pair is not present every week.
- Rates, retention counts, team and inventory size and the hour curves are design choices, not production measurements. The hour curves are in UTC; episode start hours use a copy of the `ops` curve inside the template.
- Timestamps are UTC with microseconds; Veeam's examples use the server's local offset. `DateTime` is written in UTC.
- Byte-for-byte parity with a real capture and compatibility with a specific SIEM parser are not verified. XML-valued parameters keep the literal inner quotes shown in Veeam's examples, so a strict RFC 5424 parser may reject them.
- 44002 always uses Reason 1 (unauthenticated). Veeam's raw 44002 example omits `Reason`, which its parameter table documents.
- An episode always removes exactly one point, while ordinary cleanup removes one to three (one in 70% of cases).
- The secondary repository and its point predate the stream and are retired once; their creation is not modeled.

## References

- Veeam B&R 13.1 event reference: [110 Backup Job Started](https://helpcenter.veeam.com/docs/vbr/events/event_110.html), [190 Backup Job Finished](https://helpcenter.veeam.com/docs/vbr/events/event_190.html), [10010 Restore Point Created](https://helpcenter.veeam.com/docs/vbr/events/event_10010.html), [10050 Restore Point Deleted](https://helpcenter.veeam.com/docs/vbr/events/event_10050.html), [28200 Backup Repository Deleted](https://helpcenter.veeam.com/docs/vbr/events/event_28200.html), [44002 User Authorization Denied](https://helpcenter.veeam.com/docs/vbr/events/event_44002.html), [44003 User Authorization Granted](https://helpcenter.veeam.com/docs/vbr/events/event_44003.html).
- [Removing backup repositories](https://helpcenter.veeam.com/docs/vbr/userguide/repo_delete.html).

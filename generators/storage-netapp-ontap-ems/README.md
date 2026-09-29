# NetApp ONTAP EMS syslog

Synthetic NetApp ONTAP 9.12.1 Event Management System (EMS) notifications from a two-node cluster, forwarded to a syslog destination in the default `legacy-netapp` format. It is for SIEM engineers who need realistic storage administration traffic: ZAPI Snapshot copies made by backup applications, failed management logins, account lockouts and anti-ransomware state changes. ONTAP `audit.log` and file-access auditing are out of scope.

## Event Types

| EMS event | Share | ECS category | Meaning |
|---|---:|---|---|
| `zapi.snapshot.success` | 96.6% | `configuration` | A backup application created a Snapshot copy through ZAPI |
| `security.invalid.login` | 2.0% | `authentication` | Failed login to the cluster over `ssh`, `http` or `ontapi` |
| `arw.volume.state` | 1.1% | `configuration` | Anti-ransomware state of a volume changed (`disabled`, `enabled`) |
| `useradmin.lockedout.user` | 0.3% | `authentication` | Account locked after the configured number of failures |

Shares are for the default configuration with `anomaly_mode: true`; without episodes, failed logins are 1.3-1.7%, anti-ransomware changes 1.0-1.1% and lockouts 0.1-0.3%.

## Volume and Timing

About 1,100 records a day. Timestamps are UTC with one-second precision, and records are in time order.

| Activity | Per day | Hours (UTC) |
|---|---:|---|
| ZAPI Snapshot copies of 48 volumes | about 1,070 | Around the clock, evenly |
| Failed logins of administrators | 7-10 | Working-day curve: 07:00-18:00 full rate, 18:00-22:00 about 40%, night about 15% |
| Failed logins of service accounts | 5-9 | Around the clock |
| Anti-ransomware pauses (`disabled`, later `enabled`) | About 5-6 pairs | Working-day curve |
| Account lockouts | 1.5-3 | Follow the failed logins |

- Snapshot copies: each volume in `samples/volumes.csv` gets copies in proportion to its `snapshot_weight` (on average every 15 minutes to 2 hours for database, log and virtual machine volumes, about every 4 hours for file shares, daily for archives and boot volumes).
- Administrators (`admin_users`) mistype passwords now and then: a session holds one failure (70%), two (17%), three (9%) or four (4%), a few seconds apart (median 7 s). The first three administrators are the busiest accounts. Each administrator mostly uses one application (`ssh`, or `http` for System Manager) and nine logins in ten reach the cluster management interface on the first node.
- Service accounts (`service_users`) fail in retry loops, one to six failures about 40 s apart; each account uses one application (`ontapi` for the first two, `http` otherwise).
- ONTAP counts consecutive failures. An account that reaches `lockout_attempts` is locked one to three seconds after the last failure and makes no attempt until an administrator unlocks it, which EMS does not log (median two hours). A successful login, which EMS does not log either, resets the counter; after a session that gives up, the counter stays until the account's next successful login (about an hour later).
- Anti-ransomware protection is paused on a volume and turned back on after a median of about 50 minutes (5 minutes to several hours). Volumes with a high `arw_weight` in `samples/volumes.csv` (`vol_backup_stage`, `vol_ci_cache`, `vol_scans`, which receive compressed or encrypted bulk data) are paused one to two times a day each; other volumes rarely. A few volumes start in dry-run (learning) mode and switch to `enabled` within the first days.

## Anomaly Chain

`anomaly_mode` defaults to `true`. With `false`, the generator produces only the background above, with no complete chain.

Each episode models a password attack on the management interface followed by switching off ransomware protection:

1. `security.invalid.login` for administrator A, repeated until the lockout threshold (`lockout_attempts`, default 3), a few seconds apart.
2. `useradmin.lockedout.user` for A, one to three seconds after the last failure, on the same node.
3. A few minutes later, one or two `security.invalid.login` records for a different administrator B (password spraying), below B's lockout threshold.
4. Several minutes after that, `arw.volume.state` with `op` `disabled` for volume V.
5. Restoration: `arw.volume.state` with `op` `enabled` for V after a hold drawn from the same distribution as ordinary pauses; A is unlocked on the same schedule as in the background, and B's attempts end with a successful login that resets B's counter, as most ordinary sessions do.

Linking fields: `user.name` (`netapp.ems.parameters.userName` / `username`) ties steps 1-2 and separates B in step 3; `netapp.ems.parameters.volumeName` and `volumeUuid` tie steps 4-5. From the first failure to the disable a chain spans about 3-40 minutes and always within one hour; the re-enable follows later (median about 50 minutes, sometimes hours). There is no client IP, because these EMS messages do not carry one.

Episode actors come from the busiest accounts and volumes: A and B are two of the first three administrators, logging in over their usual application to the first node, and V is one of the frequently paused volumes. A differs from the previous episode's A, V from the previous V, and B from the previous B when that account is free.

Recurrence: the first episode starts within `min(anomaly_interval_hours, 24 h)` of the start, at an hour drawn from the administrators' working-day curve. Each later episode is due one interval after the previous actual start and starts within a window of `min(interval / 4, 6 h)` around that time, at an hour weighted toward working hours. Missed episodes are never caught up.

Every step is also ordinary background in both modes: every administrator fails logins, repeated failures within seconds are common, accounts are locked out every day, several accounts fail within minutes of each other, and the same volumes have their protection paused and turned back on. Only the complete ordered chain is kept out of the background: an ordinary pause that would complete it does not happen. With `anomaly_mode: true` each episode adds its own records, so a day with an episode has about one more lockout, four to five more failed logins and about half a pause of protection more than a day without.

Detection idea: alert when, within one hour on the same cluster, an account is locked out after repeated failures, another account then fails to log in, and anti-ransomware protection is disabled on a volume. Each signal alone is routine; the ordered combination is the finding.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Meaning |
|---|---|---|
| `anomaly_mode` | `true` | Add recurring episodes to the background; `false` produces background only |
| `anomaly_interval_hours` | `24` | Episode interval in hours, 6-8760 |
| `cluster_name` | `cluster1` | Admin Vserver name in failed-login messages |
| `nodes` | `[cluster1-01, cluster1-02]` | Node hostnames; the first hosts the cluster management interface and receives most logins |
| `admin_users` | `[admin, jsmith, mlee, kpatel, storageops]` | Human administrators, at least three, busiest first, distinct from the service accounts |
| `service_users` | `[harvest, snapcenter, ansible]` | Service accounts that log in through `ontapi` or `http` |
| `lockout_attempts` | `3` | Failures that lock an account (`attempts` in the lockout message), 2-10 |

Volumes, their Vservers and owning nodes come from `samples/volumes.csv`: edit it to change the volume set, `snapshot_weight` to change each volume's share of Snapshot copies, and `arw_weight` to change how often its protection is paused (volumes with `arw_weight` of 10 or more are the frequently paused ones and must number at least two). Volume and Vserver UUIDs are generated once per run.

### Output Parameters

The shipped config writes `output/events.json` with the `json` formatter and needs no `${params.*}` or `${secrets.*}`. To send events elsewhere, replace the `output` section, for example:

```yaml
output:
  - opensearch:
      hosts: ["${params.opensearch_url}"]
      username: ${params.opensearch_user}
      password: ${secrets.opensearch_password}
      index: netapp-ontap-ems
```

## Usage

Live mode:

```bash
eventum generate --path generators/storage-netapp-ontap-ems/generator.yml --id ontap --live-mode true
```

Batch mode needs a finite window: in every file under `patterns/`, set `start` to a date at midnight UTC (for example `start: "2026-09-01T00:00:00Z"`) and `end` to the window length (for example `end: "+96h"`), then run:

```bash
eventum generate --path generators/storage-netapp-ontap-ems/generator.yml --id ontap --live-mode false
```

The daily volume and hour curve are set in `patterns/` (`auto.yml` for Snapshot copies and service accounts, `office-*.yml` for administrators); scale their `ratio` values together to change the volume. The file output is overwritten when a run starts. In live mode, records that follow another within seconds (repeated failures, a lockout) can reach the output a minute or two after their own timestamp.

For a real forwarding path, the EMS destination and filter must forward these events; `security.invalid.login` is ALERT, the lockout is ERROR, the others are NOTICE. KUMA 4.2 lists ONTAP 9.12 syslog normalization, but this pack has not been tested against it.

Performance: 14 days of data (about 15,400 records) generate in about 6 seconds.

## Limitations

- No captured ONTAP syslog line was available. `event.original` is assembled from the documented `legacy-netapp` grammar `<PRIVAL>TIMESTAMP [HOSTNAME:Event-name:Event-severity]: MSG` (RFC 3164 timestamp, hostname only) and the 9.12.1 catalog message templates, filled with the documented parameters. RFC 5424 output is not emitted.
- The severity token is written in lower case (`alert`, `error`, `notice`); its case is not documented. Facility `user` (1) is a scenario choice, so priorities are 9, 11 and 13.
- `netapp.ems.parameters` uses the catalog parameter names. The ECS mapping is inferred; there is no Elastic integration for ONTAP EMS.
- Only four EMS events are produced; a real cluster also sends hardware, WAFL, SnapMirror and other notifications. Successful logins, account unlocks and failures on an already locked account are not produced: the catalog documents no success message, and unlocking is an administrator action outside this subset.
- Snapshot names (`backup.<date>_<time>`), rates and hold durations are assumptions, not measured production volumes. Anti-ransomware pauses on the three bulk-data volumes are more frequent than in a typical cluster.
- There is no weekly cycle: weekends look like weekdays, and the working-day curve is fixed in UTC.
- With `anomaly_mode: true` each episode adds its own records, so lockouts, failed logins and anti-ransomware pauses are about one lockout, four to five failures and half a pause per episode higher than in the background alone.

## Sample Output

The episode's `disabled` change from a default run, copied verbatim (the output escapes `<` and `>` as `\u003c` and `\u003e`; timestamps are UTC):

```json
{"@timestamp": "2026-09-01T11:08:56+00:00", "ecs": {"version": "8.17.0"}, "event": {"action": "arw.volume.state", "category": ["configuration"], "kind": "event", "original": "\u003c13\u003eSep  1 11:08:56 [cluster1-01:arw.volume.state:notice]: Anti-ransomware state was changed to \"disabled\" on volume \"vol_ci_cache\" (UUID: \"5c18ce97-b4b6-4f41-bbb2-4d30c695d6dd\") in Vserver \"svm_nfs01\" (UUID: \"84e08f81-2502-4a44-bd5d-da6a31aec8fc\").", "outcome": "success", "type": ["change"]}, "host": {"name": "cluster1-01"}, "log": {"syslog": {"facility": {"code": 1, "name": "user"}, "priority": 13, "severity": {"code": 5, "name": "notice"}}}, "netapp": {"ems": {"message": "Anti-ransomware state was changed to \"disabled\" on volume \"vol_ci_cache\" (UUID: \"5c18ce97-b4b6-4f41-bbb2-4d30c695d6dd\") in Vserver \"svm_nfs01\" (UUID: \"84e08f81-2502-4a44-bd5d-da6a31aec8fc\").", "name": "arw.volume.state", "parameters": {"op": "disabled", "volumeName": "vol_ci_cache", "volumeUuid": "5c18ce97-b4b6-4f41-bbb2-4d30c695d6dd", "vserverName": "svm_nfs01", "vserverUuid": "84e08f81-2502-4a44-bd5d-da6a31aec8fc"}, "severity": "notice"}}}
```

## References

- [ONTAP 9.12.1 `event notification destination create`: syslog message, timestamp and hostname formats](https://docs.netapp.com/us-en/ontap-cli-9121/event-notification-destination-create.html)
- [ONTAP 9.12.1 EMS `security.invalid.login`](https://docs.netapp.com/us-en/ontap-ems-9121/security-invalid-events.html)
- [ONTAP 9.12.1 EMS `useradmin.lockedout.user`](https://docs.netapp.com/us-en/ontap-ems-9121/useradmin-lockedout-events.html)
- [ONTAP 9.12.1 EMS `arw.volume.state`](https://docs.netapp.com/us-en/ontap-ems-9121/arw-volume-events.html)
- [ONTAP 9.12.1 EMS `zapi.snapshot.success`](https://docs.netapp.com/us-en/ontap-ems-9121/zapi-snapshot-events.html)
- [NetApp KB: event forwarding to a syslog server](https://kb.netapp.com/on-prem/ontap/Ontap_OS/OS-KBs/Event_forwarding_to_a_Syslog_server)
- [KUMA 4.2 supported sources](https://support.kaspersky.ru/kuma/4.2/255782)

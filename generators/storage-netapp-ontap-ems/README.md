# NetApp ONTAP EMS syslog

Synthetic NetApp ONTAP 9.12.1 Event Management System (EMS) notifications from a two-node cluster, forwarded to a syslog destination in the default `legacy-netapp` format. It is for SIEM engineers who need realistic storage administration traffic: failed management logins, account lockouts, anti-ransomware state changes and ZAPI Snapshot copies. ONTAP `audit.log` and file-access auditing are out of scope.

## Event Types

Shares are measured on the final four-day default capture (`anomaly_mode: true`, 1146 events). Background-only captures of the same window hold 1045-1122 events with 74-78% Snapshot, 14-18% failed login, 4-6% anti-ransomware and 2-3% lockout records.

| EMS event | Share | ECS category | Meaning |
|---|---:|---|---|
| `zapi.snapshot.success` | 73.2% | `configuration` | A backup application created a Snapshot copy through ZAPI |
| `security.invalid.login` | 16.8% | `authentication` | Failed login to the cluster over `ssh`, `http` or `ontapi` |
| `arw.volume.state` | 6.5% | `configuration` | Anti-ransomware state of a volume changed (`disabled`, `enabled`) |
| `useradmin.lockedout.user` | 3.5% | `authentication` | Account locked after the configured number of failures |

Background processes are independent and random:

- Five administrators (office-hours login sessions) and three service accounts (around the clock, one application each) log in at their own rates. Successful logins produce no EMS record. A session either succeeds after zero to six failures, which resets the failure counter, or gives up. An account that reaches `lockout_attempts` failures is locked and stays silent until an administrator unlocks it, which EMS does not log.
- Each of 16 volumes (`samples/volumes.csv`) gets ZAPI Snapshot copies at log-normal intervals and occasional anti-ransomware maintenance: `disabled`, then `enabled` again after a log-normal hold. Some volumes start in dry-run mode and later switch to `enabled`.

## Anomaly Chain

`anomaly_mode` defaults to `true`. With `false`, the generator produces only the background above, with no complete chain.

Each episode models a password attack on the management interface followed by switching off ransomware protection:

1. `security.invalid.login` for administrator A, repeated until the lockout threshold (`lockout_attempts`, default 3).
2. `useradmin.lockedout.user` for A, one to three seconds after the last failure, on the same node.
3. After a few minutes, one or two `security.invalid.login` records for a different account B (password spraying), below B's lockout threshold.
4. After several more minutes, `arw.volume.state` with `op` `disabled` for volume V.
5. Restoration: `arw.volume.state` with `op` `enabled` for V after a hold drawn from the same distribution as ordinary maintenance.

Linking fields: `user.name` (`netapp.ems.parameters.userName` / `username`) ties steps 1-2 and separates B in step 3; `netapp.ems.parameters.volumeName` and `volumeUuid` tie steps 4-5. The chain spans about 4-18 minutes in the measured captures; every step happens within one hour. There is no client IP, because these EMS messages do not carry one.

Recurrence: the first episode is due one `anomaly_interval_hours` after the start of the source clock (default 24 hours, minimum 6). When an episode is due, it starts after an exponentially distributed delay (mean 20 minutes), once A and V are free. The next episode is due one interval after that actual start; missed episodes are never caught up. A is always a different administrator than in the previous episode, B and V differ from the previous episode's values when possible, and A must have no pending failures when chosen.

Every step is also ordinary background in both modes: every account fails logins, repeated failures by one account within seconds or minutes are common, every account can be locked out, several accounts fail within minutes of each other, and every volume has its anti-ransomware protection disabled and re-enabled. Only the complete ordered chain is kept out of the background: an ordinary `disabled` change that would complete it is skipped.

Detection idea: alert when, within one hour on the same cluster, an account is locked out after repeated failures, another account then fails to log in, and anti-ransomware protection is disabled on a volume. Each signal alone is routine; the ordered combination is the finding.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Meaning |
|---|---|---|
| `anomaly_mode` | `true` | Add recurring episodes to the background; `false` produces background only |
| `anomaly_interval_hours` | `24` | Episode interval in source hours, 6-8760 |
| `cluster_name` | `cluster1` | Admin Vserver name in failed-login messages |
| `nodes` | `[cluster1-01, cluster1-02]` | Node hostnames; the first hosts the cluster management interface and receives most logins |
| `admin_users` | `[admin, jsmith, mlee, kpatel, storageops]` | Human administrators, at least three, distinct from the service accounts |
| `service_users` | `[harvest, snapcenter, ansible]` | Service accounts that log in through `ontapi` or `http` |
| `lockout_attempts` | `3` | Failures that lock an account (`attempts` in the lockout message), 2-10 |

Volumes, their Vservers and owning nodes come from `samples/volumes.csv`. Volume and Vserver UUIDs are generated once per run.

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

Batch mode needs a bounded input: add `start` and `end` to the `cron` input, then run:

```bash
eventum generate --path generators/storage-netapp-ontap-ems/generator.yml --id ontap --live-mode false
```

The file output is overwritten when a run starts.

## Limitations

- No captured ONTAP syslog line was available. `event.original` is assembled from the documented `legacy-netapp` grammar `<PRIVAL>TIMESTAMP [HOSTNAME:Event-name:Event-severity]: MSG` (RFC 3164 timestamp, hostname only) and the 9.12.1 catalog message templates, filled with the documented parameters. RFC 5424 output is not emitted.
- The severity token is written in lower case (`alert`, `error`, `notice`); its case is not documented. Facility `user` (1) is a scenario choice, so priorities are 9, 11 and 13.
- `netapp.ems.parameters` uses the catalog parameter names. The ECS mapping is inferred; there is no Elastic integration for ONTAP EMS.
- Successful logins, account unlocks and failures on an already locked account are not modelled: the catalog documents no success message, and unlocking is an administrator action outside this subset. The failure counter resets on a successful login and on unlock.
- Snapshot names (`backup.<date>_<time>`), rates and hold durations are training assumptions, not measured production volumes. The anti-ransomware maintenance rate is higher than in a typical cluster so that the chain's steps are common in the background.
- The EMS destination and filter must forward these events; `security.invalid.login` is ALERT, the lockout is ERROR, the others are NOTICE. KUMA 4.2 lists ONTAP 9.12 syslog normalization, but this pack has not been tested against it.

## Sample Output

The episode's `disabled` change from the final default capture (line 273), copied verbatim (the output escapes `<` and `>` as `\u003c` and `\u003e`; timestamps are UTC):

```json
{"@timestamp": "2026-09-21T00:24:16+00:00", "ecs": {"version": "8.17.0"}, "event": {"action": "arw.volume.state", "category": ["configuration"], "kind": "event", "original": "\u003c13\u003eSep 21 00:24:16 [cluster1-01:arw.volume.state:notice]: Anti-ransomware state was changed to \"disabled\" on volume \"vol_home01\" (UUID: \"90708e43-b052-4fd1-b5e3-1c1d9bddb62a\") in Vserver \"svm_cifs01\" (UUID: \"70cb3884-b460-42ef-a14d-b285d7282e3d\").", "outcome": "success", "type": ["change"]}, "host": {"name": "cluster1-01"}, "log": {"syslog": {"facility": {"code": 1, "name": "user"}, "priority": 13, "severity": {"code": 5, "name": "notice"}}}, "netapp": {"ems": {"message": "Anti-ransomware state was changed to \"disabled\" on volume \"vol_home01\" (UUID: \"90708e43-b052-4fd1-b5e3-1c1d9bddb62a\") in Vserver \"svm_cifs01\" (UUID: \"70cb3884-b460-42ef-a14d-b285d7282e3d\").", "name": "arw.volume.state", "parameters": {"op": "disabled", "volumeName": "vol_home01", "volumeUuid": "90708e43-b052-4fd1-b5e3-1c1d9bddb62a", "vserverName": "svm_cifs01", "vserverUuid": "70cb3884-b460-42ef-a14d-b285d7282e3d"}, "severity": "notice"}}}
```

## References

- [ONTAP 9.12.1 `event notification destination create`: syslog message, timestamp and hostname formats](https://docs.netapp.com/us-en/ontap-cli-9121/event-notification-destination-create.html)
- [ONTAP 9.12.1 EMS `security.invalid.login`](https://docs.netapp.com/us-en/ontap-ems-9121/security-invalid-events.html)
- [ONTAP 9.12.1 EMS `useradmin.lockedout.user`](https://docs.netapp.com/us-en/ontap-ems-9121/useradmin-lockedout-events.html)
- [ONTAP 9.12.1 EMS `arw.volume.state`](https://docs.netapp.com/us-en/ontap-ems-9121/arw-volume-events.html)
- [ONTAP 9.12.1 EMS `zapi.snapshot.success`](https://docs.netapp.com/us-en/ontap-ems-9121/zapi-snapshot-events.html)
- [NetApp KB: event forwarding to a syslog server](https://kb.netapp.com/on-prem/ontap/Ontap_OS/OS-KBs/Event_forwarding_to_a_Syslog_server)
- [KUMA 4.2 supported sources](https://support.kaspersky.ru/kuma/4.2/255782)

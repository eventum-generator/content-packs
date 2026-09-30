# Cisco Secure Firewall Management Center Audit

Generates Cisco Secure Firewall Management Center (FMC) 7.4 audit Syslog records as ECS JSON: web-interface page views, network object creation, NAT policy saves, and the system pre-deploy task records that follow a save. The FMC-originating Syslog line is kept verbatim in `event.original`, in the forms of Cisco TechNote 221019 (FMCv 7.4.0). Managed FTD connection, intrusion and file events are a separate stream.

## Event Types

Shares are typical of default output (`anomaly_mode: true`). All classes occur in both modes.

| Native `Sender` / `Subsystem`, `Action` | `event.action` | Share | Category |
|---|---|---:|---|
| `sfdccsm` / `Devices > NAT > NGFW NAT Policy Editor`, `Page View` | `page-view` | 31.0% | web |
| `sfdccsm` / `Devices > NAT`, `Page View` | `page-view` | 18.9% | web |
| `mojo_server.pl` / `/ui/ddd/`, `Page View` | `page-view` | 13.3% | web |
| `sfdccsm` / `Devices > NAT > NAT Policy Editor`, `Save Policy <policy>` | `nat-policy-save` | 11.8% | configuration |
| `ActionQueueScrape.pl` / `Login`, `Login Success` (`csm_processes@Default User IP`) | `login-success` | 10.0% | authentication |
| `ActionQueueScrape.pl` / `Task Queue`, `Successful task completion : Pre-deploy Global Configuration Generation` (`admin@localhost`) | `task-completion` | 10.0% | configuration |
| `sfdccsm` / `Objects > Object Management > NetworkObject`, `create <object>` | `network-object-create` | 5.0% | configuration |

Twenty-four administrator accounts (`samples/admins.json`) work in web-interface sessions. A session opens on the `/ui/ddd/` page or the NAT list and holds one to about twenty actions seconds to minutes apart (most often a few); after it the account pauses (median about 17 minutes, up to several hours) before its next session. The account `weight` sets how often it works: the six busiest accounts write about 850 to 1,100 records in two weeks, the quietest about 250. A session comes from the account's usual workstation address or, in about 15% of sessions, a second address.

- **Page views** of the NAT list, the NAT policy editor and the `/ui/ddd/` web page (the sources do not name that page).
- **Network object creation** with a new name (`<prefix>-<number>`, prefixes in `samples/object_prefixes.json`). More than half of the creations are followed later in the session by a NAT policy save (the object put into a rule).
- **NAT policy save** of one of ten policies (`samples/nat_policies.json`), always from the editor, which is shown again right after, as in the Cisco sample. About a fifth of saves are saved again later in the session.

In 85% of saves the system then logs `csm_processes` `Login Success` and the pre-deploy task completion right after it, as in the Cisco sample. Rates, durations and the action mix are synthetic workload choices, not measured FMC production frequencies.

## Volume and Timing

About 1,250 records a day (+/- 3% from day to day), following a working day in UTC: activity rises from 04:00, peaks at about 130 records an hour around 11:00 and fades out by 20:00; between 21:00 and 03:00 there are a few records an hour (about 1-6). Configuration changes (object creation, policy saves and the system records after them) happen between 05:00 and 19:00 UTC; outside working hours the records are page views of administrators taking a short look. Sessions of several administrators overlap and their records interleave.

## Anomaly Chain

`anomaly_mode` defaults to `true`. With `false` the generator emits only the background above, which never holds the complete chain; every step still occurs there on its own and in partial sequences, from the same accounts and addresses.

Sequence, one episode (one session of one of the six busiest accounts, from one of that account's usual addresses):

1. Zero to two page views.
2. `NetworkObject, create <object>`: a new network object.
3. Zero to two page views, then the NAT policy editor and `Save Policy <P>`; the editor is shown again, and the system login and pre-deploy task follow as for any save.
4. Zero to four page views.
5. `Save Policy <P>` of the same policy: the change is reverted, followed again by the editor view and the pre-deploy task.
6. Zero to two page views; the session ends (the web interface writes no logout record).

Linking fields: `user.name` and `source.ip` (the `User_Name@User_IP` sender part) across steps 2, 3 and 5, and the policy name (`cisco.fmc.audit.policy`, parsed from `Save Policy <P>`) across steps 3 and 5. The system records carry `csm_processes@Default User IP` and `admin@localhost` and link to a save only by time. The span from the first matching create to the second save is about 5 to 50 minutes; the longest ones start at an earlier ordinary create by the same account and address. Gaps between actions follow the same distributions as ordinary sessions, and the account then pauses as after any session.

Recurrence: `anomaly_interval_hours` sets the spacing (default 24; whole days, 24 to 8760). The first episode starts within the first 24 hours; each next one starts within a window of six hours centred one interval after the previous start. Start times favour the busiest working hours (weighted by the square of the activity curve) and fall between 06:00 and 17:00 UTC. Missed episodes are not replayed. Each episode picks a different account (weighted by activity, among accounts out of session with their pause over) and a different policy than the previous one, and a new object name. With `anomaly_mode: true` each episode adds its own records (a session of about 6 to 20 records with the system records of its saves), so counts of creates, saves and repeated saves are about one per episode higher.

Detection idea: one account creates a network object, saves a NAT policy and saves the same policy again within an hour - a NAT change pushed to the pre-deploy stage and reverted soon after, for example a short-lived exposure of an internal host. Each step alone, and each pair of steps, is ordinary administration here. Background never completes the sequence: when an ordinary save would complete it (the same account from the same address created an object at most an hour earlier and saved the same policy since), that save goes to another policy instead, which happens to about one save in five. The same save after the hour or from another address is written as usual. The audit record does not show what changed, so the revert is inferred from the repeated save.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Description |
|---|---|---|
| `anomaly_mode` | `true` | Include periodic anomaly episodes; `false` gives background only |
| `anomaly_interval_hours` | `24` | Hours between episode starts; a multiple of 24 from 24 to 8760, other values fail validation |
| `management_center` | `firepower` | FMC hostname in the Syslog header and `observer.hostname` |

To use your own names, edit the sample files: accounts in `samples/admins.json` (`user`, `ip`, `alt_ip`, `weight` from 1 to 6; episodes use accounts with weight 4 or more, at least two needed), NAT policies in `samples/nat_policies.json` (`name`, at least two) and object name prefixes in `samples/object_prefixes.json` (`prefix`). The daily volume and hour curve are set in `patterns/office.yml` and `patterns/floor.yml` (UTC).

### Output Parameters

The shipped output writes `output/events.json` and needs no credentials. To send events elsewhere, replace the output and pass values through top-level placeholders, for example:

```yaml
output:
  - opensearch:
      hosts:
        - ${params.opensearch_host}
      username: ${params.opensearch_user}
      password: ${secrets.opensearch_password}
      index: fmc-audit
```

A collector that expects the native Syslog line should read `event.original`.

## Usage

Live mode:

```bash
eventum generate --path generators/security-cisco-fmc-audit/generator.yml --id fmc --live-mode true
```

Batch mode, as fast as possible:

```bash
eventum generate --path generators/security-cisco-fmc-audit/generator.yml --id fmc --live-mode false
```

The time patterns run until stopped. For a finite batch window, set `start` to a midnight and `end` in both `patterns/*.yml` files, for example `start: "2026-09-01T00:00:00Z"` and `end: "2026-09-15T00:00:00Z"` for two weeks.

Performance: about 2,000 events per second in batch mode (two weeks in under 10 seconds).

## Sample Output

An episode's second save (step 5), from default output:

```json
{"@timestamp": "2026-09-02T10:47:26+00:00", "cisco": {"fmc": {"audit": {"message": "Save Policy NATPolicy", "policy": "NATPolicy", "sender": "sfdccsm", "subsystem": "Devices > NAT > NAT Policy Editor", "tag": "FMC-AUDIT", "user": "akumar", "user_ip": "10.1.21.5"}}}, "ecs": {"version": "8.17.0"}, "event": {"action": "nat-policy-save", "category": ["configuration"], "dataset": "cisco_fmc.audit", "kind": "event", "module": "cisco_fmc", "original": "Sep 02 10:47:26 firepower: [FMC-AUDIT] sfdccsm: akumar@10.1.21.5, Devices > NAT > NAT Policy Editor, Save Policy NATPolicy", "type": ["change"]}, "message": "Devices > NAT > NAT Policy Editor, Save Policy NATPolicy", "observer": {"hostname": "firepower", "product": "Secure Firewall Management Center", "vendor": "Cisco", "version": "7.4.0"}, "process": {"name": "sfdccsm"}, "related": {"hosts": ["firepower"], "ip": ["10.1.21.5"], "user": ["akumar"]}, "source": {"ip": "10.1.21.5"}, "user": {"name": "akumar"}}
```

## Limitations

- The only complete native examples are the eight lines of Cisco TechNote 221019 (FMCv 7.4.0). Every generated line uses one of those seven forms; only the user, address, object name, policy name and time vary. The administration guide describes the layout (`Date Time Host: [Tag] Sender: User_Name@User_IP, Subsystem, Action`) and lists many more subsystems, but gives no further verbatim lines, so other menus, object types, deletions, deployments and human logins and logouts are not generated. Real audit streams cover far more of the interface than NAT.
- Failed logins are not modeled: the guide states that audit records of login errors carry neither user nor source address.
- The `[FMC-AUDIT]` tag is the one configured in the TechNote; it is user-defined on a real FMC. The collector-side prefix of the TechNote lines (receive time, `localhost`, sender address) is not emitted. The BSD Syslog header has no year or zone and one-second precision; `@timestamp` supplies the date and the time of day is UTC. The day of month is zero-padded, as in the admin guide sample (`Mar 01`).
- Records that follow at once on a real FMC are further apart here: the editor view after a save and the task completion after the system login are the next record but usually come a few seconds to about a minute and a half later (median about 25 seconds) instead of within a second, and the system login comes a minute or two after the save (median about 1.7 minutes) instead of about 20 seconds.
- Configuration changes are made only in working hours (05:00 to 19:00 UTC); off-hours records are page views only.
- After an object is created, a later save in the hour goes to a different policy than the one already saved more often than it would on a real system, since the same policy is never saved twice there by the same account and address.
- The object name is synthetic and the Syslog record never names the rule or object a save changed; the pre-deploy task records link to a save only by time, as in the source.
- `cisco.fmc.audit.*` is parsed from the line (`policy` and `object` from the action text); `event.*`, `user.*`, `source.*`, `process.*`, `observer.*` and `related.*` are ECS normalization, not source fields. No Elastic integration for FMC audit Syslog was found to mirror.
- KUMA 4.2 lists a Secure Firewall Management Center normalizer for CEF; this pack does not generate CEF and does not claim compatibility with that normalizer. No live capture was available for comparison.

## References

- [Cisco TechNote 221019: configure FMC to send audit logs to a Syslog server (7.4.0 examples)](https://www.cisco.com/c/en/us/support/docs/security/secure-firewall-management-center/221019-configure-fmc-to-send-audit-logs-to-a-sy.html)
- [Cisco Secure FMC Administration Guide 7.4: Audit and Syslog](https://www.cisco.com/c/en/us/td/docs/security/secure-firewall/management-center/admin/740/management-center-admin-74/health-audit.html)
- [KUMA 4.2 supported sources](https://support.kaspersky.ru/kuma/4.2/255782)

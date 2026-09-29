# Cisco Unified Communications Manager Audit Log

Generates Cisco Unified Communications Manager (CUCM) 14 application audit log rows as ECS JSON: Cisco Unified CM Administration logins and logouts and `processnode` configuration changes. The native row is kept verbatim in `event.original`, in the `|LogMessage` form of the `Audit00000001.log` file that Cisco DevNet shows for build 14.0.1.10000-20. CUCM syslog alarms, CDRs, database audit and Linux auditd are separate streams.

## Event Types

Shares are typical of default output (`anomaly_mode: true`). All classes occur in both modes.

| Native `EventType` / `AuditDetails` | `event.action` | Share | Category |
|---|---|---:|---|
| `GeneralConfigurationUpdate` / `record in table processnode ... updated` | `processnode_updated` | 30.9% | configuration |
| `UserLogging` / `Successfully Logged into Cisco Unified CM Admin Webpages` | `user_login` | 29.3% | authentication, session |
| `UserLogging` / `Successfully Logged out Cisco Unified Administration Web Pages` | `user_logout` | 21.6% | authentication, session |
| `GeneralConfigurationUpdate` / `record in table processnode ... added` | `processnode_added` | 9.1% | configuration |
| `GeneralConfigurationUpdate` / `record in table processnode ... deleted` | `processnode_deleted` | 9.1% | configuration |

Thirty administrator accounts (`samples/admins.json`) work in Cisco Unified CM Administration, each with its own activity weight: the busiest accounts open a dozen or more sessions a day, the rarest (such as `Administrator` and `breakglass-admin`) about three or four. A session comes from the account's usual workstation address or, in about 15% of sessions, a second address, and an account pauses a few minutes to hours (median about 17 minutes) between sessions.

Volume follows a working day in UTC: about 730 rows a day (+/- 3% from day to day), rising from 04:00, peaking around 10:00-12:00 at about 70 rows an hour and fading out by 20:00, with one or two logins an hour at night. About 40% of daytime sessions only look around (login, logout); at night every session does. The rest carry one to about a dozen configuration changes, one to a few minutes apart (median about two minutes), on the `processnode` table (`samples/processnodes.json`, 24 server names, each present or absent; about half are present at any time):

- **Update** of a present record, often the same record several times in a row; a quarter of updates are saved again shortly after.
- **Add** of an absent record. Half of the adds are followed by an update of the same record (median about 1.5 minutes later), as in the Cisco sample; of the rest, more than half are deleted again later in the same session (added by mistake or for a test). Adds are more frequent when many servers are missing from the table, deletes when many are present.
- **Delete** of a present record; some follow an update of that record in the same session.

About a quarter of sessions end without a logout row (the browser is closed and the session expires). Configuration changes fall between 05:00 and 19:00 UTC. Rates, durations and the operation mix are synthetic workload choices, not measured CUCM production frequencies.

## Anomaly Chain

`anomaly_mode` defaults to `true`. With `false` the output holds only the activity above, which never holds the complete chain; every step still occurs there on its own and in partial sequences. Per 14 days of background: about 790 updates of a record by the account that added it within the previous two hours, about 250 adds followed by a delete of the same record by the same account, and about 140 updates followed by a delete.

Sequence, one episode (one Administration session of one of the eight busiest accounts, from its usual workstation address):

1. `UserLogging` login.
2. `GeneralConfigurationUpdate` - `record in table processnode with key field name = <K> added`: a server record that is not in the table.
3. The same record `updated` shortly after, sometimes saved again.
4. Zero to several ordinary updates, of this or other records.
5. The same record `deleted`, which restores the table to its state before the episode.
6. Logout (or no logout row, as in other sessions).

Linking fields: `user.name` (`UserID`) and the record key (`cucm.audit.record.key_value`, parsed from `AuditDetails`) across steps 2, 3 and 5; `source.ip` (`ClientAddress`) for the session. `CorrelationID` stays empty: CUCM uses it to join fragments of one oversized audit message, not to link a session. Episode spans (add to delete) are usually a few minutes to a quarter of an hour, occasionally up to about 40 minutes. Gaps between the steps and the account's pause after the session are the same as in any other session.

Recurrence: `anomaly_interval_hours` sets the spacing (default 24; a multiple of 24 up to 8760). The first episode starts within the first interval, capped at 24 hours; each next one starts one interval after the actual start of the previous one, shifted within a window of a quarter of the interval (at most 6 hours) centred on that point. Start times favour busy working hours (weighted by the square of the hourly volume, between 06:00 and 16:00 UTC). An episode starts at the first new session at or after that time for which one of the eight busiest accounts is out of session with its pause over and a record is absent that the account has not added in the last two hours; missed episodes are not replayed. Each episode picks a different account (weighted by activity) and a different record than the previous one. While an episode runs, other accounts do not touch its record. At 24 hours episodes start 21-27 hours apart, at 48 hours 45-51 hours apart. With `anomaly_mode: true` each episode has its own rows, so adds, updates and deletes are each about one a day higher at the default interval.

Detection idea: one account adds, updates and deletes the same cluster server record within two hours - a server entry staged and then removed, for example to register a rogue node temporarily. Each step alone, and each pair of steps, is ordinary administration here. In the background the complete sequence never occurs: when an account would delete a record it added at most two hours earlier and updated since, it deletes another present record instead (about 3 to 4 deletes a day, drawn like any other delete). The same delete after two hours, by another account, or of another record is written as usual.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Description |
|---|---|---|
| `anomaly_mode` | `true` | Include periodic anomaly episodes; `false` gives background only |
| `anomaly_interval_hours` | `24` | Hours between episode starts; a multiple of 24 from 24 to 8760, other values fail validation |
| `cucm_node` | `cucm-pub-01` | Native `Node ID` and `host.name` |

Accounts come from `samples/admins.json` (`user`, `ip`, `alt_ip`, `weight`: relative share of sessions; accounts with weight 4 or more can carry episodes) and records from `samples/processnodes.json` (`name`, initial `present`); edit these files to use your own account names, workstation addresses and server names. Episode rotation needs at least two accounts with weight 4 or more and two absent records. The daily volume and its hourly curve are set in `patterns/office.yml` (working-day activity, 700 rows a day) and `patterns/floor.yml` (night logins, 30 rows a day).

### Output Parameters

The shipped output writes `output/events.json` and needs no credentials. To send events elsewhere, replace the output and pass values through top-level placeholders, for example:

```yaml
output:
  - opensearch:
      hosts:
        - ${params.opensearch_host}
      username: ${params.opensearch_user}
      password: ${secrets.opensearch_password}
      index: cucm-audit
```

A collector that expects the native row should read `event.original`.

## Usage

Live mode:

```bash
eventum generate --path generators/application-cisco-cucm-audit/generator.yml --id cucm --live-mode true
```

Batch mode, as fast as possible. The patterns in `patterns/` start at the current day and never end, so a batch run continues until stopped; for a finite window set `start` (a date and time at midnight, so the daily curve keeps its hours) and `end` in both pattern files, for example `start: "2026-09-01T00:00:00+00:00"` and `end: "2026-09-15T00:00:00+00:00"`:

```bash
eventum generate --path generators/application-cisco-cucm-audit/generator.yml --id cucm --live-mode false
```

Performance: a 14-day window (about 10,200 events) generates in about 11 seconds, roughly 1,000 events per second.

## Sample Output

An episode's delete row from the default output:

```json
{"@timestamp": "2026-09-02T06:58:35.314+00:00", "cucm": {"audit": {"app_id": "Cisco Tomcat", "audit_category": "AdministrativeEvent", "audit_details": "record in table processnode with key field name = cucm-dr-01.example.test deleted", "client_address": "10.20.31.5", "cluster_id": "", "component_id": "Cisco CUCM Administration", "compulsory_event": "No", "correlation_id": "", "event_status": "Success", "event_type": "GeneralConfigurationUpdate", "node_id": "cucm-pub-01", "record": {"key_field": "name", "key_value": "cucm-dr-01.example.test", "operation": "deleted", "table": "processnode"}, "resource_accessed": "CUCMAdmin", "severity": 5, "timestamp_local": "06:58:35.314", "user_id": "akumar"}}, "ecs": {"version": "8.17.0"}, "event": {"action": "processnode_deleted", "category": ["configuration"], "code": "GeneralConfigurationUpdate", "dataset": "cucm.audit", "kind": "event", "module": "cucm", "original": "06:58:35.314 |LogMessage   UserID : akumar  ClientAddress : 10.20.31.5  Severity : 5  EventType : GeneralConfigurationUpdate  ResourceAccessed: CUCMAdmin  EventStatus : Success  CompulsoryEvent : No  AuditCategory : AdministrativeEvent  ComponentID : Cisco CUCM Administration  CorrelationID :   AuditDetails :  record in table processnode with key field name = cucm-dr-01.example.test deleted  App ID: Cisco Tomcat Cluster ID:  Node ID: cucm-pub-01", "outcome": "success", "type": ["deletion"]}, "host": {"name": "cucm-pub-01"}, "message": "record in table processnode with key field name = cucm-dr-01.example.test deleted", "related": {"hosts": ["cucm-pub-01"], "ip": ["10.20.31.5"], "user": ["akumar"]}, "service": {"name": "Cisco Unified Communications Manager", "version": "14.0.1.10000-20"}, "source": {"ip": "10.20.31.5"}, "user": {"name": "akumar"}}
```

## Limitations

- The only complete native example is the DevNet file with four rows: login, `processnode` added, `processnode` updated, logout. Field names, spacing and the constant values of each form (`Severity`, `ResourceAccessed`, `AuditCategory`, `ComponentID`) follow it exactly. The CUCM 14 administration guide lists server additions and deletions among audited events, but shows no row; the `deleted` row reuses the `added`/`updated` form with the verb `deleted` seen in Cisco Community posts for other tables. It is not a captured line.
- Only successful Administration logins and `processnode` changes are modeled. Failed logins, other tables (device, numplan, users), Serviceability and CLI events are not generated because no primary row example was found for them. All configuration work therefore lands on server records, about 360 changes a day, where real clusters change devices and directory numbers often and server records rarely.
- Rows of one session are one to a few minutes apart (an update after an add follows after a median of about 1.5 minutes), where a real administrator saving twice in a row produces rows seconds apart.
- The file `HDR` line is not emitted. Native rows carry only a time of day; `@timestamp` supplies the date, and the time of day is UTC. Remote syslog framing (`AuditEventGenerated` alarms) is not modeled.
- `cucm.audit.record` (table, key field, key value, operation) is parsed from `AuditDetails`; `event.*`, `user.*`, `source.*` and `related.*` are ECS normalization, not source fields.
- KUMA 4.2 lists a CUCM normalizer for 11.5(1); this pack follows the 14.0.1 file example and does not claim compatibility with that normalizer.
- No live capture, exact-build trace or maintained Elastic integration for CUCM audit logs was available for comparison.

## References

- [Cisco DevNet: Log Collection API, complete CUCM 14 audit-file sample](https://developer.cisco.com/docs/sxml/log-collection-api/)
- [Cisco CUCM 14 administration guide: audit logs](https://www.cisco.com/c/en/us/td/docs/voice_ip_comm/cucm/admin/14SU2/adminGd/cucm_b_administration-guide-14su2/cucm_b_test-adminguide_chapter_010100.html)
- [Cisco CUCM 11.5(1) release notes: short and split audit messages](https://www.cisco.com/c/en/us/td/docs/voice_ip_comm/cucm/rel_notes/11_5_1/cucm_b_release-notes-cucm-imp-1151.pdf)
- [KUMA 4.2 supported sources](https://support.kaspersky.ru/kuma/4.2/255782)

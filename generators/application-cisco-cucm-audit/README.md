# Cisco Unified Communications Manager Audit Log

Generates Cisco Unified Communications Manager (CUCM) 14 application audit log rows as ECS JSON: Cisco Unified CM Administration logins and logouts and `processnode` configuration changes. The native row is kept verbatim in `event.original`, in the `|LogMessage` form of the `Audit00000001.log` file that Cisco DevNet shows for build 14.0.1.10000-20. CUCM syslog alarms, CDRs, database audit and Linux auditd are separate streams.

## Event Types

Measured on a 14-day default capture (`anomaly_mode: true`, 1,547 events). All classes occur in both modes.

| Native `EventType` / `AuditDetails` | `event.action` | Share | Category |
|---|---|---:|---|
| `GeneralConfigurationUpdate` / `record in table processnode ... updated` | `processnode_updated` | 31.6% | configuration |
| `UserLogging` / `Successfully Logged into Cisco Unified CM Admin Webpages` | `user_login` | 26.9% | authentication, session |
| `UserLogging` / `Successfully Logged out Cisco Unified Administration Web Pages` | `user_logout` | 21.5% | authentication, session |
| `GeneralConfigurationUpdate` / `record in table processnode ... deleted` | `processnode_deleted` | 10.1% | configuration |
| `GeneralConfigurationUpdate` / `record in table processnode ... added` | `processnode_added` | 9.9% | configuration |

Twelve administrator accounts (`samples/admins.json`) each follow their own random schedule: sessions every few hours to a few days (lognormal, per-account median 3 to 30 hours between sessions), from the account's usual workstation address or, in about 15% of sessions, a second address. About 40% of sessions only look around (login, logout). The rest carry one to about fifteen configuration changes (most often one to three) seconds to minutes apart on the `processnode` table (`samples/processnodes.json`, 24 server names, each present or absent):

- **Update** of a present record, often the same record several times in a row; a quarter of updates are saved again seconds later.
- **Add** of an absent record. Half of the adds are followed within seconds by an update of the same record, as in the Cisco sample; of the rest, more than half are deleted again later in the same session (added by mistake or for a test).
- **Delete** of a present record; some follow an update of that record in the same session.

About a quarter of sessions end without a logout row (the browser is closed and the session expires). One input tick per second emits the earliest due row with its own millisecond timestamp, or nothing. Rates, durations and the operation mix are synthetic workload choices, not measured CUCM production frequencies.

## Anomaly Chain

`anomaly_mode` defaults to `true`. With `false` the generator emits only the background above, which never holds the complete chain; every step still occurs there on its own and in partial sequences. Per 14-day background capture: 105-160 updates of a record by the account that added it within the previous two hours, 36-50 adds followed by a delete, and 17-30 updates followed by a delete.

Sequence, one episode (one Administration session of one account, from one of that account's usual addresses):

1. `UserLogging` login.
2. `GeneralConfigurationUpdate` - `record in table processnode with key field name = <K> added`: a server record that is not in the table.
3. The same record `updated` seconds later, sometimes saved again.
4. Zero to several ordinary updates, of this or other records.
5. The same record `deleted`, which restores the table to its state before the episode.
6. Logout (or no logout row, as in background).

Linking fields: `user.name` (`UserID`) and the record key (`cucm.audit.record.key_value`, parsed from `AuditDetails`) across steps 2, 3 and 5; `source.ip` (`ClientAddress`) for the session. `CorrelationID` stays empty: CUCM uses it to join fragments of one oversized audit message, not to link a session. Measured episode spans (add to delete): 0.3 to 4.3 minutes across the 14-day captures (default and 48-hour). All gaps come from the same distributions as background operations.

Recurrence: `anomaly_interval_hours` sets the spacing (default 24, minimum 6). The first episode is due at a uniformly random moment within the first interval, capped at 24 hours; each next one is due one interval after the actual start of the previous one, shifted by a uniformly random offset within a window of a quarter of the interval (at most 6 hours) centred on that point. An episode starts on the first moment at or after its due time when an account is out of session with no own session due within 3 hours and no add in the last 3 hours, and a record is absent and untouched for 3 hours; otherwise it waits. Missed episodes are not replayed. Each episode picks a different account (weighted by how often each account works) and a different record than the previous one. The episode is an extra session: the account's own schedule resumes unchanged, and no background activity is suspended or shifted, except that ordinary changes do not touch the record reserved for the running episode. Measured: 14 episodes in 14 days at 24 hours (start gaps 21.4 to 26.4 hours, first 1.6 hours after the start), 7 in 14 days at 48 hours (45.4 to 50.6 hours); rotated accounts and records in every case.

Detection idea: one account adds, updates and deletes the same cluster server record within two hours - a server entry staged and then removed, for example to register a rogue node temporarily. Each step alone, and each pair of steps, is ordinary administration here. Background never completes the sequence: an ordinary delete is skipped only when it would complete it, that is when the same account added the record at most two hours earlier and updated it since. The same delete after two hours, by another account, or of another record is written as usual.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Description |
|---|---|---|
| `anomaly_mode` | `true` | Include periodic anomaly episodes; `false` gives background only |
| `anomaly_interval_hours` | `24` | Hours between episode starts; 6 to 8760, other values fail validation |
| `cucm_node` | `cucm-pub-01` | Native `Node ID` and `host.name` |

Accounts come from `samples/admins.json` (`user`, `ip`, `alt_ip`, `median_hours` between sessions) and records from `samples/processnodes.json` (`name`, initial `present`). Episode rotation needs at least two accounts and two initially absent records.

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

Batch mode, as fast as possible (the cron input runs until stopped unless `start` and `end` are set on it):

```bash
eventum generate --path generators/application-cisco-cucm-audit/generator.yml --id cucm --live-mode false
```

## Sample Output

An episode's delete row from the final default capture:

```json
{"@timestamp": "2026-09-01T01:35:09.934+00:00", "cucm": {"audit": {"app_id": "Cisco Tomcat", "audit_category": "AdministrativeEvent", "audit_details": "record in table processnode with key field name = cucm-lab-02.example.test deleted", "client_address": "10.20.31.5", "cluster_id": "", "component_id": "Cisco CUCM Administration", "compulsory_event": "No", "correlation_id": "", "event_status": "Success", "event_type": "GeneralConfigurationUpdate", "node_id": "cucm-pub-01", "record": {"key_field": "name", "key_value": "cucm-lab-02.example.test", "operation": "deleted", "table": "processnode"}, "resource_accessed": "CUCMAdmin", "severity": 5, "timestamp_local": "01:35:09.934", "user_id": "akumar"}}, "ecs": {"version": "8.17.0"}, "event": {"action": "processnode_deleted", "category": ["configuration"], "code": "GeneralConfigurationUpdate", "dataset": "cucm.audit", "kind": "event", "module": "cucm", "original": "01:35:09.934 |LogMessage   UserID : akumar  ClientAddress : 10.20.31.5  Severity : 5  EventType : GeneralConfigurationUpdate  ResourceAccessed: CUCMAdmin  EventStatus : Success  CompulsoryEvent : No  AuditCategory : AdministrativeEvent  ComponentID : Cisco CUCM Administration  CorrelationID :   AuditDetails :  record in table processnode with key field name = cucm-lab-02.example.test deleted  App ID: Cisco Tomcat Cluster ID:  Node ID: cucm-pub-01", "outcome": "success", "type": ["deletion"]}, "host": {"name": "cucm-pub-01"}, "message": "record in table processnode with key field name = cucm-lab-02.example.test deleted", "related": {"hosts": ["cucm-pub-01"], "ip": ["10.20.31.5"], "user": ["akumar"]}, "service": {"name": "Cisco Unified Communications Manager", "version": "14.0.1.10000-20"}, "source": {"ip": "10.20.31.5"}, "user": {"name": "akumar"}}
```

## Limitations

- The only complete native example is the DevNet file with four rows: login, `processnode` added, `processnode` updated, logout. Field names, spacing and the constant values of each form (`Severity`, `ResourceAccessed`, `AuditCategory`, `ComponentID`) follow it exactly. The CUCM 14 administration guide lists server additions and deletions among audited events, but shows no row; the `deleted` row reuses the `added`/`updated` form with the verb `deleted` seen in Cisco Community posts for other tables. It is not a captured line.
- Only successful Administration logins and `processnode` changes are modeled. Failed logins, other tables (device, numplan, users), Serviceability and CLI events are not generated because no primary row example was found for them; real clusters change devices and directory numbers far more often than server records.
- The file `HDR` line is not emitted. Native rows carry only a time of day; `@timestamp` supplies the date, and the time of day is UTC. Remote syslog framing (`AuditEventGenerated` alarms) is not modeled.
- `cucm.audit.record` (table, key field, key value, operation) is parsed from `AuditDetails`; `event.*`, `user.*`, `source.*` and `related.*` are ECS normalization, not source fields.
- KUMA 4.2 lists a CUCM normalizer for 11.5(1); this pack follows the 14.0.1 file example and does not claim compatibility with that normalizer.
- No live capture, exact-build trace or maintained Elastic integration for CUCM audit logs was available for comparison.

## References

- [Cisco DevNet: Log Collection API, complete CUCM 14 audit-file sample](https://developer.cisco.com/docs/sxml/log-collection-api/)
- [Cisco CUCM 14 administration guide: audit logs](https://www.cisco.com/c/en/us/td/docs/voice_ip_comm/cucm/admin/14SU2/adminGd/cucm_b_administration-guide-14su2/cucm_b_test-adminguide_chapter_010100.html)
- [Cisco CUCM 11.5(1) release notes: short and split audit messages](https://www.cisco.com/c/en/us/td/docs/voice_ip_comm/cucm/rel_notes/11_5_1/cucm_b_release-notes-cucm-imp-1151.pdf)
- [KUMA 4.2 supported sources](https://support.kaspersky.ru/kuma/4.2/255782)

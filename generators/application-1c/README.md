# 1C:Enterprise Event Log Generator

Generates a selected **1C:Enterprise 8.3.27 event-log collector projection** for a client/server, single-data-area infobase using sequential `.lgf` storage. This is the event log, not the separate technological log. Output is ECS-style JSON with snake_case source fields under `one_c.event_log`. It is not a native XML or `.lgf` export, and has no fabricated `event.original`.

The source inventory has six staff accounts: two accountants, one sales and one warehouse user, and two administrators. There are also four temporary account names that are reused after deletion, and five fictional configuration objects. Each new temporary incarnation gets a fresh UUID and logs in from its creator's workstation. The assumed Enterprise thick client keeps its connection for one modeled session. The administrator and temporary `Roles.FullAccess` roles explicitly grant Administration, DataAdministration and Read on this synthetic configuration. Accountants can read all five objects; Sales and Warehouse cannot read the payroll register. These are configured scenario permissions, not privileges inferred from a role name.

## Event Types

Shares are measured over 30 days of `anomaly_mode: false` data (255,984 records). Counts for 30 days with the default `anomaly_mode: true` (255,902 records, five episodes) are shown for comparison.

| System event | Selected behavior | Category | Share (background) | Count (with anomaly) |
|---|---|---|---:|---:|
| `_$Access$_.Access` | Successful controlled read with one nested logged row | database / access | 91.93% | 235,139 |
| `_$Access$_.AccessDenied` | Object-level Read permission denial | database / access, denied | 4.01% | 10,363 |
| `_$Session$_.Authentication` | Successful authentication opens a session | authentication / start | 2.84% | 7,245 |
| `_$User$_.Update` | Administrator updates another staff account; unproven native Data omitted | iam / change | 0.54% | 1,354 |
| `_$User$_.New` | Administrator creates one temporary account | iam / creation | 0.19% | 475 |
| `_$User$_.Delete` | Administrator deletes that temporary incarnation | iam / deletion | 0.19% | 475 |
| `_$InfoBase$_.EventLogReduce` | Administrator reduces records older than the assumed cutoff | configuration / deletion | 0.15% | 364 |
| `_$Session$_.AuthenticationError` | Failed attempt; no native authenticated UUID is asserted | authentication / start (failure) | 0.15% | 487 |

## Volume and Timing

- Staff activity runs at about 350 records per hour at uniformly random times, the hourly count varying by up to 10%. Rates do not vary by time of day or day of week.
- The two administrators log in about 120 times a day in total at uniformly random times, plus a fresh session for about half of their management tasks (about 170 successful administrator logins a day); the day's count varies by up to 30% around that average with the day's workload.
- About 8,500 records a day in total. Source time has whole seconds, as in the native log, and about 5% of records share their second with the previous one.

## Background Model

All background decisions are random draws, with no fixed period, rotation or script. Rates below are measured over 180 days of background.

- **Staff activity.** Each record picks its actor by weight (accountants dominate) and an object the actor may read, or a payroll denial for Sales or Warehouse. About a third of reads start a burst of quick follow-up reads by the same user, seconds apart.
- **Sessions.** The data opens mid-stream: most staff already hold a session that began earlier, so their first records reuse pre-window session numbers. A session lasts a random lifetime (median about 70 minutes, lognormal). The next operation after it ends authenticates first, and the operation follows seconds later (median 29 s). Session and connection numbers grow in random steps, because sessions outside the selected output also consume numbers. An administrator also opens a fresh session for half of its management tasks unless its current session is under two minutes old.
- **Failed logins.** About 5% of login attempts fail: about 4-5% for staff accounts (3.8-5.3% per account) and about 6% for the administrators. A failed attempt is retried after about ten seconds to a minute (median 22 s), and most runs end in a successful login (68%). Most administrator logins succeed at once. About 1.3% of them start with a mistyped password, retried a few times at most. About 1.7% come from the maintenance client retrying a saved password that no longer works: each retry fails again with probability 0.75, so these runs are often longer, before the administrator types the password (90%) and runs the maintenance session the client was opened for (90%). Every run-length distribution falls with the number of failures; over 180 days the administrator runs of 1, 2, 3, 4, 5 and 6 failures number 323, 158, 85, 47, 41 and 20 (about 0.9 runs of four or more a day), and the staff runs 246, 85, 35, 4 and 1.
- **Temporary accounts.** Each administrator keeps two of the four temporary names (admin01 `svc_audit_01` and `svc_audit_03`, admin02 `svc_audit_02` and `svc_audit_04`) and uses the other two only while both of its own are taken. A maintenance session follows about 2% of other administrator logins and 90% of the logins after a stale saved password. In it the administrator creates a temporary account seconds after the login, the account logs in and checks the payroll register, and the account is removed, followed by an old-log reduction by the deleting administrator in most sessions. Other lifecycles arrive at random, a mean of 2 hours apart, by either administrator. In total there are about 16 lifecycles a day. Across all of them:
  - creation is preceded by four or more of the creator's failed logins within 30 minutes about 0.9 times a day;
  - the account logs in 2 s to 2 h after creation (median about 2 minutes);
  - it reads the payroll register 1-113 times (median 6), several seconds to a few minutes apart;
  - the creator deletes it in 90% of lifecycles, 11 s to 9 h after the last read (median about 3 minutes);
  - lifespans run from 82 s to 10 h (median about 13 minutes), and 55% last under 15 minutes;
  - 72% of deletions are followed within 30 minutes by a reduction by the deleting administrator. The whole anomaly sequence never occurs in background, so this share depends on what preceded the lifecycle: of same-administrator deletions that end four failures, a login and the creation within 30 minutes of the first failure, 10% are followed by the deleter's reduction within 30 minutes (all of them after the 30 minutes from the first failure have passed), against 77% of the other deletions. About 0.7 reductions a day are absent for this reason.
- **Log trimming.** An administrator who got in after failed attempts and opened no maintenance session trims the event log a few minutes later in 12% of cases. With standalone reductions (about one a day) and reductions after deletions, there are about 13 reductions a day.
- **Other administration.** Staff updates average about 46 a day.

Session termination is outside the selected output, because its native record body was not established, so the data does not show when a session ended.

## Anomaly Chain

`anomaly_mode: true` is the default. `anomaly_mode: false` produces only the background above, with zero complete chains. Each episode is:

1. An administrator fails to log in four or more times from its own workstation, a few seconds to a minute apart, then logs in successfully.
2. Seconds later, that administrator creates a temporary account with the selected `Roles.FullAccess` membership, under one of its own temporary names.
3. The new incarnation logs in, usually within a minute, and reads the payroll register several times in one session.
4. Its session closes outside the selected output, and the same administrator deletes that exact incarnation, usually within a few minutes.
5. The same administrator then reduces old event-log records.

Every shorter part of this sequence also occurs in background, by the same administrators and with the same temporary names. What background never contains is the whole ordered sequence joined by one administrator and one incarnation within 30 minutes of the first failure. The episode follows the laws of a background maintenance session after a stale saved password, with three differences that stay within background ranges: the run always has four or more failures (each further retry fails with probability 0.75, as in background), the deletion is always by the creator and follows within minutes, and the reduction always follows. The whole episode ends within 30 minutes of the first failed attempt; episodes usually span 7-23 minutes, occasionally up to about 28 minutes, and hold 2-13 payroll reads.

Episode records are added among the background records. Background records keep their times, and the administrator's own logins, maintenance sessions and trims continue as in background. With `anomaly_mode: true` each episode adds its own records, so counts of the chain parts (failed-login runs of four or more, creations after such a run, the full sequence without its reduction) are about one per episode higher than in background, and about seven failed logins per episode are added.

Linking fields: `user.name`/`user.id` and `client.address` of the administrator; the incarnation UUID in `user.target.id` on creation and deletion; the temporary account's `user.id`; session/connection numbers; and source time. The target UUID/name on user-management records is synthetic collector enrichment from the inventory, not a claimed native Data member. Failed attempts carry only the attempted username and zero session/connection, not verified native failure bytes. Payroll reads are recorded access occurrences; repeated synthetic employee keys do not prove distinct people, returned amounts or exfiltration.

**Recurrence.** `anomaly_interval_hours` (default 168, one episode a week) is measured in source time and clamped to at least one hour. The default keeps the episode a rare event against about six administrator runs of four or more failed logins a week. Background rates do not vary by time of day, so start times are drawn uniformly. The first episode starts at a random time within the first interval, or the first 24 hours when the interval is longer. Each later one starts at a random time within a window of a quarter of the interval (at most 6 hours) centred on one interval after the previous episode's first failed attempt; if both of the administrator's own temporary names are in use at that moment, the episode starts once one is free. Consecutive episodes alternate the two administrators, never reuse the previous episode's temporary name, and always get a fresh incarnation UUID.

Measured: at the default interval a 30-day window holds five episodes, the first 21-22 hours after the window start and creations 165.6-170.9 hours apart; a 96-hour interval gives eight in 30 days, creations 93.4-98.1 hours apart. Shorter intervals raise the counts of the chain parts accordingly.

Detection idea: join four or more failures of one administrator, its successful login, a user creation by it within minutes, and the new incarnation's payroll reads. Then join the deletion of that same UUID by the same administrator and a following event-log reduction. These signals do not establish recent-log erasure or exfiltration.

## Log management assumptions

An existing old event-log history predates the generated window. Each modeled reduction uses an older-than-midnight cutoff before the current day of the generated window. 1C preserves the cutoff date from midnight onward, so no claim is made that the just-emitted sequence was removed. The source has no in-memory history simulation, and the reduction's full native Data/cutoff payload is omitted because it was not established. `TruncateEventLog()` is the documented operation, not deprecated SQLite-only `ClearEventLog()`.

The former `EventLogSettingsUpdate` class was removed from this selected profile. The modern infobase already uses sequential storage, while recurring format conversion is unsupported for new 8.3.22+ infobases. Interactive settings save in network operation requires the administrator to be the only user. This pack neither invents a live settings change with active users nor simulates a session-drain operation. Event classes remain eight because native user deletion now closes the temporary-user lifecycle.

## Source field scope

The Administrator Guide Appendix 2 describes the XML event elements, while its section 6.13.3 example also includes Computer. Their **23-field union** occurs across generated events. This is schema/field presence, not a full native raw or value-fidelity score. Failed authentication omits native user attribution; failure, update, deletion and reduction omit unproved Data/DataPresentation payloads. Other classes preserve only selected Data subsets, not every native property.

| Source group | Selected projection |
|---|---|
| Level/date/application/event | Valid model severity and UTC normalized date, Enterprise context, documented system class; source translations/comments and exact native clock spelling are not byte-proven |
| User/workstation | Existing actor UUID/name and workstation; failure attribution omitted; management target is synthetic enrichment |
| Metadata | Compound configuration names and presentation arrays for data-access records; blanks for other classes |
| Access Data | `Data` contains rows of configured logged string fields; no invented Action/Fields payload |
| Denial Data | Object-level `Right: Read`; no RLS decision or denied data contents inferred |
| Authentication Data | Selected documented `OSUser` structure key identifies the assumed process OS account, not proof of the authentication method |
| Add-user Data | Selected `Roles` array uses role-value strings such as `Roles.FullAccess`; complete user payload remains unproven |
| Transaction | NotApplicable and blank ID; modeled operations occur outside a database transaction |
| Session/server | Current numeric session/connection, working server and main/auxiliary ports |
| Data separation | Empty map/list for this single-area scenario |

No official Elastic 1C integration field sample was established. The 23-field source inventory is used instead of claiming an Elastic coverage percentage. Access events require controlled access fields/logged fields configured in exclusive mode before capture; recording changes apply after active sessions restart. The export/collector is assumed to have Administration, DataAdministration and EventLog rights so authentication/access data is not hidden. No CORP-only access-right audit classes are generated.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Purpose |
|---|---|---|
| `infobase` | `AccountingDemo` | Synthetic configuration/infobase name |
| `server_name` | `srvr-1c-01.example.test` | Working server context |
| `host_name` | `srvr-1c-01.example.test` | Synthetic collector host |
| `server_port` | `1541` | Main server port |
| `sync_port` | `1542` | Auxiliary server port |
| `ecs_version` | `8.11.0` | Normalized ECS context |
| `anomaly_mode` | `true` | Add recurring anomaly episodes to the background |
| `anomaly_interval_hours` | `168` | Source-time interval between episodes, clamped to at least one hour |

The staff rate is `multiplier.ratio` in `patterns/activity.yml` (records per hour), and the administrator logins per day are `multiplier.ratio` in `patterns/admin_logins.yml`, with `randomizer.deviation` setting their day-to-day spread. Delays are drawn in source seconds and assume about this density; a much lower rate stretches the spacing of follow-up records, and a much higher one makes each staff account unrealistically busy. Actor UUIDs, names, workstations, OS accounts, weights, object permissions and metadata/logged column names are in `samples/actors.json` and `samples/objects.json`. Every record there must keep the same field order, and weights must be numeric. Accounts with `role: Roles.FullAccess` act as administrators. Keep at least two of them so that consecutive episodes can rotate administrators. The four temporary names are fixed in the template and shared out among the administrators in turn. Editing the inventory requires matching configuration permissions and audit setup.

### Output Parameters

The shipped `generator.yml` writes JSON Lines to `output/events.json`, so it runs as-is. To deliver to a backend, replace the output with a plugin whose connection values come from top-level placeholders, for example OpenSearch:

```yaml
output:
  - opensearch:
      hosts:
        - ${params.opensearch_host}
      username: ${params.opensearch_user}
      password: ${secrets.opensearch_password}
      index: ${params.opensearch_index}
```

| Parameter | Description |
|---|---|
| `${params.opensearch_host}` | OpenSearch host URL |
| `${params.opensearch_user}` | Username for authentication |
| `${secrets.opensearch_password}` | Password, resolved from the Eventum keyring |
| `${params.opensearch_index}` | Target index name |

The output carries the selected JSON projection. Parsing real XML or `.lgf` data must be tested against an actual native export.

## Usage

From the content-packs repository root, run live:

```bash
eventum generate --path generators/application-1c/generator.yml --id one-c --live-mode true --keep-order true
```

For a finite batch, the window lives in the time patterns, whose shipped files keep `end: never` for live runs. Copy `patterns/activity.yml` and `patterns/admin_logins.yml` to `patterns/activity.batch.yml` and `patterns/admin_logins.batch.yml` and set the same window in both; start it at midnight so that the administrator stream's days match calendar days:

```yaml
oscillator:
  period: 1
  unit: hours  # days in admin_logins.batch.yml
  start: "2026-09-25T00:00:00Z"
  end: "2026-09-26T01:05:00Z"
```

Then copy `generator.yml` to `generator.batch.yml` beside it, point its two inputs at the batch pattern files, and run:

```bash
eventum generate --path generators/application-1c/generator.batch.yml --id one-c-batch --live-mode false --keep-order true
```

This window yields about 8,700-9,100 records with one episode at the default interval. A live run shows the first episode at a random time within the first interval or the first 24 hours. `--keep-order true` preserves source order through the asynchronous writer. Timestamps are rendered in UTC whatever the CLI time zone. Check that the output is non-empty and that no errors were logged, because the CLI can exit with status 0 after template-render failures.

Performance: batch generation runs at about 2,500 records per second on one core (14 days, about 119,000 records, 46 s of CPU time).

## Sample Output

This user-creation record is row 7,240 of 30 days of default `true` data, the creation step of its first episode, pretty-printed with non-ASCII characters unescaped. The target identity is inventory enrichment, and its `Roles` array is only the selected native Data subset:

```json
{
  "@timestamp": "2026-09-01T21:04:45+00:00",
  "ecs": {
    "version": "8.11.0"
  },
  "event": {
    "kind": "event",
    "module": "one_c",
    "dataset": "one_c.event_log",
    "action": "_$User$_.New",
    "category": [
      "iam"
    ],
    "type": [
      "creation"
    ],
    "outcome": "success"
  },
  "host": {
    "name": "srvr-1c-01.example.test"
  },
  "service": {
    "name": "AccountingDemo"
  },
  "user": {
    "name": "admin01",
    "id": "00000000-0000-0000-0000-000000000105",
    "target": {
      "name": "svc_audit_01",
      "id": "03c84f98-238d-48b6-89c8-ce448c4370b8"
    }
  },
  "client": {
    "address": "ADM-WS-01"
  },
  "related": {
    "user": [
      "admin01",
      "svc_audit_01"
    ],
    "hosts": [
      "ADM-WS-01"
    ]
  },
  "message": "Пользователи.Новый пользователь",
  "one_c": {
    "event_log": {
      "level": "Information",
      "date": "2026-09-01T21:04:45+00:00",
      "application": "Enterprise",
      "application_presentation": "1C:Enterprise",
      "event_name": "_$User$_.New",
      "event_presentation": "Пользователи.Новый пользователь",
      "user_id": "00000000-0000-0000-0000-000000000105",
      "user_name": "admin01",
      "computer": "ADM-WS-01",
      "metadata_name": "",
      "metadata_presentation": "",
      "comment": "",
      "data": {
        "Roles": [
          "Roles.FullAccess"
        ]
      },
      "data_presentation": "",
      "transaction_status": "NotApplicable",
      "transaction_id": "",
      "connection": 634,
      "session": 1620,
      "server_name": "srvr-1c-01.example.test",
      "port": 1541,
      "sync_port": 1542,
      "session_data_separation": {},
      "session_data_separation_presentation": []
    }
  }
}
```

## References

- [1C Administrator Guide 8.3.27](https://1c-dn.com/library/tutorials/1c_enterprise_administrator_guide_file_mode_8_3_27/), sections 6.13.3/6.13.5/Appendix 2: XML example/field types, sequential storage, settings exclusivity and old-date cutoff semantics.
- [1C Developer Guide 8.3.27](https://1c-dn.com/library/tutorials/1c_enterprise_developer_guide_8_3_27/), chapter 22 and Appendix 5: access setup, nested logged tables, object-level denial Right, OSUser/Roles examples, truncation and administration/export permissions.
- [Native platform event changes](https://1c-dn.com/library/v8update_2079252603_changes_performed_after_version_publication/) document user-management errors and EventLogReduce; [earlier behavior changes](https://1c-dn.com/library/v8update_027v8SmKe5_changes_affecting_the_system_behavior/) document interactive/programmatic user create/update/delete and successful-authentication-only attribution.
- [Integer-second event-log time presentation](https://1c-dn.com/library/v8update_2756468690_changes_that_affect_system_behavior/) supplies source precision; it does not establish exact XML timezone spelling.

Full native 8.3.27 exports for all selected system classes and their complete Data shapes, exact failed-authentication attribution and session fields, event-specific levels, translations and comments, the native session-end body and a live exporter or SIEM parser were not available. The pack keeps selected documented semantics with explicit synthetic inventory and collector encodings. It does not prove full native byte parity, a production configuration, malicious intent, actual privileges from role names, or recent-log erasure. Internal session closure is not an emitted native record. The source XML example and the current appendix/developer terminology differ in some naming details; the retained collector field names and compound configuration names are not claimed as an exact current XML serializer.

## Limitations

- Rates are stationary, with no working hours or weekends. Administrator activity varies only between calendar days, by up to 30% around its average.
- Records that belong to one moment are seconds apart rather than immediate: a retry after a failed login follows by a median 22 s (90th percentile 48 s), and the operation after its login by a median 29 s. About 5% of records share their second with the previous record.
- Temporary accounts always log in from their creator's workstation, and temporary-account maintenance is frequent (about 16 lifecycles a day for two administrators).
- Staff sessions end silently after a random lifetime, and pre-window sessions are assumed rather than observed.
- In about one episode in seven, an ordinary login by the same administrator falls between the episode's failed attempts; in background a new attempt during a failure run joins that run.
- The random draws have long tails, so individual episodes or lifecycles can be unusually long.
- Four or more failures, a login, a creation and the deletion of that account by the same administrator within 30 minutes are followed by that administrator's reduction only after the 30 minutes have passed (10% of such deletions, against 77% of other deletions within 30 minutes).
- With `anomaly_mode: true` each episode adds its own records, so counts of the chain parts are about one per episode higher than in background; at intervals much shorter than the default these additions dominate the counts of long failed-login runs.

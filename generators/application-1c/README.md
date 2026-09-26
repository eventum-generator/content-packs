# 1C:Enterprise Event Log Generator

Generates a selected **1C:Enterprise 8.3.27 event-log collector projection** for a client/server, single-data-area infobase using sequential `.lgf` storage. This is the event log, not the separate technological log. Output is ECS-style JSON with snake_case source fields under `one_c.event_log`. It is not a native XML or `.lgf` export, and has no fabricated `event.original`.

The source inventory has six staff accounts: two accountants, one sales and one warehouse user, and two administrators. There are also four temporary account names that are reused after deletion, and five fictional configuration objects. Each new temporary incarnation gets a fresh UUID and logs in from its creator's workstation. The assumed Enterprise thick client keeps its connection for one modeled session. The administrator and temporary `Roles.FullAccess` roles explicitly grant Administration, DataAdministration and Read on this synthetic configuration. Accountants can read all five objects; Sales and Warehouse cannot read the payroll register. These are configured scenario permissions, not privileges inferred from a role name.

## Event Types

Shares are measured in the default `anomaly_mode: false` capture (25 h 05 min, 8,660 records). Counts for the paired default `true` capture (8,716 records, two episodes) are shown for comparison.

| System event | Selected behavior | Category | Share (background) | Count (with anomaly) |
|---|---|---|---:|---:|
| `_$Access$_.Access` | Successful controlled read with one nested logged row | database / access | 89.02% | 7,754 |
| `_$Access$_.AccessDenied` | Object-level Read permission denial | database / access, denied | 3.95% | 345 |
| `_$Session$_.AuthenticationError` | Failed attempt; no native authenticated UUID is asserted | authentication / start (failure) | 3.00% | 251 |
| `_$Session$_.Authentication` | Successful authentication opens a session | authentication / start | 2.88% | 250 |
| `_$User$_.Update` | Administrator updates another staff account; unproven native Data omitted | iam / change | 0.55% | 49 |
| `_$User$_.New` | Administrator creates one temporary account | iam / creation | 0.23% | 24 |
| `_$User$_.Delete` | Administrator deletes that temporary incarnation | iam / deletion | 0.23% | 24 |
| `_$InfoBase$_.EventLogReduce` | Administrator reduces records older than the assumed cutoff | configuration / deletion | 0.14% | 19 |

Captures of 25 h 05 min hold 8,582-9,223 records in both modes, about 350 per hour. Rates are synthetic workload settings, not vendor production frequencies, and they do not vary by time of day.

## Background Model

One template renders every source second in UTC; most seconds produce no record. All background decisions are random draws, with no fixed period, rotation or script. Rates below are measured over four 100-hour background captures (400 hours); distributions over all ten background captures (500 hours).

- **Staff activity.** Each record picks its actor by weight (accountants dominate) and an object the actor may read, or a payroll denial for Sales or Warehouse. About a third of reads start a burst of quick follow-up reads by the same user a few seconds apart.
- **Sessions.** The capture window opens mid-stream. Most staff already hold a session that began earlier, so their first records reuse pre-window session numbers. A session lasts a random lifetime (median about 70 minutes, lognormal). The next operation after it ends authenticates first, and the operation follows seconds later. Session and connection numbers grow in random steps, because sessions outside the selected output also consume numbers. An administrator also opens a fresh session for half of its management tasks unless its current session is under two minutes old.
- **Failed logins.** A failed attempt is retried after a few seconds to a minute. A retry fails again with probability 0.5 for administrators and 0.4 for other staff, and a run ends in a successful login 85% of the time. Administrators account for about half of the runs, because they log in to several tools. Measured: about 54 runs of two or more failures a day, 9.2 of four or more, and 6.7 administrator runs of four or more.
- **Temporary accounts.** A quarter of administrator logins that follow failed attempts open a short maintenance session. In it the administrator creates a temporary account seconds after the login, the account logs in and checks the payroll register, and the account is removed, usually followed by an old-log reduction. Other lifecycles arrive as a Poisson process with a mean spacing of 10 hours. In total there are about 16 lifecycles a day. Measured across all of them:
  - creation is preceded by three or more of the creator's failed logins within 30 minutes about 7.6 times a day, and by four or more about 4.8 times a day;
  - the account logs in 3 s to 38 min after creation (median about 1 minute);
  - it reads the payroll register 1-49 times (median 5), a few seconds to a few minutes apart;
  - the creator deletes it in 92% of lifecycles, 10 s to 2.9 h after the last read (median about 2 minutes);
  - lifespans run from 69 s to 3 h (median about 7 minutes), and 73% last under 15 minutes;
  - 59% of deletions are followed within minutes by a reduction by the same administrator.
- **Other administration.** Standalone reductions average about one a day, and staff updates about 45 a day.

**Guard.** One background rule keeps ordinary traffic from completing the anomaly by coincidence. It sits at the chain's threshold and last step: when an account created within 30 minutes of four or more of its creator's failed logins is deleted by that creator, the creator runs no log reduction for the next 30 minutes. Failed logins from episodes count too. While an administrator runs an episode, the other administrator deletes such an account instead. An episode waits to start while its administrator is under this hold. All shorter sequences remain in background, including four or more failures, a login, a creation and a deletion of that account by the same administrator. Session termination is outside the selected output, because its native record body was not established, so the stream does not show when a session ended.

## Anomaly Chain

`anomaly_mode: true` is the default. `anomaly_mode: false` produces only the background above, with zero complete chains. Each episode is:

1. An administrator fails to log in four or more times from its own workstation, a few seconds to a minute apart, then logs in successfully.
2. Seconds later, that administrator creates a temporary account with the selected `Roles.FullAccess` membership.
3. The new incarnation logs in, usually within a minute, and reads the payroll register several times in one session.
4. Its session closes outside the selected output, and the same administrator deletes that exact incarnation, usually within a few minutes.
5. The same administrator then reduces old event-log records.

Every shorter part of this sequence also occurs in background, as described above. What background never contains is the whole ordered sequence joined by one administrator and one incarnation within 30 minutes. Episode timing and counts are drawn within background ranges, not from identical distributions: the temporary login comes sooner (median 40 s), reads are a little more numerous and closer together, and the deletion and reduction always follow within minutes. Episode steps use only seconds that background leaves free, so episodes never delay or re-phase background work. The episode's successful login replaces the administrator's session, as a background retry does.

Linking fields: `user.name`/`user.id` and `client.address` of the administrator; the incarnation UUID in `user.target.id` on creation and deletion; the temporary account's `user.id`; session/connection numbers; and source time. The target UUID/name on user-management records is synthetic collector enrichment from the inventory, not a claimed native Data member. Failed attempts carry only the attempted username and zero session/connection, not verified native failure bytes. Payroll reads are recorded access occurrences; repeated synthetic employee keys do not prove distinct people, returned amounts or exfiltration.

**Recurrence.** `anomaly_interval_hours` is measured in source time and clamped to at least one hour. The first episode becomes due one interval after the window start. Its first failed attempt follows 1-600 s later, or later still while background occupies the seconds, a temporary name is busy or the administrator is under the guard hold. The next episode is due one interval after that actual first attempt, so start times drift later and never catch up. Consecutive episodes alternate the two administrators, use a different temporary name, and always get a fresh incarnation UUID.

Measured episodes, with intervals taken between creations:

- The default 12 h interval gives two per 25 h 05 min window and eight per 100 h. Creations were 12.02-12.15 h after the window start and 12.05-12.48 h apart.
- A 6 h interval gives four per 25 h 05 min window and 16 per 100 h, 6.02-6.60 h apart.
- The minimum 1 h interval gives 22 episodes per 25 h 05 min, 0.99-1.37 h apart.
- Across 70 episodes: 4-17 failed attempts in the 15 minutes before the login, 3-31 payroll reads, and 220-1,638 s from the first detected failure to the reduction.

**Counts.** At the default interval, episodes add two occurrences a day to each partial step, against the background rates above. Over the pooled 12 h captures (300 h with anomalies, 500 h without), administrator runs of four or more failures occur 7.8 times a day with anomalies against 6.9 without (z 1.0). Creations preceded by four or more creator failures occur 7.4 times a day with anomalies against 4.7 without (z 3.3 over those 800 hours). One week of each mode is expected to give z of about 1.6 for this count. At 6 h the second count rises to about 9 a day, and at 1 h the partial-step counts reveal the mode.

Detection idea: join four or more failures of one administrator, its successful login, a user creation by it within minutes, and the new incarnation's payroll reads. Then join the deletion of that same UUID by the same administrator and a following event-log reduction. These signals do not establish recent-log erasure or exfiltration.

## Log management assumptions

An existing old event-log history predates capture. Each modeled reduction uses an older-than-midnight cutoff before the capture's current day. 1C preserves the cutoff date from midnight onward, so no claim is made that the just-emitted sequence was removed. The source has no in-memory history simulation, and the reduction's full native Data/cutoff payload is omitted because it was not established. `TruncateEventLog()` is the documented operation, not deprecated SQLite-only `ClearEventLog()`.

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
| `anomaly_interval_hours` | `12` | Source-time interval between episodes, clamped to at least one hour |

Keep the one-second, count-one cron cadence: all timings are drawn in source seconds. Actor UUIDs, names, workstations, OS accounts, weights, object permissions and metadata/logged column names are in `samples/actors.json` and `samples/objects.json`. Every record there must keep the same field order, and weights must be numeric. Accounts with `role: Roles.FullAccess` act as administrators. Keep at least two of them so that consecutive episodes can rotate administrators. The four temporary names are fixed in the template. Editing the inventory requires matching configuration permissions and audit setup.

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

For a finite batch, copy `generator.yml` to `generator.batch.yml` beside it and add a window under `input[0].cron`:

```yaml
start: '2026-09-25T00:00:00+00:00'
end: '2026-09-26T01:05:00+00:00'
```

```bash
eventum generate --path generators/application-1c/generator.batch.yml --id one-c-batch --live-mode false --keep-order true
```

This window yields about 8,600-9,000 records with two episodes at the default interval. A live run shows only background until the first interval has passed. `--keep-order true` preserves source order through the asynchronous writer. Timestamps are rendered in UTC whatever the CLI time zone. Check that the output is non-empty and that no errors were logged, because the CLI can exit with status 0 after template-render failures.

## Validation

Twenty finite captures were generated from the final source, all with exit status 0 and empty `-vvv` logs:

- four default pairs (`true`/`false`) of 25 h 05 min;
- two pairs of 25 h 05 min with every event parameter overridden and a 6 h interval, using a Unicode, quote and ampersand infobase name, a `+03:00` window and `--timezone Europe/Moscow`;
- one 25 h 05 min run at the 1 h minimum;
- 100-hour captures: two with anomalies at 12 h, one at 6 h, and four without.

A streaming verifier checks:

- the 23-field source union and per-class field sets;
- UTC seconds and parameter values;
- object permissions, and authentication before every operation, with pre-window sessions constant until the next login;
- monotonic session numbers;
- the temporary-incarnation lifecycle and bounded state;
- episode recurrence (on creation times), rotation, causal joins and duplicate chain matches;
- zero complete chains without anomalies;
- tolerance comparisons of every background decision between the modes: rates, category mixes, two-sample KS on timing distributions, exact small-sample tests on values beyond the other mode's range, and the rate of creations preceded by one to four creator failures;
- determinism checks for fixed periods, name rotation, repeated gaps, aligned clocks and constant counter steps, per capture and pooled.

All 20 captures, 21 pairs (8 on/off, 11 off/off, 2 on/on) and 5 pooled comparisons pass. The calibrated `mode_compare.py` comparison returns OK for every default, custom and 100-hour pair (12 h and 6 h) and for the off/off pairs. It fails only the 1 h run, as the counts section expects.

Nine negative inputs are each rejected by their intended check:

- the previous source's captures (fixed 2-hour lifecycle, 10-second clock);
- background with repeated failures removed;
- a 20-minute lifespan floor;
- background without creations after three or more creator failures (the earlier guard);
- a fixed temporary-name rotation;
- a mode swapped in both directions;
- a 6 h capture checked against 12 h;
- an episode reusing the previous episode's temporary name.

## Sample Output

This user-creation record is row 4,162 of the default `true` capture, the creation step of its first episode, pretty-printed with non-ASCII characters unescaped. The target identity is inventory enrichment, and its `Roles` array is only the selected native Data subset:

```json
{
  "@timestamp": "2026-09-25T12:08:13+00:00",
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
      "name": "svc_audit_04",
      "id": "1c308303-6015-45cd-83cf-960eaf475628"
    }
  },
  "client": {
    "address": "ADM-WS-01"
  },
  "related": {
    "user": [
      "admin01",
      "svc_audit_04"
    ],
    "hosts": [
      "ADM-WS-01"
    ]
  },
  "message": "Пользователи.Новый пользователь",
  "one_c": {
    "event_log": {
      "level": "Information",
      "date": "2026-09-25T12:08:13+00:00",
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
      "connection": 596,
      "session": 1511,
      "server_name": "srvr-1c-01.example.test",
      "port": 1541,
      "sync_port": 1542,
      "session_data_separation": {},
      "session_data_separation_presentation": []
    }
  }
}
```

## References and Limits

- [1C Administrator Guide 8.3.27](https://1c-dn.com/library/tutorials/1c_enterprise_administrator_guide_file_mode_8_3_27/), sections 6.13.3/6.13.5/Appendix 2: XML example/field types, sequential storage, settings exclusivity and old-date cutoff semantics.
- [1C Developer Guide 8.3.27](https://1c-dn.com/library/tutorials/1c_enterprise_developer_guide_8_3_27/), chapter 22 and Appendix 5: access setup, nested logged tables, object-level denial Right, OSUser/Roles examples, truncation and administration/export permissions.
- [Native platform event changes](https://1c-dn.com/library/v8update_2079252603_changes_performed_after_version_publication/) document user-management errors and EventLogReduce; [earlier behavior changes](https://1c-dn.com/library/v8update_027v8SmKe5_changes_affecting_the_system_behavior/) document interactive/programmatic user create/update/delete and successful-authentication-only attribution.
- [Integer-second event-log time presentation](https://1c-dn.com/library/v8update_2756468690_changes_that_affect_system_behavior/) supplies source precision; it does not establish exact XML timezone spelling.

**BLOCKED_RAW_EVIDENCE:** full same 8.3.27 native exports for all selected system classes and complete Data shapes, exact failed-auth attribution/session fields, event-specific levels/translations/comments, native session-end body and live exporter/SIEM parser remain unavailable after bounded source research. This pack accepts selected documented semantics with explicit synthetic inventory/collector encodings. It does not prove full native byte parity, a production configuration, malicious intent, actual privileges from role names, or recent-log erasure. Internal session closure is not an emitted native record. The source XML example and current appendix/developer terminology differ in some naming details; the retained collector field names/compound configuration names are not claimed as an exact current XML serializer.

Synthetic behavior limits:

- Rates are stationary, with no working hours or weekends. At most one record falls in each source second.
- Temporary accounts always log in from their creator's workstation.
- Staff sessions end silently after a random lifetime, and pre-window sessions are assumed rather than observed.
- The random draws have long tails, so individual episodes or lifecycles can be unusually long.
- Administrator failed logins are frequent by design (about 6.7 runs of four or more a day), so that the chain's first steps occur in background at a comparable rate.
- Short anomaly intervals make partial-step counts diagnostic, as described in Anomaly Chain.

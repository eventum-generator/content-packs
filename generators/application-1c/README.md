# 1C:Enterprise Event Log Generator

Generates a selected **1C:Enterprise 8.3.27 event-log collector projection** for a client/server, single-data-area infobase using sequential `.lgf` storage. This is the event log, not the separate technological log. Output is ECS-style JSON with snake_case source fields under `one_c.event_log`. It is not a native XML or `.lgf` export, and has no fabricated `event.original`.

The source inventory has five existing staff accounts, four temporary account names reused after deletion, and five fictional configuration objects. Each new temporary incarnation gets a fresh UUID. The assumed Enterprise thick client keeps its selected connection during one modeled session. Administrator and temporary `Roles.FullAccess` explicitly grant Administration, DataAdministration and Read on this synthetic configuration. Accountant can read all five objects; Sales and Warehouse cannot read the payroll register. These are configured scenario permissions, not privileges inferred from a role name.

## Event Types

| System event | Selected behavior | Default enabled capture count |
|---|---|---:|
| `_$Access$_.Access` | Successful controlled reads with nested logged rows | 7801 |
| `_$Access$_.AccessDenied` | Object-level Read permission denial | 500 |
| `_$Session$_.Authentication` | Successful authentication opens a selected session | 332 |
| `_$Session$_.AuthenticationError` | Failed attempted identity; no native authenticated UUID is asserted | 285 |
| `_$User$_.New` | Create one temporary account | 14 |
| `_$User$_.Update` | Update an existing staff account; unproved native Data omitted | 71 |
| `_$User$_.Delete` | Delete the previously created temporary incarnation | 14 |
| `_$InfoBase$_.EventLogReduce` | Reduce pre-existing records older than the assumed cutoff | 14 |

One reusable Jinja file contains a bounded state machine, emitted through one FSM template entry. One event is selected every ten seconds, with UTC second-resolution source/collector time. Ordinary slot choices use weights Access/Denied/failed-auth/user-update `90:6:3:1`. Session setup, permission checks and maintenance replace some choices, so emitted shares differ. These rates are synthetic workload settings, not vendor production frequencies.

At capture start no modeled session is open. A selected operation first emits authentication when its actor has no current session. Staff sessions last at most one modeled hour, and a new authentication internally closes the previous selected session before allocating fresh global session/connection numbers. Session-end records are outside the selected output because their exact native class/body was not established. Therefore the stream does not itself prove when a session ended. Both modes keep the same source actors, workstation names and individual event classes.

Ordinary temporary-account maintenance begins about every two hours when its slot is free. The administrator creates an account, it authenticates ten minutes later, makes one payroll read ten minutes after that, then its modeled session closes and the administrator deletes it another ten minutes later. An old-log reduction is eligible ten minutes after deletion. An administrator reauthentication can delay an operation by one tick. The complete ordinary lifecycle finishes before an episode starts. A failed ordinary authentication is followed by successful authentication of the same account on the next tick. No unknown workstation or account-name family labels the mode.

## Anomaly Chain

`anomaly_mode: true` is the default. Every twelve hours of generated source time, when ordinary cleanup is complete:

1. Four failed attempts use the same administrator and workstation.
2. A successful administrator authentication precedes creation of one temporary user with the selected `Roles.FullAccess` membership.
3. That temporary incarnation authenticates, then makes twelve logged payroll reads in its same session/connection.
4. Its session closes internally before the administrator deletes that exact incarnation.
5. The administrator reduces old event-log records.

The **21 emitted records span 200 seconds** at the shipped cadence. Actor UUIDs, creation/deletion target UUID, session/connection, workstation, infobase and source time support correlation. The target UUID/name on user-management records is explicitly synthetic collector enrichment from the modeled inventory, not a claimed native Data member. Failed authentication exposes only the normalized attempted username from that inventory. Native `user_id` and `user_name` are omitted on failure instead of inventing authenticated attribution; zero session/connection expresses the selected unsuccessful-session model, not verified native failure bytes.

Twelve reads mean recorded access occurrences. Synthetic employee strings can repeat and do not prove twelve distinct people, returned amounts, exported data or exfiltration. Successful read semantics depend on access auditing configured before capture: the fictional payroll register has a string Employee field and an Amount access field; its Employee value is logged. The other objects have a string RecordKey recorded field. Logged rows encode a 1C ValueTable as a JSON array of row objects. The selected profile does not reproduce a full typed XML serialization.

The next interval resets at the actual first failed attempt. Ordinary sessions/maintenance finish first, so a due episode can wait; there is no catch-up burst or overlapping temporary account. A four-name cursor advances at every ordinary or episode creation; adjacent episodes can reuse a name because ordinary creations also advance it. Each incarnation still has fresh UUID/session values. State retains five staff session slots, one temporary user/session, a four-name cursor and fixed phase/timer/counter slots. No user or session history grows. A finite run may end with one active temporary account or a session, without fabricated final cleanup.

`anomaly_mode: false` retains isolated failures, successful sessions, temporary creation/authentication/read/deletion, user updates, denials and reductions, with zero complete dense sequences. Ordinary maintenance uses the same FullAccess membership, actor/workstation and payroll read, separated by minutes. The injected correlation is distinguished by four failures and twelve dense reads, not a special native marker.

Detection ideas: correlate four same-administrator/workstation failures followed by success, then a freshly created target UUID with twelve dense payroll accesses in one session. Join creation and deletion of that exact incarnation, followed by old-history reduction. These signals do not establish recent sequence erasure or exfiltration.

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
| `anomaly_mode` | `true` | Include recurring dense sequences |
| `anomaly_interval_hours` | `12` | Positive finite source-time interval, clamped to at least one hour |

Keep the ten-second/count-one cadence for documented timings. Actor UUIDs/names, OS accounts, configuration role permissions and metadata/logged column names are in `samples/actors.json` and `samples/objects.json`. All sample records must retain consistent field order, and weight columns must be numeric. Keep the administrator `admin01` and update target `accountant02` names because the source selects those inventory entries. Temporary names remain the fixed four-name family. Custom event parameters change server/collector/infobase context; editing actor/object inventory requires matching configuration permissions and audit setup.

### Output Parameters

The shipped local `output/events.json` file requires no top-level `${params.*}` or `${secrets.*}` values. Replace the output plugin to send the selected JSON projection to a SIEM. Real XML/.lgf parsing must be tested against an actual native export.

## Usage

From the content-packs repository root:

```bash
uv run --project ../eventum eventum generate --path generators/application-1c/generator.yml --id one-c --live-mode true
```

For a finite sample, copy the config beside the original, set cron `start: 2026-09-25T00:00:00Z` and `end: 2026-09-26T01:05:00Z`, and run that path with `--live-mode false --keep-order true -vv`. Batch mode alone does not bound an open-ended schedule. Serialize heavy commands with `flock -x /tmp/eventum-generator-heavy.lock`. Check nonempty output and errors, because CLI exit 0 alone can still accompany template-render failures.

## Validation

Four finite 25h05 runs with all event parameter overrides and a minimum-one-hour run completed with exit 0, nonempty 9031-row outputs and no error log. Custom input/CLI Europe/Moscow normalized to UTC. Source/collector shapes, actor permission inventories, session-before-operation gates, temporary incarnations and recurring correlations were checked by a streaming verifier.

| Capture | Records | Complete episodes | Temporary create/delete | Peak modeled accounts |
|---|---:|---:|---|---:|
| `default_on` | 9031 | 2 | 14/14 | 6 |
| `default_off` | 9031 | 0 | 12/12 | 6 |
| `custom_on` | 9031 | 4 | 16/16 | 6 |
| `custom_off` | 9031 | 0 | 12/12 | 6 |
| `stress_on` | 9031 | 25 | 37/37 | 6 |

Meaningful negative captures reject authentication before temporary creation, reuse of a deleted incarnation UUID, and substitution of an otherwise authorized accountant/session for one dense-chain read. The actual original 189af14 generator ran separately for twenty minutes: 14,412 records created 35 temporary names and deleted none, with about 35-second chains. That fails the current source-time and bounded lifecycle criteria. No obsolete implementation pass is claimed.

## Sample Output

This complete synthetic user-creation projection was copied from the first default enabled episode. The target identity is inventory enrichment, and its Role array is only the selected native Data subset:

```json
{
  "@timestamp": "2026-09-25T12:00:50+00:00",
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
      "name": "svc_audit_02",
      "id": "74f166bc-7e70-42cb-9bec-2396bca05664"
    }
  },
  "client": {
    "address": "ADM-WS-01"
  },
  "related": {
    "user": [
      "admin01",
      "svc_audit_02"
    ],
    "hosts": [
      "ADM-WS-01"
    ]
  },
  "message": "Пользователи.Новый пользователь",
  "one_c": {
    "event_log": {
      "level": "Information",
      "date": "2026-09-25T12:00:50+00:00",
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
      "connection": 457,
      "session": 1357,
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

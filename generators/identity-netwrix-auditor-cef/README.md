# Netwrix Auditor CEF Export

Netwrix Auditor audit trail for Active Directory changes and domain logons, as exported by the Netwrix Auditor SIEM Generic Integration for CEF Export add-on. Each event is one Activity Record rendered as a CEF line (kept in `event.original`) and parsed into ECS the way the Filebeat `decode_cef` processor does it.

The modelled domain has about 3,000 staff. Staff log on to their workstations when they arrive and to file, application and terminal servers during the day; three admins and nine helpdesk operators reset passwords, edit accounts, change group memberships and manage computer accounts, and an accounts desk of three helpdesk operators handles most onboarding, offboarding and test accounts.

## Event Types

Measured on the default configuration, 14 days, `anomaly_mode: true` (311,581 events).

| CEF class ID / name | Data source | Share | ECS category |
| --- | --- | --- | --- |
| `Successful Logon` / `Successful Logon Logon` | Logon Activity | 91.4% | `authentication` |
| `Failed Logon` / `Failed Logon Logon` | Logon Activity | 6.1% | `authentication` |
| `Modified` / `Modified user` | Active Directory | 1.3% | `iam` |
| `Modified` / `Modified group` | Active Directory | 0.79% | `iam` |
| `Modified` / `Modified computer` | Active Directory | 0.14% | `iam` |
| `Added` / `Added computer` | Active Directory | 0.10% | `iam` |
| `Removed` / `Removed computer` | Active Directory | 0.04% | `iam` |
| `Added` / `Added user` | Active Directory | 0.038% | `iam` |
| `Removed` / `Removed user` | Active Directory | 0.036% | `iam` |
| `Added` / `Added group` | Active Directory | 0.02% | `iam` |
| `Removed` / `Removed group` | Active Directory | 0.02% | `iam` |

## Volume and Timing

About 22,000 records a day, following a working day in UTC:

| UTC hours | Records per hour | People logging on per hour |
| --- | --- | --- |
| 00-06, 20-24 | 75-95 | 45-65 |
| 06-07 | about 660 | about 300 |
| 07-09 | 1,850-2,450 (morning arrivals) | 1,000-1,400 |
| 09-16 | 1,780-2,000 | 1,050-1,220 |
| 16-19 | 1,650 falling to 580 | 940 falling to 400 |
| 19-20 | about 150 | about 120 |

- **Staff.** Each person opens the working day with a workstation logon, mostly between 06:00 and 10:00 UTC (peak around 08:00), and stays about nine hours; on a given day about 85% come in, a few work late or at night. During the day each logs on to servers every hour or two. About 7% of workstation logons and 3% of server logons follow one to four mistyped attempts, each repeat less likely than the one before.
- **Operators.** Operators come in every morning, mostly between 07:00 and 08:30 UTC, unless absent (about one day in twelve), and stay about nine hours. Directory changes run 08:00-17:00 UTC at about 45 an hour; outside those hours an operator at work or on call makes about 2-3 an hour.
- **Account lifecycle.** About twelve account tasks a day, 08:00-17:00 UTC: onboarding and offboarding in equal numbers (the staff pool stays within 85-120% of `staff_count`), and about two a day of accounts created by mistake or for a test and deleted within minutes without being used. The accounts desk does nine in ten of them while one of its operators is at work. An account is not offboarded while a password reset or a logon of its own is still in progress.
- **Correlated records.** Records that belong together (retries after a mistyped password, the edits after an account is created, the failures of an old saved password) follow each other seconds to minutes apart: a mistyped password is followed by the successful logon to the same host after a median of 10 s.

## Anomaly Chain

A short-lived account that is used before it disappears: an accounts desk operator creates an account, the account logs on, and the same operator deletes it again, 9 minutes to about 2.5 hours after the creation, typically 30-60 minutes.

1. `Added` / `Added user` - operator `suser` creates the account; `filePath` ends with its name. Attribute edits (`Modified user`) follow within seconds, sometimes group changes (`Modified group`).
2. `Successful Logon` - the new account (`suser=EXAMPLE\<name>`) logs on to its workstation, sometimes after mistyped attempts (`Failed Logon`), after a median of 25 minutes, and logs on to servers like any other account while it exists.
3. `Removed` / `Removed user` - the same operator deletes the account, a median of 10 minutes after the logon. The account stops logging on.

- **Linking fields:** account name (last segment of `filePath` on user changes, the name after the domain in `suser` on logons); operator `suser` on steps 1 and 3.
- **Recurrence:** every `anomaly_interval_hours` (default 24, minimum 6) of source time, but only in the accounts desk's working hours (08:00-17:00 UTC) and while a desk operator is at work. The first episode starts within the first `min(interval, 24 h)`, or anywhere in the first working day when that span ends earlier, at an hour drawn from the desk's working-hours curve. Each later episode is due one interval after the previous start. When the due time falls in 08:00-17:00 UTC, the episode starts within `due +- min(interval / 4, 6 h) / 2`; when it falls outside those hours, the episode starts at a time drawn across the next working day. Over many episodes the start hours spread over the whole working day like the desk's own account creations. When no desk operator would still be at work at the drawn time, the start is redrawn earlier within the same window. The next episode counts from the actual start; missed episodes are not replayed.
- **Spacing by interval:** lifecycle work only happens in desk hours, so the interval sets the spacing within that frame. At 24 h, one episode a day, 21-27 h apart. From 9 to 23 h, one episode a day at any working hour, 15-33 h apart: a due time in the evening or at night moves the episode into the next working day. From 6 to 8 h, a second episode follows about one interval later on the same day when the first starts before 17:00 UTC minus the interval (before 11:00 at 6 h, before 09:00 at 8 h), about one day in three at 6 h and one in ten at 8 h; otherwise one a day. Above 24 h the same rule applies: a due time in desk hours keeps the interval, and a due time in the evening or at night moves the episode into the next working day. Multiples of 24 h keep their spacing; an interval whose remainder after whole days is 9-15 h behaves like the next whole number of days (36 h gives gaps of about 44-52 h).
- **Variation:** the operator is one of the three accounts desk operators, other than the previous episode's operator unless no other is at work. The account name, container, workstation, number of edits and groups, and the mistyped attempts are new each time.
- **Background:** every step also occurs on its own in both modes, by the same three operators: onboarding with a first logon at the desk (about three in ten new hires, same 25-minute median delay), test accounts created and deleted within minutes by the same operator without a logon, and offboarding (half direct deletions, half disabled first) of accounts that logged on shortly before. Each desk operator creates and deletes about eight accounts per four days in background (3-16 of each in a four-day window). Only the complete ordered chain is absent from background: an account is never offboarded within five hours of its creation.
- **Detection idea:** join `Added user` and `Removed user` records for the same account and operator within a few hours, with a `Successful Logon` by that account in between.

`anomaly_mode` defaults to `true`. With `false`, the generator emits background only, with no complete chain. With `true`, each episode adds its own records (one account creation and deletion, a few edits and logons), so account creations and deletions are about one per episode higher.

## Parameters

### Event Parameters

| Parameter | Default | Description |
| --- | --- | --- |
| `anomaly_mode` | `true` | Add anomaly chain episodes; `false` emits background only |
| `anomaly_interval_hours` | `24` | Episode interval in hours (6 to 8760); see Spacing by interval above for how it maps to episode spacing |
| `domain` | `example.local` | DNS domain: host names and the `\local\example` object path prefix |
| `netbios` | `EXAMPLE` | NetBIOS domain in `suser` |
| `staff_count` | `3000` | Staff accounts (100 to 20,000); onboarding and offboarding keep the pool within 85-120% of it |

The staff and operator names are the same on every run: they are built from `samples/surnames.csv`. Servers and their shares of server logons are in `samples/servers.csv`, groups and their shares of group changes in `samples/groups.csv`; three domain controllers are built in. The volume and the hour curve come from the files in `patterns/` (one file per band, `ratio` = records per day); to model a larger or smaller domain, scale the `ratio` values together with `staff_count`.

### Output Parameters

The pack writes to `output/events.json` and uses no `${params.*}` or `${secrets.*}` placeholders. To send events elsewhere, replace the `output` block with another output plugin and put its endpoint and credentials into `${params.*}` / `${secrets.*}` placeholders.

## Usage

Live mode, from the content-packs repository root:

```bash
eventum generate --path generators/identity-netwrix-auditor-cef/generator.yml --id netwrix --live-mode true
```

Batch mode: set `start` to midnight UTC of the first day and `end` to the end of the window (for example `start: "2026-09-01T00:00:00Z"`, `end: "2026-09-05T00:00:00Z"`) in every file under `patterns/`, then run:

```bash
eventum generate --path generators/identity-netwrix-auditor-cef/generator.yml --id netwrix --live-mode false --keep-order true
```

For background only, set `event.template.params.anomaly_mode` to `false` in `generator.yml`.

Performance: about 4,400 events per second (14 days, 312,000 events, in about 70 seconds).

## Format Notes and Limitations

- Netwrix publishes one complete raw record for the current add-on (10.8, `Added user`, on the "Work with Collected Data" page listed in References) and no field map. The pack keeps its header and its five extension keys in the published order: `shost` (Where), `cat` (ObjectType), `suser` (Who), `filePath` (What), `start` (When, `MMM dd yyyy HH:mm:ss`). Backslashes are escaped as in the sample.
- Inferred, not published: records of other classes follow the same pattern; the header product is the data source (`Active Directory`, `Logon Activity`); the name is `<Action> <ObjectType>` as in `Added user`, which gives `Successful Logon Logon`; severity `0` and header version `1.0` for every record; `start` in UTC. Actions and object types come from the Netwrix list of monitored actions per data source and the Integration API example records (`ObjectType` `Logon`, `What` = the computer logged on to).
- Not emitted: the `Workstation` of an Activity Record (the add-on's CEF key for it is not documented) and `msg`, which the add-on uses for Details (before/after values, group members) but whose content format is not published. Group membership changes therefore do not name the member.
- The Activity Record `When` has second precision, so `@timestamp` and `event.start` have no fractions. `@timestamp` is the record time, not the export time (the add-on exports in scheduled batches).
- ECS parsing follows `decode_cef` (`source.domain` = `shost`, `source.user.name` = `suser`, `file.path` = `filePath`); `event.category`, `event.type`, `event.action`, `event.outcome`, `user.*` and `related.*` are enrichment an ingest pipeline would add.
- Only Active Directory user, group and computer changes and Logon Activity logons are modeled. There is no weekly cycle: every day is a working day. Volumes, mixes and names are synthetic.
- Records that belong together follow each other seconds apart, not milliseconds; at night, when there is little activity, they can be minutes apart.
- Assumed lockout policy: no account lockout, or a threshold of 10 or more failed attempts with the counter reset after at most 30 minutes without a failure (the current Windows default is 10 attempts and 10 minutes). Counted that way, the failed logons of one account rarely exceed six and reached eight or nine at most in two weeks of output; runs of ten or more are possible but very rare, and lockout records are not modeled.
- Assumed workload: twelve operators for about 3,000 staff; about twelve account lifecycle tasks a day, two of them test or mistaken accounts that are deleted within minutes.

## Sample Output

An episode's `Added user` record from the default `anomaly_mode: true` capture:

```json
{
  "@timestamp": "2026-09-01T13:19:16Z",
  "cef": {
    "device": {
      "event_class_id": "Added",
      "product": "Active Directory",
      "vendor": "Netwrix",
      "version": "1.0"
    },
    "extensions": {
      "deviceEventCategory": "user",
      "filePath": "\\local\\example\\Users\\fpeterson2",
      "sourceHostName": "dc-03.example.local",
      "sourceUserName": "EXAMPLE\\hd.scampbell",
      "startTime": "2026-09-01T13:19:16Z"
    },
    "name": "Added user",
    "severity": "0",
    "version": "0"
  },
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "added-user",
    "category": [
      "iam"
    ],
    "code": "Added",
    "dataset": "cef.log",
    "kind": "event",
    "module": "cef",
    "original": "CEF:0|Netwrix|Active Directory|1.0|Added|Added user|0|shost=dc-03.example.local cat=user suser=EXAMPLE\\\\hd.scampbell filePath=\\\\local\\\\example\\\\Users\\\\fpeterson2 start=Sep 01 2026 13:19:16",
    "severity": 0,
    "start": "2026-09-01T13:19:16Z",
    "type": [
      "user",
      "creation"
    ]
  },
  "file": {
    "path": "\\local\\example\\Users\\fpeterson2"
  },
  "message": "Added user",
  "observer": {
    "product": "Active Directory",
    "vendor": "Netwrix",
    "version": "1.0"
  },
  "related": {
    "hosts": [
      "dc-03.example.local"
    ],
    "user": [
      "hd.scampbell",
      "fpeterson2"
    ]
  },
  "source": {
    "domain": "dc-03.example.local",
    "user": {
      "name": "EXAMPLE\\hd.scampbell"
    }
  },
  "user": {
    "domain": "EXAMPLE",
    "name": "hd.scampbell",
    "target": {
      "name": "fpeterson2"
    }
  }
}
```

## References

- [Netwrix Auditor 10.8: CEF Export, Work with Collected Data (raw sample)](https://docs.netwrix.com/docs/auditor/10_8/addon/siemcefexport/collecteddata)
- [Netwrix Auditor 10.8: CEF Export overview](https://docs.netwrix.com/docs/auditor/10_8/addon/siemcefexport/overview)
- [Netwrix Auditor 10.8: Run the add-on with PowerShell (msg = Details)](https://docs.netwrix.com/docs/auditor/10_8/addon/siemcefexport/powershell)
- [Netwrix Auditor 10.7: Activity Record reference](https://docs.netwrix.com/docs/auditor/10_7/api/activityrecordreference)
- [Netwrix Auditor 10.7: Search parameters reference (example records)](https://docs.netwrix.com/docs/auditor/10_7/api/filterreference/)
- [Netwrix Auditor 10.8: Monitored object types and actions](https://docs.netwrix.com/docs/auditor/10_8/requirements/supporteddatasources/monitoredobjecttypes)
- [Microsoft Sentinel Netwrix Auditor parser](https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Netwrix%20Auditor/Parsers/NetwrixAuditor.yaml)
- [Filebeat decode_cef processor](https://www.elastic.co/guide/en/beats/filebeat/current/processor-decode-cef.html)

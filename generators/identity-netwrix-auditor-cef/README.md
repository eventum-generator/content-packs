# Netwrix Auditor CEF Export

Netwrix Auditor audit trail for Active Directory changes and domain logons, as exported by the Netwrix Auditor SIEM Generic Integration for CEF Export add-on. Each event is one Activity Record rendered as a CEF line (kept in `event.original`) and parsed into ECS the way the Filebeat `decode_cef` processor does it.

Staff log on to their workstations and to servers in randomly phased work sessions; helpdesk and admin operators reset passwords, edit accounts, change group memberships, onboard and offboard users and manage computer accounts while on duty, with an on-call operator covering the hours when nobody is on shift.

## Event Types

Measured on the default configuration, 120 h, `anomaly_mode: true` (11,875 events).

| CEF class ID / name | Data source | Share | ECS category |
| --- | --- | --- | --- |
| `Successful Logon` / `Successful Logon Logon` | Logon Activity | 70.1% | `authentication` |
| `Failed Logon` / `Failed Logon Logon` | Logon Activity | 14.2% | `authentication` |
| `Modified` / `Modified user` | Active Directory | 8.2% | `iam` |
| `Modified` / `Modified group` | Active Directory | 4.0% | `iam` |
| `Added` / `Added user` | Active Directory | 1.0% | `iam` |
| `Removed` / `Removed user` | Active Directory | 1.0% | `iam` |
| `Modified` / `Modified computer` | Active Directory | 0.7% | `iam` |
| `Added` / `Added computer` | Active Directory | 0.3% | `iam` |
| `Removed` / `Removed computer` | Active Directory | 0.2% | `iam` |
| `Added` / `Added group` | Active Directory | 0.1% | `iam` |
| `Removed` / `Removed group` | Active Directory | 0.08% | `iam` |

## Anomaly Chain

A short-lived account that is used before it disappears: an operator creates an account, the account logs on, and the same operator deletes it again, usually within one or two hours.

1. `Added` / `Added user` - operator `suser` creates the account; `filePath` ends with its name. Attribute edits (`Modified user`) follow within seconds, sometimes group changes (`Modified group`).
2. `Successful Logon` - the new account (`suser=EXAMPLE\<name>`) logs on to its workstation, sometimes after mistyped attempts (`Failed Logon`), and starts an ordinary session with server logons.
3. `Removed` / `Removed user` - the same operator deletes the account. The deletion restores the directory state; the account stops logging on.

- **Linking fields:** account name (last segment of `filePath` on user changes, the name after the domain in `suser` on logons); operator `suser` on steps 1 and 3.
- **How an episode is made:** operators regularly create an account by mistake and delete it within minutes; this happens in both modes. An episode takes over the next such create-and-delete pair instead of adding work: the operator's records keep their times and types, and the only addition is that the fresh account logs on in between, after the delay new hires use when they log on at the desk (median 25 min). If the pair's own deletion time already falls after that logon, it is kept; otherwise the deletion follows the logon after a new draw from the same short delay (median 10 min). The operator's own create, edit and delete records are therefore the same with and without episodes; only the logon links them.
- **Recurrence:** every `anomaly_interval_hours` (default 24, minimum 6) of source time. The first episode is due 1 h after generation starts. From its due time plus a random delay of up to `min(1 h, interval / 8)`, the next mistaken-account pair becomes the episode, which adds a wait of its own (on average about 2 h, because mistaken-account pairs are rare). In 9 measured captures the first episode started 4.5-6.6 h after generation began. Measured spacing in 120 h captures: 24.3-31.6 h at the default 24 h interval (mean about 26 h), and 10.2-17 h at 10 h with one longer gap of 25 h when no eligible pair came up for hours. The next due time counts from the actual creation; missed episodes are not replayed.
- **Variation:** the pair must belong to an operator other than the previous episode's, either on shift with at least 1 hour left or on call. Operators take episodes in proportion to how often they create accounts by mistake, which follows their own task rate. The account name, container, workstation, number of edits and groups are new each time; the logon delay is redrawn while above 2 h.
- **Background:** every step also occurs on its own in both modes: onboarding with a first logon at the desk (about a third of new hires), accounts created by mistake and deleted within minutes without a logon (the pairs episodes take over), offboarding of accounts that logged on shortly before (half of the offboardings delete the account directly, the others disable it first), password resets followed by a logon, repeated failed logons by one account within minutes, and quick successive edits by one operator. Only the complete ordered chain is absent from background: background offboarding never picks an account that was created and used to log on within the last 5 h.
- **Detection idea:** join `Added user` and `Removed user` records for the same account and operator within a few hours, with a `Successful Logon` by that account in between.

`anomaly_mode` defaults to `true`. With `false`, the generator emits background only, with no complete chain.

## Parameters

### Event Parameters

| Parameter | Default | Description |
| --- | --- | --- |
| `anomaly_mode` | `true` | Add anomaly chain episodes; `false` emits background only |
| `anomaly_interval_hours` | `24` | Episode interval in hours of source time (6 to 8760) |
| `domain` | `example.local` | DNS domain: host names and the `\local\example` object path prefix |
| `netbios` | `EXAMPLE` | NetBIOS domain in `suser` |
| `staff_count` | `200` | Initial number of staff accounts (20 to 2000); onboarding and offboarding keep the pool within 85-120% of it |

Eight operator accounts (three `adm.*`, five `hd.*`), three domain controllers and twelve servers are built in.

### Output Parameters

The pack writes to `output/events.json` and uses no `${params.*}` or `${secrets.*}` placeholders. To send events elsewhere, replace the `output` block with another output plugin and put its endpoint and credentials into `${params.*}` / `${secrets.*}` placeholders.

## Usage

Live mode, from the content-packs repository root:

```bash
eventum generate --path generators/identity-netwrix-auditor-cef/generator.yml --id netwrix --live-mode true
```

Batch mode: add `start` and `end` to the `cron` input, then run:

```bash
eventum generate --path generators/identity-netwrix-auditor-cef/generator.yml --id netwrix --live-mode false --keep-order true
```

Background only:

```bash
eventum generate --path generators/identity-netwrix-auditor-cef/generator.yml --id netwrix --live-mode true --params '{"anomaly_mode": false}'
```

## Format Notes and Limitations

- Netwrix publishes one complete raw record for the current add-on (10.8, `Added user`, see `reference/vendor-cef-samples.txt`) and no field map. The pack keeps its header and its five extension keys in the published order: `shost` (Where), `cat` (ObjectType), `suser` (Who), `filePath` (What), `start` (When, `MMM dd yyyy HH:mm:ss`). Backslashes are escaped as in the sample.
- Inferred, not published: records of other classes follow the same pattern; the header product is the data source (`Active Directory`, `Logon Activity`); the name is `<Action> <ObjectType>` as in `Added user`, which gives `Successful Logon Logon`; severity `0` and header version `1.0` for every record; `start` in UTC. Actions and object types come from the Netwrix list of monitored actions per data source and the Integration API example records (`ObjectType` `Logon`, `What` = the computer logged on to).
- Not emitted: the `Workstation` of an Activity Record (the add-on's CEF key for it is not documented) and `msg`, which the add-on uses for Details (before/after values, group members) but whose content format is not published. Group membership changes therefore do not name the member.
- The Activity Record `When` has second precision, so `@timestamp` and `event.start` have no fractions. `@timestamp` is the record time, not the export time (the add-on exports in scheduled batches).
- ECS parsing follows `decode_cef` (`source.domain` = `shost`, `source.user.name` = `suser`, `file.path` = `filePath`); `event.category`, `event.type`, `event.action`, `event.outcome`, `user.*` and `related.*` are enrichment an ingest pipeline would add.
- Only Active Directory user, group and computer changes and Logon Activity logons are modeled. There is no working-hours or weekday cycle; sessions are randomly phased per user. Volumes, mixes and names are synthetic.
- Assumed operator workload: eight operators on randomly phased shifts, one task about every 10-20 minutes each while on duty; when nobody is on shift, an on-call operator handles a task about every 40 minutes, so directory changes never stop for hours. Mistyped passwords affect about 7% of workstation logons and 5% of server logons. Accounts created by mistake and deleted within minutes are an assumed 8% of those tasks (several a day); this share is chosen so that an episode, which takes over the next such pair, can start close to its due time. Mistaken accounts get no tickets from other operators.

## Sample Output

An episode's `Added user` record from the default `anomaly_mode: true` capture:

```json
{
  "@timestamp": "2026-09-01T05:59:51Z",
  "cef": {
    "device": {
      "event_class_id": "Added",
      "product": "Active Directory",
      "vendor": "Netwrix",
      "version": "1.0"
    },
    "extensions": {
      "deviceEventCategory": "user",
      "filePath": "\\local\\example\\Corp\\Staff\\amurphy",
      "sourceHostName": "dc-02.example.local",
      "sourceUserName": "EXAMPLE\\hd.dhoward",
      "startTime": "2026-09-01T05:59:51Z"
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
    "original": "CEF:0|Netwrix|Active Directory|1.0|Added|Added user|0|shost=dc-02.example.local cat=user suser=EXAMPLE\\\\hd.dhoward filePath=\\\\local\\\\example\\\\Corp\\\\Staff\\\\amurphy start=Sep 01 2026 05:59:51",
    "severity": 0,
    "start": "2026-09-01T05:59:51Z",
    "type": [
      "user",
      "creation"
    ]
  },
  "file": {
    "path": "\\local\\example\\Corp\\Staff\\amurphy"
  },
  "message": "Added user",
  "observer": {
    "product": "Active Directory",
    "vendor": "Netwrix",
    "version": "1.0"
  },
  "related": {
    "hosts": [
      "dc-02.example.local"
    ],
    "user": [
      "hd.dhoward",
      "amurphy"
    ]
  },
  "source": {
    "domain": "dc-02.example.local",
    "user": {
      "name": "EXAMPLE\\hd.dhoward"
    }
  },
  "user": {
    "domain": "EXAMPLE",
    "name": "hd.dhoward",
    "target": {
      "name": "amurphy"
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

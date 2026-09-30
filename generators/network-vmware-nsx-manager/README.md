# VMware NSX Manager audit syslog

Synthetic VMware NSX-T Data Center 3.2 Manager audit records from `/var/log/syslog`, wrapped in ECS JSON, for testing detections of NSX login abuse and log-forwarding tampering.

Seven administrator workstations work in sessions: a login through `ACCESS_CONTROL` (occasionally after mistyped passwords, sometimes giving up for a while), UI user-info reads (policy API audit), node API (NAPI) reads, rare deletion and re-creation of node syslog exporters, and an explicit logout or none. The accounts are local (`admin` from two workstations, `guestuser1`, `guestuser2`, read-only `audit`) and LDAP (`jdoe@contoso.local`, `asmith@contoso.local`). Around the clock, a monitoring script logs in as `admin` from `10.20.5.40` and polls the node API, and a VMware Skyline collector logs in as `admin` from `10.20.5.20`; its first attempt fails and the retry succeeds, as Broadcom documents.

## Event Types

Shares of a four-day `anomaly_mode: true` output (18,641 records, four episodes).

| Action | Share | Category |
| --- | ---: | --- |
| `user-info-read` - policy audit `ModuleName="AAA"`, `Operation="GetCurrentUserInfo"` | 53.10% | iam |
| `node-api-read` - NAPI `GET /api/v1/node/status`, `/node/version` or `/node/services` | 30.38% | configuration |
| `syslog-exporter-list` - NAPI `GET /api/v1/node/services/syslog/exporters` | 11.64% | configuration |
| `login-success` - `ACCESS_CONTROL` `LOGIN`, status `success` | 2.53% | authentication |
| `logout` - `ACCESS_CONTROL` `LOGOUT`, status `success` | 1.54% | authentication |
| `login-failure` - `ACCESS_CONTROL` `LOGIN`, status `failure` | 0.68% | authentication |
| `syslog-exporter-create` - NAPI `POST /api/v1/node/services/syslog/exporters` | 0.06% | configuration |
| `syslog-exporter-delete` - NAPI `DELETE /api/v1/node/services/syslog/exporters/<name>` | 0.06% | configuration |

Rates, session lengths, response sizes and durations are synthetic; Broadcom publishes no frequency data.

## Volume and Timing

- **Volume.** About 4,700 records a day, varying by about 3% from day to day. The monitoring script accounts for about 60 records an hour at every hour; administrator activity adds about 2 records an hour at night and rises to about 375 an hour between 10:00 and 12:00, following a smooth working-day curve (hours of the generator timezone, UTC by default). Every day has the same shape.
- **Administrators.** About 50 administrator sessions a day, most during working hours. A session lasts from under a minute to several hours (median about 25 minutes); an account is away from half a minute to two days between sessions (median about 90 minutes). Requests of one session are seconds to minutes apart in working hours and further apart at night.
- **Logins.** About 7% of administrator logins start with one or more failed attempts from the same address, seconds to minutes apart; one failure is more common than two, two than three, up to five. After a run of failures, one in five gives up and returns later. The monitoring script logs in about 50 times a day and fails rarely; the Skyline collector logs in about 22 times a day, each time failing once before it succeeds.
- **Exporters.** Three of the five exporters are configured at the start, and a fourth is added, usually within the first day or two; no more than four are configured at any time. Power accounts delete about two node syslog exporters a day on average (none to six on a given day); the deleted exporter is re-created, usually within an hour, by a power account that is logged in at that time.

## Anomaly Chain

One account sends three to five failed `LOGIN` records from its own address, then a successful `LOGIN` from the same address. The session then runs like any other: its requests continue, and within the usual gaps (none to three request intervals after the login) the account deletes one node syslog exporter with a NAPI `DELETE`, which stops forwarding NSX logs to that collector. The session ends with or without a `LOGOUT`, before the account's own next ordinary session, which keeps its usual time. The deleted exporter is re-created later on the same schedule as after ordinary deletions, which appears as `syslog-exporter-create` (a NAPI `POST` line carries no exporter name; the next `GET` of the exporter list shows the larger response).

- **Linking fields:** `user.name` across all steps; `source.ip` on the `LOGIN` records (NAPI lines carry no client address); the exporter name in `url.path`.
- **Timing:** gaps between attempts and requests follow ordinary sessions; the span from the first failure to the delete is usually one to five minutes and never more than about 29 minutes.
- **Recurrence:** `anomaly_interval_hours` (default 24, minimum 6, maximum 8760). The first episode starts within the first `min(interval, 24 h)` of the data; each later one within a window of `min(interval / 4, 6 h)` centred one interval after the previous start. Within these windows the start hour follows the square of the administrators' activity curve plus a small floor, so episodes fall mostly into working hours. An episode waits, usually minutes, for an eligible account and for at least two configured exporters; missed episodes are not replayed.
- **Variation:** each episode uses an account (`guestuser1`, `guestuser2`, `jdoe@contoso.local` or `asmith@contoso.local`, each tied to one workstation address) and an exporter different from the previous episode's, choosing accounts by their ordinary activity. These accounts, their addresses and every exporter also appear in ordinary traffic.
- **Background overlap:** ordinary traffic in both modes contains runs of up to five failed logins by one account followed by a success (about one every two days with three or more), logins that give up, the Skyline failure-success pairs, and exporter deletions by the same power accounts; `jdoe@contoso.local` and `asmith@contoso.local` each delete an exporter in an ordinary session about three times a week, `guestuser1` and `guestuser2` about once or twice a week. Ordinary traffic never contains the full ordered sequence: no account deletes an exporter within 30 minutes after three failures and a success from one address.
- **Detection idea:** per `user.name`, three or more `LOGIN` failures from one `source.ip`, a `LOGIN` success from that address, and a `DELETE` on `/api/v1/node/services/syslog/exporters/` within 30 minutes. Sort by `@timestamp` first. A burst of failures can also be a user with a stale password, and exporter removal can be planned maintenance.

`anomaly_mode` defaults to `true`. With `anomaly_mode: false` the generator produces only the background described above, with no complete chain. Both modes have the same number of records per hour.

## Parameters

### Event Parameters

| Name | Default | Description |
| --- | --- | --- |
| `manager_host` | `nsx-mgr-01` | NSX Manager hostname in the syslog header and `host.name` |
| `anomaly_mode` | `true` | Add recurring anomaly chain episodes to the background |
| `anomaly_interval_hours` | `24` | Hours between episode starts (6-8760) |

### Output Parameters

The shipped config writes `output/events.json` and needs no connection parameters or secrets. To send events to a SIEM, replace the file output in a local copy and reference placeholders such as `${params.opensearch_host}` and `${secrets.opensearch_password}` in the chosen output plugin.

## Usage

```bash
eventum generate --path generators/network-vmware-nsx-manager/generator.yml --id nsx --live-mode false
eventum generate --path generators/network-vmware-nsx-manager/generator.yml --id nsx --live-mode true
```

The daily volume curve is defined by the files in `patterns/` (`ui-floor.yml` and `ui-office.yml` for the administrators, `api.yml` for the monitoring script). They start at 00:00 of the current day and never end; for a finite batch, set `start` and `end` of the `oscillator` in each file to the same absolute times, starting at midnight so the working-day curve keeps its hours. The template holds a copy of the hourly curve for episode placement; keep it in step when changing the pattern files. Account and exporter lists are in `samples/`.

Performance: about 1,500 records per second in batch mode (14 days, 65,231 records, in 44 seconds).

## Sample Output

The exporter deletion of an episode, copied from the `anomaly_mode: true` output above:

```json
{"@timestamp": "2026-09-01T11:56:04.039Z", "ecs": {"version": "8.17.0"}, "event": {"action": "syslog-exporter-delete", "category": ["configuration"], "duration": 484051000, "kind": "event", "original": "2026-09-01T11:56:04.039Z nsx-mgr-01 NSX 16489 - [nsx@6876 comp=\"nsx-manager\" subcomp=\"node-mgmt\" username=\"jdoe@contoso.local\" level=\"INFO\" audit=\"true\"] jdoe@contoso.local \u0027DELETE /api/v1/node/services/syslog/exporters/siem-primary\u0027 200 0 \"\" \"python-requests/2.25.1\" 0.484051", "outcome": "success", "type": ["deletion"]}, "host": {"name": "nsx-mgr-01"}, "http": {"request": {"method": "DELETE"}, "response": {"body": {"bytes": 0}, "status_code": 200}}, "log": {"file": {"path": "/var/log/syslog"}, "level": "info", "syslog": {"appname": "NSX", "msgid": "-", "procid": "16489"}}, "related": {"user": ["jdoe@contoso.local"]}, "url": {"path": "/api/v1/node/services/syslog/exporters/siem-primary"}, "user": {"name": "jdoe@contoso.local"}, "user_agent": {"original": "python-requests/2.25.1"}, "vmware": {"nsx": {"audit": true, "component": "nsx-manager", "subcomponent": "node-mgmt"}}}
```

## Coverage and Limits

- **Format.** Lines follow the NSX-T 3.2 "Log Messages and Error Codes" examples as written to `/var/log/syslog`: RFC 5424 header without the `<PRI>1` prefix (a remote syslog receiver sees `<182>1` in front), `nsx@6876` structured data, and the documented message bodies. `LOGIN` records carry `UserName="<user>@<address>"`; `LOGOUT` records carry the bare user name, as in the documentation example. LDAP accounts log `UserName="<user>@<domain>@<address>"` on failure and the `LdapUserDetailsImpl [...]@<address>` string on success (Broadcom KB 432569 and 323547). Broadcom's 2022 Skyline example shows the value unquoted; this pack uses the quoted form of the 3.2 documentation.
- **Inferred parts.** Broadcom publishes a raw NAPI audit line only for `GET /api/v1/node/services/syslog/exporters`; the `POST` and `DELETE` lines reuse that layout. The manager-node `DELETE .../exporters/<name>` path follows KB 319134 (transport-node form); HTTP 201 for `POST`, response sizes, durations and exporter names are assumptions. Process IDs stay fixed per subcomponent for a run.
- **Version.** NSX 4.2.0 and later do not log successful `LOGIN` records (Broadcom KB 399588), so the chain's success step is not visible there; 4.2 also adds `Src=` to API audit records. This pack is pinned to 3.x behaviour.
- **Not modeled.** Policy and manager API write operations (`update="true"`, `entId`, `New value`), NSX CLI sessions and commands, Workspace ONE logins, `reverse-proxy.log` and envoy access logs, and multi-node manager clusters. The policy audit stream is reduced to `GetCurrentUserInfo`.
- **Timing.** Records that follow each other within milliseconds on a real manager, such as the Skyline failure and its successful retry, are seconds apart here (median about 25 seconds, up to about three minutes at night). Timestamps have millisecond precision and are in time order (occasionally two records share a timestamp).
- **Volume.** Every day has the same working-day curve; weekends and holidays are not distinguished. Exporter deletions and re-creations (about two a day) are more frequent than on a typical production manager.
- **Episodes.** With `anomaly_mode: true` each episode adds its own records, so counts of the chain parts (failure runs of three or more, successes after them, exporter deletions) are about one per episode higher; the hourly record count stays the same, so those records take the place of an equal number of ordinary requests.
- **Mapping.** ECS fields repeat values from the native line; `user.name` is the account extracted from `UserName`. `event.action` names are this pack's labels.

## References

- [Broadcom NSX-T 3.2 Log Messages and Error Codes](https://techdocs.broadcom.com/us/en/vmware-cis/nsx/nsxt-dc/3-2/administration-guide/operations-and-management/log-messages-and-error-codes.html)
- [Broadcom KB 318390: Skyline collector NSX-T failed-then-successful logins](https://knowledge.broadcom.com/external/article/318390/skyline-collector-nsxt-endpoints-cause-f.html)
- [Broadcom KB 323547: NSX Manager login records for local, LDAP and Workspace ONE users](https://knowledge.broadcom.com/external/article/323547/nsx-manager-audit-logs-not-showing-sourc.html)
- [Broadcom KB 432569: failed logins of AD accounts on NSX](https://knowledge.broadcom.com/external/article/432569/failed-logons-for-nsx-appliance-seen-on.html)
- [Broadcom KB 319134: node syslog exporter list and delete API](https://knowledge.broadcom.com/external/article/319134/editing-an-nsxt-data-center-edge-transpo.html)
- [Broadcom KB 399588: successful LOGIN missing in NSX 4.2.0 and later](https://knowledge.broadcom.com/external/article/399588)

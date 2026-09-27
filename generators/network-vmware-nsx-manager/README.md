# VMware NSX Manager audit syslog

Synthetic VMware NSX-T Data Center 3.2 Manager audit records from `/var/log/syslog`, wrapped in ECS JSON, for testing detections of NSX login abuse and log-forwarding tampering.

Eight client accounts run independent random sessions: logins through `ACCESS_CONTROL` with occasional mistyped passwords and give-ups, UI user-info reads (policy API audit), node API (NAPI) reads, occasional deletion and re-creation of node syslog exporters, and explicit logouts. The accounts are local (`admin` from three addresses, `guestuser1`, `guestuser2`, read-only `audit`) and LDAP (`jdoe@contoso.local`, `asmith@contoso.local`). A VMware Skyline collector logs in as `admin`; its first attempt fails and the retry succeeds tens of milliseconds later, as Broadcom documents.

## Event Types

Shares are measured on a 120-hour `anomaly_mode: true` capture (16,756 events, four episodes).

| Action | Share | Category |
| --- | ---: | --- |
| `user-info-read` - policy audit `ModuleName="AAA"`, `Operation="GetCurrentUserInfo"` | 64.47% | iam |
| `node-api-read` - NAPI `GET /api/v1/node/status`, `/node/version` or `/node/services` | 20.92% | configuration |
| `syslog-exporter-list` - NAPI `GET /api/v1/node/services/syslog/exporters` | 8.43% | configuration |
| `login-success` - `ACCESS_CONTROL` `LOGIN`, status `success` | 2.52% | authentication |
| `login-failure` - `ACCESS_CONTROL` `LOGIN`, status `failure` | 1.89% | authentication |
| `logout` - `ACCESS_CONTROL` `LOGOUT`, status `success` | 1.27% | authentication |
| `syslog-exporter-create` - NAPI `POST /api/v1/node/services/syslog/exporters` | 0.26% | configuration |
| `syslog-exporter-delete` - NAPI `DELETE /api/v1/node/services/syslog/exporters/<name>` | 0.25% | configuration |

Rates, session lengths, response sizes and durations are synthetic; Broadcom publishes no frequency data. Exporter changes (about eight deletions a day) are more frequent than on a typical production manager, so that the chain's last step also occurs in ordinary traffic.

## Anomaly Chain

One account sends three to five failed `LOGIN` records from one address, then a successful `LOGIN` from the same address. Zero to three ordinary requests follow, then a NAPI `DELETE` of one node syslog exporter by that account, which stops forwarding NSX logs to that collector. The session then continues with ordinary requests and ends with or without a `LOGOUT`. The deleted exporter is re-created later by any power account that is logged in, which appears as `syslog-exporter-create` (a NAPI `POST` line carries no exporter name; the next `GET` of the exporter list shows the larger response).

- **Linking fields:** `user.name` across all steps; `source.ip` on the `LOGIN` records (NAPI lines carry no client address); the exporter name in `url.path`.
- **Timing:** gaps between attempts, the first request after login and later requests come from the same distributions as ordinary sessions; measured spans from the first failure to the delete were 54-215 seconds across the default and 12-hour captures.
- **Recurrence:** `anomaly_interval_hours` (default 24, minimum 6, maximum 8760). The first episode is due one interval after the generator starts. At each due time the episode starts after a random delay of up to `min(30 min, interval / 8)`, and waits until an eligible account is idle, has its own next login more than an hour away, and at least two exporters exist. The next due time is one interval after the actual start; missed episodes are not replayed. Measured gaps were 24.02-24.25 h at the default and 12.06-12.32 h at 12 h.
- **Variation:** each episode uses an account (`guestuser1`, `guestuser2`, `jdoe@contoso.local` or `asmith@contoso.local`, each tied to one workstation address) and an exporter different from the previous episode's. These accounts, their addresses and every exporter also appear in ordinary traffic.
- **Background overlap:** ordinary traffic in both modes contains one to five failed logins by the same account seconds to minutes apart (three to six runs a day of three or more followed by a success within ten minutes), logins that give up, the Skyline failure-success pairs, successful logins followed by exporter deletions, and exporter deletions by every chain account. Only the full ordered sequence is kept out of the background: an ordinary delete that would complete it within 30 minutes is replaced by an exporter list read.
- **Detection idea:** per `user.name`, three or more `LOGIN` failures from one `source.ip`, a `LOGIN` success from that address, and a `DELETE` on `/api/v1/node/services/syslog/exporters/` within 30 minutes. Sort by `@timestamp` first. A burst of failures can also be a user with a stale password, and exporter removal can be planned maintenance.

`anomaly_mode` defaults to `true`. With `anomaly_mode: false` the generator produces only the background described above, with no complete chain.

## Parameters

### Event Parameters

| Name | Default | Description |
| --- | --- | --- |
| `manager_host` | `nsx-mgr-01` | NSX Manager hostname in the syslog header and `host.name` |
| `anomaly_mode` | `true` | Add recurring anomaly chain episodes to the background |
| `anomaly_interval_hours` | `24` | Hours between episode due times (6-8760) |

### Output Parameters

The shipped config writes `output/events.json` and needs no connection parameters or secrets. To send events to a SIEM, replace the file output in a local copy and reference placeholders such as `${params.opensearch_host}` and `${secrets.opensearch_password}` in the chosen output plugin.

## Usage

```bash
eventum generate --path generators/network-vmware-nsx-manager/generator.yml --id nsx --live-mode false
eventum generate --path generators/network-vmware-nsx-manager/generator.yml --id nsx --live-mode true
```

Live mode emits one event at most per second. For a finite batch, add `start` and `end` to the `cron` input.

## Sample Output

The exporter deletion of an episode, copied from the final `anomaly_mode: true` capture:

```json
{"@timestamp": "2026-09-21T00:14:29.497Z", "ecs": {"version": "8.17.0"}, "event": {"action": "syslog-exporter-delete", "category": ["configuration"], "duration": 1117882000, "kind": "event", "original": "2026-09-21T00:14:29.497Z nsx-mgr-01 NSX 4036 - [nsx@6876 comp=\"nsx-manager\" subcomp=\"node-mgmt\" username=\"guestuser2\" level=\"INFO\" audit=\"true\"] guestuser2 \u0027DELETE /api/v1/node/services/syslog/exporters/siem-secondary\u0027 200 0 \"\" \"PostmanRuntime/7.26.1\" 1.117882", "outcome": "success", "type": ["deletion"]}, "host": {"name": "nsx-mgr-01"}, "http": {"request": {"method": "DELETE"}, "response": {"body": {"bytes": 0}, "status_code": 200}}, "log": {"file": {"path": "/var/log/syslog"}, "level": "info", "syslog": {"appname": "NSX", "msgid": "-", "procid": "4036"}}, "related": {"user": ["guestuser2"]}, "url": {"path": "/api/v1/node/services/syslog/exporters/siem-secondary"}, "user": {"name": "guestuser2"}, "user_agent": {"original": "PostmanRuntime/7.26.1"}, "vmware": {"nsx": {"audit": true, "component": "nsx-manager", "subcomponent": "node-mgmt"}}}
```

## Coverage and Limits

- **Format.** Lines follow the NSX-T 3.2 "Log Messages and Error Codes" examples as written to `/var/log/syslog`: RFC 5424 header without the `<PRI>1` prefix (a remote syslog receiver sees `<182>1` in front), `nsx@6876` structured data, and the documented message bodies. `LOGIN` records carry `UserName="<user>@<address>"`; `LOGOUT` records carry the bare user name, as in the documentation example. LDAP accounts log `UserName="<user>@<domain>@<address>"` on failure and the `LdapUserDetailsImpl [...]@<address>` string on success (Broadcom KB 432569 and 323547). Broadcom's 2022 Skyline example shows the value unquoted; this pack uses the quoted form of the 3.2 documentation.
- **Inferred parts.** Broadcom publishes a raw NAPI audit line only for `GET /api/v1/node/services/syslog/exporters`; the `POST` and `DELETE` lines reuse that layout. The manager-node `DELETE .../exporters/<name>` path follows KB 319134 (transport-node form); HTTP 201 for `POST`, response sizes, durations and exporter names are assumptions. Process IDs stay fixed per subcomponent for a run.
- **Version.** NSX 4.2.0 and later do not log successful `LOGIN` records (Broadcom KB 399588), so the chain's success step is not visible there; 4.2 also adds `Src=` to API audit records. This pack is pinned to 3.x behaviour.
- **Not modeled.** Policy and manager API write operations (`update="true"`, `entId`, `New value`), NSX CLI sessions and commands, Workspace ONE logins, `reverse-proxy.log` and envoy access logs, and multi-node manager clusters. The policy audit stream is reduced to `GetCurrentUserInfo`.
- **Timing.** The generator emits at most one event per one-second input tick; events due close together, such as a Skyline failure-success pair, are written on consecutive ticks but keep their own millisecond timestamps, so output order and timestamps stay consistent.
- **Mapping.** ECS fields repeat values from the native line; `user.name` is the account extracted from `UserName`. `event.action` names are this pack's labels.

## References

- [Broadcom NSX-T 3.2 Log Messages and Error Codes](https://techdocs.broadcom.com/us/en/vmware-cis/nsx/nsxt-dc/3-2/administration-guide/operations-and-management/log-messages-and-error-codes.html)
- [Broadcom KB 318390: Skyline collector NSX-T failed-then-successful logins](https://knowledge.broadcom.com/external/article/318390/skyline-collector-nsxt-endpoints-cause-f.html)
- [Broadcom KB 323547: NSX Manager login records for local, LDAP and Workspace ONE users](https://knowledge.broadcom.com/external/article/323547/nsx-manager-audit-logs-not-showing-sourc.html)
- [Broadcom KB 432569: failed logins of AD accounts on NSX](https://knowledge.broadcom.com/external/article/432569/failed-logons-for-nsx-appliance-seen-on.html)
- [Broadcom KB 319134: node syslog exporter list and delete API](https://knowledge.broadcom.com/external/article/319134/editing-an-nsxt-data-center-edge-transpo.html)
- [Broadcom KB 399588: successful LOGIN missing in NSX 4.2.0 and later](https://knowledge.broadcom.com/external/article/399588)

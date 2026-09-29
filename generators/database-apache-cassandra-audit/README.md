# Apache Cassandra Audit Log

Synthetic Apache Cassandra 4.1 audit records written by `FileAuditLogger` to `audit/audit.log` on one node, for SIEM engineers who build and test database access and role-management detections. Each event is ECS JSON; `event.original` holds the raw log line in the logback pattern that Cassandra ships for the audit appender, and `message` holds the pipe-delimited audit entry.

Traffic comes from four application roles on pooled driver connections, four analysts and three DBAs using `cqlsh`, and roles that DBAs create, grant, test, revoke and drop, which reporting hosts then use.

## Volume and Hours

About 38,000 records a day, on UTC clock hours:

- Applications log round the clock: 0.25 records/s at night, 0.45/s from 07:00 and 0.65/s from 08:00 to 18:00. Each pooled connection reconnects every 40 minutes or so (log-normal) with a login, `USE "finance"` and a few re-prepared statements.
- Analysts open about 21 `cqlsh` sessions a day, DBAs about 47, nearly all between 08:00 and 17:00 with a thin evening and on-call night tail. Sessions hold one to a dozen statements a few seconds to minutes apart.
- DBA-created roles are used from reporting hosts about 23 times a day, mostly 07:00-19:00.
- About 6% of logins by people and 2-4% by reporting roles fail (wrong password), followed by a retry or a give-up; one failure in a row is more common than two, two than three. Applications fail about 0.3% of reconnects.

## Event Types

Shares are measured on a 96-hour default `anomaly_mode: true` output (152,801 records).

| Audit type | Category | Share | Produced by |
| --- | --- | ---: | --- |
| `SELECT` | QUERY | 68.42% | Applications, analysts, DBA-created roles, DBA checks |
| `UPDATE` | DML | 26.33% | Applications and analysts (CQL `INSERT` is also logged as `UPDATE`) |
| `DELETE` | DML | 1.39% | `billing_svc` |
| `LOGIN_SUCCESS` | AUTH | 1.22% | Every connection |
| `PREPARE_STATEMENT` | PREPARE | 1.09% | Applications after reconnecting |
| `USE_KEYSPACE` | OTHER | 0.93% | Drivers (`USE "finance"`) and some `cqlsh` sessions |
| `LIST_PERMISSIONS` | DCL | 0.15% | DBAs, often before logging in as a role to check its access |
| `LIST_ROLES` | DCL | 0.15% | DBAs |
| `GRANT` | DCL | 0.08% | DBAs |
| `CREATE_ROLE` | DCL | 0.05% | DBAs |
| `DROP_ROLE` | DCL | 0.05% | DBAs |
| `ALTER_ROLE` | DCL | 0.03% | DBA password rotation for service roles |
| `REVOKE` | DCL | 0.03% | DBAs |
| `ALTER_TABLE` | DDL | 0.02% | DBAs |
| `UNAUTHORIZED_ATTEMPT` | AUTH | 0.02% | Analysts reading `finance.payroll`, roles after a revoke |
| `LOGIN_ERROR` | AUTH | 0.02% | Mistyped passwords |
| `REQUEST_FAILURE` | ERROR | 0.01% | Queries against a misspelled table |

The mix is a synthetic training profile, not a measured production ratio.

## Anomaly Chain

A DBA account creates a login role, grants it `SELECT` on `finance.payroll`, logs in as that role from the same admin host, reads payroll, and removes the role again. This is how a stolen or misused DBA account can extract sensitive data under a throwaway identity and leave little behind.

1. `LOGIN_SUCCESS` - DBA from the admin bastion `10.20.10.5`; sometimes followed by `USE finance;` and an ordinary check.
2. `CREATE_ROLE` - `CREATE ROLE <r> WITH PASSWORD = '*******' AND LOGIN = true;`
3. `GRANT` - `GRANT SELECT ON TABLE finance.payroll TO <r>;`
4. `LOGIN_SUCCESS` - user `<r>`, same source IP, new source port, about 1.5 minutes after the grant.
5. `SELECT` - one to three reads of `finance.payroll` by `<r>`.
6. `LOGIN_SUCCESS` - a new DBA connection from the bastion, usually 4-25 minutes after the reads; `REVOKE SELECT ON TABLE finance.payroll FROM <r>;` in 40% of episodes.
7. `DROP_ROLE` - `DROP ROLE <r>;`, which removes the role and its permissions.

From `CREATE_ROLE` to `DROP_ROLE` an episode usually takes 4-50 minutes, always well within two hours.

**Linking fields:** `source.ip`, the role name in `user.target.name` (DCL) and `user.name` (login, select), `cassandra.audit.scope` = `payroll`.

**Recurrence:** the first episode starts within the first `anomaly_interval_hours` (at most 24 h); each next one starts one interval after the actual start of the previous one, shifted within a window of a quarter of the interval (at most 6 h) centred on that point, with no catch-up. Start times follow the DBAs' working hours: inside each window, an hour is chosen in proportion to the square of its DBA session rate plus a small floor, so with the default 24 h interval episodes start between 08:00 and 17:00 UTC, while short intervals also reach the evening and night. When all role names are in use at the chosen time, the episode starts as soon as one is free, which can put it past its window (rarely, at short intervals). The default interval is 24 h; the minimum accepted value is 6 h.

**Variation:** the DBA differs from the previous episode's DBA, and the role name differs from the previous role name unless that is the only free scratch name. The role is one of the four scratch names (`report_tmp`, `svc_backfill`, `migration_ro`, `dq_check`) that DBAs create and test from the bastion several times a day each. Read count, query text, `LIMIT`, the optional revoke and all gaps are random.

**Role names in use:** at most eight of the ten role names exist at a time. Usually one to three of the four scratch roles exist; all four are in use at once about every second day, and a role that takes the last free scratch name or brings the roles in use to eight is dropped again within an hour or so, often by another DBA. The more scratch roles exist, the more often a DBA gives a new role another name. An episode's role counts like any other role: an episode begins only while a scratch name is free and fewer than eight role names are in use, and while its role exists new ordinary roles get scratch names less often. With `anomaly_mode: true` the number of scratch roles that exist at once is one higher for the length of an episode; all four are in use at once during about a quarter of episodes.

**Ordinary look-alikes (both modes):** DBAs create the same role names, grant `finance.payroll` or other tables, test most new roles from their own host, log in as existing roles to check their access, read payroll themselves, and revoke and drop roles. Per day of background, about 5-7 roles are dropped within two hours of creation and about 8-10 new roles read payroll from a DBA host. `hr_portal`, `reporting_etl` and `hr_lead_mora` read payroll all day. Only the complete ordered sequence above within two hours is absent from ordinary traffic: an ordinary DBA does not drop, from the same address and within two hours of its creation, a role that was granted payroll, logged in and read payroll from that address; it drops another unused role instead, or none when no other role is unused, and removes that role in a later session after the two hours; the same drop after two hours or from another address is written as usual. The DBAs' ordinary sessions go on unchanged around an episode; with `anomaly_mode: true` each episode adds its own records on top, so counts of the chain parts are about one per episode higher.

**Detection idea:** per source IP and role name, `CREATE_ROLE` then a `GRANT` on a sensitive table, a login and a read of that table by the new role, then `DROP_ROLE` of the same role within 2 hours. Sort by `@timestamp` before sequence matching.

`anomaly_mode` defaults to `true`. With `false`, only ordinary background is generated and the complete chain never occurs.

## Parameters

### Event Parameters

| Name | Default | Description |
| --- | --- | --- |
| `anomaly_mode` | `true` | Generate the recurring temporary-role payroll chain |
| `anomaly_interval_hours` | `24` | Hours between episode due times, from the previous actual start; 6..8760 |
| `host_name` | `cassandra-01.example.test` | Node name in `host.name` |
| `host_ip` | `10.20.30.10` | Node broadcast address in the `host` audit field |

Volume and hours live in `patterns/*.yml` (`multiplier.ratio` is the count per day, `spreader` the part of the day): `app-*` for applications, `people-*` for analyst sessions, `admin-*` for DBA sessions and `roles-*` for sessions of DBA-created roles.

### Output Parameters

The shipped configuration writes `output/events.json` and needs no parameters or secrets. To send events elsewhere, replace the `file` output in a local copy and reference connection values as `${params.<name>}` and credentials as `${secrets.<name>}`, for example `${params.opensearch_host}` and `${secrets.opensearch_password}`.

## Usage

Live, at the configured rate:

```bash
eventum generate --path generators/database-apache-cassandra-audit/generator.yml --id cassandra --live-mode true
```

For a batch file over a fixed period, copy the generator directory and, in every file under `patterns/`, set `oscillator.start` to a midnight (for example `"2026-09-01T00:00:00Z"`) and `oscillator.end` to the end of the period (for example `"2026-09-05T00:00:00Z"`), then run:

```bash
eventum generate --path <copy>/generator.yml --id cassandra --live-mode false --keep-order true
```

Performance: about 4,500 records/s in batch mode (14 days, 535,437 records, in 118 s).

## Sample Output

The `GRANT` step of the first episode in the measured default output:

```json
{"@timestamp": "2026-09-01T14:45:54.889Z", "cassandra": {"audit": {"category": "DCL", "host": "/10.20.30.10:7000", "keyspace": "finance", "operation": "GRANT SELECT ON TABLE finance.payroll TO migration_ro;", "port": 54667, "source": "/10.20.10.5", "timestamp": 1788273954889, "type": "GRANT", "user": "ops_admin"}}, "ecs": {"version": "8.17.0"}, "event": {"action": "grant", "category": ["iam"], "created": "2026-09-01T14:45:54.889Z", "kind": "event", "original": "INFO  [Native-Transport-Requests-7] 2026-09-01 14:45:54,889 FileAuditLogger.java:51 - user:ops_admin|host:/10.20.30.10:7000|source:/10.20.10.5|port:54667|timestamp:1788273954889|type:GRANT|category:DCL|ks:finance|operation:GRANT SELECT ON TABLE finance.payroll TO migration_ro;", "outcome": "success", "type": ["user", "change"]}, "host": {"ip": ["10.20.30.10"], "name": "cassandra-01.example.test"}, "log": {"level": "INFO", "logger": "org.apache.cassandra.audit.FileAuditLogger", "origin": {"file": {"line": 51, "name": "FileAuditLogger.java"}}}, "message": "user:ops_admin|host:/10.20.30.10:7000|source:/10.20.10.5|port:54667|timestamp:1788273954889|type:GRANT|category:DCL|ks:finance|operation:GRANT SELECT ON TABLE finance.payroll TO migration_ro;", "process": {"thread": {"name": "Native-Transport-Requests-7"}}, "related": {"ip": ["10.20.10.5", "10.20.30.10"], "user": ["ops_admin", "migration_ro"]}, "source": {"ip": "10.20.10.5", "port": 54667}, "user": {"name": "ops_admin", "target": {"name": "migration_ro"}}}
```

## Limitations

- Line layout is derived from Cassandra source (`AuditLogEntry.getLogString`, `FileAuditLogger`, `AuditLogManager`) and the shipped logback audit appender pattern; no raw `audit.log` from a production 4.1 node was available for byte comparison.
- Records that a real node writes within milliseconds of each other (a driver's login, `USE` and re-prepared statements) are seconds apart here: a median of 2 s by day and 5-6 s at night, 99% within about 30 s, at most about 70 s.
- Application traffic is logged at 0.25-0.65 records/s; a busy production cluster with full DML auditing writes far more.
- The log clock is UTC; logback writes the JVM's local time zone. Working hours are fixed UTC hours with no weekends.
- The `host` field uses the IP-only form `/10.20.30.10:7000`; a node configured with a host name prints `name/ip:port`.
- All records, authentication included, run on the `Native-Transport-Requests` pool, as on a node with the default `native_transport_max_auth_threads: 0`; with a positive value, logins move to `Native-Transport-Auth-Requests` threads.
- One node only; a cluster logs each request on the coordinator that received it.
- Not modelled: `BATCH` entries with batch IDs, `TRUNCATE`, keyspace and table DDL other than `ALTER TABLE`, prepared-statement bound values (Cassandra never logs them), connection close (the audit log has no disconnect record).
- `BinAuditLogger`, the default logger, stores the same message in binary Chronicle Queue files; `auditlogviewer` prints it as `Type: audit` and `LogMessage: <message>`.
- ECS fields are an inferred mapping; no Elastic integration exists for Cassandra audit logs.

## References

- [Apache Cassandra 4.1 audit logging](https://cassandra.apache.org/doc/4.1/cassandra/operating/audit_logging.html)
- [Apache Cassandra 4.0 audit logging, viewer samples](https://cassandra.apache.org/doc/4.0/cassandra/new/auditlogging.html)
- [AuditLogEntry.java](https://github.com/apache/cassandra/blob/cassandra-4.1/src/java/org/apache/cassandra/audit/AuditLogEntry.java)
- [AuditLogEntryType.java](https://github.com/apache/cassandra/blob/cassandra-4.1/src/java/org/apache/cassandra/audit/AuditLogEntryType.java)
- [AuditLogManager.java](https://github.com/apache/cassandra/blob/cassandra-4.1/src/java/org/apache/cassandra/audit/AuditLogManager.java)
- [FileAuditLogger.java](https://github.com/apache/cassandra/blob/cassandra-4.1/src/java/org/apache/cassandra/audit/FileAuditLogger.java)
- [logback.xml (audit appender)](https://github.com/apache/cassandra/blob/cassandra-4.1/conf/logback.xml)

# Apache Cassandra Audit Log

Synthetic Apache Cassandra 4.1 audit records written by `FileAuditLogger` to `audit/audit.log` on one node, for SIEM engineers who build and test database access and role-management detections. Each event is ECS JSON; `event.original` holds the raw log line in the logback pattern that Cassandra ships for the audit appender, and `message` holds the pipe-delimited audit entry.

Traffic comes from four application roles using prepared statements, four analysts and three DBAs using `cqlsh`, and short-lived roles that DBAs create, grant, test, revoke and drop. Every actor runs its own random session process: log-normal gaps, occasional failed logins with retries or give-ups, and bursts of statements over one connection.

## Event Types

Shares are measured on the final default `anomaly_mode: true` capture (144 h, 14594 records).

| Audit type | Category | Share | Produced by |
| --- | --- | ---: | --- |
| `SELECT` | QUERY | 60.63% | Applications, analysts, temporary roles, DBA checks |
| `UPDATE` | DML | 21.43% | Applications and analysts (CQL `INSERT` is also logged as `UPDATE`) |
| `LOGIN_SUCCESS` | AUTH | 5.68% | Every connection |
| `PREPARE_STATEMENT` | PREPARE | 4.18% | Applications after reconnecting |
| `USE_KEYSPACE` | OTHER | 3.80% | Drivers (`USE "finance"`) and some `cqlsh` sessions |
| `DELETE` | DML | 1.08% | `billing_svc` |
| `LIST_ROLES` | DCL | 0.57% | DBAs |
| `GRANT` | DCL | 0.47% | DBAs |
| `LIST_PERMISSIONS` | DCL | 0.46% | DBAs |
| `CREATE_ROLE` | DCL | 0.39% | DBAs |
| `DROP_ROLE` | DCL | 0.35% | DBAs |
| `LOGIN_ERROR` | AUTH | 0.28% | Mistyped passwords |
| `ALTER_ROLE` | DCL | 0.21% | DBA password rotation for service roles |
| `REVOKE` | DCL | 0.20% | DBAs |
| `UNAUTHORIZED_ATTEMPT` | AUTH | 0.15% | Analysts reading `finance.payroll`, roles after a revoke |
| `REQUEST_FAILURE` | ERROR | 0.07% | Queries against a misspelled table |
| `ALTER_TABLE` | DDL | 0.05% | DBAs |

The mix is a synthetic training profile, not a measured production ratio.

## Anomaly Chain

A DBA account creates a login role, grants it `SELECT` on `finance.payroll`, logs in as that role from the same workstation, reads payroll, and removes the role again. This is how a stolen or misused DBA account can extract sensitive data under a throwaway identity and leave little behind.

1. `LOGIN_SUCCESS` - DBA from one of their usual addresses; sometimes followed by `USE finance;`.
2. `CREATE_ROLE` - `CREATE ROLE <r> WITH PASSWORD = '*******' AND LOGIN = true;`
3. `GRANT` - `GRANT SELECT ON TABLE finance.payroll TO <r>;`
4. `LOGIN_SUCCESS` - user `<r>`, same source IP, new source port.
5. `SELECT` - one to four reads of `finance.payroll` by `<r>`.
6. Optional new DBA login (50%) and `REVOKE SELECT ON TABLE finance.payroll FROM <r>;` (40%).
7. `DROP_ROLE` - `DROP ROLE <r>;`, which removes the role and its permissions.

**Linking fields:** `source.ip`, the role name in `user.target.name` (DCL) and `user.name` (login, select), `cassandra.audit.scope` = `payroll`, the port shared by the DBA connection.

**Recurrence:** the first episode starts at a uniformly random moment within the first `anomaly_interval_hours` after generation start (at most 24 h); each next one starts one interval after the actual start of the previous one, shifted by a uniformly random offset within a window of a quarter of the interval (at most 6 h) centred on that point, with no catch-up. The default interval is 24 h; the minimum accepted value is 6 h. Measured over 144 h: default interval, two captures with 6 episodes each, gaps 21.04-25.83 h; 8 h interval, 18 episodes, gaps 7.09-8.99 h. Intervals below 6 h are rejected: at 2 h the episodes become frequent enough that per-role timing stands out from ordinary role management.

**Variation:** the DBA differs from the previous episode's DBA and the role name from the previous role name; both come from the same pools as ordinary traffic. The source address is one of that DBA's usual addresses. Read count, query text, `LIMIT`, re-login, revoke and all gaps are random.

**Ordinary look-alikes (both modes):** DBAs create the same role names, grant `finance.payroll` or other tables, test most new roles from their own workstation (payroll access first of all), read payroll themselves, revoke and drop roles, often within minutes of creating them. Per day of background: about 3-7 roles dropped within 37 minutes of creation and about 3-4 connections of a new role reading payroll from a DBA address (up to about 4 in a busy capture). `hr_portal`, `reporting_etl` and `hr_lead_mora` read payroll all day. Only the complete ordered sequence above within two hours is absent from ordinary traffic: ordinary administration leaves out a `DROP ROLE r` only when it would complete it, that is when the same source IP created `r`, granted it payroll, logged in as `r` and read payroll, starting at most two hours earlier. The same drop after two hours or from another address is written as usual. DBAs create fewer roles as the ten-name pool fills and always leave two names free.

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

### Output Parameters

The shipped configuration writes `output/events.json` and needs no parameters or secrets. To send events elsewhere, replace the `file` output in a local copy and reference connection values as `${params.<name>}` and credentials as `${secrets.<name>}`, for example `${params.opensearch_host}` and `${secrets.opensearch_password}`.

## Usage

```bash
eventum generate --path generators/database-apache-cassandra-audit/generator.yml --id cassandra --live-mode true
```

For a batch file over a fixed period, set `start` and `end` on the `cron` input in a local copy and run:

```bash
eventum generate --path generators/database-apache-cassandra-audit/generator.yml --id cassandra --live-mode false
```

## Sample Output

The `GRANT` step of the first episode in the final default capture:

```json
{"@timestamp": "2026-09-01T09:17:42.900Z", "cassandra": {"audit": {"category": "DCL", "host": "/10.20.30.10:7000", "operation": "GRANT SELECT ON TABLE finance.payroll TO migration_ro;", "port": 42642, "source": "/10.20.10.5", "timestamp": 1788254262900, "type": "GRANT", "user": "ops_admin"}}, "ecs": {"version": "8.17.0"}, "event": {"action": "grant", "category": ["iam"], "created": "2026-09-01T09:17:42.902Z", "kind": "event", "original": "INFO  [Native-Transport-Requests-5] 2026-09-01 09:17:42,902 FileAuditLogger.java:51 - user:ops_admin|host:/10.20.30.10:7000|source:/10.20.10.5|port:42642|timestamp:1788254262900|type:GRANT|category:DCL|operation:GRANT SELECT ON TABLE finance.payroll TO migration_ro;", "outcome": "success", "type": ["user", "change"]}, "host": {"ip": ["10.20.30.10"], "name": "cassandra-01.example.test"}, "log": {"level": "INFO", "logger": "org.apache.cassandra.audit.FileAuditLogger", "origin": {"file": {"line": 51, "name": "FileAuditLogger.java"}}}, "message": "user:ops_admin|host:/10.20.30.10:7000|source:/10.20.10.5|port:42642|timestamp:1788254262900|type:GRANT|category:DCL|operation:GRANT SELECT ON TABLE finance.payroll TO migration_ro;", "process": {"thread": {"name": "Native-Transport-Requests-5"}}, "related": {"ip": ["10.20.10.5", "10.20.30.10"], "user": ["ops_admin", "migration_ro"]}, "source": {"ip": "10.20.10.5", "port": 42642}, "user": {"name": "ops_admin", "target": {"name": "migration_ro"}}}
```

## Limitations

- Line layout is derived from Cassandra source (`AuditLogEntry.getLogString`, `FileAuditLogger`, `AuditLogManager`) and the shipped logback audit appender pattern; no raw `audit.log` from a production 4.1 node was available for byte comparison.
- The log clock is UTC; logback writes the JVM's local time zone.
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

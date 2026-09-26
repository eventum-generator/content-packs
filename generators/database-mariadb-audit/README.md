# MariaDB Audit Plugin (server_audit FILE)

Generates audit records of one MariaDB Community Server 11.4.4 instance written by the bundled `server_audit` plugin 1.4.14 to its FILE output. Each output line is ECS JSON; `event.original` holds the native 10-field CSV record and `mariadb.audit.*` holds its parsed fields.

## Event Types Covered

Rates are measured from the final 76-hour-20-minute default capture with `anomaly_mode: false` (19,374 records per day).

| Native operation | Meaning | Records/day | ECS category / type |
|---|---|---:|---|
| `QUERY` | Completed `COM_QUERY` statement with its result code | 9,381 | `database` (plus `iam` for GRANT/REVOKE) |
| `READ` | Successful read table lock taken by the statement | 6,133 | `database` / `access`, outcome `unknown` |
| `WRITE` | Successful write table lock taken by the statement | 3,258 | `database` / `access`, outcome `unknown` |
| `CONNECT` | Successful login, current database set | 273 | `authentication` / `start` |
| `DISCONNECT` | End of a successful or failed connection | 301 | `authentication` / `end` |
| `FAILED_CONNECT` | Wrong password, retcode `1045`, empty database | 29 | `authentication` / `start`, outcome `failure` |

Statements behind the `QUERY` records:

| Statement | Actors | Table records before QUERY | Retcode | Per day |
|---|---|---|---:|---:|
| `SELECT ... FROM orders_NN WHERE order_id = N`, `SELECT status, COUNT(*) FROM orders_NN GROUP BY status` | every account | `READ <app db>.orders_NN` | 0 | 6,049 |
| `UPDATE orders_NN SET status = '<paid, shipped or cancelled>' WHERE order_id = N` | application account, DBAs | `WRITE <app db>.orders_NN` | 0 | 2,267 |
| `INSERT INTO orders_NN (customer_id, status, total) VALUES (...)` | application account | `WRITE <app db>.orders_NN` | 0 | 878 |
| `SELECT * FROM <sensitive db>.<table> ...` by a DBA, or by a delegate holding a grant | DBAs, grantee | `READ <sensitive db>.<table>` | 0 | 84 |
| `UPDATE <sensitive db>.<table> SET last_reviewed = CURRENT_DATE WHERE employee_id = N` | DBAs | `WRITE <sensitive db>.<table>` | 0 | 37 |
| Sensitive `SELECT` without a grant | delegates | none | 1142 | 21 |
| Mistyped statements (`SELEC`, `FORM`, `UPDTE`) | DBAs, delegates | none | 1064 | 15 |
| `GRANT SELECT ON <sensitive db>.<table> TO '<delegate>'@'<ip>'` | DBAs | `WRITE mysql.tables_priv`, `WRITE mysql.global_priv` | 0 | 15 |
| `REVOKE SELECT ON <sensitive db>.<table> FROM '<delegate>'@'<ip>'` | DBAs | `WRITE mysql.tables_priv`, `WRITE mysql.columns_priv`, `WRITE mysql.global_priv` | 0 | 15 |

## Workload Model

The generator runs a bounded event simulation of the server's clients. Every choice below is random and is taken the same way in both modes. No choice is paused or re-phased by an episode, and none uses a fixed rotation or a hard minimum gap: delays are exponential, lognormal, or Erlang, and accounts and tables are drawn at random. Rates and proportions are chosen assumptions, not vendor-measured frequencies.

- **Application pool:** three long-lived connections of the application account. Each issues a statement after an exponential think time (mean 28 s), chosen 65% point `SELECT`, 25% `UPDATE`, 10% `INSERT` against a random table from `samples/tables.json` and a random row. Each connection is retired after a lognormal lifetime (median 30 minutes) and replaced about a second later. In the default capture the application account produces 94% of records, with a median of 66 statements and 32 minutes per connection.
- **People:** every DBA and delegate opens a session after a lognormal idle time (median 30 and 40 minutes), runs a random number of statements (median 2) with lognormal think times (median 25 s), and disconnects. DBAs connect to the application database (60%) or the sensitive database (40%). They mix application reads and updates, sensitive-table reads and updates, reports, and occasional typos. Delegates run reports and point reads, sometimes try a sensitive table and are denied with 1142, and occasionally mistype.
- **Failed logins:** a DBA login starts with a wrong password 10% of the time, a delegate login 8%, a pooled reconnect 0.4%. After a failure a person retries after a lognormal delay (median 8 s), and each retry fails again with probability 0.4, up to five attempts; after any failure there is a 12% chance the person gives up and comes back later (lognormal, median 25 minutes). Runs of two to five failures of one account within minutes, failures without a following success, and failures followed by a successful login are therefore ordinary in both modes (about 29 failed logins and 1-3 runs of three or more per day across all accounts in the default captures). Maintenance logins stop at two failures, and maintenance never starts within 30 minutes of the chosen DBA's own failures, so an ordinary failure run never joins a grant cycle.
- **Grant maintenance:** a DBA temporarily grants a delegate `SELECT` on one sensitive table. The DBA, delegate, and table are drawn at random from the idle accounts and all tables. The delegate connects after a lognormal delay (median 2 minutes), reads the table one to five times, and disconnects. The DBA revokes the grant and disconnects, and after a further delay (median 200 s) the delegate's next attempt is denied with 1142. The next occurrence starts after an Erlang-2 delay (mean 80 minutes, capped at 5 hours) from the end of the previous one. In the default `false` capture this gives about 15 occurrences per day, 22 minutes to 3.8 hours apart.
- Up to six sessions are open at once (mean 3.3) in the default capture.

## Selected Source Profile

The format and hook semantics follow the MariaDB 11.4.4 source tag (`plugin/server_audit/server_audit.c`, `sql/sql_audit.h`, `sql/sql_acl.cc`, `sql/handler.cc`, `sql/lock.cc`) and its `server_audit` regression result. Selected server settings:

- `server_audit_logging=ON`, `server_audit_output_type=FILE`, `server_audit_mode=0`, `server_audit_events=CONNECT,QUERY,TABLE`, default `server_audit_query_log_limit=1024`.
- Query cache disabled, `use_stat_tables=NEVER`, `skip_name_resolve=ON`, server process time zone UTC.
- Clients send plain `COM_QUERY` text. No prepared statements, triggers, views, stored routines, proxy users, `CHANGE USER`, Galera, or replication.
- Pre-existing accounts, each at its own client IPv4 address: one application account with read/write access to the application tables; the DBA pool, each with `SELECT`, `UPDATE` and `GRANT OPTION` on every sensitive table and read/write access to the application tables; the delegated pool, each with `SELECT` on the application tables and no initial access to the sensitive database. The 50 application tables and the sensitive tables (with `employee_id` and `last_reviewed` columns) exist before the window. No account, schema, or password statement is generated.

Record layout, as written by `log_header` and the per-class formatters:

```text
timestamp,serverhost,username,host,connectionid,queryid,operation,database,object,retcode
```

- `timestamp` is `YYYYMMDD HH:MM:SS` in server local time (UTC here); `@timestamp` equals it.
- `host` is the client address, since name resolution is off. No port is written by this version.
- `connectionid` is the server thread ID. It is fresh for every successful or failed connection and stays with that connection until its `DISCONNECT`.
- `queryid` is the server query ID (mode 0), shared by every table record of a statement and its `QUERY` record; it is `0` for connection records.
- `QUERY` objects are single-quoted with backslash escapes for `\`, `'`, backspace, tab, newline, form feed, and carriage return. Table objects are unquoted. Connection records have an empty object.
- Table records end with an empty retcode. A lock record shows that the lock was taken, not that rows were returned or changed; the result code is on the following `QUERY`, which is written after the table records.
- A wrong password is rejected before the requested database is applied, and the thread closes without entering the command loop, so `FAILED_CONNECT` and its `DISCONNECT` carry an empty database and the same second.
- Every command dispatched on a connection takes a new query id, including the `COM_QUIT` that ends a session, so query ids of consecutive `QUERY` records skip one id per session closed in between.
- `GRANT` locks `tables_priv` and `global_priv`; `REVOKE SELECT` also locks `columns_priv` because `SELECT` is a column-level privilege. This order is derived from the grant-table constructor, not from a captured GRANT/REVOKE trace.
- A denied `SELECT` (1142) and a syntax error (1064) take no table lock and write no table record.

A statement's table records and its `QUERY` share one source second. The input ticks once per second and the collector writes at most one record per tick; ticks with nothing due are dropped, so `event.created` trails `@timestamp` by 0 to a few seconds (12 s at most in the final captures).

## Anomaly Chain

`event.template.params.anomaly_mode` defaults to `true`. With `false`, only background is produced.

An episode is one grant-maintenance occurrence whose DBA login is preceded by three wrong passwords:

1. Three (70%) or four `FAILED_CONNECT` of the DBA from its address, spaced like ordinary password retries (median 8 s), each closed by its `DISCONNECT` in the same second.
2. The DBA's `CONNECT` to the sensitive database and `GRANT SELECT` on the table to the delegate.
3. The delegate's `CONNECT` to the sensitive database, `READ` and successful `QUERY` of that table, `DISCONNECT`.
4. The DBA's `REVOKE SELECT` of the same grant and `DISCONNECT`.
5. The delegate's next connection to the application database, denied with 1142 on the same table.

The episode's records interleave with the application pool and other people's sessions. Linking fields: `username` and `host` of the DBA and delegate, `connectionid` of each session, `queryid` between table records and their `QUERY`, and the grantee, address, and table in the GRANT/REVOKE text and in the delegate's read and denial.

Recurrence: an episode becomes due one interval after the first record, and then one interval after the actual start of the previous episode. The first grant maintenance that starts after the due time carries the episode, so an episode starts after it is due, typically within a few hours (0.1 to 2.5 hours in the final captures); the gap before an episode's GRANT therefore tends to be longer than a typical gap between ordinary GRANTs. Missed intervals are not replayed.

Variation: the DBA, delegate, and table come from the same random draw as ordinary maintenance. An episode additionally avoids the previous episode's DBA and table pair, so consecutive episodes differ in the DBA or the table.

The episode reuses ordinary maintenance, so its account and table choice, delays and the post-revoke denial come from the same random draws as background, within background ranges. Failure runs of three or more followed by a successful login are ordinary too; what only episodes contain is such a run immediately followed by that DBA's GRANT cycle. Each episode adds one failure run, so at short intervals runs of three or more failures per DBA become more frequent than without episodes (about twice as frequent at 12 hours with one DBA and at the 6-hour minimum); at the 24-hour default with two DBAs the difference is within run-to-run variation.

Possible detection: at least three `FAILED_CONNECT` for one account and address within 5 minutes, followed within 5 minutes by a successful `CONNECT` and within 30 minutes by a `GRANT` from that same connection; join the grantee and table to the later read, the REVOKE, and the grantee's 1142. These records do not show why the logins failed, which rows were returned, or data exfiltration.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`. Invalid values stop rendering with a message starting with `MariaDB`.

| Name | Default | Purpose and constraints |
|---|---|---|
| `db_host` | `db-01.corp.example` | Server host name in the `serverhost` slot; ASCII letters, digits, `.` and `-`, up to 253 characters |
| `db_ip` | `10.100.0.5` | Server IPv4 address, enrichment only |
| `normal_user` | `app_user` | Application account used by the connection pool |
| `normal_ip` | `10.100.1.20` | Application server IPv4 address |
| `dba_accounts` | `dba` at `10.99.4.51`, `dba_ops` at `10.99.4.52` | DBA pool, 1 to 4 entries of `user` and `ip` |
| `delegated_accounts` | `audit_user` at `10.99.5.21`, `report_user` at `10.99.5.22` | Accounts that receive temporary grants, 1 to 4 entries of `user` and `ip` |
| `normal_database` | `appdb` | Database of the 50 application tables |
| `sensitive_database` | `payroll` | Database of the sensitive tables |
| `sensitive_tables` | `salaries`, `bonuses` | Sensitive tables, 1 to 8 entries |
| `anomaly_interval_hours` | `24` | Episode interval in hours of source time, number from 6 to 8,760 |
| `anomaly_mode` | `true` | `true` adds episodes to background, `false` produces background only |

Account, database, and table names are lowercase identifiers matching `[a-z][a-z0-9_]{0,31}`. All accounts must have distinct names and distinct IPv4 addresses, sensitive tables must be distinct, the two databases must differ and must not be `mysql`, and the DBA or table pool needs two or more entries so that consecutive episodes can differ. `samples/tables.json` must hold 1 to 100 unique `orders_NN` names. With about 15 grant maintenances per day, the 6-hour minimum keeps episodes to at most a quarter of them, so ordinary grants remain the majority in both modes.

### Output Parameters

The shipped file output needs no substitutions. To deliver elsewhere, replace the `output` block with another output plugin and pass its host through `${params.*}` and credentials through `${secrets.*}`, for example `${params.opensearch_host}` and `${secrets.opensearch_password}`.

## Usage

From the content-packs repository root:

```bash
# Bounded batch sample; timeout exit code 124 is expected.
timeout 3 eventum generate --path generators/database-mariadb-audit/generator.yml --id database-mariadb-audit --live-mode false --keep-order true

# Live generation, about 19,400 records per day.
eventum generate --path generators/database-mariadb-audit/generator.yml --id database-mariadb-audit --live-mode true --keep-order true
```

Output goes to `generators/database-mariadb-audit/output/events.json`. Keep `--keep-order true`: session and table-to-query ordering depends on the physical record order. To check recurrence, copy `generator.yml`, set finite `input[0].cron.start` and `end` covering at least two intervals plus six hours, and run it with `--live-mode false`; a 3-second sample covers no episode.

## Validation

Final finite captures, each checked row by row against the native grammar, session and query-id lifecycles, statement and lock semantics, the privilege model, recurrence, and variation:

| Capture | Window | Records | Complete episodes | Episode gaps |
|---|---|---:|---:|---|
| Default, `true` | 76 h 20 min | 62,682 | 3 | 91,002 s, 92,726 s |
| Default, `false` | 76 h 20 min | 61,621 | 0 | - |
| Custom 12 h: one DBA, three delegates, two tables, other names and addresses, input in UTC+05:30, `true` | 76 h 20 min | 62,179 | 5 | 45,218 to 48,179 s |
| Custom 12 h, `false` | 76 h 20 min | 61,985 | 0 | - |
| Minimum 6 h, `true` | 100 h 20 min | 82,050 | 13 | 22,115 to 30,440 s |
| Minimum 6 h, `false` | 100 h 20 min | 81,798 | 0 | - |

- Each `true` capture was compared with its `false` pair using the shared calibrated on/off comparison (per-account gaps, low quantiles and minima, same-account bursts and failure runs, daily counts, successor determinism, session holds, periodicity, constants and mix, calibrated on five independent `false` captures per configuration with family-wise error control). The default pair is OK in every class. The 12-hour and 6-hour pairs are SUSPECT only on runs of three failures per client address, the documented uplift above; every other class is OK.
- No episode GRANT followed the previous GRANT by less than the smallest gap seen without episodes.
- Every user, address, operation, database, statement shape (numbers abstracted), and retcode used in an episode also appears outside episodes in the same capture and in the paired `false` capture. `false` captures contain no complete chain.

## Limitations and Assumptions

- No unmodified production audit file was available. The vendor regression result replaces times, host names, and IDs with placeholders, so the field grammar comes from the tagged source code, and ID values, timing, and workload are synthetic.
- The profile covers FILE output only. SYSLOG output of this version omits the timestamp slot and adds a syslog header; MariaDB 12.x adds client ports and TLS details. Neither is modelled.
- The GRANT/REVOKE system-table records are derived from source, not from a captured trace. Other hook-producing activity (statistics tables, DDL, stored programs, `CHANGE USER`, proxies, password statements, prepared statements) is excluded by the selected settings and workload.
- All connections come from the configured accounts, so connection ids increase by one per connection. Clients send no connect-time statements (for example the `mysql` client's `select @@version_comment limit 1`); the modelled clients are an application pool and scripted sessions. The workload has no daily cycle, one application server, at most one temporary grant at a time, and one record per second at most from the collector.
- ECS fields other than the parsed native slots (`event.*`, `host.*`, `observer.*`, `service.*`, `source.ip`, `related.*`, `log.file.path`) are collector-side enrichment. No maintained Elastic integration for MariaDB `server_audit` was found to compare against, and no SIEM parser was run.

## Sample Output

The GRANT of the first episode, row 20,210 of the final default `true` capture (the same statement shape by the same DBA also appears in ordinary grant maintenance):

```json
{
  "@timestamp": "2026-09-02T00:57:33+00:00",
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "query",
    "category": [
      "database",
      "iam"
    ],
    "created": "2026-09-02T00:57:35+00:00",
    "dataset": "mariadb.audit",
    "ingested": "2026-09-02T00:57:35+00:00",
    "kind": "event",
    "original": "20260902 00:57:33,db-01.corp.example,dba,10.99.4.51,1321,12077,QUERY,payroll,'GRANT SELECT ON payroll.salaries TO \\'audit_user\\'@\\'10.99.5.21\\'',0",
    "outcome": "success",
    "type": [
      "change"
    ]
  },
  "host": {
    "ip": [
      "10.100.0.5"
    ],
    "name": "db-01.corp.example"
  },
  "log": {
    "file": {
      "path": "/var/log/mariadb/server_audit.log"
    }
  },
  "mariadb": {
    "audit": {
      "connectionid": 1321,
      "database": "payroll",
      "host": "10.99.4.51",
      "object": "GRANT SELECT ON payroll.salaries TO 'audit_user'@'10.99.5.21'",
      "operation": "QUERY",
      "queryid": 12077,
      "retcode": 0,
      "serverhost": "db-01.corp.example",
      "timestamp": "20260902 00:57:33",
      "username": "dba"
    }
  },
  "message": "20260902 00:57:33,db-01.corp.example,dba,10.99.4.51,1321,12077,QUERY,payroll,'GRANT SELECT ON payroll.salaries TO \\'audit_user\\'@\\'10.99.5.21\\'',0",
  "observer": {
    "hostname": "db-01.corp.example",
    "ip": [
      "10.100.0.5"
    ],
    "product": "MariaDB Community Server",
    "type": "database",
    "vendor": "MariaDB",
    "version": "11.4.4"
  },
  "related": {
    "ip": [
      "10.99.4.51"
    ],
    "user": [
      "dba"
    ]
  },
  "service": {
    "type": "mariadb",
    "version": "11.4.4"
  },
  "source": {
    "ip": "10.99.4.51"
  },
  "tags": [
    "mariadb-audit",
    "preserve_original_event"
  ],
  "user": {
    "name": "dba"
  }
}
```

## References

- [server_audit.c at mariadb-11.4.4](https://github.com/MariaDB/server/blob/mariadb-11.4.4/plugin/server_audit/server_audit.c)
- [server_audit regression result at mariadb-11.4.4](https://github.com/MariaDB/server/blob/mariadb-11.4.4/mysql-test/suite/plugins/r/server_audit.result)
- [sql_audit.h at mariadb-11.4.4](https://github.com/MariaDB/server/blob/mariadb-11.4.4/sql/sql_audit.h)
- [sql_acl.cc at mariadb-11.4.4](https://github.com/MariaDB/server/blob/mariadb-11.4.4/sql/sql_acl.cc)
- [MariaDB Audit Plugin log format](https://mariadb.com/docs/server/reference/plugins/mariadb-audit-plugin/mariadb-audit-plugin-log-format)
- [MariaDB Audit Plugin log settings](https://mariadb.com/docs/server/reference/plugins/mariadb-audit-plugin/mariadb-audit-plugin-log-settings)
- [GRANT](https://mariadb.com/docs/server/reference/sql-statements/account-management-sql-statements/grant) and [REVOKE](https://mariadb.com/docs/server/reference/sql-statements/account-management-sql-statements/revoke)
- No Elastic integration covers MariaDB `server_audit`; the Elastic `mysql_enterprise` integration models the different Oracle MySQL Enterprise Audit JSON format.

# MariaDB Audit Plugin (server_audit FILE)

Generates audit records of one MariaDB Community Server 11.4.4 instance written by the bundled `server_audit` plugin 1.4.14 to its FILE output. Each output line is ECS JSON; `event.original` holds the native 10-field CSV record and `mariadb.audit.*` holds its parsed fields.

## Event Types Covered

Rates are measured from the final 14-day default capture with `anomaly_mode: false` (19,617 records per day).

| Native operation | Meaning | Records/day | ECS category / type |
|---|---|---:|---|
| `QUERY` | Completed `COM_QUERY` statement with its result code | 9,493 | `database` (plus `iam` for GRANT/REVOKE) |
| `READ` | Successful read table lock taken by the statement | 6,166 | `database` / `access`, outcome `unknown` |
| `WRITE` | Successful write table lock taken by the statement | 3,335 | `database` / `access`, outcome `unknown` |
| `CONNECT` | Successful login, current database set | 274 | `authentication` / `start` |
| `DISCONNECT` | End of a successful or failed connection | 311 | `authentication` / `end` |
| `FAILED_CONNECT` | Wrong password, retcode `1045`, empty database | 37 | `authentication` / `start`, outcome `failure` |

Statements behind the `QUERY` records:

| Statement | Actors | Table records before QUERY | Retcode | Per day |
|---|---|---|---:|---:|
| `SELECT ... FROM orders_NN WHERE order_id = N`, `SELECT status, COUNT(*) FROM orders_NN GROUP BY status` | every account | `READ <app db>.orders_NN` | 0 | 6,081 |
| `UPDATE orders_NN SET status = '<paid, shipped or cancelled>' WHERE order_id = N` | application account, DBAs | `WRITE <app db>.orders_NN` | 0 | 2,307 |
| `INSERT INTO orders_NN (customer_id, status, total) VALUES (...)` | application account | `WRITE <app db>.orders_NN` | 0 | 915 |
| `SELECT * FROM <sensitive db>.<table> ...` by a DBA, or by a delegate holding a grant | DBAs, grantee | `READ <sensitive db>.<table>` | 0 | 86 |
| `UPDATE <sensitive db>.<table> SET last_reviewed = CURRENT_DATE WHERE employee_id = N` | DBAs | `WRITE <sensitive db>.<table>` | 0 | 37 |
| Sensitive `SELECT` without a grant | delegates | none | 1142 | 22 |
| Mistyped statements (`SELEC`, `FORM`, `UPDTE`) | DBAs, delegates | none | 1064 | 14 |
| `GRANT SELECT ON <sensitive db>.<table> TO '<delegate>'@'<ip>'` | DBAs | `WRITE mysql.tables_priv`, `WRITE mysql.global_priv` | 0 | 15 |
| `REVOKE SELECT ON <sensitive db>.<table> FROM '<delegate>'@'<ip>'` | DBAs | `WRITE mysql.tables_priv`, `WRITE mysql.columns_priv`, `WRITE mysql.global_priv` | 0 | 15 |

## Workload Model

The generator runs a bounded event simulation of the server's clients. Every choice below is random and is taken the same way in both modes. No choice is paused or re-phased by an episode, and none uses a fixed rotation or a hard minimum gap: delays are exponential or lognormal, and accounts and tables are drawn at random. Rates and proportions are chosen assumptions, not vendor-measured frequencies.

- **Application pool:** three long-lived connections of the application account. Each issues a statement after an exponential think time (mean 28 s), chosen 65% point `SELECT`, 25% `UPDATE`, 10% `INSERT` against a random table from `samples/tables.json` and a random row. Each connection is retired after a lognormal lifetime (median 30 minutes) and replaced about a second later. In the default capture the application account produces 95% of records, with a median of 65 statements and 31 minutes per connection.
- **People:** every DBA and delegate opens a session after a lognormal idle time (median 30 and 40 minutes), runs a random number of statements (median 2) with lognormal think times (median 25 s), and disconnects. DBAs connect to the application database (60%) or the sensitive database (40%). They mix application reads and updates, sensitive-table reads and updates, reports, and occasional typos. Delegates run reports and point reads, sometimes try a sensitive table and are denied with 1142, and occasionally mistype.
- **Failed logins:** a DBA login starts with a wrong password 10% of the time, a delegate login 8%, a pooled reconnect 0.4%. After a failure a person retries after a lognormal delay (median 8 s), and each retry fails again with probability 0.4, up to five attempts; after any failure there is a 12% chance the person gives up and comes back later (lognormal, median 25 minutes). In addition, 8% of a DBA's own logins come from a client with a stale saved password that retries it 3 to 6 times within seconds (lognormal spacing, median 4 s); the DBA then types the right password and logs in (60%) or leaves it for later. Runs of two to six failures of one account within minutes, failures without a following success, and failures followed by a successful login are therefore ordinary in both modes (about 37 failed logins per day across all accounts in the default `false` capture, 28 of them by DBAs; 61 to 87 DBA runs of three or more failures per 14 days in the eight `false` captures). The maintenance DBA's login follows the ordinary retry law (up to five failures) but does not give up.
- **Grant maintenance:** a DBA temporarily grants a delegate `SELECT` on one sensitive table. The DBA, delegate, and table are drawn at random from the idle accounts and all tables. The delegate connects after a lognormal delay (median 2 minutes), reads the table one to five times, and disconnects. The DBA revokes the grant and disconnects, and after a further delay (median 200 s) the delegate's next attempt is denied with 1142. Occurrences start as a Poisson process: the time between starts is exponential with a mean of 90 minutes, whatever the previous occurrence is doing. Each occurrence takes a DBA and a delegate who are idle at that moment (and waits a minute at a time if none is), so two occurrences can overlap on different accounts. In the default `false` capture this gives about 15 occurrences per day and up to two temporary grants at once; consecutive GRANTs are seconds to 9.8 hours apart.
- **Chain guard (both modes):** an ordinary GRANT is not issued when it would complete the episode's chain: three `FAILED_CONNECT`, a `CONNECT` and a GRANT of the same DBA account, the first failure at most 30 minutes earlier. Nothing is granted, read, or revoked; the DBA disconnects after the usual think time and the delegate stays idle. Only that GRANT is affected, the account and all times stay as drawn, and a GRANT more than 30 minutes after the first failure is issued as usual. In the 14-day `false` captures this happens 11 to 20 times per capture (12 to 30 in the `true` captures, where an episode's failures also count for 30 minutes); each leaves a DBA session to the sensitive database that holds no statement (`CONNECT` followed by `DISCONNECT`). Partial matches are not reset when an episode completes its chain, so an ordinary GRANT cannot complete a chain together with episode records either.
- Up to seven sessions are open at once (mean 3.3) in the default capture.

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

An episode is an additional grant cycle, run like ordinary maintenance but on its own schedule, whose DBA login is preceded by three wrong passwords:

1. Three (70%) or four `FAILED_CONNECT` of the DBA from its address, spaced like ordinary password retries (median 8 s), each closed by its `DISCONNECT` in the same second.
2. The DBA's `CONNECT` to the sensitive database and `GRANT SELECT` on the table to the delegate.
3. The delegate's `CONNECT` to the sensitive database, `READ` and successful `QUERY` of that table, `DISCONNECT`.
4. The DBA's `REVOKE SELECT` of the same grant and `DISCONNECT`.
5. The delegate's next connection to the application database, denied with 1142 on the same table.

The episode's records interleave with the application pool and other people's sessions. Linking fields: `username` and `host` of the DBA and delegate, `connectionid` of each session, `queryid` between table records and their `QUERY`, and the grantee, address, and table in the GRANT/REVOKE text and in the delegate's read and denial.

Recurrence: the first episode starts at a uniform random time within the first interval or the first 24 hours, whichever is shorter. Each next episode starts at a uniform random time in a window centred one interval after the actual start of the previous episode; the window is a quarter of the interval wide, at most six hours (24 h default: 21 to 27 hours). The workload has no daily cycle, so no hour of day is preferred. The episode is its own session and grant cycle: it takes a DBA and a delegate who are idle at that moment, like ordinary maintenance, and it never moves ordinary maintenance, which runs on its own schedule in both modes. If no such pair is idle, the start waits a minute and tries again. Like ordinary occurrences, an episode can overlap another grant cycle. Missed intervals are not replayed.

Variation: the DBA, delegate, and table come from the same random draw as ordinary maintenance. An episode additionally avoids the previous episode's DBA and table pair, so consecutive episodes differ in the DBA or the table.

The episode repeats the steps of ordinary maintenance, so its account and table choice, delays and the post-revoke denial come from the same random draws as background, within background ranges. Because ordinary occurrences start as a Poisson process, the gap from the previous GRANT to an episode's GRANT has the same distribution as the gaps between ordinary GRANTs. Failure runs of three or more followed by a successful login are ordinary too; what only episodes contain is such a run and login followed by that DBA's GRANT within 30 minutes of the first failure. Each episode adds one failure run of the DBA. Counted per capture (runs of three or more failures by one DBA account, reset by its login), the eight 14-day `false` captures have 61 to 87 runs (mean 76); the default 24-hour `true` captures have 87 and 88, within or one above that spread; the 12-hour `true` captures have 94 and 102, above it. At intervals shorter than a day the additional runs remain visible in this count.

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

Final 14-day finite captures (2026-09-01 to 2026-09-15, default accounts), each checked row by row against the native grammar, session and query-id lifecycles, statement and lock semantics, the privilege model, recurrence, and variation:

| Capture | Records | Complete episodes | First episode after start | Episode gaps |
|---|---:|---:|---|---|
| Default 24 h, `true` | 273,718 | 14 | 5.5 h | 21.3 to 26.9 h |
| Default 24 h, `false` | 274,629 | 0 | - | - |
| 12 h, `true` | 273,650 | 28 | 6.0 h | 10.6 to 13.3 h |
| 12 h, `false` | 273,156 | 0 | - | - |
| 12 h, second pair, `true` | 273,594 | 28 | 4.3 h | 10.6 to 13.4 h |
| 12 h, second pair, `false` | 273,107 | 0 | - | - |

- Each `true` capture was compared with its `false` pair using the shared calibrated on/off comparison (per-account gaps, low quantiles and minima, same-account bursts and failure runs, daily counts, successor determinism, session holds, periodicity, constants and mix, calibrated on five independent 14-day `false` captures with family-wise error control). All three pairs are OK in every class.
- Every episode starts inside its window: first starts 4.3 to 6.0 hours after the capture start; later starts deviate from the window centre by -9,704 to 10,585 s at 24 hours (window +/- 10,800 s) and -5,047 to 5,032 s at 12 hours (window +/- 5,400 s).
- The gap from the previous GRANT to an episode's GRANT matches the other GRANT-to-GRANT gaps of the same captures (70 episode GRANTs: mean 6,164 s, 21% under 30 minutes; 579 other gaps: mean 5,485 s, 25% under 30 minutes; two-sample KS p = 0.50).
- Every user, address, operation, database, statement shape (numbers abstracted), and retcode used in an episode also appears outside episodes in the same capture and in the paired `false` capture. The eight `false` captures contain no complete chain, counted without a cap on partial matches, with every candidate run, and without resetting after a completion; in the `true` captures the same count equals the number of episodes.
- After three failures and a login of a DBA in the `false` captures, a GRANT by that DBA follows at 0 per hour up to 30 minutes after the first failure (the guard) and at 0.25 to 0.39 per hour in each 10-minute bin of the following half hour; GRANTs by the other DBA follow at 0.30 to 0.38 per hour inside the window and 0.33 to 0.43 per hour after it.

## Limitations and Assumptions

- No unmodified production audit file was available. The vendor regression result replaces times, host names, and IDs with placeholders, so the field grammar comes from the tagged source code, and ID values, timing, and workload are synthetic.
- The profile covers FILE output only. SYSLOG output of this version omits the timestamp slot and adds a syslog header; MariaDB 12.x adds client ports and TLS details. Neither is modelled.
- The GRANT/REVOKE system-table records are derived from source, not from a captured trace. Other hook-producing activity (statistics tables, DDL, stored programs, `CHANGE USER`, proxies, password statements, prepared statements) is excluded by the selected settings and workload.
- All connections come from the configured accounts, so connection ids increase by one per connection. Clients send no connect-time statements (for example the `mysql` client's `select @@version_comment limit 1`); the modelled clients are an application pool and scripted sessions. The workload has no daily cycle, one application server, at most as many temporary grants at a time as there are DBA and delegate pairs (two in the default captures), and one record per second at most from the collector.
- ECS fields other than the parsed native slots (`event.*`, `host.*`, `observer.*`, `service.*`, `source.ip`, `related.*`, `log.file.path`) are collector-side enrichment. No maintained Elastic integration for MariaDB `server_audit` was found to compare against, and no SIEM parser was run.

## Sample Output

The GRANT of the first episode, row 4,592 of the final default `true` capture (the same statement shape by the same DBA also appears in ordinary grant maintenance):

```json
{
  "@timestamp": "2026-09-01T05:28:51+00:00",
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "query",
    "category": [
      "database",
      "iam"
    ],
    "created": "2026-09-01T05:28:53+00:00",
    "dataset": "mariadb.audit",
    "ingested": "2026-09-01T05:28:53+00:00",
    "kind": "event",
    "original": "20260901 05:28:51,db-01.corp.example,dba_ops,10.99.4.52,1081,4282,QUERY,payroll,'GRANT SELECT ON payroll.salaries TO \\'report_user\\'@\\'10.99.5.22\\'',0",
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
      "connectionid": 1081,
      "database": "payroll",
      "host": "10.99.4.52",
      "object": "GRANT SELECT ON payroll.salaries TO 'report_user'@'10.99.5.22'",
      "operation": "QUERY",
      "queryid": 4282,
      "retcode": 0,
      "serverhost": "db-01.corp.example",
      "timestamp": "20260901 05:28:51",
      "username": "dba_ops"
    }
  },
  "message": "20260901 05:28:51,db-01.corp.example,dba_ops,10.99.4.52,1081,4282,QUERY,payroll,'GRANT SELECT ON payroll.salaries TO \\'report_user\\'@\\'10.99.5.22\\'',0",
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
      "10.99.4.52"
    ],
    "user": [
      "dba_ops"
    ]
  },
  "service": {
    "type": "mariadb",
    "version": "11.4.4"
  },
  "source": {
    "ip": "10.99.4.52"
  },
  "tags": [
    "mariadb-audit",
    "preserve_original_event"
  ],
  "user": {
    "name": "dba_ops"
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

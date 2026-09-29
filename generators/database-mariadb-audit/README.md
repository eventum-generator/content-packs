# MariaDB Audit Plugin (server_audit FILE)

Generates audit records of one MariaDB Community Server 11.4.4 instance written by the bundled `server_audit` plugin 1.4.14 to its FILE output. Each output line is ECS JSON; `event.original` holds the native 10-field CSV record and `mariadb.audit.*` holds its parsed fields.

## Volume and Timing

Record volume follows a UTC hour-of-day curve, about 16,700 records per day with ±3% day-to-day variation; records fall at random times inside each band.

| UTC hours | Records/s |
|---|---:|
| 08-19 | 0.28 |
| 07-08, 19-21 | 0.18 |
| 21-07 | 0.10 |

The application account writes about 96% of the records. DBAs and delegates work mostly in business hours: at 08-18 UTC the four accounts together open about 4.7 sessions an hour, at 07-08 and 18-19 about 1.2, and at night about 0.1. Grant maintenance follows the same working day: about 0.75 an hour at 08-18 UTC, 0.2 an hour at 07-08 and 18-19, and 0.06 an hour at night, about 11 a day.

The records of one statement (its table records and its `QUERY`) and a failed login with its `DISCONNECT` share one second in `@timestamp`, as the server writes them. `event.created` is the collection time: the same second in half of the records, within 8 s for 90%, and up to about two minutes at night.

## Event Types Covered

Shares over 40 days with `anomaly_mode: false` (667,823 records).

| Native operation | Meaning | Share | Records/day | ECS category / type |
|---|---|---:|---:|---|
| `QUERY` | Completed `COM_QUERY` statement with its result code | 48.6% | 8,118 | `database` (plus `iam` for GRANT/REVOKE) |
| `READ` | Successful read table lock taken by the statement | 31.5% | 5,265 | `database` / `access`, outcome `unknown` |
| `WRITE` | Successful write table lock taken by the statement | 17.2% | 2,865 | `database` / `access`, outcome `unknown` |
| `DISCONNECT` | End of a successful or failed connection | 1.34% | 224 | `authentication` / `end` |
| `CONNECT` | Successful login, current database set | 1.29% | 215 | `authentication` / `start` |
| `FAILED_CONNECT` | Wrong password, retcode `1045`, empty database | 0.05% | 9 | `authentication` / `start`, outcome `failure` |

With the default `anomaly_mode: true`, episodes add about three failed logins a day, so `FAILED_CONNECT` is about 0.07% of records, about 12 a day; the other shares stay the same.

Statements behind the `QUERY` records:

| Statement | Actors | Table records before QUERY | Retcode | Per day |
|---|---|---|---:|---:|
| `SELECT ... FROM orders_NN WHERE order_id = N`, `SELECT status, COUNT(*) FROM orders_NN GROUP BY status` | every account | `READ <app db>.orders_NN` | 0 | 5,215 |
| `UPDATE orders_NN SET status = '<paid, shipped or cancelled>' WHERE order_id = N` | application account, DBAs | `WRITE <app db>.orders_NN` | 0 | 1,992 |
| `INSERT INTO orders_NN (customer_id, status, total) VALUES (...)` | application account | `WRITE <app db>.orders_NN` | 0 | 794 |
| `SELECT * FROM <sensitive db>.<table> ...` by a DBA, or by a delegate holding a grant | DBAs, grantee | `READ <sensitive db>.<table>` | 0 | 50 |
| `UPDATE <sensitive db>.<table> SET last_reviewed = CURRENT_DATE WHERE employee_id = N` | DBAs | `WRITE <sensitive db>.<table>` | 0 | 22 |
| Sensitive `SELECT` without a grant | delegates | none | 1142 | 15 |
| `GRANT SELECT ON <sensitive db>.<table> TO '<delegate>'@'<ip>'` | DBAs | `WRITE mysql.tables_priv`, `WRITE mysql.global_priv` | 0 | 11.5 |
| `REVOKE SELECT ON <sensitive db>.<table> FROM '<delegate>'@'<ip>'` | DBAs | `WRITE mysql.tables_priv`, `WRITE mysql.columns_priv`, `WRITE mysql.global_priv` | 0 | 11.5 |
| Mistyped statements (`SELEC`, `FORM`, `UPDTE`) | DBAs, delegates | none | 1064 | 7 |

## Workload Model

Rates are chosen assumptions, not vendor-measured frequencies. Both modes run the same activity. An episode adds one grant cycle that takes its DBA and delegate exactly as an ordinary maintenance does, including the 30 minutes after its GRANT in which that DBA takes no other maintenance; it does not pause or cancel any session or maintenance, and afterwards both accounts continue as after any maintenance. Accounts, tables, rows and delays are drawn at random; no choice follows a fixed rotation.

- **Application pool:** three long-lived connections of the application account. Statements arrive at the rate of the hour curve on a random connection: 65% point `SELECT`, 25% `UPDATE`, 10% `INSERT` against a random table from `samples/tables.json` and a random row. A connection is retired after a lognormal lifetime (median 30 minutes) and replaced about 1.5 s later; 0.4% of the replacements fail once with a wrong password. A connection runs a median of 51 statements.
- **People:** a session belongs to an idle DBA (1.6 times as likely) or delegate. DBAs connect to the application database (60%) or the sensitive database (40%) and mix application reads and updates, sensitive-table reads and updates, reports, and occasional typos. Delegates run reports and point reads, sometimes try a sensitive table and are denied with 1142, and occasionally mistype. A session runs a random number of statements (median 2) with lognormal think times (median 25 s).
- **Failed logins:** a DBA login starts with a wrong password 6% of the time, a delegate login 5%. A retry follows after a lognormal delay (median 8 s) and fails again with probability 0.3, up to five failures; after any failure there is a 12% chance the person gives up. In addition, 2% of a DBA's sessions start from a client with a stale saved password that retries it 2 to 5 times within seconds (fewer retries more likely); the DBA then logs in by hand (60%) or leaves it. One failure before a login is the most common case, and runs of three or more failures followed by a login happen about two to three times a week for the two DBAs together. About 0.05% of records, about 4% of all login attempts, are failed logins, about 9 a day; the two DBAs together have about 5 a day.
- **Grant maintenance:** a DBA temporarily grants a delegate `SELECT` on one sensitive table. The DBA, delegate, and table are drawn at random from the idle accounts and all tables. A DBA takes no maintenance within 30 minutes of its previous GRANT; while no DBA and delegate are available the maintenance waits about a minute at a time, for up to half an hour. The DBA's login follows the ordinary failed-login law without giving up. The delegate connects after a lognormal delay (median 2 minutes), reads the table one to five times, and disconnects. The DBA revokes the grant and disconnects, and a few minutes later (median 200 s) the delegate's next attempt is denied with 1142. Two maintenances can overlap on different accounts, so up to two temporary grants exist at once.
- **Grants after failed logins:** a DBA never issues an ordinary GRANT within 30 minutes of the first of three failed logins that were followed by a login of that DBA. If maintenance reaches that point, the DBA works on the sensitive tables as in an ordinary session instead, and the delegate is not involved. This happens about twice a week, at the same rate in both modes.
- Up to seven sessions are open at once (mean 3.2).

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

## Anomaly Chain

`event.template.params.anomaly_mode` defaults to `true`. With `false`, only background is produced.

An episode is an additional grant cycle, run like ordinary maintenance but at its own time, whose DBA login is preceded by wrong passwords:

1. Three (70%) or four `FAILED_CONNECT` of the DBA from its address, spaced like ordinary password retries (median 8 s), each closed by its `DISCONNECT` in the same second.
2. The DBA's `CONNECT` to the sensitive database and `GRANT SELECT` on the table to the delegate, a median 25 s later.
3. The delegate's `CONNECT` to the sensitive database, `READ` and successful `QUERY` of that table, `DISCONNECT`.
4. The DBA's `REVOKE SELECT` of the same grant and `DISCONNECT`.
5. The delegate's next connection to the application database, denied with 1142 on the same table.

The episode's records interleave with the application pool and other people's sessions, and take the place of an equal number of application records around them, so the daily volume and the hour curve are the same as in background. Linking fields: `username` and `host` of the DBA and delegate, `connectionid` of each session, `queryid` between table records and their `QUERY`, and the grantee, address, and table in the GRANT/REVOKE text and in the delegate's read and denial.

Recurrence: the first episode starts within the first min(interval, 24 hours) of the log, at a time drawn from the grant-maintenance hour curve. Each next episode is due one interval after the actual start of the previous one; its start is drawn in a window of width w = min(interval / 4, 6 hours) centred on the due time, weighted by the squared hour curve plus a small floor (24 h default: 21 to 27 hours after the previous start, mostly in business hours). The episode takes a DBA and a delegate who are available at that moment, like ordinary maintenance, and waits about a minute at a time while none is. Missed intervals are not replayed. The interval is `anomaly_interval_hours` (default 24, minimum 6). At intervals shorter than a day some episodes necessarily fall outside business hours.

Variation: the DBA, delegate, and table come from the same random draw as ordinary maintenance; an episode additionally avoids the previous episode's DBA and table pair, so consecutive episodes differ in the DBA or the table. Every account, account pair, and table an episode uses also appears in ordinary maintenance, and failure runs followed by a login occur in background too. What only episodes contain is such a run of at least three failures and a login followed by that DBA's GRANT within 30 minutes of the first failure.

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

Account, database, and table names are lowercase identifiers matching `[a-z][a-z0-9_]{0,31}`. All accounts must have distinct names and distinct IPv4 addresses, sensitive tables must be distinct, the two databases must differ and must not be `mysql`, and the DBA or table pool needs two or more entries so that consecutive episodes can differ. `samples/tables.json` must hold 1 to 100 unique `orders_NN` names. With about 11 grant maintenances per day, the 6-hour minimum keeps episodes to at most about a quarter of all grants, so ordinary grants remain the majority in both modes.

The volume and the hour curves live in the `time_patterns` files under `patterns/`: `app-floor` (00-24 UTC), `app-day` (07-21) and `app-core` (08-19) for application statements, `people-floor`, `people-day` (07-19) and `people-core` (08-18) for DBA and delegate sessions, and `maint-floor`, `maint-day` and `maint-core` for grant maintenance. To change the volume, scale the `ratio` of the three `app-*` files by the same factor. To move the working day to another time zone, shift the `low` / `high` bounds of the `-day` and `-core` files; episode start hours follow the shipped maintenance curve. To use other application table names, edit `samples/tables.json`.

### Output Parameters

The shipped file output needs no substitutions. To deliver elsewhere, replace the `output` block with another output plugin and pass its host through `${params.*}` and credentials through `${secrets.*}`, for example `${params.opensearch_host}` and `${secrets.opensearch_password}`.

## Usage

Live generation at the configured rate, from the content-packs repository root:

```bash
eventum generate --path generators/database-mariadb-audit/generator.yml --id database-mariadb-audit --live-mode true --keep-order true
```

Batch generation: set `start` and `end` of the `oscillator` in all nine `patterns/*.yml` files to the same range, with `start` at 00:00 UTC so the hour bands stay in place (for example `start: "2026-09-21T00:00:00Z"` and `end: "2026-09-25T00:00:00Z"`), then run:

```bash
eventum generate --path generators/database-mariadb-audit/generator.yml --id database-mariadb-audit --live-mode false --keep-order true
```

Output goes to `generators/database-mariadb-audit/output/events.json`. Keep `--keep-order true`: session and table-to-query ordering depends on the physical record order. A window of two intervals plus six hours holds at least two episodes.

Performance: about 3,600 records per second in batch mode on one core.

## Limitations

- No unmodified production audit file was available. The vendor regression result replaces times, host names, and IDs with placeholders, so the field grammar comes from the tagged source code, and ID values, timing, and workload are synthetic.
- The profile covers FILE output only. SYSLOG output of this version omits the timestamp slot and adds a syslog header; MariaDB 12.x adds client ports and TLS details. Neither is modelled.
- The GRANT/REVOKE system-table records are derived from source, not from a captured trace. Other hook-producing activity (statistics tables, DDL, stored programs, `CHANGE USER`, proxies, password statements, prepared statements) is excluded by the selected settings and workload.
- All connections come from the configured accounts, so connection ids increase by one per connection. Clients send no connect-time statements (for example the `mysql` client's `select @@version_comment limit 1`); the modelled clients are an application pool and scripted sessions. There is one application server, and a DBA or delegate takes part in at most one temporary grant at a time.
- `event.created` trails `@timestamp` by up to about two minutes at night (median 0 s, 90% within 8 s), more than a file collector usually shows. At night a person's consecutive actions, such as password retries, are at least several seconds apart.
- The hour curves are in UTC and repeat every day: there is no weekly cycle, so weekends look like weekdays.
- With `anomaly_mode: true` each episode adds its own records: three or four failed logins of one DBA, and one GRANT, REVOKE and 1142 denial more than in background. At the default interval the DBAs' failed logins are therefore about 1.7 times the background level (about 8.5 instead of 5 a day), and runs of three or more failures followed by a login occur about 9-10 times a week instead of two or three.
- ECS fields other than the parsed native slots (`event.*`, `host.*`, `observer.*`, `service.*`, `source.ip`, `related.*`, `log.file.path`) are collector-side enrichment. No maintained Elastic integration for MariaDB `server_audit` was found to compare against, and no SIEM parser was run.

## Sample Output

The GRANT of an episode (the same statement shape by the same DBA also appears in ordinary grant maintenance):

```json
{
  "@timestamp": "2026-10-12T10:26:30+00:00",
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "query",
    "category": [
      "database",
      "iam"
    ],
    "created": "2026-10-12T10:26:35.421863+00:00",
    "dataset": "mariadb.audit",
    "ingested": "2026-10-12T10:26:35.421863+00:00",
    "kind": "event",
    "original": "20261012 10:26:30,db-01.corp.example,dba_ops,10.99.4.52,1081,4771,QUERY,payroll,'GRANT SELECT ON payroll.bonuses TO \\'report_user\\'@\\'10.99.5.22\\'',0",
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
      "object": "GRANT SELECT ON payroll.bonuses TO 'report_user'@'10.99.5.22'",
      "operation": "QUERY",
      "queryid": 4771,
      "retcode": 0,
      "serverhost": "db-01.corp.example",
      "timestamp": "20261012 10:26:30",
      "username": "dba_ops"
    }
  },
  "message": "20261012 10:26:30,db-01.corp.example,dba_ops,10.99.4.52,1081,4771,QUERY,payroll,'GRANT SELECT ON payroll.bonuses TO \\'report_user\\'@\\'10.99.5.22\\'',0",
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

# Oracle Database 19c Unified Audit Trail

Generates JSON rows from a defined 22-column projection of the Oracle Database 19c `UNIFIED_AUDIT_TRAIL` view, as a connector polling that view would deliver them. It is intended for SIEM content that correlates database logons, sensitive reads and privilege changes. It is not Oracle syslog output or a native Oracle JSON export.

## Volume and Timing

About 8,600 rows per day with ±3% day-to-day variation, following a UTC hour-of-day curve; rows fall at random times inside each band.

| UTC hours | Rows per hour |
| --- | ---: |
| 07-19 | about 465 |
| 19-07 | about 250 |

Application connection pools write about 90% of the rows around the clock, with more work between 07:00 and 19:00 UTC. Analysts and administrators follow a working day: their sessions start about 16 times as often between 08:00 and 18:00 UTC as at night, about five times as often at 07-08 and 18-19, about 170 sessions a day in all.

## Event Types

Shares in a four-day log with the default `anomaly_mode: true` (34,274 rows):

| `ACTION_NAME` | `RETURN_CODE` | Scenario | `UNIFIED_AUDIT_POLICIES` | Share | Category |
| --- | --- | --- | --- | ---: | --- |
| `SELECT` | `0` | Reporting, HR and payroll table reads | `APP_DATA_AUDIT` | 74.96% | database access |
| `UPDATE` | `0` | HR employee phone updates | `APP_DATA_AUDIT` | 11.13% | database change |
| `LOGON` | `0` | Successful session start | `APP_SESSION_AUDIT` | 6.65% | authentication |
| `LOGOFF` | `0` | Session end | `APP_SESSION_AUDIT` | 6.53% | authentication |
| `LOGON` | `1017` | Invalid username/password (ORA-01017) | `ORA_LOGON_FAILURES` | 0.27% | authentication |
| `REVOKE` | `0` | Administrator revokes an application role | `ORA_ACCOUNT_MGMT` | 0.23% | iam |
| `GRANT` | `0` | Administrator grants an application role | `ORA_ACCOUNT_MGMT` | 0.23% | iam |

## Workload Model

Rates are workload assumptions, not measured Oracle frequencies. Every session starts with a `LOGON` that opens a new `SESSIONID`, runs statements and ends with a `LOGOFF`.

- **Application pools:** 41 connection pools (`APP_READ`, `BI_APP`, `HR_APP`, `ETL_APP`, `PAYROLL_APP`, one per host in `samples/clients.csv`). A pool connection runs a log-normal number of statements (median 12) minutes apart and is then replaced, so each pool logs on about ten times a day. About 1% of pool logons fail with ORA-01017 (a stale saved password) and are retried within seconds, sometimes several times in a row.
- **People:** five analysts and four administrators from `samples/people.csv`, each with one to three usual hosts, including the shared `jump01.corp.example`. A session belongs to a person drawn by their share of daily sessions (administrators about 13-40 a day, analysts about 5-12) from one of their hosts; a person has at most two sessions open at once, and a second session from the same host sometimes overlaps the first. Analysts read `REPORTING.DAILY_SALES`, `HR.EMPLOYEES` and `FINANCE.PAYROLL` and update `HR.EMPLOYEES` according to their job (median 4-6 statements); administrators run short sessions (median 2 statements) that read the three tables, update `HR.EMPLOYEES` and manage roles. Statements within a session are a log-normal gap apart (median 30 s for administrators, 45 s for analysts).
- **Failed logons:** a person's first logon attempt fails with ORA-01017 in 5% (analysts) or 7% (administrators) of sessions. The retry follows a median 20 s later (mostly 8-50 s) and fails again with probability 0.35; after a failure the person gives up in 15% of cases. One failure before a successful logon is the most common case, then two, then three or more. About 9% of people's logon attempts and about 3.5% of all logon attempts fail, about 20 a day. No account reaches ten consecutive failures, where the DEFAULT profile would lock it.
- **Role management:** administrators grant the roles `PAYROLL_READ`, `APP_REPORTER`, `HR_VIEW` and `SALES_READ` to the five analysts, about 20-25 grants a day, about half of them `PAYROLL_READ`. A role is only granted to an analyst who does not hold it, and only revoked while held. 60% of grants are revoked by the same administrator from the same host in a follow-up session a log-normal delay later (median 30 minutes); 30% of these sessions run one ordinary statement before the revoke, and 40% log off right after it. The other grants are held for a log-normal lifetime (median 90 minutes) and then revoked by whichever administrator next does role cleanup, so a grant made late in the day is revoked the next morning. About 70% of revokes come from the granting administrator and host; the median time from grant to revoke is about 45 minutes.

## Audit Configuration Assumed

Unified auditing is enabled, and the following policies are enabled in the modeled Oracle 19c database:

```sql
AUDIT POLICY ORA_LOGON_FAILURES WHENEVER NOT SUCCESSFUL;
CREATE AUDIT POLICY APP_SESSION_AUDIT ACTIONS LOGON, LOGOFF;
AUDIT POLICY APP_SESSION_AUDIT WHENEVER SUCCESSFUL;
CREATE AUDIT POLICY APP_DATA_AUDIT ACTIONS
  SELECT ON REPORTING.DAILY_SALES,
  SELECT ON HR.EMPLOYEES,
  UPDATE ON HR.EMPLOYEES,
  SELECT ON FINANCE.PAYROLL;
AUDIT POLICY APP_DATA_AUDIT WHENEVER SUCCESSFUL;
AUDIT POLICY ORA_ACCOUNT_MGMT;
```

`ORA_LOGON_FAILURES` (`ACTIONS LOGON`, enabled `WHENEVER NOT SUCCESSFUL`) is enabled by default in newly created 19c databases, but not necessarily in upgraded ones. `ORA_ACCOUNT_MGMT` audits `GRANT` and `REVOKE` among other account actions and must be enabled explicitly. The custom policies above are example deployment configuration, not built-in Oracle policies.

`HR.EMPLOYEES` uses the Oracle sample schema. `REPORTING.DAILY_SALES` and `FINANCE.PAYROLL` are synthetic application tables. Each administrator is assumed to have direct `SELECT` on the three tables and `ADMIN OPTION` on the four roles; the analysts are database users. All grants are authorized, so Oracle does not reject any of them. The episode is suspicious only because of the order and timing of its events.

## Anomaly Chain

An administrator's password is guessed from that administrator's usual workstation. The attacker then reads payroll and grants a payroll role to an ordinary analyst account. Later the role is revoked again.

1. Three or more `LOGON` failures (`RETURN_CODE=1017`, `ORA_LOGON_FAILURES`) for the administrator from one host, spaced like ordinary password retries (median about 20 s). Each attempt has its own `SESSIONID`. After the third failure, each further failure follows with probability 0.3, as for ordinary retries, up to eight and never reaching the lockout.
2. A successful `LOGON` by the same account and host, which opens a new session.
3. In that session, an optional ordinary statement (30%), then one to three `SELECT` statements on `FINANCE.PAYROLL`.
4. `GRANT PAYROLL_READ TO <analyst>`, an optional ordinary statement (35%), then `LOGOFF`.
5. Restoration, under the same law as every ordinary grant: in 60% of episodes a follow-up session by the same account and host revokes the role (median 30 minutes later, same session shape as ordinary follow-up revokes); otherwise the grant is held for an ordinary lifetime and revoked in ordinary role cleanup.

The episode's rows interleave with other traffic. The episode session counts toward the administrator's two open sessions like any other session; the administrator's ordinary sessions continue as usual before, during and after it. Consecutive steps are seconds to a few minutes apart; from the first failure to the grant takes about 2-7 minutes.

**Linking fields:** `DBUSERNAME` and `USERHOST` across the failures and the session. `SESSIONID` links steps 2-4. `ROLE` and `TARGET_USER` link the grant to its revoke.

**Actors:** the administrators marked `episode=yes` in `samples/people.csv` (`SEC_ADMIN`, `FINANCE_DBA`, `DBA_CHEN`), each at the first host listed for them (`admin01`, `wkst-091`, `wkst-083`), drawn by their number of sessions from that host and never the previous episode's administrator. These are the busiest administrator and host pairs: in ordinary traffic each of them logs on about 25-35 times a day, fails a logon two to four times a day, reads payroll about 15-40 times a day and grants `PAYROLL_READ` two to five times a day on average. The grantee is an analyst who does not hold `PAYROLL_READ` and differs from the previous episode's grantee.

**Recurrence:** the first episode starts within the first `min(anomaly_interval_hours, 24 h)` of the log. Each next episode is due `anomaly_interval_hours` after the actual start of the previous one; its start is drawn in a window of width `w = min(interval / 4, 6 h)` centred on the due time. Start hours are weighted by the squared session-start curve plus a small floor (0.02), so episodes fall mostly in working hours. Missed intervals are not replayed. If no eligible administrator or grantee is available at the drawn time, the start moves on by 5-minute steps until one is. The default interval is 24 h (episodes 21-27 h apart, mostly 08:00-18:00 UTC); the accepted range is 6 to 8,760 hours. With an 8-hour interval the window is 2 hours wide, so about a third of the episodes fall between midnight and 03:00 UTC, when the administrators are rarely active; ordinary traffic has no failed administrator logons at those hours, so a night run of failures by an administrator then belongs to an episode.

**Ordinary look-alikes (both modes):** the same administrators and hosts fail logons, sometimes three or more times in a row before succeeding; they read payroll, grant `PAYROLL_READ` to the same analysts, and revoke it in follow-up sessions of the same shape as the episode's restoration session. Only the complete ordered sequence is absent from ordinary traffic: when an ordinary session opened after three or more failures of its account and host within the last 30 minutes reads payroll, it grants a role other than `PAYROLL_READ`. A payroll read and `PAYROLL_READ` grant in a session other than the one opened after the failures still occur in ordinary traffic.

**Detection idea:** per `DBUSERNAME` and `USERHOST`, at least three ORA-01017 failures, then a successful `LOGON` whose session reads `FINANCE.PAYROLL` and grants `PAYROLL_READ`, all within 30 minutes. Sort rows by `EVENT_TIMESTAMP_UTC` before matching the sequence. A revoke of the same role from the same grantee by the same account and host within about an hour, as in most episodes, strengthens the finding.

`anomaly_mode` defaults to `true`. With `false`, only ordinary background is generated and the complete chain never occurs.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Name | Default | Description |
| --- | --- | --- |
| `anomaly_mode` | `true` | Generate the recurring failed-logon, payroll-read and grant chain |
| `anomaly_interval_hours` | `24` | Hours between episode due times, counted from the previous actual start; 6..8760 |
| `database_id` | `3459081234` | Synthetic numeric `DBID` |

### Sample Files

- `samples/people.csv`: analysts and administrators. `username`, `os_username`, `hosts` (`host:weight` pairs separated by `|`, the first host being the usual workstation), `sessions_per_day` (share of the daily sessions), `statements_median`, `workload` (the statement mix: `sales`, `bi`, `hr`, `audit`, `finance` for analysts; `access_admin`, `finance_dba`, `dba`, `dba_light` for administrators) and `episode` (`yes` for administrators that episodes can use; at least two). Analysts are also the grantees. Keep every `episode=yes` administrator busy at the first listed host, or that pair may be missing from ordinary traffic on some days.
- `samples/clients.csv`: application connection pools, one row per pool host, with `workload` `reporting`, `hr` or `finance`.

The volume and hour curves live in `patterns/`: `app-floor.yml` (00-24 UTC) and `app-day.yml` (07-19) for the pools, `people-floor.yml`, `people-day.yml` (07-19) and `people-core.yml` (08-18) for analyst and administrator sessions. To change the volume, scale the `ratio` of the files of one group by the same factor.

### Output Parameters

The shipped configuration writes `output/events.json` and needs no parameters or secrets. To send events elsewhere, replace the `file` output in a local copy. Reference connection values as `${params.<name>}` and credentials as `${secrets.<name>}`, for example `${params.opensearch_host}` and `${secrets.opensearch_password}`.

## Usage

Live generation at the configured rate, from the content-packs repository root:

```bash
eventum generate --path generators/database-oracle-unified-audit/generator.yml --id oracle-audit --live-mode true --keep-order true
```

Batch generation: set `start` and `end` of the `oscillator` in all five `patterns/*.yml` files to the same range, with `start` at 00:00 UTC so the hour bands stay in place (for example `start: "2026-09-20T00:00:00Z"` and `end: "2026-09-24T00:00:00Z"`), then run:

```bash
eventum generate --path generators/database-oracle-unified-audit/generator.yml --id oracle-audit --live-mode false --keep-order true
```

Results are written as JSON Lines to `generators/database-oracle-unified-audit/output/events.json`. A window of two intervals plus six hours holds at least two episodes.

Performance: about 4,800 rows per second in batch mode on one core.

## Sample Output

The role grant of the first episode in a four-day default log:

```json
{"ACTION_NAME": "GRANT", "AUDIT_TYPE": "Standard", "CLIENT_PROGRAM_NAME": "sqlplus@wkst-091.corp.example (TNS V1-V3)", "CURRENT_USER": "FINANCE_DBA", "DBID": 3459081234, "DBUSERNAME": "FINANCE_DBA", "ENTRY_ID": 4, "EVENT_TIMESTAMP": "2026-09-20 17:37:02.534192", "EVENT_TIMESTAMP_UTC": "2026-09-20 17:37:02.534192", "INSTANCE_ID": 1, "OBJECT_NAME": null, "OBJECT_SCHEMA": null, "OS_USERNAME": "mnovak", "RETURN_CODE": 0, "ROLE": "PAYROLL_READ", "SESSIONID": 3006292300, "SQL_BINDS": null, "SQL_TEXT": "GRANT PAYROLL_READ TO HR_ANALYST", "STATEMENT_ID": 6, "TARGET_USER": "HR_ANALYST", "UNIFIED_AUDIT_POLICIES": "ORA_ACCOUNT_MGMT", "USERHOST": "wkst-091.corp.example"}
```

## Projection and Limits

- The 22 selected columns are `AUDIT_TYPE`, `SESSIONID`, `ENTRY_ID`, `STATEMENT_ID`, `EVENT_TIMESTAMP`, `EVENT_TIMESTAMP_UTC`, `ACTION_NAME`, `RETURN_CODE`, `DBUSERNAME`, `OS_USERNAME`, `USERHOST`, `CLIENT_PROGRAM_NAME`, `DBID`, `INSTANCE_ID`, `OBJECT_SCHEMA`, `OBJECT_NAME`, `SQL_TEXT`, `SQL_BINDS`, `ROLE`, `TARGET_USER`, `UNIFIED_AUDIT_POLICIES` and `CURRENT_USER`. This is 22/22 of the selected projection, not coverage of the full view. Database Vault, RMAN, Data Pump, proxy and other feature-specific columns are out of scope.
- The modeled connector serializes `NUMBER` as JSON numbers and SQL `NULL` as JSON null. It formats both `TIMESTAMP(6)` columns as `YYYY-MM-DD HH24:MI:SS.FF6`. The database runs in UTC, so the local and UTC timestamps are equal. Oracle stores these columns without a time zone, so the text form is a declared connector choice.
- `SQL_BINDS` is null because every modeled statement uses literals. Failed logons have null `CURRENT_USER`, because no effective user has been established; this behavior is not confirmed against a live capture.
- `SESSIONID` values increase by random steps from a random start; they do not emulate Oracle's allocation. `ENTRY_ID` advances by one per audit record in a session. `STATEMENT_ID` advances by one or more, to model unaudited statements between audited ones.
- One database instance (`INSTANCE_ID` 1). `CLIENT_PROGRAM_NAME` is `JDBC Thin Client`, `SQL Developer` or `sqlplus@<host> (TNS V1-V3)` truncated to 48 characters.
- Consecutive rows of one session, including password retries, are never less than a few seconds apart (median retry gap about 20 s); real clients can retry within a second.
- The hour curves are in UTC and repeat every day: there is no weekly cycle, so weekends look like weekdays.
- With `anomaly_mode: true` each episode adds its own rows: three or more failed logons, a session with payroll reads and a `PAYROLL_READ` grant, and its revoke. At the default interval failed logons are about 15-20% more frequent than without episodes, and runs of three or more failures followed by a successful logon of the same account and host occur about two to three times a day instead of one to two.
- No version-matched Oracle 19c export of this 22-column projection was available, so byte-level row fidelity and the nullability of every column in live deployments remain unverified. Field names, types and meanings follow the Oracle reference below.

## References

- [Oracle Database 19c `UNIFIED_AUDIT_TRAIL` column definitions](https://docs.oracle.com/en/database/oracle/oracle-database/19/refrn/UNIFIED_AUDIT_TRAIL.html)
- [Oracle Database 19c predefined unified audit policies](https://docs.oracle.com/en/database/oracle/oracle-database/19/dbseg/auditing-activities-predefined-unified-audit-policies.html)
- [Oracle Database 19c object audit policy syntax and examples](https://docs.oracle.com/en/database/oracle/oracle-database/19/dbseg/auditing-object-actions.html)
- [Oracle Database 19c example of a `LOGON`, `LOGOFF` policy](https://docs.oracle.com/en/database/oracle/oracle-database/19/dbseg/troubleshooting-for-audit.html)
- [Oracle Database 19c `CREATE PROFILE` (`FAILED_LOGIN_ATTEMPTS`)](https://docs.oracle.com/en/database/oracle/oracle-database/19/sqlrf/CREATE-PROFILE.html)

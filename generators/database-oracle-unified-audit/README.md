# Oracle Database 19c Unified Audit Trail

Generates JSON rows from a defined 22-column projection of the Oracle Database 19c `UNIFIED_AUDIT_TRAIL` view, as a connector polling that view would deliver them. It is intended for SIEM content that correlates database logons, sensitive reads and privilege changes. It is not Oracle syslog output or a native Oracle JSON export.

## Event Types

Measured on a 144-hour default capture (`anomaly_mode: true`, 55,800 rows, about 9,300 rows per day):

| `ACTION_NAME` | `RETURN_CODE` | Scenario | `UNIFIED_AUDIT_POLICIES` | Share | Category |
| --- | --- | --- | --- | ---: | --- |
| `SELECT` | `0` | Reporting, HR and payroll table reads | `APP_DATA_AUDIT` | 76.69% | database access |
| `UPDATE` | `0` | HR employee phone updates | `APP_DATA_AUDIT` | 11.20% | database change |
| `LOGON` | `0` | Successful session start | `APP_SESSION_AUDIT` | 5.72% | authentication |
| `LOGOFF` | `0` | Session end | `APP_SESSION_AUDIT` | 5.72% | authentication |
| `LOGON` | `1017` | Invalid username/password (ORA-01017) | `ORA_LOGON_FAILURES` | 0.26% | authentication |
| `REVOKE` | `0` | Administrator revokes an application role | `ORA_ACCOUNT_MGMT` | 0.21% | iam |
| `GRANT` | `0` | Administrator grants an application role | `ORA_ACCOUNT_MGMT` | 0.21% | iam |

Every client is an independent session process: sessions start at random (Poisson) times, a successful `LOGON` opens a new `SESSIONID`, a log-normal number of statements follows at log-normal gaps, and a `LOGOFF` closes the session. Clients are:

- 41 application connection pools (`APP_READ`, `BI_APP`, `HR_APP`, `ETL_APP`, `PAYROLL_APP`, one per host in `samples/clients.csv`), active around the clock.
- Five analysts (`REPORT_USER`, `BI_ANALYST`, `HR_ANALYST`, `AUDIT_RO`, `FIN_ANALYST`) and four administrators (`FINANCE_DBA`, `SEC_ADMIN`, `DBA_MARTIN`, `DBA_CHEN`), each with one to three usual hosts, including the shared `jump01.corp.example`. Their sessions are about three times as frequent between 07:00 and 18:00 UTC as at night. Each person runs two independent session processes, like two open tool windows, so a second session from the same host sometimes overlaps the first.

Any logon can fail with ORA-01017. People retry after a few seconds and fail again about half the time, so bursts of two to six failures by one user and host, followed by a successful logon or by giving up, are ordinary. Application pools occasionally hit a stale password and retry quickly several times. Administrators read `FINANCE.PAYROLL`, `HR.EMPLOYEES` and `REPORTING.DAILY_SALES`, update `HR.EMPLOYEES`, and grant and revoke the roles `PAYROLL_READ`, `APP_REPORTER`, `HR_VIEW` and `SALES_READ` to the analysts. Half of the grants are revoked by the same administrator from the same host in a later follow-up session (log-normal delay, median 45 minutes); 30% of these sessions run one ordinary statement before the revoke, and 40% log off right after it. The rest stay held for a random lifetime (log-normal, median 6 h) and are then revoked by whichever administrator next does role cleanup. No new grants start while 12 of the 20 role and analyst pairs are held. The weights are workload assumptions, not measured Oracle frequencies.

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

An administrator's password is guessed from one of that administrator's usual hosts. The attacker then reads payroll and grants a payroll role to an ordinary analyst account. Later the attacker revokes the role again.

1. Three to eight `LOGON` failures (`RETURN_CODE=1017`, `ORA_LOGON_FAILURES`) for the administrator from one host, seconds apart. Each attempt has its own `SESSIONID`.
2. A successful `LOGON` by the same account and host, which opens a new session.
3. In that session, an optional ordinary statement, then one to three `SELECT` statements on `FINANCE.PAYROLL`.
4. `GRANT PAYROLL_READ TO <analyst>`, optionally one more ordinary statement, then `LOGOFF`.
5. Restoration, under the same law as every ordinary grant. In half of the episodes, a later follow-up session by the same account and host (log-normal delay, median 45 minutes) runs `REVOKE PAYROLL_READ FROM <analyst>`. That session is built like an ordinary follow-up revoke session: the logon can fail and be retried, one ordinary statement precedes the revoke in 30% of sessions, and 40% end right after it; otherwise a log-normal number of ordinary statements follows before `LOGOFF`. In the other half, the grant becomes an ordinary held grant with the same random lifetime as other grants and is revoked in ordinary work.

**Linking fields:** `DBUSERNAME` and `USERHOST` across the failures and the session. `SESSIONID` links steps 2-4. `ROLE` and `TARGET_USER` link the grant to its revoke.

**Recurrence:** the first episode starts within the first `min(anomaly_interval_hours, 24 h)` of generation, at a time drawn from the administrators' activity curve (weight 1.0 from 07:00 to 18:00 UTC, 0.3 otherwise). Each next episode is due `anomaly_interval_hours` after the actual start of the previous one, with no catch-up. Its start is drawn in a window centred on the due time, of width `w = min(interval / 4, 6 h)`, weighted by the squared activity curve plus a small floor (0.05). Once a start falls in working hours, later starts stay there instead of drifting; a start at night moves by at most `w / 2` per episode until it reaches working hours. The default interval is 24 h, and the minimum accepted value is 6 h. An episode also waits until some analyst other than the previous grantee does not hold `PAYROLL_READ`; such a wait delays that start and, through it, the next due time. Measured over 144 h: with the default interval, 6 episodes, the first at 01:26 UTC, gaps 23.57-26.66 h, starts moving from night into 08:14-09:51 UTC over the run, spans 88-526 s from the first failure to the grant. With an 8 h interval, 18 episodes, gaps 7.20-12.64 h (the longest includes a wait for an eligible grantee), spans 105-788 s; a 2 h window cannot keep 8-hourly episodes in working hours. Intervals below 6 h are rejected, so that episodes stay rare relative to ordinary failure bursts and grants.

The episode runs as a separate session alongside the administrator's ordinary sessions, which continue unchanged.

**Variation:** the administrator and host are drawn with the same weights as ordinary administrator sessions, and the pair differs from the previous episode's. The grantee is an analyst who does not hold `PAYROLL_READ` and differs from the previous episode's grantee. The failure count, reads, statement text and all gaps are random. Retry gaps and statement gaps come from the same distributions as ordinary sessions.

**Ordinary look-alikes (both modes):** the same administrators and hosts log on and fail, sometimes three or more times in a row before succeeding. They read payroll, grant `PAYROLL_READ` to the same analysts, and revoke it in follow-up sessions of the same shape as the episode's restoration session. Only the complete ordered sequence is absent from ordinary traffic. When an ordinary `PAYROLL_READ` grant would complete the chain within 30 minutes (three failures by the same user and host, then the logon of the current session and a payroll read in that session), a different role is granted instead. The time and the grant action stay the same. The guard considers only the current session, so a payroll read and grant in a session other than the one opened after the failures still occur in ordinary traffic.

**Detection idea:** per `DBUSERNAME` and `USERHOST`, at least three ORA-01017 failures, then a successful `LOGON` whose session reads `FINANCE.PAYROLL` and grants `PAYROLL_READ`, all within 30 minutes. Sort rows by `EVENT_TIMESTAMP_UTC` before matching the sequence. A revoke of the same role from the same grantee by the same account and host within about an hour, as in half of the episodes, strengthens the finding.

`anomaly_mode` defaults to `true`. With `false`, only ordinary background is generated and the complete chain never occurs.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Name | Default | Description |
| --- | --- | --- |
| `anomaly_mode` | `true` | Generate the recurring failed-logon, payroll-read and grant chain |
| `anomaly_interval_hours` | `24` | Hours between episode due times, counted from the previous actual start; 6..8760 |
| `database_id` | `3459081234` | Synthetic numeric `DBID` |

### Output Parameters

The shipped configuration writes `output/events.json` and needs no parameters or secrets. To send events elsewhere, replace the `file` output in a local copy. Reference connection values as `${params.<name>}` and credentials as `${secrets.<name>}`, for example `${params.opensearch_host}` and `${secrets.opensearch_password}`.

## Usage

Live, one input tick per second (about 9,300 rows per day):

```bash
eventum generate --path generators/database-oracle-unified-audit/generator.yml --id oracle-audit --live-mode true
```

For a batch file over a fixed period, set `start` and `end` on the `cron` input in a local copy and run:

```bash
eventum generate --path generators/database-oracle-unified-audit/generator.yml --id oracle-audit --live-mode false
```

Results are written as JSON Lines to `output/events.json`.

## Sample Output

The role grant of the first episode in the default 144-hour capture:

```json
{"ACTION_NAME": "GRANT", "AUDIT_TYPE": "Standard", "CLIENT_PROGRAM_NAME": "SQL Developer", "CURRENT_USER": "DBA_MARTIN", "DBID": 3459081234, "DBUSERNAME": "DBA_MARTIN", "ENTRY_ID": 5, "EVENT_TIMESTAMP": "2026-09-26 01:27:31.953645", "EVENT_TIMESTAMP_UTC": "2026-09-26 01:27:31.953645", "INSTANCE_ID": 1, "OBJECT_NAME": null, "OBJECT_SCHEMA": null, "OS_USERNAME": "pmartin", "RETURN_CODE": 0, "ROLE": "PAYROLL_READ", "SESSIONID": 3028048354, "SQL_BINDS": null, "SQL_TEXT": "GRANT PAYROLL_READ TO AUDIT_RO", "STATEMENT_ID": 7, "TARGET_USER": "AUDIT_RO", "UNIFIED_AUDIT_POLICIES": "ORA_ACCOUNT_MGMT", "USERHOST": "wkst-077.corp.example"}
```

## Projection and Limits

- The 22 selected columns are `AUDIT_TYPE`, `SESSIONID`, `ENTRY_ID`, `STATEMENT_ID`, `EVENT_TIMESTAMP`, `EVENT_TIMESTAMP_UTC`, `ACTION_NAME`, `RETURN_CODE`, `DBUSERNAME`, `OS_USERNAME`, `USERHOST`, `CLIENT_PROGRAM_NAME`, `DBID`, `INSTANCE_ID`, `OBJECT_SCHEMA`, `OBJECT_NAME`, `SQL_TEXT`, `SQL_BINDS`, `ROLE`, `TARGET_USER`, `UNIFIED_AUDIT_POLICIES` and `CURRENT_USER`. This is 22/22 of the selected projection, not coverage of the full view. Database Vault, RMAN, Data Pump, proxy and other feature-specific columns are out of scope.
- The modeled connector serializes `NUMBER` as JSON numbers and SQL `NULL` as JSON null. It formats both `TIMESTAMP(6)` columns as `YYYY-MM-DD HH24:MI:SS.FF6`. The database runs in UTC, so the local and UTC timestamps are equal. Oracle stores these columns without a time zone, so the text form is a declared connector choice.
- `SQL_BINDS` is null because every modeled statement uses literals. Failed logons have null `CURRENT_USER`, because no effective user has been established; this behavior is not confirmed against a live capture.
- `SESSIONID` values increase by random steps from a random start; they do not emulate Oracle's allocation. `ENTRY_ID` advances by one per audit record in a session. `STATEMENT_ID` advances by one or more, to model unaudited statements between audited ones.
- One database instance (`INSTANCE_ID` 1) and one row per second at most. `CLIENT_PROGRAM_NAME` is `JDBC Thin Client`, `SQL Developer` or `sqlplus@<host> (TNS V1-V3)` truncated to 48 characters.
- No version-matched Oracle 19c export of this 22-column projection was available, so byte-level row fidelity and the nullability of every column in live deployments remain unverified. Field names, types and meanings follow the Oracle reference below.

## References

- [Oracle Database 19c `UNIFIED_AUDIT_TRAIL` column definitions](https://docs.oracle.com/en/database/oracle/oracle-database/19/refrn/UNIFIED_AUDIT_TRAIL.html)
- [Oracle Database 19c predefined unified audit policies](https://docs.oracle.com/en/database/oracle/oracle-database/19/dbseg/auditing-activities-predefined-unified-audit-policies.html)
- [Oracle Database 19c object audit policy syntax and examples](https://docs.oracle.com/en/database/oracle/oracle-database/19/dbseg/auditing-object-actions.html)
- [Oracle Database 19c example of a `LOGON`, `LOGOFF` policy](https://docs.oracle.com/en/database/oracle/oracle-database/19/dbseg/troubleshooting-for-audit.html)

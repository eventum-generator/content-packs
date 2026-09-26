# Oracle Database 19c Unified Audit Trail

Generates JSON rows from a defined 22-column projection of Oracle Database 19c `UNIFIED_AUDIT_TRAIL`. The modeled source is a connector polling the database view, not Oracle syslog or a native Oracle JSON transport.

## Event Types

| `ACTION_NAME` | Scenario | `UNIFIED_AUDIT_POLICIES` |
| --- | --- | --- |
| `LOGON`, success | Application and administrator session start | `APP_SESSION_AUDIT` |
| `LOGON`, `RETURN_CODE=1017` | Invalid username/password | `ORA_LOGON_FAILURES` |
| `SELECT` | Reporting, HR, and payroll table reads | `APP_DATA_AUDIT` |
| `UPDATE` | HR employee phone update | `APP_DATA_AUDIT` |
| `GRANT` | Administrator assigns an application role to a user | `ORA_ACCOUNT_MGMT` |
| `LOGOFF` | End of a successful session | `APP_SESSION_AUDIT` |

Application clients are sampled from 38 synthetic user/host pairs. Once connected, they mostly execute audited `SELECT` statements; HR clients occasionally execute `UPDATE` and any client may disconnect. Administrator activity and login failures are less frequent. These weights are workload assumptions, not measured Oracle frequencies.

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

`ORA_LOGON_FAILURES` is enabled by default in newly created 19c databases, but not necessarily in upgraded ones. `ORA_ACCOUNT_MGMT` must be enabled explicitly. The custom policies above are example deployment configuration, not built-in Oracle policies. They deliberately split successful session activity, object access, failed authentication, and role grants so each emitted record has a matching policy.

`HR.EMPLOYEES` uses the Oracle sample schema. `REPORTING.DAILY_SALES` and `FINANCE.PAYROLL` are synthetic application tables. Assume `FINANCE_DBA` (or the configured `target_user`) has direct `SELECT` on `FINANCE.PAYROLL` and `ADMIN OPTION` on `PAYROLL_READ`. That role grants `SELECT` on `FINANCE.PAYROLL`. `SEC_ADMIN` has `ADMIN OPTION` on `APP_REPORTER`. `BI_ANALYST` and the configured `grantee` are database users. The successful grants are authorized actions whose *timing and correlation* make the enabled chain suspicious; the pack does not imply that Oracle would reject them.

## Anomaly Chain

`anomaly_mode` defaults to `true`. After `anomaly_after_events` routine rows (250 by default), the generator starts an eight-row episode. Another episode starts after every `anomaly_interval_events` emitted rows (4,320 by default, about 12 hours at the shipped ten-second cadence):

1. Four `LOGON` failures (`RETURN_CODE=1017`) for the configured administrator from one client host. Each failed connection has its own `SESSIONID`.
2. A successful `LOGON` by the same account and host creates a new session.
3. That session reads `FINANCE.PAYROLL`, grants `PAYROLL_READ` to the configured user, then logs off. Its `SESSIONID` is stable and its `ENTRY_ID` and `STATEMENT_ID` advance from 1 to 4.

If an ordinary session for that administrator and host is open at a scheduled start, a routine `LOGOFF` closes it first; the episode starts on the next row. Each episode's successful login receives a distinct `SESSIONID`, and the hours-long gap separates episodes without adding a synthetic marker to the Oracle projection. A detection can correlate the failed logons with the later successful session, sensitive read and role grant. The same account, host, table, role, grantee, actions and an isolated failed login also occur in background traffic, but not as the complete ordered episode. With `anomaly_mode: false`, only background is generated.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Name | Default | Purpose |
| --- | --- | --- |
| `anomaly_mode` | `true` | Include recurring episodes |
| `anomaly_after_events` | `250` | Routine rows before the first episode |
| `anomaly_interval_events` | `4320` | Emitted rows between episode starts, about 12 hours by default; use a positive value greater than eight |
| `database_id` | `3459081234` | Synthetic numeric `DBID` |
| `target_user` | `FINANCE_DBA` | Administrator account used in background and chain |
| `attacker_host` | `wkst-091.corp.example` | Client host used in background and chain |
| `grantee` | `REPORT_USER` | Database user that receives `PAYROLL_READ` in the chain and `APP_REPORTER` in background |

### Output Parameters

The shipped pack writes `output/events.json` and needs no credentials. To send it to a SIEM, replace the file output with the appropriate plugin in a local copy. Configure that plugin's endpoint and secret using top-level `${params.*}` and `${secrets.*}` substitutions as required by the destination.

## Usage

From the `content-packs` repository:

```bash
flock -x /tmp/eventum-generator-heavy.lock timeout 3s uv run --project ../eventum eventum generate --path generators/database-oracle-unified-audit/generator.yml --id oracle-audit-sample --live-mode false
uv run --project ../eventum eventum generate --path generators/database-oracle-unified-audit/generator.yml --id oracle-audit --live-mode true
```

The first command generates a short sample quickly; exit code `124` from `timeout` is expected. The second runs continuously at one event every ten seconds. Results are written as JSON Lines to `output/events.json`.

## Sample Output

This complete row is copied from a 9,361-row, 26-hour run with the shipped default parameters. It is the role grant in the first episode:

```json
{"ACTION_NAME": "GRANT", "AUDIT_TYPE": "Standard", "CLIENT_PROGRAM_NAME": "sqlplus@wkst-091.corp.example (TNS V1-V3)", "CURRENT_USER": "FINANCE_DBA", "DBID": 3459081234, "DBUSERNAME": "FINANCE_DBA", "ENTRY_ID": 3, "EVENT_TIMESTAMP": "2026-09-26 00:42:40.000000", "EVENT_TIMESTAMP_UTC": "2026-09-26 00:42:40.000000", "INSTANCE_ID": 1, "OBJECT_NAME": null, "OBJECT_SCHEMA": null, "OS_USERNAME": "ops", "RETURN_CODE": 0, "ROLE": "PAYROLL_READ", "SESSIONID": 100049, "SQL_BINDS": null, "SQL_TEXT": "GRANT PAYROLL_READ TO REPORT_USER", "STATEMENT_ID": 3, "TARGET_USER": "REPORT_USER", "UNIFIED_AUDIT_POLICIES": "ORA_ACCOUNT_MGMT", "USERHOST": "wkst-091.corp.example"}
```

## Projection and Limits

The 22 selected fields cover audit type; session, entry, and statement IDs; local and UTC timestamps; action and result; database/OS user and client; database/instance ID; affected object and SQL; role and grantee; and matching policies. This is **22/22 selected projection fields**, not coverage of the full view. Database Vault, RMAN, Data Pump, proxy, and other feature-specific columns are outside this Standard audit-row scope.

The modeled connector serializes Oracle `NUMBER` columns as JSON numbers and SQL `NULL` as JSON null. It formats both `TIMESTAMP(6)` columns as `YYYY-MM-DD HH24:MI:SS.FF6`. The generator uses Eventum's default UTC timezone, so local and UTC timestamp values are equal in this example. Oracle stores these columns without a timezone suffix; the JSON text representation here is a declared connector choice. `SQL_BINDS` is null because every modeled statement uses SQL literals. Failed logons use null `CURRENT_USER` because no effective session user has been established.

`SESSIONID` values are synthetic identifiers, not an emulation of Oracle's ID allocation. `ENTRY_ID` advances per audited record in a session. `STATEMENT_ID` also advances by one because the model emits one audit record per statement; real statements can generate multiple audit entries, and unobserved statements can create gaps. The role and object names outside `HR.EMPLOYEES` are example application objects. There is no version-matched Oracle 19c capture of this complete 22-column JSON export, so exact byte-level row fidelity and the nullability of every field in live deployments remain unverified.

## References

- [Oracle Database 19c `UNIFIED_AUDIT_TRAIL` column definitions](https://docs.oracle.com/en/database/oracle/oracle-database/19/refrn/UNIFIED_AUDIT_TRAIL.html)
- [Oracle Database 19c predefined unified audit policies](https://docs.oracle.com/en/database/oracle/oracle-database/19/dbseg/auditing-activities-predefined-unified-audit-policies.html)
- [Oracle Database 19c object audit policy syntax and examples](https://docs.oracle.com/en/database/oracle/oracle-database/19/dbseg/auditing-object-actions.html)
- [Oracle Database 19c example of a `LOGON`, `LOGOFF` policy](https://docs.oracle.com/en/database/oracle/oracle-database/19/dbseg/troubleshooting-for-audit.html)
- [Oracle Database 19c `CLIENT_PROGRAM_NAME` SQL*Plus example](https://docs.oracle.com/en/database/oracle/oracle-database/19/dvadm/database-vault-administrators-guide.pdf)

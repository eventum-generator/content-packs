# Oracle Database Unified Audit Trail

Synthetic rows shaped like a selected SQL result from Oracle Database `UNIFIED_AUDIT_TRAIL`. This pack models a database connector polling the view, not Oracle syslog.

## Event Types

| Action | Baseline frequency | Meaning |
| --- | ---: | --- |
| `SELECT` | 78% | Audited table read |
| `LOGON` | 18% | Successful session start |
| `UPDATE` | 4% | Audited data change |
| `LOGON` / `RETURN_CODE=1017` | Chain only | Invalid credentials |
| `GRANT` / `ROLE=DBA` | Chain only | Privileged role granted |

The FSM emits ordinary traffic, then periodically inserts the chain when enabled. Baseline percentages are synthetic workload assumptions, not a measured Oracle distribution.

## Anomaly Chain

Four failed `LOGON` rows for `FINANCE_DBA` from `wkst-091.corp.example` (`RETURN_CODE=1017`) precede a successful logon. The successful `SESSIONID` is reused for a `SELECT` on `FINANCE.PAYROLL` and `GRANT DBA TO REPORT_RO`; the `DBUSERNAME`, `USERHOST`, and timestamps link the steps. A rule can correlate failures followed by success and a privileged grant, or flag sensitive reads within that session. The failed attempts have their own session IDs, as they did not establish a session.

`anomaly_mode` defaults to `true`. Set it to `false` in `event.template.params` to generate only ordinary `LOGON`, `SELECT`, and `UPDATE` rows.

## Parameters

### Event Parameters

| Name | Default | Purpose |
| --- | --- | --- |
| `anomaly_mode` | `true` | Include the correlated chain |
| `database_id` | `3459081234` | Synthetic `DBID` |
| `target_user` | `FINANCE_DBA` | Account in the chain |
| `attacker_host` | `wkst-091.corp.example` | Client host in the chain |
| `grantee` | `REPORT_RO` | Account receiving the DBA role |

### Output Parameters

The shipped configuration writes `output/events.json` and requires no connection parameters or secrets. For a SIEM destination, replace the `file` output in a local copy with the chosen output plugin, using `${params.siem_host}` and `${secrets.siem_token}` placeholders for that plugin's endpoint and credentials.

## Usage

```bash
eventum generate --path generators/database-oracle-unified-audit/generator.yml --id oracle-unified-audit --live-mode false
eventum generate --path generators/database-oracle-unified-audit/generator.yml --id oracle-unified-audit --live-mode true
```

## Sample Output

This row was copied from a real generator run.

```json
{
  "ACTION_NAME": "GRANT",
  "AUDIT_TYPE": "Standard",
  "CLIENT_PROGRAM_NAME": "sqlplus",
  "CURRENT_USER": "FINANCE_DBA",
  "DBID": 3459081234,
  "DBUSERNAME": "FINANCE_DBA",
  "ENTRY_ID": 3,
  "EVENT_TIMESTAMP": "2026-09-25T12:20:07+00:00",
  "EVENT_TIMESTAMP_UTC": "2026-09-25T12:20:07+00:00",
  "INSTANCE_ID": 1,
  "OBJECT_NAME": null,
  "OBJECT_SCHEMA": null,
  "OS_USERNAME": "oracle-client",
  "RETURN_CODE": 0,
  "ROLE": "DBA",
  "SESSIONID": 262335,
  "SQL_BINDS": null,
  "SQL_TEXT": "GRANT DBA TO REPORT_RO",
  "STATEMENT_ID": 9067,
  "TARGET_USER": "REPORT_RO",
  "UNIFIED_AUDIT_POLICIES": "APP_ACCESS_AUDIT",
  "USERHOST": "wkst-091.corp.example"
}
```

## Coverage and Limits

The generator covers 22/22 selected Standard audit-row columns, including identifiers, action/result, client identity, object, SQL, and grant fields. The Oracle view also has many feature-specific columns for Database Vault, XS, RMAN, Data Pump, and other audit types; those are outside this Standard-row scope. Null columns remain null where an action does not populate them. `EVENT_TIMESTAMP` and `EVENT_TIMESTAMP_UTC` share UTC in this synthetic setup; a real connector's local timestamp rendering depends on the database session time zone. `UNIFIED_AUDIT_TRAIL` is populated only when unified auditing and relevant policies are enabled. The `UNIFIED_AUDIT_POLICIES` values here assume example policies are configured. The output is a native SQL row rather than ECS.

## References

- [Oracle Database 19c `UNIFIED_AUDIT_TRAIL` column reference](https://docs.oracle.com/en/database/oracle/oracle-database/19/refrn/UNIFIED_AUDIT_TRAIL.html)
- [Oracle Database audit trail administration](https://docs.oracle.com/en/database/oracle/oracle-database/21/dbseg/administering-the-audit-trail.html)

# MariaDB Audit Plugin Syslog

Eventum content pack for MariaDB Audit Plugin v1 SYSLOG CSV. Emits ECS JSON with the native source record in `event.original`. The native parsed fields are under the source namespace. Default mode includes background and a repeatable anomaly chain; `anomaly_mode: false` emits background only.

## Run

From the content-packs repository root:

```bash
eventum generate --path generators/database-mariadb-audit/generator.yml --id database-mariadb-audit --live-mode true
```

For a bounded local batch sample, run `timeout 3s eventum generate --path generators/database-mariadb-audit/generator.yml --id database-mariadb-audit-batch --live-mode false` (timeout exit code 124 is expected for this continuous source).

The file output is `generators/database-mariadb-audit/output/events.json`. Set `event.template.params.anomaly_mode: false` to generate only routine activity. The generator emits one event per input tick; timing depends on the Eventum input configuration.

## Events

| Native event | Meaning | Frequency | ECS category |
| --- | --- | --- | --- |
| `CONNECT` | Connection succeeded | 1 per routine session; 2 per chain | `authentication` |
| `FAILED_CONNECT` | Connection rejected | 3 per chain | `authentication` |
| `QUERY` | SQL statement audited | 1 per routine session; 2 per chain | `database` |
| `READ` | Table read audited | 1 per routine session; 1 per chain | `database` |
| `DISCONNECT` | Session ended | 1 per routine session; 1 per chain | `authentication` |

## Anomaly Chain

Three failed DBA logins, a successful login and GRANT SELECT, then a delegated user connects and reads payroll.salaries from the same source IP. Group by source.ip and a short time window; require three FAILED_CONNECT records for dba, then dba GRANT SELECT on payroll, then a separate audit_user connection and QUERY/READ of payroll.salaries. Use connectionid and queryid to avoid joining unrelated sessions.

Models the Audit Plugin v1 SYSLOG format with host as an address without :port, matching MariaDB versions before 12.0.1. MariaDB 12.0.1+ adds port information to host and changes TLS information in object for some events. The log requires server_audit_output_type=SYSLOG and CONNECT, QUERY, TABLE audit categories. A GRANT log records a successful statement, while the later delegated read is inferred from a separate audited session; audit output alone does not show the server permission table.

## Parameters

### Event Parameters

| Parameter | Default | Meaning |
| --- | --- | --- |
| `db_host` | `db-01.corp.example` | Server name |
| `db_ip` | `10.100.0.5` | Server address |
| `normal_user` | `app_user` | Background account |
| `normal_ip` | `10.100.1.20` | Background client address |
| `anomaly_user` | `dba` | Administrator in chain |
| `delegated_user` | `audit_user` | Account granted read access |
| `anomaly_ip` | `10.99.4.51` | Chain client address |
| `anomaly_interval_sessions` | `50` | Routine sessions between chains |
| `anomaly_mode` | `true` | Enable chain; false emits background only |

### Output Parameters

No top-level `${params.*}` or `${secrets.*}` placeholders are shipped. The file output works without credentials. To send to another destination, replace the `output` block with that plugin configuration and keep credentials in Eventum secrets.

## Sample output

This event was captured from an actual generator run with `anomaly_mode: true`:

```json
{
  "@timestamp": "2026-09-25T12:45:22+00:00",
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "grant-query",
    "category": [
      "iam",
      "database"
    ],
    "dataset": "mariadb.audit",
    "kind": "event",
    "original": "Sep 25 12:45:22 db-01.corp.example mysql-server_auditing: 20260925 12:45:22,db-01.corp.example,dba,10.99.4.51,1054,2050,QUERY,payroll,'GRANT SELECT ON payroll.* TO 'audit_user'@'%'',0",
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
    "syslog": {
      "appname": "mysql-server_auditing"
    }
  },
  "mariadb": {
    "audit": {
      "connectionid": 1054,
      "database": "payroll",
      "host": "10.99.4.51",
      "object": "'GRANT SELECT ON payroll.* TO 'audit_user'@'%''",
      "operation": "QUERY",
      "queryid": 2050,
      "retcode": 0,
      "serverhost": "db-01.corp.example",
      "username": "dba"
    }
  },
  "message": "20260925 12:45:22,db-01.corp.example,dba,10.99.4.51,1054,2050,QUERY,payroll,'GRANT SELECT ON payroll.* TO 'audit_user'@'%'',0",
  "observer": {
    "hostname": "db-01.corp.example",
    "ip": "10.100.0.5",
    "product": "MariaDB",
    "type": "database",
    "vendor": "MariaDB"
  },
  "related": {
    "ip": [
      "10.99.4.51"
    ],
    "user": [
      "dba"
    ]
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

## Format and references

The native SYSLOG record includes all 10 CSV fields in the vendor format (10/10); timestamp maps to @timestamp and the other fields to mariadb.audit. The syslog host and app name are also preserved.

Native SYSLOG prefix plus 10-field Audit Plugin CSV is retained in event.original. Connection ID links each successful session; QUERY and READ share query ID. Fifty table samples vary routine SQL and targets.

- [MariaDB Audit Plugin Log Format](https://mariadb.com/docs/server/reference/plugins/mariadb-audit-plugin/mariadb-audit-plugin-log-format)
- [MariaDB Audit Plugin Log Settings](https://mariadb.com/docs/server/reference/plugins/mariadb-audit-plugin/mariadb-audit-plugin-log-settings)
- [Kaspersky KUMA 4.2 supported sources](https://support.kaspersky.ru/kuma/4.2/255782)

# MySQL Enterprise Audit Log Generator

Produces realistic MySQL Enterprise Audit events (ECS-compatible JSON) matching the output of Filebeat / Elastic Agent with the `mysql_enterprise` integration. Events follow the MySQL Enterprise Audit Plugin JSON format covering all four audit classes: `audit`, `connection`, `general`, and `table_access`.

## Data Source

MySQL Enterprise Audit uses the MySQL Enterprise Audit Plugin to log server activity. When configured with `audit_log_format=JSON`, it produces structured JSON events covering connections, queries, table access, and administrative operations. The Elastic `mysql_enterprise` integration (Filebeat module) parses these into ECS-compatible fields under `mysqlenterprise.audit.*`.

## Event Types

| Template | Audit Class | Description | Chance Weight |
|---|---|---|---|
| query-select | general | SELECT queries | 300 |
| connect | connection | Successful client connection | 130 |
| disconnect | connection | Client disconnection | 120 |
| query-update | general | UPDATE statements | 100 |
| query-insert | general | INSERT statements | 80 |
| table-access-read | table_access | Table read access events | 80 |
| query-admin | general | Admin/monitoring commands (SHOW, FLUSH, OPTIMIZE) | 50 |
| table-access-write | table_access | Table write access (insert/update/delete) | 40 |
| query-error | general | Failed queries (syntax, permission, deadlock) | 27 |
| query-delete | general | DELETE statements | 25 |
| query-ddl | general | DDL: CREATE, ALTER, DROP (tables, indexes, views, procedures) | 20 |
| connect-failure | connection | Failed authentication attempts | 20 |
| query-grant | general | GRANT / REVOKE privilege changes | 8 |

## Correlation

- **Session tracking**: Connect events create session entries in shared state; DML/table_access templates pick random active sessions for consistent user/IP/connection context; disconnect pops a session.
- **Session cap**: Maximum 50 active sessions per host to prevent unbounded memory growth.
- **Monotonic counters**: Per-host event IDs and connection IDs increment across all templates.

## Parameters

| Parameter | Default | Description |
|---|---|---|
| `agent_version` | `8.17.0` | Filebeat/Elastic Agent version |

## Usage

```bash
# Live mode (continuous generation)
eventum generate --path generators/database-mysql-audit/generator.yml --id mysql --live-mode

# Sample mode (batch)
eventum generate --path generators/database-mysql-audit/generator.yml --id mysql --live-mode false
```

## Sample Output

```json
{
    "@timestamp": "2026-03-06T14:22:31.456789+00:00",
    "agent": {
        "ephemeral_id": "a1b2c3d4-e5f6-7890-abcd-ef0123456789",
        "id": "b3c4d5e6-f7a8-9012-bcde-f01234567891",
        "name": "mysql-prod-01",
        "type": "filebeat",
        "version": "8.17.0"
    },
    "client": {
        "domain": "app-server-01",
        "ip": "192.168.1.50",
        "port": 45678
    },
    "data_stream": {
        "dataset": "mysql_enterprise.audit",
        "namespace": "default",
        "type": "logs"
    },
    "ecs": { "version": "8.17.0" },
    "event": {
        "action": "mysql-query",
        "category": ["database"],
        "dataset": "mysql_enterprise.audit",
        "kind": "event",
        "module": "mysql_enterprise",
        "outcome": "success",
        "timezone": "+00:00",
        "type": ["access"]
    },
    "host": {
        "hostname": "mysql-prod-01",
        "ip": ["10.2.4.10"],
        "mac": ["02:42:0a:02:04:0a"],
        "name": "mysql-prod-01",
        "os": { "family": "linux", "full": "x86_64-Linux", "name": "Ubuntu 22.04.4 LTS", "type": "linux", "version": "5.15.0-91-generic" }
    },
    "mysqlenterprise": {
        "audit": {
            "account": { "host": "app-server-01", "user": "app_service" },
            "class": "general",
            "connection_id": "142",
            "general_data": {
                "command": "Query",
                "query": "SELECT * FROM `ecommerce`.`orders` WHERE `id` = ?",
                "sql_command": "select",
                "status": 0
            },
            "id": "1042",
            "login": { "ip": "192.168.1.50", "os": "", "proxy": "", "user": "app_service" },
            "query_statistics": {
                "bytes_received": 78,
                "bytes_sent": 4521,
                "query_time": 0.001234,
                "rows_examined": 1,
                "rows_sent": 1
            }
        }
    },
    "related": { "ip": ["192.168.1.50", "10.2.4.10"], "user": ["app_service"] },
    "server": { "user": { "name": "app_service" } },
    "service": { "id": "1", "type": "mysql_enterprise", "version": "8.0.36-commercial" },
    "source": { "address": "192.168.1.50", "ip": "192.168.1.50", "port": 45678 },
    "tags": ["mysql_enterprise-audit"],
    "user": { "name": "app_service" }
}
```

## Output Parameters

Output plugin configurations support `${params.*}` and `${secrets.*}` placeholders:

| Placeholder | Description |
|---|---|
| `${params.output_path}` | Custom output file path |
| `${secrets.es_password}` | Elasticsearch password (for elasticsearch output) |

## References

- [Elastic MySQL Enterprise integration](https://www.elastic.co/docs/reference/integrations/mysql_enterprise)
- [MySQL Enterprise Audit Plugin](https://dev.mysql.com/doc/refman/8.4/en/audit-log.html)
- [MySQL Audit Log File Formats (JSON)](https://dev.mysql.com/doc/refman/8.4/en/audit-log-file-formats.html)
- [Filebeat MySQL Enterprise module](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-module-mysqlenterprise)

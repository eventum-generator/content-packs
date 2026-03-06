# Microsoft SQL Server Audit Log Generator

Produces realistic Microsoft SQL Server audit events (ECS-compatible JSON) matching the output of Winlogbeat / Elastic Agent with the `microsoft_sqlserver` integration. All events use Windows Event ID **33205** from the SQL Server Audit subsystem.

## Data Source

SQL Server Audit captures server and database-level actions via the SQL Server Extended Events engine. Events are written to the Windows Security event log under event ID 33205 with provider `MSSQLSERVER$AUDIT`. The Elastic `microsoft_sqlserver` integration parses these into ECS-compatible fields under `sqlserver.audit.*`.

## Event Types

| Template | action_id | Description | Chance Weight |
|---|---|---|---|
| login-success | LGIS | Successful login | 150 |
| login-failure | LGIF | Failed login attempt | 25 |
| logout | LGO | Session disconnect | 140 |
| select | SL | SELECT query | 350 |
| insert | IN | INSERT statement | 80 |
| update | UP | UPDATE statement | 100 |
| delete | DL | DELETE statement | 30 |
| execute | EX | Stored procedure / function execution | 70 |
| schema-change | CR/AL/DR | DDL: CREATE, ALTER, DROP | 23 |
| permission-change | G/D/R | GRANT, DENY, REVOKE | 10 |
| backup | BA | Database backup | 15 |
| role-member-change | ADDP/DPRL | Add/drop role members | 3 |
| password-change | PWC | ALTER LOGIN password | 2 |
| dbcc | DBCC | DBCC maintenance commands | 2 |

## Correlation

- **Session tracking**: Login creates a session entry in shared state; DML/execute templates pick a random active session for consistent user/IP/app context; logout pops a session.
- **Session cap**: Maximum 50 active sessions per host to prevent unbounded memory growth.
- **Monotonic counters**: Per-host sequence numbers and transaction IDs increment across all templates.

## Parameters

| Parameter | Default | Description |
|---|---|---|
| `domain` | `CONTOSO` | Windows domain for Active Directory logins |
| `agent_version` | `8.17.0` | Winlogbeat agent version |

## Usage

```bash
# Live mode (continuous generation)
eventum generate --path generators/database-mssql-audit/generator.yml --id mssql --live-mode

# Sample mode (batch)
eventum generate --path generators/database-mssql-audit/generator.yml --id mssql --live-mode false
```

## Sample Output

```json
{
    "@timestamp": "2026-03-06T14:22:31.456789+00:00",
    "agent": {
        "ephemeral_id": "a1b2c3d4-e5f6-7890-abcd-ef0123456789",
        "id": "a1b2c3d4-e5f6-7890-abcd-ef0123456781",
        "name": "SQLPROD01",
        "type": "winlogbeat",
        "version": "8.17.0"
    },
    "ecs": { "version": "8.11.0" },
    "event": {
        "action": "database-select",
        "category": ["database"],
        "code": "33205",
        "dataset": "microsoft_sqlserver.audit",
        "kind": "event",
        "module": "microsoft_sqlserver",
        "outcome": "success",
        "sequence": 1042,
        "type": ["access"]
    },
    "host": {
        "hostname": "SQLPROD01",
        "ip": ["10.1.5.10"],
        "mac": ["00:50:56:a1:01:10"],
        "name": "SQLPROD01",
        "os": { "family": "windows", "name": "Windows Server 2022", "type": "windows", "version": "21H2" }
    },
    "related": { "ip": ["192.168.45.12", "10.1.5.10"], "user": ["api_service"] },
    "service": { "type": "microsoft_sqlserver" },
    "source": { "address": "192.168.45.12", "ip": "192.168.45.12", "port": 52431 },
    "sqlserver": {
        "audit": {
            "action_id": "SL",
            "additional_information": "",
            "application_name": ".Net SqlClient Data Provider",
            "class_type": "U",
            "client_ip": "192.168.45.12",
            "database_name": "SalesDB",
            "database_principal_name": "dbo",
            "host_name": "APPSRV01",
            "object_name": "Orders",
            "schema_name": "dbo",
            "sequence_number": 1042,
            "server_instance_name": "SQLPROD01\\MSSQLSERVER",
            "server_principal_name": "api_service",
            "session_id": 55,
            "statement": "SELECT * FROM [dbo].[Orders] WHERE [Id] = @P1",
            "succeeded": 1,
            "transaction_id": 100042
        }
    },
    "user": { "domain": "", "name": "api_service" },
    "winlog": { "channel": "Security", "event_id": "33205", "provider_name": "MSSQLSERVER$AUDIT" }
}
```

## References

- [Elastic microsoft_sqlserver integration](https://docs.elastic.co/integrations/microsoft_sqlserver)
- [SQL Server Audit (Database Engine)](https://learn.microsoft.com/en-us/sql/relational-databases/security/auditing/sql-server-audit-database-engine)
- [SQL Server Audit Action Groups and Actions](https://learn.microsoft.com/en-us/sql/relational-databases/security/auditing/sql-server-audit-action-groups-and-actions)

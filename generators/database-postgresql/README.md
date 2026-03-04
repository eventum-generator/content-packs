# PostgreSQL Audit Log Generator

Produces realistic PostgreSQL audit events matching the output of **Filebeat / Elastic Agent** with the PostgreSQL integration and **pgAudit** extension. Events follow the Elastic Common Schema (ECS) and can be ingested directly into OpenSearch or Elasticsearch.

## Event Types Covered

| Event Type | event.action | Frequency | Category |
|------------|-------------|-----------|----------|
| SELECT | `SELECT` | ~45% | database |
| INSERT | `INSERT` | ~15% | database |
| UPDATE | `UPDATE` | ~10% | database |
| DELETE | `DELETE` | ~3% | database |
| Connection | `connection_authorized` | ~10% | database, network |
| Disconnection | `disconnection` | ~8% | database, network |
| Auth Failure | `authentication_failure` | ~2% | database, authentication |
| DDL | `CREATE INDEX`, `ALTER TABLE`, ... | ~3% | database |
| Role | `GRANT`, `REVOKE`, `CREATE ROLE`, ... | ~2% | database, iam |
| Error | `error` | ~2% | database |

## Realism Features

- **Weighted event distribution** matching a production PostgreSQL server with pgAudit enabled
- **Correlated connections** — connection events create entries consumed by disconnection events with matching user/db/pid
- **6-host cluster** — primary, replicas, analytics, staging, dev servers with unique agent IDs and per-host OS metadata
- **15 database users** — superuser, application accounts, readonly/monitoring, admin, developer roles with matching app names
- **8 databases/schemas** — app_production (public, auth, billing), analytics_warehouse (public, reports), inventory_db, user_sessions, postgres
- **24 tables** — realistic e-commerce/analytics schema with weighted access patterns
- **Parameterized queries** — SELECT/INSERT/UPDATE/DELETE with prepared statement parameters ($1, $2, ...) matching pgAudit format
- **Query duration distribution** — sub-millisecond to seconds with realistic long-tail distribution
- **Authentication failures** — password failures, pg_hba.conf denials, nonexistent roles/databases with public IPs
- **DDL operations** — CREATE INDEX, ALTER TABLE, VACUUM, ANALYZE, REINDEX with realistic DBA patterns
- **Role management** — GRANT/REVOKE privileges, CREATE/ALTER/DROP ROLE operations
- **Database errors** — syntax errors, duplicate keys, foreign key violations, deadlocks, lock timeouts, query cancellations
- **pgAudit message format** — `AUDIT: SESSION,<id>,<subid>,<class>,<command>,<type>,<name>,<statement>,<params>`
- **Per-host sequence numbers** — sequential `event.sequence` scoped per hostname

## Parameters

### Event Parameters

Edit the `params` section under `event.template` in `generator.yml`:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `cluster_name` | `pg-prod-cluster` | PostgreSQL cluster name |
| `pg_version` | `16.4` | PostgreSQL version string |
| `agent_version` | `8.17.0` | Filebeat version string |

### Host Pool

Host identity (`hostname`, `agent_id`, IP, MAC) and OS metadata are defined per-host in `samples/hosts.csv` (6 hosts across 3 distros: Debian 12, Ubuntu 24.04, Rocky Linux 9). Edit the CSV to customize the fleet.

## Usage

```bash
# Install Eventum
uv tool install eventum-generator

# Run the generator
eventum generate \
  --path generators/database-postgresql/generator.yml \
  --id postgresql \
  --live-mode
```

### Adjusting Event Rate

Change the `count` in the input section:

```yaml
input:
  - cron:
      expression: "* * * * * *"
      count: 5    # 5 events/second (300/min, 18K/hour)
```

## Sample Output

### SELECT — Read Query

```json
{
    "@timestamp": "2026-03-04T10:15:42.123456+00:00",
    "event": {
        "action": "SELECT",
        "category": ["database"],
        "dataset": "postgresql.log",
        "duration": 3245000,
        "kind": "event",
        "module": "postgresql",
        "outcome": "success",
        "type": ["access"]
    },
    "message": "AUDIT: SESSION,42,1,READ,SELECT,,,SELECT id, email, name FROM public.users WHERE id = $1,{1042}",
    "postgresql": {
        "log": {
            "database": "app_production",
            "query": "SELECT id, email, name FROM public.users WHERE id = $1",
            "query_name": "SELECT"
        }
    },
    "user": { "name": "app_backend" },
    "source": { "ip": "10.1.3.22", "port": 45321 },
    "service": { "type": "postgresql" }
}
```

### Authentication Failure

```json
{
    "@timestamp": "2026-03-04T10:16:05.789012+00:00",
    "event": {
        "action": "authentication_failure",
        "category": ["database", "authentication"],
        "kind": "event",
        "module": "postgresql",
        "outcome": "failure",
        "type": ["connection", "denied"]
    },
    "log": { "level": "FATAL" },
    "message": "password authentication failed for user \"admin\"",
    "user": { "name": "admin" },
    "source": { "ip": "203.0.113.42", "port": 52134 },
    "service": { "type": "postgresql" }
}
```

## File Structure

```
database-postgresql/
  generator.yml                              # Pipeline configuration
  README.md                                  # This file
  templates/
    select.json.jinja                        # SELECT queries (pgaudit READ)
    insert.json.jinja                        # INSERT queries (pgaudit WRITE)
    update.json.jinja                        # UPDATE queries (pgaudit WRITE)
    delete.json.jinja                        # DELETE queries (pgaudit WRITE)
    connection.json.jinja                    # Connection authorized (correlated)
    disconnection.json.jinja                 # Disconnection (correlated)
    auth-failure.json.jinja                  # Authentication failures
    ddl.json.jinja                           # DDL operations (CREATE/ALTER/DROP)
    role.json.jinja                          # Role management (GRANT/REVOKE)
    error.json.jinja                         # Database errors (deadlocks, etc.)
  samples/
    hosts.csv                                # 6 PostgreSQL hosts (primary, replicas, etc.)
    users.csv                                # 15 database users with role types
    databases.json                           # 8 database/schema combinations
    tables.json                              # 24 tables with weighted access patterns
    queries.json                             # Parameterized query templates per DML type
```

## References

- [pgAudit — PostgreSQL Audit Extension](https://github.com/pgaudit/pgaudit)
- [Elastic PostgreSQL Integration](https://www.elastic.co/docs/reference/integrations/postgresql)
- [PostgreSQL CSV Log Format](https://www.postgresql.org/docs/current/runtime-config-logging.html#RUNTIME-CONFIG-LOGGING-CSVLOG)
- [Elastic Common Schema (ECS)](https://www.elastic.co/guide/en/ecs/current/index.html)
- [pgAudit Log Format](https://www.pgaudit.org/)

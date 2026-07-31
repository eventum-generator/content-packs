# SAP HANA Audit Trail Generator

Realistic synthetic [SAP HANA](https://www.sap.com/products/technology-platform/hana.html) audit trail events in ECS-compatible JSON. Output ingests directly into Elasticsearch or OpenSearch.

Every event carries the audit trail line SAP HANA itself writes, verbatim, in `message`, with the same values parsed out into ECS fields and `sap.hana.audit.*` alongside it — a parser can be developed against the raw line while dashboards and rules read the parsed one. The audited actions and the policies that report them follow the audit policy set SAP recommends in the HANA Security Guide, plus the site policies a production system adds for data access.

The modelled system is a single production tenant of an S/4HANA landscape: application servers, loaders and reporting tools connect as technical accounts, administrators connect from jump hosts, and the application schema holds the finance, sales, materials and HR tables an SAP installation actually has.

## Audit trail line

`message` holds the audit entry as the `SYSLOGPROTOCOL` trail target writes it — the target SAP recommends for production. Fields are separated by `;` and are never quoted or escaped, so a value containing a separator would shift every following position. The 38 positions:

| # | Field | # | Field |
|---|-------|---|-------|
| 1 | Event timestamp | 20 | Role name |
| 2 | Service name | 21 | Target principal |
| 3 | Host name | 22 | Action status |
| 4 | SID | 23 | Component |
| 5 | Instance number | 24 | Section |
| 6 | Port number | 25 | Parameter |
| 7 | Database name | 26 | Old value |
| 8 | Client IP address | 27 | New value |
| 9 | Client name | 28 | Comment |
| 10 | Client process ID | 29 | Executed statement |
| 11 | Client port number | 30 | Session ID |
| 12 | Policy name | 31 | Application user name |
| 13 | Audit level | 32 | Role schema name |
| 14 | Audit action | 33 | Grantee schema name |
| 15 | Session user | 34 | Origin database name |
| 16 | Target schema | 35 | Origin user name |
| 17 | Target object | 36 | XS application user name |
| 18 | Privilege name | 37 | Application name |
| 19 | Grantable | 38 | Statement user name |

Position 7 is written by the syslog target only; the `CSVTEXTFILE` target omits it and shifts positions 8 to 38 down by one. Positions 34 and 35 fill only for queries issued across tenant databases, and 36 and 39 onward only for XS Advanced events, so they stay empty here.

## Event types

52 distinct audit actions are produced, grouped by the template that renders them. Every one of them is an action SAP HANA audits: 48 are listed among the auditable actions of `CREATE AUDIT POLICY`, and the four audit-policy actions are the ones HANA always records itself under `MandatoryAuditPolicy` and therefore does not offer to user-defined policies.

| Template | Frequency | Audit actions | Policy | Level |
|----------|-----------|---------------|--------|-------|
| `data_read` | ~55% | `SELECT` | `Z_sensitive data access`, `Z_pii access`, `Z_catalog read` | INFO / WARNING |
| `auth_validate` | ~11% | `VALIDATE USER` | `_SAP_session validate` | ALERT |
| `session_connect` | ~9% | `CONNECT` (accepted) | `Z_session connect` | INFO |
| `data_change` | ~8% | `INSERT`, `UPDATE`, `DELETE` | `Z_sensitive data access`, `Z_pii access` | INFO / WARNING |
| `procedure_execute` | ~5% | `EXECUTE` | `Z_procedure execution`, `_SAP_designtime privileges` | INFO |
| `authorization_change` | ~4% | `GRANT PRIVILEGE`, `GRANT ROLE`, `REVOKE PRIVILEGE`, `REVOKE ROLE` | `_SAP_authorizations` | INFO |
| `user_admin` | ~3% | `CREATE`/`ALTER`/`DROP` of `USER`, `ROLE`, `USERGROUP` | `_SAP_user administration` | INFO |
| `session_denied` | ~2% | `CONNECT` (refused) | `_SAP_session connect` | ALERT |
| `config_change` | ~2% | `SYSTEM CONFIGURATION CHANGE`, `STOP SERVICE`, `SET`/`UNSET SYSTEM LICENSE` | `_SAP_configuration changes`, `_SAP_license addition`, `_SAP_license deletion` | INFO |
| `backup_recover` | ~1% | `BACKUP DATA`, `BACKUP CATALOG DELETE`, `RECOVER DATA` | `_SAP_recover database` | INFO |
| `audit_policy_change` | ~1% | `CREATE`/`ALTER`/`DROP AUDIT POLICY`, `ALTER SYSTEM CLEAR AUDIT LOG` | `MandatoryAuditPolicy` | CRITICAL |
| `security_object_change` | ~1% | PSE and certificate management, LDAP / SAML / JWT provider management, client-side encryption keys | `_SAP_certificates`, `_SAP_authentication provider`, `_SAP_clientside encryption` | INFO / CRITICAL |

Roughly 6% of events report `UNSUCCESSFUL`: refused logons, writes attempted by read-only reporting accounts, and grants and audit policy changes the acting account was not authorised to make. `_SAP_user administration` audits successful execution only, as SAP defines it, so no failure appears under that policy.

Audit levels map onto the syslog severities HANA writes them with: `EMERGENCY` 0, `ALERT` 1, `CRITICAL` 2, `WARNING` 4, `INFO` 6, carried in `event.severity` and `log.syslog.severity.*`.

## Realism

Events are picked by state machine rather than by chance, so the trail reads as activity rather than as independent draws.

- **Logon pairs** — a `VALIDATE USER` entry is followed by the `CONNECT` it authorises or by the refusal it causes. Both carry the same session ID, account and client, and a refusal names its reason (`authentication failed`, `user is locked`, `password has expired`, ...) in the comment position, where HANA reports it.
- **Sessions** — an accepted connection opens a session that later statements run inside, reusing its session ID, account, client host and process. Sessions retire once they have run long enough; the pools are bounded at 40 application and 8 administration sessions.
- **Account lockout** — invalid attempts accumulate per account and the sixth reports `user is locked`, matching HANA's default `maximum_invalid_connect_attempts`. A success clears the counter.
- **Who does what** — application servers and the Fiori and BW servers send prepared statements with `?` placeholders, loaders read column ranges by delta key, a person at HDB Studio reads whole rows with `TOP n`, and monitoring accounts read the `SYS` system views. Writes come from application and loader accounts; a write from a reporting account is audited and refused.
- **Application users** — the ABAP stack connects as one technical account and passes the business user through, so `sap.hana.audit.session_user` and `client.user.name` differ the way they do in a real S/4HANA system.
- **Data sensitivity drives the policy** — reads of the HR and password tables are reported by a separate policy at `WARNING`; everything else in the application schema at `INFO`.
- **Passwords are masked** — statements that set one are audited as `PASSWORD XXXXXXXXXXXXX`, as HANA masks them.
- **Configuration changes carry the previous value** — the component, section, parameter, old value and new value positions fill for `SYSTEM CONFIGURATION CHANGE`, including the changes that weaken a system: auditing switched off, the audit trail target moved, password lock time cut, TLS enforcement disabled.

### Intrusion arc

About 7% of events belong to a recurring six-phase story that one intruder walks from end to end while routine traffic keeps flowing around it:

| Phase | What appears in the trail |
|-------|---------------------------|
| Probe | Failed `VALIDATE USER` and refused `CONNECT` pairs from a host outside the managed ranges, one account per attempt — a spray, so no account reaches its lockout threshold |
| Breach | The `CONNECT` that the guessed credentials finally open: a legitimate account, an unmanaged source host, no application user |
| Escalate | `CREATE USER` for an account named to pass for a support account, then `GRANT ROLE` and `GRANT PRIVILEGE` of the roles and system privileges that hand over the database |
| Harvest | `SELECT * FROM` the HR, banking and password tables, without a predicate, from the same session |
| Cover | `ALTER AUDIT POLICY ... DISABLE` on the policies that recorded the previous two phases and `ALTER SYSTEM CLEAR AUDIT LOG` — reported at `CRITICAL` by `MandatoryAuditPolicy`, which cannot be switched off, and partly refused because the account never held audit administration |

Every phase is anchored to the same session ID, account and source address, so the whole sequence is reconstructible from `sap.hana.audit.session_id` or from `source.ip`. A phase advances only when an event belonging to it is emitted, so no step of the story is ever skipped.

## Parameters

### Event Parameters

Edit the `params` section under `event.template` in `generator.yml`:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `hana_sid` | `HDB` | System ID |
| `hana_instance` | `00` | Instance number |
| `hana_host` | `hana-prod-01.corp.local` | Fully qualified host name of the audited instance |
| `hana_ip` | `10.20.4.11` | Host address |
| `hana_port` | `30040` | Port of the service that reports the action |
| `hana_service` | `indexserver` | Service that reports the action |
| `tenant_db` | `HDB_PROD` | Tenant database name |
| `hana_version` | `2.00.077.00.1707118848` | Database version, reported in `service.version` |
| `hana_host_id` | `4f2c9a17be3d4e8f9c05a1d76b3e8420` | Machine ID of the host |
| `hana_mac` | `00-50-56-A1-3F-2C` | Host MAC address |
| `hana_os_version` | `15 SP5` | Operating system version |
| `hana_os_kernel` | `5.14.21-150500.55.83-default` | Kernel release |
| `backup_path` | `/hana/backup/HDB` | Directory manual backups are written to |
| `ecs_version` | `8.11.0` | ECS version reported in `ecs.version` |

Accounts, client hosts, database objects, privileges, roles and configuration parameters live under `samples/` — edit them to model your own landscape.

### Output Parameters

The shipped `generator.yml` writes to a local file, so it runs out of the box. To deliver events to a backend instead, edit the `output` section with `${params.*}` / `${secrets.*}` placeholders and supply their values via `--params`, `startup.yml`, or the keyring:

```yaml
# OpenSearch example
- opensearch:
    hosts:
      - ${params.opensearch_host}
    username: ${params.opensearch_user}
    password: ${secrets.opensearch_password}
    index: ${params.opensearch_index}
```

| Parameter | Description |
|-----------|-------------|
| `${params.opensearch_host}` | OpenSearch / Elasticsearch host URL |
| `${params.opensearch_user}` | Connection username |
| `${secrets.opensearch_password}` | Connection password (resolved from the keyring) |
| `${params.opensearch_index}` | Target index name |

## Usage

Requires Eventum 2.6.0 or newer — the generator filters sample rows with `where()`, which arrived in 2.6.

```bash
# Install Eventum
uv tool install eventum-generator

# Live mode — continuous stream at 5 events per second
eventum generate \
  --path generators/database-sap-hana/generator.yml \
  --id hana \
  --live-mode true

# Batch mode — generate as fast as possible until stopped
eventum generate \
  --path generators/database-sap-hana/generator.yml \
  --id hana \
  --live-mode false
```

Events are written to `output/events.json` inside the generator directory.

The intrusion arc needs a few hundred events to complete, and the first one starts early so that even a short run carries it. In live mode it takes about two minutes.

## Sample output

```json
{
    "@timestamp": "2026-07-31T09:18:35.225797+00:00",
    "client": {
        "user": { "name": "SUPPORT_L3" }
    },
    "ecs": {
        "version": "8.11.0"
    },
    "event": {
        "action": "grant_role",
        "category": ["iam"],
        "created": "2026-07-31T09:18:35.225797+00:00",
        "dataset": "sap_hana.audit",
        "ingested": "2026-07-31T09:18:36.060797+00:00",
        "kind": "event",
        "module": "sap_hana",
        "outcome": "success",
        "severity": 6,
        "timezone": "+00:00",
        "type": ["group", "change"]
    },
    "host": {
        "architecture": "x86_64",
        "containerized": false,
        "hostname": "hana-prod-01",
        "id": "4f2c9a17be3d4e8f9c05a1d76b3e8420",
        "ip": ["10.20.4.11"],
        "mac": ["00-50-56-A1-3F-2C"],
        "name": "hana-prod-01.corp.local",
        "os": {
            "family": "suse",
            "kernel": "5.14.21-150500.55.83-default",
            "name": "SLES",
            "platform": "sles",
            "type": "linux",
            "version": "15 SP5"
        }
    },
    "log": {
        "level": "info",
        "syslog": {
            "severity": { "code": 6, "name": "info" }
        }
    },
    "message": "2026-07-31T09:18:35.225797Z;indexserver;hana-prod-01.corp.local;HDB;00;30040;HDB_PROD;10.20.9.6;jump02.corp.local;13653;57962;_SAP_authorizations;INFO;GRANT ROLE;SUPPORT_L3;;;;GRANTABLE;Z_S4_HR_DISPLAY;Z_ETL_LOAD;SUCCESSFUL;;;;;;;GRANT \"Z_S4_HR_DISPLAY\" TO Z_ETL_LOAD WITH ADMIN OPTION;400018;SUPPORT_L3;_SYS_REPO;_SYS_REPO;;;;hdbsql;SUPPORT_L3",
    "process": {
        "name": "hdbsql",
        "pid": 13653
    },
    "related": {
        "hosts": ["hana-prod-01.corp.local", "jump02.corp.local"],
        "ip": ["10.20.9.6", "10.20.4.11"],
        "user": ["SUPPORT_L3", "Z_ETL_LOAD"]
    },
    "rule": {
        "name": "_SAP_authorizations",
        "ruleset": "SAP HANA audit policies"
    },
    "sap": {
        "hana": {
            "audit": {
                "action": "GRANT ROLE",
                "action_status": "SUCCESSFUL",
                "application_name": "hdbsql",
                "application_user_name": "SUPPORT_L3",
                "audit_level": "INFO",
                "database_name": "HDB_PROD",
                "grantable": "GRANTABLE",
                "grantee_schema_name": "_SYS_REPO",
                "instance_number": "00",
                "policy_name": "_SAP_authorizations",
                "port": 30040,
                "role_name": "Z_S4_HR_DISPLAY",
                "role_schema_name": "_SYS_REPO",
                "service_name": "indexserver",
                "session_id": 400018,
                "session_user": "SUPPORT_L3",
                "sid": "HDB",
                "statement_string": "GRANT \"Z_S4_HR_DISPLAY\" TO Z_ETL_LOAD WITH ADMIN OPTION",
                "statement_user_name": "SUPPORT_L3",
                "target_principal": "Z_ETL_LOAD"
            }
        }
    },
    "server": {
        "address": "hana-prod-01.corp.local",
        "domain": "corp.local",
        "port": 30040,
        "user": { "name": "SUPPORT_L3" }
    },
    "service": {
        "name": "indexserver",
        "type": "hana",
        "version": "2.00.077.00.1707118848"
    },
    "source": {
        "domain": "jump02.corp.local",
        "ip": "10.20.9.6",
        "port": 57962
    },
    "user": {
        "name": "SUPPORT_L3",
        "roles": ["Z_S4_HR_DISPLAY"],
        "target": { "name": "Z_ETL_LOAD" }
    }
}
```

## References

- [Audit Trail Layout for Trail Target CSV and SYSLOG](https://help.sap.com/docs/SAP_HANA_PLATFORM/b3ee5778bc2e4a089d3299b82ec762a7/0a57444d217649bf94a19c0b68b470cc.html) — the 38 positions of the trail line
- [Audit Policies](https://help.sap.com/docs/SAP_HANA_PLATFORM/b3ee5778bc2e4a089d3299b82ec762a7/db4b4fb4bb571014a22b8f893c94aeef.html) — audited actions, levels and action status
- [Audit Trails](https://help.sap.com/docs/SAP_HANA_PLATFORM/b3ee5778bc2e4a089d3299b82ec762a7/db560e7bbb57101490d4a1364440077f.html) — trail targets and why `SYSLOGPROTOCOL` is the production one
- [SAP HANA Security Guide](https://help.sap.com/doc/eec734dbb0fd1014a61590fcb5411390/2.0.08/en-US/SAP_HANA_Security_Guide_en.pdf) — the auditing chapter, including the actions audited by default and the recommended `_SAP_*` policy set this generator reports under
- [Elastic Common Schema (ECS)](https://www.elastic.co/guide/en/ecs/current/index.html) — no Elastic integration exists for SAP HANA, so the ECS mapping follows the schema itself and the shape Elastic uses for database audit trails

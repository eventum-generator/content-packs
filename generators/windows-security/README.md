# Windows Security Event Log Generator

Produces realistic Windows Security event log entries matching the output of **Winlogbeat / Elastic Agent**. Events follow the Elastic Common Schema (ECS) and can be ingested directly into OpenSearch or Elasticsearch.

## Event IDs Covered

| Event ID | Description | Frequency | Category |
|----------|-------------|-----------|----------|
| 4688 | Process Creation | ~25% | process |
| 4689 | Process Termination | ~25% | process |
| 4624 | Successful Logon | ~15% | authentication |
| 4634 | Logoff | ~14% | authentication |
| 4672 | Special Privileges Assigned | ~10% | iam |
| 4625 | Failed Logon | ~5% | authentication |
| 4648 | Explicit Credential Logon | ~3% | authentication |
| 4697 | Service Installed | rare | iam, configuration |
| 4720 | User Account Created | rare | iam |
| 4726 | User Account Deleted | rare | iam |
| 4732 | Member Added to Local Group | rare | iam |
| 1102 | Audit Log Cleared | rare | iam |

## Realism Features

- **Weighted event distribution** matching production Windows Server / Domain Controller traffic
- **Correlated sessions** — logon (4624) creates sessions consumed by logoff (4634)
- **Correlated processes** — creation (4688) tracked through termination (4689)
- **Realistic logon types** — Network (55%), Service (20%), RDP (8%), Interactive (5%), etc.
- **Authentication packages** — NTLM vs Kerberos distribution based on logon type
- **Failure codes** — 7 distinct Status/SubStatus pairs with realistic frequency
- **Process trees** — 30 real Windows processes with correct parent-child relationships
- **Monotonic record IDs** — sequential `winlog.record_id` across all events
- **Private IPs** for internal network logons, public IPs for brute-force attempts

## Parameters

### Event Parameters

Edit the `params` section under `event.template` in `generator.yml`:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `hostname` | `DC01` | Windows hostname |
| `domain` | `CONTOSO` | Active Directory domain (NetBIOS name) |
| `fqdn_suffix` | `contoso.local` | FQDN suffix appended to hostname |
| `domain_sid` | `S-1-5-21-3457937927-...` | Domain SID prefix for user SIDs |
| `agent_id` | `3cdc1e10-...` | Winlogbeat agent ID |
| `agent_version` | `8.17.0` | Winlogbeat version string |

### Output Parameters

Provide via `startup.yml` params/secrets (used by the OpenSearch output):

| Parameter | Variable | Description |
|-----------|----------|-------------|
| `opensearch_host` | `${params.opensearch_host}` | OpenSearch URL (e.g. `https://localhost:9200`) |
| `opensearch_user` | `${params.opensearch_user}` | OpenSearch username |
| `opensearch_password` | `${secrets.opensearch_password}` | OpenSearch password (stored in keyring) |
| `opensearch_index` | `${params.opensearch_index}` | Target index name (e.g. `winlogbeat-8.17.0`) |

## Usage

```bash
# Install Eventum
uv tool install eventum-generator

# Run with console output only (for testing)
eventum generate \
  --path generators/windows-security/generator.yml \
  --id winlog \
  --live-mode
```

### OpenSearch Configuration

The OpenSearch output uses `${params.*}` / `${secrets.*}` placeholders resolved from `startup.yml`:

```yaml
# startup.yml
- id: winlog
  path: windows-security
  params:
    opensearch_host: https://localhost:9200
    opensearch_user: admin
    opensearch_index: winlogbeat-8.17.0
```

Secrets (e.g. `opensearch_password`) are managed via the Eventum keyring. See [Eventum docs](https://eventum.run) for details.

### Adjusting Event Rate

Change the `count` in the input section:

```yaml
input:
  - cron:
      expression: "* * * * * *"
      count: 5    # 5 events/second (300/min, 18K/hour)
```

## Sample Output

### Event 4624 — Successful Logon

```json
{
    "@timestamp": "2026-02-21T12:00:01.234567+00:00",
    "event": {
        "action": "logged-in",
        "category": ["authentication"],
        "code": "4624",
        "kind": "event",
        "outcome": "success"
    },
    "user": {
        "domain": "CONTOSO",
        "id": "S-1-5-21-3457937927-2839227994-823803824-1234",
        "name": "jsmith"
    },
    "source": {
        "ip": "192.168.0.42",
        "port": 52431
    },
    "winlog": {
        "channel": "Security",
        "event_data": {
            "AuthenticationPackageName": "NTLM",
            "LogonType": "3",
            "TargetUserName": "jsmith"
        },
        "event_id": "4624",
        "keywords": ["Audit Success"],
        "logon": { "type": "Network" },
        "record_id": "1"
    }
}
```

## File Structure

```
windows-security/
  generator.yml                              # Pipeline configuration
  README.md                                  # This file
  templates/
    4624-logon-success.json.jinja            # Successful logon
    4625-logon-failure.json.jinja            # Failed logon
    4634-logoff.json.jinja                   # Logoff (correlates with 4624)
    4648-explicit-logon.json.jinja           # RunAs / explicit credentials
    4672-special-privileges.json.jinja       # Admin privilege assignment
    4688-process-created.json.jinja          # Process creation with cmdline
    4689-process-exited.json.jinja           # Process exit (correlates with 4688)
    4697-service-installed.json.jinja        # Service installation
    4720-user-created.json.jinja             # User account creation
    4726-user-deleted.json.jinja             # User account deletion
    4732-member-added-group.json.jinja       # Group membership change
    1102-audit-log-cleared.json.jinja        # Security log cleared
  samples/
    usernames.csv                            # 20 domain usernames
    workstations.csv                         # 15 workstation/server names
    processes.json                           # 30 process trees with parents
    services.json                            # 10 Windows services
```

## References

- [Microsoft Security Event Documentation](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-logon)
- [Elastic System Integration — Security](https://github.com/elastic/integrations/tree/main/packages/system/data_stream/security)
- [Elastic Common Schema (ECS)](https://www.elastic.co/guide/en/ecs/current/index.html)
- [Winlogbeat Reference](https://www.elastic.co/guide/en/beats/winlogbeat/current/index.html)

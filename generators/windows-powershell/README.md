# Windows PowerShell

Generates realistic Windows PowerShell event log entries matching the [Elastic Windows integration](https://github.com/elastic/integrations/tree/main/packages/windows) (`windows.powershell` and `windows.powershell_operational` datasets). Covers both the classic **Windows PowerShell** channel (engine lifecycle, provider starts, pipeline execution) and the modern **Microsoft-Windows-PowerShell/Operational** channel (script block logging, module logging, invocation tracking). Output is ECS-compatible JSON ready for ingestion into Elasticsearch, OpenSearch, or any SIEM.

## Event Types

| Event ID | Channel | Description | Frequency | ECS `event.type` |
|----------|---------|-------------|-----------|------------------|
| 4104 | Operational | Script Block Logging — captures executed script content | 30% | `info` |
| 4103 | Operational | Module Logging — cmdlet invocation with parameters | 30% | `info` |
| 400 | Classic | Engine State → Available (session start) | 8% | `start` |
| 403 | Classic | Engine State → Stopped (session stop) | 8% | `end` |
| 600 | Classic | Provider Started (FileSystem, Registry, etc.) | 8% | `info` |
| 800 | Classic | Pipeline Execution Details | 8% | `info` |
| 4105 | Operational | Script Block Invocation Start | 4% | `start` |
| 4106 | Operational | Script Block Invocation Stop | 4% | `end` |

## Realism Features

- **Session correlation**: Engine start (400) produces sessions consumed by engine stop (403); provider starts (600) and pipeline executions (800) reference active sessions
- **Script block correlation**: Script block logging (4104) produces block IDs referenced by invocation start/stop (4105/4106)
- **Suspicious content flagging**: ~15% of script blocks are flagged as `warning` level, matching PowerShell's `SuspiciousContentChecker` behavior for encoded commands, reflection APIs, and crypto operations
- **Multi-part script blocks**: Long scripts automatically split into multiple 4104 events with shared `ScriptBlockId`
- **Weighted command distribution**: 30 cmdlets and applications with realistic frequency weights (Get-Process, Get-Service dominate; Set-ExecutionPolicy is rare)
- **Weighted provider distribution**: FileSystem (35%), Registry (20%), Variable (15%), Function (10%), and others
- **Host application variety**: Weighted mix of `powershell.exe` (55%), `pwsh.exe` (20%), PSRemoting (15%), and ISE (10%) with realistic command-line flags
- **Command invocation details**: 4103 and 800 events include structured `CommandInvocation` and `ParameterBinding` entries
- **120-host fleet**: Each event is attributed to a random host from a pool of domain controllers, servers, and workstations with unique agent IDs
- **Per-host record IDs**: Sequential counter scoped per hostname (wraps at 2^31)
- **Per-host correlation pools**: Sessions and script blocks are tracked per host so engine start→stop and script block→invocation correlations stay within the same machine
- **Pool management**: Session and script block pools capped at 100 per host with graceful fallback when empty

## Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `domain` | `CONTOSO` | Active Directory domain name |
| `fqdn_suffix` | `contoso.local` | FQDN suffix (hostname.fqdn_suffix) |
| `domain_sid` | `S-1-5-21-3457937927-2839227994-823803824` | Domain SID prefix |
| `agent_version` | `8.17.0` | Winlogbeat/agent version |
| `powershell_version` | `5.1.22621.4111` | PowerShell host executable version |
| `engine_version` | `5.1.22621.4111` | PowerShell engine version |

### Host Pool

Host identity (`hostname`, `agent_id`, IP, MAC, role) is defined per-host in `samples/hosts.csv` (120 hosts). Each event randomly selects a host from the pool. Edit the CSV to customize the fleet.

## Output Parameters

When using `opensearch` or other remote output plugins, configure via `${params.*}` and `${secrets.*}`:

```yaml
output:
  - opensearch:
      hosts:
        - ${params.opensearch_host}
      username: ${params.opensearch_user}
      password: ${secrets.opensearch_password}
      index: ${params.opensearch_index}
```

## Usage

```bash
# Install Eventum
uv tool install eventum-generator

# Generate events (batch mode — generates as fast as possible)
eventum generate \
  --path generators/windows-powershell/generator.yml \
  --id pslog \
  --live-mode false

# Generate events (live mode — 5 events/second)
eventum generate \
  --path generators/windows-powershell/generator.yml \
  --id pslog \
  --live-mode true
```

### Adjusting Event Rate

Edit the `input` section in `generator.yml`:

```yaml
input:
  - cron:
      expression: "* * * * * *"
      count: 20    # 20 events per second
```

### Multi-generator Deployment

Add to `startup.yml` for use with `eventum run`:

```yaml
generators:
  windows-powershell:
    path: generators/windows-powershell/generator.yml
    params:
      domain: CORP
      fqdn_suffix: corp.example.com
```

## Sample Output

```json
{
  "@timestamp": "2026-02-22T17:04:03+00:00",
  "agent": {
    "ephemeral_id": "a47dbced-191e-4fbd-9bdd-0b1eca371282",
    "id": "3cdc1e10-ded0-4f5d-8434-ede1d1120b17",
    "name": "DC01.contoso.local",
    "type": "winlogbeat",
    "version": "8.17.0"
  },
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "category": ["process"],
    "code": "4104",
    "kind": "event",
    "module": "powershell",
    "provider": "Microsoft-Windows-PowerShell",
    "type": ["info"]
  },
  "host": {
    "name": "DC01",
    "os": {
      "family": "windows",
      "type": "windows"
    }
  },
  "log": {
    "level": "verbose"
  },
  "powershell": {
    "file": {
      "script_block_id": "948808fd-1769-434d-bd1c-197f6e69eedb",
      "script_block_text": "Restart-Service -Name Spooler -Force"
    },
    "sequence": 1,
    "total": 1
  },
  "related": {
    "user": ["mjohnson"]
  },
  "user": {
    "domain": "CONTOSO",
    "id": "S-1-5-21-3457937927-2839227994-823803824-9487",
    "name": "mjohnson"
  },
  "winlog": {
    "activity_id": "{1071bbe5-681f-40e0-938f-1df6197be525}",
    "channel": "Microsoft-Windows-PowerShell/Operational",
    "computer_name": "DC01.contoso.local",
    "event_id": "4104",
    "level": "verbose",
    "opcode": "Info",
    "process": {
      "pid": 2695,
      "thread": {
        "id": 4192
      }
    },
    "provider_guid": "{a0c1853b-5c40-4b15-8766-3cf1c58f985a}",
    "provider_name": "Microsoft-Windows-PowerShell",
    "record_id": "3",
    "task": "Execute a Remote Command",
    "time_created": "2026-02-22T17:04:03+00:00",
    "user": {
      "domain": "CONTOSO",
      "identifier": "S-1-5-21-3457937927-2839227994-823803824-9487",
      "name": "mjohnson",
      "type": "User"
    },
    "version": 1
  }
}
```

## File Structure

```
windows-powershell/
  generator.yml                              # Pipeline config
  README.md                                  # This file
  templates/
    400-engine-start.json.jinja              # Engine lifecycle start
    403-engine-stop.json.jinja               # Engine lifecycle stop
    600-provider-started.json.jinja          # Provider lifecycle
    800-pipeline-execution.json.jinja        # Pipeline execution details
    4103-module-logging.json.jinja           # Module/cmdlet logging
    4104-script-block.json.jinja             # Script block content
    4105-script-block-start.json.jinja       # Script block invocation start
    4106-script-block-stop.json.jinja        # Script block invocation stop
  samples/
    hosts.csv                                # 120 hosts (DCs, servers, workstations)
    scripts.json                             # PowerShell script blocks (benign + suspicious)
    commands.json                            # Cmdlets with parameters and weights
    usernames.csv                            # Domain user accounts
```

## References

- [Microsoft: about_Logging_Windows](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows)
- [Elastic Windows Integration](https://github.com/elastic/integrations/tree/main/packages/windows)
- [Elastic Winlogbeat PowerShell Module](https://www.elastic.co/guide/en/beats/winlogbeat/current/winlogbeat-module-powershell.html)
- [ECS Field Reference](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html)
- [MITRE ATT&CK T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/)

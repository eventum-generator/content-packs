# Zabbix Monitoring Generator

Generates synthetic Zabbix Server event data in ECS-compatible JSON format. Produces realistic monitoring events covering all five Zabbix event sources: trigger problems/recoveries, network discovery, active agent autoregistration, and internal state changes. Includes operator acknowledgment/update actions with correlated problem-recovery event chains via shared state.

## Event Types

| Event Type | Template | Frequency | Zabbix Source | ECS Category |
|-----------|----------|:---------:|:---:|---|
| Trigger Problem | `trigger-problem.json.jinja` | 40.0% | 0 | `host` |
| Trigger Recovery | `trigger-recovery.json.jinja` | 25.0% | 0 | `host` |
| Acknowledgment | `acknowledge.json.jinja` | 15.0% | 0 | `process` |
| Internal Event | `internal.json.jinja` | 10.0% | 3 | `host` |
| Discovery | `discovery.json.jinja` | 7.0% | 1 | `host`, `network` |
| Autoregistration | `autoregistration.json.jinja` | 3.0% | 2 | `host` |

## Realism Features

- **Problem-recovery correlation** — trigger problems are stored in a shared pool; recovery events pop from the pool to produce correlated problem-recovery pairs with matching trigger IDs and calculated durations
- **Monotonically increasing event IDs** — shared counter across all event types, mimicking Zabbix's sequential `eventid` assignment
- **15 trigger scenarios** — covering CPU, memory, disk, network, service availability, agent connectivity, MySQL, I/O wait, SSL certificates, temperature, swap, and process count thresholds
- **Weighted severity distribution** — trigger scenarios span all six Zabbix severity levels (Not classified through Disaster) with realistic expressions and operational data
- **Operator workflow simulation** — acknowledgment events model six action types (acknowledge, add message, change severity, close problem, suppress, unsuppress) with realistic comments
- **Internal event variety** — three subtypes: unsupported items (50%), unknown triggers (30%), failed LLD rules (20%), each with specific error messages
- **Network discovery scenarios** — eight scan configurations across Zabbix agent, ICMP ping, TCP port, and SNMPv2 checks with host up/down states
- **Autoregistration metadata** — new agents register with OS type, role metadata, TLS acceptance mode, and DNS resolution
- **20 monitored hosts** — Linux servers, Windows servers, workstations, and network devices across realistic host groups
- **ECS severity mapping** — Zabbix severity codes (0-5) mapped to ECS numeric severity scale (1-10)

## Parameters

### Event Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `zabbix_server` | `zabbix-srv01` | Zabbix server hostname |
| `zabbix_server_ip` | `10.1.0.5` | Zabbix server IP address |
| `zabbix_version` | `7.0.6` | Zabbix server version |
| `agent_version` | `7.0.6` | Default Zabbix agent version |

### Output Parameters

| Parameter | Description |
|-----------|-------------|
| `${params.output_path}` | Output file path |
| `${secrets.elasticsearch_password}` | Elasticsearch password (if using ES output) |

## Usage

```bash
# Generate 1000 events in sample mode
eventum generate --path generators/monitoring-zabbix/generator.yml --id test --live-mode false --batch.size 1000

# Run in live mode (5 events/sec)
eventum generate --path generators/monitoring-zabbix/generator.yml --id test --live-mode
```

## Sample Output

### Trigger Problem Event

```json
{
    "@timestamp": "2026-03-07T14:22:31.456Z",
    "event": {
        "kind": "alert",
        "module": "zabbix",
        "dataset": "zabbix.events",
        "category": ["host"],
        "type": ["info"],
        "severity": 8,
        "outcome": "success",
        "timezone": "UTC",
        "created": "2026-03-07T14:22:31.456Z"
    },
    "message": "High CPU utilization on SRV-WEB01",
    "observer": {
        "vendor": "Zabbix",
        "product": "Zabbix Server",
        "version": "7.0.6",
        "hostname": "zabbix-srv01",
        "ip": ["10.1.0.5"]
    },
    "zabbix": {
        "event": {
            "eventid": 5000042,
            "source": 0,
            "object": 0,
            "objectid": "13500",
            "value": 1,
            "acknowledged": false,
            "severity": 4,
            "severity_name": "High",
            "name": "High CPU utilization on SRV-WEB01",
            "opdata": "CPU: {ITEM.LASTVALUE1}%",
            "suppressed": false,
            "problem_duration": 0
        },
        "trigger": {
            "triggerid": "13500",
            "description": "High CPU utilization on {HOST.NAME}",
            "expression": "avg(/host/system.cpu.util,5m)>90",
            "priority": 4,
            "priority_name": "High",
            "status": "enabled",
            "value": 1,
            "tags": [{"tag": "scope", "value": "performance"}, {"tag": "component", "value": "cpu"}]
        },
        "host": {
            "hostid": "10084",
            "host": "SRV-WEB01",
            "host_group": "Linux servers/Web"
        },
        "item": {
            "name": "CPU utilization",
            "key_": "system.cpu.util"
        }
    },
    "host": {
        "hostname": "SRV-WEB01",
        "ip": ["10.1.2.20"],
        "os": {
            "name": "Linux",
            "version": "Ubuntu 22.04"
        }
    },
    "agent": {
        "type": "zabbix-agent",
        "version": "7.0.6"
    },
    "related": {
        "hosts": ["SRV-WEB01"],
        "ip": ["10.1.2.20"]
    }
}
```

## References

- [Zabbix Event Object API](https://www.zabbix.com/documentation/current/en/manual/api/reference/event/object) — event fields and enumerations
- [Zabbix Trigger Severity](https://www.zabbix.com/documentation/current/en/manual/config/triggers/severity) — severity levels
- [Zabbix Event Sources](https://www.zabbix.com/documentation/current/en/manual/config/events/sources) — trigger, discovery, autoregistration, internal, service
- [Elastic Common Schema](https://www.elastic.co/guide/en/ecs/current/index.html) — ECS field reference

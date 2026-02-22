# Network Firewall Event Generator

Produces realistic network firewall events (ECS-compatible JSON) matching the field structure used by Elastic integrations for firewall data. Events cover traffic flow decisions, session lifecycle, NAT translations, IDS/IPS threat detections, and system operational events. Vendor-agnostic — usable with any SIEM pipeline that expects ECS-normalized firewall data.

## Event Types Covered

| Event Type | Description | Frequency | ECS Category |
|------------|-------------|-----------|--------------|
| Traffic Allowed | Permitted connection through firewall | ~53% | network |
| Traffic Denied | Connection rejected with RST/ICMP unreachable | ~13% | network |
| Traffic Dropped | Connection silently dropped (default deny) | ~9% | network |
| Session Start | Stateful session establishment | ~11% | network |
| Session End | Session teardown with byte/packet counters | ~10% | network |
| NAT Translation | Source/destination NAT event | ~3% | network |
| Threat Detected | IDS/IPS signature match (alert/block) | ~1% | network, intrusion_detection |
| System Event | Device operational events (config, HA, auth) | rare | configuration, host |

## Realism Features

- **Weighted traffic distribution** matching enterprise perimeter firewall patterns
- **Correlated sessions** — session-start events are consumed by session-end with matching 5-tuple
- **NAT tracking** — outbound sessions carry source NAT details through session lifecycle
- **Zone-aware routing** — trust/untrust/dmz zones with correct interface mappings per direction
- **Direction-specific behavior** — denied/dropped traffic is predominantly inbound; allowed is mostly outbound
- **Service port distribution** — HTTPS (40%), HTTP (15%), DNS (10%), SSH (5%), etc.
- **IDS/IPS threats** — 15 realistic signatures across SQL injection, brute force, C2, exploits
- **ICMP handling** — dropped traffic includes ICMP with realistic type distribution
- **Session end reasons** — tcp-fin (50%), aged-out (20%), tcp-rst (25%), policy-deny (5%)
- **System events** — HA heartbeats, config commits, admin logins, disk/session warnings
- **Community ID** — per-flow identifier for cross-event correlation

## Parameters

### Event Parameters

Edit the `params` section under `event.template` in `generator.yml`:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `hostname` | `fw-01` | Firewall hostname |
| `domain` | `example.com` | Domain for FQDN construction |
| `serial_number` | `FW00A1B2C3D4` | Firewall serial number |
| `nat_ip` | `198.51.100.1` | Public NAT IP for SNAT/DNAT |
| `agent_id` | `e4f8c1a2-...` | Filebeat agent ID |
| `agent_version` | `8.17.0` | Filebeat version string |

## Usage

```bash
# Install Eventum
uv tool install eventum-generator

# Run the generator
eventum generate \
  --path generators/network-firewall/generator.yml \
  --id fw \
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

### Traffic Allowed

```json
{
    "@timestamp": "2026-02-21T12:00:01.234567+00:00",
    "event": {
        "action": "allow",
        "category": ["network"],
        "dataset": "firewall.traffic",
        "kind": "event",
        "outcome": "success",
        "type": ["connection", "allowed"]
    },
    "source": {
        "bytes": 12345,
        "ip": "10.1.1.30",
        "packets": 20,
        "port": 52341
    },
    "destination": {
        "bytes": 42000,
        "ip": "142.250.80.46",
        "packets": 22,
        "port": 443
    },
    "network": {
        "application": "ssl",
        "bytes": 54345,
        "community_id": "1:a1b2c3d4e5f6a7b8c9d0",
        "direction": "outbound",
        "packets": 42,
        "transport": "tcp",
        "type": "ipv4"
    },
    "observer": {
        "hostname": "fw-01",
        "type": "firewall",
        "vendor": "Generic",
        "ingress": {"zone": "trust"},
        "egress": {"zone": "untrust"}
    },
    "rule": {
        "id": "1001",
        "name": "Allow-HTTPS-Out"
    }
}
```

## File Structure

```
network-firewall/
  generator.yml                              # Pipeline configuration
  README.md                                  # This file
  templates/
    traffic-allowed.json.jinja               # Permitted traffic (53%)
    traffic-denied.json.jinja                # Denied with RST/unreachable (13%)
    traffic-dropped.json.jinja               # Silently dropped — default deny (9%)
    session-start.json.jinja                 # Session establishment (11%)
    session-end.json.jinja                   # Session teardown (correlates with start)
    nat-translation.json.jinja               # Source/destination NAT events (3%)
    threat-detected.json.jinja               # IDS/IPS alerts and blocks (1%)
    system-event.json.jinja                  # Device operational events (rare)
  samples/
    internal_hosts.csv                       # 25 internal hosts (workstations, servers, DMZ)
    firewall_rules.json                      # 15 firewall rules (allow + deny + default-deny)
    network_services.json                    # 24 services with port/protocol/application
    threat_signatures.json                   # 15 IDS/IPS threat signatures
```

## References

- [Elastic Common Schema — Network Events](https://www.elastic.co/guide/en/ecs/current/ecs-mapping-network-events.html)
- [ECS Event Categorization](https://www.elastic.co/guide/en/ecs/8.17/ecs-using-the-categorization-fields.html)
- [Elastic PANW Integration](https://github.com/elastic/integrations/tree/main/packages/panw)
- [Elastic Cisco ASA Integration](https://github.com/elastic/integrations/tree/main/packages/cisco_asa)
- [ECS Observer Fields](https://www.elastic.co/guide/en/ecs/current/ecs-observer.html)
- [Community ID Specification](https://github.com/corelight/community-id-spec)

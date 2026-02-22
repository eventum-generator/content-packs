# Check Point Security Gateway

Generates realistic Check Point Security Gateway logs in ECS-compatible JSON format, matching the [Elastic Check Point integration](https://docs.elastic.co/integrations/checkpoint) (`checkpoint.firewall` data stream). Covers 8 software blades with 11 event types and realistic traffic distributions.

## Event Types

| Event Type | Blade / Product | Frequency | ECS Category |
|---|---|---|---|
| Firewall Accept | `VPN-1 & FireWall-1` | ~55% | `network` / `allowed` |
| Firewall Drop | `VPN-1 & FireWall-1` | ~20% | `network` / `denied` |
| Firewall Reject | `VPN-1 & FireWall-1` | ~3% | `network` / `denied` |
| Application Control | `Application Control` | ~6% | `network` |
| URL Filtering | `URL Filtering` | ~5% | `network` |
| IPS Detect | `SmartDefense` | ~3% | `network`, `intrusion_detection` |
| IPS Prevent | `SmartDefense` | ~1.5% | `network`, `intrusion_detection` |
| VPN | `VPN-1 & FireWall-1` | ~3% | `network` |
| Anti-Bot | `Anti Malware` | ~1.5% | `network`, `malware` |
| Anti-Virus | `New Anti Virus` | ~1% | `network`, `malware` |
| Identity Awareness | `Identity Awareness` | ~1% | `authentication` |

## Realism Features

- **Zone-aware routing** — Internal→External (outbound), External→DMZ (inbound), Internal→Internal (east-west) with appropriate interface assignment
- **NAT translation** — Source NAT for outbound traffic (70% of accepted outbound connections)
- **Rule matching** — 15 named firewall rules with UUIDs, layer hierarchy, and weighted selection
- **Service distribution** — HTTPS-dominant (40%), HTTP (15%), DNS (12%), and 20+ other services
- **IPS signatures** — 15 real-world attack signatures with CVE references, severity, and confidence levels
- **Application identification** — 16 applications with risk scores (0–5) and risk-based allow/block decisions
- **URL categorization** — 15 categories including blocked (gambling, malware, phishing) with real domain examples
- **Malware detection** — 12 signatures across Anti-Bot (C&C, botnet) and Anti-Virus (trojans, ransomware, exploits)
- **VPN correlation** — Encrypt/Decrypt events reference active sessions from the firewall accept pool
- **Identity mapping** — Login/logout/update events with AD Query, Captive Portal, RADIUS, and Identity Agent sources
- **Check Point metadata** — Realistic `loguid`, `sequencenum`, `origin_sic_name`, layer UUIDs, and policy tags
- **Monotonic counters** — Shared sequence number across all blade types

## Parameters

### Event Parameters

Edit in `generator.yml` under `event.template.params`:

| Parameter | Default | Description |
|---|---|---|
| `hostname` | `cpgw-01` | Security Gateway hostname |
| `domain` | `example.com` | Domain name |
| `gateway_ip` | `192.168.10.1` | Gateway management IP |
| `nat_ip` | `198.51.100.1` | Public NAT IP address |
| `agent_id` | `7b2c5f1a-...` | Filebeat agent UUID |
| `agent_version` | `8.17.0` | Filebeat agent version |
| `ips_profile` | `Optimized` | SmartDefense/IPS profile name |

## Usage

### Install Eventum

```bash
uv tool install eventum-generator
```

### Run Generator

```bash
eventum generate \
  --path generators/network-checkpoint/generator.yml \
  --id checkpoint-gw \
  --live-mode
```

### Adjust Event Rate

Change `count` in the input section of `generator.yml`:

```yaml
input:
  - cron:
      expression: "* * * * * *"
      count: 10  # 10 events/second
```

## Sample Output

### Firewall Accept Event

```json
{
  "@timestamp": "2026-02-21T14:30:15.000000+00:00",
  "agent": {
    "ephemeral_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "id": "7b2c5f1a-8e3d-4a9b-b6f0-1c2d3e4f5a6b",
    "name": "cpgw-01.example.com",
    "type": "filebeat",
    "version": "8.17.0"
  },
  "checkpoint": {
    "flags": "417028",
    "ifdir": "outbound",
    "ifname": "eth0",
    "logid": "0",
    "loguid": "{0x67b8a3c7,0xa,0x3f8e2b1c,0xc9d4e5f6}",
    "match_id": "1",
    "origin": "192.168.10.1",
    "origin_sic_name": "cn=cp_mgmt,o=cpgw-01.example.com",
    "parent_rule": "0",
    "rule": "1",
    "rule_action": "Accept",
    "rule_uid": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "sequencenum": 42,
    "version": "5",
    "layer_name": "Network",
    "layer_uuid": "c0264a80-1832-4fce-8a90-d0849dc4ba33",
    "xlatesrc": "198.51.100.1",
    "xlatedst": "0.0.0.0",
    "xlatesport": 35421,
    "xlatedport": 0,
    "nat_rulenum": 1
  },
  "destination": {
    "ip": "93.184.216.34",
    "port": 443
  },
  "ecs": { "version": "8.17.0" },
  "event": {
    "action": "Accept",
    "category": ["network"],
    "dataset": "checkpoint.firewall",
    "duration": 45000000000,
    "kind": "event",
    "module": "checkpoint",
    "outcome": "success",
    "sequence": 42,
    "type": ["allowed", "connection"]
  },
  "host": { "hostname": "cpgw-01" },
  "network": {
    "application": "https",
    "bytes": 1284750,
    "direction": "outbound",
    "iana_number": "6",
    "name": "Network",
    "packets": 892,
    "transport": "tcp"
  },
  "observer": {
    "egress": { "interface": { "name": "eth1" }, "zone": "External" },
    "ingress": { "interface": { "name": "eth0" }, "zone": "Internal" },
    "name": "192.168.10.1",
    "product": "VPN-1 & FireWall-1",
    "type": "firewall",
    "vendor": "Checkpoint"
  },
  "related": { "ip": ["10.1.1.30", "93.184.216.34", "198.51.100.1"] },
  "rule": {
    "id": "1",
    "name": "Allow Outbound HTTPS",
    "uuid": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
  },
  "source": {
    "bytes": 84750,
    "ip": "10.1.1.30",
    "nat": { "ip": "198.51.100.1", "port": 35421 },
    "packets": 342,
    "port": 52481
  },
  "tags": ["checkpoint", "forwarded"]
}
```

## File Structure

```
generators/network-checkpoint/
  generator.yml                              # Pipeline configuration
  README.md                                  # This file
  templates/
    firewall-accept.json.jinja               # Firewall Accept events
    firewall-drop.json.jinja                 # Firewall Drop events
    firewall-reject.json.jinja               # Firewall Reject events
    application-control.json.jinja           # Application Control events
    url-filtering.json.jinja                 # URL Filtering events
    ips-detect.json.jinja                    # IPS Detection alerts
    ips-prevent.json.jinja                   # IPS Prevention alerts
    vpn.json.jinja                           # VPN Encrypt/Decrypt/Key Install
    anti-bot.json.jinja                      # Anti-Bot detection events
    anti-virus.json.jinja                    # Anti-Virus detection events
    identity-awareness.json.jinja            # Identity Awareness login/logout
  samples/
    internal_hosts.csv                       # 25 internal hosts (workstations, servers, DMZ)
    firewall_rules.json                      # 15 firewall rules (10 allow, 4 deny, 1 cleanup)
    network_services.json                    # 22 network services with port/protocol/weight
    ips_signatures.json                      # 15 IPS signatures with CVE references
    applications.json                        # 16 applications with risk scores
    url_categories.json                      # 15 URL categories (10 allowed, 5 blocked)
    malware_signatures.json                  # 12 malware signatures (6 Anti-Bot, 6 Anti-Virus)
    users.csv                                # 15 corporate users with department/role
```

## References

- [Check Point R81 Log Exporter Documentation](https://sc1.checkpoint.com/documents/R81/WebAdminGuides/EN/CP_R81_LoggingAndMonitoring_AdminGuide/Topics-LMG/Log-Exporter.htm)
- [Check Point Log Field Reference (SK144192)](https://support.checkpoint.com/results/sk/sk144192)
- [Elastic Check Point Integration](https://docs.elastic.co/integrations/checkpoint)
- [Elastic Check Point Integration — GitHub](https://github.com/elastic/integrations/tree/main/packages/checkpoint)
- [Check Point CEF Field Mappings](https://community.checkpoint.com/t5/Management/Log-Exporter-CEF-Field-Mappings/td-p/41060)

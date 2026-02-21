# Cisco ASA Firewall

Generates realistic Cisco ASA (Adaptive Security Appliance) syslog events as ECS-compatible JSON, matching the field structure used by the [Elastic Cisco ASA integration](https://docs.elastic.co/integrations/cisco_asa).

Cisco ASA is one of the most widely deployed enterprise firewalls. It sends logs via syslog in the format `%ASA-severity-message_id: message_text`. This generator covers the most common message types: connection tracking (built/teardown), ACL permit/deny, NAT translations, VPN sessions, authentication, SSL handshakes, and system operations.

## Event Types

| Template | Message IDs | Category | Frequency | Description |
|----------|-------------|----------|-----------|-------------|
| TCP Built | 302013 | Connection | ~25% | New TCP connection established |
| TCP Teardown | 302014 | Connection | ~24% | TCP connection closed with duration/bytes |
| UDP Built | 302015 | Connection | ~8% | New UDP connection established |
| UDP Teardown | 302016 | Connection | ~8% | UDP connection closed |
| ICMP Built | 302020 | Connection | ~2% | New ICMP connection |
| ICMP Teardown | 302021 | Connection | ~2% | ICMP connection closed |
| ACL Hit | 106100 | Firewall | ~13% | ACL permit/deny with hit count |
| ACL Deny | 106023 | Firewall | ~7% | Traffic denied by access group |
| NAT Built | 305011 | NAT | ~3% | Dynamic/static NAT translation created |
| NAT Teardown | 305012 | NAT | ~3% | NAT translation removed |
| Authentication | 113004/113005/113012/611101/611102 | Auth | ~3% | AAA authentication success/failure |
| VPN | 722022/722023/722033/722037/722051 | VPN | ~3% | AnyConnect SVC session lifecycle |
| SSL | 725001/725002/725007 | SSL | ~2% | SSL/TLS handshake start/complete/terminate |
| System | 199005/111009/111010 | System | ~1% | Configuration changes, command execution |

## Realism Features

- **Correlated connection pairs**: TCP/UDP/ICMP built events push to shared state pools; teardown events consume from them with matching connection IDs, interfaces, and addresses
- **NAT correlation**: NAT built/teardown events use shared state for consistent address mapping
- **VPN session tracking**: VPN connect events store sessions consumed by disconnect events
- **Weighted event distribution**: Event type frequency, service port distribution, direction ratios, and teardown reasons all use realistic production weights
- **ASA-specific message format**: `event.original` contains the full syslog line matching real ASA output
- **Realistic connection metrics**: Duration and byte counts follow production-like distributions (sub-second DNS, long VPN tunnels)
- **TCP teardown reasons**: Weighted distribution of FINs (50%), Reset-I (15%), Reset-O (10%), Idle Timeout (20%), SYN Timeout (5%)
- **NAT address mapping**: Outbound connections use configurable NAT IP with realistic port mapping
- **ACL hit counts**: Mix of first-hit and interval-based hit counting matching real ACL logging behavior
- **Multi-event authentication**: Covers both remote AAA (113004/113005) and local database (113012) authentication
- **TLS version distribution**: TLSv1.2/1.3 weighted selection for SSL handshake events

## Parameters

### Event Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `hostname` | `ASA-FW-01` | ASA device hostname (appears in syslog and `observer.hostname`) |
| `domain` | `example.com` | Domain name |
| `nat_ip` | `198.51.100.1` | Public NAT IP for outbound connections |
| `agent_id` | `a3b7e2c1-...` | Elastic Agent ID |
| `agent_version` | `8.17.0` | Elastic Agent version |

### Output Parameters

| Parameter | Variable | Description |
|-----------|----------|-------------|
| OpenSearch host | `${params.opensearch_host}` | OpenSearch cluster URL |
| OpenSearch user | `${params.opensearch_user}` | OpenSearch username |
| OpenSearch password | `${secrets.opensearch_password}` | OpenSearch password (from keyring) |
| OpenSearch index | `${params.opensearch_index}` | Target index name |

## Usage

```bash
# Live mode — 5 events/second continuous stream
eventum generate \
  --path generators/network-cisco-asa/generator.yml \
  --id asa \
  --live-mode

# Sample mode — generate a batch and exit
eventum generate \
  --path generators/network-cisco-asa/generator.yml \
  --id asa \
  --no-live-mode
```

### OpenSearch Output

Add to your `startup.yml`:

```yaml
generators:
  - id: cisco-asa
    path: generators/network-cisco-asa/generator.yml
    params:
      hostname: EDGE-FW-01
      nat_ip: "203.0.113.1"
      opensearch_host: "https://opensearch:9200"
      opensearch_user: admin
      opensearch_index: logs-cisco_asa.log-default
```

## Sample Output

```json
{
  "@timestamp": "2026-02-21T14:30:15.000000+00:00",
  "cisco": {
    "asa": {
      "connection_id": "100042",
      "destination_interface": "outside",
      "mapped_destination_ip": "93.184.216.34",
      "mapped_destination_port": 443,
      "mapped_source_ip": "198.51.100.1",
      "mapped_source_port": 34521,
      "message_id": "302013",
      "source_interface": "inside"
    }
  },
  "destination": {
    "address": "93.184.216.34",
    "ip": "93.184.216.34",
    "port": 443
  },
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "flow-creation",
    "category": ["network"],
    "code": "302013",
    "dataset": "cisco_asa.log",
    "kind": "event",
    "module": "cisco_asa",
    "original": "Feb 21 2026 14:30:15 ASA-FW-01 : %ASA-6-302013: Built outbound TCP connection 100042 for inside:10.1.1.30/52847 (198.51.100.1/34521) to outside:93.184.216.34/443 (93.184.216.34/443)",
    "outcome": "success",
    "severity": 6,
    "type": ["connection", "start"]
  },
  "log": {
    "level": "informational"
  },
  "network": {
    "direction": "outbound",
    "iana_number": "6",
    "transport": "tcp"
  },
  "observer": {
    "egress": {
      "interface": {
        "name": "outside"
      }
    },
    "hostname": "ASA-FW-01",
    "ingress": {
      "interface": {
        "name": "inside"
      }
    },
    "product": "asa",
    "type": "firewall",
    "vendor": "Cisco"
  },
  "related": {
    "ip": ["10.1.1.30", "93.184.216.34", "198.51.100.1"]
  },
  "source": {
    "address": "10.1.1.30",
    "ip": "10.1.1.30",
    "port": 52847
  },
  "tags": ["cisco-asa", "forwarded"]
}
```

## File Structure

```
network-cisco-asa/
  generator.yml                           # Pipeline configuration
  README.md                               # This file
  templates/
    302013-tcp-built.json.jinja           # TCP connection built
    302014-tcp-teardown.json.jinja        # TCP connection teardown
    302015-udp-built.json.jinja           # UDP connection built
    302016-udp-teardown.json.jinja        # UDP connection teardown
    302020-icmp-built.json.jinja          # ICMP connection built
    302021-icmp-teardown.json.jinja       # ICMP connection teardown
    106100-acl-hit.json.jinja             # ACL permit/deny with hit count
    106023-acl-deny.json.jinja            # Deny by access group
    305011-nat-built.json.jinja           # NAT translation created
    305012-nat-teardown.json.jinja        # NAT translation removed
    113-auth.json.jinja                   # Authentication events
    722-vpn.json.jinja                    # VPN/AnyConnect session events
    725-ssl.json.jinja                    # SSL/TLS handshake events
    system.json.jinja                     # System/configuration events
  samples/
    internal_hosts.csv                    # Workstations, servers, DMZ hosts
    acl_rules.json                        # ACL rules with zones and weights
    network_services.json                 # Service ports and protocols
    vpn_users.csv                         # VPN user accounts
    vpn_groups.json                       # VPN group policies
```

## References

- [Cisco ASA Syslog Messages](https://www.cisco.com/c/en/us/td/docs/security/asa/syslog/asa-syslog.html)
- [Elastic Cisco ASA Integration](https://docs.elastic.co/integrations/cisco_asa)
- [Elastic Integrations — cisco_asa package](https://github.com/elastic/integrations/tree/main/packages/cisco_asa)
- [Cisco ASA Configuration Guide — Logging](https://www.cisco.com/c/en/us/td/docs/security/asa/asa923/configuration/general/asa-923-general-config/monitor-syslog.html)

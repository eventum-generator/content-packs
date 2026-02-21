# Fortinet FortiGate

Generates realistic Fortinet FortiGate firewall events in ECS-compatible JSON, matching the [Elastic `fortinet_fortigate` integration](https://www.elastic.co/docs/reference/integrations/fortinet_fortigate) field structure. Events cover the full FortiGate log taxonomy: traffic forwarding (allow/deny), UTM security modules (web filter, IPS, application control, DNS filter, antivirus, anomaly detection), and operational events (system administration, VPN tunnels, user authentication).

## Event Types

| Event Type | FortiGate Type/Subtype | Log ID | Frequency | ECS Category |
|------------|----------------------|--------|-----------|-------------|
| Traffic Forward (close) | traffic/forward | 0000000013 | ~46% | network |
| Traffic Forward (deny) | traffic/forward | 0000000013 | ~15% | network |
| Traffic Local | traffic/local | 0001000014 | ~5% | network |
| UTM App Control | utm/app-ctrl | 1059028704 | ~6% | network |
| UTM Web Filter | utm/webfilter | 0316013056 | ~5% | network |
| UTM DNS | utm/dns | 1501054600 | ~5% | network |
| UTM IPS | utm/ips | 0419016384 | ~4% | network, intrusion_detection |
| UTM Antivirus | utm/virus | 0211008192 | ~1% | network, malware |
| UTM Anomaly (DoS) | utm/anomaly | 0720018432 | ~1% | network, intrusion_detection |
| Event System | event/system | 0100032001+ | ~4% | authentication, host |
| Event VPN | event/vpn | 0101037138 | ~3% | network |
| Event User Auth | event/user | 0102043008+ | ~3% | authentication |

## Realism Features

- **Weighted event distributions** matching production FortiGate log volumes (traffic ~70%, UTM ~22%, events ~8%)
- **FortiGate-specific fields** in `fortinet.firewall.*` namespace: sessionid, vd, policyid, poluuid, trandisp, srccountry/dstcountry, crscore/crlevel, srcintfrole/dstintfrole
- **Zone-aware routing** with FortiGate interface naming (port1=WAN, port2=LAN, port3=DMZ) and role attributes
- **NAT translation** with SNAT for outbound traffic (transip/transport fields)
- **Session close actions**: close (60%), timeout (20%), client-rst (12%), server-rst (8%)
- **VPN tunnel correlation** via shared state — tunnel-up events paired with tunnel-down events including duration and byte counts
- **Realistic IPS signatures** with FortiGuard reference URLs, attack IDs, and severity levels
- **FortiGuard web categories** with proper category IDs (cat field) matching real FortiGuard classification
- **Application control** with real FortiGate application IDs, categories, and risk levels
- **GeoIP country names** for external source/destination IPs weighted by real-world traffic patterns
- **Antivirus detections** with realistic FortiGuard virus signature names and file types
- **DoS/anomaly detection** with threshold-based alerting (count > threshold)
- **User authentication** via RADIUS, LDAP, FSSO with realistic user groups

## Parameters

### Event Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `hostname` | `fg-01` | FortiGate device hostname |
| `domain` | `example.com` | Domain name for FQDN |
| `serial_number` | `FG200F2024000001` | FortiGate serial number (devid) |
| `vdom` | `root` | Virtual domain name |
| `nat_ip` | `198.51.100.1` | NAT/public IP for outbound SNAT |
| `agent_id` | `e4f8c1a2-...` | Filebeat agent UUID |
| `agent_version` | `8.17.0` | Filebeat version string |

### Output Parameters

| Parameter | Variable | Description |
|-----------|----------|-------------|
| OpenSearch host | `${params.opensearch_host}` | OpenSearch endpoint URL |
| OpenSearch user | `${params.opensearch_user}` | OpenSearch username |
| OpenSearch password | `${secrets.opensearch_password}` | OpenSearch password (from keyring) |
| OpenSearch index | `${params.opensearch_index}` | Target index name |

## Usage

```bash
# Install Eventum
uv tool install eventum-generator

# Run in live mode (continuous streaming)
eventum generate \
  --path generators/network-fortigate/generator.yml \
  --id fortigate \
  --live-mode

# Adjust event rate (10 events/second)
# Edit generator.yml: change count: 5 to count: 10

# Run in sample mode (generate batch and exit)
eventum generate \
  --path generators/network-fortigate/generator.yml \
  --id fortigate \
  --no-live-mode
```

### OpenSearch Configuration

To output to OpenSearch, uncomment the `opensearch` section in `generator.yml` and configure via `startup.yml`:

```yaml
# startup.yml
generators:
  - path: generators/network-fortigate/generator.yml
    id: fortigate
    live_mode: true
    params:
      opensearch_host: "https://localhost:9200"
      opensearch_user: "admin"
      opensearch_index: "logs-fortinet_fortigate.log-default"
```

## Sample Output

### Traffic Forward (session close)

```json
{
    "@timestamp": "2026-02-21T14:32:07+00:00",
    "agent": {
        "ephemeral_id": "a1b2c3d4-5678-90ab-cdef-1234567890ab",
        "id": "e4f8c1a2-9b3d-4e5f-a6c7-d8e9f0a1b2c3",
        "name": "fg-01.example.com",
        "type": "filebeat",
        "version": "8.17.0"
    },
    "destination": {
        "bytes": 39898,
        "ip": "172.217.14.206",
        "packets": 37,
        "port": 443
    },
    "ecs": {
        "version": "8.17.0"
    },
    "event": {
        "action": "close",
        "category": ["network"],
        "code": "0000000013",
        "dataset": "fortinet_fortigate.log",
        "duration": 30000000000,
        "kind": "event",
        "module": "fortinet_fortigate",
        "outcome": "success",
        "start": "2026-02-21T14:32:07+00:00",
        "type": ["connection", "end", "allowed"]
    },
    "fortinet": {
        "firewall": {
            "action": "close",
            "appcat": "Web.Client",
            "apprisk": "medium",
            "dstintfrole": "wan",
            "duration": 30,
            "policyid": 1,
            "poluuid": "a1b2c3d4-1111-4e5f-a6c7-d8e9f0a1b2c3",
            "policytype": "policy",
            "rcvdbyte": 39898,
            "rcvdpkt": 37,
            "sentbyte": 1850,
            "sentpkt": 25,
            "sessionid": 100000,
            "srccountry": "Reserved",
            "dstcountry": "United States",
            "srcintfrole": "lan",
            "subtype": "forward",
            "trandisp": "snat",
            "transip": "198.51.100.1",
            "transport": 40772,
            "type": "traffic",
            "vd": "root"
        }
    },
    "log": {
        "level": "notice"
    },
    "message": "close HTTPS",
    "network": {
        "application": "HTTPS.BROWSER",
        "bytes": 41748,
        "direction": "outbound",
        "iana_number": "6",
        "packets": 62,
        "protocol": "https",
        "transport": "tcp"
    },
    "observer": {
        "egress": {"interface": {"name": "port1"}},
        "ingress": {"interface": {"name": "port2"}},
        "name": "fg-01",
        "product": "Fortigate",
        "serial_number": "FG200F2024000001",
        "type": "firewall",
        "vendor": "Fortinet"
    },
    "related": {
        "ip": ["10.1.1.11", "172.217.14.206", "198.51.100.1"]
    },
    "rule": {
        "id": "1",
        "name": "Allow-HTTPS-Out",
        "ruleset": "policy",
        "uuid": "a1b2c3d4-1111-4e5f-a6c7-d8e9f0a1b2c3"
    },
    "source": {
        "bytes": 1850,
        "ip": "10.1.1.11",
        "mac": "A2-E9-00-EC-40-02",
        "nat": {"ip": "198.51.100.1", "port": 40772},
        "packets": 25,
        "port": 60446
    },
    "tags": ["fortinet-fortigate", "fortinet-firewall", "forwarded"]
}
```

## File Structure

```
network-fortigate/
  generator.yml                              # Pipeline config
  README.md                                  # This file
  templates/
    traffic-forward-close.json.jinja         # Traffic allowed/closed sessions
    traffic-forward-deny.json.jinja          # Traffic denied by policy
    traffic-local.json.jinja                 # Local (management) traffic
    utm-appctrl.json.jinja                   # Application control events
    utm-webfilter.json.jinja                 # FortiGuard web filter events
    utm-dns.json.jinja                       # DNS filter/logging events
    utm-ips.json.jinja                       # IPS signature detections
    utm-virus.json.jinja                     # Antivirus detections
    utm-anomaly.json.jinja                   # DoS/anomaly detections
    event-system.json.jinja                  # System admin events
    event-vpn.json.jinja                     # VPN tunnel events
    event-user.json.jinja                    # User auth events
  samples/
    internal_hosts.csv                       # Internal network hosts (25 hosts)
    network_services.json                    # Service definitions with FortiGate app IDs
    firewall_policies.json                   # Firewall policies (accept/deny)
    ips_signatures.json                      # IPS attack signatures
    web_categories.json                      # FortiGuard web categories
    users.json                               # Users and groups
```

## References

- [FortiOS 7.6 Log Message Reference](https://docs.fortinet.com/document/fortigate/7.6.5/fortios-log-message-reference)
- [FortiOS Log Types and Subtypes](https://docs.fortinet.com/document/fortigate/7.6.5/fortios-log-message-reference/670197/log-types-and-subtypes)
- [FortiOS Log Message Fields](https://docs.fortinet.com/document/fortigate/7.6.5/fortios-log-message-reference/357866/log-message-fields)
- [Elastic fortinet_fortigate Integration](https://www.elastic.co/docs/reference/integrations/fortinet_fortigate)
- [Elastic Common Schema (ECS)](https://www.elastic.co/guide/en/ecs/current/index.html)
- [FortiGuard Web Filter Categories](https://www.fortiguard.com/webfilter/categories)

# Network NetFlow / IPFIX Event Generator

Produces realistic IPFIX biflow records (ECS-compatible JSON) matching the field structure used by the Elastic NetFlow integration (Filebeat). Events model network flow data as exported by routers, switches, and firewalls via NetFlow v9 / IPFIX. Covers the full spectrum of enterprise traffic: TCP services (HTTPS, HTTP, SSH, RDP, SMB, LDAP, databases), UDP services (DNS, NTP, SNMP, syslog), and ICMP flows.

## Flow Types Covered

### TCP Flows (~71%)

| Service | Port | % of TCP | Traffic Profile |
|---------|------|----------|-----------------|
| HTTPS | 443 | 55% | 500B-50KB request, 3-50x response, 200ms-5min |
| HTTP | 80 | 11% | 200B-30KB request, 2-100x response, 50ms-30s |
| Other TCP | various | 8% | General TCP, variable profiles |
| SSH | 22 | 6% | Bidirectional, 500B-100KB, 5s-30min |
| SMB | 445 | 4% | File sharing, 500B-200KB, 100ms-10min |
| SMTP | 25 | 3% | Email delivery, 1-100KB request, small response |
| RDP | 3389 | 3% | Interactive, 5KB-200KB, 10s-30min |
| LDAP | 389 | 3% | Directory queries, 200B-10KB, 10ms-5s |
| HTTPS-Alt | 8443 | 3% | Web apps, 500B-30KB, 200ms-2min |
| MySQL | 3306 | 2% | Database queries, 200B-50KB, 10ms-30s |
| Kerberos | 88 | 2% | Auth tickets, 200B-2KB, 5ms-500ms |

### UDP Flows (~27%)

| Service | Port | % of UDP | Traffic Profile |
|---------|------|----------|-----------------|
| DNS | 53 | 74% | 40-200B query, 1-3x response, 1-80ms |
| NTP | 123 | 11% | 76-90B, symmetric, 1-50ms |
| SNMP | 161 | 4% | 80-300B query, 1-5x response, 1-100ms |
| Other UDP | various | 4% | General UDP, small packets |
| Syslog | 514 | 3% | 100B-2KB, one-way (no response), <1ms |
| DHCP | 67 | 2% | 300-600B, symmetric, 1ms-5s |
| IPsec/IKE | 500 | 2% | 200-800B, symmetric, 10ms-5s |

### ICMP Flows (~2%)

| Type | Code | ICMP Value | % of ICMP |
|------|------|------------|-----------|
| Echo Request | 0 | 2048 | 50% |
| Dest Unreachable (network) | 0 | 768 | 10% |
| Dest Unreachable (host) | 1 | 769 | 15% |
| Dest Unreachable (port) | 3 | 771 | 15% |
| Time Exceeded | 0 | 2816 | 10% |

## Realism Features

- **IPFIX biflow records** with initiator/responder byte and packet counts matching the Elastic integration format
- **Protocol-realistic traffic profiles** — each service has appropriate byte ranges, packet counts, response ratios, and flow durations derived from production network analysis
- **TCP flag simulation** — cumulative flag bitmasks: completed flows (SYN+ACK+PSH+FIN=0x1B, 70%), active transfers (0x1A, 15%), refused connections (RST+ACK=0x14, 10%), half-open scans (SYN=0x02, 5%)
- **Flag-conditioned metrics** — SYN-only flows: 1 packet/40-60B/no response; RST+ACK: 1+1 packets; normal flows: full service profile
- **Direction-aware routing** — outbound (60%), inbound (25%), internal (15%) with correct interface and VLAN mappings per direction
- **BGP AS numbers** — weighted selection from 13 major cloud/CDN providers (Google, Cloudflare, AWS, Microsoft, Meta, Akamai, Netflix, Fastly) for external endpoints
- **Response ratio modeling** — each service defines initiator-to-responder byte ratios (e.g. HTTPS 3-50x, SMTP 0.1-0.5x, SSH 0.5-3x)
- **ICMP handling** — echo requests include reply data; unreachable/time-exceeded are one-way
- **Community ID** — per-flow identifier for cross-event correlation
- **VLAN tagging** — workstations (VLAN 10), servers (VLAN 20), DMZ (VLAN 30) based on host subnet
- **TTL variation** — realistic range per flow (48-128) reflecting network hop counts

## Parameters

### Event Parameters

Edit the `params` section under `event.template` in `generator.yml`:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `exporter_ip` | `10.0.0.1` | IP address of the NetFlow/IPFIX exporter (router) |
| `exporter_port` | `2055` | UDP port the exporter sends from |
| `source_id` | `512` | IPFIX Observation Domain ID |
| `collector_name` | `netflow-collector` | Filebeat collector hostname |
| `agent_id` | `a1b2c3d4-...` | Filebeat agent ID |
| `agent_version` | `8.17.0` | Filebeat version string |

### Output Parameters

Provide via `startup.yml` params/secrets (used by the OpenSearch output):

| Parameter | Variable | Description |
|-----------|----------|-------------|
| `opensearch_host` | `${params.opensearch_host}` | OpenSearch URL (e.g. `https://localhost:9200`) |
| `opensearch_user` | `${params.opensearch_user}` | OpenSearch username |
| `opensearch_password` | `${secrets.opensearch_password}` | OpenSearch password (stored in keyring) |
| `opensearch_index` | `${params.opensearch_index}` | Target index name (e.g. `logs-netflow.log-default`) |

## Usage

```bash
# Install Eventum
uv tool install eventum-generator

# Run with console output only (for testing)
eventum generate \
  --path generators/network-netflow/generator.yml \
  --id netflow \
  --live-mode
```

### OpenSearch Configuration

The OpenSearch output uses `${params.*}` / `${secrets.*}` placeholders resolved from `startup.yml`:

```yaml
# startup.yml
- id: netflow
  path: network-netflow
  params:
    opensearch_host: https://localhost:9200
    opensearch_user: admin
    opensearch_index: logs-netflow.log-default
```

Secrets (e.g. `opensearch_password`) are managed via the Eventum keyring. See [Eventum docs](https://eventum.run) for details.

### Adjusting Event Rate

Change the `count` in the input section:

```yaml
input:
  - cron:
      expression: "* * * * * *"
      count: 5    # 5 flows/second (300/min, 18K/hour)
```

## Sample Output

### TCP Flow (HTTPS)

```json
{
    "@timestamp": "2026-02-21T12:00:05.000000+00:00",
    "agent": {
        "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        "name": "netflow-collector",
        "type": "filebeat",
        "version": "8.17.0"
    },
    "client": {
        "bytes": 12340,
        "packets": 18
    },
    "data_stream": {
        "dataset": "netflow.log",
        "namespace": "default",
        "type": "logs"
    },
    "destination": {
        "bytes": 385200,
        "ip": "203.0.113.50",
        "locality": "external",
        "packets": 265,
        "port": 443
    },
    "event": {
        "action": "netflow_flow",
        "category": ["network", "session"],
        "dataset": "netflow.log",
        "duration": 2500000000,
        "kind": "event",
        "module": "netflow",
        "type": ["connection"]
    },
    "flow": {
        "id": "a1b2c3d4e5f6a"
    },
    "netflow": {
        "bgp_destination_as_number": 13335,
        "bgp_source_as_number": 0,
        "biflow_direction": 1,
        "destination_transport_port": 443,
        "egress_interface": 1,
        "flow_duration_milliseconds": 2500,
        "ingress_interface": 2,
        "initiator_octets": 12340,
        "initiator_packets": 18,
        "protocol_identifier": 6,
        "responder_octets": 385200,
        "responder_packets": 265,
        "tcp_control_bits": 27,
        "type": "netflow_flow",
        "vlan_id": 10
    },
    "network": {
        "bytes": 397540,
        "community_id": "1:a1b2c3d4e5f6a7b8c9d0",
        "direction": "outbound",
        "iana_number": "6",
        "packets": 283,
        "transport": "tcp",
        "type": "ipv4"
    },
    "observer": {
        "ip": ["10.0.0.1"]
    },
    "server": {
        "bytes": 385200,
        "packets": 265
    },
    "source": {
        "bytes": 12340,
        "ip": "10.1.1.30",
        "locality": "internal",
        "packets": 18,
        "port": 52341
    },
    "tags": ["netflow", "forwarded"]
}
```

## File Structure

```
network-netflow/
  generator.yml                          # Pipeline configuration
  README.md                              # This file
  templates/
    tcp-flow.json.jinja                  # TCP biflow records (71%)
    udp-flow.json.jinja                  # UDP biflow records (27%)
    icmp-flow.json.jinja                 # ICMP flow records (2%)
  samples/
    internal_hosts.csv                   # 25 internal hosts (workstations, servers, DMZ)
    tcp_services.json                    # 11 TCP service profiles with traffic characteristics
    udp_services.json                    # 7 UDP service profiles with traffic characteristics
    as_numbers.json                      # 13 BGP AS numbers (major cloud/CDN providers)
```

## References

- [RFC 3954 — Cisco Systems NetFlow Services Export Version 9](https://datatracker.ietf.org/doc/html/rfc3954)
- [RFC 7011 — Specification of the IP Flow Information Export (IPFIX) Protocol](https://www.rfc-editor.org/rfc/rfc7011.html)
- [RFC 7012 — Information Model for IP Flow Information Export (IPFIX)](https://www.rfc-editor.org/rfc/rfc7012.html)
- [IANA IPFIX Information Elements Registry](https://www.iana.org/assignments/ipfix)
- [Elastic NetFlow Integration](https://docs.elastic.co/en/integrations/netflow)
- [Elastic NetFlow Input Reference](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-netflow.html)
- [Elastic NetFlow Exported Fields](https://www.elastic.co/guide/en/beats/filebeat/current/exported-fields-netflow.html)
- [ECS Network Fields](https://www.elastic.co/guide/en/ecs/current/ecs-network.html)
- [Community ID Flow Hashing Specification](https://github.com/corelight/community-id-spec)

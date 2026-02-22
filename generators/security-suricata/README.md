# Suricata IDS/IPS Generator

Generates synthetic Suricata EVE (Extensible Event Format) JSON events compatible with the [Elastic Suricata integration](https://docs.elastic.co/en/integrations/suricata). Produces realistic IDS/IPS network security monitoring data including alerts, protocol metadata (DNS, HTTP, TLS, SSH, SMTP), flow records, file inspection events, DHCP transactions, and protocol anomalies — all in ECS-compatible format ready for direct indexing into OpenSearch or Elasticsearch.

## Event Types

| Event Type | Template | Frequency | ECS Category |
|-----------|----------|:---------:|---|
| Flow (TCP) | `flow-tcp.json.jinja` | 28.7% | `network` |
| Flow (UDP) | `flow-udp.json.jinja` | 17.2% | `network` |
| DNS Query | `dns-query.json.jinja` | 14.3% | `network` |
| DNS Answer | `dns-answer.json.jinja` | 14.3% | `network` |
| HTTP | `http.json.jinja` | 10.0% | `network`, `web` |
| TLS | `tls.json.jinja` | 7.2% | `network` |
| File Info | `fileinfo.json.jinja` | 2.2% | `network` |
| SSH | `ssh.json.jinja` | 1.4% | `network` |
| Alert (Policy) | `alert-policy.json.jinja` | 1.4% | `network`, `intrusion_detection` |
| Anomaly | `anomaly.json.jinja` | 1.1% | `network` |
| Alert (Threat) | `alert-threat.json.jinja` | 0.7% | `network`, `intrusion_detection` |
| SMTP | `smtp.json.jinja` | 0.7% | `network` |
| DHCP | `dhcp.json.jinja` | 0.7% | `network` |

## Realism Features

- **Weighted event distribution** matching production Suricata deployments (flows dominate, then DNS, then HTTP/TLS)
- **Correlated flow_id** — protocol events (HTTP, TLS, DNS, SSH, SMTP) push connection metadata to a shared pool; flow events pop from it to produce correlated flow-end records
- **DNS query/answer pairing** — queries push to a shared pool, answers pop correlated responses with matching flow_id and DNS transaction ID
- **ET Open rule signatures** with real SIDs, categories, severity levels, and MITRE ATT&CK metadata for threat alerts
- **JA3/JA3S TLS fingerprints** from real certificate data for major websites (Google, Facebook, Amazon, GitHub, Microsoft, etc.)
- **Deterministic community_id** — computed from connection tuple (src_ip, src_port, dst_ip, dst_port, proto) for cross-event correlation
- **Realistic traffic patterns** — mix of internal (RFC1918) and external IPs, ephemeral source ports, well-known destination ports
- **HTTP response distribution** — weighted status codes (mostly 200, with 301/302/304/400/404/500)
- **Protocol anomalies** — decode, stream, and application layer anomalies with real Suricata event names
- **DHCP lifecycle** — discover, offer, request, ack, and release messages with realistic lease parameters
- **Dual field retention** — both ECS-normalized fields and `suricata.eve.*` namespace fields, matching the Elastic ingest pipeline output

## Parameters

### Event Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `hostname` | `suricata-sensor-01` | Suricata sensor hostname |
| `interface` | `eth0` | Network interface name |
| `internal_subnet` | `192.168.1` | Internal network prefix (first 3 octets) |
| `dns_server_ip` | `192.168.1.1` | DNS server IP address |
| `gateway_ip` | `192.168.1.1` | Default gateway / DHCP server IP |
| `mail_domain` | `company.local` | Mail domain for SMTP HELO |
| `agent_id` | `7b2c5f18-...` | Filebeat agent UUID |
| `agent_version` | `8.17.0` | Filebeat agent version |

## Usage

### Installation

```bash
uv tool install eventum-generator
```

### Quick Start

```bash
eventum generate \
  --path generators/security-suricata/generator.yml \
  --id suricata-01 \
  --live-mode
```

### Sample Mode (batch generation)

```bash
eventum generate \
  --path generators/security-suricata/generator.yml \
  --id suricata-01 \
  --live-mode false
```

### Adjusting Event Rate

Modify the `count` parameter in `generator.yml` to change events per second:

```yaml
input:
  - cron:
      expression: "* * * * * *"
      count: 10  # 10 events per second
```

## Sample Output

### DNS Query Event

```json
{
    "@timestamp": "2026-02-21T14:30:22.123456Z",
    "agent": {
        "id": "7b2c5f18-4a91-4d3e-8c7f-1a2b3c4d5e6f",
        "name": "suricata-sensor-01",
        "type": "filebeat",
        "version": "8.17.0"
    },
    "destination": {
        "address": "192.168.1.1",
        "ip": "192.168.1.1",
        "port": 53
    },
    "dns": {
        "id": "45321",
        "question": {
            "name": "www.google.com",
            "type": "A"
        },
        "type": "query"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "event": {
        "category": ["network"],
        "dataset": "suricata.eve",
        "kind": "event",
        "module": "suricata",
        "type": ["protocol"]
    },
    "network": {
        "community_id": "1:fmTf/MbjDMinU9coqCwDUc82LmA=",
        "protocol": "dns",
        "transport": "udp"
    },
    "observer": {
        "hostname": "suricata-sensor-01",
        "product": "Suricata",
        "type": "ids",
        "vendor": "OISF"
    },
    "related": {
        "ip": ["192.168.1.42", "192.168.1.1"]
    },
    "source": {
        "address": "192.168.1.42",
        "ip": "192.168.1.42",
        "port": 54321
    },
    "suricata": {
        "eve": {
            "dns": {
                "id": 45321,
                "rrname": "www.google.com",
                "rrtype": "A",
                "type": "query",
                "version": 2
            },
            "event_type": "dns",
            "flow_id": "100000000000042",
            "in_iface": "eth0"
        }
    },
    "tags": ["suricata"]
}
```

### IDS Alert Event

```json
{
    "@timestamp": "2026-02-21T14:30:25.654321Z",
    "event": {
        "category": ["network", "intrusion_detection"],
        "dataset": "suricata.eve",
        "kind": "alert",
        "module": "suricata",
        "severity": 1,
        "type": ["denied"]
    },
    "message": "Attempted Administrator Privilege Gain",
    "rule": {
        "category": "Attempted Administrator Privilege Gain",
        "id": "2034647",
        "name": "ET EXPLOIT Apache Log4j RCE Attempt - 2021-44228 (CVE-2021-44228)"
    },
    "suricata": {
        "eve": {
            "alert": {
                "category": "Attempted Administrator Privilege Gain",
                "gid": 1,
                "severity": 1,
                "signature": "ET EXPLOIT Apache Log4j RCE Attempt - 2021-44228 (CVE-2021-44228)",
                "signature_id": 2034647
            },
            "event_type": "alert"
        }
    },
    "threat": {
        "framework": "MITRE ATT&CK",
        "tactic": {
            "id": ["TA0001"],
            "name": ["Initial Access"]
        },
        "technique": {
            "id": ["T1190"]
        }
    }
}
```

## File Structure

```
security-suricata/
  generator.yml                          # Pipeline configuration
  README.md                              # This file
  templates/
    flow-tcp.json.jinja                  # TCP flow termination records
    flow-udp.json.jinja                  # UDP flow termination records
    dns-query.json.jinja                 # DNS query events
    dns-answer.json.jinja                # DNS answer events (correlated)
    http.json.jinja                      # HTTP transaction metadata
    tls.json.jinja                       # TLS handshake with JA3 fingerprints
    fileinfo.json.jinja                  # File transfer metadata with hashes
    ssh.json.jinja                       # SSH handshake events
    alert-policy.json.jinja              # IDS alerts — policy violations
    alert-threat.json.jinja              # IDS alerts — threats with MITRE ATT&CK
    anomaly.json.jinja                   # Protocol decode/stream anomalies
    smtp.json.jinja                      # SMTP transaction events
    dhcp.json.jinja                      # DHCP lease events
  samples/
    domains.csv                          # Domain names for DNS/HTTP/TLS
    urls.csv                             # URL paths for HTTP requests
    user-agents.json                     # HTTP user agent strings
    signatures-policy.json               # ET Open policy/info rule signatures
    signatures-threat.json               # ET Open threat rule signatures with MITRE
    tls-certs.json                       # TLS certificates with JA3 fingerprints
    ssh-versions.json                    # SSH client/server version pairs
```

## References

- [Suricata EVE JSON Format](https://docs.suricata.io/en/latest/output/eve/eve-json-format.html)
- [Elastic Suricata Integration](https://docs.elastic.co/en/integrations/suricata)
- [Elastic Common Schema (ECS)](https://www.elastic.co/guide/en/ecs/current/index.html)
- [Emerging Threats Open Ruleset](https://rules.emergingthreats.net/open/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Community ID Flow Hashing](https://github.com/corelight/community-id-spec)

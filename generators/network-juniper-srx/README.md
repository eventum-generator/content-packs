# Juniper SRX with Web Filtering

Produces realistic Juniper SRX firewall events (ECS-compatible JSON) matching the field structure of the [Elastic Juniper SRX integration](https://www.elastic.co/docs/current/en/integrations/juniper_srx). Events cover the full SRX security stack: RT_FLOW session lifecycle (create/close/deny), RT_UTM Enhanced Web Filtering (URL permit/block by category), RT_IDP intrusion detection signatures, and RT_IDS screen-based DoS protection alerts.

All events use the `juniper.srx.*` vendor namespace with proper ECS categorization (`event.kind`, `event.category`, `event.type`, `event.action`) matching the Elastic ingest pipeline output.

## Event Types Covered

| Event Type | Template | Frequency | ECS Category |
|------------|----------|-----------|--------------|
| RT_FLOW_SESSION_CLOSE | Session teardown with bytes/packets/duration | ~45% | network |
| RT_FLOW_SESSION_CREATE | Permitted session establishment | ~31% | network |
| WEBFILTER_URL_PERMITTED | URL allowed by EWF category lookup | ~13% | network |
| WEBFILTER_URL_BLOCKED | URL blocked by EWF (social media, malware, etc.) | ~4.5% | network, malware |
| RT_FLOW_SESSION_DENY | Session denied by security policy | ~4% | network |
| IDP_ATTACK_LOG_EVENT | IDP signature match (SQL injection, brute force, etc.) | ~1.5% | network, intrusion_detection |
| RT_SCREEN_* | Screen alerts (SYN flood, port scan, IP spoofing, etc.) | ~1% | network, intrusion_detection |

## Realism Features

- **Correlated sessions** — SESSION_CREATE pushes to a shared pool; SESSION_CLOSE pops matching sessions with consistent 5-tuple, policy, and NAT details
- **Juniper service names** — uses real SRX predefined service names (`junos-https`, `junos-dns-udp`, `junos-ssh`, etc.)
- **Direction-aware zones** — trust/untrust/dmz zones with correct `ge-*` interface mappings per traffic direction
- **Enhanced Web Filtering categories** — 27 real EWF categories (Enhanced_Social_Web_Youtube, Enhanced_Malicious_Web_Sites, etc.) with permit/block actions
- **NAT tracking** — outbound sessions carry source NAT IP/port through the session lifecycle
- **Session close reasons** — weighted distribution: TCP FIN (50%), idle Timeout (25%), TCP RST (13%), response received (5%), aged out (5%)
- **IDP signatures** — 15 real Juniper-style attack names (HTTP:MISC:GENERIC-DIR-TRAVERSAL, SMB:EXPLOIT:MS17-010-ETERNALBLUE, etc.) with severity and action
- **Screen event types** — 11 DoS/anomaly screen types (SYN flood, TCP port scan, IP spoofing, ICMP flood, etc.) with correct event.action mapping
- **IANA protocol numbers** — `network.iana_number` matches `network.transport` (6=tcp, 17=udp, 1=icmp)
- **Encryption detection** — `juniper.srx.encrypted` varies by application type (SSL=Yes, HTTP=No, etc.)

## Parameters

### Event Parameters

Edit the `params` section under `event.template` in `generator.yml`:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `hostname` | `srx-fw-01` | SRX hostname |
| `domain` | `example.com` | Domain for FQDN construction |
| `nat_ip` | `198.51.100.1` | Public NAT IP for source NAT |
| `wf_profile` | `corporate-web-filter` | Web filtering profile name |
| `agent_id` | `a7d2e4f1-...` | Filebeat agent ID |
| `agent_version` | `8.17.0` | Filebeat version string |

### Output Parameters

Provide via `startup.yml` params/secrets (used by the OpenSearch output):

| Parameter | Variable | Description |
|-----------|----------|-------------|
| `opensearch_host` | `${params.opensearch_host}` | OpenSearch URL (e.g. `https://localhost:9200`) |
| `opensearch_user` | `${params.opensearch_user}` | OpenSearch username |
| `opensearch_password` | `${secrets.opensearch_password}` | OpenSearch password (stored in keyring) |
| `opensearch_index` | `${params.opensearch_index}` | Target index name (e.g. `filebeat-8.17.0`) |

## Usage

```bash
# Install Eventum
uv tool install eventum-generator

# Run with console output only (for testing)
eventum generate \
  --path generators/network-juniper-srx/generator.yml \
  --id srx \
  --live-mode
```

### Adjusting Event Rate

Change the `count` in the input section:

```yaml
input:
  - cron:
      expression: "* * * * * *"
      count: 10    # 10 events/second (600/min, 36K/hour)
```

### OpenSearch Configuration

```yaml
# startup.yml
- id: srx
  path: network-juniper-srx
  params:
    opensearch_host: https://localhost:9200
    opensearch_user: admin
    opensearch_index: filebeat-8.17.0
```

Secrets (e.g. `opensearch_password`) are managed via the Eventum keyring. See [Eventum docs](https://eventum.run) for details.

## Sample Output

### RT_FLOW_SESSION_CLOSE

```json
{
    "@timestamp": "2026-02-21T14:32:10.123456+00:00",
    "event": {
        "action": "flow_close",
        "category": ["network"],
        "dataset": "juniper_srx.log",
        "duration": 45000000000,
        "kind": "event",
        "module": "juniper_srx",
        "outcome": "success",
        "type": ["end", "allowed", "connection"]
    },
    "source": {
        "bytes": 24576,
        "ip": "10.1.1.30",
        "nat": {"ip": "198.51.100.1", "port": 34521},
        "packets": 42,
        "port": 52341
    },
    "destination": {
        "bytes": 156800,
        "ip": "142.250.80.46",
        "packets": 98,
        "port": 443
    },
    "network": {
        "bytes": 181376,
        "iana_number": "6",
        "packets": 140,
        "transport": "tcp"
    },
    "juniper": {
        "srx": {
            "application": "SSL",
            "encrypted": "Yes",
            "process": "RT_FLOW",
            "reason": "TCP FIN",
            "service_name": "junos-https",
            "session_id_32": "5824901",
            "tag": "RT_FLOW_SESSION_CLOSE"
        }
    },
    "observer": {
        "name": "srx-fw-01.example.com",
        "product": "SRX",
        "type": "firewall",
        "vendor": "Juniper",
        "ingress": {"zone": "trust", "interface": {"name": "ge-0/0/1.0"}},
        "egress": {"zone": "untrust"}
    },
    "rule": {"name": "allow-outbound-web"},
    "tags": ["juniper-srx", "forwarded"]
}
```

### WEBFILTER_URL_BLOCKED

```json
{
    "@timestamp": "2026-02-21T14:32:15.456789+00:00",
    "event": {
        "action": "web_filter",
        "category": ["network", "malware"],
        "dataset": "juniper_srx.log",
        "kind": "alert",
        "module": "juniper_srx",
        "type": ["info", "denied", "connection"]
    },
    "source": {"ip": "10.1.1.40", "port": 58220},
    "destination": {"ip": "142.250.191.46", "port": 443},
    "juniper": {
        "srx": {
            "category": "Enhanced_Social_Web_Youtube",
            "process": "RT_UTM",
            "profile": "corporate-web-filter",
            "reason": "BY_PRE_DEFINED",
            "tag": "WEBFILTER_URL_BLOCKED"
        }
    },
    "url": {"domain": "www.youtube.com", "path": "/watch"},
    "observer": {
        "name": "srx-fw-01.example.com",
        "product": "SRX",
        "vendor": "Juniper"
    },
    "tags": ["juniper-srx", "forwarded"]
}
```

## File Structure

```
network-juniper-srx/
  generator.yml                              # Pipeline configuration
  README.md                                  # This file
  templates/
    session-create.json.jinja                # RT_FLOW_SESSION_CREATE (~31%)
    session-close.json.jinja                 # RT_FLOW_SESSION_CLOSE (~45%)
    session-deny.json.jinja                  # RT_FLOW_SESSION_DENY (~4%)
    webfilter-permitted.json.jinja           # WEBFILTER_URL_PERMITTED (~13%)
    webfilter-blocked.json.jinja             # WEBFILTER_URL_BLOCKED (~4.5%)
    idp-attack.json.jinja                    # IDP_ATTACK_LOG_EVENT (~1.5%)
    screen-alert.json.jinja                  # RT_SCREEN_* alerts (~1%)
  samples/
    internal_hosts.csv                       # 25 internal hosts (workstations, servers, DMZ)
    network_services.json                    # 18 Juniper predefined services with IANA numbers
    security_policies.json                   # 14 security policies (permit + deny)
    web_destinations.json                    # 27 web destinations with EWF categories
    idp_signatures.json                      # 15 IDP attack signatures
```

## References

- [Juniper SRX System Logging for Security Devices](https://www.juniper.net/documentation/us/en/software/junos/network-mgmt/topics/topic-map/system-logging-for-a-security-device.html)
- [Juniper SRX Enhanced Web Filtering](https://www.juniper.net/documentation/us/en/software/junos/utm/topics/topic-map/security-utm-web-filtering.html)
- [Juniper SRX IDP Event Logging](https://www.juniper.net/documentation/us/en/software/junos/idp-policy/topics/topic-map/security-idp-event-logging.html)
- [Elastic Juniper SRX Integration](https://www.elastic.co/docs/current/en/integrations/juniper_srx)
- [Elastic Juniper SRX Integration Source](https://github.com/elastic/integrations/tree/main/packages/juniper_srx)
- [ECS Field Reference](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html)

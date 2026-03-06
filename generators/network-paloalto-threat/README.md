# Palo Alto Networks Threat Log Event Generator

Produces realistic PAN-OS Threat log events in ECS-compatible JSON format, matching the field structure used by the [Elastic panw integration](https://docs.elastic.co/integrations/panw). Threat logs record security threats detected by the firewall's threat prevention engine, including spyware (DNS sinkhole and C2 callback), vulnerability exploits (IPS), virus detections (antivirus), WildFire cloud verdicts, file type detections, and network scan activity.

## Event Types

| Template | Subtype | Frequency | Description |
|----------|---------|-----------|-------------|
| `spyware-dns.json.jinja` | spyware | ~35% | DNS-based spyware: UDP/53, dns-base app, sinkhole/drop action |
| `spyware-callback.json.jinja` | spyware | ~15% | C2 callback: TCP/443, ssl/web-browsing app, drop/reset |
| `vulnerability.json.jinja` | vulnerability | ~20% | IPS vulnerability signatures, mixed direction, alert-heavy |
| `virus.json.jinja` | virus | ~12% | Antivirus file detections, Antivirus-* content version, file hash |
| `wildfire.json.jinja` | wildfire | ~8% | WildFire cloud verdicts, report ID, file hash |
| `file-scan.json.jinja` | file / scan | ~10% | File type matching and network scan detections |

## Realism Features

- **Weighted threat distribution** — 6 templates with realistic enterprise frequency (DNS spyware 35%, vulnerability 20%, etc.)
- **Per-subtype field interdependencies** — Action, severity, application, direction, and threat_category are all correlated to subtype
- **Threat signature database** — 70+ signatures across all subtypes with realistic IDs, names, and severity levels
- **Malicious domain corpus** — 65+ domains organized by threat type (DNS malware, phishing, C2, EDL, download)
- **Content version differentiation** — Virus subtypes use `Antivirus-XXXX-YYYY`, all others use `AppThreat-XXXX-YYYY`
- **File metadata for AV/WildFire** — SHA256 hash, file name, and file type matching the threat category (PE->exe, PDF->pdf, etc.)
- **WildFire report IDs** — Unique report IDs for WildFire cloud analysis results
- **Severity-to-syslog mapping** — Critical/high/medium/low/informational mapped to correct syslog codes and priorities
- **Source NAT translation** — All outbound traffic includes NAT IP/port translation
- **Monotonic sequence numbers** — Sequence counter increments across all events
- **Geo-aware destinations** — Threat traffic skews toward higher-risk regions (Russia, China)
- **ECS-compliant output** — Full Elastic panw integration field mapping including `panw.panos.*` vendor fields

## Parameters

### Event Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `hostname` | `PA-5260` | PAN-OS firewall hostname |
| `domain` | `CORP` | Active Directory domain name |
| `serial_number` | `007200001056` | Firewall serial number |
| `nat_ip` | `198.51.100.1` | Source NAT IP for outbound traffic |
| `src_zone` | `trust` | Source security zone |
| `dst_zone` | `untrust` | Destination security zone |
| `inbound_interface` | `ethernet1/2` | Ingress interface |
| `outbound_interface` | `ethernet1/1` | Egress interface |
| `virtual_sys` | `vsys1` | Virtual system name |
| `log_profile` | `Log-to-Syslog` | Log forwarding profile |
| `src_network` | `10.0.0.0-10.255.255.255` | Source network range (geo label) |
| `agent_id` | `e4f8c1a2-...` | Elastic Agent ID |
| `agent_version` | `8.17.0` | Elastic Agent version |

## Usage

### Run the generator

```bash
eventum generate \
  --path generators/network-paloalto-threat/generator.yml \
  --id panw-threat \
  --live-mode
```

### Sample mode (generate as fast as possible)

```bash
eventum generate \
  --path generators/network-paloalto-threat/generator.yml \
  --id panw-threat \
  --live-mode false
```

### Adjust event rate

Edit the `count` value in `generator.yml` under `input.cron`:

```yaml
input:
  - cron:
      expression: "* * * * * *"
      count: 20  # 20 events per second
```

## Sample Output

### Spyware DNS Detection

```json
{
    "@timestamp": "2026-03-06T10:15:30.123456+00:00",
    "agent": {
        "ephemeral_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        "id": "e4f8c1a2-9b3d-4e5f-a6c7-d8e9f0a1b2c3",
        "name": "PA-5260",
        "type": "filebeat",
        "version": "8.17.0"
    },
    "destination": {
        "geo": {"name": "Russia"},
        "ip": "185.234.216.71",
        "port": 53
    },
    "ecs": {"version": "8.17.0"},
    "event": {
        "action": "threat",
        "category": ["intrusion_detection", "threat", "network"],
        "dataset": "panw.panos",
        "kind": "alert",
        "module": "panw",
        "outcome": "failure",
        "severity": 3,
        "type": ["denied"]
    },
    "host": {"name": "PA-5260"},
    "labels": {"nat_translated": true, "threat_denied": true},
    "log": {
        "level": "medium",
        "syslog": {
            "facility": {"code": 1, "name": "user-level"},
            "hostname": "PA-5260",
            "priority": 12,
            "severity": {"code": 4, "name": "Warning"}
        }
    },
    "network": {
        "application": "dns-base",
        "community_id": "1:a1b2c3d4e5f6a7b8c9d0",
        "direction": "outbound",
        "transport": "udp",
        "type": "ipv4"
    },
    "observer": {
        "egress": {"interface": {"name": "ethernet1/1"}, "zone": "untrust"},
        "hostname": "PA-5260",
        "ingress": {"interface": {"name": "ethernet1/2"}, "zone": "trust"},
        "product": "PAN-OS",
        "serial_number": "007200001056",
        "type": "firewall",
        "vendor": "Palo Alto Networks"
    },
    "panw": {
        "panos": {
            "action": "drop",
            "action_flags": "0x0",
            "content_version": "AppThreat-8840-8575",
            "flow_id": "3456789",
            "generated_time": "2026-03-06T10:15:30.123456+00:00",
            "log_profile": "Log-to-Syslog",
            "received_time": "2026-03-06T10:15:30.123456+00:00",
            "repeat_count": 1,
            "ruleset": "Anti-Spyware-DNS",
            "sequence_number": "100042",
            "sub_type": "spyware",
            "threat": {
                "id": "14001",
                "name": "Suspicious DNS Query (Generic:a]b.c2-beacon.xyz)"
            },
            "threat_category": "dns-malware",
            "type": "THREAT",
            "virtual_sys": "vsys1"
        }
    },
    "related": {
        "hosts": ["PA-5260", "malware-update.cn"],
        "ip": ["10.1.1.14", "185.234.216.71", "198.51.100.1"],
        "user": ["jsmith"]
    },
    "rule": {"name": "Anti-Spyware-DNS"},
    "source": {
        "geo": {"name": "10.0.0.0-10.255.255.255"},
        "ip": "10.1.1.14",
        "nat": {"ip": "198.51.100.1", "port": 34567},
        "port": 52340,
        "user": {"domain": "CORP", "name": "jsmith"}
    },
    "url": {"domain": "malware-update.cn", "original": "malware-update.cn"},
    "user": {"domain": "CORP", "name": "jsmith"}
}
```

## File Structure

```
network-paloalto-threat/
  generator.yml                              # Generator configuration
  README.md                                  # This file
  templates/
    spyware-dns.json.jinja                   # DNS-based spyware detections
    spyware-callback.json.jinja              # C2 callback detections
    vulnerability.json.jinja                 # IPS vulnerability signatures
    virus.json.jinja                         # Antivirus file detections
    wildfire.json.jinja                      # WildFire cloud verdicts
    file-scan.json.jinja                     # File type matching and scan detections
  samples/
    internal_hosts.csv                       # 15 internal workstation IPs
    usernames.csv                            # 15 Active Directory usernames
    threat_signatures.json                   # 70+ threat signatures organized by subtype
    applications.json                        # 6 PAN-OS App-IDs with weights
    malicious_domains.json                   # 65+ malicious domains by threat type
    security_rules.json                      # 7 threat prevention security policy rules
```

## References

- [PAN-OS Threat Log Fields](https://docs.paloaltonetworks.com/pan-os/11-0/pan-os-admin/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/threat-log-fields)
- [Threat Prevention Best Practices](https://docs.paloaltonetworks.com/best-practices/10/threat-prevention-best-practices)
- [Palo Alto Networks Threat Vault](https://threatvault.paloaltonetworks.com/)
- [Elastic panw Integration](https://docs.elastic.co/integrations/panw)
- [ECS Field Reference](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html)

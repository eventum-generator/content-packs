# PT Network Attack Discovery (PT NAD) Generator

Generates realistic PT NAD detection events in ECS-compatible JSON format, covering the full range of detection types exported via PT NAD's syslog integration to SIEM systems (MaxPatrol SIEM, Elastic, Splunk, etc.).

## Data Source

[PT Network Attack Discovery (PT NAD)](https://www.ptsecurity.com/ww-en/products/network-attack-discovery/) is a network traffic analysis (NTA) system by Positive Technologies that detects attacks on the perimeter and inside the network. It analyzes both north/south and east/west traffic, identifies 86+ protocols at Layer 7, detects 37+ types of suspicious activities, and maps all detections to MITRE ATT&CK TTPs. Detection rules are updated twice weekly by the PT Expert Security Center.

## Event Types

| Detection Type | Template | Distribution | Description |
|---|---|---|---|
| `session` | `network-session.json.jinja` | ~30% | Parsed protocol session metadata |
| `attack` | `attack-detection.json.jinja` | ~20% | Rule-based attack detection (IDS rules) |
| `suspicious_activity` | `suspicious-activity.json.jinja` | ~15% | Behavioral analysis detection |
| `reputation` | `reputation-alert.json.jinja` | ~10% | IOC/reputation list match |
| `protocol_anomaly` | `protocol-anomaly.json.jinja` | ~8% | Deep packet inspection anomaly |
| `lateral_movement` | `lateral-movement.json.jinja` | ~7% | East/west lateral movement |
| `c2_communication` | `connection-to-c2.json.jinja` | ~5% | Command & control channel detection |
| `credential_leak` | `credential-leak.json.jinja` | ~5% | Cleartext credential detection |

## Parameters

| Parameter | Default | Description |
|---|---|---|
| `nad_version` | `12.1.0.1234` | PT NAD platform version |
| `sensor_name` | `PT-NAD-01` | Sensor hostname |
| `sensor_ip` | `10.1.0.100` | Sensor IP address |
| `internal_subnet` | `10.1` | Internal network prefix |

## Usage

```bash
# Live mode (continuous generation)
eventum generate --path generators/security-pt-nad/generator.yml --id pt-nad --live-mode

# With custom parameters
eventum generate --path generators/security-pt-nad/generator.yml --id pt-nad --live-mode \
  --params '{"sensor_name": "PT-NAD-02", "sensor_ip": "10.2.0.100"}'
```

## Sample Output

```json
{
  "@timestamp": "2026-03-07T14:22:31.456Z",
  "event": {
    "kind": "alert",
    "module": "pt_nad",
    "dataset": "pt_nad.alert",
    "category": ["network", "intrusion_detection"],
    "type": ["denied"],
    "severity": 4,
    "outcome": "success"
  },
  "observer": {
    "vendor": "Positive Technologies",
    "product": "Network Attack Discovery",
    "version": "12.1.0.1234",
    "hostname": "PT-NAD-01",
    "ip": ["10.1.0.100"],
    "type": "ids"
  },
  "pt_nad": {
    "event_id": 1000042,
    "detection_type": "attack",
    "detection_method": "rules",
    "rule": {
      "id": "PT-10003",
      "name": "Kerberoasting: TGS Request for Service Account",
      "category": "Credential Access",
      "severity": "high"
    },
    "app_protocol": "kerberos",
    "sensor": "PT-NAD-01",
    "activity_id": 567891
  },
  "source": {"ip": "10.1.20.14", "port": 52341, "bytes": 1247, "packets": 12},
  "destination": {"ip": "10.1.1.10", "port": 88, "bytes": 8934, "packets": 15},
  "host": {
    "hostname": "DESKTOP-DEV03",
    "ip": ["10.1.20.14"],
    "os": {"name": "Windows", "version": "10.0.22631"},
    "domain": "CORP.ACME.COM"
  },
  "network": {
    "transport": "tcp",
    "protocol": "kerberos",
    "direction": "outbound",
    "bytes": 10181,
    "packets": 27
  },
  "rule": {
    "id": "PT-10003",
    "name": "Kerberoasting: TGS Request for Service Account",
    "category": "Credential Access"
  },
  "threat": {
    "framework": "MITRE ATT&CK",
    "tactic": {"id": ["TA0006"], "name": ["Credential Access"]},
    "technique": {"id": ["T1558.003"], "name": ["Kerberoasting"]}
  },
  "related": {
    "hosts": ["DESKTOP-DEV03"],
    "ip": ["10.1.20.14", "10.1.1.10"]
  }
}
```

## References

- [PT NAD product page](https://www.ptsecurity.com/ww-en/products/network-attack-discovery/)
- [PT NAD documentation portal](https://help.ptsecurity.com/en-US/projects/nad/11.1/help/1941174539)
- [PT NAD 10.2 suspicious activity types](https://global.ptsecurity.com/about/news/positive-technologies-upgrades-network-attack-discovery-solution-to-identify-33-new-types-of-suspicious-network-activities)
- [MITRE ATT&CK framework](https://attack.mitre.org/)

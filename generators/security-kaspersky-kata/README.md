# Kaspersky Anti Targeted Attack Platform (KATA) Generator

Generates realistic Kaspersky KATA detection events in ECS-compatible JSON format, covering the full range of detection types exported via KATA's syslog/CEF integration to SIEM systems.

## Data Source

[Kaspersky Anti Targeted Attack Platform (KATA)](https://www.kaspersky.com/enterprise-security/wiki-section/products/kaspersky-anti-targeted-attack-platform) is an enterprise threat detection platform that combines network traffic analysis, sandbox detonation, endpoint detection, and targeted attack analytics to identify advanced threats and APT campaigns.

## Event Types

| Detection Type | Template | Distribution | Description |
|---|---|---|---|
| `file_web` | `file-web.json.jinja` | ~15% | Malicious file downloaded via HTTP/FTP |
| `file_mail` | `file-mail.json.jinja` | ~10% | Malicious attachment detected in email |
| `ids` | `ids-event.json.jinja` | ~20% | Network intrusion detection (IDS rules) |
| `url_web` | `url-web.json.jinja` | ~12% | Malicious URL accessed via web |
| `url_mail` | `url-mail.json.jinja` | ~8% | Malicious URL found in email |
| `dns` | `dns-detection.json.jinja` | ~12% | Suspicious DNS query detected |
| `file_endpoint` | `file-endpoint.json.jinja` | ~10% | Suspicious file found on endpoint |
| `iocScanning` | `ioc-scanning.json.jinja` | ~5% | IOC match on endpoint |
| `taaScanning` | `taa-scanning.json.jinja` | ~5% | Behavioral analysis detection (TAA) |
| `heartbeat` | `heartbeat.json.jinja` | ~3% | Periodic component health status |

## Parameters

| Parameter | Default | Description |
|---|---|---|
| `kata_version` | `7.1.1.531` | KATA platform version |
| `central_node` | `KATA-CN01` | Central Node hostname |
| `central_node_ip` | `10.1.0.50` | Central Node IP address |
| `dns_server_ip` | `10.1.1.10` | Internal DNS server IP |

## Usage

```bash
# Live mode (continuous generation)
eventum generate --path generators/security-kaspersky-kata/generator.yml --id kata --live-mode

# With custom parameters
eventum generate --path generators/security-kaspersky-kata/generator.yml --id kata --live-mode \
  --params '{"central_node": "KATA-CN02", "central_node_ip": "10.2.0.50"}'
```

## Sample Output

```json
{
  "@timestamp": "2026-03-06T21:46:53.000Z",
  "event": {
    "kind": "alert",
    "module": "kaspersky",
    "dataset": "kaspersky.kata",
    "category": ["malware"],
    "type": ["info"],
    "severity": 4,
    "outcome": "success"
  },
  "observer": {
    "vendor": "Kaspersky",
    "product": "Anti Targeted Attack Platform",
    "version": "7.1.1.531",
    "hostname": "KATA-CN01",
    "ip": ["10.1.0.50"],
    "type": "ids"
  },
  "kaspersky": {
    "kata": {
      "event_id": 100019,
      "detection_type": "file_web",
      "detection_name": "File from web detected",
      "technology": "YARA",
      "threat": {
        "name": "HEUR:Exploit.MSOffice.CVE-2023-36884.gen",
        "category": "Exploit",
        "severity": "High"
      },
      "database_version": "20260306_2046",
      "sensor_id": "sensor-ws-03",
      "sandbox": {
        "verdict": "malicious",
        "risk_score": 90,
        "image": "Windows 10 x64"
      }
    }
  },
  "file": {
    "name": "genpooar.xlsx",
    "size": 4206,
    "type": "OLE",
    "hash": {
      "sha256": "4a17c8a...",
      "md5": "8a5976b..."
    }
  },
  "url": {
    "original": "http://data-collector.click/download/genpooar.xlsx",
    "domain": "data-collector.click"
  },
  "source": {"ip": "91.219.236.174", "port": 443},
  "destination": {"ip": "10.1.30.5", "port": 53546},
  "host": {
    "hostname": "LAPTOP-EXEC01",
    "ip": ["10.1.30.5"],
    "os": {"name": "Windows", "version": "11.0.22631"},
    "domain": "CORP.ACME.COM"
  },
  "user": {"name": "nwilson", "domain": "CORP"},
  "network": {"transport": "tcp", "protocol": "https", "direction": "inbound"},
  "related": {
    "hosts": ["LAPTOP-EXEC01", "data-collector.click"],
    "ip": ["10.1.30.5", "91.219.236.174"],
    "user": ["nwilson"],
    "hash": ["4a17c8a...", "8a5976b..."]
  }
}
```

## References

- [KATA syslog alert message format (v3.6)](https://support.kaspersky.com/KATA/3.6/en-US/175942.htm)
- [KATA detection syslog messages (v7.1)](https://support.kaspersky.co.uk/kata/7.1/247573)
- [KATA audit CEF messages (v4.0)](https://support.kaspersky.com/kata/4.0/en-US/208575.htm)
- [KATA product overview](https://support.kaspersky.com/kata/3.6/en-US/180914.htm)

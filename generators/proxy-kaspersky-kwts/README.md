# Kaspersky Web Traffic Security (KWTS) Proxy Generator

Generates realistic Kaspersky Web Traffic Security proxy/web gateway events in ECS-compatible JSON format, matching the syslog field structure documented for KWTS 6.1.

## Data Source

[Kaspersky Web Traffic Security](https://support.kaspersky.com/kwts/6.1) is an enterprise web gateway security solution that scans HTTP/HTTPS/FTP traffic passing through a proxy server (typically Squid). It provides antivirus scanning, anti-phishing protection, URL filtering, content filtering, and integration with Kaspersky Anti Targeted Attack (KATA).

## Event Types

| Template | Weight | Description |
|----------|--------|-------------|
| `allowed.json.jinja` | 75% | Normal allowed traffic (business apps, browsing, updates) |
| `allowed-scanned.json.jinja` | 10% | Allowed traffic that was scanned by AV (file downloads, clean) |
| `blocked-policy.json.jinja` | 6% | Blocked by URL filtering policy (adult, gambling, anonymizers) |
| `blocked-av.json.jinja` | 4% | Blocked by antivirus (malware, trojans, exploits detected) |
| `blocked-ap.json.jinja` | 3% | Blocked by anti-phishing (phishing URLs via KSN/heuristics) |
| `redirected.json.jinja` | 2% | Redirected to warning page (uncategorized, file sharing) |

## Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `kwts_hostname` | `kwts-node01.corp.example.com` | KWTS appliance hostname |
| `kwts_version` | `6.1.0.4372` | KWTS product version |
| `proxy_hostname` | `proxy-gw01.corp.example.com` | Proxy server hostname |
| `proxy_ip` | `10.10.0.1` | Proxy server IP |
| `company_domain` | `corp.example.com` | Corporate domain |
| `agent_id` | (uuid) | Elastic agent ID |
| `agent_version` | `8.17.0` | Elastic agent version |

## Usage

```bash
# Live mode (5 events/second)
eventum generate --path generators/proxy-kaspersky-kwts/generator.yml --id kwts --live-mode

# Sample mode (batch generation)
eventum generate --path generators/proxy-kaspersky-kwts/generator.yml --id kwts --live-mode false
```

## Sample Output

```json
{
    "@timestamp": "2026-03-07T10:23:45.123456+00:00",
    "agent": {
        "ephemeral_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        "id": "b7e3f1a2-9c4d-4e6f-8a1b-2c3d4e5f6789",
        "name": "kwts-node01.corp.example.com",
        "type": "filebeat",
        "version": "8.17.0"
    },
    "event": {
        "action": "blocked",
        "category": ["web", "network", "malware"],
        "dataset": "kaspersky_kwts.traffic",
        "kind": "alert",
        "module": "kaspersky_kwts",
        "outcome": "failure",
        "reason": "HEUR:Trojan.Script.Generic",
        "type": ["access", "denied", "connection"]
    },
    "kaspersky": {
        "kwts": {
            "action": "Block",
            "av_status": "Detected",
            "scan_result": "HEUR:Trojan.Script.Generic",
            "threat_name": "HEUR:Trojan.Script.Generic",
            "threat_category": "Trojan"
        }
    }
}
```

## References

- [KWTS 6.1 Documentation](https://support.kaspersky.com/kwts/6.1)
- [Contents of syslog messages about traffic processing events](https://support.kaspersky.com/KWTS/6.1/en-US/179953.htm)
- [CEF format syslog messages](https://support.kaspersky.co.uk/kwts/6.1/267200)
- [Syslog event log](https://support.kaspersky.com/KWTS/6.1/en-US/180301.htm)

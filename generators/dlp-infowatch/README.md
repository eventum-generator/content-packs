# InfoWatch Traffic Monitor (DLP) Generator

Produces realistic InfoWatch Traffic Monitor DLP events in CEF-over-JSON format, matching the event types exported via InfoWatch SIEM integration (CEF/syslog to ArcSight, RuSIEM, etc.).

InfoWatch Traffic Monitor is a Russian DLP system for data leak prevention that monitors email, web, messengers, cloud storage, USB/removable media, printing, clipboard, and screenshots.

## Event Types

| Template | Type | Chance | Description |
|----------|------|--------|-------------|
| `policy-violation` | Alert | 25% | DLP policy rule match -- blocks or alerts on confidential data |
| `content-capture` | Event | 35% | Routine traffic interception with no policy violation |
| `device-control` | Event | 12% | USB/removable media/Bluetooth device detection |
| `print-control` | Event | 8% | Print job monitoring and blocking |
| `system-event` | Event | 10% | InfoWatch system operational messages |
| `incident-update` | Event | 10% | Analyst workflow -- incident status changes |

## Monitored Channels

Email (SMTP/MAPI), web mail, web upload (cloud/social), instant messengers, USB/removable media, local/network printers, clipboard copy, network folders (SMB), FTP transfer, screenshot capture.

## DLP Policies

12 built-in policies covering: financial data, personal data (PD/SNILS), trade secrets, PCI DSS (credit cards), source code, database exports, contracts, resumes, profanity/harassment.

## Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `hostname` | `iwtm-srv01` | InfoWatch TM server hostname |
| `server_ip` | `10.1.0.10` | Server IP address |
| `iwtm_version` | `7.3.0` | InfoWatch Traffic Monitor version |
| `agent_id` | `f1ee4a83-...` | Elastic agent ID |
| `agent_version` | `8.17.0` | Elastic agent version |

## Usage

```bash
# Live mode (continuous generation)
eventum generate --path generators/dlp-infowatch/generator.yml --id iwtm --live-mode

# Sample mode (batch generation)
eventum generate --path generators/dlp-infowatch/generator.yml --id iwtm --live-mode false
```

## Sample Output

```json
{
  "@timestamp": "2026-03-06T21:54:29.000Z",
  "agent": {
    "ephemeral_id": "136b7fde-b9d6-4646-bfbf-f51bea2702a8",
    "id": "f1ee4a83-b99b-4611-925d-b83b001f8b86",
    "name": "iwtm-srv01",
    "type": "filebeat",
    "version": "8.17.0"
  },
  "cef": {
    "device": {
      "event_class_id": "230",
      "product": "Traffic Monitor",
      "vendor": "InfoWatch",
      "version": "7.3.0"
    },
    "extensions": {
      "categoryOutcome": "Blocked",
      "deviceAction": "block",
      "deviceCustomString1": "Personal Data",
      "deviceCustomString1Label": "DataCategory",
      "deviceCustomString2": "Passport Data Detection",
      "deviceCustomString2Label": "PolicyName",
      "deviceCustomString3": "high",
      "deviceCustomString3Label": "ViolationLevel",
      "deviceCustomString4": "pending",
      "deviceCustomString4Label": "IncidentStatus",
      "deviceCustomNumber1": 33855,
      "deviceCustomNumber1Label": "FileSize",
      "sourceUserName": "andreev_v",
      "destinationUserName": "docs@yandex.ru",
      "sourceAddress": "10.1.5.60",
      "destinationAddress": "77.88.55.60",
      "transportProtocol": "LOCAL",
      "fileName": "bank_details.txt",
      "filePath": "C:\\Users\\andreev_v\\Desktop\\bank_details.txt",
      "fileHash": "0d301a3879af9b5316e921b5a8df1e79cda20d2bc283c86aa7fa43bee8ac9220",
      "message": "Policy violation: Passport Data Detection triggered on Screenshot capture channel"
    },
    "name": "Policy Violation",
    "severity": 7,
    "version": "0"
  },
  "data_stream": {
    "dataset": "cef.log",
    "namespace": "default",
    "type": "logs"
  },
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "block",
    "category": ["intrusion_detection"],
    "code": "230",
    "dataset": "cef.log",
    "id": "1000015",
    "kind": "alert",
    "module": "cef",
    "outcome": "success",
    "severity": 7,
    "type": ["denied"]
  },
  "file": {
    "hash": {
      "sha256": "0d301a3879af9b5316e921b5a8df1e79cda20d2bc283c86aa7fa43bee8ac9220"
    },
    "name": "bank_details.txt",
    "path": "C:\\Users\\andreev_v\\Desktop\\bank_details.txt",
    "size": 33855
  },
  "message": "Policy violation: Passport Data Detection triggered on Screenshot capture channel",
  "rule": {
    "id": "POL-005",
    "name": "Passport Data Detection",
    "category": "data-loss-prevention"
  },
  "source": {
    "address": "10.1.5.60",
    "ip": "10.1.5.60",
    "user": {
      "domain": "CORP",
      "email": "v.andreev@corp.local",
      "full_name": "Vladislav Andreev",
      "name": "andreev_v"
    }
  },
  "related": {
    "ip": ["10.1.5.60", "77.88.55.60"],
    "user": ["andreev_v", "docs@yandex.ru"],
    "hash": ["0d301a3879af9b5316e921b5a8df1e79cda20d2bc283c86aa7fa43bee8ac9220"],
    "hosts": ["iwtm-srv01", "WS-ANDREEV"]
  }
}
```

## References

- [InfoWatch Traffic Monitor](https://infowatch.com/products/data-loss-prevention-traffic-monitor) -- official product page
- [Elastic CEF Integration](https://docs.elastic.co/en/integrations/cef) -- CEF log format ingestion into Elastic
- [InfoWatch SIEM Integration](https://www.infowatch.ru/products/dlp-sistema-traffic-monitor/integratsii-dlp-sistemy) -- SIEM connector documentation

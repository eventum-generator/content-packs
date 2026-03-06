# Kaspersky Security Center (KSC) Generator

Generates realistic Kaspersky Security Center events matching the event types exported via KSC syslog/CEF integration to SIEM systems. Events are produced in ECS-compatible JSON format.

## Data Source

[Kaspersky Security Center](https://support.kaspersky.com/KSC/14.2/en-US/) is the centralized management console for Kaspersky endpoint security products. It collects events from Kaspersky Endpoint Security (KES) agents, Network Agents, and the Administration Server itself, and exports them to SIEM systems via syslog (RFC 5424) or CEF format.

## Event Types

| Event Type | Event Class ID | Chance | Description |
|---|---|---|---|
| Threat Detected | `GNRL_EV_VIRUS_FOUND` | 12% | Malware/virus detection by KES components (File, Mail, Web, AMSI) |
| Network Attack | `GNRL_EV_ATTACK_DETECTED` | 8% | Network intrusion detection (exploits, scans, brute force, DoS) |
| Task Completed | `GNRL_EV_TASK_STATE_CHANGED` | 20% | Scan, update, patch, and deploy task completion |
| Update Status | `GNRL_EV_BASES_UPDATED/OUTDATED` | 15% | Signature database update success/failure |
| Device Status | `KLSRV_HOST_STATUS_*` | 15% | Managed device health (OK, Warning, Critical) |
| Policy Event | `KLSRV_EV_POLICY_*` / `GNRL_EV_APP_CTRL_BLOCKED` | 10% | Policy applied, violated, or changed |
| License Event | `GNRL_EV_LICENSE_*` / `KLSRV_EV_LICENSE_*` | 5% | License validation, expiration, limit exceeded |
| Protection Status | `GNRL_EV_APPLICATION_*` / `GNRL_EV_PROTECTION_*` | 8% | Component start/stop/enable/disable |
| Audit Event | `KLAUD_EV_SERVERACTION` | 7% | Admin console login, policy changes, task management |

## Parameters

| Parameter | Default | Description |
|---|---|---|
| `ksc_version` | `14.2.0.26967` | KSC Administration Server version |
| `ksc_server` | `KSC-SRV01` | KSC server hostname |
| `ksc_server_ip` | `10.1.0.10` | KSC server IP address |
| `kes_version` | `12.0.0.1131` | Kaspersky Endpoint Security version |
| `update_source` | `https://dnl-01.geo.kaspersky.com/` | Update source URL |
| `license_type` | `Kaspersky Endpoint Security for Business Advanced` | License product name |
| `license_count` | `500` | Licensed device count |

## Usage

```bash
# Live mode (5 events/second)
eventum generate --path generators/security-kaspersky-ksc/generator.yml --id ksc --live-mode

# Sample mode (generate batch and exit)
eventum generate --path generators/security-kaspersky-ksc/generator.yml --id ksc --live-mode false

# With custom parameters
eventum generate --path generators/security-kaspersky-ksc/generator.yml --id ksc --live-mode \
  --params '{"ksc_server": "KSC-PROD01", "license_count": 1000}'
```

## Sample Output

```json
{
  "@timestamp": "2026-03-07T14:22:31.456Z",
  "event": {
    "kind": "event",
    "module": "kaspersky",
    "dataset": "kaspersky.ksc",
    "category": ["malware"],
    "type": ["info"],
    "severity": 4,
    "outcome": "success",
    "timezone": "UTC",
    "created": "2026-03-07T14:22:31.456Z"
  },
  "observer": {
    "vendor": "Kaspersky",
    "product": "Security Center",
    "version": "14.2.0.26967",
    "hostname": "KSC-SRV01",
    "ip": ["10.1.0.10"]
  },
  "host": {
    "hostname": "DESKTOP-HR01",
    "ip": ["10.1.10.21"],
    "mac": ["00:50:56:8a:12:34"],
    "os": { "name": "Windows", "version": "10.0.19045" },
    "domain": "CORP.ACME.COM"
  },
  "kaspersky": {
    "ksc": {
      "event_id": 1000001,
      "event_class_id": "GNRL_EV_VIRUS_FOUND",
      "event_type": "Malicious object detected",
      "component": "File Threat Protection",
      "result": "Quarantined",
      "threat": { "name": "HEUR:Trojan.Win32.Generic", "level": "High" },
      "object": { "type": "File", "name": "C:\\Users\\jsmith\\Downloads\\invoice.exe" }
    }
  },
  "file": {
    "name": "invoice.exe",
    "path": "C:\\Users\\jsmith\\Downloads\\invoice.exe",
    "size": 245760,
    "hash": { "sha256": "a1b2c3...", "md5": "d4e5f6..." }
  },
  "user": { "name": "jsmith", "domain": "CORP" },
  "related": {
    "hosts": ["DESKTOP-HR01"],
    "ip": ["10.1.10.21"],
    "user": ["jsmith"],
    "hash": ["a1b2c3...", "d4e5f6..."]
  }
}
```

## References

- [Kaspersky Security Center 14.2 Documentation](https://support.kaspersky.com/KSC/14.2/en-US/)
- [About events in Kaspersky Security Center](https://support.kaspersky.com/KSC/14.2/en-US/151331.htm)
- [Export of events to SIEM systems](https://support.kaspersky.com/help/KSC/13/en-US/151332.htm)
- [KES for Windows event types](https://support.kaspersky.com/keswin/12.0/en-us/214871.htm)
- [Administration Server critical events](https://support.kaspersky.com/KSC/CloudConsole/en-US/177080.htm)

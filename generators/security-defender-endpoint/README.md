# Microsoft Defender for Endpoint (EDR) Generator

Produces realistic Microsoft Defender for Endpoint Advanced Hunting events matching the JSON structure streamed to Microsoft Sentinel via the Microsoft 365 Defender data connector. Events cover the 8 core Advanced Hunting tables used for EDR telemetry.

## Event Types

| Template | Category | Weight | Description |
|----------|----------|--------|-------------|
| `process-events.json.jinja` | DeviceProcessEvents | 33 | Process creation events with full PE metadata |
| `network-events.json.jinja` | DeviceNetworkEvents | 28 | Network connections (TCP/UDP, inbound/outbound) |
| `file-events.json.jinja` | DeviceFileEvents | 22 | File create, modify, delete, rename operations |
| `registry-events.json.jinja` | DeviceRegistryEvents | 9 | Registry key/value modifications |
| `image-load-events.json.jinja` | DeviceImageLoadEvents | 4 | DLL/image load events |
| `logon-events.json.jinja` | DeviceLogonEvents | 2 | Interactive, network, remote logon events |
| `device-events.json.jinja` | DeviceEvents | 1.5 | AV scans, USB mounts, firewall blocks, services |
| `alert-info.json.jinja` | AlertInfo | 0.5 | Security alerts with MITRE ATT&CK techniques |

## Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `tenant` | `Contoso` | Tenant display name in event envelope |
| `domain` | `CONTOSO` | NetBIOS domain name |
| `fqdn_suffix` | `contoso.com` | DNS suffix for device FQDNs |
| `domain_sid` | `S-1-5-21-...` | Domain SID prefix for user SIDs |
| `tenant_id` | `3adb963c-...` | Azure AD tenant ID (GUID) |

## Usage

```bash
# Live mode (5 events/sec, continuous)
eventum generate --path generators/security-defender-endpoint/generator.yml --id mde --live-mode

# Batch mode (generate and exit)
eventum generate --path generators/security-defender-endpoint/generator.yml --id mde --live-mode false

# Custom parameters
eventum generate --path generators/security-defender-endpoint/generator.yml --id mde --live-mode \
  --param tenant=Fabrikam \
  --param domain=FABRIKAM \
  --param fqdn_suffix=fabrikam.com
```

## Sample Output

### AlertInfo

```json
{"Tenant": "Contoso", "category": "AdvancedHunting-AlertInfo", "operationName": "Publish", "properties": {"Timestamp": "2026-03-05T21:48:29.890Z", "AlertId": "da638034938542563831_394601025", "Title": "Suspicious credential access via LSASS", "Category": "CredentialAccess", "Severity": "High", "ServiceSource": "Microsoft Defender for Endpoint", "DetectionSource": "EDR", "AttackTechniques": "[\"OS Credential Dumping (T1003)\",\"LSASS Memory (T1003.001)\"]", "MachineGroup": null}, "tenantId": "3adb963c-8e61-48e8-a06d-6dbb0dacea39", "time": "2026-03-05T21:52:16.047Z"}
```

## References

- [Microsoft Defender for Endpoint Advanced Hunting schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables)
- [DeviceProcessEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table)
- [DeviceNetworkEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table)
- [DeviceFileEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table)
- [DeviceRegistryEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceregistryevents-table)
- [DeviceImageLoadEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceimageloadevents-table)
- [DeviceLogonEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicelogonevents-table)
- [DeviceEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceevents-table)
- [AlertInfo](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-alertinfo-table)

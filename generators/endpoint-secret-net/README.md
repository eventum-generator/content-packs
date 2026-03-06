# Secret Net Studio Endpoint Security Generator

Generates realistic Secret Net Studio events matching the event types produced by the Secret Net Studio endpoint protection and access control solution by Security Code (Код Безопасности). Events are produced in ECS-compatible JSON format.

## Data Source

[Secret Net Studio](https://www.securitycode.ru/products/secret-net-studio/) is a certified endpoint protection platform by Security Code (Код Безопасности), widely deployed in Russian government, defense, and critical infrastructure organizations. It provides multi-layer workstation and server protection including mandatory/discretionary access control, integrity monitoring, device control, closed software environment, network protection, and data protection with secure erasure and shadow copying.

## Event Types

| Event Type | Event Class Prefix | Chance | Description |
|---|---|---|---|
| Authentication | `SN_AUTH_*` | 25% | Login, logout, failed auth, lock/unlock, token authentication |
| Discretionary Access | `SN_DAC_*` | 18% | File/folder/registry access grants and denials |
| Integrity Control | `SN_INTEGRITY_*` | 15% | File/registry integrity checks — pass, fail, modified, missing |
| Device Control | `SN_DEVICE_*` | 12% | USB/peripheral connect, disconnect, block, allow, read-only |
| Mandatory Access | `SN_MAC_*` | 8% | Confidentiality level access checks and label operations |
| Closed Environment | `SN_CSE_*` | 7% | Blocked/warned/allowed application execution |
| Network Protection | `SN_NET_*` | 7% | Firewall rule matches, connection allow/block, intrusion attempts |
| Data Protection | `SN_DATA_*` | 4% | Secure erasure, shadow copying, print marking |
| Audit | `SN_AUDIT_*` | 4% | Admin actions, policy changes, configuration modifications |

## Parameters

| Parameter | Default | Description |
|---|---|---|
| `sn_version` | `8.10.0.1573` | Secret Net Studio version |
| `sn_server` | `SN-SRV01` | Secret Net management server hostname |
| `sn_server_ip` | `10.1.0.15` | Secret Net management server IP |
| `domain` | `CORP.ACME.COM` | Active Directory domain |
| `organization` | `ACME Corp` | Organization name |

## Usage

```bash
# Live mode (5 events/second)
eventum generate --path generators/endpoint-secret-net/generator.yml --id sn --live-mode

# Sample mode (generate batch and exit)
eventum generate --path generators/endpoint-secret-net/generator.yml --id sn --live-mode false

# With custom parameters
eventum generate --path generators/endpoint-secret-net/generator.yml --id sn --live-mode \
  --params '{"sn_server": "SN-PROD01", "domain": "SECURE.GOV.RU"}'
```

## Sample Output

```json
{
  "@timestamp": "2026-03-07T10:15:23.456Z",
  "event": {
    "kind": "event",
    "module": "secret_net",
    "dataset": "secret_net.endpoint",
    "category": ["authentication"],
    "type": ["start"],
    "severity": 1,
    "outcome": "success",
    "timezone": "UTC",
    "created": "2026-03-07T10:15:23.456Z"
  },
  "observer": {
    "vendor": "Security Code",
    "product": "Secret Net Studio",
    "version": "8.10.0.1573",
    "hostname": "SN-SRV01",
    "ip": ["10.1.0.15"]
  },
  "host": {
    "hostname": "DESKTOP-FIN02",
    "ip": ["10.1.10.35"],
    "mac": ["00:50:56:8a:23:45"],
    "os": { "name": "Windows 10", "version": "10.0.19045" },
    "domain": "CORP.ACME.COM"
  },
  "secret_net": {
    "event_id": 1000001,
    "event_class": "SN_AUTH_LOGIN_OK",
    "subsystem": "Идентификация и аутентификация",
    "action": "login_success",
    "description": "Успешный вход в систему",
    "auth_method": "password+token",
    "logon_type": 2,
    "computer_level": "Строго конфиденциально"
  },
  "user": {
    "name": "sidorova.en",
    "full_name": "Сидорова Елена Николаевна",
    "domain": "CORP"
  },
  "related": {
    "hosts": ["DESKTOP-FIN02"],
    "ip": ["10.1.10.35"],
    "user": ["sidorova.en"]
  }
}
```

## Key Design Decisions

- **Picking mode**: `chance` — Secret Net events are independent, not session-based; each event type has its own probability weight
- **Shared state**: Used for monotonically increasing `event_id` counter across all event types
- **Russian locale**: Event descriptions and field values use Russian to match real Secret Net Studio output
- **Confidentiality levels**: Three-tier system (Несекретно, Конфиденциально, Строго конфиденциально) matching Russia's classification scheme
- **Subsystem mapping**: Each template maps to a distinct Secret Net subsystem for accurate categorization

## References

- [Secret Net Studio Product Page](https://www.securitycode.ru/products/secret-net-studio/)
- [Secret Net Studio Documentation](https://docs.securitycode.ru/products/secret_net_studio/)
- [Secret Net LSP (Linux)](https://www.securitycode.net/products/szi_secret_net/)
- [Security Code Company](https://www.securitycode.ru/)
- [ФСТЭК Certification Info](https://cryptostore.ru/article/obzory/secret_net_vozmozhnosti_po_zashchite_informatsii_ot_nsd/)

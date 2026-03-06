# Palo Alto Networks GlobalProtect VPN Event Generator

Produces realistic PAN-OS GlobalProtect VPN events in ECS-compatible JSON format, matching the field structure used by the [Elastic panw integration](https://docs.elastic.co/integrations/panw). GlobalProtect logs record the full VPN client lifecycle: portal prelogin, authentication (portal and gateway), configuration retrieval, IPSec tunnel establishment, HIP (Host Information Profile) checks, tunnel latency monitoring, configuration release, and user logout.

## Event Types

| Template | Event ID | Stage | Frequency | Description |
|----------|----------|-------|-----------|-------------|
| `portal-prelogin.json.jinja` | portal-prelogin | before-login | ~10% | Portal prelogin cookie request |
| `portal-auth.json.jinja` | portal-auth | login | ~8% | Portal authentication (LDAP, SAML, Certificate, RADIUS) |
| `portal-getconfig.json.jinja` | portal-getconfig | configuration | ~8% | Portal configuration retrieval |
| `gateway-auth.json.jinja` | gateway-auth | login | ~10% | Gateway authentication (success) |
| `gateway-auth-failure.json.jinja` | gateway-auth | login | ~0.5% | Gateway authentication failure |
| `gateway-getconfig.json.jinja` | gateway-getconfig | configuration | ~8% | Gateway configuration retrieval (IPSec/SSL-VPN) |
| `gateway-setup-ipsec.json.jinja` | gateway-setup-ipsec | tunnel | ~8% | IPSec tunnel establishment |
| `gateway-hip-check.json.jinja` | gateway-hip-check | host-info | ~21% | Host Information Profile check |
| `gateway-tunnel-latency.json.jinja` | gateway-tunnel-latency | tunnel | ~16% | Tunnel latency measurement |
| `gateway-config-release.json.jinja` | gateway-config-release | configuration | ~3% | Gateway configuration release |
| `gateway-logout.json.jinja` | gateway-logout | tunnel | ~5% | User logout with session duration |

## Realism Features

- **Weighted event distribution** -- 11 templates with realistic enterprise frequency (HIP checks most frequent, auth failures rare)
- **Authentication methods** -- LDAP (~50%), SAML (~30%), Certificate (~15%), RADIUS (~5%)
- **Connection methods** -- user-logon (~50%), pre-logon (~20%), on-demand (~20%), manual (~10%)
- **Tunnel types** -- IPSec (~90%), SSL-VPN (~10%) for gateway config retrieval
- **HIP check variation** -- "HIP report is not needed" (~70%) vs "HIP report processed successfully" (~30%)
- **Latency metrics** -- Gaussian-distributed pre-tunnel (~100ms) and post-tunnel (~65ms) latency
- **Session durations** -- Exponential distribution with ~4 hour mean for logout events
- **Auth failure realism** -- Three error types: "Authentication failed", "Invalid credentials", "User not found"
- **Multi-platform clients** -- Windows, macOS, Linux with matching GP client versions
- **Machine/platform correlation** -- Each machine maps to a specific OS platform via os_index
- **Geographic diversity** -- Source geo weighted toward US, UK, Germany, Canada, India
- **Monotonic sequence numbers** -- Sequence counter increments across all events with no gaps
- **Multiple gateways** -- 5 gateways across US-East, US-West, EU-West, EU-Central, APAC

## Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `hostname` | `PA-5260` | PAN-OS firewall hostname |
| `serial_number` | `007200001056` | Firewall serial number |
| `domain` | `CORP` | Active Directory domain name |
| `virtual_sys` | `vsys1` | Virtual system name |
| `agent_id` | `e4f8c1a2-...` | Elastic Agent ID |
| `agent_version` | `8.17.0` | Elastic Agent version |

## Usage

### Run the generator

```bash
eventum generate \
  --path generators/vpn-paloalto-globalprotect/generator.yml \
  --id gp-vpn \
  --live-mode
```

### Sample mode (generate as fast as possible)

```bash
eventum generate \
  --path generators/vpn-paloalto-globalprotect/generator.yml \
  --id gp-vpn \
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

### Gateway Authentication

```json
{
    "@timestamp": "2026-03-06T18:57:31+00:00",
    "agent": {
        "ephemeral_id": "093755d4-c40e-4de3-9af3-376d3e09cb81",
        "id": "e4f8c1a2-9b3d-4e5f-a6c7-d8e9f0a1b2c3",
        "name": "PA-5260",
        "type": "filebeat",
        "version": "8.17.0"
    },
    "ecs": {"version": "8.17.0"},
    "event": {
        "action": "globalprotect",
        "category": ["network", "authentication"],
        "code": "gateway-auth",
        "dataset": "panw.panos",
        "duration": 0,
        "kind": "event",
        "module": "panw",
        "outcome": "success"
    },
    "host": {
        "id": "b2c3d4e5-4444-4bbb-c444-444444444444",
        "ip": ["192.168.63.115"],
        "name": "desktop-fin02",
        "os": {"family": "windows", "full": "Microsoft Windows 11 Pro 10.0.22631"}
    },
    "log": {
        "syslog": {
            "facility": {"code": 1, "name": "user-level"},
            "hostname": "PA-5260",
            "priority": 14,
            "severity": {"code": 6, "name": "Informational"}
        }
    },
    "observer": {
        "hostname": "PA-5260",
        "product": "PAN-OS",
        "serial_number": "007200001056",
        "type": "firewall",
        "vendor": "Palo Alto Networks"
    },
    "panw": {
        "panos": {
            "action_flags": "0x0",
            "auth_method": "LDAP",
            "client_ver": "6.2.4-116",
            "connect_method": "user-logon",
            "description": "Gateway authentication successful via LDAP",
            "error_code": 0,
            "error_message": "",
            "event": {"id": "gateway-auth", "reason": "", "status": "success"},
            "generated_time": "2026-03-06T18:57:31+00:00",
            "login_duration": 0,
            "machine": {"mac_address": "00:1a:2b:3c:4d:04", "name": "DESKTOP-FIN02"},
            "portal": "gw-apac-01",
            "received_time": "2026-03-06T18:57:31+00:00",
            "repeat_count": 1,
            "selection_type": "",
            "sequence_number": "100009",
            "serial_number": "007200001056",
            "stage": "login",
            "type": "GLOBALPROTECT",
            "virtual_sys": "vsys1"
        }
    },
    "related": {
        "hosts": ["PA-5260", "desktop-fin02"],
        "ip": ["174.230.43.107", "192.168.63.115"],
        "user": ["rmoore"]
    },
    "source": {
        "ip": "192.168.63.115",
        "nat": {"ip": "174.230.43.107"},
        "user": {"domain": "CORP", "name": "rmoore"}
    },
    "user": {"domain": "CORP", "name": "rmoore"}
}
```

## File Structure

```
vpn-paloalto-globalprotect/
  generator.yml                              # Generator configuration
  README.md                                  # This file
  templates/
    portal-prelogin.json.jinja               # Portal prelogin cookie request
    portal-auth.json.jinja                   # Portal authentication
    portal-getconfig.json.jinja              # Portal configuration retrieval
    gateway-auth.json.jinja                  # Gateway authentication (success)
    gateway-auth-failure.json.jinja          # Gateway authentication (failure)
    gateway-getconfig.json.jinja             # Gateway config with tunnel type
    gateway-setup-ipsec.json.jinja           # IPSec tunnel establishment
    gateway-hip-check.json.jinja             # Host Information Profile check
    gateway-tunnel-latency.json.jinja        # Tunnel latency measurement
    gateway-config-release.json.jinja        # Gateway configuration release
    gateway-logout.json.jinja                # User logout with session duration
  samples/
    usernames.csv                            # 12 Active Directory usernames with full names
    client_platforms.json                    # 7 client platform combos (Windows, macOS, Linux)
    gateways.json                            # 5 GlobalProtect gateways across regions
    machines.json                            # 17 endpoint machines with OS mapping
```

## References

- [PAN-OS GlobalProtect Log Fields](https://docs.paloaltonetworks.com/pan-os/11-0/pan-os-admin/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/globalprotect-log-fields)
- [GlobalProtect Admin Guide](https://docs.paloaltonetworks.com/globalprotect/10-1/globalprotect-admin)
- [Elastic panw Integration](https://docs.elastic.co/integrations/panw)
- [ECS Field Reference](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html)

# Cisco AnyConnect VPN Event Generator

Produces realistic Cisco ASA AnyConnect VPN syslog events (ECS-compatible JSON) matching the output of the Elastic Agent `cisco_asa` integration. Events cover the full VPN session lifecycle: authentication, tunnel establishment, IP assignment, DAP evaluation, session roaming, and disconnection with traffic statistics.

## Event Types Covered

| Message ID | Event Type | Description | Frequency | ECS Action |
|------------|------------|-------------|-----------|------------|
| 113004 | Auth Success | AAA authentication successful | ~11.2% | `logged-in` |
| 113005 | Auth Rejected | AAA authentication rejected | ~0.9% | `logon-failed` |
| 113039 | Session Started | AnyConnect parent session started | ~11.2% | `client-vpn-connected` |
| 722022 | Tunnel Established | SVC connection established (TCP/UDP) | ~20.1% | `client-vpn-connected` |
| 722051 | IP Assigned | IPv4 address assigned to session | ~11.2% | `address-assigned` |
| 734001 | DAP Selected | Dynamic Access Policy records selected | ~11.2% | `logged-in` |
| 722023 | Tunnel Terminated | SVC connection terminated | ~19.0% | `client-vpn-disconnected` |
| 716002 | Session Terminated | WebVPN session terminated with reason | ~5.6% | `client-vpn-disconnected` |
| 113019 | Session Disconnected | Session disconnect with duration/bytes/reason | ~6.7% | `client-vpn-disconnected` |
| 716058 | Session Lost | AnyConnect session lost connection | ~1.7% | `client-vpn-disconnected` |
| 716059 | Session Resumed | AnyConnect session resumed from new IP | ~1.3% | `client-vpn-resumed` |

## Realism Features

- **Weighted event distribution** matching production AnyConnect VPN traffic patterns
- **Correlated VPN sessions** — session start events (113039) produce session context consumed by disconnect events (113019) with matching user/group/IP
- **Correlated tunnels** — tunnel established (722022) and terminated (722023) events share protocol, user, and compression state
- **Session roaming** — lost sessions (716058) are correlated with resume events (716059), with 40% chance of IP change (network roaming)
- **Realistic disconnect reasons** — weighted distribution: User Requested (45%), Idle Timeout (25%), Max Time Exceeded (8%), Lost Service (7%), Connection Preempted (5%), DPD Failure (4%)
- **Session duration distribution** — short (<5 min, 10%), medium (5 min–1 hr, 20%), long (1–4 hrs, 25%), workday (4–9 hrs, 35%), extended (>9 hrs, 10%)
- **Traffic statistics** — realistic bytes transmitted/received per session
- **Client platform diversity** — 12 Cisco Secure Client / AnyConnect versions across Windows, macOS, and Linux with weighted distribution
- **Authentication failure scenarios** — 70% real users (typos), 30% attacker-style usernames (admin, root, test)
- **Multiple tunnel groups and group policies** — CorpVPN, EMPLOYEE_VPN, CONTRACTOR_VPN with weighted selection
- **DAP record combinations** — 5 realistic policy combinations (DfltAccessPolicy, CorpCompliance, FullTunnel, etc.)
- **Original syslog messages** — each event includes `event.original` with the raw ASA syslog format
- **Full ECS compliance** — `cisco.asa.*` namespace, `observer.*`, `source.*`, `related.*`, `data_stream.*` fields

## Parameters

### Event Parameters

Edit the `params` section under `event.template` in `generator.yml`:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `hostname` | `ASA-FW-01` | ASA device hostname |
| `domain` | `corp.example.com` | Domain for FQDN construction |
| `outside_interface` | `outside` | External interface name |
| `vpn_pool_network` | `10.10.10` | VPN IP pool /24 prefix (first 3 octets) |
| `asa_ip` | `203.0.113.1` | ASA outside IP address |
| `agent_id` | `a1b2c3d4-...` | Filebeat agent ID |
| `agent_version` | `8.17.0` | Filebeat version string |

## Usage

```bash
# Install Eventum
uv tool install eventum-generator

# Run the generator
eventum generate \
  --path generators/vpn-cisco-anyconnect/generator.yml \
  --id vpn \
  --live-mode
```

### Adjusting Event Rate

Change the `count` in the input section:

```yaml
input:
  - cron:
      expression: "* * * * * *"
      count: 5    # 5 events/second (300/min, 18K/hour)
```

## Sample Output

### AnyConnect Session Started (113039)

```json
{
    "@timestamp": "2026-02-21T14:32:18.000000+00:00",
    "agent": {
        "ephemeral_id": "f1a2b3c4-d5e6-7890-abcd-ef1234567890",
        "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        "name": "ASA-FW-01.corp.example.com",
        "type": "filebeat",
        "version": "8.17.0"
    },
    "cisco": {
        "asa": {
            "message_id": "113039"
        }
    },
    "data_stream": {
        "dataset": "cisco_asa.log",
        "namespace": "default",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "event": {
        "action": "client-vpn-connected",
        "category": ["network", "session"],
        "code": "113039",
        "dataset": "cisco_asa.log",
        "kind": "event",
        "module": "cisco_asa",
        "original": "<166>Feb 21 2026 14:32:18 ASA-FW-01 : %ASA-6-113039: Group <GP_AnyConnect> User <jsmith> IP <198.51.100.42> AnyConnect parent session started.",
        "outcome": "success",
        "severity": 6,
        "type": ["connection", "start"]
    },
    "host": {
        "hostname": "ASA-FW-01"
    },
    "log": {
        "level": "informational",
        "syslog": {
            "facility": {"code": 20},
            "priority": 166,
            "severity": {"code": 6}
        }
    },
    "observer": {
        "hostname": "ASA-FW-01",
        "name": "ASA-FW-01.corp.example.com",
        "product": "asa",
        "type": "firewall",
        "vendor": "Cisco"
    },
    "related": {
        "hosts": ["ASA-FW-01"],
        "ip": ["198.51.100.42"],
        "user": ["jsmith"]
    },
    "source": {
        "address": "198.51.100.42",
        "ip": "198.51.100.42",
        "user": {
            "group": {"name": "GP_AnyConnect"},
            "name": "jsmith"
        }
    },
    "tags": ["cisco-asa", "forwarded"]
}
```

### Session Disconnected (113019)

```json
{
    "@timestamp": "2026-02-21T22:04:33.000000+00:00",
    "agent": {
        "ephemeral_id": "d4e5f6a7-b8c9-0123-4567-890abcdef012",
        "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        "name": "ASA-FW-01.corp.example.com",
        "type": "filebeat",
        "version": "8.17.0"
    },
    "cisco": {
        "asa": {
            "message_id": "113019",
            "session_type": "SSL"
        }
    },
    "data_stream": {
        "dataset": "cisco_asa.log",
        "namespace": "default",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "event": {
        "action": "client-vpn-disconnected",
        "category": ["network"],
        "code": "113019",
        "dataset": "cisco_asa.log",
        "duration": 27135000000000,
        "end": "2026-02-21T22:04:33.000000+00:00",
        "kind": "event",
        "module": "cisco_asa",
        "original": "<164>Feb 21 2026 22:04:33 ASA-FW-01 : %ASA-4-113019: Group = GP_AnyConnect, Username = jsmith, IP = 198.51.100.42, Session disconnected. Session Type: SSL, Duration: 7h:32m:15s, Bytes xmt: 45678901, Bytes rcv: 152345678, Reason: User Requested",
        "reason": "User Requested",
        "severity": 4,
        "type": ["connection", "end"]
    },
    "host": {
        "hostname": "ASA-FW-01"
    },
    "log": {
        "level": "warning",
        "syslog": {
            "facility": {"code": 20},
            "priority": 164,
            "severity": {"code": 4}
        }
    },
    "observer": {
        "hostname": "ASA-FW-01",
        "name": "ASA-FW-01.corp.example.com",
        "product": "asa",
        "type": "firewall",
        "vendor": "Cisco"
    },
    "related": {
        "hosts": ["ASA-FW-01"],
        "ip": ["198.51.100.42"],
        "user": ["jsmith"]
    },
    "source": {
        "bytes": 45678901,
        "user": {
            "group": {"name": "GP_AnyConnect"},
            "name": "jsmith"
        }
    },
    "destination": {
        "bytes": 152345678
    },
    "tags": ["cisco-asa", "forwarded"]
}
```

## File Structure

```
vpn-cisco-anyconnect/
  generator.yml                                # Pipeline config (input → event → output)
  README.md                                    # This file
  samples/
    usernames.csv                              # 25 VPN usernames with department
    client_platforms.json                      # 12 AnyConnect/Secure Client versions with OS and weights
  templates/
    113004-auth-success.json.jinja             # AAA authentication successful
    113005-auth-rejected.json.jinja            # AAA authentication rejected
    113019-session-disconnected.json.jinja     # Session disconnected (duration, bytes, reason)
    113039-session-started.json.jinja          # AnyConnect parent session started (producer)
    716002-session-terminated.json.jinja       # WebVPN session terminated
    716058-session-lost.json.jinja             # AnyConnect session lost connection (producer)
    716059-session-resumed.json.jinja          # AnyConnect session resumed (consumer)
    722022-tunnel-established.json.jinja       # SVC tunnel established TCP/UDP (producer)
    722023-tunnel-terminated.json.jinja        # SVC tunnel terminated (consumer)
    722051-ip-assigned.json.jinja              # IPv4 address assigned to session
    734001-dap-selected.json.jinja             # DAP records selected for connection
```

## References

- [Cisco Secure Firewall ASA Series Syslog Messages](https://www.cisco.com/c/en/us/td/docs/security/asa/syslog/asa-syslog.html)
- [Cisco ASA Syslog Messages 101001–199027](https://www.cisco.com/c/en/us/td/docs/security/asa/syslog/asa-syslog/syslog-messages-101001-to-199021.html)
- [Cisco ASA Syslog Messages 722001–776020](https://www.cisco.com/c/en/us/td/docs/security/asa/syslog/asa-syslog/syslog-messages-722001-to-776020.html)
- [Elastic Cisco ASA Integration](https://github.com/elastic/integrations/tree/main/packages/cisco_asa)
- [Elastic Common Schema (ECS) Reference](https://www.elastic.co/guide/en/ecs/current/index.html)
- [Cisco AnyConnect / Secure Client Documentation](https://www.cisco.com/c/en/us/support/security/secure-client-5/model.html)

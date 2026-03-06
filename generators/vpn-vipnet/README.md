# ViPNet Coordinator VPN/Firewall

Generates realistic InfoTeCS ViPNet Coordinator HW events — a Russian-certified VPN crypto-gateway and firewall that uses GOST cryptographic algorithms for securing network communications within ViPNet protected networks.

## Data Source

**ViPNet Coordinator HW** by InfoTeCS is a hardware/software security gateway providing:
- Site-to-site and client-to-site VPN tunnels with GOST encryption
- Network firewall with stateful packet inspection
- IP packet journal with event codes for traffic anomalies
- Node authentication and key management within ViPNet network

## Event Types

| Template | Event | Chance | Description |
|----------|-------|--------|-------------|
| `tunnel-established` | Tunnel up | 50 | VPN tunnel between coordinators/clients established |
| `tunnel-destroyed` | Tunnel down | 40 | VPN tunnel torn down (timeout, admin, rekeying) |
| `auth-success` | Auth success | 60 | User/admin authentication via web, CLI, or ViPNet Client |
| `auth-failure` | Auth failure | 8 | Failed authentication attempt |
| `firewall-allowed` | FW allow | 300 | Firewall rule allowed traffic |
| `firewall-blocked` | FW block | 60 | Firewall rule blocked traffic |
| `packet-encrypted` | Encrypted packet | 250 | IP packet encrypted and forwarded through VPN |
| `packet-unencrypted` | Event 22 | 10 | Non-encrypted packet from network node (security alert) |
| `config-changed` | Config change | 5 | Configuration modification by administrator |
| `keepalive` | Keepalive | 80 | Node liveness monitoring with latency |
| `time-sync-error` | Event 4 | 3 | Time divergence between nodes exceeds threshold |

## Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `hostname` | `VIPNET-GW-01` | Coordinator hostname |
| `domain` | `corp.example.ru` | Domain suffix |
| `agent_id` | (UUID) | Elastic Agent ID |
| `agent_version` | `8.17.0` | Agent version |
| `max_timediff` | `7200` | Max allowed time difference (seconds) |

## Usage

```bash
eventum generate --path generators/vpn-vipnet/generator.yml --id vipnet --live-mode
```

## Sample Output

```json
{
    "@timestamp": "2026-03-07T10:15:30.000000+00:00",
    "event": {
        "action": "tunnel-established",
        "category": ["network"],
        "kind": "event",
        "module": "vipnet",
        "outcome": "success",
        "type": ["connection", "start", "allowed"]
    },
    "observer": {
        "product": "ViPNet Coordinator",
        "type": "vpn",
        "vendor": "InfoTeCS"
    },
    "vipnet": {
        "coordinator": {
            "tunnel_type": "site-to-site",
            "encryption_algorithm": "GOST R 34.12-2015 (Kuznechik)",
            "local_node": {"id": "0x1A0E0001", "name": "Coordinator-HQ"},
            "remote_node": {"id": "0x1A0E0002", "name": "Coordinator-SPB"}
        }
    }
}
```

## References

- [InfoTeCS ViPNet Coordinator HW](https://infotecs.ru/products/vipnet-coordinator-hw/)
- [ViPNet Coordinator HW Reference Guide](https://manualzz.com/doc/26284283/vipnet-coordinator-hw-va.-reference-guide)
- [ViPNet SIEM Integration (R-Vision)](https://docs.rvision.ru/sources/ru/latest/NGFW/z_infotecs-vipnet-coordinator-4-guide.html)

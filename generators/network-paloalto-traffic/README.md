# Palo Alto Networks Traffic Log Generator

Produces realistic PAN-OS Traffic log events in ECS-compatible JSON format, matching the field structure used by the [Elastic panw integration](https://docs.elastic.co/integrations/panw). Traffic logs record network session information including session start, end, drop, and deny events with zone-aware flow profiles, NAT translation, and byte/packet counters.

## Event Types

| Template | Subtype | Action | Frequency | Description |
|----------|---------|--------|-----------|-------------|
| `traffic-end.json.jinja` | end | allow | ~72% | Completed session with bytes/packets/duration |
| `traffic-start.json.jinja` | start | allow | ~14% | New session initiation (zero counters) |
| `traffic-drop.json.jinja` | drop | drop/drop-icmp | ~7% | Silently dropped packets |
| `traffic-deny.json.jinja` | deny | deny/reset-* | ~7% | Policy-denied connections |

## Realism Features

- **Zone-aware flow profiles** -- 4 traffic directions (trust->untrust 70%, untrust->dmz 15%, trust->trust 10%, dmz->trust 5%) with correct interfaces and NAT behavior
- **Lognormal byte distributions** -- Realistic traffic volume using `lognormal()` for bytes_sent/bytes_received with proper clamping
- **Protocol-aware session end reasons** -- TCP sessions end with tcp-fin (38%), aged-out (21%), tcp-rst-from-client (10%), etc.; UDP/ICMP always aged-out
- **Session flags** -- 0x400053 for TCP, 0x400000 for UDP/ICMP, 0x0 for drops/denies
- **30 PAN-OS App-IDs** -- Weighted application distribution (ssl 300, web-browsing 180, dns 90, etc.) with protocol, port, category, risk metadata
- **Zone-matched security rules** -- 12 rules matched by source/destination zone pair
- **Source NAT translation** -- Only for outbound (trust->untrust) flows
- **Monotonic counters** -- sequence_number and flow_id increment via shared state
- **Deny action distribution** -- deny 40%, reset-both 25%, reset-client 20%, reset-server 15%
- **Drop application correlation** -- Dropped traffic uses incomplete/insufficient-data/not-applicable apps
- **Geo-aware destinations** -- Allowed traffic skews US/EU; dropped/denied traffic skews higher-risk regions
- **ECS-compliant output** -- Full Elastic panw integration field mapping including `panw.panos.*` vendor fields

## Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `hostname` | `PA-3260` | PAN-OS firewall hostname |
| `domain` | `CORP` | Active Directory domain name |
| `serial_number` | `012801096514` | Firewall serial number |
| `nat_ip` | `198.51.100.1` | Source NAT IP for outbound traffic |
| `virtual_sys` | `vsys1` | Virtual system name |
| `log_profile` | `Log-to-Syslog` | Log forwarding profile |
| `src_network` | `10.0.0.0-10.255.255.255` | Source network range (geo label) |
| `agent_id` | `f7a3b1c2-...` | Elastic Agent ID |
| `agent_version` | `8.17.0` | Elastic Agent version |

## Usage

### Run the generator

```bash
eventum generate \
  --path generators/network-paloalto-traffic/generator.yml \
  --id panw-traffic \
  --live-mode
```

### Sample mode (generate as fast as possible)

```bash
eventum generate \
  --path generators/network-paloalto-traffic/generator.yml \
  --id panw-traffic \
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

### Traffic End (session completed)

```json
{
    "@timestamp": "2026-03-06T10:30:15.123456+00:00",
    "agent": {
        "ephemeral_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        "id": "f7a3b1c2-8d4e-5f6a-b7c8-d9e0f1a2b3c4",
        "name": "PA-3260",
        "type": "filebeat",
        "version": "8.17.0"
    },
    "destination": {
        "bytes": 245678,
        "geo": {"name": "United States"},
        "ip": "142.250.80.46",
        "packets": 245,
        "port": 443
    },
    "event": {
        "action": "flow_terminated",
        "category": ["network"],
        "dataset": "panw.panos",
        "duration": 35000000000,
        "kind": "event",
        "module": "panw",
        "outcome": "success",
        "start": "2026-03-06T10:29:40.123456+00:00",
        "type": ["connection", "end", "allowed"]
    },
    "network": {
        "application": "ssl",
        "bytes": 250234,
        "community_id": "1:a1b2c3d4e5f6a7b8c9d0",
        "direction": "outbound",
        "packets": 249,
        "transport": "tcp",
        "type": "ipv4"
    },
    "observer": {
        "egress": {"interface": {"name": "ethernet1/1"}, "zone": "untrust"},
        "hostname": "PA-3260",
        "ingress": {"interface": {"name": "ethernet1/2"}, "zone": "trust"},
        "product": "PAN-OS",
        "serial_number": "012801096514",
        "type": "firewall",
        "vendor": "Palo Alto Networks"
    },
    "panw": {
        "panos": {
            "action": "allow",
            "bytes_sent": 4556,
            "bytes_received": 245678,
            "elapsed_time": 35,
            "session_end_reason": "tcp-fin",
            "session_flags": "0x400053",
            "sub_type": "end",
            "type": "TRAFFIC"
        }
    },
    "source": {
        "bytes": 4556,
        "ip": "10.1.1.14",
        "nat": {"ip": "198.51.100.1", "port": 34567},
        "packets": 4,
        "port": 52340
    }
}
```

## File Structure

```
network-paloalto-traffic/
  generator.yml                              # Generator configuration
  README.md                                  # This file
  templates/
    traffic-end.json.jinja                   # Session end events (completed flows)
    traffic-start.json.jinja                 # Session start events (new flows)
    traffic-drop.json.jinja                  # Dropped traffic events
    traffic-deny.json.jinja                  # Policy-denied traffic events
  samples/
    applications.json                        # 30 PAN-OS App-IDs with weights
    internal_hosts.csv                       # 15 internal workstation IPs
    server_hosts.csv                         # 6 DMZ server IPs
    usernames.csv                            # 15 Active Directory usernames
    security_rules.json                      # 12 security policy rules
    url_categories.json                      # 18 URL categories with weights
```

## References

- [PAN-OS Traffic Log Fields](https://docs.paloaltonetworks.com/pan-os/11-0/pan-os-admin/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/traffic-log-fields)
- [PAN-OS Security Policy Rules](https://docs.paloaltonetworks.com/pan-os/11-0/pan-os-admin/policy/security-policy)
- [Elastic panw Integration](https://docs.elastic.co/integrations/panw)
- [ECS Field Reference](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html)

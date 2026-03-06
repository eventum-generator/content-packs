# UserGate NGFW

Generates realistic UserGate NGFW (Next-Generation Firewall) events in ECS-compatible JSON, matching the UserGate CEF syslog log structure. UserGate NGFW is a Russian UTM appliance providing firewall, IDS/IPS, web filtering, VPN, content filtering, and gateway antivirus capabilities. Events cover the full UserGate log taxonomy: traffic forwarding (accept/deny), security modules (web filter, IDPS, DNS filter), and operational events (system administration, VPN tunnels, user authentication).

## Event Types

| Event Type | UserGate Log Type | Frequency | ECS Category |
|------------|------------------|-----------|-------------|
| Traffic Accept | traffic/firewall | ~49% | network |
| Traffic Deny | traffic/firewall | ~16% | network |
| Web Filter | web access/content filter | ~7% | network, web |
| IDPS Alert | ids/rule | ~4% | network, intrusion_detection |
| DNS Filter | dns/rule | ~5% | network |
| System Event | event/system | ~5% | authentication, configuration, host |
| User Auth | event/user auth | ~4% | authentication |
| VPN | event/vpn | ~3% | network |

## Realism Features

- **Weighted event distributions** matching production UserGate log volumes (traffic ~65%, security ~20%, operational ~15%)
- **UserGate CEF format** in `message` field with proper header: `CEF:0|UserGate|NGFW|7|<log_type>|<rule_type>|<threat_level>|...`
- **Zone-aware routing** with UserGate zone names (Trusted, Untrusted, DMZ)
- **NAT translation** with SNAT for outbound traffic
- **Threat levels** 1-10 matching UserGate severity scale
- **VPN tunnel correlation** via shared state — tunnel-up events paired with tunnel-down events including duration and byte counts
- **IDPS signatures** with Snort/Suricata-style SIDs and severity levels
- **UserGate web categories** with allow/block/warn actions
- **GeoIP country codes** for external source/destination IPs weighted by real-world traffic patterns
- **User authentication** via LDAP, RADIUS, Captive Portal with realistic user groups
- **DNS query logging** with realistic domain names and query types
- **Session ID tracking** via shared state across all traffic events

## Parameters

### Event Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `hostname` | `ug-fw-01` | UserGate device hostname |
| `domain` | `example.com` | Domain name for FQDN |
| `device_id` | `utmcore@usergate-fw01` | UserGate device external ID |
| `nat_ip` | `198.51.100.1` | NAT/public IP for outbound SNAT |
| `agent_id` | `f1a2b3c4-...` | Filebeat agent UUID |
| `agent_version` | `8.17.0` | Filebeat version string |

## Usage

```bash
# Install Eventum
uv tool install eventum-generator

# Run in live mode (continuous streaming)
eventum generate \
  --path generators/network-usergate/generator.yml \
  --id usergate \
  --live-mode

# Run in sample mode (generate batch and exit)
eventum generate \
  --path generators/network-usergate/generator.yml \
  --id usergate \
  --live-mode false
```

## Sample Output

### Traffic Accept

```json
{
    "@timestamp": "2026-03-07T10:15:32+00:00",
    "agent": {
        "ephemeral_id": "a1b2c3d4-5678-90ab-cdef-1234567890ab",
        "id": "f1a2b3c4-5d6e-7f8a-9b0c-d1e2f3a4b5c6",
        "name": "ug-fw-01.example.com",
        "type": "filebeat",
        "version": "8.17.0"
    },
    "destination": {
        "bytes": 39898,
        "geo": {"country_iso_code": "US"},
        "ip": "172.217.14.206",
        "packets": 37,
        "port": 443
    },
    "event": {
        "action": "accept",
        "category": ["network"],
        "dataset": "usergate.log",
        "duration": 30000000000,
        "kind": "event",
        "module": "usergate",
        "outcome": "success",
        "type": ["connection", "end", "allowed"]
    },
    "message": "CEF:0|UserGate|NGFW|7|traffic|firewall|1|rt=1709806532000 deviceExternalId=utmcore@usergate-fw01 suser=j.smith act=accept cs1Label=Rule cs1=Allow trusted to untrusted src=10.1.1.10 spt=60446 cs2Label=Source Zone cs2=Trusted cs3Label=Source Country cs3=RU proto=TCP dst=172.217.14.206 dpt=443 cs4Label=Destination Zone cs4=Untrusted cs5Label=Destination Country cs5=US sourceTranslatedAddress=198.51.100.1 sourceTranslatedPort=40772 in=39898 out=1850 cn1Label=Packets sent cn1=25 cn2Label=Packets received cn2=37",
    "observer": {
        "name": "ug-fw-01",
        "product": "NGFW",
        "serial_number": "utmcore@usergate-fw01",
        "type": "firewall",
        "vendor": "UserGate"
    },
    "tags": ["usergate", "usergate-ngfw", "forwarded"]
}
```

## File Structure

```
network-usergate/
  generator.yml                    # Pipeline config
  README.md                        # This file
  templates/
    traffic-accept.json.jinja     # Traffic allowed sessions
    traffic-deny.json.jinja       # Traffic denied by policy
    web-filter.json.jinja         # Content filtering events
    idps-alert.json.jinja         # IDS/IPS signature detections
    dns.json.jinja                # DNS query logging
    system-event.json.jinja       # System admin events
    auth.json.jinja               # User authentication events
    vpn.json.jinja                # VPN tunnel events
  samples/
    internal_hosts.csv            # Internal network hosts (25 hosts)
    network_services.json         # Service definitions with ports
    firewall_rules.json           # Firewall rules (accept/deny)
    ips_signatures.json           # IDS/IPS attack signatures
    web_categories.json           # Web content categories
    users.json                    # Users and groups
```

## References

- [UserGate NGFW Documentation](https://support.usergate.com/docs/version/7.x/usergate-ngfw-710-0/syslog-format-1)
- [UserGate CEF Log Export Format](https://support.usergate.com/docs/version/7.x/usergate-ngfw-710/logs-export-cef-format)
- [UserGate Traffic Log Format](https://support.usergate.com/ru/node/25463)
- [UserGate IDPS Log](https://support.usergate.com/docs/version/7.x/usergate-ngfw-710-0/idps-log-1)
- [Elastic Common Schema (ECS)](https://www.elastic.co/guide/en/ecs/current/index.html)

# Network Snort IDS Alert Generator

Produces realistic Snort IDS/IPS alert events (ECS-compatible JSON) matching the Elastic Snort integration (`snort.log` dataset). Events cover the full spectrum of Snort alert classifications — malware command and control, web application attacks, reconnaissance, policy violations, protocol anomalies, denial of service, and ICMP events. Compatible with Snort 2 and Snort 3 alert field structures.

## Event Types Covered

| Event Type | Classification | Frequency | Priority | Primary Protocol |
|------------|---------------|-----------|----------|-----------------|
| Trojan Activity | A Network Trojan was Detected | ~15% | 1 | TCP |
| Web Application Attack | Web Application Attack | ~10% | 1 | TCP |
| Attempted Admin | Attempted Administrator Privilege Gain | ~5% | 1 | TCP |
| Attempted User | Attempted User Privilege Gain | ~4% | 1 | TCP |
| Policy Violation | Potential Corporate Privacy Violation | ~12.5% | 1 | TCP/UDP |
| Attempted Recon | Attempted Information Leak | ~7.5% | 2 | TCP/UDP |
| Network Scan | Detection of a Network Scan | ~10% | 3 | TCP/ICMP |
| Misc Activity | Misc Activity | ~12.5% | 3 | TCP/UDP |
| Protocol Decode | Generic Protocol Command Decode | ~7.5% | 3 | TCP/UDP |
| Attempted DoS | Attempted Denial of Service | ~4% | 2 | TCP/UDP/ICMP |
| Bad Unknown | Potentially Bad Traffic | ~6% | 2 | TCP |
| ICMP Event | Generic ICMP Event | ~5% | 3 | ICMP |
| Shellcode Detect | Executable Code was Detected | ~1% | 1 | TCP |

## Realism Features

- **57 inline Snort signatures** covering real-world CVEs (Log4j, EternalBlue, ProxyShell, Heartbleed, Spring4Shell), malware families (ZeroAccess, Mirai, Emotet, Cobalt Strike), and protocol anomalies
- **Weighted alert distribution** matching production IDS deployments (Talos Intelligence data)
- **Direction-aware traffic** — trojans predominantly outbound, web attacks inbound, policy violations from internal hosts
- **Multi-stage reconnaissance correlation** — scan source IPs persist in shared state across templates, simulating progressive attacker enumeration
- **Protocol-specific metadata** — TCP flags, sequence/ack numbers, window sizes, TTL values for TCP; type/code pairs for ICMP; length fields for UDP
- **Realistic TTL distribution** — 64 (Linux), 128 (Windows), 255 (network equipment), with hop-decremented variants
- **IPS action variety** — `allow`, `would_drop`, `drop` with classification-appropriate ratios (shellcode mostly blocked, misc activity mostly allowed)
- **Service-aware port selection** — each signature targets appropriate destination ports based on the attacked service
- **Community ID** per alert for cross-event flow correlation
- **Real Snort SID ranges** — VRT/Talos-style SIDs (100–999999) and local rules (1000000+)

## Parameters

### Event Parameters

Edit the `params` section under `event.template` in `generator.yml`:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `sensor_hostname` | `IDS01` | Snort sensor hostname |
| `sensor_interface` | `eth0` | Monitored network interface |
| `home_network_prefix` | `10.1.` | Internal network prefix |
| `agent_id` | `a7c3e1f0-...` | Filebeat agent ID |
| `agent_version` | `8.17.0` | Filebeat version string |

## Usage

```bash
# Install Eventum
uv tool install eventum-generator

# Run the generator
eventum generate \
  --path generators/network-snort/generator.yml \
  --id snort \
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

### Trojan Activity Alert (Outbound C2)

```json
{
    "@timestamp": "2026-02-21T12:00:01.234567+00:00",
    "event": {
        "action": "would_drop",
        "category": ["network", "intrusion_detection"],
        "dataset": "snort.log",
        "kind": "alert",
        "module": "snort",
        "outcome": "failure",
        "severity": 1,
        "type": ["denied"]
    },
    "source": {
        "address": "10.1.1.30",
        "ip": "10.1.1.30",
        "port": 52341
    },
    "destination": {
        "address": "198.51.100.47",
        "ip": "198.51.100.47",
        "port": 443
    },
    "network": {
        "community_id": "1:a1b2c3d4e5f6a7b8c9d0",
        "direction": "outbound",
        "iana_number": "6",
        "transport": "tcp",
        "type": "ipv4"
    },
    "observer": {
        "name": "IDS01",
        "product": "ids",
        "type": "ids",
        "vendor": "snort"
    },
    "rule": {
        "category": "Trojan Activity",
        "description": "MALWARE-CNC Cobalt Strike beacon outbound connection",
        "id": "45000",
        "version": "2"
    },
    "snort": {
        "gid": 1,
        "ip": {"id": 34521, "length": 342, "tos": 0, "ttl": 128},
        "tcp": {"ack": 2000257859, "flags": "***AP***", "length": 20, "seq": 179136002, "window": 65535}
    },
    "related": {
        "ip": ["10.1.1.30", "198.51.100.47"]
    }
}
```

## File Structure

```
network-snort/
  generator.yml                                # Pipeline configuration
  README.md                                    # This file
  templates/
    trojan-activity.json.jinja                 # Malware C2 alerts (~15%)
    web-application-attack.json.jinja          # SQL injection, XSS, RCE (~10%)
    attempted-admin.json.jinja                 # Admin privilege escalation (~5%)
    attempted-user.json.jinja                  # User privilege escalation (~4%)
    policy-violation.json.jinja                # Policy violations — Tor, crypto, P2P (~12.5%)
    attempted-recon.json.jinja                 # Nmap scans, version probes (~7.5%)
    network-scan.json.jinja                    # Port/host scans, ICMP probes (~10%)
    misc-activity.json.jinja                   # Suspicious user agents, PowerShell, IRC (~12.5%)
    protocol-command-decode.json.jinja         # DNS zone transfer, FTP bounce, SMTP (~7.5%)
    attempted-dos.json.jinja                   # SYN/UDP/ICMP flood, amplification (~4%)
    bad-unknown.json.jinja                     # Suspicious outbound, self-signed certs (~6%)
    icmp-event.json.jinja                      # Echo, unreachable, time exceeded (~5%)
    shellcode-detect.json.jinja                # NOOP sled, reverse shell (~1%)
  samples/
    internal_hosts.csv                         # 25 internal hosts (workstations, servers, DMZ)
```

## References

- [Snort 3 Documentation](https://docs.snort.org)
- [Snort 3 Alert JSON Plugin](https://docs.snort.org/start/alert_logging)
- [Snort Rule Classifications](https://docs.snort.org/rules/options/general/classtype)
- [Elastic Snort Integration](https://github.com/elastic/integrations/tree/main/packages/snort)
- [ECS Intrusion Detection Category](https://www.elastic.co/guide/en/ecs/current/ecs-using-the-categorization-fields.html)
- [ECS Network Fields](https://www.elastic.co/guide/en/ecs/current/ecs-network.html)
- [Community ID Specification](https://github.com/corelight/community-id-spec)
- [Talos Intelligence — Snort Signatures](https://blog.talosintelligence.com/2017-in-snort-signatures/)

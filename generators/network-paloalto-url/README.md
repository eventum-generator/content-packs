# Palo Alto Networks URL Filtering Event Generator

Produces realistic PAN-OS URL Filtering events in ECS-compatible JSON format, matching the field structure used by the [Elastic panw integration](https://docs.elastic.co/integrations/panw). URL Filtering logs record web browsing activity evaluated against URL Filtering security profiles, capturing allowed, blocked, and interactive (continue/override) access decisions.

## Event Types

| Template | Action | Frequency | Category | Description |
|----------|--------|-----------|----------|-------------|
| `alert.json.jinja` | `alert` | ~87% | URL allowed | Allowed URL access with alert logging (business, search, CDN, email, social, etc.) |
| `block.json.jinja` | `block-url` | ~6.5% | URL blocked | Hard block by URL category (malware, phishing, C2, adult, gambling, unknown) |
| `block.json.jinja` | `block-continue` | ~2.4% | URL blocked | Block with continue page (not-resolved, insufficient-content) |
| `block.json.jinja` | `block-override` | ~0.8% | URL blocked | Block with override page (questionable, hacking) |
| `block.json.jinja` | `drop` | ~0.7% | URL blocked | Silent drop |
| `block.json.jinja` | `reset-client` | ~0.4% | URL blocked | Reset sent to client |
| `block.json.jinja` | `reset-server` | ~0.2% | URL blocked | Reset sent to server |
| `block.json.jinja` | `reset-both` | ~0.1% | URL blocked | Reset sent to both |
| `continue-override.json.jinja` | `continue` | ~1.2% | URL allowed | Allowed after user clicked Continue (correlated with block-continue) |
| `continue-override.json.jinja` | `override` | ~0.7% | URL allowed | Allowed after override password (correlated with block-override) |

## Realism Features

- **Weighted URL category distribution** — 27 PAN-DB categories with realistic enterprise traffic weights (business-and-economy 18%, search-engines 10%, CDN 9%, etc.)
- **Best-practice URL filtering profile** — Categories mapped to actions following Palo Alto Networks security best practices (alert for business, block for malware/phishing/C2, continue for not-resolved, override for hacking tools)
- **Correlated continue/override flows** — Block-continue and block-override events store sessions in a shared pool; subsequent continue/override events consume them, preserving the same user, URL, and category
- **Realistic PAN-OS App-IDs** — 12 applications (ssl, web-browsing, google-base, ms-office365, etc.) with weighted selection
- **Source NAT translation** — All outbound traffic includes NAT IP/port translation
- **Monotonic sequence numbers** — Sequence counter increments across all events
- **HTTP header logging** — User-Agent strings generated via Faker, HTTP methods with realistic distribution (GET 80%, POST 12%)
- **Geo-aware destinations** — Allowed traffic skews toward US/EU/JP; blocked traffic skews toward higher-risk regions
- **ECS-compliant output** — Full Elastic panw integration field mapping including `panw.panos.*` vendor fields, `labels.*` flags, and `related.*` arrays
- **Security policy rules** — 7 rules with weighted selection (Allow-Business-Web 40%, Block-Malicious 2%)

## Parameters

### Event Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `hostname` | `PA-5260` | PAN-OS firewall hostname |
| `domain` | `CORP` | Active Directory domain name |
| `serial_number` | `007200001056` | Firewall serial number |
| `nat_ip` | `198.51.100.1` | Source NAT IP for outbound traffic |
| `src_zone` | `trust` | Source security zone |
| `dst_zone` | `untrust` | Destination security zone |
| `inbound_interface` | `ethernet1/2` | Ingress interface |
| `outbound_interface` | `ethernet1/1` | Egress interface |
| `virtual_sys` | `vsys1` | Virtual system name |
| `log_profile` | `Log-to-Syslog` | Log forwarding profile |
| `content_version` | `AppThreat-8840-8575` | App/Threat content version |
| `src_network` | `10.0.0.0-10.255.255.255` | Source network range (geo label) |
| `agent_id` | `e4f8c1a2-...` | Elastic Agent ID |
| `agent_version` | `8.17.0` | Elastic Agent version |

## Usage

### Run the generator

```bash
eventum generate \
  --path generators/network-paloalto-url/generator.yml \
  --id panw-url \
  --live-mode
```

### Sample mode (generate as fast as possible)

```bash
eventum generate \
  --path generators/network-paloalto-url/generator.yml \
  --id panw-url \
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

### URL Alert (allowed)

```json
{
    "@timestamp": "2026-02-21T14:30:15.123456+00:00",
    "agent": {
        "ephemeral_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        "id": "e4f8c1a2-9b3d-4e5f-a6c7-d8e9f0a1b2c3",
        "name": "PA-5260",
        "type": "filebeat",
        "version": "8.17.0"
    },
    "destination": {
        "geo": {
            "name": "United States"
        },
        "ip": "142.250.80.46",
        "port": 443
    },
    "ecs": {
        "version": "8.17.0"
    },
    "event": {
        "action": "url_filtering",
        "category": ["intrusion_detection", "threat", "network"],
        "dataset": "panw.panos",
        "kind": "alert",
        "module": "panw",
        "outcome": "success",
        "severity": 5,
        "type": ["allowed"]
    },
    "host": {
        "name": "PA-5260"
    },
    "http": {
        "request": {
            "method": "get"
        }
    },
    "labels": {
        "nat_translated": true,
        "url_filter_denied": false
    },
    "log": {
        "level": "informational",
        "syslog": {
            "facility": {"code": 1, "name": "user-level"},
            "hostname": "PA-5260",
            "priority": 14,
            "severity": {"code": 6, "name": "Informational"}
        }
    },
    "network": {
        "application": "ssl",
        "community_id": "1:a1b2c3d4e5f6a7b8c9d0",
        "direction": "inbound",
        "transport": "tcp",
        "type": "ipv4"
    },
    "observer": {
        "egress": {"interface": {"name": "ethernet1/1"}, "zone": "untrust"},
        "hostname": "PA-5260",
        "ingress": {"interface": {"name": "ethernet1/2"}, "zone": "trust"},
        "product": "PAN-OS",
        "serial_number": "007200001056",
        "type": "firewall",
        "vendor": "Palo Alto Networks"
    },
    "panw": {
        "panos": {
            "action": "alert",
            "action_flags": "0x0",
            "content_version": "AppThreat-8840-8575",
            "flow_id": "3456789",
            "generated_time": "2026-02-21T14:30:15.123456+00:00",
            "http_content_type": "text/html",
            "log_profile": "Log-to-Syslog",
            "received_time": "2026-02-21T14:30:15.123456+00:00",
            "repeat_count": 1,
            "ruleset": "Allow-Business-Web",
            "sequence_number": "100042",
            "sub_type": "url",
            "threat": {"id": "9999", "name": "URL-filtering"},
            "type": "THREAT",
            "url": {"category": "search-engines"},
            "virtual_sys": "vsys1"
        }
    },
    "related": {
        "hosts": ["PA-5260", "www.google.com"],
        "ip": ["10.1.1.14", "142.250.80.46", "198.51.100.1"],
        "user": ["jsmith"]
    },
    "rule": {
        "name": "Allow-Business-Web"
    },
    "source": {
        "geo": {"name": "10.0.0.0-10.255.255.255"},
        "ip": "10.1.1.14",
        "nat": {"ip": "198.51.100.1", "port": 34567},
        "port": 52340,
        "user": {"domain": "CORP", "name": "jsmith"}
    },
    "url": {
        "domain": "www.google.com",
        "original": "www.google.com/search?q=network+security+best+practices",
        "path": "/search?q=network+security+best+practices"
    },
    "user": {
        "domain": "CORP",
        "name": "jsmith"
    },
    "user_agent": {
        "original": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }
}
```

## File Structure

```
network-paloalto-url/
  generator.yml                              # Generator configuration
  README.md                                  # This file
  templates/
    alert.json.jinja                         # URL alert events (allowed traffic)
    block.json.jinja                         # URL block events (denied traffic)
    continue-override.json.jinja             # Continue/override events (correlated)
  samples/
    internal_hosts.csv                       # 15 internal workstation IPs
    usernames.csv                            # 15 Active Directory usernames
    url_categories.json                      # 27 PAN-DB URL categories with sample URLs
    applications.json                        # 12 PAN-OS App-IDs with weights
    security_rules.json                      # 7 security policy rules
```

## References

- [PAN-OS URL Filtering Log Fields](https://docs.paloaltonetworks.com/pan-os/11-0/pan-os-admin/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/url-filtering-log-fields)
- [PAN-DB URL Filtering Categories](https://docs.paloaltonetworks.com/advanced-url-filtering/administration/url-filtering-basics/url-categories)
- [URL Filtering Best Practices](https://docs.paloaltonetworks.com/best-practices/10/url-filtering-best-practices)
- [Elastic panw Integration](https://docs.elastic.co/integrations/panw)
- [ECS Field Reference](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html)

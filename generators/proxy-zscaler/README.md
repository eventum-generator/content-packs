# Zscaler Internet Access (ZIA) Web Proxy

Generates realistic Zscaler ZIA web proxy/transaction events matching the [Elastic zscaler_zia integration](https://docs.elastic.co/integrations/zscaler_zia) field structure. Simulates the NSS (Nanolog Streaming Service) web log feed from a Zscaler ZIA cloud tenant.

Zscaler ZIA is a cloud-native Secure Web Gateway (SWG) that inspects all outbound web traffic via the Zscaler Client Connector agent on endpoints. Events represent individual HTTP/HTTPS transactions with full URL categorization, threat detection, DLP inspection, and SSL/TLS details.

## Event Types

| Event Type | Action | Description | Weight (%) | ECS Outcome |
|---|---|---|---|---|
| Allowed traffic | `Allowed` | Normal business, cloud, and general web browsing | 80% | `success` |
| Blocked - URL policy | `Blocked` | URL filtering policy (adult, gambling, anonymizers, hacking) | 8% | `failure` |
| Blocked - Security | `Blocked` | Malware, phishing, C2, cryptomining, suspicious content | 3% | `failure` |
| Cautioned - DLP | `Cautioned` | DLP policy violation (sensitive data upload detected) | 1.5% | `success` |
| Bandwidth throttled | `Allowed` | Streaming/downloads with bandwidth policy applied | 5% | `success` |
| Blocked - File type | `Blocked` | Executable/archive downloads from untrusted sites | 2% | `failure` |
| Browser isolation | `Isolated` | Uncategorized or risky sites rendered via Cloud Browser Isolation | 0.5% | `success` |

## Realism Features

- **Jinja2 macros** (`_base.json.jinja`) eliminate boilerplate across 7 templates
- **Log-normal distributions** for request/response byte sizes (most small, some very large)
- **Weighted URL categories** across Zscaler's 3-level hierarchy (class/super/sub)
- **Realistic TLS details** — cipher suites, TLS versions, certificate validation, OCSP results
- **Multi-device fleet** — 16 endpoints (Windows, macOS, iOS, Android) with varied OS versions
- **20 users** across 8 departments and 5 office locations
- **DLP engine simulation** — HIPAA, PCI, GDPR, Code Protection with dictionary hit counts
- **Threat signatures** — 14 malware/phishing signatures with severity levels and categories
- **Bandwidth throttling** — streaming and cloud storage downloads with throttle byte counts
- **File type control** — executables, scripts, archives blocked from untrusted download sources
- **Cloud app attribution** — 21 cloud applications with class and risk score

## Parameters

| Parameter | Default | Description |
|---|---|---|
| `company` | `SafeMarch Inc` | Organization name |
| `cloudname` | `zscaler.net` | Zscaler cloud name |
| `datacenter` | `US-CA1 Client Node DC` | Zscaler datacenter name |
| `datacenter_city` | `San Jose` | Datacenter city |
| `datacenter_country` | `US` | Datacenter country code |
| `nss_server` | `nss-feed-01` | NSS feed server name |
| `product_version` | `6.2.1.110_04` | Zscaler product version |
| `agent_id` | `a1b2c3d4-...` | Filebeat agent UUID |
| `agent_version` | `8.17.0` | Elastic Agent version |
| `timezone` | `UTC` | Event timezone |

## Output Parameters

For production deployment with OpenSearch/Elasticsearch:

```yaml
output:
  - opensearch:
      hosts:
        - ${params.opensearch_host}
      username: ${params.opensearch_user}
      password: ${secrets.opensearch_password}
      index: ${params.opensearch_index}
```

| Parameter | Description |
|---|---|
| `${params.opensearch_host}` | OpenSearch/Elasticsearch host URL |
| `${params.opensearch_user}` | Username for authentication |
| `${secrets.opensearch_password}` | Password (from Eventum keyring) |
| `${params.opensearch_index}` | Target index name |

## Usage

```bash
# Live mode (5 events/second)
eventum generate \
  --path generators/proxy-zscaler/generator.yml \
  --id zscaler-zia \
  --live-mode

# Batch mode (generate as fast as possible)
eventum generate \
  --path generators/proxy-zscaler/generator.yml \
  --id zscaler-zia \
  --live-mode false
```

### startup.yml example

```yaml
generators:
  zscaler-zia:
    path: generators/proxy-zscaler/generator.yml
    params:
      company: Acme Corp
      cloudname: zscaler.net
```

## Sample Output

```json
{
  "@timestamp": "2026-02-22T19:11:26+00:00",
  "agent": {
    "ephemeral_id": "cf035b63-9770-4838-a25f-704bd9ae8de2",
    "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "name": "nss-feed-01",
    "type": "filebeat",
    "version": "8.17.0"
  },
  "cloud": {
    "provider": "zscaler.net"
  },
  "destination": {
    "domain": "www.zendesk.com",
    "ip": "4.122.149.47",
    "port": 443
  },
  "device": {
    "id": "48196358",
    "model": {
      "identifier": "MacBookAir10-1"
    }
  },
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "allowed",
    "category": ["web"],
    "id": "1",
    "kind": "event",
    "module": "zscaler_zia",
    "outcome": "success",
    "reason": "Policy Permit",
    "timezone": "UTC",
    "type": ["access"]
  },
  "host": {
    "hostname": "MACBOOK-TPATEL",
    "name": "macbook-tpatel",
    "os": {
      "type": "macos",
      "version": "Version 13.6.3 (Build 22G436)"
    },
    "type": "Zscaler Client Connector"
  },
  "http": {
    "request": {
      "bytes": 1175,
      "method": "GET",
      "referrer": "https://www.zendesk.com/"
    },
    "response": {
      "bytes": 4666
    },
    "version": ["1.1"]
  },
  "network": {
    "protocol": "https"
  },
  "organization": {
    "name": "SafeMarch Inc"
  },
  "related": {
    "hosts": ["macbook-tpatel"],
    "ip": ["10.19.157.22", "203.0.113.207", "4.122.149.47"],
    "user": ["jmorales", "jmorales@safemarch.com"]
  },
  "rule": {
    "name": ["Allow_Business_Apps"]
  },
  "source": {
    "ip": "10.19.157.22",
    "nat": {
      "ip": "203.0.113.207"
    },
    "port": 56441
  },
  "tls": {
    "cipher": "TLS_AES_128_GCM_SHA256",
    "version": "TLS1.3"
  },
  "url": {
    "domain": "www.zendesk.com",
    "full": "https://www.zendesk.com/agent/dashboard",
    "original": "https://www.zendesk.com/agent/dashboard",
    "path": "/agent/dashboard",
    "scheme": "https"
  },
  "user": {
    "domain": "safemarch.com",
    "email": "jmorales@safemarch.com",
    "name": "jmorales"
  },
  "user_agent": {
    "original": "Mozilla/5.0 (Macintosh; PPC Mac OS X 10_7_5) ..."
  },
  "zscaler_zia": {
    "web": {
      "action": "Allowed",
      "app": {
        "class": "Collaboration",
        "name": "Slack",
        "risk_score": "Low"
      },
      "bandwidth_throttle": "No",
      "department": "Engineering",
      "device": {
        "hostname": "MACBOOK-TPATEL",
        "os": {
          "type": "macOS",
          "version": "Version 13.6.3 (Build 22G436)"
        }
      },
      "location": "Austin Office",
      "malware": {
        "category": "None",
        "class": "None"
      },
      "module": "Web Security",
      "risk": {
        "score": 5
      },
      "ssl_decrypted": "No",
      "threat": {
        "name": "None",
        "severity": "None (0)"
      },
      "url": {
        "category": {
          "sub": "Online Trading/Brokerage/Insurance",
          "super": "Business and Economy"
        },
        "class": "Business Use"
      }
    }
  }
}
```

## File Structure

```
generators/proxy-zscaler/
  generator.yml                                    # Pipeline config
  README.md                                        # This file
  templates/
    _base.json.jinja                               # Shared macros (agent, ecs, host, device, user, etc.)
    allowed.json.jinja                             # Allowed web traffic
    blocked-policy.json.jinja                      # Blocked by URL filtering policy
    blocked-security.json.jinja                    # Blocked by security threat
    cautioned-dlp.json.jinja                       # Cautioned by DLP policy
    throttled.json.jinja                           # Allowed with bandwidth throttling
    blocked-filetype.json.jinja                    # Blocked by file type control
    isolated.json.jinja                            # Browser isolation
  samples/
    devices.csv                                    # 16 endpoints (Windows, macOS, iOS, Android)
    users.csv                                      # 20 users across 8 departments
    url_categories_allowed.json                    # 22 allowed URL categories with domains
    url_categories_blocked_policy.json             # 7 policy-blocked URL categories
    url_categories_blocked_security.json           # 6 security-blocked URL categories
    cloud_apps.json                                # 21 cloud applications
    threats.json                                   # 14 threat signatures
  output/
    events.json                                    # Generated events (overwritten each run)
```

## References

- [Zscaler ZIA NSS Feed Output Format: Web Logs](https://help.zscaler.com/zia/nss-feed-output-format-web-logs)
- [Elastic Zscaler ZIA Integration](https://docs.elastic.co/integrations/zscaler_zia)
- [Elastic Integrations — zscaler_zia](https://github.com/elastic/integrations/tree/main/packages/zscaler_zia)
- [Zscaler URL Categories](https://help.zscaler.com/zia/about-url-categories)
- [Zscaler Threat Categories](https://help.zscaler.com/zia/about-threat-categories)
- [Zscaler DLP Engines](https://help.zscaler.com/zia/understanding-dlp-engines)

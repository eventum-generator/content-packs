# Security WAF Log Generator

Produces realistic Web Application Firewall (WAF) log events (ECS-compatible JSON) modeled after ModSecurity with OWASP Core Rule Set (CRS) detections. Events cover the full spectrum of WAF activity — allowed traffic, SQL injection, XSS, RCE, LFI, SSRF attacks, bot detection, rate limiting, geo-blocking, and CAPTCHA challenges. Compatible with Elastic Agent and Filebeat for ingestion into Elasticsearch or OpenSearch.

## Event Types Covered

| Event Type | Description | Frequency | Severity | OWASP CRS Rules |
|------------|-------------|-----------|----------|-----------------|
| Allowed | Clean traffic passing all rules | ~75% | — | — |
| SQL Injection | SQLi attempts (tautology, UNION, blind) | ~5% | 2 | 942xxx |
| Cross-Site Scripting | XSS via script tags, event handlers, SVG | ~4% | 2 | 941xxx |
| Remote Code Execution | OS command injection, shell commands | ~2% | 2 | 932xxx |
| Local File Inclusion | Path traversal, /etc/passwd access | ~2% | 2 | 930xxx |
| Bot Detection | Scanners, empty UAs, known bad bots | ~3% | 4 | Custom |
| Rate Limiting | Request velocity threshold exceeded | ~4% | 3 | Custom |
| Geo-Blocking | Requests from restricted countries | ~2% | 3 | Custom |
| CAPTCHA Challenge | Suspicious behavior triggers challenge | ~1.5% | 4 | Custom |
| SSRF | Cloud metadata, internal IP access | ~1.5% | 2 | 934xxx |

## Realism Features

- **OWASP CRS rule IDs** — 32 real ModSecurity rules from CRS 3.x/4.x across SQLi, XSS, RCE, LFI, SSRF, and protocol enforcement categories
- **35 realistic attack payloads** — SQL injection (tautology, UNION, blind, time-based), XSS (script tags, event handlers, SVG), RCE (pipe, backtick, subshell), LFI (dotdot, encoding), SSRF (cloud metadata, internal IPs, gopher)
- **45 target URLs** spanning pages, APIs, assets, and well-known paths
- **26 user agents** — browsers, mobile, bots, developer tools, vulnerability scanners (sqlmap, nikto, nuclei)
- **GeoIP data** for 18 cities across 14 countries; geo-blocking from 4 restricted nations
- **Weighted action distributions** — attack severity determines block rate (RCE: 92% blocked, SQLi: 90%, protocol: 65%)
- **MITRE ATT&CK mapping** on attack events (Initial Access, Execution, Reconnaissance, Impact)
- **Anomaly scoring** — correlated score values based on attack type and rule count
- **Monotonic transaction IDs** via shared state counter

## Parameters

### Event Parameters

Edit the `params` section under `event.template` in `generator.yml`:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `hostname` | `waf-prod-01` | WAF node hostname |
| `server_name` | `app.example.com` | Protected web application domain |
| `server_ip` | `10.0.1.50` | Backend server IP address |
| `waf_vendor` | `ModSecurity` | WAF product name |
| `waf_mode` | `blocking` | WAF operating mode (blocking/detection) |
| `agent_id` | `c4f2e8a1-...` | Filebeat agent UUID |
| `agent_version` | `8.17.0` | Filebeat agent version |

## Usage

```bash
# Install Eventum
uv tool install eventum-generator

# Run the generator
eventum generate \
  --path generators/security-waf/generator.yml \
  --id waf \
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

### Allowed Request

```json
{
    "@timestamp": "2026-03-04T14:30:22.123456+00:00",
    "event": {
        "action": "allowed",
        "category": ["web", "network"],
        "dataset": "waf.log",
        "kind": "event",
        "module": "waf",
        "outcome": "success",
        "type": ["access", "allowed"]
    },
    "http": {
        "request": { "bytes": 542, "method": "GET" },
        "response": { "body": { "bytes": 12450 }, "status_code": 200 },
        "version": "2.0"
    },
    "observer": {
        "hostname": "waf-prod-01",
        "product": "WAF",
        "type": "waf",
        "vendor": "ModSecurity"
    },
    "source": {
        "ip": "203.0.113.42",
        "geo": { "country_iso_code": "US", "city_name": "Ashburn" }
    },
    "url": { "domain": "app.example.com", "path": "/products" },
    "waf": { "action": "pass", "anomaly_score": 0, "mode": "blocking" }
}
```

### SQL Injection Alert (Blocked)

```json
{
    "@timestamp": "2026-03-04T14:30:25.654321+00:00",
    "event": {
        "action": "denied",
        "category": ["web", "intrusion_detection"],
        "kind": "alert",
        "outcome": "failure",
        "severity": 2
    },
    "http": {
        "request": { "bytes": 891, "method": "POST" },
        "response": { "status_code": 403 }
    },
    "message": "SQL Injection Attack Detected via libinjection",
    "rule": {
        "category": "SQLI",
        "id": "942100",
        "name": "SQL Injection Attack Detected via libinjection",
        "ruleset": "OWASP CRS"
    },
    "source": { "ip": "198.51.100.73", "geo": { "country_iso_code": "RU" } },
    "threat": {
        "technique": { "name": ["Exploit Public-Facing Application"] }
    },
    "waf": {
        "action": "blocked",
        "anomaly_score": 15,
        "matched_data": "\\' OR 1=1--"
    }
}
```

## File Structure

```
security-waf/
  generator.yml                          # Pipeline configuration
  README.md                              # This file
  templates/
    allowed.json.jinja                   # Clean traffic (~75%)
    sqli.json.jinja                      # SQL injection attacks (~5%)
    xss.json.jinja                       # Cross-site scripting (~4%)
    rce.json.jinja                       # Remote code execution (~2%)
    lfi.json.jinja                       # Local file inclusion (~2%)
    bot-detection.json.jinja             # Bot/scanner detection (~3%)
    rate-limit.json.jinja                # Rate limiting (~4%)
    geo-block.json.jinja                 # Geographic blocking (~2%)
    captcha-challenge.json.jinja         # CAPTCHA challenges (~1.5%)
    ssrf.json.jinja                      # Server-side request forgery (~1.5%)
  samples/
    urls.json                            # 45 target URLs (pages, APIs, assets)
    user-agents.json                     # 26 user agents (browsers, bots, scanners)
    waf-rules.json                       # 32 OWASP CRS rules
    attack-payloads.json                 # 35 attack payloads (SQLi, XSS, RCE, LFI, SSRF)
    geo-data.json                        # 18 GeoIP locations
```

## References

- [OWASP Core Rule Set (CRS)](https://coreruleset.org/)
- [ModSecurity Reference Manual](https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v3.x))
- [Elastic ModSecurity Integration](https://www.elastic.co/docs/reference/integrations/modsecurity)
- [ECS Web Category Fields](https://www.elastic.co/guide/en/ecs/current/ecs-using-the-categorization-fields.html)
- [ECS HTTP Fields](https://www.elastic.co/guide/en/ecs/current/ecs-http.html)
- [MITRE ATT&CK Techniques](https://attack.mitre.org/techniques/)
- [CRS Rule ID Ranges](https://coreruleset.org/docs/2-how-crs-works/2-3-false-positives-and-tuning/)

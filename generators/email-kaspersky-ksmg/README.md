# Kaspersky Secure Mail Gateway (KSMG) Generator

Produces realistic Kaspersky Secure Mail Gateway ScanLogic events as ECS-compatible JSON, matching the CEF syslog format documented for KSMG 2.0/2.1. Events cover all major protection modules: Anti-Virus, Anti-Spam, Anti-Phishing, Content Filtering, Mail Authentication (SPF/DKIM/DMARC), and KATA integration (APT/zero-day detection).

## Event Types Covered

| Event Class | Scan Type | Description | Frequency | ECS Outcome |
|-------------|-----------|-------------|-----------|-------------|
| LMS_EV_SCAN_LOGIC_AV_STATUS | AV | Anti-Virus scan (clean, infected, disinfected, encrypted, error) | ~25% | success / failure / unknown |
| LMS_EV_SCAN_LOGIC_AS_STATUS | AS | Anti-Spam scan (clean, spam, probable spam, mass mail, blacklisted) | ~25% | success / failure / unknown |
| LMS_EV_SCAN_LOGIC_AP_STATUS | AP | Anti-Phishing scan (clean, phishing, malicious links) | ~15% | success / failure |
| LMS_EV_SCAN_LOGIC_MA_STATUS | MA | Mail Authentication (SPF/DKIM/DMARC pass/fail) | ~15% | success / failure |
| LMS_EV_SCAN_LOGIC_CF_STATUS | CF | Content Filtering (clean, banned files, size violations) | ~10% | success / failure |
| LMS_EV_SCAN_LOGIC_KT_STATUS | KT | KATA integration (clean, APT/zero-day detected) | ~4% | success / failure |
| LMS_EV_SCAN_LOGIC_MESSAGE_BACKUP | — | Message quarantined due to threat/policy | ~4% | success |
| LMS_EV_SCAN_LOGIC_ALL_NOT_PROCESSED | — | Scan failure (timeout, error, resource exhaustion) | ~2% | failure |

## Realism Features

- **Weighted scan outcomes** — each scan module uses realistic outcome distributions (e.g., AV: 93.5% clean, 3% infected, 1% disinfected, 2% encrypted)
- **Directional traffic** — 72% inbound / 28% outbound with appropriate sender/recipient selection
- **Lognormal message sizes** — right-skewed distribution from 500 bytes to 30 MB
- **Categorized email subjects** — subject category correlates with scan type (spam subjects for AS, phishing for AP, mixed for AV)
- **Mail authentication details** — MA events include realistic SPF/DKIM/DMARC verdict combinations with failure sub-types (softfail, temperror, permerror)
- **Threat intelligence** — AV infected events reference real malware family names and file indicators
- **Weighted external domains** — sender domains drawn from weighted pool (Gmail, Outlook dominate)
- **Content filtering specifics** — banned filename/format details, size violation thresholds
- **KATA alerts** — APT detection events include unique alert UUIDs
- **Shared macros** — consistent agent, observer, ECS, and related field blocks via Jinja2 macros
- **Processing time simulation** — lognormal distribution for scan processing duration (5ms to 60s)

## Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `ksmg_hostname` | `ksmg-node01` | KSMG appliance hostname |
| `ksmg_ip` | `10.1.0.20` | KSMG appliance IP address |
| `ksmg_version` | `2.0.1.6960` | KSMG software version |
| `domain` | `corp.example.com` | Organization email domain |
| `agent_id` | `c4d5e6f7-...` | Elastic Agent UUID |
| `agent_version` | `8.17.0` | Elastic Agent version |

## Output Parameters

For output plugins beyond the default file output, use `${params.*}` and `${secrets.*}` placeholders:

```yaml
# OpenSearch example
- opensearch:
    hosts:
      - ${params.opensearch_host}
    username: ${params.opensearch_user}
    password: ${secrets.opensearch_password}
    index: ${params.opensearch_index}
```

## Usage

```bash
# Install Eventum
uv tool install eventum-generator

# Live mode (5 events/second, continuous)
eventum generate \
  --path generators/email-kaspersky-ksmg/generator.yml \
  --id ksmg \
  --live-mode true

# Batch mode (generate as fast as possible, then stop)
eventum generate \
  --path generators/email-kaspersky-ksmg/generator.yml \
  --id ksmg \
  --live-mode false
```

### Adjusting Event Rate

Edit the `count` value in `generator.yml`:

```yaml
input:
  - cron:
      expression: "* * * * * *"
      count: 20    # 20 events/second
```

### Using with startup.yml

```yaml
generators:
  ksmg:
    path: generators/email-kaspersky-ksmg/generator.yml
    params:
      ksmg_hostname: ksmg-prod
      domain: mycompany.com
      ksmg_ip: "10.10.1.50"
```

## Sample Output

```json
{
  "@timestamp": "2026-03-06T23:14:11+00:00",
  "agent": {
    "ephemeral_id": "4b90b471-aca5-4fb4-ba08-01d369e2e273",
    "id": "c4d5e6f7-a1b2-4c3d-9e8f-0a1b2c3d4e5f",
    "name": "ksmg-node01",
    "type": "filebeat",
    "version": "8.17.0"
  },
  "ecs": { "version": "8.17.0" },
  "email": {
    "direction": "outbound",
    "from": { "address": ["b.garcia@corp.example.com"] },
    "message_id": "<3c68d131-0789-40d0-a893-9fdd8f18ebb7@corp.example.com>",
    "subject": "Meeting agenda for tomorrow",
    "to": { "address": ["karinamatthews@vendor-tech.io"] }
  },
  "event": {
    "action": "Skip",
    "category": ["email"],
    "dataset": "kaspersky_ksmg.scanlogic",
    "duration": 5000000,
    "kind": "event",
    "module": "kaspersky_ksmg",
    "outcome": "success",
    "reason": "NotDetected",
    "severity": 1,
    "type": ["info"]
  },
  "kaspersky": {
    "ksmg": {
      "event_class": "LMS_EV_SCAN_LOGIC_AV_STATUS",
      "message_id": "<3c68d131-0789-40d0-a893-9fdd8f18ebb7@corp.example.com>",
      "message_size": 80168,
      "scan_status": "Clean",
      "action": "Skip",
      "rule": "Default (Inbound)",
      "rule_id": "1",
      "scan_type": "av",
      "direction": "outbound",
      "processing_time_ms": 5,
      "av_status": "Clean",
      "node": "ksmg-node01"
    }
  },
  "log": { "level": "informational" },
  "observer": {
    "hostname": "ksmg-node01.corp.example.com",
    "ip": ["10.1.0.20"],
    "product": "Kaspersky Secure Mail Gateway",
    "type": "email-gateway",
    "vendor": "Kaspersky",
    "version": "2.0.1.6960"
  },
  "related": {
    "hosts": ["ksmg-node01"],
    "ip": ["10.1.0.20", "10.1.0.20"],
    "user": ["b.garcia", "karinamatthews"]
  },
  "source": {
    "domain": "corp.example.com",
    "ip": "10.1.0.20"
  },
  "tags": ["kaspersky-ksmg", "forwarded"]
}
```

## File Structure

```
generators/email-kaspersky-ksmg/
  generator.yml                            # Pipeline config
  README.md                                # This file
  templates/
    scan-result.json.jinja                 # Shared scan result (AV, AS, AP, CF, MA, KT)
    message-backup.json.jinja              # Message quarantine/backup events
    not-processed.json.jinja               # Scan failure events
    macros/
      envelope.jinja                       # Shared macros (agent, ECS, observer, related)
  samples/
    internal_users.csv                     # 20 internal mailbox users
    external_domains.json                  # Weighted external mail domains
    subjects.json                          # Categorized email subjects
    threats.json                           # Malware family names and file indicators
    rules.json                             # KSMG processing rules
  output/
    events.json                            # Generated events
```

## References

- [Kaspersky Secure Mail Gateway 2.0 Documentation](https://support.kaspersky.com/KSMG/2.0/en-US/) — Product documentation
- [KSMG ScanLogic Event Classes](https://support.kaspersky.com/KSMG/2.0/en-US/206426.htm) — CEF syslog event format
- [Elastic Common Schema (ECS)](https://www.elastic.co/guide/en/ecs/current/index.html) — Field definitions
- [ECS Email Fields](https://www.elastic.co/guide/en/ecs/current/ecs-email.html) — Email-specific ECS fields

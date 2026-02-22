# Fortinet FortiMail Generator

Generates realistic Fortinet FortiMail email security gateway events as ECS-compatible JSON, matching the [Elastic `fortinet_fortimail` integration](https://www.elastic.co/docs/reference/integrations/fortinet_fortimail) field structure. Events include email processing statistics, SMTP protocol events, antispam detection, antivirus scanning, and system administration.

## Event Types Covered

### Statistics Logs (`type=statistics`)

| Template | Description | Frequency | Classifier |
|----------|-------------|-----------|------------|
| Clean inbound | Legitimate email accepted | 27.9% | Not Spam, Bypass Scan On Auth |
| Clean outbound | Outbound email delivered | 12.5% | Not Spam, Bypass Scan On Auth |
| Spam rejected | Spam blocked at gateway | 13.9% | FortiGuard AntiSpam, DNSBL, Phishing |
| Spam quarantined | Spam tagged or quarantined | 4.2% | Bayesian, Sender Reputation |
| Auth failure | SPF/DKIM/DMARC/recipient fail | 5.6% | SPF Check, DKIM Failure, DMARC |

### Mail Event Logs (`type=event`)

| Template | Description | Frequency | Subtype |
|----------|-------------|-----------|---------|
| SMTP receive | Incoming message received | 10.5% | smtp |
| SMTP deliver | Outbound delivery status | 10.5% | smtp |
| SMTP TLS | STARTTLS negotiation | 3.5% | smtp |

### Antispam Logs (`type=spam`)

| Template | Description | Frequency |
|----------|-------------|-----------|
| Spam detection | Detection reason details | 7.0% |

### System Event Logs (`type=kevent`)

| Template | Description | Frequency | Subtype |
|----------|-------------|-----------|---------|
| Admin login | Admin login/logout events | 1.7% | admin |
| System update | FortiGuard DB updates | 1.0% | update |

### Antivirus Logs (`type=virus`)

| Template | Description | Frequency | Subtype |
|----------|-------------|-----------|---------|
| Virus infected | Virus/malware detection | 0.3% | infected |

## Realism Features

- **Weighted event distribution** matching production FortiMail deployments (~65% statistics, ~25% SMTP events, ~7% spam details, ~3% system events)
- **Correlated spam sessions** — spam detection logs share session IDs with their corresponding statistics events via shared state pool
- **Realistic classifier/disposition combinations** — 8+ spam classifiers (FortiGuard AntiSpam, DNSBL, SURBL, Heuristic, Banned Word), 5+ dispositions (Accept, Reject, Discard, Quarantine, Defer)
- **Authentication failure variety** — SPF, DKIM, DMARC, and recipient verification failures with appropriate dispositions
- **SMTP protocol detail** — receive/deliver/TLS events with realistic sendmail-style message format, DSN codes, and relay info
- **TLS certificate diversity** — multiple CAs (Google Trust Services, DigiCert, Let's Encrypt, SwissSign) with realistic verify results
- **Monotonic log IDs** — type-prefixed 10-digit IDs (`02*` statistics, `0003*` SMTP, `0300*` spam, `0100*` virus, `0701*`/`0704*` kevent)
- **Session ID format** — authentic FortiMail pattern: `[7-char prefix][char][6-digit seq]-[7-char prefix][char][6-digit seq]`
- **FortiGuard update events** — antivirus DB, antispam DB, engine updates with version numbers
- **Weighted external mail servers** — 15 realistic SMTP servers (Google, Outlook, ProtonMail, AWS SES, etc.) with country codes
- **50+ email subjects** across 5 categories (business, automated, newsletter, spam, phishing)

## Parameters

### Event Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `hostname` | `fml-01` | FortiMail appliance hostname |
| `domain` | `company.com` | Protected email domain |
| `device_id` | `FEVM02TM24000001` | FortiMail serial number |
| `device_ip` | `198.51.100.10` | FortiMail management/receiving IP |
| `agent_id` | `b3a1c4d5-...` | Elastic Agent ID |
| `agent_version` | `8.17.0` | Elastic Agent version |

## Usage

```bash
uv tool install eventum-generator

# Live mode (real-time event streaming)
eventum generate \
  --path generators/fortinet-fortimail/generator.yml \
  --id fml \
  --live-mode

# Sample mode (generate as fast as possible)
eventum generate \
  --path generators/fortinet-fortimail/generator.yml \
  --id fml \
  --live-mode false
```

### Adjusting Event Rate

The default rate is 5 events/second (~18,000 events/hour). To change:

```yaml
input:
  - cron:
      expression: "* * * * * *"
      count: 20  # 20 events/second (~72,000/hour)
```

## Sample Output

```json
{
    "@timestamp": "2026-02-21T14:30:15.123456+00:00",
    "agent": {
        "ephemeral_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        "id": "b3a1c4d5-e6f7-4890-a1b2-c3d4e5f60718",
        "name": "fml-01",
        "type": "filebeat",
        "version": "8.17.0"
    },
    "destination": {
        "ip": "198.51.100.10"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "email": {
        "direction": "in",
        "from": {
            "address": ["jdoe@gmail.com"]
        },
        "subject": "Q4 Financial Report - Final Review",
        "to": {
            "address": ["j.smith@company.com"]
        },
        "x_mailer": "mta"
    },
    "event": {
        "code": "0200004500",
        "dataset": "fortinet_fortimail.log",
        "kind": "event",
        "module": "fortinet_fortimail",
        "outcome": "success"
    },
    "fortinet_fortimail": {
        "log": {
            "classifier": "Not Spam",
            "client": {
                "cc": "US",
                "ip": "203.0.113.45",
                "name": "mail-yw1-f202.google.com"
            },
            "destination_ip": "198.51.100.10",
            "direction": "in",
            "disposition": "Accept",
            "domain": "company.com",
            "from": "jdoe@gmail.com",
            "hfrom": "jdoe@gmail.com",
            "id": "0200004500",
            "message_length": 23951,
            "policy_id": "0:1:1:SYSTEM",
            "priority": "information",
            "resolved": "OK",
            "scan_time": 0.008128,
            "session_id": "aBcDeFgk001000-aBcDeFgm001000",
            "source": {
                "folder": "",
                "type": "ext"
            },
            "type": "statistics",
            "virus": "",
            "xfer_time": 0.005643
        }
    },
    "log": {
        "level": "information",
        "syslog": {
            "priority": 190
        }
    },
    "observer": {
        "product": "FortiMail",
        "serial_number": "FEVM02TM24000001",
        "type": "firewall",
        "vendor": "Fortinet"
    },
    "related": {
        "ip": ["203.0.113.45", "198.51.100.10"],
        "user": ["mail-yw1-f202.google.com", "jdoe@gmail.com", "j.smith@company.com"]
    },
    "server": {
        "domain": "company.com",
        "registered_domain": "company.com",
        "top_level_domain": "com"
    },
    "source": {
        "ip": "203.0.113.45",
        "user": {
            "name": "mail-yw1-f202.google.com"
        }
    },
    "tags": ["fortinet-fortimail", "forwarded"]
}
```

## File Structure

```
fortinet-fortimail/
  generator.yml
  README.md
  templates/
    stats-clean-inbound.json.jinja
    stats-clean-outbound.json.jinja
    stats-spam-rejected.json.jinja
    stats-spam-quarantined.json.jinja
    stats-auth-failure.json.jinja
    event-smtp-receive.json.jinja
    event-smtp-deliver.json.jinja
    event-smtp-tls.json.jinja
    spam-detection.json.jinja
    kevent-admin-login.json.jinja
    kevent-system-update.json.jinja
    virus-infected.json.jinja
  samples/
    internal_users.csv
    mail_servers.json
    subjects.json
    viruses.json
```

## References

- [FortiMail 7.4.0 Log Reference](https://docs.fortinet.com/document/fortimail/7.4.0/log-reference)
- [FortiMail Log Message Syntax](https://docs.fortinet.com/document/fortimail/7.4.0/log-reference/890875/log-message-syntax)
- [FortiMail Classifiers and Dispositions](https://docs.fortinet.com/document/fortimail/7.4.0/log-reference/47449/log-message-dispositions-and-classifiers)
- [Elastic FortiMail Integration](https://www.elastic.co/docs/reference/integrations/fortinet_fortimail)
- [FortiMail 7.6.1 Administration Guide — Logging](https://docs.fortinet.com/document/fortimail/7.6.1/administration-guide/435158/about-fortimail-logging)

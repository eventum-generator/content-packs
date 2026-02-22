# Microsoft Exchange Message Tracking Generator

Produces realistic Microsoft Exchange Server 2019 message tracking log events as ECS-compatible JSON, matching the Elastic `microsoft_exchange` integration field structure. Events cover the full mail flow pipeline: SMTP receive, mailbox submission, transport routing, delivery, shadow redundancy, categorization (anti-spam, distribution group expansion, recipient resolution), and error handling (defer, fail, DSN, drop).

## Event Types Covered

| Event ID | Source | Description | Frequency | ECS Outcome |
|----------|--------|-------------|-----------|-------------|
| RECEIVE | SMTP / STOREDRIVER | Message received (inbound SMTP or internal mailbox) | ~26% | success |
| DELIVER | STOREDRIVER | Message delivered to local mailbox | ~24% | success |
| SEND | SMTP | Message sent between transport services | ~12% | success |
| SUBMIT | STOREDRIVER | Submitted from Mailbox Transport to Transport service | ~10% | success |
| HAREDIRECT | SMTP | Shadow redundancy copy created | ~7% | success |
| AGENTINFO | AGENT | Transport agent processing (anti-spam verdicts, rules) | ~6% | success |
| NOTIFYMAPI | STOREDRIVER | Message detected in Outbox via MAPI | ~5% | success |
| RESOLVE | RESOLVER | Recipient resolved via Active Directory lookup | ~2% | success |
| HADISCARD | SMTP | Shadow message discarded after primary delivered | ~2% | success |
| EXPAND | RESOLVER | Distribution group expanded to members | ~2% | success |
| DEFER | QUEUE | Delivery temporarily delayed (retry pending) | ~1% | failure |
| TRANSFER | ROUTING | Message forked (content conversion, bifurcation) | ~1% | success |
| FAIL | SMTP / QUEUE / DNS | Permanent delivery failure | ~0.5% | failure |
| DSN | DSN | Delivery Status Notification (bounce/NDR) | ~0.5% | success |
| REDIRECT | RESOLVER | Message redirected to alternate recipient | ~0.3% | success |
| DROP | AGENT | Message silently dropped (spam, policy block) | ~0.3% | success |

## Realism Features

- **Cross-template message correlation** — RECEIVE events push message context (message-id, sender, recipient, subject, size) to a shared pool; downstream events (DELIVER, SEND, SUBMIT, etc.) sample from the pool to produce correlated event chains
- **Lognormal message sizes** — `module.rand.number.lognormal()` produces realistic right-skewed size distribution (most messages 2–75 KB, some up to 25 MB)
- **Anti-spam verdicts** — AGENTINFO events include realistic SCL, SFV, IPV, BCL, and country code fields in `custom_data` with weighted distributions
- **Distribution group expansion** — EXPAND events reference real group names from sample data with `related_recipient_address` and `recipient_count` from group membership
- **Weighted external domain selection** — inbound senders drawn from weighted pool (Gmail, Outlook dominate; niche providers are rare)
- **Categorized email subjects** — two-step selection: weighted category (business, automated, newsletter, spam, phishing) then random within category
- **Monotonic counters** — `internal_message_id` sequence with overflow wrapping at 2^31-1
- **Realistic connector names** — frontend receive connectors, send connectors matching Exchange naming conventions
- **DSN correlation** — bounce events reference original message-id with empty return-path (`<>`)
- **Failure diversity** — FAIL events include 6 different SMTP error codes; DEFER events include 5 different temporary failure reasons

## Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `hostname` | `EXCH01` | Exchange server short name |
| `domain` | `contoso.com` | Organization domain |
| `server_ip` | `10.0.1.10` | Exchange server IP address |
| `dag_name` | `DAG01` | Database Availability Group name |
| `ad_site` | `Default-First-Site-Name` | Active Directory site |
| `schema_version` | `15.02.1544.009` | Exchange schema version (CU14) |
| `agent_id` | `a1b2c3d4-...` | Elastic Agent UUID |
| `agent_version` | `8.17.0` | Elastic Agent version |
| `ecs_version` | `8.17.0` | ECS version |
| `max_message_pool` | `80` | Max messages in correlation pool |

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
  --path generators/email-exchange/generator.yml \
  --id exch \
  --live-mode true

# Batch mode (generate as fast as possible, then stop)
eventum generate \
  --path generators/email-exchange/generator.yml \
  --id exch \
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
  exchange:
    path: generators/email-exchange/generator.yml
    params:
      hostname: EXCH-PROD
      domain: mycorp.com
      server_ip: "10.10.5.20"
```

## Sample Output

```json
{
  "@timestamp": "2026-02-22T17:06:16+00:00",
  "agent": {
    "ephemeral_id": "a3065800-f0a7-4a1a-8bc6-dd80589ba492",
    "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "name": "EXCH01",
    "type": "filebeat",
    "version": "8.17.0"
  },
  "destination": {
    "domain": "contoso.com",
    "ip": "10.0.1.10",
    "user": {
      "email": "d.brown@contoso.com",
      "name": "d.brown"
    }
  },
  "ecs": { "version": "8.17.0" },
  "email": {
    "direction": "inbound",
    "delivery_timestamp": "2026-02-22T17:06:16+00:00",
    "from": { "address": ["washingtonlaura@partner-corp.com"] },
    "local_id": "a28cc2d2-7cae-40e5-b969-26100937968c",
    "message_id": "<8c1014ded8af460497c9189b4470b611@mail.partner-corp.com>",
    "subject": "MFA enrollment reminder",
    "to": { "address": ["d.brown@contoso.com"] },
    "attachments": { "file": { "size": 18211 } }
  },
  "event": {
    "action": "receive",
    "category": ["email"],
    "dataset": "microsoft_exchange.messagetracking",
    "kind": "event",
    "module": "microsoft_exchange",
    "outcome": "success",
    "type": ["info"]
  },
  "microsoft_exchange": {
    "messagetracking": {
      "client_ip": "203.0.113.50",
      "client_hostname": "mail.partner-corp.com",
      "server_ip": "10.0.1.10",
      "server_hostname": "EXCH01.contoso.com",
      "source_context": "08DC9B0C54F70E7D;2026-02-22T17:06:16.284Z;1",
      "connector_id": "EXCH01\\Default Frontend EXCH01",
      "source": "SMTP",
      "event_id": "RECEIVE",
      "internal_message_id": 18,
      "network_message_id": "a28cc2d2-7cae-40e5-b969-26100937968c",
      "recipient_status": "250 2.1.5 Recipient OK",
      "recipient_count": 1,
      "return_path": "washingtonlaura@partner-corp.com",
      "directionality": "Incoming",
      "custom_data": "S:DeliveryPriority=Normal;S:AccountForest=contoso.com",
      "transport_traffic_type": "Email",
      "schema_version": "15.02.1544.009"
    }
  },
  "observer": {
    "hostname": "EXCH01.contoso.com",
    "ip": ["10.0.1.10"],
    "product": "Exchange Server",
    "type": "mail",
    "vendor": "Microsoft",
    "version": "15.02.1544.009"
  },
  "related": {
    "ip": ["203.0.113.50", "10.0.1.10"],
    "user": ["washingtonlaura", "d.brown"]
  },
  "source": {
    "domain": "partner-corp.com",
    "ip": "203.0.113.50",
    "user": {
      "email": "washingtonlaura@partner-corp.com",
      "name": "washingtonlaura"
    }
  },
  "tags": ["microsoft-exchange", "forwarded"]
}
```

## File Structure

```
generators/email-exchange/
  generator.yml                              # Pipeline config
  README.md                                  # This file
  templates/
    receive-inbound.json.jinja               # RECEIVE — external SMTP (producer)
    receive-internal.json.jinja              # RECEIVE — internal STOREDRIVER (producer)
    deliver.json.jinja                       # DELIVER — mailbox delivery (consumer)
    send.json.jinja                          # SEND — SMTP inter-service (consumer)
    submit.json.jinja                        # SUBMIT — mailbox submission (consumer)
    haredirect.json.jinja                    # HAREDIRECT — shadow redundancy create
    hadiscard.json.jinja                     # HADISCARD — shadow message discarded
    notifymapi.json.jinja                    # NOTIFYMAPI — Outbox detection
    agentinfo.json.jinja                     # AGENTINFO — anti-spam/transport rules
    resolve.json.jinja                       # RESOLVE — AD recipient resolution
    expand.json.jinja                        # EXPAND — distribution group expansion
    transfer.json.jinja                      # TRANSFER — message fork/bifurcation
    defer.json.jinja                         # DEFER — temporary delivery failure
    fail.json.jinja                          # FAIL — permanent delivery failure
    dsn.json.jinja                           # DSN — bounce/NDR generation
    drop.json.jinja                          # DROP — silent message drop (spam)
    redirect.json.jinja                      # REDIRECT — alternate recipient
  samples/
    internal_users.csv                       # 20 internal mailbox users
    external_domains.json                    # 14 weighted external mail domains
    subjects.json                            # 53 categorized email subjects
    connectors.json                          # Exchange receive/send connectors
    distribution_groups.json                 # 10 weighted distribution groups
  output/
    events.json                              # Generated events
```

## References

- [Message tracking — Microsoft Learn](https://learn.microsoft.com/en-us/exchange/mail-flow/transport-logs/message-tracking) — Event types, source values, field structure
- [Mail flow and transport pipeline — Microsoft Learn](https://learn.microsoft.com/en-us/exchange/mail-flow/mail-flow) — Transport services architecture
- [Anti-spam message headers — Microsoft Learn](https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/message-headers-eop-mdo) — X-Forefront-Antispam-Report fields
- [ECS Email Fields RFC 0010](https://github.com/elastic/ecs/blob/main/rfcs/text/0010-email.md) — Elastic Common Schema email field definitions
- [Elastic microsoft_exchange integration](https://github.com/elastic/integrations/tree/main/packages/microsoft_exchange_online_message_trace) — Integration package

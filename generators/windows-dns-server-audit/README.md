# Microsoft DNS Server Audit and Analytical Logs

Produces ECS-compatible Windows DNS Server Audit and Analytical events. The Audit channel carries configuration changes; the Analytical channel carries DNS query and response records. A real deployment must enable Analytical logging separately.

Reference field coverage: **63/63 fields across the three [Elastic DNS Audit parsed test events](https://github.com/elastic/integrations/blob/main/packages/microsoft_dnsserver/data_stream/audit/_dev/test/pipeline/test-events.json-expected.json). This reference includes ingestion and host metadata, which the pack fills with stable synthetic values. Analytical 256/257 messages follow the Microsoft event catalog rather than that Audit-only fixture.**

## Event Types

| Native event ID | Meaning | Routine selection |
| --- | --- | ---: |
| 256 → 257 | Query received, then linked success response | 85% of routine starts |
| 536 | Cache record purged | 8% |
| 514 | Zone setting updated | 5% |
| 540 | Root hints modified | 2% |
| 577 → 256 × 3 → 580 | Policy created, unanswered queries, policy deleted | Anomaly only |

Routine percentages are configured selection weights, not measured vendor frequencies. One reusable Jinja template covers the FSM states; the source-specific native records are emitted alongside normalized ECS fields. The `event.sequence` and device counters are bounded.

## Anomaly Chain

At every 250 routine starts, the state machine creates server-level policy `ShadowIgnore` (event 577) with `Action=Ignore` and criteria `FQDN=EQ,*.updates.corp.example`. Three event-256 queries for `beacon.updates.corp.example` then arrive from `10.20.4.17` without corresponding 257 responses. Event 580 deletes the same policy. Correlate by DNS server, policy name, criteria, QNAME, client IP, XID, and timestamps. A rule can detect a short-lived Ignore policy or a sudden query-to-response gap for a domain. The absence of a response is an inference from the generated stream, not a direct error event. DNS Analytical logging must be enabled in a real installation to see queries.

`anomaly_mode: true` is the default. Set `event.template.params.anomaly_mode: false` to generate routine background only. The anomaly identities and targeted objects do not appear in background mode.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Meaning |
| --- | --- | --- |
| `server_name`, `server_ip` | `dns-01.corp.example`, `10.20.0.53` | Single DNS server identity |
| `admin_name` | `DNSAdmin` | Audit change actor |
| `client_ip` | `10.20.4.17` | Query source for the chain |
| `normal_zone`, `anomaly_zone` | `corp.example`, `updates.corp.example` | Normal and targeted DNS namespaces |
| `policy_name` | `ShadowIgnore` | Short-lived Ignore policy |
| `anomaly_interval_events` | `250` | Routine starts between chains; counter is bounded |
| `anomaly_mode` | `true` | Include chain; `false` emits background only |

### Output Parameters

The shipped configuration writes `output/events.json` locally and needs no `${params.*}` or `${secrets.*}` overrides. Change `output.file.path` or replace the output plugin when connecting to a SIEM.

## Usage

From the content-packs repository root:

```bash
eventum generate --path generators/windows-dns-server-audit/generator.yml --id windows-dns-server-audit --live-mode true
```

Adjust the cron expression and count in `generator.yml` for a different event rate.

## Sample Output

Copied from a real enabled-mode generator run:

```json
{
  "@timestamp": "2026-09-25T14:34:02+00:00",
  "data_stream": {
    "dataset": "microsoft_dnsserver.audit",
    "namespace": "default",
    "type": "logs"
  },
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "POLICY_OP",
    "agent_id_status": "verified",
    "category": [
      "configuration"
    ],
    "code": "577",
    "created": "2026-09-25T14:34:02+00:00",
    "dataset": "microsoft_dnsserver.audit",
    "ingested": "2026-09-25T14:34:02+00:00",
    "kind": "event",
    "provider": "Microsoft-Windows-DNSServer",
    "sequence": 9812,
    "type": [
      "creation"
    ]
  },
  "host": {
    "architecture": "x86_64",
    "hostname": "dns-01.corp.example",
    "id": "d0500000-1111-4444-8888-123456789abc",
    "ip": [
      "10.20.0.53"
    ],
    "mac": [
      "02-42-AC-11-00-53"
    ],
    "name": "dns-01.corp.example",
    "os": {
      "build": "20348.2322",
      "family": "windows",
      "kernel": "10.0.20348.2322 (WinBuild.160101.0800)",
      "name": "Windows Server 2022 Datacenter",
      "platform": "windows",
      "type": "windows",
      "version": "10.0"
    }
  },
  "input": {
    "type": "winlog"
  },
  "log": {
    "level": "information"
  },
  "message": "A server level policy ShadowIgnore for Query processing has been created on server dns-01.corp.example with following properties: Processing order:1; Criteria:FQDN=EQ,*.updates.corp.example; Action:Ignore; Condition:And; IsEnabled:True.",
  "microsoft_dnsserver": {
    "audit": {
      "action": "Ignore",
      "condition": "And",
      "criteria": "FQDN=EQ,*.updates.corp.example",
      "is_enabled": "True",
      "name_server": "dns-01.corp.example",
      "policy": "ShadowIgnore",
      "processing_order": "1",
      "type": "Query processing"
    }
  },
  "process": {
    "pid": 852,
    "thread": {
      "id": 7708
    }
  },
  "related": {
    "user": [
      "DNSAdmin"
    ]
  },
  "tags": [
    "preserve_duplicate_custom_fields"
  ],
  "user": {
    "name": "DNSAdmin"
  },
  "winlog": {
    "api": "wineventlog",
    "channel": "Microsoft-Windows-DNSServer/Audit",
    "computer_name": "dns-01.corp.example",
    "event_data": {
      "Action": "Ignore",
      "Condition": "And",
      "Criteria": "FQDN=EQ,*.updates.corp.example",
      "IsEnabled": "True",
      "Policy": "ShadowIgnore",
      "ProcessingOrder": "1",
      "ServerName": "dns-01.corp.example",
      "Type": "Query processing"
    },
    "event_id": "577",
    "keywords": [
      "AUDIT_POLICY"
    ],
    "opcode": "Info",
    "provider_guid": "{eb79061a-a566-4698-9119-3ed2807060e7}",
    "provider_name": "Microsoft-Windows-DNSServer",
    "record_id": "9812",
    "task": "POLICY_OP",
    "user": {
      "domain": "dns-01.corp.example",
      "identifier": "S-1-5-21-1000000000-1000000000-1000000000-500",
      "name": "DNSAdmin",
      "type": "User"
    }
  }
}
```

## References and Limits

- [Microsoft DNS logging and event IDs](https://learn.microsoft.com/en-us/windows-server/networking/dns/dns-logging-and-diagnostics): 256/257 Analytical and 514/536/540/577/580 Audit families.
- [Elastic Microsoft DNS Server integration](https://github.com/elastic/integrations/tree/main/packages/microsoft_dnsserver/data_stream/audit): normalized Audit fields.
- [KUMA 4.0 supported sources](https://support.kaspersky.com/kuma/4.0/en-US/255782.htm): source prioritization.

The generated policy is a synthetic security scenario. Audit messages alone do not prove whether a query was dropped; that conclusion requires correlating Analytical query and response events. The query and response IDs are paired by XID for ordinary traffic.

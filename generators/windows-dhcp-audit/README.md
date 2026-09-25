# Microsoft DHCP Server CSV Audit Log

Produces ECS-compatible events with the native Windows `DhcpSrvLog` CSV line in `event.original`, including lease assignment, renewal, release, DNS update and failover records.

Reference field coverage: **40/40 fields in the [Elastic Microsoft DHCP sample event](https://github.com/elastic/integrations/blob/main/packages/microsoft_dhcp/data_stream/log/sample_event.json). Filebeat/host metadata is stable synthetic context; the CSV line itself is the native source.**

## Event Types

| CSV ID | Meaning | Routine weight |
| --- | --- | ---: |
| 10 | Assign | 45% |
| 11 | Renew | 30% |
| 12 | Release | 8% |
| 30 | DNS Update Request | 8% |
| 32 | DNS Update Successful | 5% |
| 31 | DNS Update Failed | 2% |
| 36 | Failover/Client ID hash drop | 2% |

Routine percentages are configured selection weights, not measured vendor frequencies. One reusable Jinja template covers the FSM states; the source-specific native records are emitted alongside normalized ECS fields. The `event.sequence` and device counters are bounded.

## Anomaly Chain

The same synthetic client ID `0023DF0000A1` and hostname `ws-finance-01.corp.example` receive addresses `10.20.7.41`, `.42`, and `.43` through 10 Assign events. The first two assignments are quickly followed by 12 Release. The third is followed by 30 DNS Update Request and 31 DNS Update Failed. Correlate by `source.mac`, `source.domain`, server, the sequence of `source.ip` values, and timestamps. Rules can flag rapid lease churn or DNS update failure after address churn. This pattern may be misconfiguration or client instability; the CSV log alone does not establish a malicious actor. ID 36 is ordinary failover telemetry and is not used as an attack signal.

`anomaly_mode: true` is the default. Set `event.template.params.anomaly_mode: false` to generate routine background only. The anomaly identities and targeted objects do not appear in background mode.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Meaning |
| --- | --- | --- |
| `server_name`, `server_ip` | `dhcp-01.corp.example`, `10.20.0.10` | Single DHCP server identity |
| `anomaly_hostname`, `anomaly_client_id` | `ws-finance-01.corp.example`, `0023DF0000A1` | Correlated lease client |
| `anomaly_ips` | `10.20.7.41`–`.43` | Successive addresses |
| `anomaly_interval_events` | `250` | Routine events between chains; counter is bounded |
| `anomaly_mode` | `true` | Include chain; `false` emits background only |

### Output Parameters

The shipped configuration writes `output/events.json` locally and needs no `${params.*}` or `${secrets.*}` overrides. Change `output.file.path` or replace the output plugin when connecting to a SIEM.

## Usage

From the content-packs repository root:

```bash
eventum generate --path generators/windows-dhcp-audit/generator.yml --id windows-dhcp-audit --live-mode true
```

Adjust the cron expression and count in `generator.yml` for a different event rate.

## Sample Output

Copied from a real enabled-mode generator run:

```json
{
  "@timestamp": "2026-09-25T12:00:09+00:00",
  "agent": {
    "ephemeral_id": "a1b2c3d4-1111-4444-8888-123456789abc",
    "id": "a1b2c3d4-1111-4444-8888-123456789abc",
    "name": "dhcp-01.corp.example",
    "type": "filebeat",
    "version": "8.17.0"
  },
  "data_stream": {
    "dataset": "microsoft_dhcp.log",
    "namespace": "default",
    "type": "logs"
  },
  "ecs": {
    "version": "8.17.0"
  },
  "elastic_agent": {
    "id": "a1b2c3d4-1111-4444-8888-123456789abc",
    "snapshot": false,
    "version": "8.17.0"
  },
  "event": {
    "action": "dhcp-dns-update",
    "agent_id_status": "verified",
    "category": [
      "network"
    ],
    "code": "31",
    "dataset": "microsoft_dhcp.log",
    "ingested": "2026-09-25T12:00:09+00:00",
    "kind": "event",
    "original": "31,09/25/26,12:00:09,DNS Update Failed,10.20.7.43,ws-finance-01.corp.example,0023DF0000A1,,0,6,,,,,,,,,10054",
    "outcome": "failure",
    "reason": "DNS update failed.",
    "sequence": 257,
    "timezone": "UTC",
    "type": [
      "connection"
    ]
  },
  "host": {
    "ip": [
      "10.20.0.10"
    ],
    "mac": [
      "02-42-AC-11-00-10"
    ],
    "name": "dhcp-01.corp.example"
  },
  "input": {
    "type": "log"
  },
  "log": {
    "file": {
      "path": "C:\\Windows\\System32\\Dhcp\\DhcpSrvLog-Fri.log"
    },
    "offset": 23604
  },
  "message": "DNS Update Failed",
  "observer": {
    "hostname": "dhcp-01.corp.example",
    "ip": [
      "10.20.0.10"
    ],
    "mac": [
      "02-42-AC-11-00-10"
    ]
  },
  "related": {
    "hosts": [
      "ws-finance-01.corp.example"
    ],
    "ip": [
      "10.20.7.43"
    ]
  },
  "source": {
    "address": "ws-finance-01.corp.example",
    "domain": "ws-finance-01.corp.example",
    "ip": "10.20.7.43",
    "mac": "00-23-DF-00-00-A1"
  },
  "tags": [
    "preserve_original_event",
    "microsoft_dhcp"
  ]
}
```

## References and Limits

- [Elastic Microsoft DHCP raw CSV test lines](https://github.com/elastic/integrations/blob/main/packages/microsoft_dhcp/data_stream/log/_dev/test/pipeline/test-log.log): IDs and column ordering.
- [Microsoft DHCP failover events](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn338988%28v%3Dws.11%29): ID 36 is informational.
- [Microsoft DHCP Server events](https://learn.microsoft.com/en-us/windows-server/networking/technologies/dhcp/dhcp-server-events): complementary Event Viewer telemetry.
- [KUMA 4.0 supported sources](https://support.kaspersky.com/kuma/4.0/en-US/255782.htm): source prioritization.

The native CSV log has no reliable administrator identity for these lease records. Its lines should not be interpreted as DHCP configuration audit events. We model a client behavior anomaly only.

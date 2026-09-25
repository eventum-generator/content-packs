# Microsoft DHCP Server CSV Audit Log

Generates Windows DHCP Server audit rows in `event.original` with ECS fields shaped like the Elastic Microsoft DHCP integration. The modeled server has 97 Windows clients across two private subnets, each with a configured eight-hour lease duration. Its one-minute input ticks skip idle periods. All clients start with pre-existing valid leases; subsequent renewals, releases, and reassignments obey per-client state. Renewals occur no sooner than four hours after the preceding lease event, while releases have a separate timer. Each DNS result follows a request for the same host and IP.

The emitted records use the 19-column CSV variant shown in Elastic's raw fixture and Microsoft's full ID 11 example. Dates are modeled in UTC, which is also the explicit `event.timezone` used to interpret the timezone-free CSV line. File names follow the source's weekday rotation.

## Event Types

| CSV ID | Native description | Background behavior |
| --- | --- | --- |
| 10 | Assign | Reassignment after release |
| 11 | Renew | Active lease reaches its four-hour renewal time |
| 12 | Release | Active client lease released |
| 30 | DNS Update Request | May follow an assignment or renewal |
| 32 | DNS Update Successful | Follows ID 30 for the same host and IP |
| 31 | DNS Update Failed | Follows ID 30 for the same host and IP; uses the observed `10054` error code |

Each active client has an independent release timer: 2–24 hours for the 13 mobile clients and 1–7 days for stationary clients. After a background release, a client reconnects in 30–180 minutes; a renewal is scheduled four hours after an assignment or previous renewal. A DNS request follows 30% of assignments or 5% of renewals, and 5% of requests fail. Request and result events are separated by 1–8 seconds. These are synthetic selection settings, not measured Microsoft frequencies. The background includes ID 31, the target client, and all four target addresses. The target has one row in the 97-client sample, so it is not overrepresented in the client pool.

## Anomaly Chain

After at least 250 background rows, `anomaly_mode: true` emits one eight-row sequence for `ws-finance-01.corp.example` / client ID `0023DF0000A1`:

1. ID 12 releases its current lease.
2. IDs 10 and 12 assign then release `10.20.7.41`.
3. IDs 10 and 12 assign then release `10.20.7.42`.
4. ID 10 assigns `10.20.7.43`, followed by ID 30 DNS Update Request and ID 31 DNS Update Failed for that address.

The sequence takes less than seven minutes, with one-minute ticks for lease events and 1–8 seconds between the final assignment, DNS request, and DNS result. Join lease rows by MAC/client ID, hostname, and server. Native DNS rows leave the MAC column empty, as in Elastic's raw examples, so join IDs 30/31 to the final lease by hostname, IP, server, and time. A rule can detect three distinct assignments with two intervening releases for one client within six minutes, then a DNS failure for the final address within 20 seconds of its assignment. The DNS failure coincides with rapid address churn; the log does not prove that the churn caused the failure or that a malicious actor is involved.

`anomaly_mode` defaults to `true`. Set it to `false` for ordinary background only. Both modes use the same target identity, addresses, event IDs, and error code. The timed sequence is the anomaly, not any single row.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Meaning |
| --- | --- | --- |
| `server_name`, `server_ip` | `dhcp-01.corp.example`, `10.20.0.10` | DHCP server identity |
| `anomaly_hostname`, `anomaly_client_id` | `ws-finance-01.corp.example`, `0023DF0000A1` | Client used in the correlated sequence and normal traffic |
| `anomaly_base_ip` | `10.20.7.40` | Target client's ordinary starting address |
| `anomaly_ips` | `10.20.7.41`, `.42`, `.43` | Successive anomaly addresses; also rotate in normal traffic after releases |
| `anomaly_after_events` | `250` | Minimum number of background rows before the one-time sequence |
| `lease_renew_minutes` | `240` | Four-hour renewal time for the modeled eight-hour lease |
| `anomaly_mode` | `true` | Include one sequence; `false` produces background only |

The 97-client pool is in `samples/clients.json`; `mobile` selects the shorter ordinary release interval. Change that file to model another client population. Keep the four target addresses distinct and outside the other clients' addresses.

### Output Parameters

The shipped configuration writes `output/events.json` locally. It has no required top-level `${params.*}` or `${secrets.*}` overrides. Change `output.file.path` or replace the output plugin when connecting to a SIEM.

## Usage

From the content-packs repository root:

```bash
uv run --project ../eventum eventum generate --path generators/windows-dhcp-audit/generator.yml --id windows-dhcp-audit --live-mode true
```

For an existing Eventum installation, run `eventum generate` with the same arguments. The five-field cron expression offers one timestamp per minute. The state model drops idle ticks, so output volume follows the 97-client lease and release schedules. Adjust the cron interval, client sample, and timers together for another fleet.

## Sample Output

The following event was copied from the enabled-mode seven-day validation run:

```json
{
  "@timestamp": "2026-09-25T08:57:13+00:00",
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
    "ingested": "2026-09-25T08:57:13+00:00",
    "kind": "event",
    "original": "31,09/25/26,08:57:13,DNS Update Failed,10.20.7.43,ws-finance-01.corp.example,,,0,6,,,,,,,,,10054",
    "outcome": "failure",
    "reason": "DNS update failed.",
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
    "offset": 31774
  },
  "message": "DNS Update Failed",
  "microsoft": {
    "dhcp": {
      "dns_error_code": "10054",
      "result": "6",
      "result_description": "No Quarantine Information",
      "transaction_id": "0"
    }
  },
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
    "ip": "10.20.7.43"
  },
  "tags": [
    "preserve_original_event",
    "microsoft_dhcp"
  ]
}
```

## Evidence and Limits

- [Microsoft DHCP Server audit-log format and ID catalog](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/dd183591(v=ws.10)) establishes IDs 10/11/12 and 30/31/32, but documents the older seven-column baseline rather than the newer 19-column suffix.
- [Microsoft's full ID 11 row](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/event-4199-windows-client-cannot-get-ip-address-dhcp-server) shows a nonzero transaction ID, result 0, and `MSFT 5.0` vendor class.
- [Elastic's first-party raw fixture](https://github.com/elastic/integrations/blob/main/packages/microsoft_dhcp/data_stream/log/_dev/test/pipeline/test-log.log) provides full ID 10, 30, and 31 rows. Its [ingest pipeline](https://github.com/elastic/integrations/blob/main/packages/microsoft_dhcp/data_stream/log/elasticsearch/ingest_pipeline/dhcp.yml) maps the extended columns and ECS fields. The [Elastic sample event](https://github.com/elastic/integrations/blob/main/packages/microsoft_dhcp/data_stream/log/sample_event.json) has 40 leaf fields; all 40 paths occur in generated output. That sample is ID 35, which this generator does not emit, so field coverage is not ID 35 behavior validation.
- [Microsoft's DHCP troubleshooting guide](https://learn.microsoft.com/en-us/windows-server/troubleshoot/troubleshoot-dhcp-issue) documents renewal at half the lease duration; [Add-DhcpServerv4Scope](https://learn.microsoft.com/en-us/powershell/module/dhcpserver/add-dhcpserverv4scope?view=windowsserver2025-ps) shows the configurable scope duration and its eight-day default. This pack intentionally models a shorter eight-hour lease duration across its client subnets.
- [Microsoft's dynamic DNS documentation](https://learn.microsoft.com/en-us/windows-server/networking/dns/dynamic-update) supports DHCP updates on client behalf. [Microsoft's weekday log-name specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ipamm/39bcd84c-4d67-4711-85cc-6a03eaf1bb3d) supports the `DhcpSrvLog-<weekday>.log` path. [Windows QuarantineStatus](https://learn.microsoft.com/en-us/windows/win32/api/dhcpsapi/ne-dhcpsapi-quarantinestatus) defines result values 0 and 6.

**Raw-evidence limit:** no complete current Microsoft ID 12 CSV row was found. Its event meaning is documented, but the extended optional columns for release rows are inferred from the ID 10/11 lease layout. Collector fields such as Filebeat IDs, `event.ingested`, and `log.offset` are synthetic. This pack remains a draft until the ID 12 suffix is checked against a native capture.

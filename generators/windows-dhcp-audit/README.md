# Microsoft DHCP Server CSV Audit Log

Generates the 19-column IPv4 DHCP audit CSV variant, with parsed ECS JSON in the output file and the native row in `event.original`. This is the Windows DHCP audit file stream, not Windows Event Log or IPv6. The selected format follows complete Microsoft, Elastic and Graylog integration examples. Those examples do not identify an exact Windows Server build. The modeled server runs in UTC, so both the timezone-free CSV date/time and `event.timezone: UTC` agree even when the input CLI uses another timezone. Weekday file names follow the server's UTC day.

The server has 97 Windows clients across two private subnets. All start with pre-existing valid leases and staggered first renewal times. The default synthetic lease duration is eight hours, with T1 renewal scheduled after four hours. Each successful assignment/renewal refreshes the full lease lifetime. Releases only apply to an active matching client/IP. The state model retires an expired lease before issuing a new assignment; lease-expiry audit IDs 17/18 are outside this selected emitted subset. The default one-minute cadence keeps observed renewals before expiration. Lease lifetime is internal simulation state, not an invented CSV column.

## Event Types

| CSV ID | Native description | Background behavior |
| --- | --- | --- |
| 10 | Assign | New assignment after release or expired state |
| 11 | Renew | Existing active lease reaches T1 |
| 12 | Release | Client releases its active matching lease; vendor-class fields are empty |
| 30 | DNS Update Request | May follow assignment or renewal |
| 32 | DNS Update Successful | Result for the same host and IP as ID 30 |
| 31 | DNS Update Failed | Result for the same host and IP; observed error `10054` |

The 13 mobile clients release after 2–24 hours, stationary clients after 1–7 days. Background reconnect is scheduled 30–180 minutes after release. Due operations compete for one input tick and can wait longer than the timer. DNS requests follow 30% of assignments or 5% of renewals, and 5% of results fail. The request follows its lease event by 1–8 seconds, and its result follows by another 1–8 seconds. These rates and fleet timers are synthetic choices, not measured Microsoft frequencies. Pending DNS events finish before another lease operation or episode begins.

Both modes include the target client, all four target addresses, releases, assignments, renewals and ordinary DNS failures. Assign/Renew carry the observed `MSFT 5.0` vendor class; Release and DNS rows leave it empty. DNS rows also leave native MAC empty and use transaction ID 0 / QResult 6. Lease rows use a nonzero synthetic 32-bit transaction ID and QResult 0. No transaction ID is claimed to identify a client session.

## Anomaly Chain

`anomaly_mode: true` repeats an eight-row address-churn episode every 24 hours of generated source time by default. When due, it waits for pending DNS to finish and for the target to have a valid lease, then starts on the next input tick. A target awaiting ordinary reconnect can defer an episode. The next interval is measured from the actual initial release, so episodes do not overlap or catch up in a burst.

1. ID 12 releases the target's current active address.
2. ID 10 assigns another address, followed by ID 12 for that same address.
3. ID 10 assigns a second address, followed by ID 12 for that address.
4. ID 10 assigns a third distinct address, then ID 30 and ID 31 for the final hostname/IP.

The three assigned addresses come from the same four-address pool used by ordinary reconnects. Their order varies between adjacent episodes using a bounded rotation; addresses can be reused in later episodes. Lease transaction IDs vary per operation. The eight records take less than seven minutes: one-minute ticks plus 0–59 second jitter for lease events, and the two short DNS gaps. Join lease rows by MAC/client ID, hostname and server. Native DNS rows have no MAC, so join to the final assignment by hostname, IP, server and time. A rule can detect three distinct assignments with two intervening releases within six minutes, followed by DNS failure within 20 seconds of the final assignment. The failure coincides with churn; these logs do not establish causation or a malicious actor.

`anomaly_mode` defaults to `true`. Set it to `false` for ordinary background without the complete fast sequence. No extra native marker or synthetic event sequence identifies an episode.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Meaning |
| --- | --- | --- |
| `server_name`, `server_ip` | `dhcp-01.corp.example`, `10.20.0.10` | DHCP server identity |
| `anomaly_hostname`, `anomaly_client_id` | `ws-finance-01.corp.example`, `0023DF0000A1` | Client used in episodes and ordinary traffic |
| `anomaly_base_ip` | `10.20.7.40` | Target's initial address, also in the rotating pool |
| `anomaly_ips` | `10.20.7.41`, `.42`, `.43` | Three more pool addresses; their episode order varies |
| `anomaly_interval_hours` | `24` | Positive recurrence interval, clamped to at least one hour |
| `lease_renew_minutes` | `240` | T1, clamped to at least 240 minutes; full modeled lease is twice T1 |
| `anomaly_mode` | `true` | Periodic episodes mixed with background; `false` for background only |

Use lower-case ASCII hostnames and uppercase 12-hex Ethernet client IDs. Keep the four target IPv4 addresses distinct, in one client subnet, and outside other clients' addresses. Keep the target hostname/client ID distinct from the other 96 clients. The pool is in `samples/clients.json`; `mobile` selects the shorter release timer. The shipped source cadence is one tick per minute with count 1. Adjust fleet and timers together when changing cadence or population. State is bounded by 97 leases, one pending DNS pair, three episode addresses and scalar scheduler/cursor/file counters.

### Output Parameters

The shipped config writes `output/events.json` locally. It has no required top-level `${params.*}` or `${secrets.*}` substitutions. Change the file path or output plugin for SIEM delivery.

## Usage

From the content-packs repository root:

```bash
uv run --project ../eventum eventum generate --path generators/windows-dhcp-audit/generator.yml --id windows-dhcp-audit --live-mode true
```

For a finite eight-day-and-six-hour sample covering multiple default episodes, create a config beside the original so relative sample/template paths stay valid:

```bash
uv run --project ../eventum python - <<'PYCONFIG'
from pathlib import Path
import yaml
root = Path('generators/windows-dhcp-audit')
config = yaml.safe_load((root / 'generator.yml').read_text())
config['input'][0]['cron'].update(
    start='2026-09-25T00:00:00+00:00',
    end='2026-10-03T06:00:00+00:00',
)
(root / '.finite.yml').write_text(yaml.safe_dump(config, sort_keys=False))
PYCONFIG
flock -x /tmp/eventum-generator-heavy.lock uv run --project ../eventum eventum generate --path generators/windows-dhcp-audit/.finite.yml --id windows-dhcp-sample --live-mode false --keep-order true
rm generators/windows-dhcp-audit/.finite.yml
```

Idle input ticks are dropped, so row count depends on generated lease/release/DNS schedules. Set `anomaly_mode: false` in the temporary config for the same background window. A finite run may end with a pending DNS result; the generator does not fabricate a completion.

## Sample Output

This synthetic Release event was copied from a verified enabled-mode run. Its optional vendor-class columns are empty, matching the observed ID 12 variant. The same shape occurs in background; this is not a vendor capture.

```json
{
  "@timestamp": "2026-09-26T00:02:08+00:00",
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
    "action": "dhcp-release",
    "agent_id_status": "verified",
    "category": [
      "network"
    ],
    "code": "12",
    "dataset": "microsoft_dhcp.log",
    "ingested": "2026-09-26T00:02:08+00:00",
    "kind": "event",
    "original": "12,09/26/26,00:02:08,Release,10.20.7.42,ws-finance-01.corp.example,0023DF0000A1,,3812757102,0,,,,,,,,,0",
    "outcome": "success",
    "reason": "A lease was released by a client.",
    "timezone": "UTC",
    "type": [
      "allowed",
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
      "path": "C:\\Windows\\System32\\Dhcp\\DhcpSrvLog-Sat.log"
    },
    "offset": 0
  },
  "message": "Release",
  "microsoft": {
    "dhcp": {
      "dns_error_code": "0",
      "result": "0",
      "result_description": "NoQuarantine",
      "transaction_id": "3812757102"
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
      "10.20.7.42"
    ]
  },
  "source": {
    "address": "ws-finance-01.corp.example",
    "domain": "ws-finance-01.corp.example",
    "ip": "10.20.7.42",
    "mac": "00-23-DF-00-00-A1"
  },
  "tags": [
    "preserve_original_event",
    "microsoft_dhcp"
  ]
}
```

## References and Limits

- [Microsoft audit-log catalog](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/dd183591(v=ws.10)) defines IDs 10/11/12 and 30/31/32. Its older seven-column example does not establish the modern optional suffix.
- [Microsoft full Renew example](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/event-4199-windows-client-cannot-get-ip-address-dhcp-server) shows the extended ID 11 row. [Graylog Illuminate 7.1 DHCP integration](https://go2docs.graylog.org/illuminate-current/content_packs/microsoft_dhcp_content_pack.htm) gives complete Assign/Renew/Release examples, including empty Release vendor columns. Its supported server range is 2016/2019/2022/2025, but the example has no exact build identifier.
- [Elastic raw DHCP fixtures](https://github.com/elastic/integrations/blob/158ba7a3e2c86176f28292a317828261ec3782c1/packages/microsoft_dhcp/data_stream/log/_dev/test/pipeline/test-log.log) contain complete ID 10/30/31/32 rows. [Elastic pipeline](https://github.com/elastic/integrations/blob/main/packages/microsoft_dhcp/data_stream/log/elasticsearch/ingest_pipeline/dhcp.yml) supplies the manual ECS field/action/QResult mapping. Its [sample event](https://github.com/elastic/integrations/blob/main/packages/microsoft_dhcp/data_stream/log/sample_event.json) is ID 35, which is not generated here; matching field paths does not validate ID semantics.
- [NXLog IPv4 audit header](https://docs.nxlog.co/integrations/dhcp/windows-dhcp-server.html) confirms 19 column names/order. [Microsoft weekday audit files](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ipamm/39bcd84c-4d67-4711-85cc-6a03eaf1bb3d) defines day-of-week naming.
- [Microsoft DHCP lifecycle](https://learn.microsoft.com/en-us/windows-server/troubleshoot/troubleshoot-dhcp-issue) describes T1 at 50% of lease time. [Scope configuration](https://learn.microsoft.com/en-us/powershell/module/dhcpserver/add-dhcpserverv4scope?view=windowsserver2025-ps) documents configurable duration and an eight-day default; this generator intentionally uses eight hours. [Dynamic DNS](https://learn.microsoft.com/en-us/windows-server/networking/dns/dynamic-update) describes server updates on clients' behalf.

**BLOCKED_RAW_EVIDENCE:** individual selected native row variants are now supported by complete examples, including Release. A complete correlated episode and an exact Windows Server build capture remain unavailable after a bounded search. This is a selected synthetic scenario, not full native trace parity. Empty relay-agent/DHCID/user-class/user-name fields model the observed direct-client variant. Scope configuration, lease timers and expiry cleanup are internal assumptions; expiry IDs 17/18, file headers, service lifecycle, failover and IPv6 are omitted. `log.offset` counts only emitted ASCII body rows with CRLF and resets per UTC date; it is not a real file offset including headers. Filebeat identity, host/observer MACs and immediate ingestion timestamps are synthetic collector metadata.

Existing `linux-syslog` DHCP rows are an ISC daemon host stream, and Suricata/NetFlow DHCP traffic is network telemetry. They do not duplicate this Windows server IPv4 CSV audit stream.

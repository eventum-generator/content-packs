# Microsoft DHCP Server CSV Audit Log

Generates the Microsoft DHCP Server IPv4 audit log (`DhcpSrvLog-<Day>.log`, 19-column CSV) as parsed ECS JSON, with the native row in `event.original`. For SIEM and detection engineers who need lease and DNS-update traffic from a Windows DHCP server with a recurring address-churn scenario mixed in. This is the DHCP audit file stream, not Windows Event Log or IPv6. The server runs in UTC, so the timezone-free CSV date/time, `@timestamp` and `event.timezone: UTC` agree even when the input CLI uses another timezone. Weekday file names follow the server's UTC day.

The server has 97 Windows clients in two scopes: 84 desktops and VDI machines in `10.20.4.0/23` and 13 laptops in `10.20.7.0/24`. Each client has its own set of four addresses in its scope (`samples/clients.json`); the sets do not overlap, so an address is never held by two clients.

## Event Types

Shares measured on the final 96-hour default capture (`anomaly_mode: true`, 4,868 rows, four episodes).

| CSV ID | Native description | Share | Category | When it occurs |
| --- | --- | ---: | --- | --- |
| 11 | Renew | 35.2% | network / connection | An active lease reaches T1 |
| 10 | Assign | 17.7% | network / connection | Session start, or reconnect inside a link flap |
| 12 | Release | 17.7% | network / connection | Session end, or the disconnect of a link flap |
| 30 | DNS Update Request | 14.7% | network / connection | After 55% of assignments and 12% of renewals |
| 32 | DNS Update Successful | 13.7% | network / connection | Result of a request, same host and IP |
| 31 | DNS Update Failed | 0.9% | network / connection | Result of a request, native error `10054` |

Every client runs its own processes with random, skewed timing:

- **Sessions.** A session starts with Assign, renews at T1 plus a lognormal delay (median 90 s), and ends with Release. Session length is lognormal (median 4 h for laptops, 30 h for desktops); the offline gap before the next Assign is lognormal (median 2 h / 50 min). Connects are thinned by an hour-of-day curve that is high from 08:00 to 17:00 UTC and low at night.
- **Link flaps.** While a client is active, flap bursts arrive at a per-client rate (median one per 3 h for laptops, 30 h for desktops, also thinned by the hour curve). A flap is Release, then Assign after a lognormal gap (median 45 s); with probability 0.4 another flap follows after a lognormal gap (median 150 s). On each reassignment a laptop gets another address of its set with probability 0.5, a desktop with 0.2 (dock, VLAN or switch-port change); otherwise it gets the previous address back. Background therefore contains fast Release->Assign pairs, bursts of two and more cycles, and address changes by the same client within minutes.
- **DNS updates.** A request follows its lease event, and its result follows the request, after a lognormal delay of a few seconds (median 5 s). A result fails with probability 0.06, or 0.5 when the same client had a failure within the last three hours, so repeated failures by one client occur in background.

These rates are synthetic choices, not measured Microsoft frequencies. Assign/Renew carry the observed `MSFT 5.0` vendor class; Release and DNS rows leave it empty. DNS rows also leave native MAC empty and use transaction ID 0 / QResult 6. Lease rows use a random nonzero 32-bit transaction ID and QResult 0.

## Anomaly Chain

With `anomaly_mode: true`, one laptop's ordinary link flap turns into a churn through three more addresses of its own set within minutes, and the last DNS registration fails. Eight native rows, all for one client:

1. ID 12 releases the current address R.
2. ID 10 assigns address A (not R), then ID 12 releases A.
3. ID 10 assigns address B (not R or A), then ID 12 releases B.
4. ID 10 assigns address C (not R, A or B).
5. ID 30 requests the DNS update for C, and ID 31 reports its failure.

**Linking fields.** Lease rows share `source.mac` (client ID), `source.domain` (hostname) and the server. DNS rows have no native MAC, so they join to the final assignment by hostname, IP and time. Each lease operation has its own transaction ID; no native field identifies the episode.

**Recurrence.** Every `anomaly_interval_hours` (default 24, minimum 4) of generated source time. The first due time falls within the first min(interval, 24 h) of the run; each later due time falls in a window of width min(interval / 4, 6 h) centred one interval after the previous actual start. Due times in both windows are weighted by the square of the hour curve plus a small floor, so episodes land in busy hours. At intervals of 8 h or less, they necessarily cover the whole clock. The episode starts at the next background flap of a laptop after the due time, so the start follows the due time by a random wait (minutes in working hours, longer at night). The next due time counts from that actual start. Missed episodes are not replayed: in the 96-hour 8-hour-interval test run, one of eleven taken-over bursts ended with the laptop's session, leaving a 17-hour gap between complete episodes.

**Variation.** The episode takes over that flap: its first Release is the flap's own Release at the flap's own time, from a laptop other than the previous episode's client. The episode forces the first two continuations of the burst, gives the three reassignments the laptop's three other addresses in random order, and adds a DNS update for the third one that fails. Reassignment and continuation gaps are drawn from the background flap distributions. Measured episodes span 5–17 minutes; the whole sequence nearly always fits within one hour. The laptop's session end, renewals and offline gaps keep their own schedule. After the third reassignment, the burst continues or ends by the background rule, which also draws the next flap time, exactly as after any background burst. If the session ends inside the burst, the burst ends as in background and the episode stays incomplete.

**Detection idea.** For one hostname, three assignments of three distinct new addresses, each separated by a release, followed by a failed DNS update for the last address, within one hour. Every element also occurs alone in background: fast Release->Assign, bursts of several cycles, address changes, and DNS failures after an assignment. Only the complete ordered sequence is the signal. The failure coincides with the churn; these logs do not establish causation or a malicious actor.

**Background guard.** When a background DNS result would complete this sequence within one hour of its first Release, it is written as ID 32 (success) instead of ID 31. The row keeps its time, client and address.

`anomaly_mode` defaults to `true`. Set it to `false` for background only, without the complete sequence.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Meaning |
| --- | --- | --- |
| `server_name` | `dhcp-01.corp.example` | DHCP server name (`host.name`, `observer.hostname`, `agent.name`) |
| `server_ip` | `10.20.0.10` | DHCP server IPv4 address |
| `lease_renew_minutes` | `240` | T1 in minutes, 60–5760; the modeled lease lasts twice T1 |
| `anomaly_mode` | `true` | Recurring episodes mixed with background; `false` for background only |
| `anomaly_interval_hours` | `24` | Episode interval in hours, 4–8760 |

The client fleet is in `samples/clients.json`: hostname, 12-hex client ID, `mobile` (laptop timers and address-change probability) and exactly four addresses per client. Keep the address sets distinct between clients.

### Output Parameters

The shipped config writes `output/events.json` with the `json` formatter. There are no top-level `${params.*}` or `${secrets.*}` substitutions. To deliver elsewhere, replace the `output` section, for example with an `opensearch` or `tcp` output, and keep the `json` formatter.

## Usage

From the content-packs repository root, live mode:

```bash
eventum generate --path generators/windows-dhcp-audit/generator.yml --id windows-dhcp-audit --live-mode true
```

Batch mode for a fixed period: add `start` and `end` to the `cron` input in a copy of `generator.yml` placed next to it (so relative sample and template paths stay valid), then run:

```bash
eventum generate --path generators/windows-dhcp-audit/generator-batch.yml --id windows-dhcp-audit --live-mode false --keep-order true
```

Cover at least two intervals to see more than one episode. The input ticks once per second and ticks with nothing due are dropped, so the row count follows the modeled schedules (about 1,200 rows per day with the shipped fleet). A finite run may end with a pending DNS result.

## Sample Output

The first Release of an episode, copied byte-for-byte from the final default capture. The same shape occurs in background.

```json
{
  "@timestamp": "2026-09-25T11:45:59+00:00",
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
    "ingested": "2026-09-25T11:46:01.840189+00:00",
    "kind": "event",
    "original": "12,09/25/26,11:45:59,Release,10.20.7.209,nb-finance-02.corp.example,0023DFA72F49,,555229266,0,,,,,,,,,0",
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
      "path": "C:\\Windows\\System32\\Dhcp\\DhcpSrvLog-Fri.log"
    },
    "offset": 61406
  },
  "message": "Release",
  "microsoft": {
    "dhcp": {
      "dns_error_code": "0",
      "result": "0",
      "result_description": "NoQuarantine",
      "transaction_id": "555229266"
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
      "nb-finance-02.corp.example"
    ],
    "ip": [
      "10.20.7.209"
    ]
  },
  "source": {
    "address": "nb-finance-02.corp.example",
    "domain": "nb-finance-02.corp.example",
    "ip": "10.20.7.209",
    "mac": "00-23-DF-A7-2F-49"
  },
  "tags": [
    "preserve_original_event",
    "microsoft_dhcp"
  ]
}
```

## Limits

- **No complete native trace.** Individual row variants follow complete vendor and integration examples (below), but no correlated capture of this scenario or of an identified Windows Server build exists. This is a synthetic scenario, not native trace parity.
- **Emitted subset.** Only IDs 10/11/12/30/31/32 are emitted. Lease expiry (IDs 17/18), NACKs, conflicts, relay, failover, service start/stop, file headers and IPv6 are omitted. Relay-agent, DHCID, user-class and user-name columns stay empty (direct clients).
- **Addresses.** Fixed per-client address sets model roaming between ports and VLANs; a real server reuses addresses between clients. A laptop reaches all four of its addresses in background only over time: each 96-hour background capture showed 50–52 of the 52 laptop client/address pairs. Clients always renew at T1, so no lease expires.
- **Collector fields.** `log.offset` counts emitted CSV rows with CRLF and resets per UTC date; it does not include file headers. Filebeat identity, host/observer MACs and the `event.ingested` delay (1 s plus a lognormal delay, median 1.5 s) are synthetic.
- **Rates.** Session, flap, DNS and failure rates, and the hour curve, are synthetic choices.

## References

- [Microsoft audit-log catalog](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/dd183591(v=ws.10)) defines IDs 10/11/12 and 30/31/32. Its older seven-column example does not establish the modern optional suffix.
- [Microsoft full Renew example](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/event-4199-windows-client-cannot-get-ip-address-dhcp-server) shows the extended ID 11 row. [Graylog Illuminate 7.1 DHCP integration](https://go2docs.graylog.org/illuminate-current/content_packs/microsoft_dhcp_content_pack.htm) gives complete Assign/Renew/Release examples, including empty Release vendor columns; its supported server range is 2016/2019/2022/2025, but the example has no build identifier.
- [Elastic raw DHCP fixtures](https://github.com/elastic/integrations/blob/158ba7a3e2c86176f28292a317828261ec3782c1/packages/microsoft_dhcp/data_stream/log/_dev/test/pipeline/test-log.log) contain complete ID 10/30/31/32 rows. The [Elastic pipeline](https://github.com/elastic/integrations/blob/main/packages/microsoft_dhcp/data_stream/log/elasticsearch/ingest_pipeline/dhcp.yml) supplies the ECS field, action and QResult mapping. Its [sample event](https://github.com/elastic/integrations/blob/main/packages/microsoft_dhcp/data_stream/log/sample_event.json) is ID 35, which is not generated here.
- [NXLog IPv4 audit header](https://docs.nxlog.co/integrations/dhcp/windows-dhcp-server.html) confirms the 19 column names and order. [Microsoft weekday audit files](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ipamm/39bcd84c-4d67-4711-85cc-6a03eaf1bb3d) defines day-of-week naming.
- [Microsoft DHCP lifecycle](https://learn.microsoft.com/en-us/windows-server/troubleshoot/troubleshoot-dhcp-issue) places T1 at 50% of the lease. [Scope configuration](https://learn.microsoft.com/en-us/powershell/module/dhcpserver/add-dhcpserverv4scope?view=windowsserver2025-ps) documents configurable duration with an eight-day default; this generator uses eight hours. [Dynamic DNS](https://learn.microsoft.com/en-us/windows-server/networking/dns/dynamic-update) describes server updates on clients' behalf.

Existing `linux-syslog` DHCP rows are an ISC daemon host stream, and Suricata/NetFlow DHCP traffic is network telemetry; neither duplicates this Windows server audit stream.

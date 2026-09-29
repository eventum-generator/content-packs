# Microsoft DHCP Server CSV Audit Log

Generates the Microsoft DHCP Server IPv4 audit log (`DhcpSrvLog-<Day>.log`, 19-column CSV) as parsed ECS JSON, with the native row in `event.original`. For SIEM and detection engineers who need lease and DNS-update traffic from a Windows DHCP server with a recurring address-churn scenario mixed in. This is the DHCP audit file stream, not Windows Event Log or IPv6. The server runs in UTC, so the timezone-free CSV date/time, `@timestamp` and `event.timezone: UTC` agree even when the generator uses another timezone. Weekday file names follow the server's UTC day.

The server has 970 Windows clients in two scopes: 840 desktops and VDI machines in `10.20.16.0/20` and 130 laptops in `10.20.32.0/22`. Each client has its own set of four addresses in its scope (`samples/clients.json`); the sets do not overlap, so an address is never held by two clients.

## Event Types

Shares of a four-day default run (`anomaly_mode: true`, 50,171 rows, four episodes).

| CSV ID | Native description | Share | Category | When it occurs |
| --- | --- | ---: | --- | --- |
| 11 | Renew | 30.8% | network / connection | An active lease reaches T1 |
| 10 | Assign | 14.4% | network / connection | Session start, or reconnect inside a link flap |
| 12 | Release | 14.4% | network / connection | Session end, or the disconnect of a link flap |
| 30 | DNS Update Request | 20.2% | network / connection | After 55% of assignments and 40% of renewals |
| 32 | DNS Update Successful | 18.9% | network / connection | Result of a request, same host and IP |
| 31 | DNS Update Failed | 1.3% | network / connection | Result of a request, native error `10054` |

Every client has its own sessions, link flaps and DNS updates, with random, skewed timing:

- **Sessions.** A session starts with Assign, renews 0-30 minutes after T1, and ends with Release. Session length is lognormal (median 4 h for laptops, 30 h for desktops); the offline gap before the next Assign is lognormal (median 2 h / 50 min, at most 12 h / 8 h before the client tries again). Connects follow an hour-of-day activity curve that is high from 08:00 to 17:00 UTC and low at night, so a client that goes offline in the evening usually returns in the morning.
- **Link flaps.** While a client is active, flap bursts arrive at a per-client rate (one per 1.5-4 h for laptops, one per 15-60 h for desktops, less often at night). A flap is Release, then Assign about a minute later; with probability 0.4 another flap follows a few minutes later. On each reassignment a laptop gets another address of its set with probability 0.7, a desktop with 0.2 (dock, Wi-Fi, VLAN or switch-port change), preferring addresses it has not held yet or not for a while; otherwise it gets the previous address back. Background therefore contains fast Release->Assign pairs, bursts of two and more cycles, and address changes by the same client within minutes.
- **DNS updates.** A request follows its Assign or Renew, and its result follows the request, each a few seconds later (median about 5 s). A result fails with probability 0.06, or 0.5 when the same client had a failure within the last three hours, so repeated failures by one client occur in background.

These rates are synthetic choices, not measured Microsoft frequencies. Assign/Renew carry the observed `MSFT 5.0` vendor class; Release and DNS rows leave it empty. DNS rows also leave native MAC empty and use transaction ID 0 / QResult 6. Lease rows use a random nonzero 32-bit transaction ID and QResult 0.

## Volume and Timing

About 12,900 rows a day: 9,000 spread evenly around the clock and 3,900 on a working-day curve peaking around 12:30 UTC, each day's counts varying by up to 10%. The hourly rate runs from about 360 rows at night to about 800 at midday. Renewals and DNS updates dominate the night; connects and flaps the working day, and client activity follows the hourly volume. Rows that belong together (an Assign, its DNS request and its result) are consecutive rows, usually a few seconds apart; about 8% of DNS request and result pairs share one second, and about 7% of seconds hold two or more rows.

## Anomaly Chain

With `anomaly_mode: true`, one laptop gets a link flap that churns through three more addresses of its own set within minutes, and the last DNS registration fails. Eight native rows, all for one client:

1. ID 12 releases the current address R.
2. ID 10 assigns address A (not R), then ID 12 releases A.
3. ID 10 assigns address B (not R or A), then ID 12 releases B.
4. ID 10 assigns address C (not R, A or B).
5. ID 30 requests the DNS update for C, and ID 31 reports its failure.

**Linking fields.** Lease rows share `source.mac` (client ID), `source.domain` (hostname) and the server. DNS rows have no native MAC, so they join to the final assignment by hostname, IP and time. Each lease operation has its own transaction ID; no native field identifies the episode.

**Recurrence.** Every `anomaly_interval_hours` (default 24, minimum 4) of generated time. The first episode is due within the first min(interval, 24 h) of the run; each later one in a window of width min(interval / 4, 6 h) centred one interval after the previous actual start. Due times in both windows are weighted by the square of the hour curve plus a small floor, so episodes land in busy hours; at intervals of 8 h or less they necessarily cover the whole clock. The episode starts at its due time; only when no laptop is online does it wait for the next one to connect. The next due time counts from the actual start. A missed episode is not replayed.

**Variation.** The episode is an extra link flap of an online laptop other than the previous episode's client, chosen with the same weights as ordinary flaps (a laptop that flaps more often is chosen more often). The flap continues for at least three cycles, the three reassignments take the laptop's three other addresses in random order, and the DNS update for the third one fails. Reassignment and continuation gaps have the background distributions, so episodes span about 5-30 minutes. The laptop's session end, renewals and offline gaps keep their own schedule; after the third reassignment the flap continues or ends as any background flap does, and the laptop's next flap follows the usual timing. If the laptop's session ends inside the flap (about one episode in 25), the flap ends as in background and the episode stays incomplete.

**Detection idea.** For one hostname, three assignments of three distinct new addresses, each separated by a release, followed by a failed DNS update for the last address, within one hour. Every element also occurs alone in background: fast Release->Assign, bursts of several cycles, address changes, and DNS failures after an assignment. Only the complete ordered sequence is the signal. The failure coincides with the churn; these logs do not establish causation or a malicious actor.

**Background.** The complete sequence never occurs outside episodes. When a client's ordinary flaps happen to form the same churn within one hour, the DNS update for the last address succeeds (ID 32).

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

From the content-packs repository root, live:

```bash
eventum generate --path generators/windows-dhcp-audit/generator.yml --id windows-dhcp-audit --live-mode true
```

The volume curves in `patterns/leases-floor.yml` and `patterns/leases-day.yml` start at midnight of the current day and never end. For a finite batch, set `start` and `end` in both files (for example `start: "2026-09-01T00:00:00Z"`, `end: "+7d"`) and run:

```bash
eventum generate --path generators/windows-dhcp-audit/generator.yml --id windows-dhcp-audit --live-mode false --keep-order true
```

Start the window at midnight so the working-day curve peaks at midday, and cover at least two intervals to see more than one episode. A finite run may end with a pending DNS result.

## Sample Output

The first Release of an episode from a default run, copied byte-for-byte. The same shape occurs in background.

```json
{
  "@timestamp": "2026-09-25T14:28:40+00:00",
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
    "ingested": "2026-09-25T14:28:41.538596+00:00",
    "kind": "event",
    "original": "12,09/25/26,14:28:40,Release,10.20.32.189,nb-finance-010.corp.example,0023DFA8FECF,,418295063,0,,,,,,,,,0",
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
    "offset": 973827
  },
  "message": "Release",
  "microsoft": {
    "dhcp": {
      "dns_error_code": "0",
      "result": "0",
      "result_description": "NoQuarantine",
      "transaction_id": "418295063"
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
      "nb-finance-010.corp.example"
    ],
    "ip": [
      "10.20.32.189"
    ]
  },
  "source": {
    "address": "nb-finance-010.corp.example",
    "domain": "nb-finance-010.corp.example",
    "ip": "10.20.32.189",
    "mac": "00-23-DF-A8-FE-CF"
  },
  "tags": [
    "preserve_original_event",
    "microsoft_dhcp"
  ]
}
```

## Limitations

- **No complete native trace.** Individual row variants follow complete vendor and integration examples (below), but no correlated capture of this scenario or of an identified Windows Server build exists. This is a synthetic scenario, not native trace parity.
- **Emitted subset.** Only IDs 10/11/12/30/31/32 are emitted. Lease expiry (IDs 17/18), NACKs, conflicts, relay, failover, service start/stop, file headers and IPv6 are omitted. Relay-agent, DHCID, user-class and user-name columns stay empty (direct clients).
- **Addresses.** Fixed per-client address sets model roaming between docks, Wi-Fi and VLANs; a real server reuses addresses between clients. Clients always renew at T1, so no lease expires.
- **Row spacing.** Rows that a real server writes within the same second (an Assign, its DNS update request and result; a Release and a quick reassignment) are usually seconds apart here: DNS request to result median 5 s, 90% within 16 s, at most about 80 s at night; about 8% of pairs share one second.
- **Episode records.** With `anomaly_mode: true` each episode adds one link flap of its own (eight records or more), so counts of the chain parts (multi-cycle flaps with address changes, a failed DNS update right after a flap) are about one per episode higher than with `anomaly_mode: false`.
- **Collector fields.** `log.offset` counts emitted CSV rows with CRLF and resets per UTC date; it does not include file headers. `related.ip` and `related.hosts` are added for correlation; the Elastic integration pipeline does not set them. Filebeat identity, host/observer MACs and the `event.ingested` delay (1 s plus a lognormal delay, median 1.5 s) are synthetic.
- **Rates.** Session, flap, DNS and failure rates, the hour curve and the daily volume are synthetic choices.

## Performance

About 1,700 rows per second on one core: a 14-day default run (182,435 rows) takes about 110 s of CPU time.

## References

- [Microsoft audit-log catalog](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/dd183591(v=ws.10)) defines IDs 10/11/12 and 30/31/32. Its older seven-column example does not establish the modern optional suffix.
- [Microsoft full Renew example](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/event-4199-windows-client-cannot-get-ip-address-dhcp-server) shows the extended ID 11 row. [Graylog Illuminate 7.1 DHCP integration](https://go2docs.graylog.org/illuminate-current/content_packs/microsoft_dhcp_content_pack.htm) gives complete Assign/Renew/Release examples, including empty Release vendor columns; its supported server range is 2016/2019/2022/2025, but the example has no build identifier.
- [Elastic raw DHCP fixtures](https://github.com/elastic/integrations/blob/158ba7a3e2c86176f28292a317828261ec3782c1/packages/microsoft_dhcp/data_stream/log/_dev/test/pipeline/test-log.log) contain complete ID 10/30/31/32 rows. The [Elastic pipeline](https://github.com/elastic/integrations/blob/main/packages/microsoft_dhcp/data_stream/log/elasticsearch/ingest_pipeline/dhcp.yml) supplies the ECS field, action and QResult mapping. Its [sample event](https://github.com/elastic/integrations/blob/main/packages/microsoft_dhcp/data_stream/log/sample_event.json) is ID 35, which is not generated here.
- [NXLog IPv4 audit header](https://docs.nxlog.co/integrations/dhcp/windows-dhcp-server.html) confirms the 19 column names and order. [Microsoft weekday audit files](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ipamm/39bcd84c-4d67-4711-85cc-6a03eaf1bb3d) defines day-of-week naming.
- [Microsoft DHCP lifecycle](https://learn.microsoft.com/en-us/windows-server/troubleshoot/troubleshoot-dhcp-issue) places T1 at 50% of the lease. [Scope configuration](https://learn.microsoft.com/en-us/powershell/module/dhcpserver/add-dhcpserverv4scope?view=windowsserver2025-ps) documents configurable duration with an eight-day default; this generator uses eight hours. [Dynamic DNS](https://learn.microsoft.com/en-us/windows-server/networking/dns/dynamic-update) describes server updates on clients' behalf.

Existing `linux-syslog` DHCP rows are an ISC daemon host stream, and Suricata/NetFlow DHCP traffic is network telemetry; neither duplicates this Windows server audit stream.

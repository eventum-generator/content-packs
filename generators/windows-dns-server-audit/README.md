# Microsoft DNS Server Audit and Analytical Logs

Generates parsed Windows DNS Server policy Audit records and ETW Analytical query records as ECS JSON. The selected profile is a Windows Server 2022 authoritative IPv4/UDP server with recursion disabled, one pre-existing zone and eight pre-existing A records. It enables the Analytical channel separately from the default Audit channel. Output is parsed collector JSON, with native `winlog.event_data` and rendered messages. It is not a Windows XML, EVTX or ETL export.

## Event Types

| Native ID | Channel | Role in this scenario |
| --- | --- | --- |
| 256 `QUERY_RECEIVED` | Analytical | Incoming A query, source IP/port, XID, RD and DNS packet bytes |
| 257 `RESPONSE_SUCCESS` | Analytical | Authoritative A answer, matching QNAME, client, port, XID and GUID |
| 259 `IGNORED_QUERY` | Analytical | Server policy drops the incoming query, with no 257 reply |
| 577 `POLICY_OP` | Audit | Creates an enabled server-level `Ignore` query policy |
| 580 `POLICY_OP` | Audit | Deletes an existing policy |

The clock renders two records per ten-second tick, normally one 256/257 transaction. The source timestamps place completion 3 ms after reception, rather than at its template invocation. DNS response flags are QR/AA/RD with RA clear, RCODE 0 and one A answer with TTL 300. Packet lengths, XIDs, questions and answer bytes agree with the parsed fields. The 3 ms duration, TTL, 0.1 transaction/s rate and administrative schedule are synthetic scenario assumptions, not vendor measurements.

Both modes create a maintenance policy after about 100 seconds and subsequently every two hours from its actual creation. It remains for about 30 minutes and receives three dropped queries eight minutes apart. The background also contains ordinary successful queries from the same `client_ip`. The zone and its eight sample A records already exist before capture and remain unchanged. This pack does not emit zone or resource-record mutation events.

## Anomaly Chain

`anomaly_mode: true` is the default. After `anomaly_interval_seconds` (six hours by default), the administrator creates a short-lived `Ignore` policy. Three 256/259 query/drop pairs for `beacon.updates.corp.example.` from `10.20.4.17` follow ten seconds apart, then the administrator deletes the policy. Under the shipped clock this policy lives 30 seconds. Correlate creation, three closely spaced drops and deletion on the same server and policy name within a minute. Each received/dropped query is joined by QNAME, QTYPE, XID, source IP and nearby time. Ignored records have no native port, packet or GUID field. No successful response follows a dropped query.

Episodes repeat from the previous actual creation time, with a fresh UUID suffix in the policy name and fresh query XIDs/GUIDs. The same name pattern, administrator, client, QNAME, `Ignore` action and event classes occur in maintenance activity in both modes. There is one active policy and one pending query. A due short episode waits for a maintenance policy to close and for the current pair to complete, so its actual interval can exceed the configured interval by up to roughly 30 minutes plus two ten-second ticks. Delayed episodes do not catch up in a burst. Maintenance also waits for an active short episode. Changing the input cadence changes the observed episode duration and query spacing.

`anomaly_mode: false` retains maintenance policy lifecycles and their sparse drops, but produces no short three-drop episode.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Meaning |
| --- | --- | --- |
| `server_name`, `server_ip` | `dns-01.corp.example`, `10.20.0.53` | DNS server identity |
| `admin_name` | `DNSAdmin` | Renamed local administrator, synthetic SID ending in 500 |
| `client_ip` | `10.20.4.17` | Client for drops and ordinary `www` queries |
| `normal_zone` | `corp.example` | Pre-existing authoritative zone |
| `anomaly_zone` | `updates.corp.example` | FQDN policy criterion and ignored-query suffix |
| `policy_name` | `QueryFilter` | Name stem for maintenance and short policies, followed by a UUID |
| `anomaly_interval_seconds` | `21600` | Positive recurrence interval, supported values at least 3,600 seconds |
| `anomaly_mode` | `true` | Enables repeated short policy episodes |

Use valid ASCII DNS names and IPv4 addresses. `anomaly_zone` must be a subdomain of `normal_zone`. Keep the name stem short enough that stem plus hyphen and UUID fits the documented 256-character policy-name limit. Ordinary QNAMEs, clients and answers live in `samples/queries.json`. Update that file when changing the zone or address plan. No template lookup creates or changes a DNS record.

### Output Parameters

The shipped configuration writes `output/events.json` and has no required `${params.*}` or `${secrets.*}` values. Change `output.file.path` or the output plugin to deliver to a SIEM.

## Usage

From the content-packs repository root:

```bash
uv run --project ../eventum eventum generate --path generators/windows-dns-server-audit/generator.yml --id windows-dns-server-audit --live-mode true
```

For a complete finite capture, copy `generator.yml` next to the original, set `input[0].cron.start` and `end` to a window such as `2026-09-26T00:00:00Z` through `2026-09-26T13:10:00Z`, and run the copied path with `--live-mode false --keep-order true`. This covers two six-hour episodes and repeated maintenance. The mode switch alone does not bound an open-ended cron schedule. Heavy runs share `flock -x /tmp/eventum-generator-heavy.lock`.

## Sample Output

A complete 259 event copied from the final default enabled finite capture:

```json
{
  "@timestamp": "2026-09-26T06:00:10.003000+00:00",
  "data_stream": {
    "dataset": "microsoft_dnsserver.analytical",
    "namespace": "default",
    "type": "logs"
  },
  "dns": {
    "id": "60082",
    "question": {
      "name": "beacon.updates.corp.example",
      "type": "A"
    }
  },
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "category": [
      "network"
    ],
    "code": "259",
    "dataset": "microsoft_dnsserver.analytical",
    "kind": "event",
    "provider": "Microsoft-Windows-DNSServer",
    "severity": 2,
    "type": [
      "protocol"
    ]
  },
  "host": {
    "hostname": "dns-01.corp.example",
    "ip": [
      "10.20.0.53"
    ],
    "name": "dns-01.corp.example",
    "os": {
      "family": "windows",
      "name": "Windows Server 2022 Datacenter",
      "platform": "windows",
      "type": "windows"
    }
  },
  "input": {
    "type": "etw"
  },
  "log": {
    "file": {
      "path": "Microsoft-Windows-DNSServer-Analytical.etl"
    },
    "level": "error"
  },
  "message": "IGNORED_QUERY: TCP=0; InterfaceIP=10.20.0.53; Source=10.20.4.17; Reason=Policy; QNAME=beacon.updates.corp.example.; QTYPE=1; XID=60082; Zone=corp.example; PolicyName=QueryFilter-5477cdbf-acff-49fa-9a3d-9b6362defce2; AdditionalInfo = VirtualizationInstance: .",
  "microsoft_dnsserver": {
    "analytical": {
      "additional_info": ".",
      "description": "Ignored query",
      "interface_ip": "10.20.0.53",
      "policy_name": "QueryFilter-5477cdbf-acff-49fa-9a3d-9b6362defce2",
      "question_name": "beacon.updates.corp.example.",
      "question_type": "A",
      "reason": "Policy",
      "source": {
        "ip": "10.20.4.17"
      },
      "xid": "60082",
      "zone": "corp.example"
    }
  },
  "related": {
    "ip": [
      "10.20.4.17"
    ]
  },
  "source": {
    "ip": "10.20.4.17"
  },
  "winlog": {
    "channel": "Microsoft-Windows-DNS-Server/Analytical",
    "event_data": {
      "AdditionalInfo": ".",
      "InterfaceIP": "10.20.0.53",
      "PolicyName": "QueryFilter-5477cdbf-acff-49fa-9a3d-9b6362defce2",
      "QNAME": "beacon.updates.corp.example.",
      "QTYPE": "1",
      "Reason": "Policy",
      "Source": "10.20.4.17",
      "TCP": "0",
      "XID": "60082",
      "Zone": "corp.example"
    },
    "flags": [
      "64_BIT_HEADER",
      "EXTENDED_INFO",
      "PROCESSOR_INDEX"
    ],
    "flags_raw": "0x241",
    "keywords": [
      "IGNORED_QUERY"
    ],
    "keywords_raw": "0x8000000000000008",
    "level": "Error",
    "level_raw": 2,
    "opcode_raw": 0,
    "provider_guid": "{eb79061a-a566-4698-9119-3ed2807060e7}",
    "provider_message": "Microsoft-Windows-DNS-Server",
    "provider_name": "Microsoft-Windows-DNSServer",
    "session": "Microsoft-Windows-DNSServer-Analytical.etl",
    "task": "LOOK_UP",
    "task_raw": 1,
    "version": 0
  }
}
```

## References and Limits

- [Microsoft DNS logging and diagnostics](https://learn.microsoft.com/en-us/windows-server/networking/dns/dns-logging-and-diagnostics) applies to Windows Server 2022 and documents Audit 577/580 and Analytical 257/259 messages, separate channels and provider GUID. Its table omits 256.
- [Microsoft DNS policy behavior](https://learn.microsoft.com/en-us/powershell/module/dnsserver/add-dnsserverqueryresolutionpolicy?view=windowsserver2025-ps) documents server-level FQDN matching, `Ignore` dropping a matched query without response, processing order and policy creation. [Policy removal](https://learn.microsoft.com/en-us/powershell/module/dnsserver/remove-dnsserverqueryresolutionpolicy?view=windowsserver2025-ps) deletes an existing named policy. These cmdlet references are the current documentation, not a version-matched Server 2022 capture.
- [Microsoft event timestamp schema](https://learn.microsoft.com/en-us/windows/win32/wes/eventschema-timecreated-systempropertiestype-element) defines the event logging `SystemTime`; generated `@timestamp` values are explicitly converted to UTC.
- Elastic input fixtures pinned at commit `78fd455d22cdb74bd2a8e53249c25cc060f06010`: [Audit](https://github.com/elastic/integrations/blob/78fd455d22cdb74bd2a8e53249c25cc060f06010/packages/microsoft_dnsserver/data_stream/audit/_dev/test/pipeline/test-events.json) and [Analytical](https://github.com/elastic/integrations/blob/78fd455d22cdb74bd2a8e53249c25cc060f06010/packages/microsoft_dnsserver/data_stream/analytical/_dev/test/pipeline/test-events.json). These maintained collector examples establish the selected `event_data` field shapes, numeric-string values and rendered message grammar. They do not establish an exact Windows Server 2022 build.

All selected native `event_data` fields are emitted: 256 13/13, 257 20/20, 259 10/10 and 577 8/8. A 580 has the documented policy/server message placeholders, but its two generated data names lack a complete captured record. The published 259 examples contain `Reason=System` and `PolicyName=NULL`. Generated `Reason=Policy`, the named policy and authoritative-zone value are inferred for a policy hit, not verified by a matching capture. `ElapsedTime=3` is treated as milliseconds to match the synthetic 3 ms completion timing; the selected fixtures expose the field but do not prove its units. ETW header flags and file/session labels follow the selected collector profile, not a mandatory transport format. Process/thread IDs, agent/enrichment fields and full native XML/ETL bytes are omitted. No complete version-matched policy-create/drop/delete raw capture was obtained, so native raw parity is not established. The PR remains draft for that evidence limit.

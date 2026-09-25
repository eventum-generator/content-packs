# Microsoft DNS Server Audit and Analytical Logs

Generates parsed Windows DNS Server events in ECS JSON, with native `winlog.event_data` and rendered messages. Audit records describe policy changes; ETW Analytical records describe queries and replies. This is a small, synthetic authoritative `corp.example` server, not a raw `.etl` or Windows XML export. A real server enables Analytical logging separately from the default Audit channel.

## Event Types

| Native ID | Channel | Role in this scenario |
| --- | --- | --- |
| 256 `QUERY_RECEIVED` | Analytical | Incoming query, including source, XID, RD, and valid DNS packet bytes |
| 257 `RESPONSE_SUCCESS` | Analytical | Successful A reply with the same QNAME, client, XID, port, and ETW GUID |
| 259 `IGNORED_QUERY` | Analytical | Policy-matched query with no 257 reply |
| 577 `POLICY_OP` | Audit | Creates a server-level `Ignore` query policy |
| 580 `POLICY_OP` | Audit | Deletes that policy |

The default clock produces two records per second, usually a 256/257 transaction separated by 3 ms. The source selects eight internal A records. A baseline maintenance policy is created after 100 transactions, remains for about 30 minutes, and receives three 256/259 transactions roughly eight minutes apart before it is deleted. These are scenario settings, not measured production event frequencies.

## Anomaly Chain

With `anomaly_mode: true` (the default), the same administrator creates the same `ShadowIgnore` policy a second time after 3,600 routine transactions. Three 256/259 pairs for `beacon.updates.corp.example.` from `10.20.4.17` follow one second apart; the policy is deleted three seconds after creation. The QNAME, source, policy name, action, and event IDs also occur in the baseline. A useful detection correlates a 577 with a burst of policy-matched 259 events and a 580 on the same DNS server within a short window, instead of matching a single field. Correlate each 256/259 pair by QNAME, QTYPE, XID, source IP and nearby time; do not expect a 257 reply for an ignored query.

With `anomaly_mode: false`, the baseline maintenance policy and sparse ignored queries remain, but the short-lived burst does not occur. The one-shot chain and the baseline policy are separate state transitions; neither grows an unbounded collection.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Meaning |
| --- | --- | --- |
| `server_name`, `server_ip` | `dns-01.corp.example`, `10.20.0.53` | DNS server identity |
| `admin_name` | `DNSAdmin` | Policy-change actor |
| `client_ip` | `10.20.4.17` | Client for ignored queries |
| `normal_zone` | `corp.example` | Authoritative zone in events |
| `anomaly_zone` | `updates.corp.example` | Policy FQDN criterion and ignored QNAME suffix |
| `policy_name` | `ShadowIgnore` | Policy used by both maintenance and anomaly sequences |
| `anomaly_interval_events` | `3600` | Routine transaction count before the short-lived sequence; values below 1,901 are delayed until the baseline policy closes |
| `anomaly_mode` | `true` | Enables the short-lived sequence |

The ordinary QNAMEs, clients and A answers are in `samples/queries.json`. Update that file when changing `normal_zone`.

### Output Parameters

The shipped configuration writes `output/events.json` and has no required `${params.*}` or `${secrets.*}` values. Change `output.file.path` or the output plugin to deliver to a SIEM.

## Usage

From the content-packs repository root:

```bash
eventum generate --path generators/windows-dns-server-audit/generator.yml --id windows-dns-server-audit --live-mode true
```

For a bounded sample, prefix the command with `timeout 2` and set `--live-mode false`; the mode switch alone does not stop a continuous cron generator. The default clock and count live in `generator.yml`.

## Sample Output

A complete 259 event copied from an enabled generator run:

```json
{
  "@timestamp": "2026-09-25T18:53:12.003000+00:00",
  "data_stream": {
    "dataset": "microsoft_dnsserver.analytical",
    "namespace": "default",
    "type": "logs"
  },
  "dns": {
    "id": "51115",
    "question": {
      "name": "beacon.updates.corp.example",
      "registered_domain": "corp.example",
      "top_level_domain": "example",
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
  "message": "IGNORED_QUERY: TCP=0; InterfaceIP=10.20.0.53; Source=10.20.4.17; Reason=Policy; QNAME=beacon.updates.corp.example.; QTYPE=1; XID=51115; Zone=corp.example; PolicyName=ShadowIgnore; AdditionalInfo = VirtualizationInstance: .",
  "microsoft_dnsserver": {
    "analytical": {
      "additional_info": ".",
      "description": "Ignored query",
      "interface_ip": "10.20.0.53",
      "policy_name": "ShadowIgnore",
      "question_name": "beacon.updates.corp.example.",
      "question_type": "A",
      "reason": "Policy",
      "source": {
        "ip": "10.20.4.17"
      },
      "xid": "51115",
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
      "PolicyName": "ShadowIgnore",
      "QNAME": "beacon.updates.corp.example.",
      "QTYPE": "1",
      "Reason": "Policy",
      "Source": "10.20.4.17",
      "TCP": "0",
      "XID": "51115",
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

- [Microsoft DNS logging and diagnostics](https://learn.microsoft.com/en-us/windows-server/networking/dns/dns-logging-and-diagnostics): Audit IDs 577/580, Analytical IDs 257/259, and separate logging configuration. The table omits 256.
- [Microsoft DNS policy behavior](https://learn.microsoft.com/en-us/powershell/module/dnsserver/add-dnsserverqueryresolutionpolicy?view=windowsserver2025-ps): `Ignore` drops a matched query without answering it.
- [Elastic Audit input fixtures](https://github.com/elastic/integrations/blob/main/packages/microsoft_dnsserver/data_stream/audit/_dev/test/pipeline/test-events.json): actual 577 structure and message.
- [Elastic Analytical ETW input fixtures](https://github.com/elastic/integrations/blob/main/packages/microsoft_dnsserver/data_stream/analytical/_dev/test/pipeline/test-events.json) and [parsed fixtures](https://github.com/elastic/integrations/blob/main/packages/microsoft_dnsserver/data_stream/analytical/_dev/test/pipeline/test-events.json-expected.json): actual 256/257/259 field sets and collector shape.

All fields in the selected 256 (13/13), 257 (20/20), 259 (10/10), and 577 (8/8) native `event_data` structures are emitted. The published 259 examples have `Reason=System` and `PolicyName=NULL`. They do not show a policy-matched 259, so the generated `Reason=Policy`, named policy and `Zone=corp.example` are inferences from the documented `Ignore` behavior and 259 schema. The 580 field names come from the documented event text; a full 580 native sample was unavailable. These details need validation against an actual policy-hit capture before claiming full native fidelity. The output is parsed ECS JSON, with no `event.original` Windows XML or raw ETL bytes.

# Sophos Firewall SFOS 20 Firewall Rule syslog

Eventum content pack for the Device Standard Format (Legacy) Firewall Rule records documented for SFOS 20. Each event is ECS JSON with the native key-value line in `event.original`. `anomaly_mode: true` is the default; `false` produces background only.

## Run

From the content-packs repository root:

```bash
eventum generate --path generators/network-sophos-firewall/generator.yml --id network-sophos-firewall --live-mode true
```

For a bounded sample, run `timeout 3s eventum generate --path generators/network-sophos-firewall/generator.yml --id network-sophos-firewall-batch --live-mode false`. Exit code 124 is expected for this continuous source. Output is written to `generators/network-sophos-firewall/output/events.json`.

## Events

| ID | Meaning | Background frequency | ECS category |
| --- | --- | --- | --- |
| `010101600001` | Firewall Rule Allowed | About 82% | `network` |
| `010102600002` | Firewall Rule Denied | About 18% | `network` |

The frequencies and four-step injection interval are synthetic workload settings, not measured Sophos rates. This pack models TCP firewall-rule decisions, with 55 native fields, from one firewall. It omits other SFOS log components and Central Reporting Format. The guide's denied sample uses ICMP; this generator uses the same documented Firewall Rule fields and log ID with TCP ports, which the field table permits. `event.original` is the vendor body without a transport syslog header. Forward that body through a syslog output when testing a native KUMA parser.

## Anomaly Chain

The same source, `10.40.9.77`, reaches the same destination, `10.40.20.15`. The firewall denies SSH (22), SMB (445), and RDP (3389), then allows HTTPS (443) under a different rule. Correlate `source.ip`, `destination.ip`, `sophos.firewall.log_id`, `destination.port`, and `@timestamp` to detect multi-port probing followed by allowed access to the target. This is traffic behavior, not evidence of a policy change or compromise. Sort by `@timestamp`; file-line order is not guaranteed under concurrent generation.

`anomaly_mode: false` keeps routine allow/deny traffic but never uses the chain source or schedules its steps.

## Parameters

### Event Parameters

| Parameter | Default | Meaning |
| --- | --- | --- |
| `device_name` | `sophos-fw-01.example.test` | Firewall hostname |
| `device_id` | `SFV-EXAMPLE-001` | Synthetic device identifier |
| `anomaly_mode` | `true` | Include the chain; `false` emits background only |
| `anomaly_interval_events` | `80` | Routine pairs between chain injections |
| `probe_source_ip` | `10.40.9.77` | Stable chain source |
| `probe_destination_ip` | `10.40.20.15` | Stable chain destination |

### Output Parameters

No top-level `${params.*}` or `${secrets.*}` placeholders are shipped. File output works without credentials. For SIEM delivery, replace the `output` block with a suitable plugin and configure its endpoint there.

## Sample output

This complete anomaly event was captured from a run with `anomaly_mode: true`:

```json
{
  "@timestamp": "2026-09-25T13:49:45+00:00",
  "destination": {
    "ip": "10.40.20.15",
    "port": 22
  },
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "firewall-deny",
    "category": [
      "network"
    ],
    "code": "010102600002",
    "dataset": "sophos_firewall.log",
    "kind": "event",
    "original": "device=\"SFW\" date=2026-09-25 time=13:49:45 timezone=\"UTC\" device_name=\"sophos-fw-01.example.test\" device_id=SFV-EXAMPLE-001 log_id=010102600002 log_type=\"Firewall\" log_component=\"Firewall Rule\" log_subtype=\"Denied\" status=\"Deny\" priority=Information duration=0 fw_rule_id=0 policy_type=1 user_name=\"\" user_gp=\"\" iap=0 ips_policy_id=0 appfilter_policy_id=0 in_interface=\"Port2\" out_interface=\"Port1\" src_ip=10.40.9.77 dst_ip=10.40.20.15 protocol=\"TCP\" src_port=55667 dst_port=22 sent_pkts=0 recv_pkts=0 sent_bytes=0 recv_bytes=0 srczonetype=\"LAN\" srczone=\"LAN\" dstzonetype=\"LAN\" dstzone=\"LAN\" connid=\"\" hb_health=\"No Heartbeat\" message=\"\" appresolvedby=\"Signature\" app_is_cloud=0 log_occurrence=1 src_mac=02:40:01:00:00:4d dst_mac=02:40:20:00:00:0f src_country_code=R1 dst_country_code=R1 application=\"\" application_risk=0 application_technology=\"\" application_category=\"\" tran_src_ip= tran_src_port=0 tran_dst_ip= tran_dst_port=0 dir_disp=\"\" vconnid=\"\"",
    "type": [
      "denied"
    ]
  },
  "host": {
    "id": "SFV-EXAMPLE-001",
    "name": "sophos-fw-01.example.test"
  },
  "network": {
    "transport": "tcp"
  },
  "related": {
    "ip": [
      "10.40.9.77",
      "10.40.20.15"
    ]
  },
  "sophos": {
    "firewall": {
      "app_is_cloud": 0,
      "appfilter_policy_id": 0,
      "application": "",
      "application_category": "",
      "application_risk": 0,
      "application_technology": "",
      "appresolvedby": "Signature",
      "connid": "",
      "date": "2026-09-25",
      "device": "SFW",
      "device_id": "SFV-EXAMPLE-001",
      "device_name": "sophos-fw-01.example.test",
      "dir_disp": "",
      "dst_country_code": "R1",
      "dst_ip": "10.40.20.15",
      "dst_mac": "02:40:20:00:00:0f",
      "dst_port": 22,
      "dstzone": "LAN",
      "dstzonetype": "LAN",
      "duration": 0,
      "fw_rule_id": 0,
      "hb_health": "No Heartbeat",
      "iap": 0,
      "in_interface": "Port2",
      "ips_policy_id": 0,
      "log_component": "Firewall Rule",
      "log_id": "010102600002",
      "log_occurrence": 1,
      "log_subtype": "Denied",
      "log_type": "Firewall",
      "message": "",
      "out_interface": "Port1",
      "policy_type": 1,
      "priority": "Information",
      "protocol": "TCP",
      "recv_bytes": 0,
      "recv_pkts": 0,
      "sent_bytes": 0,
      "sent_pkts": 0,
      "src_country_code": "R1",
      "src_ip": "10.40.9.77",
      "src_mac": "02:40:01:00:00:4d",
      "src_port": 55667,
      "srczone": "LAN",
      "srczonetype": "LAN",
      "status": "Deny",
      "time": "13:49:45",
      "timezone": "UTC",
      "tran_dst_ip": "",
      "tran_dst_port": 0,
      "tran_src_ip": "",
      "tran_src_port": 0,
      "user_gp": "",
      "user_name": "",
      "vconnid": ""
    }
  },
  "source": {
    "ip": "10.40.9.77",
    "port": 55667
  }
}
```

## References

- [Sophos Firewall SFOS 20 syslog guide: Firewall Rule field descriptions and sample logs](https://docs.sophos.com/nsg/sophos-firewall/20.0/syslog/index.html)
- [Sophos Firewall syslog log-ID structure](https://docs.sophos.com/nsg/sophos-firewall/20.0/Help/en-us/webhelp/onlinehelp/AdministratorHelp/Logs/LogViewer/LogsSyslogInfo/index.html)
- [Sophos Firewall rule actions and logging](https://docs.sophos.com/nsg/sophos-firewall/20.0/Help/en-us/webhelp/onlinehelp/AdministratorHelp/RulesAndPolicies/FirewallRules/FirewallRuleAdd/index.html)
- [KUMA 4.2 supported event sources](https://support.kaspersky.ru/kuma/4.2/255782)

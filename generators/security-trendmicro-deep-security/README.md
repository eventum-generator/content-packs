# Trend Micro Deep Security Agent CEF

Eventum content pack for Deep Security Agent firewall and intrusion-prevention messages forwarded through syslog in CEF. Output is ECS JSON with the native CEF line in `event.original`. `anomaly_mode: true` is the default; `false` leaves only background traffic.

## Run

From the content-packs repository root:

```bash
eventum generate --path generators/security-trendmicro-deep-security/generator.yml --id security-trendmicro-deep-security --live-mode true
```

For a bounded batch sample, use `timeout 3s eventum generate --path generators/security-trendmicro-deep-security/generator.yml --id security-trendmicro-deep-security-batch --live-mode false`. Exit code 124 is expected for this continuous source. Events go to `generators/security-trendmicro-deep-security/output/events.json`.

## Events

| CEF signature ID | Meaning | Routine distribution | ECS category |
| --- | --- | --- | --- |
| `20` | Log-only firewall rule | 85% | `network` |
| `21` | Deny firewall rule | 12%; two per chain | `network` |
| `1001111` | Intrusion-prevention rule with `IDS:Reset` | 3%; two per chain | `network`, `intrusion_detection` |

The routine percentages are synthetic workload weights, not vendor-measured production rates. Fifty agent hosts share a manager syslog sender; `dvchost` and `cn1` identify the protected host.

## Anomaly Chain

One source attempts SMB/445 and RDP/3389 against the same protected host and hits firewall deny rule 21. The source then triggers IPS rule 1001111 with `IDS:Reset` on HTTP/80 twice. Correlate `source.ip`, `destination.ip`, `host.name` or `trendmicro.deep_security.host_id`, and a short time window. The records show a multi-port probe followed by IPS resets. They do not establish that the host was compromised. Concurrent output can reorder lines; sort by `@timestamp` when inspecting the chain.

The generator models only firewall and IPS CEF records. It does not emit anti-malware, integrity-monitoring, application-control, web-reputation, LEEF, or manager sign-in events. KUMA 4.2 lists Trend Micro Deep Security via the Syslog-CEF normalizer. The shipped output is ECS JSON, so pass `event.original` to a native CEF parser if testing that normalizer.

## Parameters

### Event Parameters

| Parameter | Default | Meaning |
| --- | --- | --- |
| `manager_name` | `dsm-01.corp.example` | Syslog sender |
| `agent_version` | `20.0.0` | CEF Device Version |
| `anomaly_mode` | `true` | Add the four-event chain; `false` emits background only |
| `anomaly_interval_events` | `250` | Routine records between chains |
| `attack_source_ip` | `10.50.9.77` | Stable chain source |
| `attack_target_name` | `app-01.corp.example` | Protected agent host |
| `attack_target_ip` | `10.50.20.15` | Protected host IP |
| `attack_host_id` | `101` | Agent host identifier in `cn1` |

### Output Parameters

No top-level `${params.*}` or `${secrets.*}` placeholders are shipped. File output needs no credentials. Replace the `output` block to forward to a SIEM, then configure its endpoint and credentials there.

## Sample output

This complete event was captured from an `anomaly_mode: true` run:

```json
{
  "@timestamp": "2026-09-25T13:34:51+00:00",
  "destination": {
    "ip": "10.50.20.15",
    "port": 445
  },
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "firewall-deny",
    "category": [
      "network"
    ],
    "code": "21",
    "dataset": "trendmicro.deep_security",
    "kind": "event",
    "original": "Sep 25 13:34:51 dsm-01.corp.example CEF:0|Trend Micro|Deep Security Agent|20.0.0|21|Deny Inbound Management|5|cn1=101 cn1Label=Host ID dvchost=app-01.corp.example act=Deny dmac=00:50:56:F5:7F:65 smac=00:0C:29:EB:35:DE TrendMicroDsFrameType=IP src=10.50.9.77 dst=10.50.20.15 in=60 cs3=DF cs3Label=Fragmentation Bits proto=TCP spt=45856 dpt=445 cs2=0x02 SYN cs2Label=TCP Flags cnt=1",
    "type": [
      "denied"
    ]
  },
  "host": {
    "ip": [
      "10.50.20.15"
    ],
    "name": "app-01.corp.example"
  },
  "network": {
    "transport": "tcp"
  },
  "related": {
    "hosts": [
      "app-01.corp.example"
    ],
    "ip": [
      "10.50.9.77",
      "10.50.20.15"
    ]
  },
  "source": {
    "ip": "10.50.9.77",
    "port": 45856
  },
  "trendmicro": {
    "deep_security": {
      "action": "Deny",
      "host_id": 101,
      "manager_name": "dsm-01.corp.example",
      "rule_id": "21",
      "rule_name": "Deny Inbound Management"
    }
  }
}
```

## References

- [Trend Micro Workload Security syslog/CEF message formats](https://docs.trendmicro.com/en-us/documentation/article/trend-micro-cloud-one-workload-security-event-syslog-message-formats)
- [Elastic Trend Micro integration](https://github.com/elastic/integrations/tree/main/packages/trendmicro)
- [KUMA 4.2 supported event sources](https://support.kaspersky.ru/kuma/4.2/255782)

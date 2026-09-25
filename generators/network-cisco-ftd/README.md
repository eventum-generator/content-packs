# Cisco Firepower Threat Defense security events

Eventum content pack for FTD security-event syslog IDs 430001, 430002 and 430003. Each output is ECS JSON with the vendor syslog line in `event.original`. `anomaly_mode: true` is the default; `false` produces ordinary connection traffic only.

## Run

From the content-packs repository root:

```bash
eventum generate --path generators/network-cisco-ftd/generator.yml --id network-cisco-ftd --live-mode true
```

For a bounded batch sample, use `timeout 3s eventum generate --path generators/network-cisco-ftd/generator.yml --id network-cisco-ftd-batch --live-mode false`. Exit code 124 is expected for this continuous source. Events go to `generators/network-cisco-ftd/output/events.json`.

## Events

| ID | Meaning | Frequency | ECS category |
| --- | --- | --- | --- |
| `430002` | Connection start | One per ordinary flow; one per chain | `network` |
| `430003` | Connection end | One per ordinary flow; one per chain | `network` |
| `430001` | IPS intrusion, dropped packet | Two per chain | `intrusion_detection`, `network` |

The FSM pairs normal connection starts and ends and inserts one four-event chain after 250 ordinary flows. The interval is a synthetic workload knob, not a measured FTD event distribution.

## Anomaly Chain

A TCP connection starts under an allow access rule. Two IPS messages with different SIDs report dropped packets on that same connection, followed by its end event. Correlate `cisco.ftd.security_event.device_uuid`, `instance_id`, `first_packet_second`, and `connection_id`, then inspect the repeated intrusion SIDs, source, destination and time window. This is evidence of an inspected connection with IPS drops; it does not imply compromise or a policy bypass. Log line order is not guaranteed by concurrent generation, so order correlated events by `@timestamp`.

The template models FTD 6.5+ correlation fields. It does not model file, malware, SSL, URL, NAT, or administrative messages. KUMA 4.2 lists FTD under its Cisco ASA/IOS syslog normalizer; that normalizer's handling of these specific security-event fields has not been tested. Forward `event.original` as syslog if testing a native parser, since the shipped output is an ECS JSON envelope.

## Parameters

### Event Parameters

| Parameter | Default | Meaning |
| --- | --- | --- |
| `device_name` | `ftd-edge-01.corp.example` | Syslog sender and ECS host |
| `device_uuid` | `9d1a0010-2a2b-4c4d-8e8f-010203040506` | FTD device correlation ID |
| `anomaly_mode` | `true` | Add the four-event chain; `false` emits ordinary flows only |
| `anomaly_interval_events` | `250` | Ordinary flows between chains |
| `attack_source_ip` | `10.40.9.77` | Stable chain source |
| `attack_destination_ip` | `10.40.20.15` | Stable chain target |

### Output Parameters

No top-level `${params.*}` or `${secrets.*}` placeholders are shipped. File output runs without credentials. To forward to a SIEM, replace the `output` block with a suitable plugin and configure its endpoint and credentials there.

## Sample output

This complete event was captured from an `anomaly_mode: true` run:

```json
{
  "@timestamp": "2026-09-25T13:35:48+00:00",
  "cisco": {
    "ftd": {
      "message_id": "430002",
      "security_event": {
        "access_control_rule_name": "Allow to DMZ",
        "connection_id": 1251,
        "device_uuid": "9d1a0010-2a2b-4c4d-8e8f-010203040506",
        "dst_ip": "10.40.20.15",
        "dst_port": 443,
        "first_packet_second": "2026-09-25T13:35:48Z",
        "instance_id": 2,
        "protocol": "tcp",
        "src_ip": "10.40.9.77",
        "src_port": 44986
      }
    }
  },
  "destination": {
    "ip": "10.40.20.15",
    "port": 443
  },
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "connection-start",
    "category": [
      "network"
    ],
    "code": "430002",
    "dataset": "cisco_ftd.log",
    "kind": "event",
    "original": "Sep 25 13:35:48 ftd-edge-01.corp.example %FTD-6-430002: EventPriority: Low, DeviceUUID: 9d1a0010-2a2b-4c4d-8e8f-010203040506, InstanceID: 2, FirstPacketSecond: 2026-09-25T13:35:48Z, ConnectionID: 1251, SrcIP: 10.40.9.77, DstIP: 10.40.20.15, SrcPort: 44986, DstPort: 443, Protocol: tcp, IngressInterface: inside, EgressInterface: dmz, IngressZone: Inside, EgressZone: DMZ, ACPolicy: Corporate Access Policy, AccessControlRuleName: Allow to DMZ, Client: SSL client, ApplicationProtocol: HTTPS, AccessControlRuleAction: Allow, InitiatorPackets: 1, ResponderPackets: 0, InitiatorBytes: 74, ResponderBytes: 0, NAPPolicy: Balanced Security and Connectivity",
    "type": [
      "start"
    ]
  },
  "host": {
    "name": "ftd-edge-01.corp.example"
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
  "source": {
    "ip": "10.40.9.77",
    "port": 44986
  }
}
```

## References

- [Cisco FTD security event syslog IDs, correlation fields and IPS semantics](https://www.cisco.com/c/en/us/td/docs/security/firepower/Syslogs/fptd_syslog_guide/security-event-syslog-messages.html)
- [Cisco FTD severity-6 message catalog](https://www.cisco.com/c/en/us/td/docs/security/firepower/Syslogs/fptd_syslog_guide/syslogs-sev-level.html)
- [Elastic Cisco FTD integration and ECS mapping](https://github.com/elastic/integrations/tree/main/packages/cisco_ftd)
- [KUMA 4.2 supported event sources](https://support.kaspersky.ru/kuma/4.2/255782)

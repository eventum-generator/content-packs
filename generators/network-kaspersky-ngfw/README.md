# Kaspersky NGFW 1.0 Firewall CEF sessions

Synthetic Kaspersky NGFW 1.0 Firewall session-start and session-end messages. The generator writes ECS JSON; each event's event.original contains a CEF message body for the Firewall stream. It does not prepend a syslog transport header.

## Event types

| CEF name | Meaning | Share |
| --- | --- | --- |
| Session start | TCP session created | 50% |
| Firewall | TCP session ended, with directional counters | 50% |

The configured cadence is one event every 30 seconds, about 2,880 events or 1,440 complete sessions per synthetic day. Routine sessions mix HTTPS (about 84%), HTTP (5%), TCP DNS (5%), SMB (about 6%), and occasional large SMB transfers. These proportions are scenario assumptions, not published NGFW production measurements. Each start/end pair preserves its session ID, addresses, ports, rule, and start time. End events report the elapsed duration and counters; in/out are bytes received from the client/server, respectively.

## Anomaly Chain

With anomaly_mode: true, one additional sequence starts after 60 routine sessions, about one synthetic hour:

1. A client at 10.20.1.87 opens an SMB session to 10.20.2.14:445, then its end record reports 75 MB from the server.
2. Thirty seconds later, the same client opens a second SMB session to that server; its end record reports 82 MB from the server.

Join starts and ends by kaspersky.ngfw.session_id, then correlate the two completed sessions by source/destination and their one-minute separation. A rule can alert on two large server-to-client SMB transfers in a short window. Background mode also emits the same individual large-transfer signatures but spaces them roughly two hours apart. No individual record identifies the mode or proves data theft.

anomaly_mode defaults to true. Set it to false for routine traffic without the adjacent two-session sequence. The anomaly occurs once per generator run. Compare @timestamp when analyzing samples, because concurrently written output lines can be out of order.

## Parameters

### Event Parameters

Edit event.template.params in generator.yml.

| Name | Default | Purpose |
| --- | --- | --- |
| anomaly_mode | true | Include the one-time SMB sequence. |
| anomaly_delay_sessions | 60 | Routine sessions before that sequence. |
| device_host | ngfw-01.example.test | Device host name in CEF and ECS. |
| device_version | 1.0.0.0 | NGFW 1.0 CEF device version. |
| large_smb_source_ip | 10.20.1.87 | Client for occasional and adjacent large SMB sessions. |
| large_smb_destination_ip | 10.20.2.14 | Server for those sessions. |

### Output Parameters

File output works as shipped and needs no top-level params or secrets. To send events elsewhere, replace output.file with an output plugin and declare top-level params/secrets for that destination.

## Usage

Run from the content-packs repository:

~~~bash
eventum generate --path generators/network-kaspersky-ngfw/generator.yml --id kaspersky-ngfw --live-mode false
eventum generate --path generators/network-kaspersky-ngfw/generator.yml --id kaspersky-ngfw --live-mode true
~~~

Events are written to generators/network-kaspersky-ngfw/output/events.json. A CEF collector needs the event.original value, rather than the surrounding ECS JSON.

## Sample output

This complete event is from an anomaly-mode Eventum run:

~~~json
{
  "@timestamp": "2026-09-25T18:27:30+00:00",
  "destination": {
    "bytes": 75000000,
    "ip": "10.20.2.14",
    "port": 445
  },
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "Firewall",
    "category": [
      "network"
    ],
    "dataset": "kaspersky.ngfw",
    "duration": 30000000000,
    "end": "2026-09-25T18:27:30+00:00",
    "kind": "event",
    "original": "CEF:0|Kaspersky|NGFW|1.0.0.0|Firewall|Firewall|Unknown|rt=2026-09-25T18:27:30Z dtz=UTC+00:00 cs4=Low cs4Label=Priority devicePayloadId=900061 cs1=Internal SMB inspection cs1Label=SecurityRule act=Inspect FullMatch=yes start=2026-09-25T18:27:00Z end=2026-09-25T18:27:30Z cn1=30 cn1Label=Duration cn2=40000 cn2Label=ClientPackets cn3=53572 cn3Label=ServerPackets in=2800000 out=75000000 dvchost=ngfw-01.example.test src=10.20.1.87 dst=10.20.2.14 proto=TCP spt=54295 dpt=445 KasperskyNGFWTCPRedir=no app=Unknown",
    "start": "2026-09-25T18:27:00+00:00",
    "type": [
      "end"
    ]
  },
  "kaspersky": {
    "ngfw": {
      "action": "Inspect",
      "rule": "Internal SMB inspection",
      "session_id": "900061"
    }
  },
  "network": {
    "bytes": 77800000,
    "packets": 93572,
    "protocol": "smb",
    "transport": "tcp"
  },
  "observer": {
    "hostname": "ngfw-01.example.test",
    "product": "NGFW",
    "vendor": "Kaspersky",
    "version": "1.0.0.0"
  },
  "source": {
    "bytes": 2800000,
    "ip": "10.20.1.87",
    "port": 54295
  }
}
~~~

## Scope and evidence

This pack models the Kaspersky:NGFW:CEF Firewall session stream. Kaspersky Security Center, KATA, KWTS, and KSMG are distinct products and streams, not duplicate generators. KUMA 4.2 lists a CEF normalizer for NGFW 1.0 and 1.2; this pack specifically models 1.0.

Kaspersky documents the CEF header, the Firewall event names, and a field-by-field Firewall extension table. The generated fields follow those documented keys and meanings. A complete real NGFW 1.0 Firewall CEF extension was not available in the cited sources, so exact device field ordering, label values, and optional-field omission cannot be proven byte-for-byte. The CEF body is synthetic and does not claim to be a packet capture or a complete syslog message. Application protocol names in ECS are inferred from destination ports; app=Unknown reflects an unclassified application in the CEF message.

Both modes were run in Eventum sample mode. The verifier checked JSON parsing, CEF key/value correspondence with ECS, UTC event times, start/end identifiers and endpoints, elapsed duration, directional byte/packet counters, branch coverage, and the sequence distinction between modes. The large SMB byte and packet volumes are compatible with a 30-second, roughly 20–22 Mbps transfer, but represent a synthetic scenario rather than vendor-published traffic.

## References

- [Kaspersky NGFW 1.0 CEF format and event names](https://support.kaspersky.com/ngfw/1.0/274361)
- [Kaspersky NGFW 1.0 Firewall field table](https://support.kaspersky.com/ngfw/1.0/274840)
- [Kaspersky NGFW SIEM export](https://support.kaspersky.com/ngfw/1.0/269371)
- [KUMA 4.2 supported sources](https://support.kaspersky.ru/kuma/4.2/255782)

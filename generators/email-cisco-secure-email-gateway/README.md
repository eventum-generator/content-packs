# Cisco Secure Email Gateway mail logs

Synthetic `mail_logs` text records for Cisco Secure Email Gateway (ESA/SEG), following the MID, ICID, RID, and DCID lifecycle in Cisco's AsyncOS 16.5 guide. ESA and SEG are names for the same product here.

## Event Types

| Action | Baseline frequency | Native identifier |
| --- | --- | --- |
| `open`, `icid-close` | Each message cycle | ICID |
| `start`, `sender`, `recipient-0` | Each message cycle | MID and ICID |
| `ready`, `antivirus`, `queued` | Each message cycle | MID |
| `outbound`, `dcid-close` | Each message cycle | DCID |
| `delivery-start`, `delivery-done` | Each message cycle | DCID and MID |
| `recipient-1` | Chain only | MID, ICID, RID 1 |

The generator uses `fsm` so ordinary mail traverses a complete injection and delivery lifecycle. Every twentieth cycle in the default mode is the anomalous large outbound message; this is a synthetic cadence, not a measured vendor frequency.

## Anomaly Chain

An SMTP connection from `suspect_ip` starts a message from `svc-backup@example.test` to two recipients at `external.example.test`. The gateway logs a 12–18 MB message, negative antivirus result, queueing, a new delivery connection, and successful delivery to both recipient IDs. Correlate the connection to message by ICID and MID, then the message to delivery by MID and DCID. A rule can alert on unusually large outbound mail from a service account to a new external domain, followed by completed delivery. These logs show routing and size, not message contents or proof of malicious intent. Sort by `@timestamp` before sequence matching because output line order is not guaranteed.

`event.template.params.anomaly_mode` defaults to `true`. Set it to `false` for ordinary single-recipient mail cycles only.

## Parameters

### Event Parameters

| Name | Default | Purpose |
| --- | --- | --- |
| `anomaly_mode` | `true` | Include the large outbound mail sequence |
| `host_name` | `esa-01.example.test` | Gateway name |
| `interface_name` | `mail.example.test` | SMTP listener name |
| `interface_ip` | `10.20.30.25` | SMTP interface address |
| `suspect_sender` | `svc-backup@example.test` | Sender in the sequence |
| `suspect_ip` | `10.20.40.77` | Client IP in the sequence |
| `external_domain` | `external.example.test` | Recipient domain in the sequence |

### Output Parameters

The shipped configuration writes `output/events.json` with no connection parameters or secrets. To send events to a SIEM, replace the file output in a local copy and use `${params.siem_host}` and `${secrets.siem_token}` as required by the selected output plugin.

## Usage

```bash
eventum generate --path generators/email-cisco-secure-email-gateway/generator.yml --id seg --live-mode false
eventum generate --path generators/email-cisco-secure-email-gateway/generator.yml --id seg --live-mode true
```

## Sample Output

Copied from an `anomaly_mode: true` run:

```json
{
  "@timestamp": "2026-09-25T13:38:37+00:00",
  "cisco": {
    "esa": {
      "message": "MID 200257090 ready 16296275 bytes from <svc-backup@example.test>",
      "message_size": 16296275,
      "mid": 200257090
    }
  },
  "ecs": {
    "version": "8.17.0"
  },
  "email": {
    "from": {
      "address": [
        "svc-backup@example.test"
      ]
    }
  },
  "event": {
    "action": "ready",
    "category": [
      "email"
    ],
    "kind": "event",
    "original": "Fri Sep 25 13:38:37 2026 Info: MID 200257090 ready 16296275 bytes from <svc-backup@example.test>",
    "type": [
      "info"
    ]
  },
  "host": {
    "ip": [
      "10.20.30.25"
    ],
    "name": "esa-01.example.test"
  },
  "log": {
    "file": {
      "path": "mail_logs"
    },
    "level": "info"
  },
  "related": {
    "user": [
      "svc-backup@example.test"
    ]
  }
}
```

## Coverage and Limits

The selected native fields are represented where they occur in the raw records: timestamp, level, message text, MID, ICID, RID, DCID, sender, recipient, and ready byte count. The structured fields do not attribute a DCID to an injection record or a sender to a delivery-only record when the line itself lacks it; join adjacent records by their native IDs. Cisco's AsyncOS 16.5 guide reproduces examples with historical timestamps, so this pack targets the documented text `mail_logs` layout rather than claiming a tested appliance build. KUMA 4.2 lists Cisco SEG through a CEF syslog normalizer. This pack emits native text `mail_logs`, so that CEF normalizer is not expected to parse it without a separate conversion.

## References

- [Cisco AsyncOS 16.5 text mail-log examples and ID lifecycle](https://www.cisco.com/c/en/us/td/docs/security/esa/esa16-5/user_guide/b_ESA_Admin_Guide_16-5/b_ESA_Admin_Guide_12_1_chapter_0100111.html)
- [KUMA 4.2 source catalog](https://support.kaspersky.ru/kuma/4.2/255782)

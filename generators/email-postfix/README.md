# Postfix SMTP Syslog

Generates native Postfix `smtpd`, `qmgr` and `smtp` syslog messages with consistent queue IDs and ECS correlation fields. The full syslog record is in `event.original`.

Reference coverage: **14/14 documented native slots** across the modeled Postfix records: syslog timestamp, host, service, PID, queue ID, client address, SASL username, envelope sender, size, recipient count, recipient, relay, DSN and delivery status. Postfix has no Elastic integration sample for a broader ECS comparison.

## Event Types

| Native record | Meaning | Routine selection |
| --- | --- | ---: |
| `postfix/smtpd` queue ID, `client=`, `sasl_username=` | Accepted submission | 70% of routine entries |
| `postfix/qmgr` `from=`, `size=`, `nrcpt=1` | Active accepted message | Follows acceptance |
| `postfix/smtp` `to=`, `relay=`, `dsn=`, `status=sent` | Delivered recipient | Follows queue activation |
| `postfix/qmgr` `removed` | Queue completion | Follows delivery |
| `postfix/smtpd` `NOQUEUE: reject` | Recipient rejection | 30% of routine entries |
| SASL failures, accepted submission with `nrcpt=5`, five deliveries | Suspicious submission | Anomaly only |

Weights apply to initial routine choices; an accepted message expands into four syslog records. They are configured weights, not measured Postfix frequencies. The authentication-failure line with `sasl_username` requires Postfix 3.6.12 or newer in the 3.6 line.

## Anomaly Chain

Three SASL LOGIN failures for `payroll@corp.example` from `10.99.3.51` are followed by an accepted `smtpd` submission from that identity. The resulting queue ID remains identical through one `qmgr` record (`nrcpt=5`), five `smtp status=sent` recipient deliveries and `qmgr removed`. Correlate failures and acceptance by username, source IP and host; correlate the subsequent message by queue ID. Rules can detect repeated failures preceding an accepted submission and an unusual recipient fan-out. The failure records have no queue ID because no message was accepted yet.

`anomaly_mode: true` is the default. Set `event.template.params.anomaly_mode: false` for background only. The payroll identity and five-recipient submission are absent in background mode.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Meaning |
| --- | --- | --- |
| `mail_host`, `mail_ip` | `mail-01.corp.example`, `10.80.0.5` | Mail server identity |
| `normal_user`, `normal_ip` | `service@corp.example`, `10.80.1.20` | Routine sender |
| `anomaly_user`, `anomaly_ip` | `payroll@corp.example`, `10.99.3.51` | Chain actor |
| `anomaly_interval_events` | `250` | Background events between chains |
| `anomaly_mode` | `true` | Include anomaly sequence; `false` emits background only |

### Output Parameters

The shipped config writes `output/events.json` and has no `${params.*}` or `${secrets.*}` placeholders. Change `output.file.path` or replace the output plugin to connect a SIEM.

## Usage

From the content-packs repository root:

```bash
eventum generate --path generators/email-postfix/generator.yml --id email-postfix --live-mode true
```

For a short local sample, use `--live-mode false` and stop the command after enough events.

## Sample Output

The following event came from an enabled-mode run:

```json
{
  "@timestamp": "2026-09-25T12:36:50+00:00",
  "ecs": {
    "version": "8.17.0"
  },
  "email": {
    "to": {
      "address": [
        "invoice1@partner.example"
      ]
    }
  },
  "event": {
    "action": "delivery-sent",
    "category": [
      "email"
    ],
    "dataset": "postfix.syslog",
    "kind": "event",
    "original": "Sep 25 12:36:50 mail-01.corp.example postfix/smtp[2401]: 00000338: to=<invoice1@partner.example>, relay=mx.partner.example[198.51.100.25]:25, delay=0.8, delays=0.1/0.1/0.2/0.4, dsn=2.0.0, status=sent (250 2.0.0 Ok: queued as REMOTE1)",
    "outcome": "success",
    "type": [
      "info"
    ]
  },
  "host": {
    "ip": [
      "10.80.0.5"
    ],
    "name": "mail-01.corp.example"
  },
  "log": {
    "level": "info",
    "syslog": {
      "appname": "postfix/smtp"
    }
  },
  "message": "00000338: to=<invoice1@partner.example>, relay=mx.partner.example[198.51.100.25]:25, delay=0.8, delays=0.1/0.1/0.2/0.4, dsn=2.0.0, status=sent (250 2.0.0 Ok: queued as REMOTE1)",
  "observer": {
    "hostname": "mail-01.corp.example",
    "ip": "10.80.0.5",
    "product": "Postfix",
    "type": "mail",
    "vendor": "Postfix"
  },
  "postfix": {
    "queue_id": "00000338",
    "service": "smtp"
  },
  "process": {
    "name": "postfix/smtp",
    "pid": 2401
  },
  "related": {
    "hosts": [
      "mail-01.corp.example"
    ]
  },
  "tags": [
    "postfix",
    "preserve_original_event"
  ]
}
```

## References and Limits

- [Postfix queue lifecycle](https://www.postfix.org/QSHAPE_README.html) describes tracking messages by queue ID.
- [Postfix log examples](https://www.postfix.org/ETRN_README.html) show `qmgr` `from=`, `size=` and `nrcpt=` records.
- [Postfix 3.6.12 release note](https://www.postfix.org/announcements/postfix-3.8.3.html) documents `sasl_username` on authentication failures.
- [KUMA 4.0 supported sources](https://support.kaspersky.com/kuma/4.0/en-US/255782.htm) lists Postfix 3.6 syslog.

The file output is ECS JSON containing native syslog in `event.original`. A raw syslog collector needs that field extracted. Queue IDs link accepted mail to delivery, but authentication failures cannot be tied to a queue ID before acceptance.

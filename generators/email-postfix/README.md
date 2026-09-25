# Postfix SMTP Syslog

Generates Postfix 3.8.3+ submission-relay messages for `smtpd`, `cleanup`, `qmgr` and `smtp`. The complete native syslog line is in `event.original`; the output file contains parsed ECS JSON, not bare syslog lines. This profile assumes SASL is enabled on the submission service.

## Event Types

| Native record | Purpose | Background selection |
| --- | --- | ---: |
| `postfix/smtpd` with `client=`, `sasl_method=LOGIN`, `sasl_username=` | Accepted authenticated message | 90% of routine decisions |
| `postfix/smtpd` `NOQUEUE: reject: RCPT` | Unknown recipient rejected before queueing | 7% of routine decisions |
| `postfix/smtpd` `SASL LOGIN authentication failed` | Isolated failed login | 3% of routine decisions, at least 20 generated records apart |
| `postfix/cleanup` `message-id=` | Message enters the queue | After every acceptance |
| `postfix/qmgr` `from=`, `size=`, `nrcpt=` | Queue activation | After cleanup; ordinary `nrcpt` is 1/2/5 with weights 85/13/2 |
| `postfix/smtp` `to=`, `relay=`, `delay=`, `delays=`, `dsn=`, `status=sent` | One successful recipient delivery | One per queued recipient |
| `postfix/qmgr` `removed` | Message leaves the queue | After every modeled delivery completes |

The weights are synthetic configuration choices for a mostly successful submission relay, not measured Postfix frequencies. The one-second input tick is also a configurable synthetic traffic rate. Routine senders and recipients vary; queue IDs, relay addresses, per-recipient counts and delivery delays remain internally consistent.

## Anomaly Chain

After 250 routine decisions, one episode emits three failed SASL LOGIN attempts from the same user, IP and `smtpd` PID, followed by an accepted message from that session. Its queue ID then links `cleanup`, `qmgr nrcpt=5`, five distinct `smtp status=sent` deliveries and `qmgr removed`. A rule can correlate repeated failures followed by a successful submission, then count delivered recipients by queue ID. Failed authentications have no queue ID, so the correlation into the accepted message uses the user, IP, host, PID and time window.

`anomaly_mode: true` is the default. With `false`, only background is emitted. The target user and IP, isolated failures and five-recipient deliveries also occur in background; no individual value or record marks the episode. The mode changes the sequence, not the event schema.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Meaning |
| --- | --- | --- |
| `mail_host`, `mail_ip` | `mail-01.corp.example`, `10.80.0.5` | Postfix host identity |
| `normal_user`, `normal_ip` | `service@corp.example`, `10.80.1.20` | First routine sender; seven more are in `samples/senders.json` |
| `anomaly_user`, `anomaly_ip` | `payroll@corp.example`, `10.99.3.51` | Episode identity, also used by routine mail and isolated failures |
| `anomaly_interval_events` | `250` | Routine decisions before the single episode |
| `anomaly_mode` | `true` | Include the episode; `false` emits background only |

### Output Parameters

The shipped configuration writes `output/events.json` and has no `${params.*}` or `${secrets.*}` placeholders. Change `output.file.path` or replace the output plugin for a SIEM. A collector expecting raw syslog should extract `event.original`.

## Usage

From the content-packs repository root:

```bash
eventum generate --path generators/email-postfix/generator.yml --id email-postfix --live-mode true
```

For a finite sample, add `input.cron.start` and `input.cron.end`, then run with `--live-mode false`.

## Sample Output

This accepted message was copied from a verified anomaly-mode run. The same record shape also appears in background.

```json
{
  "@timestamp": "2026-09-25T00:19:30+00:00",
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "smtp-accept",
    "category": [
      "email"
    ],
    "dataset": "postfix.syslog",
    "kind": "event",
    "original": "Sep 25 00:19:30 mail-01.corp.example postfix/smtpd[2400]: 4F657A0489: client=unknown[10.99.3.51], sasl_method=LOGIN, sasl_username=payroll@corp.example",
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
      "appname": "postfix/smtpd"
    }
  },
  "message": "4F657A0489: client=unknown[10.99.3.51], sasl_method=LOGIN, sasl_username=payroll@corp.example",
  "observer": {
    "hostname": "mail-01.corp.example",
    "ip": "10.80.0.5",
    "product": "Postfix",
    "type": "mail",
    "vendor": "Postfix"
  },
  "postfix": {
    "queue_id": "4F657A0489",
    "sasl": {
      "username": "payroll@corp.example"
    },
    "service": "smtpd"
  },
  "process": {
    "name": "postfix/smtpd",
    "pid": 2400
  },
  "related": {
    "hosts": [
      "mail-01.corp.example"
    ],
    "ip": [
      "10.99.3.51"
    ],
    "user": [
      "payroll@corp.example"
    ]
  },
  "source": {
    "ip": "10.99.3.51"
  },
  "tags": [
    "postfix",
    "preserve_original_event"
  ],
  "user": {
    "name": "payroll@corp.example"
  }
}
```

## References and Limits

- [Postfix architecture](https://www.postfix.org/OVERVIEW.html) documents the `smtpd` → `cleanup` → queue manager → `smtp` path.
- [Postfix 3.8.3 announcement](https://www.postfix.org/announcements/postfix-3.8.3.html) documents `sasl_username` after authentication failure. The field was also backported to 3.7.8, 3.6.12 and 3.5.22; this generator models 3.8.3+.
- [Postfix ETRN examples](https://www.postfix.org/ETRN_README.html) show queue activation with `from=`, `size=` and `nrcpt=`.
- [Postfix connection-cache examples](https://www.postfix.org/CONNECTION_CACHE_README.html) show outbound `to=`, `relay=`, `delay=`, `delays=`, `dsn=` and `status=sent`.
- [Postfix backscatter examples](https://www.postfix.org/BACKSCATTER_README.html) show `NOQUEUE: reject: RCPT` syntax.
- [Postfix users list trace](https://www.mail-archive.com/postfix-users%40postfix.org/msg83417.html) shows one real queue ID through `smtpd`, `cleanup`, `qmgr`, `smtp` and `removed`.
- [Postfix users list explanation](https://www.mail-archive.com/search?f=1&l=postfix-users%40postfix.org&o=newest&q=date%3A20110309) explains that `smtpd client=` creates a queue ID and `qmgr removed` closes that queue lifecycle.

This is a selected successful-delivery path, not a complete Postfix mail log. It omits connection/TLS logs, postscreen, local delivery, bounce and deferred retries. An exact Postfix 3.8.3+ raw trace containing the complete three-failure-to-acceptance episode is not available in the cited evidence; the chain joins documented line formats and is a synthetic scenario. There is no source-specific Elastic integration sample used as a schema reference; `postfix.syslog` is the generator's ECS dataset name.

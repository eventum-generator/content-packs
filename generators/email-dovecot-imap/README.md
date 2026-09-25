# Dovecot IMAP and POP3 login syslog

Synthetic Dovecot login-process messages with native `imap-login` and `pop3-login` text in `event.original` and parsed ECS fields.

## Event Types

| Action | Baseline frequency | Category |
| --- | ---: | --- |
| IMAP login success | 96% | Authentication |
| IMAP authentication failure | 4% | Authentication |
| Four IMAP failures, IMAP success, then POP3 success | Chain only | Authentication |

The baseline weights are synthetic assumptions, not measured Dovecot traffic.

## Anomaly Chain

Four failed IMAP logins for `accounts@corp.example` from `192.0.2.91` are followed by an IMAP success and then a POP3 success for the same mailbox and client IP. A SIEM rule can group by user and `rip`, sort by `@timestamp`, and alert on the failure-to-success transition plus protocol switch inside a short window. File line order is not the contract. Each login is a separate session ID; these login logs do not report mail reads or prove data extraction.

`anomaly_mode` defaults to `true`. Set it to `false` in `event.template.params` for routine logins and isolated failures only.

## Parameters

### Event Parameters

| Name | Default | Purpose |
| --- | --- | --- |
| `anomaly_mode` | `true` | Include the failed-login and protocol-switch sequence |
| `host_name` | `mail01.corp.example` | Dovecot host name |
| `local_ip` | `10.20.0.20` | Local listener IP (`lip`) |
| `target_user` | `accounts@corp.example` | Mailbox in the chain |
| `suspicious_client_ip` | `192.0.2.91` | Remote IP (`rip`) in the chain |

### Output Parameters

The shipped configuration writes `output/events.json` and needs no connection parameters or secrets. Replace the `file` output in a local copy and add `${params.siem_host}` and `${secrets.siem_token}` for the selected output plugin where applicable.

## Usage

```bash
eventum generate --path generators/email-dovecot-imap/generator.yml --id dovecot-imap --live-mode false
eventum generate --path generators/email-dovecot-imap/generator.yml --id dovecot-imap --live-mode true
```

## Sample Output

This event was copied from a generator run with `anomaly_mode: true`.

```json
{
  "@timestamp": "2026-09-25T12:45:02+00:00",
  "destination": {
    "ip": "10.20.0.20",
    "port": 993
  },
  "dovecot": {
    "login_result": "failure",
    "method": "PLAIN",
    "protocol": "imap",
    "session": "747e1335926d02ac",
    "tls": true
  },
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "login-failure",
    "category": [
      "authentication"
    ],
    "kind": "event",
    "original": "Sep 25 12:45:02 mail01.corp.example dovecot: imap-login: Disconnected (auth failed, 1 attempts in 2 secs): user=<accounts@corp.example>, method=PLAIN, rip=192.0.2.91, lip=10.20.0.20, TLS, session=<747e1335926d02ac>",
    "outcome": "failure",
    "type": [
      "denied"
    ]
  },
  "host": {
    "ip": [
      "10.20.0.20"
    ],
    "name": "mail01.corp.example"
  },
  "related": {
    "ip": [
      "192.0.2.91",
      "10.20.0.20"
    ],
    "user": [
      "accounts@corp.example"
    ]
  },
  "service": {
    "name": "dovecot",
    "type": "imap"
  },
  "source": {
    "ip": "192.0.2.91"
  },
  "user": {
    "name": "accounts@corp.example"
  }
}
```

## Coverage and Limits

The selected login examples expose nine elements, all preserved and parsed where present: protocol, outcome, user, authentication method, remote IP, local IP, TLS marker, session ID, and success-login `mpid` (9/9). Dovecot's documented default `login_log_format_elements` provides the field syntax, while the syslog prefix depends on logging and forwarding configuration. This pack covers login process records only, not IMAP commands, mailbox actions, LMTP delivery, or auth-worker diagnostics. KUMA 4.2 lists Dovecot POP3/IMAP syslog; exact parser compatibility depends on the deployed Dovecot format.

## References

- [Dovecot 2.3 core logging settings](https://doc.dovecot.org/2.3/settings/core/)
- [Dovecot vendor login example](https://doc.dovecot.org/main/core/config/proxy/haproxy.html)
- [Dovecot community archive with a failed IMAP login line](https://dovecot.org/mailman3/archives/list/dovecot%40dovecot.org/thread/NJDLPY35DMSK2W3YUI33SYA7BVC54DTQ/)
- [KUMA 4.2 supported event sources](https://support.kaspersky.ru/kuma/4.2/255782)

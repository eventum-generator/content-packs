# Dovecot 2.3.20 IMAP and POP3 login syslog

Generates synthetic Dovecot login-process messages in `event.original` inside ECS JSON. The profile uses Dovecot 2.3.20 login text and a UTC, RFC 3164-style syslog envelope; it does not represent IMAP commands or mail reads.

## Event Types

| Native login message | Background share | Meaning |
| --- | ---: | --- |
| `imap-login: Login` | ~82% | Successful IMAP authentication |
| `pop3-login: Login` | ~12% | Successful POP3 authentication |
| `imap-login: Disconnected: Connection closed (auth failed, ...)` | ~6% | Failed IMAP authentication and closed connection |

Shares and the one-event-per-ten-seconds rate are synthetic workload settings, not measured Dovecot rates. Routine traffic spans 20 named mailboxes plus the two episode mailboxes, internal and external client IPs, and both protocols.

## Anomaly Chain

Four IMAP connections from one mailbox and client IP fail authentication at ten-second intervals. The next connection succeeds over IMAP, followed by a successful POP3 login for the same mailbox and IP. Each connection has its own session ID. A SIEM rule can correlate the six records by `user.name`, `source.ip`, `host.name`, and event time, then detect the dense failure-to-success transition and protocol switch. These login records do not prove mailbox access or data extraction.

With `anomaly_mode: true` (the default), the chain recurs after every `anomaly_interval_events` routine records. The default 360-record interval yields starts about 61 minutes apart because the six chain records also consume one minute. Consecutive episodes alternate between `accounts@corp.example` / `192.0.2.91` and `finance@corp.example` / `192.0.2.92`. Both pairs also have ordinary IMAP failures, IMAP successes and POP3 successes in background; the short six-record sequence distinguishes the anomaly. Set `anomaly_mode: false` to keep only background activity.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Purpose |
| --- | --- | --- |
| `anomaly_mode` | `true` | Emit recurring six-record episodes |
| `anomaly_interval_events` | `360` | Routine records between episode starts |
| `host_name` | `mail01.corp.example` | Hostname in the chosen syslog envelope |
| `local_ip` | `10.20.0.20` | Dovecot listener IP (`lip`) |
| `mail_domain` | `corp.example` | Domain for routine mailbox names |
| `target_user` | `accounts@corp.example` | First episode mailbox, also present in background |
| `alternate_target_user` | `finance@corp.example` | Second episode mailbox, also present in background |
| `suspicious_client_ip` | `192.0.2.91` | First episode client IP, also present in background |
| `alternate_client_ip` | `192.0.2.92` | Second episode client IP, also present in background |

### Output Parameters

The shipped configuration writes `output/events.json` and needs no endpoint parameters or secrets. For another destination, replace the `output` block in a local copy and use that plugin's `${params.*}` and `${secrets.*}` placeholders.

## Usage

From the content-packs repository root, set `input[0].cron.start` and `input[0].cron.end` for a finite batch. For example, `2026-09-25T00:00:00+03:00` to `2026-09-25T02:04:00+03:00` produces 745 records and two complete episodes with the default settings.

```bash
uv run --project ../eventum eventum generate --path generators/email-dovecot-imap/generator.yml --id dovecot-imap --live-mode false
```

For a continuous stream, leave `end` unset and use live mode:

```bash
uv run --project ../eventum eventum generate --path generators/email-dovecot-imap/generator.yml --id dovecot-imap --live-mode true
```

## Sample Output

This synthetic record was copied from a finite generator run. It is not a vendor capture.

```json
{"@timestamp": "2026-09-24T22:00:00+00:00", "destination": {"ip": "10.20.0.20"}, "dovecot": {"auth_attempts": 1, "auth_duration_seconds": 2, "disconnect_reason": "Connection closed", "login_result": "failure", "method": "PLAIN", "protocol": "imap", "session": "6X0R1BBdjnlN4yRN", "tls": true}, "ecs": {"version": "8.17.0"}, "event": {"action": "login-failure", "category": ["authentication"], "kind": "event", "original": "Sep 24 22:00:00 mail01.corp.example dovecot: imap-login: Disconnected: Connection closed (auth failed, 1 attempts in 2 secs): user=\u003caccounts@corp.example\u003e, method=PLAIN, rip=192.0.2.91, lip=10.20.0.20, TLS, session=\u003c6X0R1BBdjnlN4yRN\u003e", "outcome": "failure", "type": ["denied"]}, "host": {"ip": ["10.20.0.20"], "name": "mail01.corp.example"}, "related": {"ip": ["192.0.2.91", "10.20.0.20"], "user": ["accounts@corp.example"]}, "service": {"name": "dovecot", "type": "imap"}, "source": {"ip": "192.0.2.91"}, "user": {"name": "accounts@corp.example"}}
```

## Source and Scope

The [Dovecot 2.3 settings](https://doc.dovecot.org/2.3/settings/core/) define the default login-field order, comma joining of nonempty values, and syslog as the default logging destination. A [first-hand 2.3.20 IMAP success capture](https://dovecot.org/mailman3/archives/list/dovecot%40dovecot.org/thread/73CEPDRB7TWP6BJABZL6VBZZH66HQ6S6/) shows `Login`, `user`, `method`, `rip`, `lip`, `mpid`, `TLS` and `session`. A [first-hand 2.3.20 IMAP failure capture](https://dovecot.org/mailman3/archives/list/dovecot%40dovecot.org/thread/C2U64DRTHU7QL26IEV44SRGLKXZ3F4H4/) confirms `Disconnected: Connection closed (auth failed, ...):` and the absence of `mpid`. A [POP3 success capture on Dovecot's own mailing list](https://dovecot.org/mailman3/archives/list/dovecot%40dovecot.org/thread/RF5LJE3G3UZNPYWR7YKDAL7NC5LMI2Y5/) confirms the `pop3-login: Login` form but does not pin its Dovecot version.

`session` is a unique connection identifier in [Dovecot 2.3 variables](https://doc.dovecot.org/2.3/configuration_manual/config_file/config_variables/). The generator uses a 16-character base64-like form seen in success captures; the 2.3.20 failure capture has a shorter valid ID, so 16 characters are a selected profile, not a universal length. `TLS` confirms a secure connection but cannot distinguish implicit TLS on 993/995 from STARTTLS on 143/110; the output therefore does not invent `destination.port`. The two-second failure duration is a modeled connection duration, consistent with the documented default `auth_failure_delay`, not a measured timing distribution. The RFC 3164-style envelope assumes a UTC syslog collector; Dovecot logging and forwarding can change it.

**BLOCKED_RAW_EVIDENCE:** no complete 2.3.20 raw capture was found for the selected TLS failure with a two-second duration or for POP3 success. The generated lines combine same-branch documented field order with first-hand examples, but exact byte-for-byte fidelity for those variants remains unconfirmed. The output is ECS JSON containing a native-style line in `event.original`, not a native syslog stream. This pack excludes IMAP commands, POP3 retrievals, mailbox changes, LMTP delivery and auth-worker diagnostics.

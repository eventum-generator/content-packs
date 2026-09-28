# Dovecot 2.3.20 IMAP and POP3 login syslog

Generates synthetic Dovecot login-process messages in `event.original` inside ECS JSON, for testing mail-server authentication detections. The profile uses Dovecot 2.3.20 login text and a UTC, RFC 3164-style syslog envelope; it does not represent IMAP commands or mail reads.

## Event Types

| Native login message | Share | Category |
| --- | ---: | --- |
| `imap-login: Login` | 75.1% | authentication, start |
| `imap-login: Disconnected: Connection closed (auth failed, ...)` | 14.0% | authentication, denied |
| `pop3-login: Login` | 10.9% | authentication, start |

Shares are measured on a 7-day `anomaly_mode: false` run with the default settings (36,953 records, about 220 per hour; about 31% of POP3 logins come from public addresses). Rates are synthetic workload settings, not measured Dovecot rates.

Background activity comes from independent random processes; none of them runs on a fixed period, rotation or script:

- **Mail clients.** Fifty personal and six shared mailboxes use office workstations, laptops and phones. Laptops connect from the office, the VPN or their owner's home connection (a public address). Phones connect from roaming public addresses. Each client reconnects at its own random interval, more often during UTC daytime. Some phones use POP3. Some workstations and laptops poll an IMAP and a POP3 account together, so an IMAP login is followed by a POP3 login from the same address within seconds to minutes. This happens from office and home addresses alike.
- **Rejected logins.** Clients sometimes fail one to five times before they succeed: a mistyped password (more often at the first start after a night) or a transient rejection. Webmail users at `webmail_ip` mistype passwords the same way.
- **Password changes and new clients.** After a password change, the mailbox's IMAP clients fail repeatedly until their owner updates them, then succeed. A new client can start with typos.
- **Internet noise.** Single guesses, password sprays over real and non-existent mailboxes, and brute-force runs against one mailbox. They come from recurring hostile hosts, one-off hosts, or addresses from the ranges that phones also use. Scanners may try up to three passwords per connection.

Which mailbox uses which clients, and which hostile hosts recur, is fixed per `mail_domain`; all activity on top of that differs in every run.

## Anomaly Chain

One mailbox fails IMAP authentication four times from one public address, a few seconds to about a minute apart. Then the next IMAP login from that address succeeds, and a POP3 login for the same mailbox and address follows within seconds to minutes. The pattern fits a guessed password followed by a mailbox download over POP3. Each connection has its own session ID. Link the records by `user.name`, `source.ip` and `host.name`, ordered by `@timestamp`. Episodes in the measured runs lasted 41-227 seconds. The login records do not prove mailbox access or data extraction.

- **Recurrence.** With `anomaly_mode: true` (the default), the first episode starts within the first `anomaly_interval_hours` (at most 24 hours) of the run, at a time of day drawn from the UTC daytime load curve of the background. Each next episode is due one interval after the previous actual start; its start is drawn in a window of a quarter interval (at most 6 hours) centred on that due time, weighted towards busy hours. Missed episodes are never caught up. Default episodes in a 7-day run started between 08:55 and 15:42 UTC, 21.3-25.8 hours apart. At intervals of 8 hours or less the window covers most of the clock, so episodes also fall into quiet hours.
- **Variation.** Each episode uses a different mailbox and a different public address from the previous one. The mailbox is one whose own clients have already logged in over IMAP and over POP3 from public addresses earlier in the run; early in a run, before any has, it is a mailbox with a roaming POP3 client. The address is not one the mailbox's own clients use at that moment.
- **Background overlap.** Every part of the chain also occurs in ordinary traffic of both modes: repeated failures of one mailbox and address within minutes, four or more failures followed by a success, and IMAP-then-POP3 pairs. Per 7 days of background, five default runs showed 55-65 cases of four failures followed by an IMAP success within 15 minutes, 21-27 cases of failure, IMAP success and POP3 success from one mailbox and address, and 1,473-1,539 IMAP-then-POP3 pairs within 10 minutes.
- **Detection.** Only the full order separates the modes. Ordinary traffic never completes four failures, an IMAP success and a POP3 success for one mailbox and address within 15 minutes of the first failure: an ordinary POP3 login that would complete it is left out, and the client keeps its schedule. A rule that correlates these six logins for one mailbox and address within 15 minutes finds every episode and nothing else.

Set `anomaly_mode: false` to keep only background activity.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Purpose |
| --- | --- | --- |
| `anomaly_mode` | `true` | Add the recurring anomaly episodes to the background |
| `anomaly_interval_hours` | `24` | Hours from one episode start to the next due time (3 to 8760) |
| `host_name` | `mail01.corp.example` | Hostname in the syslog envelope |
| `local_ip` | `10.20.0.20` | Dovecot listener IP (`lip`) |
| `webmail_ip` | `10.20.0.30` | Client IP of the webmail server |
| `mail_domain` | `corp.example` | Domain of all mailbox names |

Mailbox local parts and their type (`personal` or `shared`) are listed in `samples/mailboxes.csv`.

### Output Parameters

The shipped configuration writes `output/events.json` and needs no endpoint parameters or secrets. To send events elsewhere, replace the `output` block in a local copy and use that plugin's `${params.*}` and `${secrets.*}` placeholders, for example:

```yaml
output:
  - opensearch:
      hosts:
        - ${params.opensearch_host}
      username: ${params.opensearch_user}
      password: ${secrets.opensearch_password}
      index: dovecot-login
```

## Usage

From the content-packs repository root, stream in real time:

```bash
eventum generate --path generators/email-dovecot-imap/generator.yml --id dovecot-imap --live-mode true
```

For a finite batch, set `input[0].cron.start` and `input[0].cron.end` in a copy of `generator.yml` and run it in sample mode. For example, `2026-09-25T00:00:00+00:00` to `2026-10-02T00:00:00+00:00` (7 days) produced about 38,300 records and seven episodes with the default settings.

```bash
eventum generate --path generators/email-dovecot-imap/generator.yml --id dovecot-imap --live-mode false --keep-order true
```

The input ticks every second, and a tick without a due login is dropped, so each second holds at most one record.

## Sample Output

This synthetic record is the first failure of an episode, copied from a finite generator run. It is not a vendor capture.

```json
{"@timestamp": "2026-09-25T15:42:14+00:00", "destination": {"ip": "10.20.0.20"}, "dovecot": {"auth_attempts": 1, "auth_duration_seconds": 2, "disconnect_reason": "Connection closed", "login_result": "failure", "method": "PLAIN", "protocol": "imap", "session": "jAN6fEUhVw6LlkAX", "tls": true}, "ecs": {"version": "8.17.0"}, "event": {"action": "login-failure", "category": ["authentication"], "kind": "event", "original": "Sep 25 15:42:14 mail01.corp.example dovecot: imap-login: Disconnected: Connection closed (auth failed, 1 attempts in 2 secs): user=\u003caaron.walsh@corp.example\u003e, method=PLAIN, rip=203.0.113.218, lip=10.20.0.20, TLS, session=\u003cjAN6fEUhVw6LlkAX\u003e", "outcome": "failure", "type": ["denied"]}, "host": {"ip": ["10.20.0.20"], "name": "mail01.corp.example"}, "related": {"ip": ["203.0.113.218", "10.20.0.20"], "user": ["aaron.walsh@corp.example"]}, "service": {"name": "dovecot", "type": "imap"}, "source": {"ip": "203.0.113.218"}, "user": {"name": "aaron.walsh@corp.example"}}
```

## Source and Scope

The [Dovecot 2.3 settings](https://doc.dovecot.org/2.3/settings/core/) define the default login-field order, comma joining of nonempty values, and syslog as the default logging destination. A [first-hand 2.3.20 IMAP success capture](https://dovecot.org/mailman3/archives/list/dovecot%40dovecot.org/thread/73CEPDRB7TWP6BJABZL6VBZZH66HQ6S6/) shows `Login`, `user`, `method`, `rip`, `lip`, `mpid`, `TLS` and `session`. A [first-hand 2.3.20 IMAP failure capture](https://dovecot.org/mailman3/archives/list/dovecot%40dovecot.org/thread/C2U64DRTHU7QL26IEV44SRGLKXZ3F4H4/) confirms `Disconnected: Connection closed (auth failed, N attempts in S secs):` and the absence of `mpid`. A [POP3 success capture on Dovecot's own mailing list](https://dovecot.org/mailman3/archives/list/dovecot%40dovecot.org/thread/RF5LJE3G3UZNPYWR7YKDAL7NC5LMI2Y5/) confirms the `pop3-login: Login` form but does not pin its Dovecot version.

`session` is a unique connection identifier in [Dovecot 2.3 variables](https://doc.dovecot.org/2.3/configuration_manual/config_file/config_variables/). The generator uses a 16-character base64-like form seen in success captures; the 2.3.20 failure capture has a shorter valid ID, so 16 characters are a selected profile, not a universal length. `mpid` grows like a process ID counter. `TLS` confirms a secure connection but cannot distinguish implicit TLS on 993/995 from STARTTLS on 143/110; the output therefore does not invent `destination.port`. Failure durations start at two seconds per attempt, consistent with the documented default `auth_failure_delay`; they are modeled, not a measured timing distribution. The RFC 3164-style envelope assumes a UTC syslog collector; Dovecot logging and forwarding can change it.

Limits:

- **BLOCKED_RAW_EVIDENCE:** no complete 2.3.20 raw capture was found for a TLS failure with the modeled durations or for POP3 success. The lines combine same-branch documented field order with first-hand examples; byte-for-byte fidelity for those variants remains unconfirmed.
- Failures are modeled for IMAP only. A POP3 client with an outdated password produces no records, because no POP3 failure capture was found.
- Timestamps have one-second resolution, as the syslog clock does, and each second holds at most one record.
- The output is ECS JSON containing a native-style line in `event.original`, not a native syslog stream. This pack excludes IMAP commands, POP3 retrievals, mailbox changes, logouts, LMTP delivery and auth-worker diagnostics.

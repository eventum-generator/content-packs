# Dovecot 2.3.20 IMAP and POP3 login syslog

Generates synthetic Dovecot login-process messages in `event.original` inside ECS JSON, for testing mail-server authentication detections. The profile uses Dovecot 2.3.20 login text and a UTC, RFC 3164-style syslog envelope; it does not represent IMAP commands or mail reads.

## Event Types

| Native login message | Share | Category |
| --- | ---: | --- |
| `imap-login: Login` | 83.4% | authentication, start |
| `pop3-login: Login` | 10.7% | authentication, start |
| `imap-login: Disconnected: Connection closed (auth failed, ...)` | 5.9% | authentication, denied |

Shares over four days of a default run. About 30% of POP3 logins and about 40% of all logins come from public addresses; about a third of the failures come from hostile hosts. Rates are synthetic workload settings, not measured Dovecot rates.

## Volume and Timing

About 23,600 logins a day (±3% from day to day) at random times, following a UTC hour-of-day curve: a round-the-clock floor plus a working-day curve peaking at 12:00-13:00.

| UTC hours | Logins/s |
| --- | ---: |
| 00-05, 20-24 | 0.13-0.15 |
| 05-08 | 0.18-0.27 |
| 08-11, 14-17 | 0.34-0.47 |
| 11-14 | 0.51-0.52 |
| 17-20 | 0.17-0.27 |

Mail clients reconnect, and webmail users log in, along the same curve; internet scanning is flat around the clock. Several logins can share one second.

Background activity comes from independent random processes; none of them runs on a fixed period, rotation or script:

- **Mail clients.** 250 personal and 25 shared mailboxes use office workstations, laptops and phones. Laptops connect from the office, the VPN or their owner's home connection (one of two public addresses). Phones connect through a few carrier NAT addresses each, shared with other subscribers, and usually come back to each of them within a day, at most within about two days. Each client reconnects on its own schedule, every few minutes to about an hour. Some phones use POP3. Some workstations and laptops poll an IMAP and a POP3 account together, so an IMAP login is followed by a POP3 login from the same address within seconds to minutes. This happens from office and home addresses alike.
- **Rejected logins.** Clients sometimes fail one to five times before they succeed: a mistyped password (more often at the first start after a night) or a transient rejection; one failure is more common than two, two than three. Webmail users at `webmail_ip` mistype passwords the same way. Retries follow a failure after a median 15 seconds in working hours.
- **Password changes and new clients.** After a password change, the mailbox's IMAP clients fail repeatedly, backing off, until their owner updates them, then succeed. A new phone replaces the mailbox's phone and keeps its carrier addresses. A new client can start with typos.
- **Internet noise.** Single guesses, password sprays over real and non-existent mailboxes, and brute-force runs against one mailbox. They come from recurring hostile hosts, one-off hosts, or addresses from the ranges that phones also use. Scanners may try up to three passwords per connection.

Which mailbox uses which clients and addresses, and which hostile hosts recur, is fixed per `mail_domain`; all activity on top of that differs in every run.

## Anomaly Chain

One mailbox fails IMAP authentication four times from one public address, a few seconds to about a minute apart. Then the next IMAP login from that address succeeds, and a POP3 login for the same mailbox and address follows within seconds to minutes. The pattern fits a guessed password followed by a mailbox download over POP3. Each connection has its own session ID. Link the records by `user.name`, `source.ip` and `host.name`, ordered by `@timestamp`. An episode lasts about one to three minutes. The login records do not prove mailbox access or data extraction.

- **Recurrence.** With `anomaly_mode: true` (the default), the first episode starts within the first `anomaly_interval_hours` (at most 24 hours) of the run, at a time of day drawn from the UTC load curve of the background, but not in about the first hour and a half: until then no mailbox and address fit the Variation rules below. Each next episode is due one interval after the previous actual start; its start is drawn in a window of a quarter interval (at most 6 hours) centred on that due time, weighted towards busy hours. Missed episodes are never caught up. With the default interval, successive episodes start about 21 to 27 hours apart, near the time of day of the first one and drifting towards busier hours; when the first one falls at night, several episodes in a row can start in quiet hours. At intervals of 8 hours or less the window covers most of the clock.
- **Variation.** Each episode uses a different mailbox and a different address from the previous one. The mailbox is one whose own clients have already logged in over IMAP and over POP3 from public addresses earlier in the run (early in a run, one whose laptop or phone polls both), chosen with equal weight among such mailboxes. The address is a carrier address of that mailbox's phone, a phone that reconnects at least about hourly in working hours and usually comes back to each of its addresses within a day; the phone used the address earlier in the run, and none of the mailbox's clients uses it at that moment. These addresses are shared with other subscribers.
- **Background overlap.** Every part of the chain also occurs in ordinary traffic of both modes: repeated failures of one mailbox and address within minutes, four failures followed by an IMAP success within 15 minutes (about 35 a day), failure, IMAP success and POP3 success from one mailbox and address (about 13 a day), three failures, IMAP success and POP3 success (about 3 a day), and IMAP-then-POP3 pairs within 10 minutes (about 900 a day). The episode's mailbox and address also log in together in ordinary traffic.
- **Detection.** Only the full order separates the modes. Ordinary traffic never completes four failures, an IMAP success and a POP3 success for one mailbox and address within 15 minutes of the first failure: after four failures and an IMAP success of one mailbox and address, the next POP3 login of that mailbox from that address comes more than 15 minutes after the first of those failures. A rule that correlates these six logins for one mailbox and address within 15 minutes finds every episode and nothing else.

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

Mailbox local parts and their type (`personal` or `shared`) are listed in `samples/mailboxes.csv` (4 to 700 rows, at least four personal).

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

For a finite batch, set `start` and `end` of the `oscillator` in both `patterns/*.yml` files to the same range, with `start` at 00:00 UTC so the hour curve stays in place (for example `start: "2026-09-01T00:00:00Z"` and `end: "2026-09-08T00:00:00Z"`), then run:

```bash
eventum generate --path generators/email-dovecot-imap/generator.yml --id dovecot-imap --live-mode false --keep-order true
```

The volume is the sum of the two `time_patterns` files under `patterns/`: `floor.yml` (round the clock) and `daytime.yml` (the working-day curve). To change it, scale the `ratio` of both files by the same factor; with fewer mailboxes in `samples/mailboxes.csv`, scale it by the same share, so each client keeps its reconnect rate. Episode start hours follow the shipped curve even if you reshape the pattern files.

Performance: about 2,500 events per second in batch mode on one core.

## Sample Output

This synthetic record is the first failure of an episode, copied from a finite generator run. It is not a vendor capture.

```json
{"@timestamp": "2026-09-01T12:48:04+00:00", "destination": {"ip": "10.20.0.20"}, "dovecot": {"auth_attempts": 1, "auth_duration_seconds": 2, "disconnect_reason": "Connection closed", "login_result": "failure", "method": "PLAIN", "protocol": "imap", "session": "Clr8Vo8JzJzoZUBv", "tls": true}, "ecs": {"version": "8.17.0"}, "event": {"action": "login-failure", "category": ["authentication"], "kind": "event", "original": "Sep  1 12:48:04 mail01.corp.example dovecot: imap-login: Disconnected: Connection closed (auth failed, 1 attempts in 2 secs): user=\u003cmateo.wojcik@corp.example\u003e, method=PLAIN, rip=198.51.100.44, lip=10.20.0.20, TLS, session=\u003cClr8Vo8JzJzoZUBv\u003e", "outcome": "failure", "type": ["denied"]}, "host": {"ip": ["10.20.0.20"], "name": "mail01.corp.example"}, "related": {"ip": ["198.51.100.44", "10.20.0.20"], "user": ["mateo.wojcik@corp.example"]}, "service": {"name": "dovecot", "type": "imap"}, "source": {"ip": "198.51.100.44"}, "user": {"name": "mateo.wojcik@corp.example"}}
```

## Source and Scope

The [Dovecot 2.3 settings](https://doc.dovecot.org/2.3/settings/core/) define the default login-field order, comma joining of nonempty values, and syslog as the default logging destination. A [first-hand 2.3.20 IMAP success capture](https://dovecot.org/mailman3/archives/list/dovecot%40dovecot.org/thread/73CEPDRB7TWP6BJABZL6VBZZH66HQ6S6/) shows `Login`, `user`, `method`, `rip`, `lip`, `mpid`, `TLS` and `session`. A [first-hand 2.3.20 IMAP failure capture](https://dovecot.org/mailman3/archives/list/dovecot%40dovecot.org/thread/C2U64DRTHU7QL26IEV44SRGLKXZ3F4H4/) confirms `Disconnected: Connection closed (auth failed, N attempts in S secs):` and the absence of `mpid`. A [POP3 success capture on Dovecot's own mailing list](https://dovecot.org/mailman3/archives/list/dovecot%40dovecot.org/thread/RF5LJE3G3UZNPYWR7YKDAL7NC5LMI2Y5/) confirms the `pop3-login: Login` form but does not pin its Dovecot version.

`session` is a unique connection identifier in [Dovecot 2.3 variables](https://doc.dovecot.org/2.3/configuration_manual/config_file/config_variables/). The generator uses a 16-character base64-like form seen in success captures; the 2.3.20 failure capture has a shorter valid ID, so 16 characters are a selected profile, not a universal length. `mpid` grows like a process ID counter. `TLS` confirms a secure connection but cannot distinguish implicit TLS on 993/995 from STARTTLS on 143/110; the output therefore does not invent `destination.port`. Failure durations start at two seconds per attempt, consistent with the documented default `auth_failure_delay`; they are modeled, not a measured timing distribution. The RFC 3164-style envelope assumes a UTC syslog collector; Dovecot logging and forwarding can change it.

Limits:

- No complete 2.3.20 raw capture was found for a TLS failure with the modeled durations or for a POP3 success. Those lines combine the documented field order of the same branch with first-hand examples; their byte-for-byte fidelity is unconfirmed.
- Failures are modeled for IMAP only. A POP3 client with an outdated password produces no records, because no POP3 failure capture was found.
- Timestamps have one-second resolution, as the syslog clock does; several records can share one second.
- Retries after a rejected password, and the POP3 login that follows a client's IMAP login, are a few seconds further apart at night than in working hours (median retry 21 seconds instead of 15).
- The hour curve is in UTC and repeats every day: there is no weekly cycle, so weekends look like weekdays.
- With `anomaly_mode: true` each episode adds its own records, so counts of the chain parts (repeated failures of one mailbox and address, four failures followed by an IMAP success, IMAP-then-POP3 pairs) are about one per episode higher than in background alone.
- The output is ECS JSON containing a native-style line in `event.original`, not a native syslog stream. This pack excludes IMAP commands, POP3 retrievals, mailbox changes, logouts, LMTP delivery and auth-worker diagnostics.

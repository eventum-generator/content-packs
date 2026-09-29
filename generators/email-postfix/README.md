# Postfix SMTP Submission Syslog

Generates synthetic Postfix 3.8.3+ submission-relay messages from `smtpd`, `cleanup`, `qmgr` and `smtp`, for testing mail-server authentication and outbound-mail detections. The complete native syslog line is in `event.original`; the output file contains parsed ECS JSON, not bare syslog lines. The selected profile has SASL LOGIN enabled on the submission service, `enable_long_queue_ids=no`, `smtp_destination_recipient_limit=1`, `local_header_rewrite_clients=permit_sasl_authenticated`, `show_user_unknown_table_name=no`, and mail-log timestamps in UTC. It does not emit a remote syslog packet.

## Event Types

| Native record | Share | Category |
| --- | ---: | --- |
| `postfix/smtpd` `client=`, `sasl_method=LOGIN`, `sasl_username=` (queue ID assigned to an authenticated submission) | 18.5% | email, info |
| `postfix/cleanup` `message-id=` | 18.5% | email, info |
| `postfix/qmgr` `from=`, `size=`, `nrcpt=` `(queue active)` | 18.5% | email, info |
| `postfix/smtp` `to=`, `relay=`, `delay=`, `delays=`, `dsn=2.0.0`, `status=sent` (one per recipient) | 25.3% | email, info |
| `postfix/qmgr` `removed` | 18.5% | email, end |
| `postfix/smtpd` `SASL LOGIN authentication failed` | 0.4% | authentication, email, denied |
| `postfix/smtpd` `NOQUEUE: reject: RCPT ... User unknown` | 0.4% | email, denied |

Shares over four days of a default run. Every accepted submission produces the full queue lifecycle: queue creation, cleanup, activation, one delivery per recipient and removal. Rates are synthetic workload settings, not measured Postfix frequencies.

## Volume and Timing

About 54,700 records a day (±3% from day to day), about 10,100 submitted messages, at random times on a UTC hour-of-day curve: a flat application share plus staff mail that follows a working day peaking at 12:00-13:00.

| UTC hours | Records/s | Staff share of messages |
| --- | ---: | ---: |
| 00-04, 20-24 | 0.39-0.42 | 9-17% |
| 04-08 | 0.42-0.64 | 18-45% |
| 08-11, 14-17 | 0.75-0.98 | 55-66% |
| 11-14 | 1.02-1.07 | 67% |
| 17-20 | 0.47-0.64 | 24-48% |

- **Staff.** 150 users (`samples/users.json`) submit from their own workstation (`ws-NNNN.corp.example`) or VPN laptop (no reverse DNS, shown as `unknown`), about 4,500 messages a day in total. Each user has a steady share for the run, between about 10 and 60 messages a day, so every user sends mail every day. A message goes to one to five external recipients (one 68%, two 16%, three 8%, four and five 4% each). About 3% of submissions start with a mistyped or outdated password: one failure is more common than two, two more common than three; after one or two failures the user usually gets it right, after three the user gives up. Retries follow a failure after a median 14 seconds, within the same `smtpd` process. About 4% of staff submissions address an unknown local mailbox and are rejected before queueing; most users resend about a minute later.
- **Applications.** Eight service accounts (`samples/senders.json`) send notifications, reports and job output around the clock, about 5,600 messages a day, weighted by the `share` column. They rarely fail authentication (once, then succeed on retry a few seconds later) and rarely address an unknown mailbox, without resending.
- **Messages.** Sizes are right-skewed (staff mail with attachments up to the 10 MB default `message_size_limit`, application mail smaller). Each recipient is delivered by its own `smtp` process to one of three relays (`samples/recipients.json`). Setup time varies and transmission time grows with message size.
- **Processes.** `qmgr` keeps one process ID. `smtpd`, `cleanup` and `smtp` processes are reused from job to job, exit after 100 seconds idle or 100 jobs, and new processes take increasing process IDs, so process IDs repeat across unrelated clients.

About 2% of SASL attempts fail. Several records can share one second.

## Anomaly Chain

One staff user fails SASL LOGIN three times from the user's own workstation or laptop address, a few seconds to about a minute apart, within one `smtpd` process. The next attempt succeeds, and the authenticated session submits a message for five external recipients, which is delivered and removed like any other. The pattern fits a password guessed or replayed from the user's machine followed by outbound mail. Link the failures and the queue creation by `user.name`, `source.ip`, `host.name` and `process.pid`, then the rest of the lifecycle by `postfix.queue_id`. The failures and the queue creation span about half a minute to 100 seconds.

- **Recurrence.** With `anomaly_mode: true` (the default), the first episode starts within the first `anomaly_interval_hours` (at most 24 hours) of the run, at a time drawn towards busy staff hours. Each next episode is due one interval after the previous actual start; its start is drawn in a window of a quarter interval (at most 6 hours) centred on that due time, weighted towards busy hours. Missed episodes are never caught up. With the default 24-hour interval, successive episodes start about 21 to 27 hours apart, mostly between 08:00 and 16:00 UTC; at intervals of 8 hours or less some episodes start at night.
- **Variation.** Each episode uses a different user from the previous one, drawn from the busier half of the staff by their mail volume. The address is that user's usual address, and the user keeps sending ordinary mail before and after the episode.
- **Background overlap.** Every record type of the chain occurs in ordinary traffic of both modes: failures of one user and address a few seconds apart, three failures in a row (about 12-14 a day), one or two failures followed by an accepted submission, and five-recipient messages from the same users. The episode's user and address also send ordinary mail every day.
- **Detection.** Only the full order separates the modes. Ordinary traffic never has three SASL failures followed by an accepted submission for one user and address within 2 minutes of the first failure: a user who has failed three times within 2 minutes fails again if they try once more inside that window, also right after an episode. A rule that correlates three failures and a queue creation for one user and address within 2 minutes finds every episode and nothing else.

Set `anomaly_mode: false` to keep only background activity.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Purpose |
| --- | --- | --- |
| `anomaly_mode` | `true` | Add the recurring anomaly episodes to the background |
| `anomaly_interval_hours` | `24` | Hours from one episode start to the next due time (1 to 8760) |
| `mail_host` | `mail-01.corp.example` | Postfix hostname in the syslog line and generated Message-IDs |
| `mail_ip` | `10.80.0.5` | Postfix host IP |

Senders and recipients are sample files under `samples/`:

- `users.json` - staff users: `user`, `ip`, `client` (reverse DNS name or `unknown`), `helo` (at least 4 rows).
- `senders.json` - application accounts: `user`, `ip`, `client`, `share` (relative volume).
- `recipients.json` - external recipients: `email`, `relay_host`, `relay_ip` (at least 5 rows).
- `unknown_recipients.json` - non-existent local addresses used in rejected submissions.

Usernames must be ASCII addresses.

### Output Parameters

The shipped configuration writes `output/events.json` and needs no endpoint parameters or secrets. To send events elsewhere, replace the `output` block in a local copy and use that plugin's `${params.*}` and `${secrets.*}` placeholders. A collector expecting raw syslog should extract `event.original`.

## Usage

From the content-packs repository root, stream in real time:

```bash
eventum generate --path generators/email-postfix/generator.yml --id email-postfix --live-mode true
```

For a finite batch, set `start` and `end` of the `oscillator` in all three `patterns/*.yml` files to the same range, with `start` at 00:00 UTC so the hour curve stays in place (for example `start: "2026-09-01T00:00:00Z"` and `end: "2026-09-05T00:00:00Z"`), then run:

```bash
eventum generate --path generators/email-postfix/generator.yml --id email-postfix --live-mode false --keep-order true
```

The volume is the sum of the `time_patterns` files under `patterns/`: `staff-floor.yml` and `staff-day.yml` (staff mail) and `applications.yml` (application mail). To change it, scale the `ratio` of the files of one population by the same factor; with a different number of users in `samples/users.json`, scale the staff files by the same share so each user keeps a realistic volume. Episode start hours follow the shipped staff curve even if you reshape the pattern files. When a finite window ends, the last message may be cut off before its deliveries.

Performance: about 6,500 events per second in batch mode on one core.

## Sample Output

This synthetic record is the accepted submission that ends an episode, copied from a finite default run. It is not a vendor capture.

```json
{"@timestamp": "2026-09-01T11:07:59+00:00", "ecs": {"version": "8.17.0"}, "event": {"action": "queue-created", "category": ["email"], "dataset": "postfix.syslog", "kind": "event", "original": "Sep  1 11:07:59 mail-01.corp.example postfix/smtpd[59392]: 8E5BDF3BD5: client=ws-0324.corp.example[10.80.21.78], sasl_method=LOGIN, sasl_username=alex.hansen@corp.example", "outcome": "success", "type": ["info"]}, "host": {"ip": ["10.80.0.5"], "name": "mail-01.corp.example"}, "log": {"level": "info", "syslog": {"appname": "postfix/smtpd"}}, "message": "8E5BDF3BD5: client=ws-0324.corp.example[10.80.21.78], sasl_method=LOGIN, sasl_username=alex.hansen@corp.example", "observer": {"hostname": "mail-01.corp.example", "ip": "10.80.0.5", "product": "Postfix", "type": "mail", "vendor": "Postfix"}, "postfix": {"queue_id": "8E5BDF3BD5", "sasl": {"username": "alex.hansen@corp.example"}, "service": "smtpd"}, "process": {"name": "postfix/smtpd", "pid": 59392}, "related": {"hosts": ["mail-01.corp.example"], "ip": ["10.80.21.78"], "user": ["alex.hansen@corp.example"]}, "source": {"ip": "10.80.21.78"}, "tags": ["postfix", "preserve_original_event"], "user": {"name": "alex.hansen@corp.example"}}
```

## References and Limits

- [Postfix 3.8.3 smtpd source](https://github.com/vdukhovni/postfix/blob/v3.8.3/postfix/src/smtpd/smtpd.c#L2316) logs queue-ID/client/SASL information while initializing cleanup, before final DATA acceptance, and [appends `sasl_username=<...>`](https://github.com/vdukhovni/postfix/blob/v3.8.3/postfix/src/smtpd/smtpd.c#L1681) to reject records of authenticated clients. [Versioned SASL logging](https://github.com/vdukhovni/postfix/blob/v3.8.3/postfix/src/smtpd/smtpd_sasl_glue.c#L344) uses the client name/address and username on failure.
- [Postfix 3.8.3 generated Message-ID](https://github.com/vdukhovni/postfix/blob/v3.8.3/postfix/src/cleanup/cleanup_message.c#L694) uses queue-file creation time and requires header rewriting or `always_add_missing_headers`; this profile selects [authenticated header rewriting](https://www.postfix.org/postconf.5.html#local_header_rewrite_clients). [Versioned delay formatting](https://github.com/vdukhovni/postfix/blob/v3.8.3/postfix/src/util/format_tv.c#L70) gives the printed precision.
- [Postfix architecture](https://www.postfix.org/OVERVIEW.html) documents the `smtpd` → `cleanup` → queue manager → `smtp` path; [process limits](https://www.postfix.org/postconf.5.html#max_idle) define `max_idle` and `max_use`.
- [Postfix 3.8.3 announcement](https://www.postfix.org/announcements/postfix-3.8.3.html) documents `sasl_username` after authentication failure.
- [Postfix ETRN examples](https://www.postfix.org/ETRN_README.html) show queue activation with `from=`, `size=` and `nrcpt=`; [connection-cache examples](https://www.postfix.org/CONNECTION_CACHE_README.html) show `to=`, `relay=`, `delay=`, `delays=`, `dsn=` and `status=sent`; [backscatter examples](https://www.postfix.org/BACKSCATTER_README.html) show `NOQUEUE: reject: RCPT` syntax.
- [Queue-ID specification](https://www.postfix.org/postconf.5.html#enable_long_queue_ids), [delay specification](https://www.postfix.org/postconf.5.html#delay_logging_resolution_limit) and [single-recipient SMTP transport](https://www.postfix.org/postconf.5.html#smtp_destination_recipient_limit) define the selected profile.
- [Postfix users list trace](https://www.mail-archive.com/postfix-users%40postfix.org/msg83417.html) shows one queue ID through `smtpd`, `cleanup`, `qmgr`, `smtp` and `removed`.

There is no Elastic integration for Postfix; `postfix.syslog` is this pack's dataset name.

Limits:

- This is a selected successful-delivery path, not a complete Postfix mail log: it omits connection, disconnect and TLS records, postscreen, local and LMTP delivery, bounces, deferred retries and `conn_use=` on cached connections. All deliveries go to external relays.
- No complete Postfix 3.8.3+ raw capture of three failures followed by an accepted submission was found; the chain joins documented line formats.
- The failure reason `authentication failure` is the Cyrus SASL wording; a Dovecot SASL backend prints a different reason.
- Records of one message are seconds apart instead of milliseconds, and the printed `delay` and `delays` follow that spacing: a median total delay of about 5 seconds at busy hours and 9 seconds at night, where a real relay usually delivers in under a second.
- Timestamps have one-second resolution, as the syslog clock does.
- The hour curve is in UTC and repeats every day: there is no weekly cycle, so weekends look like weekdays.
- Queue IDs have a valid microsecond part and a random inode part.
- With `anomaly_mode: true` each episode adds its own records, so counts of three failures in a row and of five-recipient messages are about one per episode higher than in background alone.
- The output is ECS JSON with the native line in `event.original`, not a native syslog stream.

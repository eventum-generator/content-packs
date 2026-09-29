# Cisco Secure Email Gateway mail logs

Synthetic text `mail_logs` from a Cisco Secure Email Gateway (formerly ESA, AsyncOS 16.x) pushed over syslog, shaped as the Elastic `cisco_secure_email_gateway` integration indexes them. The simulated appliance is a virtual gateway with one `Management` interface and one public listener: internet mail arrives for `contoso.example` users, and two internal Exchange hosts relay outbound mail through the `RELAYLIST` sender group.

Each record keeps the raw syslog line in `event.original` (`<166>Mmm dd HH:MM:SS host mail_logs: Info: ...`) and the fields the integration's grok patterns extract from it: `email.message_id` (MID), `cisco_secure_email_gateway.log.injection_connection_id` (ICID), `delivery_connection_id` (DCID), `recipient_id` (RID), `email.from.address`, `email.to.address`, `read_bytes`, connection and message status, scanning engine verdicts.

## Event Types

Shares are typical of default output with `anomaly_mode: true` (per day about 95,000 lines, 1,740 outbound and 2,300 inbound messages, 435 rejected connections).

| Line | Share | Category |
| --- | --- | --- |
| `New SMTP ICID ... address ... reverse dns host ... verified` | 4.69% | Connection |
| `ICID ... ACCEPT SG` / `RELAY SG` / `REJECT SG ... SBRS` | 4.69% | Connection policy |
| `ICID ... close` | 4.69% | Connection |
| `Start MID ... ICID` | 4.23% | Message |
| `MID ... ICID ... From:` | 4.23% | Message |
| `MID ... ICID ... RID n To:` | 4.91% | Message |
| `MID ... Message-ID` | 4.23% | Message |
| `MID ... Subject` | 4.23% | Message |
| `MID ... ready <bytes> bytes from` | 4.23% | Message |
| `MID ... matched all recipients for per-recipient policy DEFAULT` | 4.23% | Policy |
| `MID ... SPF: mailfrom identity ... Pass` | 2.18% | Authentication |
| `MID ... DKIM: pass signature verified` | 2.18% | Authentication |
| `MID ... DMARC: ... DMARC pass` | 2.18% | Authentication |
| `MID ... interim verdict using engine: CASE spam ...` | 2.41% | Anti-spam |
| `MID ... using engine: CASE spam ...` / `GRAYMAIL positive` | 2.90% | Anti-spam |
| `MID ... interim AV verdict using Sophos CLEAN` | 4.23% | Anti-virus |
| `MID ... antivirus negative` | 4.23% | Anti-virus |
| `MID ... antivirus positive` | <0.01% | Anti-virus |
| `Message aborted MID ... Dropped by antivirus` | <0.01% | Anti-virus |
| `MID ... attachment` | 1.87% | Content |
| `MID ... Outbreak Filters: verdict negative` | 2.40% | Outbreak filters |
| `MID ... queued for delivery` | 4.23% | Message |
| `EUQ: Tagging MID ... for quarantine` | 0.23% | Quarantine |
| `RPC Delivery start RCID ... MID ...` | 0.23% | Quarantine |
| `EUQ: Quarantined MID` | 0.23% | Quarantine |
| `RPC Message done RCID ... MID` | 0.23% | Quarantine |
| `New SMTP DCID ... interface ... address` | 4.35% | Delivery |
| `Delivery start DCID ... MID ... to RID [...]` | 4.35% | Delivery |
| `Message done DCID ... MID ... to RID [...]` | 4.31% | Delivery |
| `MID ... RID [...] Response '...'` | 4.31% | Delivery |
| `Bounced: DCID ... MID ... to RID n - 5.1.0 - ...` | 0.04% | Delivery |
| `DCID ... close` | 4.35% | Delivery |
| `Message finished MID ... done` | 4.23% | Message |

**Volume and hour curve.** About 95,000 lines a day (about 1,740 outbound and 2,300 inbound messages, and 435 rejected connections). Times are UTC. Total volume follows the working day of internal users: about 2,050 lines per hour at night, rising from 06:00, about 6,500 per hour between 09:00 and 15:00, falling after 16:00 to a tail until 19:00. Internet mail is higher between 06:00 and 17:00 and continues at night.

**Background.** 100 internal users (`samples/users.json`) each have an activity weight, their own working hours in UTC and a personal mailbox at one of the freemail providers. Outbound mail comes from users in proportion to their weight, mostly within their own working hours (single messages and series of 2-5 messages to the same recipients); about 2% of recipients are mistyped and hard-bounce. Inbound mail goes to users in proportion to their weight: partner and freemail correspondents, newsletters marked as graymail, spam quarantined by CASE (about 210 messages a day), low-reputation connections rejected by the blocked-list sender group, and a few virus drops a day. Rates and shares are synthetic, not vendor-measured.

**Personal mail.** Every user now and then sends mail to the own personal mailbox, singly or in quick series whose messages each draw their own content: about 165 such messages a day, about 23 of them 8 MB or more. A group of 22 users does this one to six times a day, the others a few times a week.

## Anomaly Chain

A likely exfiltration to a personal mailbox:

1. One internal user sends three outbound messages of at least `large_message_bytes` (8 MB) each (`MID ... ready <bytes> bytes from <user>`) within 40 minutes.
2. Each message goes to the user's own freemail mailbox (`MID ... ICID ... RID 0 To: <user><NN>@<freemail>`).
3. Each message is delivered (`New SMTP DCID`, `Delivery start`, `Message done ... to RID [0]`, `Response '2.x.0 ...'`, `Message finished`).

Linking fields: `email.from.address` on the `ready` line, joined by MID (`email.message_id`) to the `To:` line for the recipient and to the `Message done` line for the delivery; the personal mailbox carries the user's local part followed by two digits. The gateway logs no content beyond attachment names, so the chain shows volume and destination, not intent.

**Recurrence.** The first episode starts within `min(anomaly_interval_hours, 24 h)` of the first record, at an hour drawn from the office mail curve. Each later episode is due one interval after the actual start of the previous one and starts within a window of `min(interval / 4, 6 h)` centred on that due time, leaning towards busy office hours; missed intervals are not caught up. At the default 24 h the first episode falls about 6-16 h after the start of the output and later ones 21-27 h apart; at a 6 h interval they are about 5.3-6.7 h apart.

**Variation.** The episode user belongs to the 22 users who mail their personal mailbox several times a day and changes between consecutive episodes, and so does the mailbox. Message sizes (the background large-file distribution above the threshold), the number of attachments (one to three, as in background), attachment names and subjects vary per episode; gaps between the messages follow the same law as background series (lognormal, median about 165 s). Relay host, message IDs and delivery responses follow the background rules.

**Background overlap.** Every element occurs in ordinary traffic of both modes. Each user|mailbox pair an episode can use also has ordinary messages, one to six a day. Two large messages to the own mailbox within 40 minutes occur 5-12 times per 4 days, and three or more large messages from one sender within 40 minutes to other recipients 64-100 times. Three large messages to the own mailbox within 46 minutes do not occur in background: the one that would complete them keeps its time and size and goes to the user's other recipients instead. Episodes add three messages of their own; the user's other mail continues as usual, while the total line count is the same in both modes.

**Detection idea.** Alert when one internal sender has three or more delivered messages of 8 MB or more within 40 minutes to a freemail mailbox that matches the sender's name.

`event.template.params.anomaly_mode` defaults to `true`. Set it to `false` for background only: the same traffic without a complete chain.

## Parameters

### Event Parameters

Set under `event.template.params` in `generator.yml`.

| Name | Default | Description |
| --- | --- | --- |
| `anomaly_mode` | `true` | Add the recurring large-mail episode |
| `anomaly_interval_hours` | `24` | Hours from one episode start to the next due time; 1 to 8760 |
| `host_name` | `esa-01.contoso.example` | Gateway host name in the syslog header |
| `interface_ip` | `10.20.30.25` | Address of the `Management` interface |
| `internal_domain` | `contoso.example` | Domain of internal users |
| `relay_hosts` | `exch-01.contoso.example`, `exch-02.contoso.example` (`10.20.10.11`, `.12`) | Internal Exchange hosts that relay outbound mail and receive inbound mail; users are assigned to them in turn |
| `large_message_bytes` | `8000000` | Size threshold of the episode messages; background never has three such messages to the sender's own mailbox within 40 minutes |
| `max_message_bytes` | `20000000` | Largest message the listener accepts |
| `partner_domains` | 8 domains | Partner mail domains with their MX address and base reputation (SBRS) |
| `freemail_domains` | 3 domains | Public mailbox providers; users' personal mailboxes are spread over them in turn |
| `newsletter_senders` | 4 senders | Bulk senders marked as graymail |

### Samples

| File | Content |
| --- | --- |
| `samples/users.json` | 100 internal users: local part, activity weight, working-hours start and length (UTC), personal mailbox suffix, personal-mail weight |
| `samples/contact_names.csv` | Local parts for partner and freemail contacts |
| `samples/subjects.csv` | Message subjects |
| `samples/attachments.csv` | Attachment names |

### Output Parameters

The shipped configuration writes `output/events.json` and needs no connection settings. To send events elsewhere, replace the `file` output in a local copy with the output plugin you need and reference its settings as `${params.<name>}` and `${secrets.<name>}`, for example `${params.opensearch_host}` and `${secrets.opensearch_password}`.

## Usage

```bash
# Live: real time
eventum generate --path generators/email-cisco-secure-email-gateway/generator.yml --id seg --live-mode true

# Batch: as fast as possible
eventum generate --path generators/email-cisco-secure-email-gateway/generator.yml --id seg --live-mode false
```

The rate and hour curve come from the files in `patterns/` (`office-*.yml` for internal users, `internet-*.yml` for internet mail). They start on 2026-01-01 and never end; for a finite batch window set the same `start` and `end` under `oscillator` in every pattern file, with `start` at midnight UTC so the daily curve stays aligned. The episode needs up to one `anomaly_interval_hours` (at most 24 h) of output for the first one; for a batch run set a window of two or more intervals.

Performance: about 2,600 lines per second in batch mode (14 days, 1.33 million lines, in 8.5 minutes).

## Sample Output

The `ready` line of the first episode message in the 4-day `anomaly_mode: true` output:

```json
{"@timestamp": "2026-09-01T11:55:22.000Z", "cisco_secure_email_gateway": {"log": {"category": {"name": "mail_logs"}, "host": "esa-01.contoso.example", "message": "MID 74652742 ready 9721387 bytes from \u003cf.sergeeva@contoso.example\u003e", "read_bytes": 9721387}}, "ecs": {"version": "8.17.0"}, "email": {"from": {"address": ["f.sergeeva@contoso.example"]}, "message_id": "74652742"}, "event": {"dataset": "cisco_secure_email_gateway.log", "kind": "event", "original": "\u003c166\u003eSep  1 11:55:22 esa-01.contoso.example mail_logs: Info: MID 74652742 ready 9721387 bytes from \u003cf.sergeeva@contoso.example\u003e", "timezone": "UTC"}, "log": {"level": "info", "syslog": {"priority": 166}}, "tags": ["preserve_original_event"]}
```

## Limitations

- No complete raw capture of an AsyncOS 16.x appliance was available. Line grammar follows the examples in the AsyncOS 16.5 Logging chapter (examples there carry old dates) and the Elastic integration's test fixtures; the `RELAY SG ... SBRS rfc1918` line follows Cisco TechNote 214631; the `REJECT SG BLOCKED_LIST` line applies the documented `ACCEPT SG` grammar to the default blocked sender group.
- Structured fields are what the Elastic integration 1.29.3 extracts. Its connection pattern matches only the `Management` interface, which is why the appliance uses one interface; sender-group, antivirus, attachment, quarantine and bounce lines keep only `email.message_id` or the message text, as the integration leaves them. Elastic agent fields (`agent.*`, `data_stream.*`, `input.type`) are omitted.
- Syslog timestamps have one-second resolution and no year; `@timestamp` is UTC with `.000` milliseconds, and the syslog priority is always `<166>` (local4.info), as in the integration fixtures.
- Lines that the appliance writes at the same instant are spread over consecutive seconds: the connection and sender-group lines share a second in 42% of connections and are at most 6 s apart in 99%. A message takes a median 28 s from `Start MID` to `Message finished` (10% under 13 s, 10% over 57 s), longer than on a real gateway, and longer at night (median about 45 s) than by day (about 23 s), the reverse of a loaded gateway.
- Background never has three large messages to the sender's own mailbox within 46 minutes; the 40-minute chain therefore has a slightly wider empty margin than a real gateway would show.
- Not covered: TLS, SMTP authentication, per-connection message reuse, delayed (soft-bounce) delivery, DLP, AMP, URL filtering, message filters, `Subject` with double quotes, and log levels other than `Info`.
- SPF, DKIM and DMARC pass for legitimate inbound senders and are not logged for spam senders.
- With `anomaly_mode: true` each episode adds its own three large messages to a personal mailbox, so counts of large personal mail are about three per episode higher than in background only; at short intervals (a few hours) closely spaced large messages per sender become noticeably more frequent.
- Users, their weights and working hours are fixed; mail volume per user does not change from day to day beyond random variation, and weekends look like weekdays.

## References

- [Cisco AsyncOS 16.5 for Secure Email Gateway, Logging](https://www.cisco.com/c/en/us/td/docs/security/esa/esa16-5/user_guide/b_ESA_Admin_Guide_16-5/b_ESA_Admin_Guide_12_1_chapter_0100111.html)
- [Cisco TechNote 214631: What does "SBRS rfc1918" in the mail logs mean](https://www.cisco.com/c/en/us/support/docs/security/email-security-appliance/214631-what-does-sbrs-rfc1918-in-the-mail-log.html)
- [Elastic integration: Cisco Secure Email Gateway](https://github.com/elastic/integrations/tree/main/packages/cisco_secure_email_gateway)

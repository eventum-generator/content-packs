# Cisco Secure Email Gateway mail logs

Synthetic text `mail_logs` from a Cisco Secure Email Gateway (formerly ESA, AsyncOS 16.x) pushed over syslog, shaped as the Elastic `cisco_secure_email_gateway` integration indexes them. The simulated appliance is a virtual gateway with one `Management` interface and one public listener: internet mail arrives for `contoso.example` users, and two internal Exchange hosts relay outbound mail through the `RELAYLIST` sender group.

Each record keeps the raw syslog line in `event.original` (`<166>Mmm dd HH:MM:SS host mail_logs: Info: ...`) and the fields the integration's grok patterns extract from it: `email.message_id` (MID), `cisco_secure_email_gateway.log.injection_connection_id` (ICID), `delivery_connection_id` (DCID), `recipient_id` (RID), `email.from.address`, `email.to.address`, `read_bytes`, connection and message status, scanning engine verdicts.

## Event Types

Shares are measured on the final 80-hour `anomaly_mode: true` capture (86,162 lines; 3,715 messages: 1,838 outbound, 1,877 inbound; 356 rejected connections).

| Line | Share | Category |
| --- | --- | --- |
| `New SMTP ICID ... address ... reverse dns host ... verified` | 4.72% | Connection |
| `ICID ... ACCEPT SG` / `RELAY SG` / `REJECT SG ... SBRS` | 4.72% | Connection policy |
| `ICID ... close` | 4.72% | Connection |
| `Start MID ... ICID` | 4.31% | Message |
| `MID ... ICID ... From:` | 4.31% | Message |
| `MID ... ICID ... RID n To:` | 4.99% | Message |
| `MID ... Message-ID` | 4.31% | Message |
| `MID ... Subject` | 4.31% | Message |
| `MID ... ready <bytes> bytes from` | 4.31% | Message |
| `MID ... matched all recipients for per-recipient policy DEFAULT` | 4.31% | Policy |
| `MID ... SPF: mailfrom identity ... Pass` | 1.94% | Authentication |
| `MID ... DKIM: pass signature verified` | 1.94% | Authentication |
| `MID ... DMARC: ... DMARC pass` | 1.94% | Authentication |
| `MID ... interim verdict using engine: CASE spam ...` | 2.18% | Anti-spam |
| `MID ... using engine: CASE spam ...` / `GRAYMAIL positive` | 2.62% | Anti-spam |
| `MID ... interim AV verdict using Sophos CLEAN` | 4.28% | Anti-virus |
| `MID ... antivirus negative` | 4.28% | Anti-virus |
| `MID ... antivirus positive` | 0.03% | Anti-virus |
| `Message aborted MID ... Dropped by antivirus` | 0.03% | Anti-virus |
| `MID ... attachment` | 2.00% | Content |
| `MID ... Outbreak Filters: verdict negative` | 2.15% | Outbreak filters |
| `MID ... queued for delivery` | 4.28% | Message |
| `EUQ: Tagging MID ... for quarantine` | 0.21% | Quarantine |
| `RPC Delivery start RCID ... MID ...` | 0.21% | Quarantine |
| `EUQ: Quarantined MID` | 0.21% | Quarantine |
| `RPC Message done RCID ... MID` | 0.21% | Quarantine |
| `New SMTP DCID ... interface ... address` | 4.44% | Delivery |
| `Delivery start DCID ... MID ... to RID [...]` | 4.44% | Delivery |
| `Message done DCID ... MID ... to RID [...]` | 4.39% | Delivery |
| `MID ... RID [...] Response '...'` | 4.39% | Delivery |
| `Bounced: DCID ... MID ... to RID n - 5.1.0 - ...` | 0.05% | Delivery |
| `DCID ... close` | 4.44% | Delivery |
| `Message finished MID ... done` | 4.31% | Message |

Background traffic is independent random processes, not a script: outbound mail per internal user (lognormal activity weights, each user's own working hours in UTC), mail from every user to the own personal mailbox, inbound internet mail with a day/night rate, series of 2-5 messages to the same recipients, occasional mistyped recipients that hard-bounce, spam quarantined by CASE, rejected low-reputation connections and rare virus drops. Rates and shares are synthetic, not vendor-measured.

## Anomaly Chain

A likely exfiltration to a personal mailbox:

1. One internal user sends three to five outbound messages of at least `large_message_bytes` (8 MB) each (`MID ... ready <bytes> bytes from <user>`), the first three within 40 minutes.
2. Each message goes to the user's own freemail mailbox (`MID ... ICID ... RID 0 To: <user><NN>@<freemail>`).
3. Each message is delivered (`New SMTP DCID`, `Delivery start`, `Message done ... to RID [0]`, `Response '2.x.0 ...'`, `Message finished`).

Linking fields: `email.from.address` on the `ready` line, joined by MID (`email.message_id`) to the `To:` line for the recipient and to the `Message done` line for the delivery; the personal mailbox carries the user's local part followed by two digits. The gateway logs no content beyond attachment names, so the chain shows volume and destination, not intent.

**Recurrence.** The first episode falls due `anomaly_interval_hours` (default 24, minimum 1) after the capture start. When due, the episode waits a random delay (exponential, mean 10 minutes) and then begins on an opportunity drawn like personal mail in the background: a user picked uniformly and accepted with that user's working-hours factor, so episodes lean towards working hours but can occur at night. The next episode is due one interval after the actual start; missed intervals are not caught up. Measured on the final captures: default interval, first episode 24.3 h after start, then gaps of 27.6 h and 26.7 h; an 8 h interval gave 7 episodes with gaps of 8.1-16.0 h.

**Variation.** The user and personal mailbox change between consecutive episodes. Message count, sizes (the background large-file distribution, taken above the threshold), the number of attachments (one to three, as in background), attachment names and subjects vary per episode; gaps between messages follow the same law as background series (lognormal, median about 165 s), and a draw is redrawn only when the first three messages would not fit the 40-minute chain window. Relay host, message IDs and delivery responses follow the background rules.

**Background overlap.** Every element occurs in ordinary traffic of both modes. Every user mails the own personal mailbox, singly or in quick series whose messages each draw their own content (333-399 such messages per 80 h in the six background captures, 46-64 of them 8 MB or more, with one to three attachments); each episode user|mailbox pair also had 4-22 background messages. Two large messages to the own mailbox within 40 minutes occur 3-7 times per 80 h, and three or more large messages from one sender within 40 minutes to other recipients 12-21 times. Three large messages to the own mailbox within 40 minutes are rare in background by construction of those series; the one that would occur keeps its time and size and goes to the user's other recipients instead, which happened at most twice per 80 h capture.

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
| `relay_hosts` | `exch-01`, `exch-02` (`10.20.10.11`, `.12`) | Internal Exchange hosts that relay outbound mail and receive inbound mail |
| `large_message_bytes` | `8000000` | Size threshold of the episode messages; background never has three such messages to the sender's own mailbox within 40 minutes |
| `max_message_bytes` | `20000000` | Largest message the listener accepts |
| `users` | 40 names | Local parts of internal users |
| `partner_domains` | 8 domains | Partner mail domains with their MX address and base reputation (SBRS) |
| `freemail_domains` | 3 domains | Public mailbox providers; each user has a personal address at one of them |
| `newsletter_senders` | 4 senders | Bulk senders marked as graymail |
| `contact_names` | 20 names | Local parts for partner and freemail contacts |
| `subjects` | 16 subjects | Message subjects |
| `attachment_names` | 16 names | Attachment names |

### Output Parameters

The shipped configuration writes `output/events.json` and needs no connection settings. To send events elsewhere, replace the `file` output in a local copy with the output plugin you need and reference its settings as `${params.<name>}` and `${secrets.<name>}`, for example `${params.opensearch_host}` and `${secrets.opensearch_password}`.

## Usage

```bash
# Batch: a finite window (add start/end to the cron input), as fast as possible
eventum generate --path generators/email-cisco-secure-email-gateway/generator.yml --id seg --live-mode false

# Live: real time, one-second resolution
eventum generate --path generators/email-cisco-secure-email-gateway/generator.yml --id seg --live-mode true
```

The episode needs at least one `anomaly_interval_hours` of source time; for a batch run set a window of two or more intervals.

## Sample Output

The `ready` line of the first episode message in the final `anomaly_mode: true` capture:

```json
{"@timestamp": "2026-09-02T00:18:01.000Z", "cisco_secure_email_gateway": {"log": {"category": {"name": "mail_logs"}, "host": "esa-01.contoso.example", "message": "MID 57270617 ready 8194749 bytes from \u003cg.mikhailova@contoso.example\u003e", "read_bytes": 8194749}}, "ecs": {"version": "8.17.0"}, "email": {"from": {"address": ["g.mikhailova@contoso.example"]}, "message_id": "57270617"}, "event": {"dataset": "cisco_secure_email_gateway.log", "kind": "event", "original": "\u003c166\u003eSep  2 00:18:01 esa-01.contoso.example mail_logs: Info: MID 57270617 ready 8194749 bytes from \u003cg.mikhailova@contoso.example\u003e", "timezone": "UTC"}, "log": {"level": "info", "syslog": {"priority": 166}}, "tags": ["preserve_original_event"]}
```

## Limitations

- No complete raw capture of an AsyncOS 16.x appliance was available. Line grammar follows the examples in the AsyncOS 16.5 Logging chapter (examples there carry old dates) and the Elastic integration's test fixtures; the `RELAY SG ... SBRS rfc1918` line follows Cisco TechNote 214631; the `REJECT SG BLOCKED_LIST` line applies the documented `ACCEPT SG` grammar to the default blocked sender group.
- Structured fields are what the Elastic integration 1.29.3 extracts. Its connection pattern matches only the `Management` interface, which is why the appliance uses one interface; sender-group, antivirus, attachment, quarantine and bounce lines keep only `email.message_id` or the message text, as the integration leaves them. Elastic agent fields (`agent.*`, `data_stream.*`, `input.type`) are omitted.
- Syslog timestamps have one-second resolution and no year; `@timestamp` is UTC with `.000` milliseconds, and the syslog priority is always `<166>` (local4.info), as in the integration fixtures.
- Each second emits at most four lines; lines queued in a busy second move to the next one.
- The background guard uses a window 10 s wider than the 40-minute chain window, so lines that a busy second pushes into the next one cannot complete a chain in background.
- Not covered: TLS, SMTP authentication, per-connection message reuse, delayed (soft-bounce) delivery, DLP, AMP, URL filtering, message filters, `Subject` with double quotes, and log levels other than `Info`.
- SPF, DKIM and DMARC pass for legitimate inbound senders and are not logged for spam senders.
- At short intervals (8 h and below) episodes add enough clusters of large messages that the rate of closely spaced large messages per sender rises measurably above a background-only run; at the default 24 h it does not.

## References

- [Cisco AsyncOS 16.5 for Secure Email Gateway, Logging](https://www.cisco.com/c/en/us/td/docs/security/esa/esa16-5/user_guide/b_ESA_Admin_Guide_16-5/b_ESA_Admin_Guide_12_1_chapter_0100111.html)
- [Cisco TechNote 214631: What does "SBRS rfc1918" in the mail logs mean](https://www.cisco.com/c/en/us/support/docs/security/email-security-appliance/214631-what-does-sbrs-rfc1918-in-the-mail-log.html)
- [Elastic integration: Cisco Secure Email Gateway](https://github.com/elastic/integrations/tree/main/packages/cisco_secure_email_gateway)

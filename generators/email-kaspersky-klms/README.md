# Kaspersky Security for Linux Mail Server CEF

Generates ECS JSON containing a synthetic KLMS ScanLogic CEF record in `event.original`. The profile uses the legacy Kaspersky Security 8 documentation and its illustrative `8.0MP2` header. The selected stream is [KLMS CEF over syslog](https://support.kaspersky.com/KLMS/8.2/en-US/151504.htm), separately identified from Kaspersky Secure Mail Gateway (KSMG): [KUMA's supported-source table](https://support.kaspersky.com/help/kuma/3.0.3/en-US/255782.htm) lists separate KLMS and KSMG CEF normalizers, so shared `LMS_EV_SCAN_LOGIC_*` IDs alone do not make the two product streams duplicates.

## Source Profile

MA and antivirus scanning are enabled for a single recipient and the `Default` rule. The selected policy [rejects each SPF, DKIM or DMARC violation](https://support.kaspersky.com/KLMS/8.2/en-US/98046.htm); clean engine results use `Skip`. The [processing model](https://support.kaspersky.com/KLMS/8.2/en-US/42881.htm) scans configured engines before applying rule actions. Consequently, an AV result can accompany an authentication failure. A clean AV result does not imply mail delivery.

Kaspersky exports ScanLogic events after message processing. This generator emits two records for every processed message: MA followed by AV. Both exports carry the same message ID, size, relay, sender, recipient and UTC processing timestamp with one-second resolution. The paired export selection, MA-first order and identical timestamp are explicit scenario assumptions. They are not confirmed native ordering or a claim that every KLMS installation exports exactly two records.

## Event Types

Shares are those of about a day of default output with `anomaly_mode: true` (they vary by a point or so from day to day); `false` output of the same window gives 38.9 / 11.1 / 49.6 / 0.4%.

| Native class | Result | Share | Category | Documented field meanings |
|---|---|---:|---|---|
| `LMS_EV_SCAN_LOGIC_MA_STATUS` | `ViolationNotFound` | 38.9% | `email` | SPF, DKIM and DMARC verdicts for a message |
| `LMS_EV_SCAN_LOGIC_MA_STATUS` | `ViolationFound` | 11.1% | `email` | At least one failing verdict; action `Reject` |
| `LMS_EV_SCAN_LOGIC_AV_STATUS` | `Clean` | 49.5% | `malware` | Antivirus result for that same message |
| `LMS_EV_SCAN_LOGIC_AV_STATUS` | `Infected` | 0.5% | `malware` | Infected result; action `Reject`, severity `High` |

The [ScanLogic key table](https://support.kaspersky.com/KLMS/8.2/en-US/151789.htm) defines permitted keys, not mandatory complete records. This profile emits message ID, received-from server IP, action, size, sender, one recipient, rule and status. MA additionally includes `SpfVerdict`, `DkimVerdict` and `DmarcVerdict`. Other optional ScanLogic fields and classes are outside this profile. Verdicts use the documented [authentication](https://support.kaspersky.com/KLMS/8.2/en-US/149345.htm) and [antivirus](https://support.kaspersky.com/KLMS/8.2/en-US/90878.htm) catalogs. The tuples are all-pass, all-fail, SPF-only failure and DKIM-only failure; a single failure with DMARC passing assumes the other mechanism passes with alignment. No alignment field is invented.

`act` is modeled as the selected engine's action, not a delivery outcome. Serialization of these action/status values into the exact MA/AV CEF remains an inference pending a capture. The outer ECS object joins native identities and preserves the raw body. It does not add an authenticated user, transport envelope, threat name or delivery verdict absent from this profile. CEF extension values escape equals signs, backslashes and line breaks, and header values escape pipes, according to the [CEF format rules](https://help.forcepoint.com/emailsec/en-us/on-prem/8.5.x/email_siem/guid-b4c8e212-b0d7-43f0-ba45-91013abf86ac.html).

## Traffic Model

The server scans about 13,400 messages per day (about 26,800 records); daily volume varies by about 3%. Ordinary senders follow a daily curve from 0.6 of their mean hourly rate at night to 1.4 of it around 13:00 UTC; spoofing senders are active at a flat rate round the clock. The busiest hour carries about 780 messages and the quietest about 345.

Senders come from `samples/senders.json`; each opens SMTP sessions at random moments with a share set by its `weight` within its population (ordinary or spoofing). A session delivers one or more messages; nothing runs on a fixed period or cooldown. Messages of one session follow each other within seconds: a bulk mailing reaches its recipients a median of 6 seconds apart (90% within 20 seconds), while a spoofing sender's messages are about half a minute apart.

| Sender kind | Senders | Share of messages | Session shape | Authentication and AV |
|---|---:|---:|---|---|
| `partner` | 24 | 53.0% | 1-4 messages, usually one recipient | Mostly pass; occasional SPF-only or DKIM-only failure; rare infection |
| `notify` | 5 | 17.7% | 1-3 messages | Pass or SPF-only failure |
| `bulk` | 5 | about 13% | 4-10 messages to distinct recipients | Pass, occasional single failure |
| `forwarder` | 3 | 9.6% | 1-4 messages | Forwarding breaks SPF, often DKIM and DMARC too |
| `spoof` | 6 | about 7% | 1-6 messages about half a minute apart, often to one high-value mailbox | Mostly all-fail; infection more likely after the first message |

Message sizes are log-normal per kind, and infected messages are larger. Ordinary traffic of both modes contains repeated all-fail messages from one spoofing sender to one high-value mailbox within minutes (154 same-flow pairs and 45 triples within 180 seconds per 28 hours of default `false` output) and infected all-fail messages that follow such a failure.

## Anomaly Chain

Both background and anomaly modes are supported. `anomaly_mode: true` is the default; `false` produces only background.

About every `anomaly_interval_hours` (6 hours by default), one spoofing sender from the `spoof` kind sends three messages through its relay to one high-value mailbox (`"episode": true` in `samples/recipients.json`):

1. Message 1: SPF, DKIM and DMARC `Fail`, MA `Reject`; AV `Clean`.
2. Message 2, about half a minute later: the same verdicts; AV `Clean`.
3. Message 3: the same verdicts; AV `Infected`, action `Reject`, severity `High`.

All three messages fall within 180 seconds (usually within about 90) and each produces an MA/AV pair joined by `cs1`/`email.local_id`. The sender is drawn with the same weights as spoofing traffic and the mailbox with the spoofing traffic's `lure_weight`; both differ from the previous episode's. Message IDs and sizes are new. A detection correlates relay, sender and recipient: at least two all-fail clean messages followed within 180 seconds by an all-fail message whose AV result is `Infected`. This models a spoofed-mail campaign that sends lures and then a malicious payload; everything is rejected, and no compromise or delivery is asserted.

Every element of the chain occurs in ordinary traffic of both modes: the same senders, relays and mailboxes, the all-fail tuple, infected results, repeated failures within minutes and infections after a failure. Ordinary traffic never completes the exact sequence: an ordinary all-fail message that would follow two all-fail clean messages of the same flow within 180 seconds is always scanned clean. The episode's messages are interleaved with the traffic (the total message count is the same in both modes); the episode sender's ordinary sessions and all other traffic continue as usual. No mode or episode marker is emitted.

Recurrence: spoofing traffic has no daily curve, so episode start times are uniform over the day. The first episode starts at a random moment within the first `anomaly_interval_hours` (at most 24 hours) of the data. Each next episode is due one interval after the actual start of the previous one and starts at a random moment within a window of a quarter of the interval (at most 6 hours) centred on that due time: with the default 6 hours, consecutive starts are 5 h 15 min to 6 h 45 min apart, and a 28-hour window holds four to six episodes. There is no catch-up: after a pause in live mode, one episode runs and the next is due one interval after its start. Intervals below 1 hour are raised to 1 hour.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Purpose |
|---|---|---|
| `anomaly_mode` | `true` | Periodic campaign enabled; `false` emits background only |
| `anomaly_interval_hours` | `6` | Hours from one actual episode start until the next episode is due; values below 1 are raised to 1 |
| `mail_host` | `mail-01.example.test` | Synthetic hostname with no whitespace or line breaks |
| `product_version` | `8.0MP2` | Illustrative vendor header value, not a verified live build |

### Samples

- `samples/senders.json`: `sender`, `relay` (IPv4 or IPv6), `kind` (`partner`, `bulk`, `notify`, `forwarder`, `spoof`) and `weight`, the sender's share of session starts within its population (spoofing or ordinary). Episodes need at least two `spoof` senders.
- `samples/recipients.json`: `mailbox`, `weight` (ordinary traffic), `lure_weight` (spoofing traffic) and `episode`. Episodes need at least two mailboxes with `"episode": true`.

Shipped `.test`/`.example` names and RFC 5737 addresses are synthetic. Mailboxes may contain `=` or `+`; CEF escaping handles them.

### Volume

The message rate and its daily curve are set in `patterns/`: `ordinary-floor.yml` and `ordinary-daytime.yml` for ordinary senders, `spoof.yml` for spoofing senders; `multiplier.ratio` is the number of messages started per day by each file.

### Output Parameters

The file output needs no credentials. Replace it with a SIEM output plugin and configure credentials there. A collector expecting native CEF must receive `event.original` instead of the outer JSON object.

## Usage

From the content-packs repository root, live mode:

```bash
eventum generate --path generators/email-kaspersky-klms/generator.yml --id klms --live-mode true
```

For a finite sample, set `oscillator.start` and `oscillator.end` in each of the three `patterns/*.yml` files to the same window, starting at midnight UTC so the daily curve keeps its hours, for example `start: "2026-09-25T00:00:00Z"` and `end: "2026-09-26T04:00:00Z"`, then run:

```bash
eventum generate --path generators/email-kaspersky-klms/generator.yml --id klms-batch --live-mode false
```

Records go to `generators/email-kaspersky-klms/output/events.json`. Native timestamps assume server timezone UTC.

Performance: about 2,700 records per CPU second; a 14-day default window (375,224 records) took 141 CPU seconds.

## Sample Output

This synthetic event is copied from default `true` output: the infected third message of an episode, at 07:00:23, 39 seconds after message 1 at 06:59:44. Its MA record has the same ID and three `Fail` verdicts. It is not a vendor capture:

```json
{"@timestamp": "2026-09-25T07:00:23+00:00", "ecs": {"version": "8.17.0"}, "email": {"from": {"address": ["ceo.office@examp1e.test"]}, "local_id": "adf1b964db344ebc", "to": {"address": ["accounting@example.test"]}}, "event": {"action": "reject", "category": ["malware"], "code": "LMS_EV_SCAN_LOGIC_AV_STATUS", "dataset": "kaspersky.klms", "kind": "event", "original": "September 25, 2026 07:00:23 mail-01.example.test CEF:0|AO Kaspersky Lab|Kaspersky Linux Mail Security|8.0MP2|LMS_EV_SCAN_LOGIC_AV_STATUS|antivirus scan status|High|cs1=adf1b964db344ebc cs1Label=MessageId src=192.0.2.199 act=Reject fsize=72259 suser=ceo.office@examp1e.test duser=accounting@example.test cs2=Default cs2Label=Rules outcome=Infected", "type": ["info"]}, "kaspersky": {"klms": {"class_id": "LMS_EV_SCAN_LOGIC_AV_STATUS"}}, "observer": {"hostname": "mail-01.example.test", "product": "Kaspersky Linux Mail Security", "vendor": "Kaspersky", "version": "8.0MP2"}, "source": {"ip": "192.0.2.199"}}
```

## Limitations

- Rates, session shapes, verdict weights and sizes are synthetic model choices, not measured vendor traffic.
- Messages of one SMTP session are several seconds apart (see Traffic Model) rather than the sub-second spacing a fast sender can reach; about 8% of consecutive messages share one second.
- With `anomaly_mode: true` each episode adds its own three messages, so counts of all-fail messages from a spoofing sender to a high-value mailbox, and of infected results after such failures, are about three and one per episode higher than in background.
- Kaspersky's [complete CEF example](https://support.kaspersky.com/KLMS/8.2/en-US/151684.htm) is a Settings event; no complete MA or AV ScanLogic record was found in the vendor documentation. Exact MA/AV event names, severities, raw `act`/`outcome` vocabulary, `cs1` lexical form, product build, pair order and timestamps, and syslog framing are therefore inferred. The full-month prefix and vendor/product/version strings follow the illustrative Settings example. No PRI or unsupported transport detail is invented.

## References

- [Publishing program events to a SIEM system](https://support.kaspersky.com/KLMS/8.2/en-US/151504.htm)
- [Values of fields in the body of CEF messages for classes of ScanLogic group events](https://support.kaspersky.com/KLMS/8.2/en-US/151789.htm)
- [Content and properties of syslog messages in CEF format](https://support.kaspersky.com/KLMS/8.2/en-US/151684.htm)
- [About Mail Sender Authentication statuses](https://support.kaspersky.com/KLMS/8.2/en-US/149345.htm) and [About Anti-Virus scan statuses](https://support.kaspersky.com/KLMS/8.2/en-US/90878.htm)
- [Email processing algorithm](https://support.kaspersky.com/KLMS/8.2/en-US/42881.htm) and [Configuring actions on messages during DMARC, SPF and DKIM message authentication](https://support.kaspersky.com/KLMS/8.2/en-US/98046.htm)
- [KUMA supported event sources](https://support.kaspersky.com/help/kuma/3.0.3/en-US/255782.htm)
- No Elastic integration sample was available for KLMS; the ECS mapping is inferred.

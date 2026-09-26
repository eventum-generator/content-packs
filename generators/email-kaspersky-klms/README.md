# Kaspersky Security for Linux Mail Server CEF

Generates ECS JSON containing a synthetic KLMS ScanLogic CEF record in `event.original`. The profile uses the legacy Kaspersky Security 8 documentation and its illustrative `8.0MP2` header. The selected stream is [KLMS CEF over syslog](https://support.kaspersky.com/KLMS/8.2/en-US/151504.htm), separately identified from Kaspersky Secure Mail Gateway (KSMG). Complete native ScanLogic capture fidelity remains unverified.

## Source Profile

MA and antivirus scanning are enabled for a single recipient and the `Default` rule. The selected policy [rejects each SPF, DKIM or DMARC violation](https://support.kaspersky.com/KLMS/8.2/en-US/98046.htm); clean engine results use `Skip`. The [processing model](https://support.kaspersky.com/KLMS/8.2/en-US/42881.htm) scans configured engines before applying rule actions. Consequently, an AV result can accompany an authentication failure. A clean AV result does not imply mail delivery.

Kaspersky exports ScanLogic events after message processing. This generator emits two records for every processed message: MA followed by AV. Both exports carry the same message ID, size, relay, sender, recipient and UTC processing timestamp with one-second resolution. The paired export selection, MA-first order and identical timestamp are explicit scenario assumptions. They are not confirmed native ordering or a claim that every KLMS installation exports exactly two records.

## Event Types

Shares are measured on the final 28-hour default capture with `anomaly_mode: true` (4,912 records); the `false` capture of the same window gives 32.9 / 17.1 / 48.8 / 1.2%.

| Native class | Result | Share | Category | Documented field meanings |
|---|---|---:|---|---|
| `LMS_EV_SCAN_LOGIC_MA_STATUS` | `ViolationNotFound` | 32.7% | `email` | SPF, DKIM and DMARC verdicts for a message |
| `LMS_EV_SCAN_LOGIC_MA_STATUS` | `ViolationFound` | 17.3% | `email` | At least one failing verdict; action `Reject` |
| `LMS_EV_SCAN_LOGIC_AV_STATUS` | `Clean` | 48.6% | `malware` | Antivirus result for that same message |
| `LMS_EV_SCAN_LOGIC_AV_STATUS` | `Infected` | 1.4% | `malware` | Infected result; action `Reject`, severity `High` |

The [ScanLogic key table](https://support.kaspersky.com/KLMS/8.2/en-US/151789.htm) defines permitted keys, not mandatory complete records. This profile emits message ID, received-from server IP, action, size, sender, one recipient, rule and status. MA additionally includes `SpfVerdict`, `DkimVerdict` and `DmarcVerdict`. Other optional ScanLogic fields and classes are outside this profile. Verdicts use the documented [authentication](https://support.kaspersky.com/KLMS/8.2/en-US/149345.htm) and [antivirus](https://support.kaspersky.com/KLMS/8.2/en-US/90878.htm) catalogs. The tuples are all-pass, all-fail, SPF-only failure and DKIM-only failure; a single failure with DMARC passing assumes the other mechanism passes with alignment. No alignment field is invented.

`act` is modeled as the selected engine's action, not a delivery outcome. Serialization of these action/status values into the exact MA/AV CEF remains an inference pending a capture. The outer ECS object joins native identities and preserves the raw body. It does not add an authenticated user, transport envelope, threat name or delivery verdict absent from this profile. CEF extension values escape equals signs, backslashes and line breaks, and header values escape pipes, according to the [CEF format rules](https://help.forcepoint.com/emailsec/en-us/on-prem/8.5.x/email_siem/guid-b4c8e212-b0d7-43f0-ba45-91013abf86ac.html).

## Traffic Model

Every sender in `samples/senders.json` starts SMTP sessions as an independent random (Poisson) process at its own `sessions_per_day` rate. Human-driven senders follow a daily curve peaking at 13:00 UTC (0.6x to 1.4x of the mean); spoofing senders do not. A session delivers one or more messages; nothing runs on a fixed period, rotation or script, and no sender has a cooldown or minimum spacing.

| Sender kind | Senders | Share of messages | Session shape | Authentication and AV |
|---|---:|---:|---|---|
| `partner` | 14 | 45.2% | 1-4 messages seconds apart, usually one recipient | Mostly pass; occasional SPF-only or DKIM-only failure; rare infection |
| `spoof` | 6 | 22.4% | 1-6 messages about half a minute apart, often to one high-value mailbox | Mostly all-fail; infection more likely after the first message |
| `notify` | 3 | 13.4% | 1-3 messages seconds apart | Pass or SPF-only failure |
| `bulk` | 3 | 10.5% | 4-10 messages to distinct recipients | Pass, occasional single failure |
| `forwarder` | 2 | 8.5% | 1-4 messages seconds apart | Forwarding breaks SPF, often DKIM and DMARC too |

Shares are from the default `true` capture. Message sizes are log-normal per kind, and infected messages are larger. The default samples produce about 2,000-2,300 messages (4,100-4,500 records) per day. Consequently, ordinary traffic of both modes contains repeated all-fail messages from one spoofing sender to one recipient within minutes (124-152 same-flow pairs and 35-50 triples within 180 seconds per 28 hours in the default captures) and infected all-fail messages that follow such a failure (14-25 per 28 hours).

## Anomaly Chain

Both background and anomaly modes are supported. `anomaly_mode: true` is the default; `false` produces only background.

About every `anomaly_interval_hours` (6 hours by default), one spoofing sender from the `spoof` kind sends three messages through its relay to one high-value mailbox (`"episode": true` in `samples/recipients.json`):

1. Message 1: SPF, DKIM and DMARC `Fail`, MA `Reject`; AV `Clean`.
2. Message 2, about half a minute later: the same verdicts; AV `Clean`.
3. Message 3: the same verdicts; AV `Infected`, action `Reject`, severity `High`.

All three messages fall within 180 seconds and each produces an MA/AV pair joined by `cs1`/`email.local_id`. Each episode picks a sender and a mailbox that both differ from the previous episode; message IDs and sizes are new. A detection correlates relay, sender and recipient: at least two all-fail clean messages followed within 180 seconds by an all-fail message whose AV result is `Infected`. This models a spoofed-mail campaign that sends lures and then a malicious payload; everything is rejected, and no compromise or delivery is asserted.

Every element of the chain occurs in ordinary traffic of both modes: the same senders, relays and mailboxes, the all-fail tuple, infected results, repeated failures within minutes and infections after a failure. Ordinary traffic only never completes the exact sequence: an ordinary infected all-fail message that would follow two all-fail clean messages of the same flow within 180 seconds is exported as clean. Episodes do not pause, delay or reschedule any ordinary sender. No mode or episode marker is emitted.

The first episode falls due one interval after the first input timestamp and starts after a random delay of 1 to 30 minutes. Each next episode falls due one interval after the actual start of the previous one and again starts 1 to 30 minutes later, so consecutive starts are 6 h 01 min to 6 h 30 min apart by default and episode clock times drift later: a 28-hour run holds four episodes. There is no catch-up: after a pause in live mode, one episode runs and the next is due one interval after its start. Intervals below 1 hour are raised to 1 hour. A finite run ending inside an episode can omit its remaining messages; every emitted message still has both records.

State is bounded: one queue of scheduled messages (sessions last minutes), one pending MA/AV pair, a next-session time per sender, the last 180 seconds of history per sender-recipient flow, the next episode due time and the previous episode's sender and mailbox. Completed message IDs are not retained.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Purpose |
|---|---|---|
| `anomaly_mode` | `true` | Periodic campaign enabled; `false` emits background only |
| `anomaly_interval_hours` | `6` | Hours from one actual episode start until the next episode is due (a random 60-1800 s start delay follows); lower values than 1 are raised to 1 |
| `mail_host` | `mail-01.example.test` | Synthetic hostname with no whitespace or line breaks |
| `product_version` | `8.0MP2` | Illustrative vendor header value, not a verified live build |

### Samples

- `samples/senders.json`: `sender`, `relay` (IPv4 or IPv6), `kind` (`partner`, `bulk`, `notify`, `forwarder`, `spoof`) and `sessions_per_day`. Episodes need at least two `spoof` senders.
- `samples/recipients.json`: `mailbox`, `weight` (ordinary traffic), `lure_weight` (spoofing traffic) and `episode`. Episodes need at least two mailboxes with `"episode": true`.

Shipped `.test`/`.example` names and RFC 5737 addresses are synthetic. Mailboxes may contain `=` or `+`; CEF escaping handles them.

Keep `input[0].cron` at `expression: '* * * * * *'` and `count: 2`: the template exports an MA record on the first timestamp of a second and the AV record of the same message on the second.

### Output Parameters

The file output needs no credentials. Replace it with a SIEM output plugin and configure credentials there. A collector expecting native CEF must receive `event.original` instead of the outer JSON object.

## Usage

From the content-packs repository root, live mode:

```bash
eventum generate --path generators/email-kaspersky-klms/generator.yml --id klms --live-mode true --keep-order true
```

For a finite sample, add a window to the input in `generator.yml`:

```yaml
input:
  - cron:
      expression: '* * * * * *'
      count: 2
      start: '2026-09-25T00:00:00+00:00'
      end: '2026-09-26T04:00:00+00:00'
```

Then run:

```bash
eventum generate --path generators/email-kaspersky-klms/generator.yml --id klms-batch --live-mode false --keep-order true
```

This 28-hour window with default parameters wrote 4,762-5,268 records in eight runs, with four complete episodes in each of the two `true` runs. Records go to `generators/email-kaspersky-klms/output/events.json`. Native timestamps assume server timezone UTC; the generator normalizes input timestamps to UTC.

## Sample Output

This synthetic event is copied from the final default `true` run: the infected third message of the first episode, at 06:16:41, 85 seconds after message 1, which started 15 min 16 s after the episode fell due. Its MA record has the same ID and three `Fail` verdicts. It is not a vendor capture:

```json
{
  "@timestamp": "2026-09-25T06:16:41+00:00",
  "ecs": {
    "version": "8.17.0"
  },
  "email": {
    "from": {
      "address": [
        "billing@invoice-example.test"
      ]
    },
    "local_id": "6cf13957a6ca015e",
    "to": {
      "address": [
        "finance@example.test"
      ]
    }
  },
  "event": {
    "action": "reject",
    "category": [
      "malware"
    ],
    "code": "LMS_EV_SCAN_LOGIC_AV_STATUS",
    "dataset": "kaspersky.klms",
    "kind": "event",
    "original": "September 25, 2026 06:16:41 mail-01.example.test CEF:0|AO Kaspersky Lab|Kaspersky Linux Mail Security|8.0MP2|LMS_EV_SCAN_LOGIC_AV_STATUS|antivirus scan status|High|cs1=6cf13957a6ca015e cs1Label=MessageId src=198.51.100.74 act=Reject fsize=166247 suser=billing@invoice-example.test duser=finance@example.test cs2=Default cs2Label=Rules outcome=Infected",
    "type": [
      "info"
    ]
  },
  "kaspersky": {
    "klms": {
      "class_id": "LMS_EV_SCAN_LOGIC_AV_STATUS"
    }
  },
  "observer": {
    "hostname": "mail-01.example.test",
    "product": "Kaspersky Linux Mail Security",
    "vendor": "Kaspersky",
    "version": "8.0MP2"
  },
  "source": {
    "ip": "198.51.100.74"
  }
}
```

## Validation and Limits

Final finite runs: eight default 28-hour runs (two with `anomaly_mode: true`, 4 episodes each, and six background runs), a custom pair over 14 hours with a 3-hour interval, a different host, a product version containing `|`, mailboxes with `=` and `+` and an IPv6 relay (4 episodes / 0), and a 1-hour interval stress run over 12 hours (9 episodes). The streaming verifier checked CEF escaping and key sets, native-to-ECS identities, verdict/action/severity consistency, MA/AV pair continuity, UTC order, episode recurrence (due one interval after the previous actual start, started 1-30 minutes later, none missing), sender and mailbox rotation, and that every chain constituent occurs in ordinary traffic. Mode comparisons of volume, sender and recipient mix, verdict and infection shares, gap distributions including their minimum and low quantiles, and same-flow failure bursts found no difference between the modes beyond run-to-run variation; the same gates pass between all background runs.

Known limits:

- Rates, session shapes, verdict weights and sizes are synthetic model choices, not measured vendor traffic. Throughput is at most one message per second.
- Kaspersky's [complete CEF example](https://support.kaspersky.com/KLMS/8.2/en-US/151684.htm) is a Settings event. No complete MA/AV ScanLogic record was found in the bounded source search. Exact MA/AV event names, severities, raw `act`/`outcome` vocabulary, `cs1` lexical form, product build, pair ordering/timestamps and syslog framing remain **BLOCKED_RAW_EVIDENCE**. The full-month prefix and vendor/product/version strings follow the illustrative Settings example. No PRI or unsupported transport detail is invented.
- [KUMA's supported-source table](https://support.kaspersky.com/help/kuma/3.0.3/en-US/255782.htm) identifies separate KLMS and KSMG CEF normalizers. Shared `LMS_EV_SCAN_LOGIC_*` IDs alone do not make the two product streams duplicates.

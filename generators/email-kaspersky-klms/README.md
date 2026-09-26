# Kaspersky Security for Linux Mail Server CEF

Generates ECS JSON containing a synthetic KLMS ScanLogic CEF record in `event.original`. The profile uses the legacy Kaspersky Security 8 documentation and its illustrative `8.0MP2` header. The selected stream is [KLMS CEF over syslog](https://support.kaspersky.com/KLMS/8.2/en-US/151504.htm), separately identified from Kaspersky Secure Mail Gateway (KSMG). Complete native ScanLogic capture fidelity remains unverified.

## Source Profile

MA and antivirus scanning are enabled for a single recipient and the `Default` rule. The selected policy [rejects each SPF, DKIM or DMARC violation](https://support.kaspersky.com/KLMS/8.2/en-US/98046.htm); clean engine results use `Skip`. The [processing model](https://support.kaspersky.com/KLMS/8.2/en-US/42881.htm) scans configured engines before applying rule actions. Consequently, an AV result can accompany an authentication failure. A clean AV result does not imply mail delivery.

Kaspersky exports ScanLogic events after message processing. This generator emits two records per minute for one processed message: MA followed by AV. Both exports carry the same message ID, size, relay, sender, recipient and UTC processing timestamp. The paired export selection, MA-first order and identical timestamp are explicit scenario assumptions. They are not confirmed native ordering or a claim that every KLMS installation exports exactly two records. The minute cadence models 60 processed messages and 120 records per hour, rather than engine processing time.

## Event Types

| Native class | Selected results | Documented field meanings |
|---|---|---|
| `LMS_EV_SCAN_LOGIC_MA_STATUS` | `ViolationNotFound` or `ViolationFound` | SPF, DKIM and DMARC verdicts for a message |
| `LMS_EV_SCAN_LOGIC_AV_STATUS` | `Clean` or `Infected` | Antivirus result for that same message |

The [ScanLogic key table](https://support.kaspersky.com/KLMS/8.2/en-US/151789.htm) defines permitted keys, not mandatory complete records. This profile emits message ID, received-from server IP, action, size, sender, one recipient, rule and status. MA additionally includes `SpfVerdict`, `DkimVerdict` and `DmarcVerdict`. Other optional ScanLogic fields and classes are outside this profile. Verdicts use the documented [authentication](https://support.kaspersky.com/KLMS/8.2/en-US/149345.htm) and [antivirus](https://support.kaspersky.com/KLMS/8.2/en-US/90878.htm) catalogs. Partial SPF/DKIM failures with DMARC passing assume the other authentication mechanism passes with alignment. No alignment field is invented.

`act` is modeled as the selected engine's action, not a delivery outcome. Serialization of these action/status values into the exact MA/AV CEF remains an inference pending a capture. The outer ECS object joins native identities and preserves the raw body. It does not add an authenticated user, transport envelope, threat name or delivery verdict absent from this profile. CEF extension values escape equals signs, backslashes and line breaks according to the [CEF format rules](https://help.forcepoint.com/emailsec/en-us/on-prem/8.5.x/email_siem/guid-b4c8e212-b0d7-43f0-ba45-91013abf86ac.html).

## Anomaly Chain

Both background and anomaly modes are supported. `anomaly_mode: true` is the default. Every `anomaly_interval_hours` (6 hours by default), one sender and relay send three distinct messages to the same recipient on consecutive minute ticks. Each message has failing SPF, DKIM and DMARC. The first two have clean AV results; the third is infected. The episode contains six exports across two minutes. All three message IDs and their sizes are newly generated for each episode. Sender, recipient and relay are configurable persistent identities, rather than unique anomaly markers.

Correlate three authentication failures on relay, sender and recipient within minutes, then join the third message's infected AV result by `cs1`/`email.local_id`. This models a rejected spoofed-mail campaign with a malicious third payload. It does not assert compromise or delivery.

Both modes contain the same four relay/sender actors, four recipients, actions, authentication tuples and clean/infected AV statuses. Routine target failures are spread by at least 20 minutes and include isolated failed-MA/infected-AV pairs. Other actors also have occasional authentication failures and infected messages. `anomaly_mode: false` removes the rapid campaign; every constituent event still occurs in ordinary traffic. No mode or episode marker is emitted.

State is bounded: one pending MA/AV message, at most four actor failure clocks, a three-step episode cursor, a four-value routine cursor and two scheduler clocks. Completed message IDs are not retained. A finite run ending during an episode can omit its remaining messages; every minute still emits a complete MA/AV pair.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Purpose |
|---|---|---|
| `anomaly_mode` | `true` | Periodic campaign enabled; `false` emits background only |
| `anomaly_interval_hours` | `6` | Hours between episode starts; minimum 1, lower values clamp to 1 |
| `mail_host` | `mail-01.example.test` | Synthetic hostname with no whitespace or line breaks |
| `product_version` | `8.0MP2` | Illustrative vendor header value, not a verified live build |
| `unusual_sender` | `billing@invoice-example.test` | Valid sender mailbox used in both modes |
| `target_recipient` | `finance@example.test` | Valid recipient mailbox used in both modes |
| `unusual_relay_ip` | `198.51.100.74` | Valid received-from server IP used in both modes |

Fractional intervals start on the first minute tick at or after their due time. Each new due time is measured from the actual episode start. A custom 3-hour interval was tested with different host, sender, recipient and relay, including valid mailbox `=` characters. Addresses should distinguish the target identity from the three fixed ordinary actors and recipients. Shipped `.test` names and RFC 5737 addresses are synthetic. Keep `input[0].cron.count: 2` to preserve complete paired exports.

### Output Parameters

The file output needs no credentials. Replace it with a SIEM output plugin and configure credentials there. A collector expecting native CEF must receive `event.original` instead of the outer JSON object.

## Usage

From the content-packs repository root:

```bash
flock -x /tmp/eventum-generator-heavy.lock uv run --project ../eventum eventum generate --path generators/email-kaspersky-klms/generator.yml --id klms --live-mode true --keep-order true
```

For a finite 12-hour-and-15-minute sample containing two complete default episodes, create a config beside the original to preserve relative template paths:

```bash
uv run --project ../eventum python - <<'PYCONFIG'
from pathlib import Path
import yaml
root = Path('generators/email-kaspersky-klms')
config = yaml.safe_load((root / 'generator.yml').read_text())
config['input'][0]['cron'].update(
    start='2026-09-25T00:00:00+00:00',
    end='2026-09-25T12:15:00+00:00',
)
(root / '.finite.yml').write_text(yaml.safe_dump(config, sort_keys=False))
PYCONFIG
flock -x /tmp/eventum-generator-heavy.lock uv run --project ../eventum eventum generate --path generators/email-kaspersky-klms/.finite.yml --id klms-finite --live-mode false --keep-order true
rm generators/email-kaspersky-klms/.finite.yml
```

The finite command exits normally and writes 1,472 records to `generators/email-kaspersky-klms/output/events.json`. Native timestamps assume server timezone UTC. The generator normalizes input timestamps to UTC even when the CLI uses another timezone. The sixth cron field is seconds, so `* * * * * 0` runs once per minute.

## Sample Output

This synthetic event is copied exactly from the final default-on generator run, third message of the first episode. Its paired AV record has the same ID and an infected result. It is not a vendor capture:

```json
{
  "@timestamp": "2026-09-25T06:02:00+00:00",
  "ecs": {
    "version": "8.17.0"
  },
  "email": {
    "from": {
      "address": [
        "billing@invoice-example.test"
      ]
    },
    "local_id": "ff6c31cabc7ab0e8",
    "to": {
      "address": [
        "finance@example.test"
      ]
    }
  },
  "event": {
    "action": "reject",
    "category": [
      "email"
    ],
    "code": "LMS_EV_SCAN_LOGIC_MA_STATUS",
    "dataset": "kaspersky.klms",
    "kind": "event",
    "original": "September 25, 2026 06:02:00 mail-01.example.test CEF:0|AO Kaspersky Lab|Kaspersky Linux Mail Security|8.0MP2|LMS_EV_SCAN_LOGIC_MA_STATUS|mail authentication status|Low|cs1=ff6c31cabc7ab0e8 cs1Label=MessageId src=198.51.100.74 act=Reject fsize=1958 suser=billing@invoice-example.test duser=finance@example.test cs2=Default cs2Label=Rules cs4=Fail cs4Label=SpfVerdict cs5=Fail cs5Label=DkimVerdict cs6=Fail cs6Label=DmarcVerdict outcome=ViolationFound",
    "type": [
      "info"
    ]
  },
  "kaspersky": {
    "klms": {
      "class_id": "LMS_EV_SCAN_LOGIC_MA_STATUS",
      "dkim": "Fail",
      "dmarc": "Fail",
      "spf": "Fail"
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

## Validation and Raw Evidence Limit

Four finite runs covered 78 hours 15 minutes each, with default 6-hour and custom 3-hour intervals in both modes. Each produced 9,392 records and 4,696 complete message pairs. Observed complete episodes were 13/0 and 26/0. The streaming verifier checked CEF escaping and permitted keys, native-to-ECS identities, verdict/action consistency within this profile, pair continuity, minute cadence, UTC, recurring distinct message IDs and ordinary constituent signatures. An actual original capture with `=` in mailbox addresses failed CEF parsing; the corrected custom runs pass.

Kaspersky's [complete CEF example](https://support.kaspersky.com/KLMS/8.2/en-US/151684.htm) is a Settings event. No complete MA/AV ScanLogic record was found in the bounded source search. Exact MA/AV event names, severities, raw `act`/`outcome` vocabulary, `cs1` lexical form, product build, pair ordering/timestamps and syslog framing remain **BLOCKED_RAW_EVIDENCE**. The full-month prefix and vendor/product/version strings follow the illustrative Settings example. No new PRI or unsupported transport detail is invented. Semantic checks do not certify full native parity.

[KUMA's supported-source table](https://support.kaspersky.com/help/kuma/3.0.3/en-US/255782.htm) identifies separate KLMS and KSMG CEF normalizers. Shared `LMS_EV_SCAN_LOGIC_*` IDs alone do not make the two product streams duplicates. This work updates the existing KLMS pack and does not create another mail-security source.

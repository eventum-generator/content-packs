# Kaspersky Security for Linux Mail Server CEF

Generates ECS JSON with a KLMS ScanLogic syslog/CEF record in `event.original`. The selected stream is the [KLMS syslog CEF export](https://support.kaspersky.com/KLMS/8.2/en-US/151504.htm), not the Kaspersky Secure Mail Gateway (KSMG), KATA, or Web Traffic Security streams.

## Event Types

| Native class | Routine behavior | Meaning |
|---|---|---|
| `LMS_EV_SCAN_LOGIC_MA_STATUS` | Most records; `ViolationNotFound` or `ViolationFound` | SPF, DKIM and DMARC scan for a message |
| `LMS_EV_SCAN_LOGIC_AV_STATUS` | About one tenth of records; `Clean` or `Infected` | Antivirus scan for the preceding message |

These are generator choices, not measured KLMS traffic rates. The raw fields and per-class permitted key lists follow [KLMS 8.2 ScanLogic documentation](https://support.kaspersky.com/KLMS/8.2/en-US/151789.htm). The status values come from the KLMS [mail authentication](https://support.kaspersky.com/KLMS/8.2/en-US/149345.htm) and [antivirus](https://support.kaspersky.com/KLMS/8.2/en-US/90878.htm) catalogs. `Skip` and `Reject` are configurable [message actions](https://support.kaspersky.com/KLMS/8.2/en-US/61193.htm).

## Anomaly Chain

`anomaly_mode: true` is the default. After 120 routine records, one four-record sequence on consecutive minute ticks contains three mail-authentication failures from `billing@invoice-example.test`, received from relay `198.51.100.74` for `finance@example.test`. The third message then has an `Infected` antivirus record. That AV record carries the same native `cs1` message ID, sender, recipient, relay address and `fsize` as the third authentication record. Correlate the three failures on relay, sender and recipient within four minutes, then join the AV result on message ID.

The same sender, recipient and relay have authentication failures at 20-minute gaps in both modes. A separate message has an authentication failure and an infected AV result on adjacent ticks in both modes. Other routine messages also produce clean or infected AV results. No individual event marks the chain. `anomaly_mode: false` omits only the short four-record sequence. The generator models a rejected spoofed-mail attempt with a malicious payload; it does not imply delivery to the mailbox.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Purpose |
|---|---|---|
| `anomaly_mode` | `true` | Include one short chain; `false` emits background only |
| `mail_host` | `mail-01.example.test` | Synthetic syslog host |
| `product_version` | `8.0MP2` | CEF header value shown in Kaspersky's illustrative header |
| `unusual_sender` | `billing@invoice-example.test` | Sender used in both modes |
| `target_recipient` | `finance@example.test` | Recipient used in both modes |
| `unusual_relay_ip` | `198.51.100.74` | SMTP relay address used in both modes |

### Output Parameters

The shipped file output needs no credentials. Replace it with a SIEM output plugin and configure its endpoint and credentials there. A collector expecting native syslog/CEF must receive `event.original` rather than the outer JSON object.

## Usage

Run from the content-packs repository root:

```bash
eventum generate --path generators/email-kaspersky-klms/generator.yml --id klms --live-mode false --keep-order true
eventum generate --path generators/email-kaspersky-klms/generator.yml --id klms --live-mode true --keep-order true
```

Batch mode generates continuously until interrupted. Live mode emits one record per minute; the sixth cron field is seconds. The output file is `generators/email-kaspersky-klms/output/events.json`.

## Sample Output

This complete event is copied from a real anomaly-mode run:

```json
{
  "@timestamp": "2026-09-25T19:36:00+00:00",
  "ecs": {
    "version": "8.17.0"
  },
  "email": {
    "from": {
      "address": [
        "billing@invoice-example.test"
      ]
    },
    "local_id": "1b35d85e77327677",
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
    "original": "September 25, 2026 19:36:00 mail-01.example.test CEF:0|AO Kaspersky Lab|Kaspersky Linux Mail Security|8.0MP2|LMS_EV_SCAN_LOGIC_MA_STATUS|mail authentication status|Low|cs1=1b35d85e77327677 cs1Label=MessageId src=198.51.100.74 act=Reject fsize=15913 suser=billing@invoice-example.test duser=finance@example.test cs2=Default cs2Label=Rules cs4=Fail cs4Label=SpfVerdict cs5=Fail cs5Label=DkimVerdict cs6=Fail cs6Label=DmarcVerdict outcome=ViolationFound",
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

## Source and Validation Limit

Kaspersky's [CEF format page](https://support.kaspersky.com/KLMS/8.2/en-US/151684.htm) provides a complete `LMS_EV_SETTINGS_CHANGED` example with `CEF:0`, vendor/product strings and `8.0MP2`. Its [ScanLogic page](https://support.kaspersky.com/KLMS/8.2/en-US/151789.htm) lists applicable keys for MA and AV classes but publishes no complete native ScanLogic record. Consequently, the exact ScanLogic CEF name, severity, `act`/`outcome` serialization, `cs1` ID format and syslog-prefix form cannot be certified without a KLMS capture. The generated values follow the documented field meanings and status/action catalogs, but full raw fidelity remains unverified. This is a versioned illustrative CEF stream, not a validated appliance fixture.

Kaspersky's [KUMA supported-source table](https://support.kaspersky.com/help/kuma/3.0.3/en-US/255782.htm) lists distinct KLMS and KSMG syslog/CEF normalizers, as well as separate KATA and KWTS sources. The native class IDs overlap KSMG, but the product and stream identities differ. No KLMS-specific Elastic integration fixture is used; the outer ECS fields are a synthetic SIEM-friendly projection.

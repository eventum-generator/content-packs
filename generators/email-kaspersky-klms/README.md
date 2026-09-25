# Kaspersky Linux Mail Security CEF

KLMS ScanLogic mail authentication and antivirus CEF records, distinct from Kaspersky Secure Mail Gateway. The generator writes ECS JSON with the native CEF record in `event.original`.

## Event types

| Event code | Meaning | Approximate frequency | ECS category |
| --- | --- | --- | --- |
| `LMS_EV_SCAN_LOGIC_MA_STATUS` | SPF/DKIM/DMARC scan | ~99% in anomaly mode | email |
| `LMS_EV_SCAN_LOGIC_AV_STATUS` | Antivirus scan | ~1% in anomaly mode | malware |

Frequencies are synthetic scenario weights, not measured production rates.

## Anomaly Chain

After about 80 routine mail-authentication records, three messages from 198.51.100.74 to finance@example.test fail SPF, DKIM and DMARC. The third message has a subsequent antivirus-status record with the same `email.local_id` and native `cs1` value. Correlate sender, recipient and relay IP, then join the final two records on message ID. This supports a spoofed-mail campaign with a malicious payload detection.

`anomaly_mode: true` is the default and mixes this chain into ordinary traffic. Set it to `false` for background records only. Correlate by `@timestamp` because output-line order can differ under concurrent generation.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`.

| Name | Default | Purpose |
| --- | --- | --- |
| `anomaly_mode` | `true` | Enable spoofed-mail chain. |
| `anomaly_interval_events` | `80` | Routine records between chains. |
| `mail_host` | `mail-01.example.test` | KLMS syslog hostname. |
| `product_version` | `8.0MP2` | CEF version shown in Kaspersky example. |
| `unusual_sender` | `billing@invoice-example.test` | Chain sender. |
| `target_recipient` | `finance@example.test` | Chain mailbox. |
| `unusual_relay_ip` | `198.51.100.74` | Chain relay. |

### Output Parameters

The shipped file output works without overrides. To send records elsewhere, replace `output.file` with the desired output plugin and use top-level `params`/`secrets` substitutions for destination and credentials. No top-level placeholders are required by this pack.

## Usage

From the content-packs repository:

```bash
eventum generate --path generators/email-kaspersky-klms/generator.yml --id kaspersky-klms --live-mode false
eventum generate --path generators/email-kaspersky-klms/generator.yml --id kaspersky-klms --live-mode true
```

The file output is `generators/email-kaspersky-klms/output/events.json`. Extract `event.original` when a collector requires raw CEF rather than ECS JSON.

## Sample output

Copied from an actual Eventum anomaly-mode run:

```json
{
  "@timestamp": "2026-09-25T13:04:17+00:00",
  "ecs": {
    "version": "8.17.0"
  },
  "email": {
    "from": {
      "address": [
        "billing@invoice-example.test"
      ]
    },
    "local_id": "synthetic-klms-1-1",
    "to": {
      "address": [
        "finance@example.test"
      ]
    }
  },
  "event": {
    "action": "scanned",
    "category": [
      "email"
    ],
    "code": "LMS_EV_SCAN_LOGIC_MA_STATUS",
    "dataset": "kaspersky.klms",
    "kind": "event",
    "original": "Sep 25 13:04:17 mail-01.example.test KLMS: CEF:0|AO Kaspersky Lab|Kaspersky Linux Mail Security|8.0MP2|LMS_EV_SCAN_LOGIC_MA_STATUS|mail authentication status|Low|cs1=synthetic-klms-1-1 cs1Label=MessageId src=198.51.100.74 act=scanned fsize=40192 suser=billing@invoice-example.test duser=finance@example.test cs2=mail-authentication cs2Label=Rules reason=authentication-failed cs4=fail cs4Label=SpfVerdict cs5=fail cs5Label=DkimVerdict cs6=fail cs6Label=DmarcVerdict outcome=Failed",
    "type": [
      "info"
    ]
  },
  "kaspersky": {
    "klms": {
      "class_id": "LMS_EV_SCAN_LOGIC_MA_STATUS",
      "dkim": "fail",
      "dmarc": "fail",
      "spf": "fail"
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

## Scope and validation

17/17 selected documented CEF fields are represented across the MA_STATUS and AV_STATUS records. Other ScanLogic classes and administrative event groups are out of scope. Both modes were generated and parsed; a time-sorted complete chain was found in anomaly mode and no chain records appeared in background mode.

This is KLMS, not the existing KSMG generator; the products have separate KUMA normalizers. The CEF header uses the 8.0MP2 version from the vendor example and the ScanLogic fields documented in KLMS 8.2 help. Exact action/status vocabulary and compatibility with every KLMS release were not verified against a live appliance. KESL is not covered by this pack.

## References

- [KLMS 8.2 CEF message structure](https://support.kaspersky.com/KLMS/8.2/en-US/151684.htm)
- [KLMS 8.2 ScanLogic fields](https://support.kaspersky.com/KLMS/8.2/en-US/151789.htm)
- [KUMA 4.2 supported sources](https://support.kaspersky.ru/kuma/4.2/255782)

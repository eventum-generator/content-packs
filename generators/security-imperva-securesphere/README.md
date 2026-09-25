# Imperva SecureSphere 8.5 CEF security alerts

Eventum content pack for the SecureSphere CEF security-event action-set template documented for versions 6.2–8.5. The generator pins `device_version` to `8.5`. Each output is ECS JSON with the native CEF body in `event.original`. `anomaly_mode: true` is the default; `false` emits background only.

## Run

From the content-packs repository root:

```bash
eventum generate --path generators/security-imperva-securesphere/generator.yml --id security-imperva-securesphere --live-mode true
```

For a bounded batch, run `timeout 3s eventum generate --path generators/security-imperva-securesphere/generator.yml --id security-imperva-securesphere-batch --live-mode false`. Exit code 124 is expected for this continuous source. Output is written to `generators/security-imperva-securesphere/output/events.json`.

## Events

| CEF class ID | Meaning | Background frequency | ECS category |
| --- | --- | --- | --- |
| `signature` | Signature security alert | About 70% | `intrusion_detection`, `web` |
| `protocol` | Protocol security alert | About 20% | `intrusion_detection`, `web` |
| `profile` | Profile security alert | About 10% | `intrusion_detection`, `web` |
| `correlation` | Correlated security alert | Chain only | `intrusion_detection`, `web` |

These weights and the chain interval are synthetic workload settings, not measured Imperva rates. The primary CEF guide lists the five possible alert types (`firewall`, `signature`, `protocol`, `profile`, `correlation`) and the complete security-event extension template. This pack covers four types in a WAF-like security-alert stream, with all 19 extension keys from that template. Alert names, policy names, and descriptions are synthetic examples of configurable metadata, not a vendor signature catalog. `act=None` and `act=Block` represent the guide's no-action and block-transaction outcomes.

The complete CEF template is documented only for SecureSphere 6.2–8.5; this pack does not claim field-level compatibility with current Imperva releases. KUMA 4.2 lists SecureSphere under the generic Syslog-CEF normalizer. Forward `event.original` via syslog for parser testing because the shipped file is an ECS JSON envelope.

## Anomaly Chain

The same client, `10.43.9.77`, triggers a low-severity signature alert, a medium-severity protocol alert, then a high-severity correlation alert blocked by SecureSphere, all against `10.43.20.15:443`. Correlate `source.ip`, `destination.ip`, `imperva.securesphere.class_id`, CEF `act`, and `@timestamp` to detect escalation across security alert types. These are simulated alert outcomes, not proof that a real attack reached the application. Sort by `@timestamp`; file-line order is not guaranteed under concurrent generation.

`anomaly_mode: false` keeps routine signature, protocol, and profile alerts, but never emits the chain client or correlation step.

## Parameters

### Event Parameters

| Parameter | Default | Meaning |
| --- | --- | --- |
| `device_name` | `securesphere-mx-01.example.test` | ECS device host |
| `device_version` | `8.5` | Pinned documented CEF profile |
| `anomaly_mode` | `true` | Include the three-event chain; `false` emits background only |
| `anomaly_interval_events` | `80` | Routine pairs between chain injections |
| `chain_source_ip` | `10.43.9.77` | Stable chain client |
| `protected_server_ip` | `10.43.20.15` | Protected server |

### Output Parameters

No top-level `${params.*}` or `${secrets.*}` placeholders are shipped. File output works without credentials. Replace the `output` block and configure the selected plugin to forward to a SIEM.

## Sample output

This complete anomaly event was captured with `anomaly_mode: true`:

```json
{
  "@timestamp": "2026-09-25T13:59:20+00:00",
  "destination": {
    "ip": "10.43.20.15",
    "port": 443
  },
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "no-action",
    "category": [
      "intrusion_detection",
      "web"
    ],
    "code": "signature",
    "dataset": "imperva_securesphere.cef",
    "kind": "alert",
    "original": "CEF:0|Imperva Inc.|SecureSphere|8.5|signature|Signature violation|Low|act=None dst=10.43.20.15 dpt=443 duser=anonymous src=10.43.9.77 spt=53430 proto=TCP rt=Sep 25 2026 13:59:20 cat=Alert cs1=SignaturePolicy cs1Label=Policy cs2=PortalGroup cs2Label=ServerGroup cs3=HTTPS cs3Label=ServiceName cs4=CustomerPortal cs4Label=ApplicationName cs5=SignatureMatch cs5Label=Description",
    "type": [
      "info"
    ]
  },
  "host": {
    "name": "securesphere-mx-01.example.test"
  },
  "imperva": {
    "securesphere": {
      "class_id": "signature",
      "device_version": "8.5",
      "extension": {
        "act": "None",
        "cat": "Alert",
        "cs1": "SignaturePolicy",
        "cs1Label": "Policy",
        "cs2": "PortalGroup",
        "cs2Label": "ServerGroup",
        "cs3": "HTTPS",
        "cs3Label": "ServiceName",
        "cs4": "CustomerPortal",
        "cs4Label": "ApplicationName",
        "cs5": "SignatureMatch",
        "cs5Label": "Description",
        "dpt": 443,
        "dst": "10.43.20.15",
        "duser": "anonymous",
        "proto": "TCP",
        "rt": "Sep 25 2026 13:59:20",
        "spt": 53430,
        "src": "10.43.9.77"
      },
      "name": "Signature violation",
      "product": "SecureSphere",
      "severity": "Low",
      "vendor": "Imperva Inc.",
      "version": 0
    }
  },
  "network": {
    "transport": "tcp"
  },
  "related": {
    "ip": [
      "10.43.9.77",
      "10.43.20.15"
    ]
  },
  "source": {
    "ip": "10.43.9.77",
    "port": 53430
  }
}
```

## References

- [Imperva SecureSphere CEF Certification Guide: versions 6.2–8.5, event types and full template](https://www.imperva.com/docs/sb_imperva_securesphere_cef_guide.pdf)
- [Imperva SecureSphere v14 standard placeholders](https://docs-be.imperva.com/bundle/v14.x-standard-placeholders/raw/resource/enus/v14.x-standard-placeholders.pdf)
- [KUMA 4.2 supported event sources](https://support.kaspersky.ru/kuma/4.2/255782)

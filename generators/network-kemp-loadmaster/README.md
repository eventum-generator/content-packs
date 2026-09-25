# Progress Kemp LoadMaster ESP CEF

Eventum content pack for LoadMaster ESP CEF events. Each output is ECS JSON with the vendor CEF body in `event.original`. `anomaly_mode: true` is the default; `false` emits background only.

## Run

From the content-packs repository root:

```bash
eventum generate --path generators/network-kemp-loadmaster/generator.yml --id network-kemp-loadmaster --live-mode true
```

For a bounded batch, run `timeout 3s eventum generate --path generators/network-kemp-loadmaster/generator.yml --id network-kemp-loadmaster-batch --live-mode false`. Exit code 124 is expected for this continuous source. Output is written to `generators/network-kemp-loadmaster/output/events.json`.

## Events

| CEF class ID | Meaning | Background frequency | ECS category |
| --- | --- | --- | --- |
| `9` | ESP Access Denied | About 10% | `web` |
| `8` | ESP Logged on | About 5% | `authentication` |
| `14` | ESP Request | About 85% | `web` |

Those weights and the chain interval are synthetic workload settings, not measured LoadMaster rates. The source is the L7 ESP CEF profile published by Progress Kemp. Header version `1.0` follows the vendor's CEF examples; it is not a claim about appliance firmware. This pack omits WAF, SMTP, connection, and SSOMGR codes. The shipped file is ECS JSON, so forward `event.original` via syslog to test KUMA's generic CEF parser.

## Anomaly Chain

Three `Access Denied` events for `operator@example.test` from `10.42.9.77` precede a `Logged on` event and an ESP `Request` for `/admin`. All five events share the same user, source IP, and virtual service `10.42.20.15:443`. Correlate `user.name`, `source.ip`, `kemp.loadmaster.extension.vs`, CEF class ID, and `@timestamp` to detect access denials followed by login and sensitive-path access. The logs show service behavior; they do not establish that the user was compromised. Sort by `@timestamp`; file-line order is not guaranteed under concurrent generation.

`anomaly_mode: false` keeps routine denials, logons, and requests but never emits the chain user or source.

## Parameters

### Event Parameters

| Parameter | Default | Meaning |
| --- | --- | --- |
| `device_name` | `loadmaster-01.example.test` | ECS device host |
| `virtual_ip` | `10.42.20.15` | ESP virtual service address |
| `anomaly_mode` | `true` | Include the five-event chain; `false` emits background only |
| `anomaly_interval_events` | `80` | Routine pairs between chain injections |
| `chain_source_ip` | `10.42.9.77` | Stable chain client |
| `chain_user` | `operator@example.test` | Stable chain user |

### Output Parameters

No top-level `${params.*}` or `${secrets.*}` placeholders are shipped. File output works without credentials. Replace the `output` block and configure the selected plugin to forward to a SIEM.

## Sample output

This complete anomaly event was captured with `anomaly_mode: true`:

```json
{
  "@timestamp": "2026-09-25T13:59:06+00:00",
  "destination": {
    "ip": "10.42.20.15",
    "port": 443
  },
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "access-denied",
    "category": [
      "web"
    ],
    "code": "9",
    "dataset": "kemp_loadmaster.esp",
    "kind": "event",
    "original": "CEF:0|Kemp|LM|1.0|9|Access Denied|6|vs=10.42.20.15:443 event=Access Denied srcip=10.42.9.77 user=operator@example.test msg=denied access",
    "type": [
      "denied"
    ]
  },
  "host": {
    "name": "loadmaster-01.example.test"
  },
  "kemp": {
    "loadmaster": {
      "class_id": 9,
      "device_version": "1.0",
      "extension": {
        "event": "Access Denied",
        "msg": "denied access",
        "srcip": "10.42.9.77",
        "user": "operator@example.test",
        "vs": "10.42.20.15:443"
      },
      "name": "Access Denied",
      "product": "LM",
      "severity": 6,
      "vendor": "Kemp",
      "version": 0
    }
  },
  "related": {
    "ip": [
      "10.42.9.77",
      "10.42.20.15"
    ],
    "user": [
      "operator@example.test"
    ]
  },
  "source": {
    "ip": "10.42.9.77"
  },
  "user": {
    "name": "operator@example.test"
  }
}
```

## References

- [Progress Kemp LoadMaster CEF extension and event classes](https://docs.progress.com/bundle/loadmaster-technical-note-common-event-format-cef-logs-ga/page/CEF-Extension.html)
- [Progress Kemp ESP user logs and CEF setup](https://docs.progress.com/bundle/loadmaster-technical-note-esp-logs-ltsf/page/User-Logs.html)
- [KUMA 4.2 supported event sources](https://support.kaspersky.ru/kuma/4.2/255782)

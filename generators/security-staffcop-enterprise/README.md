# Staffcop Enterprise syslog

Synthetic Staffcop Enterprise 5.8 Syslog connector events in the vendor-documented native key-value format. This pack models screenshot and statistics events with policy matches. It does not emit Staffcop CEF.

## Event types

| Native event | Approximate share with anomaly mode | ECS category | Meaning |
| --- | ---: | --- | --- |
| `Screenshot` | 91.7% | `host` | Endpoint screenshot event, optionally matching a policy |
| `Stat` | 8.3% | `host` | Statistics event with two matching policies in routine activity or the chain |

The template uses FSM mode and emits one event per five simulated minutes from twelve ordinary endpoints and a thirteenth endpoint that also has benign activity. The syslog header represents the connector's forwarding time, three minutes after the `time` field and ECS `@timestamp`. The vendor documents roughly five-minute forwarding. With anomaly mode disabled, the stream contains routine `Screenshot` and `Stat` events. About one in five routine screenshots has one policy match, while occasional routine `Stat` events from other employees have two. These proportions are synthetic scenario choices.

## Anomaly Chain

With `anomaly_mode: true` (the default), `ivan` on `WS-023` produces two `Screenshot` events without policy matches, then a screenshot matching `Скриншоты`, then a `Stat` event matching both `Скриншоты` and `Финансовые данные`. The four events share the user, computer, IP, and application and span 15 simulated minutes. A detection can group by `user.name` and `host.name`, sort by `@timestamp`, and alert on the screenshot series ending with two policy matches. The file's row order is not a reliable clock. The same actor also emits isolated benign screenshots in both modes. With `anomaly_mode: false`, routine `Stat` records with two policies and the actor’s benign screenshots remain, but their four-step sequence does not occur.

The policies are illustrative names. A `Stat` event with two matches does not prove that earlier screenshots caused it, and policy count is not a severity scale. The sequence gives rule authors correlated events without claiming causality not present in the source.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Purpose |
| --- | --- | --- |
| `anomaly_mode` | `true` | Include the four-step linked sequence; `false` produces background only |
| `syslog_host` | `staffcop-srv` | Host in the syslog header |
| `routine_endpoint_count` | `12` | Number of distinct background user/endpoint pairs |
| `suspect_user` | `ivan` | Account in the anomaly chain |
| `suspect_computer` | `WS-023` | Endpoint in the anomaly chain |
| `suspect_ip` | `10.20.4.23` | Endpoint address in the anomaly chain |
| `application` | `chrome` | Application in native `app` |
| `policy_screenshot` | `Скриншоты` | First policy match |
| `policy_sensitive` | `Финансовые данные` | Second policy match in the `Stat` step |

### Output Parameters

No top-level `${params.*}` or `${secrets.*}` are required. Output defaults to `output/events.json`; edit the file output section to deliver elsewhere.

## Usage

From the content-packs repository:

```bash
eventum generate --path generators/security-staffcop-enterprise/generator.yml --id staffcop --live-mode false
```

For continuous generation, use `--live-mode true`. Set `event.template.params.anomaly_mode` to `false` for background only. The file output is overwritten when a run starts.

## Sample output

This JSON event was copied from an anomaly-mode run, not handwritten:

```json
{
  "@timestamp": "2026-09-25T17:47:00+00:00",
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "Stat",
    "category": [
      "host"
    ],
    "id": "468036",
    "kind": "event",
    "original": "Sep 25 17:50:00 staffcop-srv staffcop: id=\"468036\" time=\"Sep 25 17:47:00\" event=\"Stat\" computer=\"WS-023\" ip=\"10.20.4.23\" user=\"ivan\" app=\"chrome\" policy_1=\"\u0421\u043a\u0440\u0438\u043d\u0448\u043e\u0442\u044b\" policy_2=\"\u0424\u0438\u043d\u0430\u043d\u0441\u043e\u0432\u044b\u0435 \u0434\u0430\u043d\u043d\u044b\u0435\"",
    "type": [
      "info"
    ]
  },
  "host": {
    "ip": [
      "10.20.4.23"
    ],
    "name": "WS-023"
  },
  "observer": {
    "name": "staffcop-srv"
  },
  "process": {
    "name": "chrome"
  },
  "related": {
    "hosts": [
      "WS-023"
    ],
    "ip": [
      "10.20.4.23"
    ],
    "user": [
      "ivan"
    ]
  },
  "staffcop": {
    "event_time": "2026-09-25T17:47:00+00:00",
    "forwarded_at": "2026-09-25T17:50:00+00:00",
    "policy_matches": [
      "\u0421\u043a\u0440\u0438\u043d\u0448\u043e\u0442\u044b",
      "\u0424\u0438\u043d\u0430\u043d\u0441\u043e\u0432\u044b\u0435 \u0434\u0430\u043d\u043d\u044b\u0435"
    ]
  },
  "user": {
    "name": "ivan"
  }
}
```

## Format and coverage

`event.original` follows the complete Staffcop 5.8 native Syslog connector example: syslog time/host/program and all nine named fields (`id`, `time`, `event`, `computer`, `ip`, `user`, `app`, `policy_1`, `policy_2`). The two policy fields are omitted when no policy matches. This covers 9/9 fields in the vendor's two-policy example. Values are synthetic, not a captured Staffcop line. The connector must be enabled and configured to forward the selected events; otherwise, no such stream is produced.

KUMA 4.2 lists a Staffcop Enterprise normalizer for versions 5.4/5.5 using CEF over syslog. This pack is pinned to Staffcop 5.8's native key-value format, so compatibility with that CEF normalizer is not claimed. It also does not model all Staffcop event classes or the optional CEF export mode.

## References

- [KUMA 4.2 supported sources](https://support.kaspersky.ru/kuma/4.2/255782)
- [Staffcop Enterprise 5.8 Syslog connector, native samples and CEF option](https://docs.staffcop.ru/1ver/integrations/syslog_connector.html)
- [Staffcop Enterprise 5.8 multiple-policy Syslog change](https://docs.staffcop.ru/changelog.html)

# Kerio Control Filter Log

Kerio Control URL-rule allow and deny records in the Filter log format documented by GFI. Eventum writes ECS JSON and preserves the raw Filter log line in `event.original`.

## Event types

| Action | Meaning | Approximate background frequency | ECS category |
| --- | --- | --- | --- |
| `ALLOW URL` | URL rule allows an HTTP request | 85% | web |
| `DENY URL` | URL rule blocks an HTTP request | 15% | web |

Weights are synthetic scenario choices, not measured production frequencies.

## Anomaly Chain

After 60 routine records, one authenticated user at one client IP tries four distinct paths on the same blocked host: `/`, `/admin`, `/config`, and `/backup`. All four requests are denied by the same URL rule. Correlate by client IP, user, host, and time window; a rule can detect rapid enumeration of blocked paths.

`anomaly_mode: true` is the default and mixes this sequence with background. Set it to `false` for background only. Sort by `@timestamp` when checking the sequence; concurrent output may reorder lines.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`.

| Name | Default | Purpose |
| --- | --- | --- |
| `anomaly_mode` | `true` | Enable blocked-path enumeration. |
| `anomaly_interval_events` | `60` | Routine records between chains. |
| `firewall_host` | `kerio-fw-01.example.test` | Firewall name in ECS. |
| `target_user` | `analyst` | Chain user. |
| `target_client_ip` | `192.0.2.45` | Chain client IP. |
| `target_domain` | `blocked.example.test` | Blocked host. |

### Output Parameters

The shipped file output needs no overrides. Replace `output.file` with another output plugin and use top-level `${params.*}` or `${secrets.*}` substitutions for destination settings when needed.

## Usage

From the content-packs repository:

```bash
eventum generate --path generators/network-kerio-control/generator.yml --id kerio-control --live-mode false
eventum generate --path generators/network-kerio-control/generator.yml --id kerio-control --live-mode true
```

Output: `generators/network-kerio-control/output/events.json`. Extract `event.original` for a collector that accepts Filter log lines.

## Sample output

Copied from an actual anomaly-mode run:

```json
{
  "@timestamp": "2026-09-25T13:29:44+00:00",
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "DENY",
    "category": [
      "web"
    ],
    "dataset": "kerio.control_filter",
    "kind": "event",
    "original": "[25/Sep/2026 13:29:44] DENY URL 'Restricted Sites' 192.0.2.45 analyst HTTP GET http://blocked.example.test/",
    "type": [
      "access"
    ]
  },
  "host": {
    "name": "kerio-fw-01.example.test"
  },
  "http": {
    "request": {
      "method": "GET"
    }
  },
  "kerio": {
    "control": {
      "filter_action": "DENY",
      "filter_rule": "Restricted Sites"
    }
  },
  "related": {
    "ip": [
      "192.0.2.45"
    ],
    "user": [
      "analyst"
    ]
  },
  "source": {
    "ip": "192.0.2.45"
  },
  "url": {
    "full": "http://blocked.example.test/"
  },
  "user": {
    "name": "analyst"
  }
}
```

## Scope and validation

The selected URL-rule format covers 8/8 documented fields: time, action, rule type, rule name, client IP, user, HTTP method, and URL. Packet-rule logs and the configurable packet template are outside this pack. Both modes were generated, parsed, and checked for the complete time-sorted chain or its absence.

The GFI page gives an `ALLOW URL` raw example and explicitly defines `DENY` as the other URL-rule action. This pack uses the same documented line layout for both. KUMA 4.2 lists a Kerio Control normalizer, but exact parser compatibility with this Filter log subset is not verified.

## References

- [GFI Kerio Control Filter log format and examples](https://manuals.gfi.com/en/kerio/control/content/logs/using-the-filter-log-1454.html)
- [KUMA 4.2 supported sources](https://support.kaspersky.ru/kuma/4.2/255782)

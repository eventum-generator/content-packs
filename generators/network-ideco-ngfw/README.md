# Ideco NGFW Novum Syslog Generator

Produces ECS JSON events with native Ideco NGFW Novum Syslog messages in `event.original`. It models the documented `traffic-journal` and `fail2ban` services; the parsed keys remain under `ideco.ngfw`.

## Event Types

| Native service and action | Routine frequency | Category |
|---|---:|---|
| `traffic-journal` `accept` | 85% | Network |
| `traffic-journal` `drop` | 15% | Network |
| `fail2ban` `Found` | Chain only | Intrusion detection |
| `fail2ban` `Ban` | Chain only | Intrusion detection |

Routine weights are synthetic defaults, not measured production rates. A five-event anomaly chain follows every 220 routine events when enabled.

## Anomaly Chain

The `utm-web-interface` jail reports three `Found` events for `198.51.100.25`, then a `Ban`. A `traffic-journal` `drop` for the same source follows on the NGFW INPUT table and HTTPS port. A detector can correlate the repeated findings, ban, and later denied connection by source IP, device, jail, and time. The post-ban traffic event is a modeled scenario; the vendor documentation does not guarantee that every ban produces a separate traffic-journal record. Correlate by `@timestamp` because delivery order in the generated file can differ from event-time order.

`anomaly_mode` defaults to `true`. Set it to `false` for only ordinary accepted and denied traffic events.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Purpose |
|---|---|---|
| `anomaly_mode` | `true` | Include or omit the chain |
| `anomaly_interval_events` | `220` | Routine events between chains |
| `ngfw_host` | `ideco-ngfw-01` | NGFW hostname in Syslog |
| `ngfw_ip` | `10.50.0.1` | NGFW management IP |
| `ordinary_source_ip` | `10.50.1.20` | Routine traffic source |
| `unusual_source_ip` | `198.51.100.25` | Correlated chain source |
| `ordinary_destination_ip` | `198.51.100.10` | Routine traffic destination |
| `fail2ban_jail` | `utm-web-interface` | Documented web-interface jail |

### Output Parameters

The shipped configuration writes `output/events.json` and needs no output parameters or secrets. Replace the `output` block to deliver elsewhere, using that plugin's `${params.*}` and `${secrets.*}` placeholders for endpoint settings and credentials.

## Usage

From the content-packs repository root:

```bash
eventum generate --path generators/network-ideco-ngfw/generator.yml --id ideco-ngfw --live-mode false
eventum generate --path generators/network-ideco-ngfw/generator.yml --id ideco-ngfw --live-mode true
```

Batch mode runs continuously until interrupted. Live mode emits one record per second.

## Sample Output

This complete event was copied from a generator run:

```json
{"@timestamp": "2026-09-25T12:11:28+00:00", "ecs": {"version": "8.17.0"}, "event": {"action": "fail2ban_ban", "category": ["intrusion_detection"], "dataset": "ideco.ngfw_syslog", "kind": "event", "original": "2026-09-25T12:11:28+00:00 ideco-ngfw-01 fail2ban - - - NOTICE [utm-web-interface] Ban 198.51.100.25", "outcome": "success", "type": ["denied"]}, "ideco": {"ngfw": {"action": "Ban", "jail": "utm-web-interface", "service": "fail2ban", "src_ip": "198.51.100.25"}}, "message": "NOTICE [utm-web-interface] Ban 198.51.100.25", "observer": {"hostname": "ideco-ngfw-01", "ip": "10.50.0.1", "product": "NGFW Novum", "vendor": "Ideco"}, "source": {"ip": "198.51.100.25"}}
```

## Source and Scope

The [Ideco NGFW Novum v22 Syslog guide](https://docs.ideco.ru/pdf/v22/ru-ngfw-settings-services-syslog.pdf) documents the `traffic-journal` message prefix, `result`, `rule_id`, `table`, `action`, protocol and endpoint fields, plus the `fail2ban` `Found`/`Ban` forms and jail names. This generator chooses the documented Syslog transport, not CEF. It covers all 10 selected traffic fields and the four selected fail2ban fields. IPS, DPI, NAT, WAF, DNS, and administrator-audit messages are outside this scoped pack.

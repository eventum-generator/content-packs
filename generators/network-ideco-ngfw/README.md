# Ideco NGFW Novum Syslog Generator

Generates synthetic Ideco NGFW Novum Syslog messages in `event.original` inside an ECS JSON envelope. This pack models the `traffic-journal` and `fail2ban` services in the [v22 Syslog guide](https://docs.ideco.ru/pdf/v22/ru-ngfw-settings-services-syslog.pdf), using the displayed Syslog payload format rather than CEF.

## Event Types

| Native service and action | Background share | Meaning |
|---|---:|---|
| `traffic-journal` `accept` | ~74% | Allowed connection |
| `traffic-journal` `drop` | ~19% | Denied connection |
| `fail2ban` `Found` | ~6% | Jail finding |
| `fail2ban` `Ban` | ~1% | IP ban |

Shares are synthetic workload settings, not measured device rates. Background `fail2ban` findings are spread over about 70 seconds per source before a ban. Traffic varies by source, destination, port, INPUT/FORWARD table, rule and security-profile action. Each traffic record has a distinct `flow_id`, as required by the vendor field catalog.

## Anomaly Chain

The default `utm-vpn-authd` jail records six `Found` messages for `198.51.100.25` on consecutive seconds, then `NOTICE [...] Ban` for the same IP. The first `Found` is a normal routine record; five more and the ban form a one-shot FSM chain. Background uses the same jail, `Found` and `Ban` actions, and the target IP appears in traffic. Its other bans follow slower findings for different IPs. A detector can flag six findings followed by a ban for one source and jail in a short window.

The model uses a 45-minute hold after the target ban and stops emitting its traffic during that interval. [Ideco's v21 fail2ban guidance](https://docs.ideco.ru/pdf/v21/ru-ngfw-settings-server-management-additionally.pdf) describes six failed password attempts within 15 minutes and a 45-minute block. The v22 guide shows `Found` and `Ban` syntax but does not confirm that threshold or hold time for each jail. These timings are scenario assumptions, not assertions about every v22 installation.

`anomaly_mode` defaults to `true`. Set it to `false` for background only. The chain occurs once after at least `anomaly_after_events` routine records, including its first finding. It waits for a non-fail2ban background slot so ordinary six-finding sequences retain their own records. Background-only mode can include one isolated `Found` for the target IP, but never its rapid sequence or target `Ban`.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Purpose |
|---|---|---|
| `anomaly_mode` | `true` | Include the one-shot rapid-findings chain |
| `anomaly_after_events` | `220` | Minimum routine-record count before the target's first `Found` |
| `ngfw_host` | `ideco-ngfw-01` | Hostname in the displayed Syslog record |
| `ngfw_ip` | `10.50.0.1` | NGFW observer IP and INPUT destination |
| `internal_source_ip` | `10.50.1.20` | One ordinary LAN source |
| `target_source_ip` | `198.51.100.25` | Source in the rapid-findings chain and ordinary traffic |
| `external_destination_ip` | `198.51.100.10` | One ordinary WAN destination |
| `fail2ban_jail` | `utm-vpn-authd` | Jail; the v22 guide also lists `utm-web-interface` |

The fixed synthetic rule IDs, zones, and profile names are examples of one deployment, not vendor defaults.

### Output Parameters

The shipped configuration writes `output/events.json` and needs no endpoint parameters or secrets. To send events elsewhere, replace the `output` block with the desired plugin and its `${params.*}` and `${secrets.*}` placeholders.

## Usage

From the content-packs repository root, set `input[0].cron.start` and `input[0].cron.end` for a finite batch run. For example, `2026-09-25T00:00:00+03:00` and `2026-09-25T00:06:00+03:00` produce 361 records and the default chain.

```bash
uv run --project ../eventum eventum generate --path generators/network-ideco-ngfw/generator.yml --id ideco-ngfw --live-mode false
```

For a continuous stream, leave `end` unset and use live mode:

```bash
uv run --project ../eventum eventum generate --path generators/network-ideco-ngfw/generator.yml --id ideco-ngfw --live-mode true
```

## Sample Output

This synthetic event was copied from a finite generator run. It is not a vendor-captured record.

```json
{"@timestamp": "2026-09-24T21:03:39+00:00", "ecs": {"version": "8.17.0"}, "event": {"action": "fail2ban_found", "category": ["intrusion_detection"], "dataset": "ideco.ngfw_syslog", "kind": "event", "original": "2026-09-24T21:03:39+00:00 ideco-ngfw-01 fail2ban - - - INFO [utm-vpn-authd] Found 198.51.100.25 - 2026-09-24 21:03:39", "type": ["info"]}, "ideco": {"ngfw": {"fields": {"action": "Found", "found_at": "2026-09-24 21:03:39", "jail": "utm-vpn-authd", "src_ip": "198.51.100.25"}, "service": "fail2ban"}}, "message": "INFO [utm-vpn-authd] Found 198.51.100.25 - 2026-09-24 21:03:39", "observer": {"hostname": "ideco-ngfw-01", "ip": "10.50.0.1", "product": "NGFW Novum", "vendor": "Ideco"}, "related": {"ip": ["198.51.100.25"]}, "source": {"ip": "198.51.100.25"}}
```

`event.original` is the displayed Syslog message shape without network framing; the output file itself contains ECS JSON. To ingest native Syslog messages, extract `event.original`. Syslog can be sent over TCP or UDP according to the vendor guide; this pack does not model wire framing, priority metadata or collector delivery.

## Source and Scope

The [Ideco v22 Syslog guide](https://docs.ideco.ru/pdf/v22/ru-ngfw-settings-services-syslog.pdf) shows a complete `fail2ban INFO [utm-vpn-authd] Found IP - timestamp` record, the `NOTICE [jail] Ban IP` body format and its jail list. Its `traffic-journal` field dictionary defines `result`, `rule_id`, `table`, `action`, source/destination fields and unique `flow_id`. The generator emits 19 selected traffic fields out of 39 documented keys, including empty IPS/DPI properties when no inspection occurs. It does not claim coverage of optional NAT, identity, location, cluster or VCE properties.

**BLOCKED_RAW_EVIDENCE:** the displayed `traffic-journal` example in the official PDF is visibly truncated after the beginning of `ips_profile`; a complete first-party raw traffic line was not available. The generated traffic body follows the published field names and documented value meanings, but its complete field set and serialization cannot be confirmed against a vendor capture. The v22 guide shows a full Syslog envelope for `Found`, only a body example for `Ban`, and no full `utm-web-interface` raw line. Those variants follow the displayed service envelope and body grammar and remain unverified at full-line level.

The pack is separate from other vendors' NGFW generators. It does not cover Ideco WAF, DNS, IPS alerts, administrator audit, web proxy or CEF streams.

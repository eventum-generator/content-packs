# Yandex 360 Audit Log Generator

Produces one native enriched event object per line from the Yandex 360 organization audit-log API. It models identity and Disk activity; it does not model a paginated API response or Mail audit logs.

## Event Types

| Native `event.type` | Baseline weight | Category |
|---|---:|---|
| `disk_fs-view` | 36% | File access |
| `id_cookie.set` | 32% | Authentication |
| `disk_fs-get-download-url` | 18% | Download |
| `disk_fs-store` | 10% | File write |
| `disk_fs-set-private` | 4% | Sharing change |
| `disk_fs-set-public` | Chain only | Sharing change |

These are synthetic weights, not measured production rates. The FSM emits one four-event chain after every 80 routine events when `anomaly_mode` is enabled.

## Anomaly Chain

A successful `id_cookie.set` for `admin@corp.example` arrives from `198.51.100.42`, outside the ordinary internal address pool. The same `event.uid` and `event.ip` then view `disk:/finance/payroll-2026.xlsx`, create a public link with `public_rights.macros: all`, and request a download URL for that file. The order and fixed file path make it possible to detect unusual login followed by external sharing and download in a short window. Join on `event.org_id`, `event.uid`, `event.ip`, and `event.meta.tgt_rawaddress`; independent `request_id` and `idempotency_id` values identify individual API events, not the whole session.

Set `anomaly_mode: false` for background only. This removes the unusual login and the correlated file-access and sharing sequence. It does not suppress ordinary downloads or ordinary private-link changes.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Purpose |
|---|---|---|
| `anomaly_mode` | `true` | Include the correlated chain; `false` emits only background |
| `org_id` | `1234567` | Synthetic organization ID |
| `organization_domain` | `corp.example` | Synthetic login domain |
| `suspicious_ip` | `198.51.100.42` | Unusual login and file-action address |
| `compromised_login` | `admin@corp.example` | Chain actor |
| `compromised_uid` | `1130000000123456` | Stable chain actor ID |
| `sensitive_path` | `disk:/finance/payroll-2026.xlsx` | File used in the chain |

### Output Parameters

The shipped configuration writes to `output/events.json` and needs no output parameters or secrets. To send events to a SIEM, replace the `file` output with the required output plugin and configure its endpoint and credentials there.

## Usage

Run from the content-packs repository root:

```bash
eventum generate --path generators/cloud-yandex-360-audit/generator.yml --id yandex-360 --live-mode false
eventum generate --path generators/cloud-yandex-360-audit/generator.yml --id yandex-360 --live-mode true
```

The first command generates as fast as possible until interrupted. Live mode emits one event per second.

## Sample Output

This complete event was copied from the generated `output/events.json`:

```json
{
  "event": {
    "idempotency_id": "d5ca0c5b-8567-4ca3-9494-f58b15d67bf5",
    "ip": "10.20.7.32",
    "is_system": false,
    "meta": {
      "device_id": null,
      "revision": "1"
    },
    "occurred_at": "2026-09-25T11:59:58+00:00",
    "org_id": 1234567,
    "request_id": "693e6f3a-a302-441f-95c3-3d55e563e3a0",
    "service": "ID",
    "status": "Success",
    "type": "id_cookie.set",
    "uid": 1130000000100005
  },
  "user_login": "marina@corp.example",
  "user_name": "marina"
}
```

## Source and Scope

The [Yandex 360 audit API](https://yandex.ru/dev/api360/doc/ru/audit-logs/get-logs) defines the `enrichedEvent`/`auditlogEvent` fields and each included event type. Disk `meta` keys follow its documented per-type parameter list. The endpoint requires an audit-capable tariff and `ya360_security:read_auditlog`. Its `items` and `iteration_key` pagination envelope is omitted because each generated line represents one item ready for SIEM ingestion. Mail audit logs use a separate method and are outside this generator.

Coverage: 13/13 selected required envelope fields from the vendor's `enrichedEvent` and `auditlogEvent` schema, plus the documented Disk metadata for supported types. This is not coverage of every Yandex 360 audit event. The API does not document a production type distribution, so the baseline weights are illustrative.

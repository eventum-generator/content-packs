# Yandex 360 Organization Audit Generator

Produces one `enrichedEvent` item per line from the [Yandex 360 organization audit-log API](https://yandex.ru/dev/api360/doc/ru/audit-logs/get-logs) (`cloud-api.yandex.net/v1/auditlog/organizations/{org_id}/events`). It covers browser sign-ins and selected Disk actions. The API's `items`/`iteration_key` pagination wrapper and the separate Mail audit method are outside this SIEM-oriented event stream.

## Event Types

| Native `event.type` | Routine sampling weight | Meaning |
|---|---:|---|
| `id_cookie.set` | 25 | Browser or mobile sign-in |
| `disk_fs-view` | 37 | File view |
| `disk_fs-get-download-url` | 18 | File download |
| `disk_fs-store` | 12 | File upload or edit |
| `disk_fs-set-public` | 5 | Create a shared link |
| `disk_fs-set-private` | 3 | Remove a shared link |

Weights are relative generator choices. The routine scheduler also inserts a few spaced admin actions, and an unavailable public-link state can redirect a choice to a file view. Yandex does not publish production frequencies for these types. A bounded per-file state ensures `disk_fs-set-private` only follows `disk_fs-set-public` for that file. Its `meta` contains only `unixtime`, `tgt_rawaddress`, and `resource_name`, as specified by Yandex; public-link creation adds `public_rights.macros` and `public_rights.rights`.

## Anomaly Chain

`anomaly_mode: true` is the default. After 120 routine events, it inserts one four-event sequence on adjacent minute ticks:

1. `id_cookie.set`: `admin@corp.example` signs in from `203.0.113.42`, an alternate address to the account's usual address.
2. `disk_fs-view`: the same `event.uid` and `event.ip` view `disk:/finance/payroll-2026.xlsx`.
3. `disk_fs-set-public`: the account creates an `all`/`read` public link for that file.
4. `disk_fs-get-download-url`: the account downloads the same file.

A rule can match this ordered sequence within four minutes using `event.org_id`, `event.uid`, `event.ip`, and `event.meta.tgt_rawaddress`. `event.request_id` and `event.idempotency_id` identify individual operations, not a session. Background traffic in **both** modes contains each of these same actor/address/file actions separately, at least 20 minutes apart in the scheduled baseline. No individual event identifies the injected chain. `anomaly_mode: false` produces the background stream without this short sequence.

The documentation defines `disk_fs-get-download-url` as a file download. The event does not include a download URL or prove where the content was subsequently sent.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Purpose |
|---|---|---|
| `anomaly_mode` | `true` | Insert one short admin sequence; `false` produces background only |
| `org_id` | `1234567` | Synthetic organization ID |
| `organization_domain` | `corp.example` | Domain for synthetic employee logins |
| `alternate_ip` | `203.0.113.42` | Alternate admin address used in the chain and spaced background actions |
| `compromised_login` | `admin@corp.example` | Admin login used in both modes |
| `compromised_uid` | `1130000000123456` | Stable admin user ID |
| `sensitive_path` | `disk:/finance/payroll-2026.xlsx` | File path used in both modes |

Five employee profiles and three ordinary files are inline `items` samples in `generator.yml`. Their IDs, display names, addresses, file names, and MIME types remain stable throughout a run.

### Output Parameters

The shipped configuration writes to `output/events.json` and needs no output parameters or secrets. Replace the `file` output with a SIEM output plugin and configure its endpoint and credentials to send events elsewhere.

## Usage

Run from the content-packs repository root:

```bash
eventum generate --path generators/cloud-yandex-360-audit/generator.yml --id yandex-360 --live-mode false --keep-order true
eventum generate --path generators/cloud-yandex-360-audit/generator.yml --id yandex-360 --live-mode true --keep-order true
```

Batch mode generates continuously until interrupted. Live mode emits one event per minute; the sixth cron field is seconds. `--keep-order true` keeps the file in timestamp order. Set `event.template.params.anomaly_mode: false` in `generator.yml` to exercise background mode.

## Sample Output

This complete `id_cookie.set` item is copied from an actual generator run:

```json
{
  "event": {
    "idempotency_id": "5c744503-57f2-49ab-b732-b5ed6c9c1c09",
    "ip": "198.51.100.90",
    "is_system": false,
    "meta": {
      "device_id": "",
      "revision": "1"
    },
    "occurred_at": "2026-09-25T17:37:00+00:00",
    "org_id": 1234567,
    "request_id": "@309862,1790357820.0795600,9400041844236835,42f382873483621f9b081932b946ee40,1130000000123456,admin@corp.example",
    "service": "ID",
    "status": "Success",
    "type": "id_cookie.set",
    "uid": 1130000000123456
  },
  "user_login": "admin@corp.example",
  "user_name": "Администратор системы"
}
```

## Source and Scope

[Yandex's current organization audit-log method](https://yandex.ru/dev/api360/doc/ru/audit-logs/get-logs) defines the `enrichedEvent`/`auditlogEvent` object, accepted `service` values, sign-in type, Disk event names, and per-type Disk `meta` keys. The generated item includes all 13 required key paths in those two objects plus the optional `event.uid`. The published complete response examples cover `id_cookie.set` only. They show a human-readable `user_name`, UUID-shaped `idempotency_id`, a compound `@...` request ID, and an ISO 8601 string for `occurred_at` (despite the table labeling that field `integer`). The generator follows the concrete example for sign-ins.

For Disk events, the current API page supplies field lists but no complete raw `enrichedEvent` example. Disk `request_id` values here are synthetic UUID strings; the exact format, and the lexical form of `tgt_rawaddress`, remain unverified. The [older Disk audit method](https://yandex.ru/dev/api360/doc/ru/ref/AuditLogService/AuditLogService_Disk) has a different endpoint, schema, and OAuth permission and is not used as a reference for this generator. Full raw fidelity of the current Disk event objects requires a captured response from the current organization audit API.

# Yandex 360 Organization Audit Generator

Produces one native `enrichedEvent` item per JSON Line from the current [Yandex 360 organization audit API](https://yandex.ru/dev/api360/doc/ru/audit-logs/get-logs), covering browser sign-ins and personal Disk file activity. The selected transport is `GET https://cloud-api.yandex.net/v1/auditlog/organizations/{org_id}/events`, with OAuth permission `ya360_security:read_auditlog`. It emits chronological items, excluding the API page wrapper (`items`, `iteration_key`) and the separate Mail audit stream. No ECS wrapper is added.

## Event Types

| Native `event.type` | Category | Background share | Modeled operation |
| --- | --- | ---: | --- |
| `id_cookie.set` | authentication | 8.3% | Successful browser sign-in, service `ID` |
| `disk_fs-view` | file | 44.1% | View an existing personal file, service `Web` |
| `disk_fs-get-download-url` | file | 27.2% | Authenticated owner downloads a file, service `Web` |
| `disk_fs-store` | file | 9.0% | Edit an existing file, service `Web` |
| `disk_fs-set-public` | file | 5.7% | Publish a currently private file link |
| `disk_fs-set-private` | file | 5.7% | Remove an existing owner/file link |

Shares are for background (`anomaly_mode: false`). There is one event per minute, at a random second within that minute, about 1,440 per day; about 0.4% of minutes stay empty, where a download would complete the chain described below. Rates, weights and timing describe a synthetic busy-browser organization, not measured production frequencies.

Six accounts own three or four personal files each; file sets differ per owner, so only some owners hold the payroll spreadsheet. Every owner works from a usual address and a shared alternate address. Traffic consists of short browser sessions from one owner and address: a single operation, sign-in followed by views, downloads or edits, view-then-download bursts, and sharing sessions. Up to three sessions interleave, and their operations are usually one to five minutes apart. A sharing session publishes a randomly chosen file of the owner that is currently private, with `employees` or `all` rights (both `read`, weighted 55/45); about 70% open the file first, and the session may end with a download, an edit or more browsing. Early in a run, sharing leans towards file/rights pairs a client has not published yet, so every pair appears; after that, choices are fully random.

Owner UID and file path identify a link. A successful publication precedes every private operation. Each link gets a removal time 30-50 minutes after publication (skewed towards the short end), and the owner removes it through a logged website operation within a few minutes of that time, mostly from the publishing address. Holds range from 30 to 58 minutes. This is synthetic owner maintenance, not automatic link expiry. Across the 12 owner/address clients, at most 24 links are live and at most three sessions run at once, and one episode runs at a time. Clients and files already exist at startup; edits model uploads of an existing file, and no file deletion or account privilege change is implied.

## Anomaly Chain

`anomaly_mode` defaults to `true`, which adds recurring episodes to the background. `false` produces only background.

An episode is four operations, usually one to three minutes apart, from one account and the configured alternate address:

1. The account signs in through `id_cookie.set`.
2. It views one of its files.
3. It publishes an `all`/`read` link to that file.
4. It downloads the same file.

Correlate `event.org_id`, `event.uid`, `event.ip` and Disk `event.meta.tgt_rawaddress`. `request_id` and `idempotency_id` identify single operations, not a browser session, and every operation receives new IDs. Accounts rotate across the six owners, and target files advance through each owner's files after a complete owner rotation.

The first episode is due at a uniformly drawn point within the first `anomaly_interval_hours` (at most 24 hours; the background has no daily curve). Each later one is due one interval after the previous actual start, at a uniformly drawn point within a window centred on that time, `w = min(interval / 4, 6 h)` wide, with no catch-up bursts. An episode starts only once the account's current session has ended and the target file is private, and never as a fourth concurrent session. It then runs like an ordinary session of that client, and other clients keep working in between. Gaps between starts run about 22.4-26.0 hours at the default interval and 10.6-13.5 hours at 12 hours. Episode links get the same removal-time draw as other links.

Background contains every three-step part of the chain in both modes at comparable rates: sign-in, view and download of one file without a publication; sign-in, view and `all` publication of one file; view, `all` publication and download of one file without a sign-in; and sign-in, `all` publication and download of one file without a view. Sign-ins followed within minutes by views and downloads are common. Background never completes the full ordered sequence (sign-in, view of a file, `all` publication of that file, download of that file by the same UID and address) within 15 minutes of the sign-in, whichever of the client's sign-ins, views and publications the steps are taken from, an episode's own steps included: such an ordinary download is not recorded, and its minute stays empty; nothing else moves. Each episode therefore completes the sequence exactly once. Past 15 minutes, ordinary sessions complete it at a natural rate. A detection therefore needs all four steps on one file, in order, within 15 minutes.

The alternate address is ordinary traffic too. An account named `admin` does not establish organization-administrator privileges. Yandex calls `disk_fs-get-download-url` a file download, but this record contains neither a download URL nor a destination. The chain supports a rapid public-sharing detection; it does not prove anonymous retrieval, exfiltration or compromise.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Meaning |
| --- | --- | --- |
| `anomaly_mode` | `true` | Boolean: add recurring episodes; `false` produces only background |
| `anomaly_interval_hours` | `24` | Finite number from 6 to 8,760; average spacing between episode starts; the first falls within the first interval (at most 24 h), each later one in a window of a quarter of the interval (at most 6 h) centred on one interval after the previous actual start |
| `org_id` | `1234567` | Positive integer organization ID |
| `organization_domain` | `corp.example` | Domain for the five sampled employee logins |
| `alternate_ip` | `2001:db8:8005:f00:61ce:682c:bca4:42e5/128` | Alternate client address shared by all owners in both modes |
| `compromised_login` | `admin@corp.example` | Extra modeled account, also ordinary; the name is kept for compatibility |
| `compromised_uid` | `1130000000123456` | Positive integer UID distinct from the five sampled owners |
| `compromised_name` | `Соколов Алексей` | Extra account's display name |
| `compromised_usual_ip` | `2001:db8:b081:b42d::1:90/128` | Extra account's usual client address |
| `sensitive_path` | `disk:/finance/payroll-2026.xlsx` | File held by the extra account and by sampled owners that list it |
| `sensitive_media_type` | `spreadsheet` | Native media category of that file (`document` or `spreadsheet`) |

The five employees are the `users` sample in `samples/users.json`: login prefix, display name (surname first), UID, usual address and the list of their file paths. The `files` sample in `samples/files.csv` lists the other file paths with their categories. The extra account holds `sensitive_path` and the first three sampled files.

The template requires six distinct UIDs and logins, distinct `disk:/` paths with DOCX `document` or XLSX `spreadsheet` categories, and two to four known files per owner. Addresses must be `2001:db8::/32` documentation addresses with a `/128` prefix; each owner's usual and alternate addresses differ. Logins cannot contain commas, since the sign-in request ID is comma-delimited. Keep the shipped cadence of one event per minute. These are model bounds, not restrictions of Yandex's API.

### Output Parameters

The shipped `generator.yml` writes JSON Lines to `output/events.json`, so it runs as-is. To deliver to a backend, replace the output with a plugin whose connection values come from top-level placeholders, for example OpenSearch:

```yaml
output:
  - opensearch:
      hosts:
        - ${params.opensearch_host}
      username: ${params.opensearch_user}
      password: ${secrets.opensearch_password}
      index: ${params.opensearch_index}
```

| Parameter | Description |
| --- | --- |
| `${params.opensearch_host}` | OpenSearch host URL |
| `${params.opensearch_user}` | Username for authentication |
| `${secrets.opensearch_password}` | Password, resolved from the Eventum keyring |
| `${params.opensearch_index}` | Target index name |

## Usage

From the content-packs repository root, run live:

```bash
eventum generate --path generators/cloud-yandex-360-audit/generator.yml --id yandex-360 --live-mode true --keep-order true
```

For a finite batch, copy `generator.yml` to `generator.batch.yml` beside it and add a window under `input[0].cron`:

```yaml
start: '2026-10-01T00:00:00+00:00'
end: '2026-10-03T03:20:00+00:00'
```

```bash
eventum generate --path generators/cloud-yandex-360-audit/generator.batch.yml --id yandex-360-batch --live-mode false --keep-order true
```

This window has 3,081 minute slots (a few stay empty) and usually two episodes at the default interval. Longer intervals need longer windows, and a live run shows only background until the first episode, which starts within the first interval (at most 24 hours). `--keep-order true` preserves source order through the asynchronous writer. Native timestamps are rendered in UTC whatever the CLI time zone.

Unsupported parameters raise template render errors, and unsupported cadence can leave a partial trace. The current Eventum CLI can still exit zero after `Failed to render template`, so check for nonempty output and diagnostics rather than relying on the exit status.

## Sample Output

This complete `id_cookie.set` item opens the first episode of a generated default run:

```json
{"event": {"idempotency_id": "2c6b4908-a519-4de2-ad61-0ae925dacba2", "ip": "2001:db8:8005:f00:61ce:682c:bca4:42e5/128", "is_system": false, "meta": {"device_id": "", "revision": "1"}, "occurred_at": "2026-10-01T16:01:22+00:00", "org_id": 1234567, "request_id": "@5756,1790870482.6881498,6343957899868700,8565f057755f1966cf13c1ed822b5246a7,1130000000123456,admin@corp.example", "service": "ID", "status": "Success", "type": "id_cookie.set", "uid": 1130000000123456}, "user_login": "admin@corp.example", "user_name": "\u0421\u043e\u043a\u043e\u043b\u043e\u0432 \u0410\u043b\u0435\u043a\u0441\u0435\u0439"}
```

## Source Fidelity and Limits

- [Current organization audit-log method](https://yandex.ru/dev/api360/doc/ru/audit-logs/get-logs), accessed 2026-09-26: field-complete envelope, all six event names, their metadata, and five full browser-sign-in examples. The service is SaaS; no exporter build or version is published. This profile follows the current v1 method.
- [File-category catalog linked from the audit metadata glossary](https://yandex.ru/dev/disk-api/doc/ru/reference/recent-upload#query): `document` for Word documents and `spreadsheet` for Excel tables; `mime_type` is a different property.
- [Official administrator audit guide](https://yandex.ru/support/yandex-360/business/admin/ru/admin-audit-log): token permission, organization context and enriched-item initiator fields.
- [Business Disk access guide](https://yandex.ru/support/yandex-360/business/disk/web/ru/share/personal-and-public-access) and [public-link guide](https://yandex.ru/support/yandex-360/customers/disk/web/ru/share/sharing): owner files, internal and external link sharing, access removal and link lifetime. The model assumes organization policy permits external links, files have no inherited folder or personal grants, and no automatic link expiry is set.

The published sign-in item has 16 structural paths and 14 leaves; output covers 16/16 and 14/14. Its pagination wrapper is outside this denominator. The schema table calls `occurred_at` an integer, but the description and full examples use ISO 8601 strings; the generator follows the examples. `event.ip` uses the host-CIDR form of all five examples (`<address>/128`) with documentation IPv6 addresses; the vendor's own examples are real IPv6 addresses.

The sign-in `request_id` reproduces the structure of all five examples: `@` and a 4-6 digit number, epoch seconds with a 6-7 digit fraction, a 16-digit number, 34 hex characters whose 33rd is `a`, then UID and login. The fraction sits within the displayed second or up to 0.1 s before it, as in the examples. What these components mean is not documented; they are synthetic values of the observed shape, not a certified derivation.

[Elastic integrations](https://github.com/elastic/integrations/tree/main/packages) has no Yandex 360 package (checked 2026-09-26), so there is no maintained ECS sample to mirror; the pack emits native API items.

For Disk metadata, view, download and store cover 5/5 documented paths, public covers 8/8 including the rights object, and private covers 4/4 (with `resource_type`, without `resource_media_type`). These counts check the format specification, not raw-record parity. No complete current-API Disk record was found, so Disk request IDs are synthetic UUID strings and the `disk:/...` form of `tgt_rawaddress` is inferred. Disk items therefore follow the documented metadata, not a raw sample. The [older Disk audit method](https://yandex.ru/dev/api360/doc/ru/ref/AuditLogService/AuditLogService_Disk) has a different endpoint, schema and permission and does not validate this stream.

Only successful interactive browser and website operations are modeled; error and system-event variants have not been captured. Output keys are sorted and non-ASCII characters escaped by the JSON formatter, so items are semantically equal to API items, not byte-equal. Output has not been compared with a live tenant or verified against a live SIEM parser, and API pagination is not modeled. All identities, addresses and IDs are synthetic.

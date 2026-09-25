# Nextcloud Admin Audit

Generates Nextcloud 35.0.0 `admin_audit` HTTP records from the dedicated file backend (`data/audit.log`) and wraps each native JSON line in ECS. The native record is retained in `event.original` and parsed under `nextcloud.audit`. The ECS `agent.type: filebeat` and `log.file.path` fields model a file collector; they are not native Nextcloud fields. This pack does not mix ordinary `nextcloud.log` diagnostics or syslog framing into the audit stream.

The modeled instance has 12 users and 60 files. Existing sessions account for file activity without a login event immediately before every request. A login attempt and its result share one request ID; separate requests never use that ID as a session key. The native `version` value `35.0.0.10` is the four-part internal number in the [35.0.0 release tag](https://github.com/nextcloud/server/blob/v35.0.0/version.php), rather than the public release string.

## Event Types

| Native message | Action | Routine selection weight |
| --- | --- | ---: |
| `Login attempt: "..."` followed by `Login successful: "..."` or `Login failed: "..."` | Password login request | 10% |
| `File with id "..." accessed: "..."` | DAV file read | 53% |
| `File with id "..." written to: "..."` | DAV file update | 23% |
| `The file ... has been shared via link ...` | Public link creation | 9% |
| `The expiration date ... has been removed` | Public link expiration removal | 3% |
| `The permissions ... have been changed to "3"` | Public link changed from read-only (1) to read and update (3) | 2% |

These are synthetic selection weights, not measured Nextcloud rates. A selected login emits adjacent attempt/result records with the same request ID and native timestamp; failed results are 12% of routine logins, plus one routine failed login for the target user. Updates select an existing link and occur once per applicable property. The model retains at most 64 links.

## Anomaly Chain

With `anomaly_mode: true` (the default), one twelve-record sequence starts after 250 background records: three failed password attempts for `finance_admin`, a fourth attempt with successful login, a read of file ID `84521`, creation of a public link, removal of its expiration date and a permission change from 1 to 3. All requests use the same user identity and remote IP. Each attempt/result pair shares `reqId`; other requests have distinct IDs. The link creation and changes share a link ID, recorded in the creation message and the update request URLs. The expiry message contains the file ID but not the link ID.

Background includes the same user, IP and file, all modeled action types, and ordinary public links for that file. The signal is their order and short interval, not a special event field or exclusive account. `anomaly_mode: false` produces background only. A detection can join failed attempts to the later success by attempted username and IP, then require the file/link actions within a short window. `reqId` joins only events from the same HTTP request; it does not prove a persistent session.

The modeled sharing policy sets a default public-link expiration but does not enforce it, so a user can remove the date. It also permits editing a public file link. These settings are necessary for the later two audit messages to represent valid operations.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Meaning |
| --- | --- | --- |
| `server_name` | `cloud-01.corp.example` | ECS server host name |
| `server_version` | `35.0.0.10` | Four-part native log version for Nextcloud 35.0.0 |
| `audit_log_path` | `/var/www/html/data/audit.log` | ECS path of the collected audit file; does not change local generator output |
| `anomaly_user`, `anomaly_ip` | `finance_admin`, `10.99.3.51` | User and remote IP used in both background and chain |
| `anomaly_file`, `anomaly_file_id` | `/finance_admin/files/Finance/Payroll/2026-Q3.xlsx`, `84521` | File used in both background and chain; keep path under `/<anomaly_user>/files/` |
| `first_share_id` | `32019` | First public-link ID for routine and anomaly links |
| `anomaly_after_events` | `250` | Number of background records before the one-time chain |
| `anomaly_mode` | `true` | `false` emits only background |

### Output Parameters

The shipped config writes to `output/events.json` and has no `${params.*}` or `${secrets.*}` placeholders. Change `output.file.path` or replace the output plugin for a SIEM destination.

## Usage

Enable `admin_audit` with file logging and allow its INFO messages through the log-level configuration. From the `content-packs` repository root:

```bash
uv run --project ../eventum eventum generate --path generators/application-nextcloud-audit/generator.yml --id nextcloud-audit --live-mode true
```

For a finite batch, copy `generator.yml` beside the original, add `start` and `end` to its `input.cron` entry, and run the copy with `--live-mode false --keep-order true`.

## Sample Output

This complete event came from an enabled-mode run after the source and serializer review:

```json
{
  "@timestamp": "2026-09-25T00:04:19+00:00",
  "agent": {
    "name": "cloud-01.corp.example",
    "type": "filebeat"
  },
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "share-create",
    "category": [
      "file"
    ],
    "dataset": "nextcloud.audit",
    "kind": "event",
    "original": "{\"reqId\":\"bY4sfp3P0V99Zwz9kRSa\",\"level\":1,\"time\":\"2026-09-25T00:04:19+00:00\",\"remoteAddr\":\"10.99.3.51\",\"user\":\"finance_admin\",\"app\":\"admin_audit\",\"method\":\"POST\",\"url\":\"/ocs/v2.php/apps/files_sharing/api/v1/shares\",\"scriptName\":\"/ocs/v2.php\",\"message\":\"The file \\\"/finance_admin/files/Finance/Payroll/2026-Q3.xlsx\\\" with ID \\\"84521\\\" has been shared via link with permissions \\\"1\\\" (Share ID: 32034)\",\"userAgent\":\"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/126.0.0.0 Safari/537.36\",\"version\":\"35.0.0.10\",\"data\":{\"app\":\"admin_audit\"}}",
    "outcome": "success",
    "type": [
      "creation"
    ]
  },
  "file": {
    "path": "/finance_admin/files/Finance/Payroll/2026-Q3.xlsx"
  },
  "host": {
    "name": "cloud-01.corp.example"
  },
  "http": {
    "request": {
      "method": "POST"
    }
  },
  "log": {
    "file": {
      "path": "/var/www/html/data/audit.log"
    },
    "level": "info"
  },
  "message": "The file \"/finance_admin/files/Finance/Payroll/2026-Q3.xlsx\" with ID \"84521\" has been shared via link with permissions \"1\" (Share ID: 32034)",
  "nextcloud": {
    "audit": {
      "app": "admin_audit",
      "data": {
        "app": "admin_audit"
      },
      "level": 1,
      "message": "The file \"/finance_admin/files/Finance/Payroll/2026-Q3.xlsx\" with ID \"84521\" has been shared via link with permissions \"1\" (Share ID: 32034)",
      "method": "POST",
      "remoteAddr": "10.99.3.51",
      "reqId": "bY4sfp3P0V99Zwz9kRSa",
      "scriptName": "/ocs/v2.php",
      "time": "2026-09-25T00:04:19+00:00",
      "url": "/ocs/v2.php/apps/files_sharing/api/v1/shares",
      "user": "finance_admin",
      "userAgent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/126.0.0.0 Safari/537.36",
      "version": "35.0.0.10"
    }
  },
  "related": {
    "ip": [
      "10.99.3.51"
    ],
    "user": [
      "finance_admin"
    ]
  },
  "source": {
    "ip": "10.99.3.51"
  },
  "tags": [
    "nextcloud",
    "admin_audit"
  ],
  "url": {
    "path": "/ocs/v2.php/apps/files_sharing/api/v1/shares"
  },
  "user": {
    "name": "finance_admin"
  },
  "user_agent": {
    "original": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/126.0.0.0 Safari/537.36"
  }
}
```

## References and Limits

- [Nextcloud 35 logging guide](https://docs.nextcloud.com/server/stable/admin_manual/configuration_server/logging_configuration.html) documents the dedicated audit file, default INFO filtering, native fields and optional routing into the main log.
- [Nextcloud 35.0.0 authentication listener](https://github.com/nextcloud/server/blob/v35.0.0/apps/admin_audit/lib/Listener/AuthEventListener.php), [file actions](https://github.com/nextcloud/server/blob/v35.0.0/apps/admin_audit/lib/Actions/Files.php), [sharing listener](https://github.com/nextcloud/server/blob/v35.0.0/apps/admin_audit/lib/Listener/SharingEventListener.php) and [sharing actions](https://github.com/nextcloud/server/blob/v35.0.0/apps/admin_audit/lib/Actions/Sharing.php) define the eight emitted message forms.
- [Nextcloud 30 raw login-attempt record](https://github.com/nextcloud/server/issues/48826) independently confirms the `/index.php/login` URL and `data.app` field for an earlier version.
- [Nextcloud 35.0.0 audit logger](https://github.com/nextcloud/server/blob/v35.0.0/apps/admin_audit/lib/AuditLogger.php), [log field/JSON serializer](https://github.com/nextcloud/server/blob/v35.0.0/lib/private/Log/LogDetails.php) and [application registration](https://github.com/nextcloud/server/blob/v35.0.0/apps/admin_audit/lib/AppInfo/Application.php) establish the dedicated backend, 13 modeled native fields, field order and JSON encoding.
- [Nextcloud sharing settings](https://docs.nextcloud.com/server/stable/admin_manual/configuration_files/file_sharing_configuration.html) and [OCS Share API](https://docs.nextcloud.com/server/stable/developer_manual/client_apis/OCS/ocs-share-api.html) support the modeled link policy and permissions 1/3. [ECS](https://www.elastic.co/docs/reference/ecs) is used for the wrapper.
- [KUMA 4.0 supported sources](https://support.kaspersky.com/kuma/4.0/en-US/255782.htm) lists Nextcloud v26.0.4 via syslog. This pack models the Nextcloud 35.0.0 JSON audit file, so direct compatibility with that normalizer is not asserted.

Field coverage is **13/13** for the non-optional native fields emitted by the tagged serializer for these HTTP audit records, including `data.app`. CLI-only, exception, backtrace and optional client request ID fields are outside scope. The `event.original` JSON uses the tagged PHP serializer's field order and compact separators for the modeled values. A captured production `audit.log` line from a running 35.0.0 server was not available, so request routes and end-to-end native bytes remain unconfirmed against a live instance. The guide's illustrative JSON example is from Nextcloud 21 and is not a 35.0.0 raw fixture.

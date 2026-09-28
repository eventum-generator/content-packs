# Nextcloud Admin Audit

Generates Nextcloud 35.0.0 `admin_audit` HTTP records from the dedicated file backend (`data/audit.log`) and wraps each native JSON line in ECS, for testing detections on logins, file access and public links. The native record is retained in `event.original` and parsed under `nextcloud.audit`. The ECS `agent.type: filebeat` and `log.file.path` fields model a file collector; they are not native Nextcloud fields. This pack does not mix ordinary `nextcloud.log` diagnostics or syslog framing into the audit stream.

The modeled instance has 12 users and 60 files. Existing sessions account for file activity without a login event immediately before every request. A login attempt and its result share one request ID and native timestamp; separate requests never use that ID as a session key. The native `version` value `35.0.0.10` is the four-part internal number in the [35.0.0 release tag](https://github.com/nextcloud/server/blob/v35.0.0/version.php), rather than the public release string.

## Event Types

| Native message | Action | Share |
| --- | --- | ---: |
| `Login attempt: "..."` | Password login request | 10.3% |
| `Login successful: "..."` | Login result | 5.0% |
| `Login failed: "..."` | Login result | 5.4% |
| `File with id "..." accessed: "..."` | DAV file read | 46.1% |
| `File with id "..." written to: "..."` | DAV file update | 18.6% |
| `The file ... has been shared via link ...` | Public link creation | 6.8% |
| `The expiration date ... has been removed` | Public link expiration removal | 4.8% |
| `The permissions ... have been changed to "3"` | Public link changed from read-only (1) to read and update (3) | 3.1% |

Shares are measured on a 7-day `anomaly_mode: false` run with the default settings (4,127 records, about 25 per hour). They are synthetic workload settings, not measured Nextcloud rates.

Background activity comes from independent random processes; none of them runs on a fixed period, rotation or script:

- **User sessions.** Each user works in sessions at an own random rate, mostly during UTC working hours, from the office address or one of two home addresses. About a third of sessions start with a password login; about 15% of those logins follow one to five mistyped passwords a few seconds apart, and a few are given up. A session then reads and writes the user's files minutes apart, often the file it just used, creates public links (read-only, with a default expiration date) and removes a link's expiration or allows updates through it, often minutes after creating the link. Each property of a link changes at most once.
- **Stale passwords.** A sync client with an outdated password retries three to eight times about a minute apart; half of them end with a successful login.
- **Outside guesses.** A few times a day, an address from the documentation ranges tries one or more passwords for a user, without success.

Users, their files, office and home addresses and activity rates are fixed per `server_name`; all activity on top of that differs in every run. Public link IDs grow by one to four per link, as other share types consume IDs; the model retains at most 64 links.

## Anomaly Chain

One user fails password login three times from one home address, a few seconds to about a minute apart, then logs in successfully from that address. Minutes later, from the same address and with the same delays between operations as ordinary sessions, the user reads a file, creates a public link to it, removes the link's expiration date and changes it from read-only to read and update. The pattern fits a guessed password followed by publishing a file for outside access. Each attempt/result pair shares `reqId`; other requests have distinct IDs. The link creation and changes share a link ID, recorded in the creation message and the update request URLs; the expiry message contains the file ID but not the link ID. Episodes in the measured runs lasted 3-20 minutes; the length is not capped below the one-hour chain window.

- **Recurrence.** With `anomaly_mode: true` (the default), the first episode starts within the first `anomaly_interval_hours` (at most 24 hours) of the run, at a time of day drawn from the user activity curve. Each next episode is due one interval after the previous actual start; its start is drawn in a window of a quarter interval (at most 6 hours) centred on that due time, weighted towards busy hours. Missed episodes are never caught up. At intervals of 8 hours or less the window covers most of the clock, so episodes also fall into quiet hours.
- **Variation.** Each episode uses a different user (chosen in proportion to activity), a different home address and a different file from the previous one. The address and file belong to that user and also appear in the user's ordinary sessions.
- **Background overlap.** Every part of the chain also occurs in ordinary traffic of both modes: repeated failed logins of one user and address within minutes, failures followed by a success, reads followed by a link to the same file, and expiration removals and permission changes of fresh links. Per 7 days of background, five default runs showed 87-119 cases of three failed logins of one user and address within 10 minutes, 7-17 cases of three failures followed by a success from that address within an hour, 128-156 reads followed by a link to the same file within an hour, and 37-78 links whose expiration was removed and whose permissions were then changed within an hour of creation.
- **Detection.** Only the full order separates the modes. Ordinary traffic never completes three failed logins and a successful login from one address, then a read, link creation, expiration removal and permission change for one file from that user and address, within 60 minutes of the first failure, in any combination of its records: an ordinary permission change that would complete it is left out, and the session goes on unchanged. In the measured runs, a rule that correlates these records for one user and address within 60 minutes, over every combination of records, matched each episode once and never matched `anomaly_mode: false` traffic. `reqId` joins only records of the same HTTP request; it does not prove a persistent session.

The modeled sharing policy sets a default public-link expiration but does not enforce it, so a user can remove the date. It also permits editing a public file link. These settings are necessary for the later two audit messages to represent valid operations.

Set `anomaly_mode: false` to keep only background activity.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Meaning |
| --- | --- | --- |
| `server_name` | `cloud-01.corp.example` | ECS server host name; also fixes the user organisation |
| `server_version` | `35.0.0.10` | Four-part native log version for Nextcloud 35.0.0 |
| `audit_log_path` | `/var/www/html/data/audit.log` | ECS path of the collected audit file; does not change local generator output |
| `first_share_id` | `32019` | Public-link IDs start after this value |
| `anomaly_interval_hours` | `24` | Hours from one episode start to the next due time (3 to 8760) |
| `anomaly_mode` | `true` | Add the recurring anomaly episodes to the background; `false` emits only background |

### Output Parameters

The shipped config writes to `output/events.json` and has no `${params.*}` or `${secrets.*}` placeholders. Change `output.file.path` or replace the output plugin for a SIEM destination.

## Usage

Enable `admin_audit` with file logging and allow its INFO messages through the log-level configuration. From the `content-packs` repository root:

```bash
eventum generate --path generators/application-nextcloud-audit/generator.yml --id nextcloud-audit --live-mode true
```

For a finite batch, add `start` and `end` to the `cron` input in a local copy and run it with `--live-mode false --keep-order true`. The input ticks every second, and a tick without a due record is dropped, so each second holds at most one record.

## Sample Output

This complete link-creation event came from the first episode of a finite run with the default settings:

```json
{
  "@timestamp": "2026-09-25T12:21:18+00:00",
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
    "original": "{\"reqId\":\"te22OTIhWKqMTpIpkzI5\",\"level\":1,\"time\":\"2026-09-25T12:21:18+00:00\",\"remoteAddr\":\"198.51.100.30\",\"user\":\"konstantin\",\"app\":\"admin_audit\",\"method\":\"POST\",\"url\":\"/ocs/v2.php/apps/files_sharing/api/v1/shares\",\"scriptName\":\"/ocs/v2.php\",\"message\":\"The file \\\"/konstantin/files/IT/Inventory-01.pdf\\\" with ID \\\"14090\\\" has been shared via link with permissions \\\"1\\\" (Share ID: 32049)\",\"userAgent\":\"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0.0.0 Safari/537.36\",\"version\":\"35.0.0.10\",\"data\":{\"app\":\"admin_audit\"}}",
    "outcome": "success",
    "type": [
      "creation"
    ]
  },
  "file": {
    "path": "/konstantin/files/IT/Inventory-01.pdf"
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
  "message": "The file \"/konstantin/files/IT/Inventory-01.pdf\" with ID \"14090\" has been shared via link with permissions \"1\" (Share ID: 32049)",
  "nextcloud": {
    "audit": {
      "app": "admin_audit",
      "data": {
        "app": "admin_audit"
      },
      "level": 1,
      "message": "The file \"/konstantin/files/IT/Inventory-01.pdf\" with ID \"14090\" has been shared via link with permissions \"1\" (Share ID: 32049)",
      "method": "POST",
      "remoteAddr": "198.51.100.30",
      "reqId": "te22OTIhWKqMTpIpkzI5",
      "scriptName": "/ocs/v2.php",
      "time": "2026-09-25T12:21:18+00:00",
      "url": "/ocs/v2.php/apps/files_sharing/api/v1/shares",
      "user": "konstantin",
      "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0.0.0 Safari/537.36",
      "version": "35.0.0.10"
    }
  },
  "related": {
    "ip": [
      "198.51.100.30"
    ],
    "user": [
      "konstantin"
    ]
  },
  "source": {
    "ip": "198.51.100.30"
  },
  "tags": [
    "nextcloud",
    "admin_audit"
  ],
  "url": {
    "path": "/ocs/v2.php/apps/files_sharing/api/v1/shares"
  },
  "user": {
    "name": "konstantin"
  },
  "user_agent": {
    "original": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0.0.0 Safari/537.36"
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

Rates, session shapes and addresses are synthetic workload settings; working hours follow UTC. Timestamps have one-second resolution, as in the native log, and each second holds at most one record apart from a login attempt and its result, which share their time.

# Nextcloud Admin Audit

Generates Nextcloud 35.0.0 `admin_audit` HTTP records from the dedicated file backend (`data/audit.log`) and wraps each native JSON line in ECS, for testing detections on logins, file access and public links. The native record is retained in `event.original` and parsed under `nextcloud.audit`. The ECS `agent.type: filebeat` and `log.file.path` fields model a file collector; they are not native Nextcloud fields. This pack does not mix ordinary `nextcloud.log` diagnostics or syslog framing into the audit stream.

The modeled instance has 180 users and 1,154 files. Existing sessions account for file activity without a login event immediately before every request. A login attempt and its result share one request ID and native timestamp; separate requests never use that ID as a session key. The native `version` value `35.0.0.10` is the four-part internal number in the [35.0.0 release tag](https://github.com/nextcloud/server/blob/v35.0.0/version.php), rather than the public release string.

## Volume and Timing

About 10,800 records per day, following a UTC working-day curve; the daily total varies by about ±10% from day to day.

| UTC hours | Records/s |
| --- | ---: |
| 10-15 | 0.27 |
| 08-10, 15-17 | 0.20 |
| 07-08, 17-19 | 0.12 |
| 19-07 | 0.04 |

User activity follows this curve: each user works in sessions, and busier users have more of them. Password guesses from outside arrive at about five a day around the clock. Operations within a session are minutes apart; records that belong to one moment (a login and its immediate retry, consecutive requests) are a few seconds apart in office hours and 15-25 seconds apart at night.

## Event Types

| Native message | Action | Category | Share | Weekly range |
| --- | --- | --- | ---: | ---: |
| `File with id "..." accessed: "..."` | DAV file read | file | 57.5% | 57.5-57.9% |
| `File with id "..." written to: "..."` | DAV file update | file | 24.0% | 23.7-24.0% |
| `Login attempt: "..."` | Password login request | authentication | 8.4% | 8.4-8.5% |
| `Login successful: "..."` | Login result | authentication | 7.7% | 7.7-7.8% |
| `The file ... has been shared via link ...` | Public link creation | file | 0.9% | 0.7-1.1% |
| `Login failed: "..."` | Login result | authentication | 0.7% | 0.7-0.7% |
| `The expiration date ... has been removed` | Public link expiration removal | file | 0.5% | 0.4-0.6% |
| `The permissions ... have been changed to "3"` | Public link changed from read-only (1) to read and update (3) | file | 0.2% | 0.2-0.3% |

Shares are over a typical week of about 75,000 records; the last column shows how they vary from week to week. They are synthetic workload settings, not measured Nextcloud rates. About 8% of login attempts fail. Users create about 75-120 public links a day; about half of the links later lose their expiration date and about a quarter are opened for updates.

The permission-change message gives the file path relative to the owner's files folder (`/Sales/Forecast-01.pdf`), while reads, writes and link creation give the full path (`/maria.p/files/Sales/Forecast-01.pdf`). `file.path` holds the full path in every file and link record.

Background activity comes from independent random processes; none of them runs on a fixed period, rotation or script:

- **User sessions.** Each user works from the office address or a home address, mostly during UTC working hours. Half of the sessions start with a password login in the web interface; 3% of those logins follow one to five mistyped passwords seconds apart, and a tenth of those are given up. Other sessions read and write the user's files minutes apart, often the file just used, and now and then create a public link (read-only, with a default expiration date) or remove a link's expiration or allow updates through it. Each property of a link changes at most once.
- **Sharing sessions.** A few web sessions are opened to share a file with someone outside: the user reads the file, creates a public link to it, in half of the cases removes the link's expiration date minutes later and sometimes then allows updates, and may go on with a few ordinary operations. The share of web sessions opened to share drifts from day to day between 4% and 12%, so sharing activity differs from week to week.
- **Stale passwords.** About once a day a sync client with an outdated password retries three to eight times about a minute apart; half of them end with a successful login.
- **Outside guesses.** About five times a day an address from the documentation ranges tries one or more passwords for a user, without success.

Users, their files, office and home addresses and activity weights are fixed per `server_name`; all activity on top of that differs in every run. Public link IDs grow by one to four per link, as other share types consume IDs.

## Anomaly Chain

One user fails password login three times from their home address, seconds to about a minute apart, then logs in successfully from that address. Minutes later, from the same address and with the same delays between operations as ordinary sessions, the user reads a file, creates a public link to it, removes the link's expiration date and changes it from read-only to read and update. The pattern fits a guessed password followed by publishing a file for outside access. Each attempt/result pair shares `reqId`; other requests have distinct IDs. The link creation and changes share a link ID, recorded in the creation message and the update request URLs; the expiry message contains the file ID but not the link ID. Episodes last about 3-25 minutes and always finish within an hour of the first failure.

- **Recurrence.** With `anomaly_mode: true` (the default), the first episode starts within the first `anomaly_interval_hours` (at most 24 hours) of the run, at a time of day drawn from the activity curve. Each next episode is due one interval after the previous actual start; its start is drawn in a window of a quarter interval (at most 6 hours) centred on that due time, weighted towards busy hours, so each start lies within three hours of its due time. Episodes that start in office hours stay there, moving through the day by a few hours at a time; an episode that starts late at night can recur at night for many days, since the night hours are equally quiet. Missed episodes are never caught up. At intervals of 8 hours or less the window covers most of the clock, so episodes also fall into quiet hours.
- **Variation.** Each episode uses a different user (chosen in proportion to activity) and a different file from the previous one. The home address and file belong to that user and also appear in the user's ordinary sessions. The episode adds its own records; the user's ordinary sessions go on as usual.
- **Background overlap.** Every step of the chain, and the user, home address and file of every episode, also occur in ordinary traffic of both modes. In a typical week of background there are about 75-90 cases of three failed logins of one user and address within 10 minutes, 55-65 cases of three failures followed by a success from that address within an hour, and 80-120 reads followed within an hour by a link to the same file, removal of its expiration date and a permission change. Failed logins followed within the hour by publishing a file are rare: about one to five a week reach the expiration removal after three failures, and at most two a week also reach the permission change after two failures.
- **Detection.** Only the full order separates single occurrences; the longest parts are rare in background, so episodes stand out in their weekly counts (see the limits below). Ordinary traffic never completes three failed logins and a successful login from one address, then a read, link creation, expiration removal and permission change for one file from that user and address, within 60 minutes of the first failure, in any combination of its records: an ordinary permission change that would complete it applies to another of the user's read-only links instead, and when the user has no other read-only link that change is absent. `reqId` joins only records of the same HTTP request; it does not prove a persistent session.

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

Enable `admin_audit` with file logging and allow its INFO messages through the log-level configuration. From the `content-packs` repository root, live generation at the configured rate:

```bash
eventum generate --path generators/application-nextcloud-audit/generator.yml --id nextcloud-audit --live-mode true
```

Batch generation: set `start` and `end` of the `oscillator` in all four `patterns/*.yml` files to the same range, with `start` at 00:00 UTC so the hour bands stay in place (for example `start: "2026-09-21T00:00:00Z"` and `end: "2026-09-28T00:00:00Z"`), then run:

```bash
eventum generate --path generators/application-nextcloud-audit/generator.yml --id nextcloud-audit --live-mode false --keep-order true
```

To change the volume, scale the `ratio` of every pattern file by the same factor.

Performance: about 2,900 records per second in batch mode on one core (14 days, 149,972 records, in 52 s).

## Sample Output

The link creation of the first episode of a week of default output:

```json
{"@timestamp": "2026-09-21T11:08:04+00:00", "agent": {"name": "cloud-01.corp.example", "type": "filebeat"}, "ecs": {"version": "8.17.0"}, "event": {"action": "share-create", "category": ["file"], "dataset": "nextcloud.audit", "kind": "event", "original": "{\"reqId\":\"wQvQ0YOnvKhJDWzisYVe\",\"level\":1,\"time\":\"2026-09-21T11:08:04+00:00\",\"remoteAddr\":\"203.0.113.29\",\"user\":\"ulyana\",\"app\":\"admin_audit\",\"method\":\"POST\",\"url\":\"/ocs/v2.php/apps/files_sharing/api/v1/shares\",\"scriptName\":\"/ocs/v2.php\",\"message\":\"The file \\\"/ulyana/files/HR/Onboarding-02.xlsx\\\" with ID \\\"14432\\\" has been shared via link with permissions \\\"1\\\" (Share ID: 32120)\",\"userAgent\":\"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/126.0.0.0 Safari/537.36\",\"version\":\"35.0.0.10\",\"data\":{\"app\":\"admin_audit\"}}", "outcome": "success", "type": ["creation"]}, "file": {"path": "/ulyana/files/HR/Onboarding-02.xlsx"}, "host": {"name": "cloud-01.corp.example"}, "http": {"request": {"method": "POST"}}, "log": {"file": {"path": "/var/www/html/data/audit.log"}, "level": "info"}, "message": "The file \"/ulyana/files/HR/Onboarding-02.xlsx\" with ID \"14432\" has been shared via link with permissions \"1\" (Share ID: 32120)", "nextcloud": {"audit": {"app": "admin_audit", "data": {"app": "admin_audit"}, "level": 1, "message": "The file \"/ulyana/files/HR/Onboarding-02.xlsx\" with ID \"14432\" has been shared via link with permissions \"1\" (Share ID: 32120)", "method": "POST", "remoteAddr": "203.0.113.29", "reqId": "wQvQ0YOnvKhJDWzisYVe", "scriptName": "/ocs/v2.php", "time": "2026-09-21T11:08:04+00:00", "url": "/ocs/v2.php/apps/files_sharing/api/v1/shares", "user": "ulyana", "userAgent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/126.0.0.0 Safari/537.36", "version": "35.0.0.10"}}, "related": {"ip": ["203.0.113.29"], "user": ["ulyana"]}, "source": {"ip": "203.0.113.29"}, "tags": ["nextcloud", "admin_audit"], "url": {"path": "/ocs/v2.php/apps/files_sharing/api/v1/shares"}, "user": {"name": "ulyana"}, "user_agent": {"original": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/126.0.0.0 Safari/537.36"}}
```

## References and Limits

- [Nextcloud 35 logging guide](https://docs.nextcloud.com/server/stable/admin_manual/configuration_server/logging_configuration.html) documents the dedicated audit file, default INFO filtering, native fields and optional routing into the main log.
- [Nextcloud 35.0.0 authentication listener](https://github.com/nextcloud/server/blob/v35.0.0/apps/admin_audit/lib/Listener/AuthEventListener.php), [file actions](https://github.com/nextcloud/server/blob/v35.0.0/apps/admin_audit/lib/Actions/Files.php), [sharing listener](https://github.com/nextcloud/server/blob/v35.0.0/apps/admin_audit/lib/Listener/SharingEventListener.php) and [sharing actions](https://github.com/nextcloud/server/blob/v35.0.0/apps/admin_audit/lib/Actions/Sharing.php) define the eight emitted message forms.
- [Nextcloud 30 raw login-attempt record](https://github.com/nextcloud/server/issues/48826) independently confirms the `/index.php/login` URL and `data.app` field for an earlier version.
- [Nextcloud 35.0.0 audit logger](https://github.com/nextcloud/server/blob/v35.0.0/apps/admin_audit/lib/AuditLogger.php), [log field/JSON serializer](https://github.com/nextcloud/server/blob/v35.0.0/lib/private/Log/LogDetails.php) and [application registration](https://github.com/nextcloud/server/blob/v35.0.0/apps/admin_audit/lib/AppInfo/Application.php) establish the dedicated backend, 13 modeled native fields, field order and JSON encoding.
- [Nextcloud sharing settings](https://docs.nextcloud.com/server/stable/admin_manual/configuration_files/file_sharing_configuration.html) and [OCS Share API](https://docs.nextcloud.com/server/stable/developer_manual/client_apis/OCS/ocs-share-api.html) support the modeled link policy and permissions 1/3. [ECS](https://www.elastic.co/docs/reference/ecs) is used for the wrapper.
- [KUMA 4.0 supported sources](https://support.kaspersky.com/kuma/4.0/en-US/255782.htm) lists Nextcloud v26.0.4 via syslog. This pack models the Nextcloud 35.0.0 JSON audit file, so direct compatibility with that normalizer is not asserted.

Field coverage is **13/13** for the non-optional native fields emitted by the tagged serializer for these HTTP audit records, including `data.app`. CLI-only, exception, backtrace and optional client request ID fields are outside scope. The `event.original` JSON uses the tagged PHP serializer's field order and compact separators for the modeled values. A captured production `audit.log` line from a running 35.0.0 server was not available, so request routes and end-to-end native bytes remain unconfirmed against a live instance. The guide's illustrative JSON example is from Nextcloud 21 and is not a 35.0.0 raw fixture.

- Rates, session shapes, the sharing share and addresses are synthetic workload settings; working hours follow UTC.
- Timestamps have one-second resolution, as in the native log. A login attempt and its result share their time. Records of one moment, such as a mistyped password and its retry or consecutive requests of one session, are a few seconds apart in office hours and 15-25 seconds apart at night, rather than milliseconds.
- With `anomaly_mode: true` each episode adds its own records, so counts of the chain parts (repeated failures followed by a success, then a read, link, expiration removal and permission change of one file from one address) are about one per episode higher than in background alone: about seven more a week at the default interval, about 21 more at 8 hours. For the longest parts, which background produces only a few times a week, this is several times the background count.
- An ordinary permission change that would complete the full chain within the hour goes to another read-only link of the same user, or is absent when there is none; the full order over a span longer than an hour is rare as well.

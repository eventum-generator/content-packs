# Nextcloud Admin Audit

Generates ECS events for Nextcloud `admin_audit` login, file and public-share activity. The complete native `audit.log` JSON line is preserved in `event.original`, and all native fields appear under `nextcloud.audit`.

Reference coverage: **12/12 documented native fields** under `nextcloud.audit` (`reqId`, `level`, `time`, `remoteAddr`, `user`, `app`, `method`, `url`, `scriptName`, `message`, `userAgent`, `version`) from the [Nextcloud logging manual](https://docs.nextcloud.com/server/stable/admin_manual/configuration_server/logging_configuration.html). Optional exception, backtrace and CLI-only fields do not apply to the modeled HTTP audit events.

## Event Types

| Audit message | Meaning | Routine weight |
| --- | --- | ---: |
| `Login successful` | User login | 15% |
| `File with id ... accessed` | File read | 55% |
| `File with id ... written to` | File update | 20% |
| `... shared via link ...` | Public-link creation | 10% |
| `Login failed`, targeted read, link creation, expiration removal, permission change | Linked audit sequence | Anomaly only |

These are configured weights, not measured Nextcloud rates. Each HTTP request receives its own `reqId`; it identifies one request, not a session.

## Anomaly Chain

Three failed login audit messages name `finance_admin` from `10.99.3.51` while `user` is `--` because no actor is authenticated. A successful login for that user follows from the same IP. The user then accesses file ID `84521`, creates a public link for it, removes the share expiration date and changes its permissions. Correlate attempted login name parsed from `message`, `remoteAddr`, later `user`, file ID and the per-chain share ID within a time window. Rules can detect failure-to-successful-login and public-link exposure after file access. Do not join these separate HTTP actions by `reqId`.

`anomaly_mode: true` is the default. Set `event.template.params.anomaly_mode: false` for background only; the finance identity, IP, file and share are then absent.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Meaning |
| --- | --- | --- |
| `server_name`, `server_version` | `cloud-01.corp.example`, `35.0.0.1` | ECS host and native logged version |
| `normal_user`, `normal_ip` | `alice`, `10.90.1.20` | Routine actor |
| `anomaly_user`, `anomaly_ip` | `finance_admin`, `10.99.3.51` | Chain actor |
| `anomaly_file`, `anomaly_file_id` | `/finance_admin/files/Finance/Payroll/2026-Q3.xlsx`, `84521` | Target file |
| `anomaly_share_id` | `32019` | Starting public share ID; increments per chain |
| `anomaly_interval_events` | `250` | Background events between chains |
| `anomaly_mode` | `true` | Include anomaly sequence; `false` emits background only |

### Output Parameters

The shipped config writes `output/events.json` and has no `${params.*}` or `${secrets.*}` placeholders. Change `output.file.path` or replace the output plugin to connect a SIEM.

## Usage

Enable `admin_audit` and configure its INFO records to be logged. Then, from the content-packs repository root:

```bash
eventum generate --path generators/application-nextcloud-audit/generator.yml --id application-nextcloud-audit --live-mode true
```

For a short local sample, use `--live-mode false` and stop the command after enough events.

## Sample Output

The following event came from an enabled-mode run:

```json
{
  "@timestamp": "2026-09-25T12:26:19+00:00",
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
    "original": "{\"app\": \"admin_audit\", \"level\": 1, \"message\": \"The file \\\"/finance_admin/files/Finance/Payroll/2026-Q3.xlsx\\\" with ID \\\"84521\\\" has been shared via link with permissions \\\"1\\\" (Share ID: 32019)\", \"method\": \"POST\", \"remoteAddr\": \"10.99.3.51\", \"reqId\": \"GZtwFBJlRxjbQxducFQG\", \"scriptName\": \"/ocs/v2.php\", \"time\": \"2026-09-25T12:26:19+00:00\", \"url\": \"/ocs/v2.php/apps/files_sharing/api/v1/shares\", \"user\": \"finance_admin\", \"userAgent\": \"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36\", \"version\": \"35.0.0.1\"}",
    "outcome": "success",
    "type": [
      "creation"
    ]
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
    "level": "info"
  },
  "message": "The file \"/finance_admin/files/Finance/Payroll/2026-Q3.xlsx\" with ID \"84521\" has been shared via link with permissions \"1\" (Share ID: 32019)",
  "nextcloud": {
    "audit": {
      "app": "admin_audit",
      "level": 1,
      "message": "The file \"/finance_admin/files/Finance/Payroll/2026-Q3.xlsx\" with ID \"84521\" has been shared via link with permissions \"1\" (Share ID: 32019)",
      "method": "POST",
      "remoteAddr": "10.99.3.51",
      "reqId": "GZtwFBJlRxjbQxducFQG",
      "scriptName": "/ocs/v2.php",
      "time": "2026-09-25T12:26:19+00:00",
      "url": "/ocs/v2.php/apps/files_sharing/api/v1/shares",
      "user": "finance_admin",
      "userAgent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36",
      "version": "35.0.0.1"
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
    "original": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36"
  }
}
```

## References and Limits

- [Nextcloud logging and admin audit manual](https://docs.nextcloud.com/server/stable/admin_manual/configuration_server/logging_configuration.html) defines the native JSON fields, audit backend and INFO logging requirement.
- [Nextcloud admin_audit source](https://github.com/nextcloud/server/tree/stable35/apps/admin_audit/lib) defines the emitted login, file and sharing messages.
- [KUMA 4.0 supported sources](https://support.kaspersky.com/kuma/4.0/en-US/255782.htm) lists Nextcloud v26.0.4 via syslog.

This pack preserves the documented native JSON **file** record for Nextcloud 35 inside an ECS event. KUMA's listed Nextcloud normalizer targets v26.0.4 **syslog**; the JSON `event.original` is not asserted to be directly compatible with that normalizer. Nextcloud's default WARN log level suppresses INFO audit records, so enable `admin_audit` and a conditional logging override for its app context in a real installation.

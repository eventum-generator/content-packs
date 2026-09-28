# Aruba ClearPass Policy Manager audit records

Synthetic ClearPass 6.11 administrative audit records in ECS JSON, with a ClearPass-like syslog message in `event.original`, for testing detections on administrator logins and configuration changes. This profile models the **Audit Records** export template with **RFC 5424** explicitly selected. ClearPass defaults to Standard/raw export, so a default installation will not produce this format.

## Event Types

| Native category / action | Share | ECS category |
| --- | ---: | --- |
| `Logged in` / `None` (WebUI) | 24.3% | Authentication |
| `Login Failed` / `None` (WebUI) | 15.6% | Authentication |
| `Account Settings` / `MODIFY` | 22.3% | Configuration |
| `Cluster-wide Parameter` / `MODIFY` | 19.3% | Configuration |
| `Log Service Configuration` / `MODIFY` | 11.2% | Configuration |
| `SSH Public Key` / `ADD` | 7.2% | Configuration |

Shares are measured on a 7-day `anomaly_mode: false` run with the default settings (2,377 records, about 14 per hour). They are synthetic workload settings, not measured ClearPass frequencies. The `eventId`, native action, category, field names and representative values follow Aruba's [ClearPass 6.11 auditable-event examples](https://arubanetworking.hpe.com/techdocs/ClearPass/6.11/PolicyManager/Content/CPPM_UserGuide/Common%20Compliance/cc_Appendix_A_FAU_GEN.1%20AUDITABLE%20EVENTS_new.htm). Names, addresses, timing and weights are synthetic.

Background activity comes from independent random processes; none of them runs on a fixed period, rotation or script:

- **Administrator sessions.** Ten administrators, including the built-in `admin_user` account, open WebUI sessions at their own random rates, mostly during UTC working hours. A session comes from the administrator's desk, one of two VPN addresses or a shared jump host. About 15% of logins start with one to five mistyped passwords a few seconds apart; a few of those are given up. A session then makes zero to eight configuration changes minutes apart.
- **Stale passwords.** A browser tab or script with an outdated password retries three to eight times about a minute apart; half of them end with a successful login.
- **Outside guesses.** A few times a day, an address from the documentation ranges tries one or more passwords for `admin_user` or another administrator, without success.

The administrators, their desks, VPN addresses and activity rates are fixed per `node_ip`; all activity on top of that differs in every run.

## Anomaly Chain

One administrator fails WebUI login four times from one client, a few seconds to about a minute apart, then logs in successfully from that client. Minutes later, with delays drawn from the same distribution as ordinary configuration changes (limited to what fits in 30 minutes), the account modifies the `Log Service Configuration` and adds an `SSH Public Key`. The pattern fits a guessed administrator password followed by weakened logging and persistent shell access.

Correlate the login records by `user.name`, `source.ip` and `host.name`. Configuration-change records include native `User` but no client IP or login session ID, so their association to the login is only by user, node and time, not a proven session join. Episodes in the measured runs lasted 3-27 minutes.

- **Recurrence.** With `anomaly_mode: true` (the default), the first episode starts within the first `anomaly_interval_hours` (at most 24 hours) of the run, at a time of day drawn from the administrator activity curve. Each next episode is due one interval after the previous actual start; its start is drawn in a window of a quarter interval (at most 6 hours) centred on that due time, weighted towards busy hours. Missed episodes are never caught up. At intervals of 8 hours or less the window covers most of the clock, so episodes also fall into quiet hours.
- **Variation.** Each episode uses a different administrator (chosen in proportion to activity) and a different client from the previous one. The client is one of that administrator's own VPN addresses or the jump host, which the administrator also uses in ordinary sessions. Each successful login has its own Session ID.
- **Background overlap.** Every part of the chain also occurs in ordinary traffic of both modes: repeated failures of one account and client within minutes, failures followed by a success, and log-service changes and SSH key additions after logins. Per 7 days of background, five default runs showed 60-113 cases of four failures of one account and client within 10 minutes, 13-20 cases of four failures followed by a success from that client within 30 minutes, and 41-73 successful logins followed by a log-service change and then an SSH key addition by that account within 30 minutes.
- **Detection.** Only the full order separates the modes. Ordinary traffic never completes four failures and a success from one client, then a log-service change and an SSH key addition by that account, within 30 minutes of the first failure, in any combination of its records: an ordinary SSH key addition that would complete it is left out, and the session's other changes stay as they are. In the measured runs, a rule that correlates these five logins and two changes for one account within 30 minutes, over every combination of records, matched each episode once and never matched `anomaly_mode: false` traffic.

Set `anomaly_mode: false` to keep only background activity.

## Parameters

### Event Parameters

Edit these under `event.template.params` in a local copy of `generator.yml`.

| Name | Default | Purpose |
| --- | --- | --- |
| `anomaly_mode` | `true` | Add the recurring anomaly episodes to the background |
| `anomaly_interval_hours` | `24` | Hours from one episode start to the next due time (3 to 8760) |
| `node_ip` | `10.20.0.10` | ClearPass node and syslog hostname; also fixes the administrator organisation |
| `admin_user` | `admin` | Name of the built-in administrator account; must differ from the names in `samples/admins.json` |
| `software_version` | `6.11.11.261850` | Documented 6.11 example version in `origin` |
| `syslog_priority` | `151` | Synthetic RFC 5424 priority; verify against an Audit Records capture |

### Output Parameters

The shipped file output writes `output/events.json` and requires no credentials or connection parameters. To deliver to a SIEM, replace that output plugin in a local copy with the appropriate destination and its required parameters or secrets.

## Usage

```bash
eventum generate --path generators/identity-aruba-clearpass/generator.yml --id clearpass --live-mode true
```

For a finite batch, add `start` and `end` to the `cron` input in a local copy and run it with `--live-mode false --keep-order true`. The input ticks every second, and a tick without a due record is dropped, so each second holds at most one record.

## Sample Output

This complete JSON event is from a finite run of the shipped default parameters with anomaly mode enabled. It is the successful WebUI login of an episode. `@timestamp` follows the inner audit `Timestamp`; `clearpass.export_timestamp` and the outer syslog timestamp represent the later export.

```json
{
  "@timestamp": "2026-09-25T14:31:46.793Z",
  "clearpass": {
    "action": "None",
    "audit_timestamp": "2026-09-25T14:31:46.793Z",
    "category": "Logged in",
    "component": "Policy Manager UI",
    "description": "User: security-admin\\nRole: Super Administrator\\nAuthentication Source: Policy Manager Local Admin Users\\nSession ID: 47955c47f859d7520970e1dbf5cf2e37\\nClient IP Address: 10.8.1.42\\nSession Inactive Expiry Time: 359 mins",
    "event_id": 3003,
    "export_timestamp": "2026-09-25T14:32:00.833Z",
    "level": "INFO",
    "message_id": "527-1-0",
    "process_id": 26172,
    "software_version": "6.11.11.261850",
    "syslog_priority": 151
  },
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "login-success",
    "category": [
      "authentication"
    ],
    "dataset": "clearpass.audit",
    "kind": "event",
    "original": "<151>1 2026-09-25T14:32:00.833Z 10.20.0.10 ClearPass 26172 527-1-0 [timeQuality tzKnown=\"1\"][origin swVersion=\"6.11.11.261850\" software=\"PolicyManager\" ip=\"10.20.0.10\" enterpriseId=\"1.3.6.1.4.1.14823\"][clearPass@14823 eventId=\"3003\" Action=\"None\" Category=\"Logged in\" Description=\"User: security-admin\\nRole: Super Administrator\\nAuthentication Source: Policy Manager Local Admin Users\\nSession ID: 47955c47f859d7520970e1dbf5cf2e37\\nClient IP Address: 10.8.1.42\\nSession Inactive Expiry Time: 359 mins\" Level=\"INFO\" Component=\"Policy Manager UI\" CppmNode.CPPM-Node=\"10.20.0.10\" Timestamp=\"2026-09-25T14:31:46.793Z\"]",
    "outcome": "success",
    "type": [
      "start"
    ]
  },
  "host": {
    "ip": [
      "10.20.0.10"
    ],
    "name": "10.20.0.10"
  },
  "related": {
    "ip": [
      "10.8.1.42"
    ],
    "user": [
      "security-admin"
    ]
  },
  "source": {
    "ip": "10.8.1.42"
  },
  "user": {
    "name": "security-admin"
  }
}
```

## Coverage and Limits

The six modeled event classes use the native `clearPass@14823` structured-data names and values shown in the selected Aruba audit examples. The full native Audit Records RFC 5424 packet is **not verified**. Aruba's published audit examples begin at the timestamp and omit `<PRI>1`; its published `<151>1` packet is for **Session Logs**, not Audit Records. This generator adds the required RFC 5424 prefix and uses priority `151` as an explicit synthetic assumption. Its process ID, message ID progression, 6–31 second export delay, session IDs, administrator names and addresses, and ordinary activity distribution are also modeled rather than measured. Status: **BLOCKED_RAW_EVIDENCE** until an actual 6.11 Audit Records RFC 5424 export is compared byte for byte. Do not treat this as a native parser acceptance test.

The inner native audit timestamp is used for ECS `@timestamp`; the outer syslog timestamp is retained as `clearpass.export_timestamp`. WebUI descriptions retain the vendor's literal `\n` separators in the decoded raw string, not physical line breaks. ECS fields are a detection-oriented projection of the synthetic raw record. This is the RFC 5424 profile; a CEF parser or a collector configured for Standard/raw needs a different format.

The model covers one node and six audit classes; working hours follow UTC. Because configuration records carry no client address, a rule keyed on the account can join an episode's changes to an ordinary failed-then-successful login of the same account shortly before it.

## References

- [Aruba ClearPass 6.11 Common Criteria auditable-event examples](https://arubanetworking.hpe.com/techdocs/ClearPass/6.11/PolicyManager/Content/CPPM_UserGuide/Common%20Compliance/cc_Appendix_A_FAU_GEN.1%20AUDITABLE%20EVENTS_new.htm)
- [Aruba ClearPass 6.11 syslog export filter and format selection](https://arubanetworking.hpe.com/techdocs/ClearPass/6.11/PolicyManager/Content/CPPM_UserGuide/Admin/syslogExportFilters_add_syslog_filter_general.htm)
- [RFC 5424 syslog format](https://www.rfc-editor.org/rfc/rfc5424)

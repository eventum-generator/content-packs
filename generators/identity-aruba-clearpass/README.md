# Aruba ClearPass Policy Manager audit records

Synthetic ClearPass 6.11 administrative audit records in ECS JSON, with a ClearPass-like syslog message in `event.original`, for testing detections on administrator logins and configuration changes. This profile models the **Audit Records** export template with **RFC 5424** explicitly selected. ClearPass defaults to Standard/raw export, so a default installation will not produce this format.

## Event Types

| Native category / action | Share | ECS category |
| --- | ---: | --- |
| `Logged in` / `None` (WebUI) | 38.5% | Authentication |
| `Account Settings` / `MODIFY` | 21.1% | Configuration |
| `Cluster-wide Parameter` / `MODIFY` | 18.5% | Configuration |
| `Log Service Configuration` / `MODIFY` | 11.1% | Configuration |
| `SSH Public Key` / `ADD` | 8.8% | Configuration |
| `Login Failed` / `None` (WebUI) | 2.1% | Authentication |

Shares are for background activity (`anomaly_mode: false`) with the default settings; failed logins are about 5% of login attempts. They are synthetic workload settings, not measured ClearPass frequencies. The `eventId`, native action, category, field names and representative values follow Aruba's [ClearPass 6.11 auditable-event examples](https://arubanetworking.hpe.com/techdocs/ClearPass/6.11/PolicyManager/Content/CPPM_UserGuide/Common%20Compliance/cc_Appendix_A_FAU_GEN.1%20AUDITABLE%20EVENTS_new.htm). Names, addresses, timing and weights are synthetic.

## Volume and Activity

The node writes about 300 audit records a day. Volume follows a UTC working-day curve: about 2 records an hour at night, rising to about 36 an hour around 12:00, with a daily variation of about 3%.

- **Administrator sessions.** Twelve administrators, including the built-in `admin_user` account, open WebUI sessions at their own steady rates; an administrator has one session at a time. About 12% of sessions are maintenance work on logging and CLI access (mostly log service changes and SSH key additions), mostly from a shared jump host; routine sessions come from the administrator's desk, one of two VPN addresses or the jump host and mostly change account settings and cluster parameters. A session makes one to eight changes minutes apart; some routine sessions only log in.
- **Mistyped passwords.** 1% of logins from a desk, 2% from a VPN laptop and 6% from the jump host start with one to five failures a few seconds apart; one failure is the most common and each longer run is rarer. A few are given up.
- **Stale passwords.** Each administrator changes the password about every 45 days; one of the administrator's clients keeps the old saved password for about a day and retries it three to seven times about half a minute apart before the administrator types the new one, or gives up.
- **Outside guesses.** About every other day, an address from the documentation ranges tries one to six passwords for `admin_user` or another administrator, without success.

The administrators, their desks, VPN addresses and activity weights are fixed per `node_ip`; all activity on top of that differs in every run.

## Anomaly Chain

One administrator fails WebUI login four times from one client, a few seconds to about a minute apart, then logs in successfully from that client. Minutes later, with delays drawn from the same distribution as ordinary configuration changes (limited to what fits in 30 minutes), the account modifies the `Log Service Configuration` and adds an `SSH Public Key`. The pattern fits a guessed administrator password followed by weakened logging and persistent shell access. Episodes last about 3 to 20 minutes.

Correlate the login records by `user.name`, `source.ip` and `host.name`. Configuration-change records include native `User` but no client IP or login session ID, so their association to the login is only by user, node and time, not a proven session join.

- **Recurrence.** With `anomaly_mode: true` (the default), the first episode starts within the first `anomaly_interval_hours` (at most 24 hours), at a time of day drawn from the volume curve. Each next episode is due one interval after the previous actual start; its start falls in a window of a quarter interval (at most 6 hours) centred on that due time, weighted towards busy hours. Missed episodes are never caught up. At intervals of 8 hours or less the window covers most of the clock, so episodes also fall into quiet hours.
- **Variation.** Each episode uses a different administrator (chosen in proportion to activity) and a different client from the previous one. The client is one of that administrator's own VPN addresses or the jump host, which the administrator also uses in ordinary sessions. Each successful login has its own Session ID. The administrator's ordinary sessions continue unchanged during and after an episode.
- **Background overlap.** Every step of the chain and every administrator and client pair an episode can use also occur in ordinary activity: failure runs of one account and client, failures followed by a success, and log-service changes and SSH key additions after logins, mostly in maintenance sessions.
- **Detection.** Ordinary activity never completes four failures and a success from one client, then a log-service change and an SSH key addition by that account, within 30 minutes of the first failure, in any combination of its records: where an ordinary SSH key addition would complete it, the session makes another kind of change at that moment instead. Each episode completes the chain exactly once.
- **Episode records.** Each episode adds its seven records on top of the ordinary activity, so with `anomaly_mode: true` failed logins, and counts of the chain parts, are about one episode's worth per interval higher.

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

The volume and its hour-of-day curve are set in `patterns/floor.yml` (records spread over the whole day) and `patterns/office.yml` (the working-hours peak).

### Output Parameters

The shipped file output writes `output/events.json` and requires no credentials or connection parameters. To deliver to a SIEM, replace that output plugin in a local copy with the appropriate destination and its required parameters or secrets.

## Usage

Live, from the current time:

```bash
eventum generate --path generators/identity-aruba-clearpass/generator.yml --id clearpass --live-mode true
```

For a finite batch, set `start` and `end` of the `oscillator` in both files under `patterns/` of a local copy to the same window (start at midnight, e.g. `start: "2026-09-01T00:00:00+00:00"`, `end: "2026-09-08T00:00:00+00:00"`) and run:

```bash
eventum generate --path generators/identity-aruba-clearpass/generator.yml --id clearpass --live-mode false --keep-order true
```

In live mode, a record arrives after its own audit timestamp: about two minutes later at the median, within 20 minutes for 90% of records, and up to several hours for records of sessions that start during quiet hours; episode records arrive up to about 30 minutes late. The syslog header time and `clearpass.export_timestamp` stay seconds after the audit timestamp, so they lag arrival by the same amount; live detection rules should look back several hours or use ingest time.

Performance: about 1,700 records per second in batch mode (one year of data, about 109,000 records, in about a minute).

## Sample Output

This complete JSON event is from a finite run of the shipped default parameters with anomaly mode enabled. It is the successful WebUI login of an episode. `@timestamp` follows the inner audit `Timestamp`; `clearpass.export_timestamp` and the outer syslog timestamp represent the later export.

```json
{
  "@timestamp": "2026-09-02T15:31:34.441Z",
  "clearpass": {
    "action": "None",
    "audit_timestamp": "2026-09-02T15:31:34.441Z",
    "category": "Logged in",
    "component": "Policy Manager UI",
    "description": "User: platform-admin\\nRole: Super Administrator\\nAuthentication Source: Policy Manager Local Admin Users\\nSession ID: cd5726be9347be2a593fb506b33f7119\\nClient IP Address: 10.8.2.232\\nSession Inactive Expiry Time: 359 mins",
    "event_id": 3003,
    "export_timestamp": "2026-09-02T15:31:51.338Z",
    "level": "INFO",
    "message_id": "1178-1-0",
    "process_id": 31154,
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
    "original": "<151>1 2026-09-02T15:31:51.338Z 10.20.0.10 ClearPass 31154 1178-1-0 [timeQuality tzKnown=\"1\"][origin swVersion=\"6.11.11.261850\" software=\"PolicyManager\" ip=\"10.20.0.10\" enterpriseId=\"1.3.6.1.4.1.14823\"][clearPass@14823 eventId=\"3003\" Action=\"None\" Category=\"Logged in\" Description=\"User: platform-admin\\nRole: Super Administrator\\nAuthentication Source: Policy Manager Local Admin Users\\nSession ID: cd5726be9347be2a593fb506b33f7119\\nClient IP Address: 10.8.2.232\\nSession Inactive Expiry Time: 359 mins\" Level=\"INFO\" Component=\"Policy Manager UI\" CppmNode.CPPM-Node=\"10.20.0.10\" Timestamp=\"2026-09-02T15:31:34.441Z\"]",
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
      "10.8.2.232"
    ],
    "user": [
      "platform-admin"
    ]
  },
  "source": {
    "ip": "10.8.2.232"
  },
  "user": {
    "name": "platform-admin"
  }
}
```

## Source Fidelity and Limits

The six modeled event classes use the native `clearPass@14823` structured-data names and values shown in the selected Aruba audit examples. The full native Audit Records RFC 5424 message has not been compared with a real export: Aruba's published audit examples begin at the timestamp and omit `<PRI>1`, and its published `<151>1` message is for **Session Logs**, not Audit Records. The records add the required RFC 5424 prefix with priority `151` as an assumption. Process ID, message ID progression, the 6–31 second export delay, session IDs, administrator names and addresses, and the activity mix are modeled rather than measured. Do not treat the records as a native parser acceptance test.

The inner native audit timestamp is used for ECS `@timestamp`; the outer syslog timestamp is retained as `clearpass.export_timestamp`. WebUI descriptions retain the vendor's literal `\n` separators in the decoded raw string, not physical line breaks. ECS fields are a detection-oriented projection of the synthetic raw record. This is the RFC 5424 profile; a CEF parser or a collector configured for Standard/raw needs a different format.

The data covers one node and six audit classes; working hours follow UTC and every day of the week looks alike. Every login uses the Super Administrator role. Because configuration records carry no client address, a rule keyed on the account can join an episode's changes to an ordinary failed-then-successful login of the same account shortly before it. With `anomaly_mode: true`, each episode adds its own records, so failed logins and counts of the chain parts are about one episode's worth per interval higher than in background-only data.

## References

- [Aruba ClearPass 6.11 Common Criteria auditable-event examples](https://arubanetworking.hpe.com/techdocs/ClearPass/6.11/PolicyManager/Content/CPPM_UserGuide/Common%20Compliance/cc_Appendix_A_FAU_GEN.1%20AUDITABLE%20EVENTS_new.htm)
- [Aruba ClearPass 6.11 syslog export filter and format selection](https://arubanetworking.hpe.com/techdocs/ClearPass/6.11/PolicyManager/Content/CPPM_UserGuide/Admin/syslogExportFilters_add_syslog_filter_general.htm)
- [RFC 5424 syslog format](https://www.rfc-editor.org/rfc/rfc5424)

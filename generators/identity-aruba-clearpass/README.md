# Aruba ClearPass Policy Manager audit records

Synthetic ClearPass 6.11 administrative audit records in ECS JSON, with a ClearPass-like syslog message in `event.original`. This profile models the **Audit Records** export template with **RFC 5424** explicitly selected. ClearPass defaults to Standard/raw export, so a default installation will not produce this format.

## Event Types

The generator emits one administrative record every five minutes from one ClearPass node. Routine event selection uses these synthetic weights; they are not measured ClearPass frequencies. Four early routine records deliberately exercise the chain's account and sensitive actions in both modes, so observed proportions will differ slightly.

| Native category / action | Routine weight | ECS category |
| --- | ---: | --- |
| `Logged in` / `None` (WebUI) | 45% | Authentication |
| `Login Failed` / `None` (WebUI) | 10% | Authentication |
| `Account Settings` / `MODIFY` | 20% | Configuration |
| `Cluster-wide Parameter` / `MODIFY` | 15% | Configuration |
| `Log Service Configuration` / `MODIFY` | 7% | Configuration |
| `SSH Public Key` / `ADD` | 3% | Configuration |

The `eventId`, native action, category, field names and representative values follow Aruba's [ClearPass 6.11 auditable-event examples](https://arubanetworking.hpe.com/techdocs/ClearPass/6.11/PolicyManager/Content/CPPM_UserGuide/Common%20Compliance/cc_Appendix_A_FAU_GEN.1%20AUDITABLE%20EVENTS_new.htm). Routine names, addresses, timing and weights are synthetic.

## Anomaly Chain

After `anomaly_after_events` routine records, the default `anomaly_mode: true` inserts a seven-record sequence on the same node: four failed WebUI logins for `admin` from `192.0.2.91`, a successful login for that account and client, a `Log Service Configuration` modification by the account, then an `SSH Public Key` addition by the account. Afterward, another sequence starts every `anomaly_interval_events` routine records (144 by default, about 12 hours 35 minutes between episode starts at the shipped cadence). Routine records continue between episodes. Each successful login has a separate native Session ID, and the long time gap distinguishes episodes without adding an artificial episode field. The account, client IP, failed login, log-setting modification and key addition also occur in ordinary traffic; detection should use the short ordered sequence rather than a fixed value or action alone.

Correlate the first five records by `user.name`, `source.ip` and `host.name`. Configuration-change records include native `User` but no client IP or login session ID, so their association to the login is only by user, node and time, not a proven session join. A SIEM rule could require four failures followed by a success and both changes within the next 40 minutes. `anomaly_mode: false` emits only routine records and never enters the chain.

## Parameters

### Event Parameters

Edit these under `event.template.params` in a local copy of `generator.yml`.

| Name | Default | Purpose |
| --- | --- | --- |
| `anomaly_mode` | `true` | Insert recurring sequences |
| `anomaly_after_events` | `80` | Routine records before the first sequence |
| `anomaly_interval_events` | `144` | Routine records between sequence starts; about 12 hours of background |
| `node_ip` | `10.20.0.10` | ClearPass node and syslog hostname |
| `admin_user` | `admin` | Account shared by the sequence and ordinary activity |
| `suspicious_client_ip` | `192.0.2.91` | WebUI client address shared by the sequence and ordinary activity |
| `software_version` | `6.11.11.261850` | Documented 6.11 example version in `origin` |
| `syslog_priority` | `151` | Synthetic RFC 5424 priority; verify against an Audit Records capture |

### Output Parameters

The shipped file output writes `output/events.json` and requires no credentials or connection parameters. To deliver to a SIEM, replace that output plugin in a local copy with the appropriate destination and its required parameters or secrets.

## Usage

From the `content-packs` repository, a short sample run writes to `output/events.json`. The code `124` from `timeout` is expected because the shipped cron source has no finite end.

```bash
flock -x /tmp/eventum-generator-heavy.lock timeout 3s eventum generate --path generators/identity-aruba-clearpass/generator.yml --id clearpass-sample --live-mode false
```

For continuous generation, use:

```bash
eventum generate --path generators/identity-aruba-clearpass/generator.yml --id clearpass-live --live-mode true
```

## Sample Output

This complete JSON event is from a finite run of the shipped default parameters with anomaly mode enabled. It is the successful WebUI login in the sequence. `@timestamp` follows the inner audit `Timestamp`; `clearpass.export_timestamp` and the outer syslog timestamp represent the later export.

```json
{
  "@timestamp": "2026-09-25T07:00:00.222Z",
  "clearpass": {
    "action": "None",
    "audit_timestamp": "2026-09-25T07:00:00.222Z",
    "category": "Logged in",
    "component": "Policy Manager UI",
    "description": "User: admin\\nRole: Super Administrator\\nAuthentication Source: Policy Manager Local Admin Users\\nSession ID: ba08937b0a6f9384a55e982da2bf25c6\\nClient IP Address: 192.0.2.91\\nSession Inactive Expiry Time: 359 mins",
    "event_id": 3003,
    "export_timestamp": "2026-09-25T07:00:08.640Z",
    "level": "INFO",
    "message_id": "199-1-0",
    "process_id": 41040,
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
    "original": "<151>1 2026-09-25T07:00:08.640Z 10.20.0.10 ClearPass 41040 199-1-0 [timeQuality tzKnown=\"1\"][origin swVersion=\"6.11.11.261850\" software=\"PolicyManager\" ip=\"10.20.0.10\" enterpriseId=\"1.3.6.1.4.1.14823\"][clearPass@14823 eventId=\"3003\" Action=\"None\" Category=\"Logged in\" Description=\"User: admin\\nRole: Super Administrator\\nAuthentication Source: Policy Manager Local Admin Users\\nSession ID: ba08937b0a6f9384a55e982da2bf25c6\\nClient IP Address: 192.0.2.91\\nSession Inactive Expiry Time: 359 mins\" Level=\"INFO\" Component=\"Policy Manager UI\" CppmNode.CPPM-Node=\"10.20.0.10\" Timestamp=\"2026-09-25T07:00:00.222Z\"]",
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
      "192.0.2.91"
    ],
    "user": [
      "admin"
    ]
  },
  "source": {
    "ip": "192.0.2.91"
  },
  "user": {
    "name": "admin"
  }
}
```

## Coverage and Limits

The six modeled event classes use the native `clearPass@14823` structured-data names and values shown in the selected Aruba audit examples. The full native Audit Records RFC 5424 packet is **not verified**. Aruba's published audit examples begin at the timestamp and omit `<PRI>1`; its published `<151>1` packet is for **Session Logs**, not Audit Records. This generator adds the required RFC 5424 prefix and uses priority `151` as an explicit synthetic assumption. Its process ID, message ID progression, 6–31 second export delay, session IDs and ordinary activity distribution are also modeled rather than measured. Status: **BLOCKED_RAW_EVIDENCE** until an actual 6.11 Audit Records RFC 5424 export is compared byte for byte. Do not treat this as a native parser acceptance test.

The inner native audit timestamp is used for ECS `@timestamp`; the outer syslog timestamp is retained as `clearpass.export_timestamp`. WebUI descriptions retain the vendor's literal `\n` separators in the decoded raw string, not physical line breaks. ECS fields are a detection-oriented projection of the synthetic raw record. This is the RFC 5424 profile; a CEF parser or a collector configured for Standard/raw needs a different format.

## References

- [Aruba ClearPass 6.11 Common Criteria auditable-event examples](https://arubanetworking.hpe.com/techdocs/ClearPass/6.11/PolicyManager/Content/CPPM_UserGuide/Common%20Compliance/cc_Appendix_A_FAU_GEN.1%20AUDITABLE%20EVENTS_new.htm)
- [Aruba ClearPass 6.11 syslog export filter and format selection](https://arubanetworking.hpe.com/techdocs/ClearPass/6.11/PolicyManager/Content/CPPM_UserGuide/Admin/syslogExportFilters_add_syslog_filter_general.htm)
- [RFC 5424 syslog format](https://www.rfc-editor.org/rfc/rfc5424)

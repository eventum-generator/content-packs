# Imperva SecureSphere WAF alerts (CEF)

Web application firewall security alerts and management console system events of Imperva SecureSphere 14.x, sent by the Management Server syslog action sets in CEF. Each record is ECS JSON with the native syslog message in `event.original`; field names follow the Elastic Imperva integration (`imperva.securesphere`). For SOC analysts and detection engineers who need WAF alert traffic with a recurring client that moves from one attacked application to another.

## Event Types

Shares measured over 120 hours with the default settings (`anomaly_mode: true`, 48,860 records, 5 episodes).

| CEF class ID | Event | `act` | Share | ECS `event.kind` |
|---|---|---|---|---|
| `Signature` | Signature violation (7 rules: SQL injection, cross-site scripting, traversal and more) | `none` / `block` | 42.9% / 17.5% | `alert` |
| `Profile` | Profile violation (4 rules: unknown parameter, value length and more) | `none` / `block` | 17.0% / 0.9% | `alert` |
| `Protocol` | HTTP protocol violation (4 rules) | `none` / `block` | 14.8% / 1.7% | `alert` |
| `Correlation` | Correlation alert (2 rules) | `none` / `block` | 2.3% / 2.7% | `alert` |
| `User logged in` | Management console login (system event) | - | 0.2% | `event` |

The shares are synthetic workload weights, not measured Imperva rates. Alert names, policy names, descriptions, server groups, services and applications are configurable SecureSphere metadata; the shipped values are examples, not a vendor signature catalog (`suspicious-pattern` with severity `High` and `Recommended Signatures Policy for Web Applications` come from the Elastic fixture). Alerts of traffic without a signed-in application user keep the unresolved `duser=${Alert.username}` placeholder, as in the Elastic fixture of a SecureSphere 15.0 alert; about a quarter of the alerts carry a user name.

## Background Model

The protected estate is five web applications in four server groups (seven servers); the HR Portal is reachable from the internal network only. 600 client addresses (`samples/clients.csv`: 396 from external networks, 204 internal) each have an activity weight, a home application that takes about 70% of their alerts, a second application with about 20%, and the rest spread over the applications by weight. Every address belongs to one application user (106 users in all), who is named in the alert when the client is signed in.

The firewall reports about 9,750 records a day, all times UTC:

- Single alerts on ordinary traffic (false positives, profile deviations of signed-in users, odd clients) follow the working day of the users: about 95 an hour at night (21:00-07:00), about 240 an hour at 07:00-09:00 and 18:00-21:00, and about 360 an hour at 09:00-18:00.
- About 1,600 bursts a day of scanners, attack tools and broken clients, around the clock (about 58 an hour at night, 75 by day): one to six signature and protocol violations of one client against one application, a median of about 40 s apart, a quarter of them followed by a correlation alert a minute or two later. Rules repeat inside a burst.
- Standalone correlation alerts over traffic that raised no single alert, about 90 a day.
- About 23 console logins a day by three administrators, almost all at 08:00-18:00.

Together this gives about 255 records an hour at night, 420 at 07:00-09:00 and 18:00-21:00, and 560 at 09:00-18:00. Daily totals vary by about 3%.

## Anomaly Chain

`anomaly_mode` defaults to `true`. With `false` the generator emits the background only and the complete chain never occurs.

Sequence, all for one client C (`src` / `source.ip`), within 30 minutes:

1. Signature violation from C on application A (`cs4` / `imperva.securesphere.device.custom_string4.value`, with its `cs2` server group, `cs3` service and `dst` servers), rule R1.
2. Signature violation from C on A with a different rule R2. The burst holds two to six alerts; rules repeat, protocol violations may be mixed in, and a quarter of bursts get a correlation alert on A, as in the background.
3. Signature violation from C on another application B, a few minutes after the burst (lognormal lag, median 4 minutes, kept inside the window): the client moves on to the next application.

Linking fields: `src` / `source.ip` in all steps; the same `cs4` in steps 1-2 with distinct `name` / `imperva.securesphere.name`; a different `cs4` (and `cs2`, `cs3`, `dst`) in step 3. Episodes spanned 1 to 17 minutes from the first violation on A inside the window to the violation on B.

Recurrence: the first episode starts within the first `anomaly_interval_hours` (at most 24 h) of generation, at a time drawn from the hourly rate of bursts, not at a fixed offset from the generation start. Each next episode is due `anomaly_interval_hours` after the actual start of the previous one and starts in a window of a quarter of the interval (at most 6 h) centred on the due time, weighted toward the busier burst hours. Missed episodes are not caught up.

Variation: the client, A and B differ from the previous episode's. The client is one of the 49 clients busy enough on two applications that both client-application pairs occur in every few days of background (at least about 20 signature violations over four days on each), drawn by activity weight among those with no signature violation in the last 30 minutes and no burst running; A and B are drawn by that client's own application shares. Burst size, rules, gaps, user, `act` and the correlation follow-up follow the background law; the burst is conditioned on two or more distinct signature rules. The rule and `act` of the violation on B follow the background signature law. The episode's records come in place of about as many background records at those moments, so the hourly volume is the same in both modes; during an episode the client's signature violations on other applications are reported on application A.

Nothing in the chain is unique to it: multi-rule bursts on one application, correlation alerts after them, and clients raising signature violations on their other applications all occur in background of both modes, and every episode client occurs with both of its applications in background. Only the complete sequence is kept out of ordinary traffic: when a client has raised two distinct signature rules on one application within the last 30 minutes, its further signature violations within that time are reported on that application (time, client and rule as drawn).

Detection idea: a client that triggered two distinct signature rules on one application then triggers a signature on another application within 30 minutes.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Meaning |
|---|---|---|
| `anomaly_mode` | `true` | Add periodic episodes to the background |
| `anomaly_interval_hours` | `24` | Hours between episode starts, 2-8760 |
| `device_version` | `14.16.1.10_0` | CEF Device Version (typed into the action set message) |
| `syslog_pri` | `14` | Syslog PRI prefix (facility and level of the action set) |
| `signature_policy` | `Recommended Signatures Policy for Web Applications` | `cs1` of signature violations |
| `protocol_policy` | `Web Protocol Policy` | `cs1` of protocol violations |
| `profile_policy` | `Web Profile Policy` | `cs1` of profile violations |
| `correlation_policy` | `Web Correlation Policy` | `cs1` of correlation alerts |

The estate is described in `samples/`:

- `clients.csv` - client addresses: `ip`, `zone` (`internal` or `external`), activity `weight`, `home` and `second` application names, application `user`.
- `applications.json` - applications: `server_group`, `service`, `application`, `servers`, `port`, `weight` (share of the spread alerts), `internal_only`; at least two.
- `rules.json` - alert rules: `kind` (`Signature`, `Protocol`, `Profile`, `Correlation`), `name`, `description`, `severity` (`Low`, `Medium`, `High`), `weight`; at least three signature rules.
- `admins.json` - console administrators: `name`, `ip`, `weight`.

The volume and the hour curve are set in `patterns/`: `traffic-floor.yml`, `traffic-day.yml` and `traffic-office.yml` are stacked hour bands of single alerts (records a day in `multiplier.ratio`, hours as fractions of the day in `spreader.parameters`), `automation.yml` the flat stream of bursts, `console-floor.yml` and `console-office.yml` the console logins. Scale the ratios to change the volume.

### Output Parameters

The shipped `generator.yml` writes to a local file and uses no `${params.*}` or `${secrets.*}` placeholders. To send events to a backend, replace the `output` block and parameterize its endpoint and credentials, for example `hosts: ["${params.opensearch_host}"]` and `password: ${secrets.opensearch_password}`, then pass `--params '{"opensearch_host": "..."}'` and store the secret in the Eventum keyring.

## Usage

```bash
# Live: records at the rates above, in real time
eventum generate --path generators/security-imperva-securesphere/generator.yml --id securesphere --live-mode true

# Batch: as fast as possible over a finite window (see below)
eventum generate --path generators/security-imperva-securesphere/generator.yml --id securesphere --live-mode false
```

Events go to `generators/security-imperva-securesphere/output/events.json`.

The files in `patterns/` start at midnight UTC of the current day and never end. For a finite batch window, set `start` to a midnight and `end` in every file, for example `start: "2026-10-05T00:00:00+00:00"` and `end: "+96h"`; a start other than midnight shifts the hour curve.

Performance: about 1,500 events/s (14 days, 136,000 records, in 89 s).

## Limitations

- Only the security event (non-firewall) and system event action-set templates. Firewall alerts (different `cs3`, no `cs4`/`cs5`), custom policy alerts, DAM audit events and database alerts are not generated; of system events only console logins.
- The complete CEF template is documented in the SecureSphere CEF guide for versions 6.2-8.5. It is used here for 14.x because the v14 placeholder guide keeps the same placeholders and the Elastic fixtures from 14.16 and 15.0 carry the same extension keys; no vendor document states it for 14.x.
- `act` values: `block` is taken from the Elastic fixture; the guide describes the other outcome only as "no action", and the literal `none` is an assumption.
- Alert severity is fixed per rule (Low, Medium, High); the console login severity `High` is taken from the Elastic fixtures.
- Whole-second timestamps as in `rt` (`@timestamp` and `receipt_time` end in `.000Z` as in the Elastic documents); several records can share a second, and `rt` carries no time zone (UTC is used).
- The same 600 client addresses recur every day; no new addresses appear over time, and each address signs in as one user.
- Every day follows the same UTC hour curve; weekends and holidays are not quieter.
- Within 30 minutes after a client raises two distinct signature rules on one application, its further signature violations stay on that application, so moves to another application in that time are about a quarter as frequent as in the following half hour.
- With `anomaly_mode: true` each episode adds its own records (a multi-rule burst on one application and one signature violation on another), so these patterns are about one per episode more frequent than with `anomaly_mode: false`.
- The syslog PRI is constant, as one action set has one facility and level. JSON escaping writes `<` as `\u003c` in `event.original`.

## Sample Output

The violation on the second application that closes the first episode of a 120-hour default run:

```json
{"@timestamp": "2026-10-05T14:27:16.000Z", "destination": {"ip": "10.43.22.30", "port": 8443, "user": {"name": "${Alert.username}"}}, "ecs": {"version": "8.17.0"}, "event": {"action": "block", "code": "Signature", "kind": "alert", "original": "\u003c14\u003eCEF:0|Imperva Inc.|SecureSphere|14.16.1.10_0|Signature|SQL Injection|High|act=block dst=10.43.22.30 dpt=8443 duser=${Alert.username} src=203.0.113.176 spt=50806 proto=TCP rt=Oct 05 2026 14:27:16 cat=Alert cs1=Recommended Signatures Policy for Web Applications cs1Label=Policy cs2=Partner-SG cs2Label=ServerGroup cs3=Partner-API cs3Label=ServiceName cs4=Partner API cs4Label=ApplicationName cs5=SQL injection pattern in parameter cs5Label=Description", "severity": 7}, "imperva": {"securesphere": {"destination": {"address": "10.43.22.30", "port": 8443, "user_name": "${Alert.username}"}, "device": {"action": "block", "custom_string1": {"label": "Policy", "value": "Recommended Signatures Policy for Web Applications"}, "custom_string2": {"label": "ServerGroup", "value": "Partner-SG"}, "custom_string3": {"label": "ServiceName", "value": "Partner-API"}, "custom_string4": {"label": "ApplicationName", "value": "Partner API"}, "custom_string5": {"label": "Description", "value": "SQL injection pattern in parameter"}, "event": {"category": "Alert", "class_id": "Signature"}, "product": "SecureSphere", "receipt_time": "2026-10-05T14:27:16.000Z", "vendor": "Imperva Inc.", "version": "14.16.1.10_0"}, "name": "SQL Injection", "severity": "High", "source": {"address": "203.0.113.176", "port": 50806}, "transport_protocol": "TCP", "version": "0"}}, "message": "SQL Injection", "network": {"transport": "tcp"}, "observer": {"product": "SecureSphere", "vendor": "Imperva Inc.", "version": "14.16.1.10_0"}, "related": {"ip": ["10.43.22.30", "203.0.113.176"], "user": ["${Alert.username}"]}, "service": {"name": "Partner-API"}, "source": {"ip": "203.0.113.176", "port": 50806}, "tags": ["preserve_original_event", "preserve_duplicate_custom_fields"]}
```

## References

- [Imperva SecureSphere CEF Connector Configuration Guide (versions 6.2-8.5)](https://www.imperva.com/docs/sb_imperva_securesphere_cef_guide.pdf)
- [Imperva SecureSphere v14 Standard Placeholders User Guide](https://docs-be.imperva.com/bundle/v14.x-standard-placeholders/raw/resource/enus/v14.x-standard-placeholders.pdf)
- [Elastic Imperva integration, SecureSphere data stream](https://github.com/elastic/integrations/tree/main/packages/imperva/data_stream/securesphere)

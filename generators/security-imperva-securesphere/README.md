# Imperva SecureSphere WAF alerts (CEF)

Web application firewall security alerts and management console system events of Imperva SecureSphere 14.x, sent by the Management Server syslog action sets in CEF. Each record is ECS JSON with the native syslog message in `event.original`; field names follow the Elastic Imperva integration (`imperva.securesphere`).

The protected estate is five web applications in four server groups (seven servers). About 300 clients (70% from external networks, 30% internal) each have their own activity weight and a home application that takes about 85% of their alerts, and about 60 application users sign in to them. Traffic is a superposition of independent random processes: single alerts of ordinary traffic (false positives, profile deviations of signed-in users; busier during the working day), bursts of one to six signature and protocol violations from one client against one application (scanners, attack tools, broken clients; flat over the day), a quarter of them followed by a correlation alert, standalone correlation alerts, and console logins of three administrators.

## Event types

Shares measured on a 78-hour default capture (`anomaly_mode: true`, 7,444 events, 3 episodes).

| CEF class ID | Event | `act` | Share | ECS `event.kind` |
|---|---|---|---|---|
| `Signature` | Signature violation (7 rules: SQL injection, cross-site scripting, traversal and more) | `none` / `block` | 41.1% / 17.4% | `alert` |
| `Profile` | Profile violation (4 rules: unknown parameter, value length and more) | `none` / `block` | 20.0% / 1.1% | `alert` |
| `Protocol` | HTTP protocol violation (4 rules) | `none` / `block` | 13.8% / 1.8% | `alert` |
| `Correlation` | Correlation alert (2 rules) | `none` / `block` | 1.6% / 2.3% | `alert` |
| `User logged in` | Management console login (system event) | - | 0.9% | `event` |

The shares are synthetic workload weights, not measured Imperva rates. Alert names, policy names, descriptions, server groups, services and applications are configurable SecureSphere metadata; the shipped values are examples, not a vendor signature catalog (`suspicious-pattern` with severity `High` and `Recommended Signatures Policy for Web Applications` come from the Elastic fixture). Alerts of traffic without an application user keep the unresolved `duser=${Alert.username}` placeholder, as in the Elastic fixture of a SecureSphere 15.0 alert.

## Anomaly Chain

`anomaly_mode` defaults to `true`. With `false` the generator emits the background only and the complete chain never occurs.

Sequence, all for one client C (`src` / `source.ip`), within 30 minutes:

1. Signature violation from C on application A (`cs4` / `imperva.securesphere.device.custom_string4.value`, with its `cs2` server group, `cs3` service and `dst` servers), rule R1.
2. Signature violation from C on A with a different rule R2. The burst holds two to six alerts; rules repeat, protocol violations may be mixed in, and a quarter of bursts get a correlation alert on A, as in the background.
3. Signature violation from C on another application B, a few minutes after the burst (lognormal lag, median 4 minutes, kept inside the window): the client moves on to the next application.

Linking fields: `src` / `source.ip` in all steps; the same `cs4` in steps 1-2 with distinct `name` / `imperva.securesphere.name`; a different `cs4` (and `cs2`, `cs3`, `dst`) in step 3.

Recurrence: an episode becomes due every `anomaly_interval_hours` of source time (default 24, minimum 2), first one interval after generation starts. It starts after a random delay (exponential, mean 20 minutes); the next due time counts from the actual start, so a late episode never causes catch-up. The time of day of episodes is therefore set by the generation start and drifts later by the delays; background bursts are flat over the day. Episodes in the final captures spanned 1.5 to 29 minutes from the first violation on A inside the window (which can be a background one) to the violation on B.

Variation: the client, A and B differ from the previous episode's. They come from recent background alerts of a client seen on two or more applications, so they keep the background weighting and both client-application pairs also occur in ordinary traffic. Burst size, rules, gaps, user, `act` and the correlation follow-up follow the background law; the burst is conditioned on two or more distinct signature rules. The rule and `act` of the violation on B follow the background signature law.

Detection idea: a client that triggered two distinct signature rules on one application then triggers a signature on another application within 30 minutes. Every fragment occurs in background of both modes: multi-rule bursts on one application, correlation alerts after them (the block share of background correlation alerts is 55% after two or more rules, 58% after one rule and 57% after none; five 78-hour background captures pooled), and clients raising signatures on a second application (about 1% of single-rule starts are followed by one in each 10-minute step). Only the complete sequence is kept out of the background: a background signature violation of a client that raised two or more distinct rules on another application within the last 1800 s (the chain window) is reported on that application instead; time, client and rule stay unchanged. The guard fires on about 2% of background multi-rule bursts: after a multi-rule burst, the share followed by a signature on another application in 10-minute steps is 0.17% / 0.27% / 0.54% inside the window and 0.97% / 0.90% / 1.14% in the next 30 minutes, matching single-rule starts (0.8-1.1%).

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Meaning |
|---|---|---|
| `anomaly_mode` | `true` | Add periodic episodes to the background |
| `anomaly_interval_hours` | `24` | Episode interval in source hours, 2-8760 |
| `device_version` | `14.16.1.10_0` | CEF Device Version (typed into the action set message) |
| `syslog_pri` | `14` | Syslog PRI prefix (facility and level of the action set) |
| `client_count` | `300` | Client addresses, 40-600 |
| `external_networks` | 3 networks | Networks of external clients |
| `internal_network` | `10.60.0.0/16` | Network of internal clients |
| `external_share` | `0.7` | Share of external clients |
| `user_count` | `60` | Application users, 5-500 |
| `admins` | 3 admins | Console administrators (`name`, `ip`) |
| `applications` | 5 applications | `server_group`, `service`, `application`, `servers`, `port`, `weight`; at least two |
| `signature_policy` | `Recommended Signatures Policy for Web Applications` | `cs1` of signature violations |
| `protocol_policy` | `Web Protocol Policy` | `cs1` of protocol violations |
| `profile_policy` | `Web Profile Policy` | `cs1` of profile violations |
| `correlation_policy` | `Web Correlation Policy` | `cs1` of correlation alerts |
| `signatures` | 7 rules | Signature violations (`name`, `description`, `severity`, `weight`), at least three |
| `protocol_violations` | 4 rules | Protocol violations |
| `profile_violations` | 4 rules | Profile violations |
| `correlations` | 2 rules | Correlation alerts |

### Output Parameters

The shipped `generator.yml` writes to a local file and uses no `${params.*}` or `${secrets.*}` placeholders. To send events to a backend, replace the `output` block and parameterize its endpoint and credentials, for example `hosts: ["${params.opensearch_host}"]` and `password: ${secrets.opensearch_password}`, then pass `--params '{"opensearch_host": "..."}'` and store the secret in the Eventum keyring.

## Usage

Live mode:

```bash
eventum generate --path generators/security-imperva-securesphere/generator.yml --id securesphere --live-mode true
```

Batch mode (bound the run with `start` / `end` on the `cron` input for a finite capture):

```bash
eventum generate --path generators/security-imperva-securesphere/generator.yml --id securesphere --live-mode false
```

Events go to `generators/security-imperva-securesphere/output/events.json`.

## Limitations

- Only the security event (non-firewall) and system event action-set templates. Firewall alerts (different `cs3`, no `cs4`/`cs5`), custom policy alerts, DAM audit events and database alerts are not modeled; of system events only console logins.
- The complete CEF template is documented in the SecureSphere CEF guide for versions 6.2-8.5. It is used here for 14.x because the v14 placeholder guide keeps the same placeholders and the Elastic fixtures from 14.16 and 15.0 carry the same extension keys; no vendor document states it for 14.x.
- `act` values: `block` is taken from the Elastic fixture; the guide describes the other outcome only as "no action", and the literal `none` is an assumption.
- Alert severity is fixed per rule (Low, Medium, High); the console login severity `High` is taken from the Elastic fixtures.
- One event per second at most, with whole-second timestamps as in `rt` (`@timestamp` and `receipt_time` end in `.000Z` as in the Elastic documents); `rt` carries no time zone (UTC is used).
- The chain guard lowers the rate of moves to a second application inside 30 minutes after a multi-rule burst (see Detection idea); a detector on that step alone sees the dip only across many bursts.
- The syslog PRI is constant, as one action set has one facility and level. JSON escaping writes `<` as `\u003c` in `event.original`.

## Sample output

The violation on the second application that closes the first episode of the final default capture:

```json
{"@timestamp": "2026-09-27T01:03:26.000Z", "destination": {"ip": "10.43.21.20", "port": 443, "user": {"name": "${Alert.username}"}}, "ecs": {"version": "8.17.0"}, "event": {"action": "block", "code": "Signature", "kind": "alert", "original": "\u003c14\u003eCEF:0|Imperva Inc.|SecureSphere|14.16.1.10_0|Signature|SQL Injection|High|act=block dst=10.43.21.20 dpt=443 duser=${Alert.username} src=192.0.2.130 spt=57931 proto=TCP rt=Sep 27 2026 01:03:26 cat=Alert cs1=Recommended Signatures Policy for Web Applications cs1Label=Policy cs2=Shop-SG cs2Label=ServerGroup cs3=Shop-HTTPS cs3Label=ServiceName cs4=Online Store cs4Label=ApplicationName cs5=SQL injection pattern in parameter cs5Label=Description", "severity": 7}, "imperva": {"securesphere": {"destination": {"address": "10.43.21.20", "port": 443, "user_name": "${Alert.username}"}, "device": {"action": "block", "custom_string1": {"label": "Policy", "value": "Recommended Signatures Policy for Web Applications"}, "custom_string2": {"label": "ServerGroup", "value": "Shop-SG"}, "custom_string3": {"label": "ServiceName", "value": "Shop-HTTPS"}, "custom_string4": {"label": "ApplicationName", "value": "Online Store"}, "custom_string5": {"label": "Description", "value": "SQL injection pattern in parameter"}, "event": {"category": "Alert", "class_id": "Signature"}, "product": "SecureSphere", "receipt_time": "2026-09-27T01:03:26.000Z", "vendor": "Imperva Inc.", "version": "14.16.1.10_0"}, "name": "SQL Injection", "severity": "High", "source": {"address": "192.0.2.130", "port": 57931}, "transport_protocol": "TCP", "version": "0"}}, "message": "SQL Injection", "network": {"transport": "tcp"}, "observer": {"product": "SecureSphere", "vendor": "Imperva Inc.", "version": "14.16.1.10_0"}, "related": {"ip": ["10.43.21.20", "192.0.2.130"], "user": ["${Alert.username}"]}, "service": {"name": "Shop-HTTPS"}, "source": {"ip": "192.0.2.130", "port": 57931}, "tags": ["preserve_original_event", "preserve_duplicate_custom_fields"]}
```

## References

- [Imperva SecureSphere CEF Connector Configuration Guide (versions 6.2-8.5)](https://www.imperva.com/docs/sb_imperva_securesphere_cef_guide.pdf)
- [Imperva SecureSphere v14 Standard Placeholders User Guide](https://docs-be.imperva.com/bundle/v14.x-standard-placeholders/raw/resource/enus/v14.x-standard-placeholders.pdf)
- [Elastic Imperva integration, SecureSphere data stream](https://github.com/elastic/integrations/tree/main/packages/imperva/data_stream/securesphere)

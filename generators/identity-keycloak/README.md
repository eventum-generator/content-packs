# Keycloak Event Log Generator

Generates Keycloak 26.7.4 `jboss-logging` event listener lines (user and admin events) for one realm, as Elastic Agent's Keycloak integration indexes them. `event.original` holds the native log line; `keycloak.*`, `user.*`, `source.*` and `url.*` follow the Elastic `keycloak.log` ingest pipeline.

The realm has 1,500 users and 5 administrators. Users log in to one to three OIDC clients; some attempts start with wrong passwords; each login is followed by the authorization-code exchange and sometimes by a logout. Administrators work mostly in `security-admin-console`, where they grant and remove realm roles, and connect over VPN for 40-50% of their attempts. Addresses are the account's workstation or one of three VPN egress addresses shared by all remote staff.

## Volume and Timing

Event volume follows a UTC hour-of-day curve, about 29,000 events per day with ±10% day-to-day variation; events fall at random times inside each band.

| UTC hours | Events/s |
|---|---:|
| 08-18 | 0.60 |
| 07-08, 18-20 | 0.30 |
| 20-23 | 0.15 |
| 23-07 | 0.09 |

Each account's activity follows the same curve. The records of one login follow each other within seconds: wrong passwords a median 12 s apart, `CODE_TO_TOKEN` a median 2.8 s after `LOGIN` (9 s at night) and never more than 55 s after it, within Keycloak's one-minute Client Login Timeout. About 0.1% of `LOGIN`s, nearly all at night, have no `CODE_TO_TOKEN` because the code expired.

## Event Types Covered

Shares over six days of a default run (`anomaly_mode: true`); the last column shows how much they vary between six-day periods without anomalies.

| Action | Share | Range | Category | Meaning |
|---|---:|---:|---|---|
| `LOGIN` | 39.26% | 39.11-39.25% | authentication | Browser login to an OIDC client |
| `CODE_TO_TOKEN` | 39.21% | 39.07-39.22% | authentication | Authorization-code exchange after `LOGIN` |
| `LOGOUT` | 11.67% | 11.70-11.85% | authentication | Logout of a session (30% of user sessions, 50% of admin console sessions) |
| `LOGIN_ERROR` | 9.47% | 9.29-9.59% | authentication | `invalid_user_credentials`; 12% of attempts start with 1-8 wrong passwords (each extra failure half as likely), 15% of those give up; administrators over VPN sometimes type a rotated password 3-8 times (below) |
| `CREATE-REALM_ROLE_MAPPING` | 0.22% | 0.18-0.25% | iam | Realm role granted to a user in the admin console |
| `DELETE-REALM_ROLE_MAPPING` | 0.17% | 0.16-0.20% | iam | Realm role removed, including expiry of time-bound `secops-admin` grants |

The rates are synthetic, not a vendor-published distribution. Users average 7.7 logins per day and administrators 12; administrators log in to `security-admin-console` (85%) or `account-console`. Administrator passwords are rotated by a vault. Over VPN an administrator types the admin console password by hand and sometimes types the previous one, retrying it 3-8 times before fetching the new one: 7% of VPN admin console attempts, and 45% of the attempts that directly follow such an attempt. About 90% then log in and go on with the console work they came for (at least one operation). Administrator attempts from a VPN address with five or more failures, mostly of this kind, happen about 11 times a week across the five administrators.

## Anomaly Chain

`anomaly_mode` defaults to `true`. With `false` the generator writes only the background described above and never the complete chain.

Sequence, per `user.id` + `source.ip`, within 15 minutes (typically 1-6 minutes from the first failure to the grant):

1. Five to eight `LOGIN_ERROR` (`invalid_user_credentials`) for one administrator from one VPN egress address, seconds apart, all in one browser authentication session (same `code_id` / `authSessionParentId`).
2. `LOGIN` of that administrator to `security-admin-console` from the same address; `sessionId` equals the attempt's `code_id`.
3. `CODE_TO_TOKEN` for that session (`onltac:` token id).
4. `CREATE-REALM_ROLE_MAPPING` granting the privileged realm role (`secops-admin`) to a user who does not hold it, by the same administrator and address. The session may continue with further ordinary grants and removals.

Linking fields: `user.id`, `source.ip`, `keycloak.session.id` / `keycloak.login.code_id`, `user.target.id`, and the role name in the `representation` inside `event.original`.

Volume: episodes do not change the event volume or the hour curve; an episode's records take the place of about ten background records out of some 29,000 a day. During the episode the administrator has no other login in progress, as with any login. Episode records keep the same timing as ordinary logins, including the 55 s limit on the code exchange; in the rare case (at night only) where the exchange would come later, the episode ends after `LOGIN`, stays incomplete, and the next episode is still due one interval after its start.

Restoration: every `secops-admin` grant, background or episode, is time-bound; after a lognormal lease (median 8 h) the next admin console session removes it with `DELETE-REALM_ROLE_MAPPING`, typically 5-30 hours after the grant; a grant made near the end of a run can still be in place when it ends.

Recurrence: `anomaly_interval_hours` (default 24, minimum 6, maximum 720), counted in source time. The first episode starts within the first min(interval, 24 h), its hour drawn from the background hour curve, so about 9% of first starts fall at night (23-07 UTC). Each later episode is due one interval after the actual previous start and starts at a random time in a window of w = min(interval / 4, 6 h) centred on the due time, weighted by the squared hour curve plus a small floor; missed time is never caught up. An episode never uses the previous episode's administrator, and waits until the chosen one has no login in progress, which can delay it slightly. The squared weighting pulls each later start by up to w / 2 toward office hours, so at the default interval a run that begins at night moves into the working day within a few episodes (night share: 9% of first starts, 6% of second starts, about 2% over 20 episodes). Consecutive starts are 21-27 h apart at the default interval and 10.5-13.5 h apart at 12 h. Intervals of 12 h or less put every other start into evening or night hours (night share about 30%), and at 8 h or less the start phase necessarily covers the whole clock.

Variation: more active administrators are chosen more often, never the previous episode's; the target is never the previous episode's target; the address is any of the three VPN egress addresses; the number of failures (5-8) is distributed like the administrators' stale-password bursts of that length.

Background overlap: every element of the chain also occurs in ordinary traffic in both modes. Every administrator + VPN address pair (5 x 3) logs in at least three times a week. Administrators over VPN sometimes type the previous, vault-rotated password several times before fetching the new one: about 11 bursts of five or more wrong passwords a week across the five administrators (roughly 3 to 19 in a given week), most followed by a login and often by a role grant within 15 minutes. These retries cluster: an administrator who hit a stale password is likely to hit it again in the next sessions, so some administrator-days hold several such bursts. `secops-admin` grants happen 8-12 times a day in both modes.

Detection idea: at least five failed logins for one account from one address, then a successful admin console login and a privileged role grant by that account and address within 15 minutes.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Name | Default | Description |
|---|---|---|
| `anomaly_mode` | `true` | Emit recurring anomaly episodes; `false` gives background only |
| `anomaly_interval_hours` | `24` | Source-time interval between episodes (6-720) |
| `realm` | `corp` | Realm name |
| `realm_id` | `523dd4a1-c4d0-4cf1-acb4-ea0f1de7e9c4` | Realm id (also the role `containerId`) |
| `sso_base_url` | `https://sso.corp.example` | Keycloak base URL used in `account-console` and admin console redirect URIs |
| `admin_console_client_uuid` | `3f1c9b52-8d47-4e0a-b6d2-71a95c0e4f83` | Internal id of `security-admin-console`, logged as `clientId` of admin events |
| `privileged_role_name` | `secops-admin` | Privileged realm role granted by the chain |
| `privileged_role_id` | `b18f4680-7b51-450e-89f2-65d98024e7b7` | Id of that role |
| `vpn_nat_ips` | `[10.20.200.10, 10.20.200.11, 10.20.200.12]` | VPN egress addresses shared by remote staff |
| `hostname` | `keycloak-01.corp.example` | Keycloak host and agent name |
| `host_ip` | `10.20.1.15` | Keycloak host address |
| `collector_id` | `a0634c5c-35db-4f7a-8273-73052fa14208` | Elastic Agent id |
| `collector_ephemeral_id` | `e026770f-355a-4130-97ba-658b5a1f98f2` | Elastic Agent ephemeral id |
| `collector_version` | `8.17.0` | Elastic Agent version |

### Output Parameters

The shipped `generator.yml` writes `output/events.json`. To deliver elsewhere, replace the file output with another output plugin and put endpoint settings in top-level `${params.*}` placeholders and credentials in `${secrets.*}`, for example `hosts: ["${params.opensearch_host}"]` and `password: ${secrets.opensearch_password}`.

## Usage

Live generation at the configured rate:

```bash
eventum generate --path generators/identity-keycloak/generator.yml --id keycloak --live-mode true
```

Batch generation: set `start` and `end` of the `oscillator` in all four `patterns/*.yml` files to the same range, with `start` at 00:00 UTC so the hour bands stay in place (for example `start: "2026-09-01T00:00:00Z"` and `end: "2026-09-04T00:00:00Z"`), then run:

```bash
eventum generate --path generators/identity-keycloak/generator.yml --id keycloak --live-mode false --keep-order true
```

The hour curve is the sum of four `time_patterns` files under `patterns/`: `baseline` (00-24 UTC), `daytime` (07-20), `office` (08-18) and `evening` (20-23). To change the volume, scale the `ratio` of every pattern file by the same factor; a lower volume stretches the gaps between the records of one login and leaves more codes unexchanged at night. Episode start hours follow the shipped curve even if you reshape the pattern files.

Performance: about 2,600 events per second in batch mode on one core.

## Sample Output

The first episode's privileged grant of a default run:

```json
{"@timestamp": "2026-09-01T03:40:38.276Z", "agent": {"ephemeral_id": "e026770f-355a-4130-97ba-658b5a1f98f2", "id": "a0634c5c-35db-4f7a-8273-73052fa14208", "name": "keycloak-01.corp.example", "type": "filebeat", "version": "8.17.0"}, "data_stream": {"dataset": "keycloak.log", "namespace": "default", "type": "logs"}, "ecs": {"version": "8.11.0"}, "elastic_agent": {"id": "a0634c5c-35db-4f7a-8273-73052fa14208", "snapshot": false, "version": "8.17.0"}, "event": {"action": "CREATE-REALM_ROLE_MAPPING", "agent_id_status": "verified", "category": ["iam"], "code": "CREATE-REALM_ROLE_MAPPING", "dataset": "keycloak.log", "ingested": "2026-09-01T03:40:41Z", "kind": "event", "original": "2026-09-01 03:40:38,276 INFO  [org.keycloak.events] (executor-thread-46) operationType=\"CREATE\", realmId=\"523dd4a1-c4d0-4cf1-acb4-ea0f1de7e9c4\", realmName=\"corp\", clientId=\"3f1c9b52-8d47-4e0a-b6d2-71a95c0e4f83\", userId=\"4dc163fa-d66b-46b2-b00c-ac3390f7f3a4\", ipAddress=\"10.20.200.11\", resourceType=\"REALM_ROLE_MAPPING\", resourcePath=\"users/e7ec4496-f5dd-48a4-8fbd-ddb322908061/role-mappings/realm\", representation=\"[{\\\"id\\\":\\\"b18f4680-7b51-450e-89f2-65d98024e7b7\\\",\\\"name\\\":\\\"secops-admin\\\",\\\"composite\\\":false,\\\"clientRole\\\":false,\\\"containerId\\\":\\\"523dd4a1-c4d0-4cf1-acb4-ea0f1de7e9c4\\\"}]\"", "outcome": "unknown", "timezone": "+00:00", "type": ["info", "admin", "creation"]}, "host": {"architecture": "x86_64", "containerized": true, "hostname": "keycloak-01.corp.example", "ip": ["10.20.1.15"], "name": "keycloak-01.corp.example", "os": {"codename": "bookworm", "family": "debian", "kernel": "6.1.0-28-amd64", "name": "Debian GNU/Linux", "platform": "debian", "type": "linux", "version": "12"}}, "input": {"type": "filestream"}, "keycloak": {"admin": {"operation": "CREATE", "resource": {"path": "users/e7ec4496-f5dd-48a4-8fbd-ddb322908061/role-mappings/realm", "type": "REALM_ROLE_MAPPING"}}, "client": {"id": "3f1c9b52-8d47-4e0a-b6d2-71a95c0e4f83"}, "event_type": "admin", "realm": {"id": "523dd4a1-c4d0-4cf1-acb4-ea0f1de7e9c4"}}, "log": {"file": {"path": "/opt/keycloak/data/log/keycloak.log"}, "level": "INFO", "logger": "org.keycloak.events", "offset": 9512095}, "process": {"thread": {"name": "executor-thread-46"}}, "related": {"ip": ["10.20.200.11"], "user": ["4dc163fa-d66b-46b2-b00c-ac3390f7f3a4", "e7ec4496-f5dd-48a4-8fbd-ddb322908061"]}, "source": {"address": "10.20.200.11", "ip": "10.20.200.11"}, "tags": ["preserve_original_event", "forwarded", "keycloak-log"], "user": {"id": "4dc163fa-d66b-46b2-b00c-ac3390f7f3a4", "target": {"id": "e7ec4496-f5dd-48a4-8fbd-ddb322908061"}}}
```

## Limitations

- Listener profile: Keycloak 26.7.4 `jboss-logging` with `success-level=info` (the default is `debug`), `include-representation=true` and realm admin event details enabled. With the defaults, successful events are not written at INFO and admin lines carry no `representation`.
- Detail keys and order: `LOGIN` and `CODE_TO_TOKEN` copy a raw Keycloak 26 log (issue 44344). No 26.x raw `LOGIN_ERROR` with the full detail set was found; its keys follow the Elastic fixture and a 26.0.7 raw line; `username` and the `authSession*` keys are not in that raw line and come from the listener source and the 2021 Elastic fixture. `LOGOUT` details (`redirect_uri` only) are inferred from the listener source; no 26.x raw `LOGOUT` was available. Keycloak stores details in a `HashMap`, so the order in a real deployment can differ for other key sets.
- Role representation keys (`id`, `name`, `composite`, `clientRole`, `containerId`) follow `RoleRepresentation` for roles without description or attributes; the exact body depends on the admin client.
- Only one realm and the event types above are modeled: no refresh-token, client-credentials, required-action, brute-force lockout, code-exchange error or user/group admin events.
- Records of one login are seconds apart rather than milliseconds: at night `CODE_TO_TOKEN` follows `LOGIN` after a median 9 s instead of well under a second, and about 0.1% of `LOGIN`s have no code exchange.
- The hour curve is in UTC and repeats every day: there is no weekly cycle, so weekends look like weekdays.
- `event.ingested` lags the event by 0.3-20 s (lognormal); log file rotation is not modeled.
- Each episode adds its own administrator burst of five or more wrong passwords, with its login and grant, to the background ones, so with `anomaly_mode: true` these counts are higher by about one per episode (about six more a week at the default interval, on top of roughly 3 to 19 a week in background). A single week with anomalies therefore usually looks like a busy background week; the higher average shows over longer runs. A 12-hour interval doubles the excess.

## References

- [Keycloak 26.7.4 JBossLoggingEventListenerProvider](https://github.com/keycloak/keycloak/blob/26.7.4/services/src/main/java/org/keycloak/events/log/JBossLoggingEventListenerProvider.java) and [factory](https://github.com/keycloak/keycloak/blob/26.7.4/services/src/main/java/org/keycloak/events/log/JBossLoggingEventListenerProviderFactory.java)
- [Keycloak 26.7.4 AdminEventBuilder](https://github.com/keycloak/keycloak/blob/26.7.4/services/src/main/java/org/keycloak/services/resources/admin/AdminEventBuilder.java), [RoleMapperResource](https://github.com/keycloak/keycloak/blob/26.7.4/services/src/main/java/org/keycloak/services/resources/admin/RoleMapperResource.java), [StringUtil](https://github.com/keycloak/keycloak/blob/26.7.4/server-spi/src/main/java/org/keycloak/utils/StringUtil.java)
- Raw Keycloak lines: [LOGIN / CODE_TO_TOKEN (issue 44344)](https://github.com/keycloak/keycloak/issues/44344), [LOGIN_ERROR (issue 35732)](https://github.com/keycloak/keycloak/issues/35732)
- [Keycloak logging configuration](https://www.keycloak.org/server/logging)
- [Elastic Keycloak integration: ingest pipelines, fields and test fixtures](https://github.com/elastic/integrations/tree/main/packages/keycloak/data_stream/log)

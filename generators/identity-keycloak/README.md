# Keycloak Event Log Generator

Generates Keycloak 26.7.4 `jboss-logging` event listener lines (user and admin events) for one realm, as Elastic Agent's Keycloak integration indexes them. `event.original` holds the native log line; `keycloak.*`, `user.*`, `source.*` and `url.*` follow the Elastic `keycloak.log` ingest pipeline.

The realm has 36 users and 5 administrators. Every account is an independent random process: lognormal idle gaps thinned by an office-hours curve (UTC), a login attempt that sometimes starts with wrong passwords, the authorization-code exchange, an optional logout and, for administrators in the admin console, realm role grants and removals. Addresses are the account's workstation or one of three VPN egress addresses shared by all remote staff.

## Event Types Covered

Shares measured on the final 72-hour default capture (`anomaly_mode: true`, 2,372 records); the five 72-hour background captures fall in the ranges shown.

| Action | Share (on) | Share range (off) | Category | Meaning |
|---|---:|---:|---|---|
| `LOGIN` | 36.3% | 35.9-37.3% | authentication | Browser login to an OIDC client |
| `CODE_TO_TOKEN` | 36.3% | 35.9-37.3% | authentication | Authorization-code exchange, 1-2 s after `LOGIN` |
| `LOGOUT` | 11.7% | 10.9-12.2% | authentication | Logout of a session (30% of user sessions, 50% of admin console sessions) |
| `LOGIN_ERROR` | 10.8% | 9.0-12.1% | authentication | `invalid_user_credentials`; 12% of attempts start with 1-8 wrong passwords, 15% of those give up |
| `CREATE-REALM_ROLE_MAPPING` | 2.6% | 2.6-3.2% | iam | Realm role granted to a user in the admin console |
| `DELETE-REALM_ROLE_MAPPING` | 2.2% | 2.0-2.5% | iam | Realm role removed, including expiry of time-bound `secops-admin` grants |

The rates are synthetic, not a vendor-published distribution. Administrators log in to `security-admin-console` (85%) or `account-console`; users to one to three of `account-console`, `portal`, `hr-app`, `mail-ui`.

## Anomaly Chain

`anomaly_mode` defaults to `true`. With `false` the generator writes only the background described above and never the complete chain.

Sequence, per `user.id` + `source.ip`, within 15 minutes (measured spans 1-3 minutes):

1. Five to eight `LOGIN_ERROR` (`invalid_user_credentials`) for one administrator from one VPN egress address, seconds apart, all in one browser authentication session (same `code_id` / `authSessionParentId`).
2. `LOGIN` of that administrator to `security-admin-console` from the same address; `sessionId` equals the attempt's `code_id`.
3. `CODE_TO_TOKEN` for that session (`onltac:` token id).
4. `CREATE-REALM_ROLE_MAPPING` granting the privileged realm role (`secops-admin`) to a user who does not hold it, by the same administrator and address. The session may continue with further ordinary grants and removals.

Linking fields: `user.id`, `source.ip`, `keycloak.session.id` / `keycloak.login.code_id`, `user.target.id`, and the role name in the `representation` inside `event.original`.

Restoration: every `secops-admin` grant, background or episode, is time-bound; after a lognormal lease (median 8 h) the next admin console session removes it with `DELETE-REALM_ROLE_MAPPING`. All three episode grants of the default capture were removed later in the capture.

Recurrence: `anomaly_interval_hours` (default 24, minimum 6, maximum 720), counted in source time. The first episode starts within the first min(interval, 24 h), its hour drawn from the background hour curve. Each later episode is due one interval after the actual previous start and starts at a random time in a window of w = min(interval / 4, 6 h) centred on the due time, weighted by the squared hour curve plus a small floor; missed time is never caught up. The start is further delayed until an administrator is idle with no own attempt due within the episode span. The default capture had starts at 13:33, 13:30 and 12:48 UTC (gaps 23.95 h and 23.31 h); a 12-hour custom capture had six starts with gaps 11.5-13.0 h. Intervals of 12 h or less put some starts into evening hours, and at 8 h or less the start phase necessarily covers the whole clock. Because each start stays near the previous one, the whole run keeps the hour of the first draw; a first start at night can keep all episodes in the evening or night.

Variation: the administrator is drawn with the background activity weights among idle administrators, excluding the previous episode's; the target excludes the previous target; the address is any of the three VPN egress addresses; the failure count is drawn from the tail of the background wrong-password law.

Background overlap: every element of the chain also occurs in ordinary traffic in both modes. Administrators log in from VPN egress addresses (15-45% of their attempts), so each chain administrator + address pair also appears in background (checked against five background captures). Bursts of repeated wrong passwords by one account within minutes, failures followed by a login and code exchange, admin console sessions with several quick grants, and `secops-admin` grants (6-13 per background capture) all occur in background. Only the complete ordered chain is absent: a background grant of the privileged role that would complete it within the 15-minute window grants another role instead, at the same time, by the same administrator.

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

Batch generation: add `start` and `end` to the `cron` input (for example `start: "2026-09-01T00:00:00Z"` and `end: "2026-09-04T00:00:00Z"`), then run:

```bash
eventum generate --path generators/identity-keycloak/generator.yml --id keycloak --live-mode false --keep-order true
```

## Sample Output

The first episode's privileged grant from the final default capture:

```json
{"@timestamp": "2026-09-01T13:36:14.114Z", "agent": {"ephemeral_id": "e026770f-355a-4130-97ba-658b5a1f98f2", "id": "a0634c5c-35db-4f7a-8273-73052fa14208", "name": "keycloak-01.corp.example", "type": "filebeat", "version": "8.17.0"}, "data_stream": {"dataset": "keycloak.log", "namespace": "default", "type": "logs"}, "ecs": {"version": "8.11.0"}, "elastic_agent": {"id": "a0634c5c-35db-4f7a-8273-73052fa14208", "snapshot": false, "version": "8.17.0"}, "event": {"action": "CREATE-REALM_ROLE_MAPPING", "agent_id_status": "verified", "category": ["iam"], "code": "CREATE-REALM_ROLE_MAPPING", "dataset": "keycloak.log", "ingested": "2026-09-01T13:36:15Z", "kind": "event", "original": "2026-09-01 13:36:14,114 INFO  [org.keycloak.events] (executor-thread-9) operationType=\"CREATE\", realmId=\"523dd4a1-c4d0-4cf1-acb4-ea0f1de7e9c4\", realmName=\"corp\", clientId=\"3f1c9b52-8d47-4e0a-b6d2-71a95c0e4f83\", userId=\"ed8a63bd-a7a4-4b64-ac7e-7af1e2b5cf7c\", ipAddress=\"10.20.200.11\", resourceType=\"REALM_ROLE_MAPPING\", resourcePath=\"users/1cb9ad5b-dcbe-4b2f-8fc8-61122d880945/role-mappings/realm\", representation=\"[{\\\"id\\\":\\\"b18f4680-7b51-450e-89f2-65d98024e7b7\\\",\\\"name\\\":\\\"secops-admin\\\",\\\"composite\\\":false,\\\"clientRole\\\":false,\\\"containerId\\\":\\\"523dd4a1-c4d0-4cf1-acb4-ea0f1de7e9c4\\\"}]\"", "outcome": "unknown", "timezone": "+00:00", "type": ["info", "admin", "creation"]}, "host": {"architecture": "x86_64", "containerized": true, "hostname": "keycloak-01.corp.example", "ip": ["10.20.1.15"], "name": "keycloak-01.corp.example", "os": {"codename": "bookworm", "family": "debian", "kernel": "6.1.0-28-amd64", "name": "Debian GNU/Linux", "platform": "debian", "type": "linux", "version": "12"}}, "input": {"type": "filestream"}, "keycloak": {"admin": {"operation": "CREATE", "resource": {"path": "users/1cb9ad5b-dcbe-4b2f-8fc8-61122d880945/role-mappings/realm", "type": "REALM_ROLE_MAPPING"}}, "client": {"id": "3f1c9b52-8d47-4e0a-b6d2-71a95c0e4f83"}, "event_type": "admin", "realm": {"id": "523dd4a1-c4d0-4cf1-acb4-ea0f1de7e9c4"}}, "log": {"file": {"path": "/opt/keycloak/data/log/keycloak.log"}, "level": "INFO", "logger": "org.keycloak.events", "offset": 3101021}, "process": {"thread": {"name": "executor-thread-9"}}, "related": {"ip": ["10.20.200.11"], "user": ["ed8a63bd-a7a4-4b64-ac7e-7af1e2b5cf7c", "1cb9ad5b-dcbe-4b2f-8fc8-61122d880945"]}, "source": {"address": "10.20.200.11", "ip": "10.20.200.11"}, "tags": ["preserve_original_event", "forwarded", "keycloak-log"], "user": {"id": "ed8a63bd-a7a4-4b64-ac7e-7af1e2b5cf7c", "target": {"id": "1cb9ad5b-dcbe-4b2f-8fc8-61122d880945"}}}
```

## Limitations

- Listener profile: Keycloak 26.7.4 `jboss-logging` with `success-level=info` (the default is `debug`), `include-representation=true` and realm admin event details enabled. With the defaults, successful events are not written at INFO and admin lines carry no `representation`.
- Detail keys and order: `LOGIN` and `CODE_TO_TOKEN` copy a Keycloak 26 raw capture (issue 44344). No 26.x raw `LOGIN_ERROR` with the full detail set was found; its keys follow the Elastic fixture and a 26.0.7 raw line; `username` and the `authSession*` keys are not in that raw line and come from the listener source and the 2021 Elastic fixture. `LOGOUT` details (`redirect_uri` only) are inferred from the listener source; no 26.x raw `LOGOUT` was available. Keycloak stores details in a `HashMap`, so the order in a real deployment can differ for other key sets.
- Role representation keys (`id`, `name`, `composite`, `clientRole`, `containerId`) follow `RoleRepresentation` for roles without description or attributes; the exact body depends on the admin client.
- Only one realm and the event types above are modeled: no refresh-token, client-credentials, required-action, brute-force lockout or user/group admin events.
- One line per one-second tick: concurrent events are serialized by up to a few seconds.
- The episode administrator must be idle with no own attempt due during the episode, which slightly favours less active administrators.
- `event.ingested` lags the event by 0.3-20 s (lognormal); log file rotation is not modeled.

## References

- [Keycloak 26.7.4 JBossLoggingEventListenerProvider](https://github.com/keycloak/keycloak/blob/26.7.4/services/src/main/java/org/keycloak/events/log/JBossLoggingEventListenerProvider.java) and [factory](https://github.com/keycloak/keycloak/blob/26.7.4/services/src/main/java/org/keycloak/events/log/JBossLoggingEventListenerProviderFactory.java)
- [Keycloak 26.7.4 AdminEventBuilder](https://github.com/keycloak/keycloak/blob/26.7.4/services/src/main/java/org/keycloak/services/resources/admin/AdminEventBuilder.java), [RoleMapperResource](https://github.com/keycloak/keycloak/blob/26.7.4/services/src/main/java/org/keycloak/services/resources/admin/RoleMapperResource.java), [StringUtil](https://github.com/keycloak/keycloak/blob/26.7.4/server-spi/src/main/java/org/keycloak/utils/StringUtil.java)
- Raw Keycloak lines: [LOGIN / CODE_TO_TOKEN (issue 44344)](https://github.com/keycloak/keycloak/issues/44344), [LOGIN_ERROR (issue 35732)](https://github.com/keycloak/keycloak/issues/35732)
- [Keycloak logging configuration](https://www.keycloak.org/server/logging)
- [Elastic Keycloak integration: ingest pipelines, fields and test fixtures](https://github.com/elastic/integrations/tree/main/packages/keycloak/data_stream/log)

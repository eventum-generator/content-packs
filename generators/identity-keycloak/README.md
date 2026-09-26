# Keycloak Event Log Generator

Generates Keycloak 26.7.4 `jboss-logging` listener lines and ECS documents for a realm at one event every five seconds. `event.original` is the native line; `keycloak.*` follows the Elastic `keycloak.log` event pipeline.

## Event Types Covered

| Action | Events in a 2.5-hour anomaly-mode run | Meaning |
|---|---:|---|
| `LOGIN` | 916 | Successful OIDC login |
| `LOGIN_ERROR` | 204 | Invalid credentials |
| `CODE_TO_TOKEN` | 513 | Authorization-code exchange for an existing session |
| `LOGOUT` | 119 | End of a tokenized session |
| `DELETE-REALM_ROLE_MAPPING` | 17 | Realm-role mapping removed |
| `CREATE-REALM_ROLE_MAPPING` | 16 | Realm-role mapping added |
| `UPDATE-REALM` | 16 | Realm event configuration updated |

These counts are one synthetic run, not a vendor-published production distribution. Five-second ticks with 0-2 seconds of jitter keep authorization-code exchanges within Keycloak's default 60-second client login timeout. Routine user events are weighted; role removals, additions, and realm configuration updates occur at wider intervals. A one-entry active-session state links ordinary `LOGIN`, `CODE_TO_TOKEN`, and `LOGOUT` records by `sessionId`; the authorization-code exchange reuses the login `code_id`.

## Anomaly Chain

`event.template.params.anomaly_mode` defaults to `true`. After 720 routine events, then every 720 routine events when a tracked role mapping is absent, the generator emits this nine-event sequence. A 2.5-hour run contains two complete episodes, starting at output indices 720 and 1449:

1. Five `LOGIN_ERROR` events from one IP against five distinct user IDs. The last failure belongs to `svc-admin`.
2. `svc-admin` logs in from the same IP, then exchanges its authorization code. `sessionId` and `code_id` match across those two records.
3. The same actor and IP assign the synthetic `secops-admin` realm role to a target user.
4. The actor updates `events/config`. Its representation keeps user/admin event logging and `jboss-logging` enabled, so subsequent listener events remain possible.

Possible SIEM rules correlate distinct failed accounts per IP, success after failures for the same user, a `CREATE-REALM_ROLE_MAPPING` after that login, and a nearby `UPDATE-REALM`. The background includes the same IP, acting user ID, role, resource types and administrative operations; the target ID also appears in a preceding routine `DELETE-REALM_ROLE_MAPPING`. No field labels a single event as anomalous. `anomaly_mode: false` emits only this background. Each routine deletion selects another pre-existing role mapping and a fresh target UUID; a routine or anomalous grant restores that mapping, so the grant changes state rather than repeating a no-op assignment. Each episode has a new target UUID and a new login/session/code UUID.

The modeled `secops-admin` role grants access in a fictional application; its name alone does **not** imply Keycloak administrator privileges. The acting `svc-admin` account is assumed to already have the Keycloak permissions required to manage users and events. The `events/config` update is an auditable change, not an asserted logging shutdown.

## Source Profile and Field Map

The profile is the [Keycloak 26.7.4 logging listener](https://github.com/keycloak/keycloak/blob/26.7.4/services/src/main/java/org/keycloak/events/log/JBossLoggingEventListenerProvider.java) with successful event level set to `INFO`, error level `WARN`, default double-quoted values, and `include-representation=true`. Realm user/admin event logging and admin-event representation must also be enabled. The source is configured with Keycloak's plain-text `file` handler at its default `data/log/keycloak.log` path; the default log-file format matches the generated prefix. File rotation is outside the 2.5-hour validation window, so the synthetic offset is monotonic in that run. The [26.7.4 factory](https://github.com/keycloak/keycloak/blob/26.7.4/services/src/main/java/org/keycloak/events/log/JBossLoggingEventListenerProviderFactory.java) defaults to successful events at `DEBUG` and representation off, so this is a configured profile. Its representation switch is version-specific and should not be assumed for older 26.1.x releases. The [26.7.4 API constant](https://www.keycloak.org/docs-api/26.7.4/javadocs/org/keycloak/models/Constants.html#DEFAULT_ACCESS_CODE_LIFESPAN) gives a one-minute default Client Login Timeout. The generator expires an unexchanged authorization code at 60 seconds; all observed exchanges in the validation run occur within 21 seconds.

| Output | Evidence | Mapping |
|---|---|---|
| `event.original`, `message`, `log.level` | Versioned listener, real [LOGIN_ERROR](https://github.com/keycloak/keycloak/issues/35732) and [LOGIN/CODE_TO_TOKEN](https://github.com/keycloak/keycloak/issues/44344) lines | Exact listener key order, quotes and optional `sessionId`; error at `WARN` |
| `keycloak.login.*`, `keycloak.session.id` | [Elastic event pipeline](https://github.com/elastic/integrations/blob/main/packages/keycloak/data_stream/log/elasticsearch/ingest_pipeline/events.yml) | User event type, code, auth method/type, redirect URI, session ID |
| `keycloak.admin.*`, `event.action`, `event.code`, `user.target.id` | Elastic event pipeline and [Keycloak 26.7.4 role-mapper source](https://github.com/keycloak/keycloak/blob/26.7.4/services/src/main/java/org/keycloak/services/resources/admin/RoleMapperResource.java) | `CREATE`/`DELETE` role mappings and `UPDATE` realm event settings; both role operations receive a representation in this version |
| `source.*`, `related.*`, `user.*` | Elastic event pipeline | Address and user/target IDs consistent within each event and mapping lifecycle; no invented username enrichment on admin/token events |
| Collector and host metadata | [Elastic reference sample](https://github.com/elastic/integrations/blob/main/packages/keycloak/data_stream/log/sample_event.json) | Synthetic fixed Filebeat and host identity, with increasing file offsets |

The generated records cover all 42 leaf fields in Elastic's published sample. That sample is a generic server-startup log, so this number validates collector shape only. Native event semantics were checked separately against listener code, source examples, and the [Elastic field schema](https://github.com/elastic/integrations/blob/main/packages/keycloak/data_stream/log/fields/fields.yml). Complete raw Keycloak 26.7.4 captures for every generated `LOGOUT` and representation-bearing admin variant were not available; representation serialization is supported by versioned source but remains a raw-example gap. This PR stays draft pending that evidence or a real-instance comparison.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Name | Default | Purpose |
|---|---|---|
| `anomaly_mode` | `true` | Emit recurring correlated sequences among routine records |
| `realm`, `realm_id` | `corp`, `523dd4a1-c4d0-4cf1-acb4-ea0f1de7e9c4` | Realm name and stable ID |
| `redirect_uri` | `https://sso.corp.example/callback` | OIDC client redirect URI in login details |
| `hostname`, `host_ip` | `keycloak-01.corp.example`, `10.20.1.15` | Server and collector host |
| `collector_id`, `collector_ephemeral_id`, `collector_version` | Synthetic UUIDs, `8.13.0` | Filebeat identity and version |
| `suspicious_ip` | `198.51.100.91` | IP present in routine and anomaly records |
| `compromised_user`, `compromised_user_id` | `svc-admin`, `7c8c3984-477c-4ab0-8644-f19c6d159a4b` | Acting identity present in both modes |
| `target_user_id` | `977821e2-168b-4969-b157-2c1347957bdd` | Initial pre-existing role-mapping target; later tracked targets get fresh UUIDs |
| `privileged_role_id`, `privileged_role_name` | `b18f4680-7b51-450e-89f2-65d98024e7b7`, `secops-admin` | Modeled application role in representations |
| `anomaly_after_events` | `720` | First due routine count; waits until the tracked mapping is absent |
| `anomaly_interval_events` | `720` | Routine records between later due points; an assigned mapping can delay the episode |

### Output Parameters

The shipped generator writes `output/events.json` without external credentials. To index elsewhere, replace its file output with the relevant output plugin and use top-level `${params.*}` for endpoint settings and `${secrets.*}` for keyring-backed secrets. See the [OpenSearch output guide](https://eventum.run/docs/tutorials/delivery/opensearch).

## Usage

From the content-packs repository, make a finite copy of the config for a batch run:

```bash
uv run --project ../eventum python - <<'PY'
from pathlib import Path
p = Path("generators/identity-keycloak")
source = (p / "generator.yml").read_text()
finite = source.replace(
    "      count: 1\n",
    '      count: 1\n      start: "2026-09-25T00:00:00+00:00"\n'
    '      end: "2026-09-25T02:30:00+00:00"\n',
    1,
)
(p / "generator.batch.yml").write_text(finite)
PY
flock -x /tmp/eventum-generator-heavy.lock uv run --project ../eventum eventum generate --path generators/identity-keycloak/generator.batch.yml --id keycloak --live-mode false --keep-order true
rm generators/identity-keycloak/generator.batch.yml
```

For continuous generation at the configured five-second rate:

```bash
uv run --project ../eventum eventum generate --path generators/identity-keycloak/generator.yml --id keycloak --live-mode true
```

## Sample Output

This complete synthetic `CREATE-REALM_ROLE_MAPPING` record was copied from the first validated episode. Exact equivalence to a raw Keycloak 26.7.4 representation-bearing admin capture remains unverified:

```json
{"@timestamp": "2026-09-25T01:00:35.351000+00:00", "agent": {"ephemeral_id": "e026770f-355a-4130-97ba-658b5a1f98f2", "id": "a0634c5c-35db-4f7a-8273-73052fa14208", "name": "keycloak-01.corp.example", "type": "filebeat", "version": "8.13.0"}, "data_stream": {"dataset": "keycloak.log", "namespace": "default", "type": "logs"}, "ecs": {"version": "8.17.0"}, "elastic_agent": {"id": "a0634c5c-35db-4f7a-8273-73052fa14208", "snapshot": false, "version": "8.13.0"}, "event": {"action": "CREATE-REALM_ROLE_MAPPING", "agent_id_status": "verified", "category": ["iam"], "code": "CREATE-REALM_ROLE_MAPPING", "dataset": "keycloak.log", "ingested": "2026-09-25T01:00:37.351000+00:00", "kind": "event", "original": "2026-09-25 01:00:35,351 INFO  [org.keycloak.events] (executor-thread-1) operationType=\"CREATE\", realmId=\"523dd4a1-c4d0-4cf1-acb4-ea0f1de7e9c4\", realmName=\"corp\", clientId=\"security-admin-console\", userId=\"7c8c3984-477c-4ab0-8644-f19c6d159a4b\", ipAddress=\"198.51.100.91\", resourceType=\"REALM_ROLE_MAPPING\", resourcePath=\"users/c2f61e2d-a749-4612-9970-e5e037db77bb/role-mappings/realm\", representation=\"[{\\\"id\\\": \\\"b18f4680-7b51-450e-89f2-65d98024e7b7\\\", \\\"name\\\": \\\"secops-admin\\\"}]\"", "outcome": "unknown", "timezone": "+00:00", "type": ["info", "admin", "creation"]}, "host": {"architecture": "x86_64", "containerized": true, "hostname": "keycloak-01.corp.example", "id": "5082ec46978249e68488c21de3f64030", "ip": ["10.20.1.15"], "mac": ["02-42-0A-14-01-0F"], "name": "keycloak-01.corp.example", "os": {"codename": "bookworm", "family": "debian", "kernel": "6.1.0", "name": "Debian", "platform": "debian", "type": "linux", "version": "12"}}, "input": {"type": "filestream"}, "keycloak": {"admin": {"operation": "CREATE", "resource": {"path": "users/c2f61e2d-a749-4612-9970-e5e037db77bb/role-mappings/realm", "type": "REALM_ROLE_MAPPING"}}, "client": {"id": "security-admin-console"}, "event_type": "admin", "realm": {"id": "523dd4a1-c4d0-4cf1-acb4-ea0f1de7e9c4"}}, "log": {"file": {"device_id": "2049", "inode": "537921", "path": "/opt/keycloak/data/log/keycloak.log"}, "level": "INFO", "logger": "org.keycloak.events", "offset": 389982}, "message": "operationType=\"CREATE\", realmId=\"523dd4a1-c4d0-4cf1-acb4-ea0f1de7e9c4\", realmName=\"corp\", clientId=\"security-admin-console\", userId=\"7c8c3984-477c-4ab0-8644-f19c6d159a4b\", ipAddress=\"198.51.100.91\", resourceType=\"REALM_ROLE_MAPPING\", resourcePath=\"users/c2f61e2d-a749-4612-9970-e5e037db77bb/role-mappings/realm\", representation=\"[{\\\"id\\\": \\\"b18f4680-7b51-450e-89f2-65d98024e7b7\\\", \\\"name\\\": \\\"secops-admin\\\"}]\"", "process": {"thread": {"name": "executor-thread-1"}}, "related": {"ip": ["198.51.100.91"], "user": ["7c8c3984-477c-4ab0-8644-f19c6d159a4b", "c2f61e2d-a749-4612-9970-e5e037db77bb"]}, "source": {"address": "198.51.100.91", "ip": "198.51.100.91"}, "tags": ["keycloak-log"], "user": {"id": "7c8c3984-477c-4ab0-8644-f19c6d159a4b", "target": {"id": "c2f61e2d-a749-4612-9970-e5e037db77bb"}}}
```

## References

- [Keycloak logging and file-handler options](https://www.keycloak.org/server/logging)
- [Keycloak 26.7.4 listener and factory](https://github.com/keycloak/keycloak/tree/26.7.4/services/src/main/java/org/keycloak/events/log)
- [Keycloak 26.7.4 role-mapping resource](https://github.com/keycloak/keycloak/blob/26.7.4/services/src/main/java/org/keycloak/services/resources/admin/RoleMapperResource.java)
- [Keycloak 26.7.4 realm event configuration resource](https://github.com/keycloak/keycloak/blob/26.7.4/services/src/main/java/org/keycloak/services/resources/admin/RealmAdminResource.java)
- [Keycloak `LOGIN_ERROR` raw log](https://github.com/keycloak/keycloak/issues/35732), [login/token exchange raw log](https://github.com/keycloak/keycloak/issues/44344), [role-mapping raw logs](https://docs.oracle.com/en/industries/communications/cloud-native-core/3.24.3/cncconsole_troubleshooting_24.3.0/logs1.html)
- [Elastic Keycloak integration](https://github.com/elastic/integrations/tree/main/packages/keycloak/data_stream/log)

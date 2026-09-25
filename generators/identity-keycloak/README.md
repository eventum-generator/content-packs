# Keycloak Event Log Generator

Generates Keycloak user and administrator event-listener log records as ECS-compatible JSON. The original Keycloak log line is preserved in `event.original` and its event details are available under `keycloak.*`.

## Event Types Covered

| Action | Share in a 1,200-event validation run | Category |
|---|---:|---|
| `LOGIN` | 54.4% | authentication |
| `CODE_TO_TOKEN` | 16.2% | authentication |
| `LOGIN_ERROR` | 15.1% | authentication |
| `LOGOUT` | 12.2% | authentication |
| Admin `CREATE` | ~1.1% | iam |
| Admin `UPDATE` | ~1.1% | configuration |

The generator uses `mode: fsm`. Routine events are weighted, but token exchanges and logouts reuse an active user session. The anomaly has ordered states. The percentages describe this generator's test run, not a published Keycloak production distribution.

## Anomaly Chain

Set `event.template.params.anomaly_mode` to `false` to emit only background activity. The default `true` includes this chain among routine events.

After 80 routine events, five `LOGIN_ERROR` records come from the same external address against different accounts. The last account then logs in successfully from that address. The same identity in realm `corp` maps a synthetic `secops-admin` realm role to another user and updates `events/config`. The role name appears in the configured listener representation. The chain repeats after another stretch of routine activity. It supports separate detections for password spraying, success after failures, privilege assignment, audit-configuration change, and their combination. The event stream carries no special anomaly marker.

User and administrator event logging must be enabled on a real Keycloak instance for comparable records. The logging listener must use success level `info` and `include-representation=true`, and the realm must include admin-event representations; defaults omit successful events and the role body. The synthetic `secops-admin` role is assumed to grant administrative rights in this example realm. The listener line uses the default double-quoted value format.

## Reference Field Map

| Field group | Source | Generation strategy |
|---|---|---|
| `@timestamp`, `log.*`, `message`, `event.original` | Elastic `keycloak.log` sample and Keycloak logging listener | Render the documented log format and maintain a byte offset |
| `agent.*`, `elastic_agent.*`, `host.*`, `data_stream.*` | Elastic sample | Fixed synthetic collector and host identity |
| `keycloak.*`, `source.ip`, `user.*`, `event.action` | Keycloak user/admin event fields | Reuse the identity and address across the intrusion sequence |

All 42 fields in the Elastic `keycloak.log` sample are present in generated output. The Elastic reference is a generic server-log entry; user and admin event details are based on Keycloak's event documentation and administrative event model.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Name | Default | Purpose |
|---|---|---|
| `anomaly_mode` | `true` | Emit the correlated anomaly chain alongside routine events; `false` emits only background |
| `realm` | `corp` | Realm name for user and administrator events |
| `realm_id` | `523dd4a1-c4d0-4cf1-acb4-ea0f1de7e9c4` | Stable realm ID in the listener line |
| `hostname` | `keycloak-01.corp.example` | Keycloak server and collector host |
| `host_ip` | `10.20.1.15` | Server address |
| `collector_id` | `a0634c5c-35db-4f7a-8273-73052fa14208` | Stable collector ID |
| `collector_ephemeral_id` | `e026770f-355a-4130-97ba-658b5a1f98f2` | Collector process ID |
| `collector_version` | `8.13.0` | Collector version |
| `suspicious_ip` | `198.51.100.91` | Address used throughout the anomaly |
| `compromised_user` | `svc-admin` | Account that authenticates after the spray |
| `compromised_user_id` | `7c8c3984-477c-4ab0-8644-f19c6d159a4b` | Stable account ID across the chain |
| `target_user_id` | `977821e2-168b-4969-b157-2c1347957bdd` | Account receiving a role mapping |
| `privileged_role_id` | `b18f4680-7b51-450e-89f2-65d98024e7b7` | Synthetic realm-role ID in the representation |
| `privileged_role_name` | `secops-admin` | Synthetic privileged realm role granted to the target |

### Output Parameters

The shipped output writes `output/events.json` and needs no output overrides. To index the same events, replace the file output with an OpenSearch output using `${params.opensearch_host}` for the host and `${secrets.opensearch_password}` from the keyring for the password. See the [OpenSearch output guide](https://eventum.run/docs/tutorials/delivery/opensearch).

## Usage

```bash
# Bounded batch run; --live-mode false generates as fast as possible.
timeout 3 eventum generate --path generators/identity-keycloak/generator.yml --id keycloak --live-mode false

# Continuous 5 events/second run.
eventum generate --path generators/identity-keycloak/generator.yml --id keycloak --live-mode true
```

## Sample Output

This complete role-mapping event was produced by the generator:

```json
{
  "@timestamp": "2026-09-25T10:46:11+00:00",
  "agent": {
    "ephemeral_id": "e026770f-355a-4130-97ba-658b5a1f98f2",
    "id": "a0634c5c-35db-4f7a-8273-73052fa14208",
    "name": "keycloak-01.corp.example",
    "type": "filebeat",
    "version": "8.13.0"
  },
  "data_stream": {
    "dataset": "keycloak.log",
    "namespace": "default",
    "type": "logs"
  },
  "ecs": {
    "version": "8.17.0"
  },
  "elastic_agent": {
    "id": "a0634c5c-35db-4f7a-8273-73052fa14208",
    "snapshot": false,
    "version": "8.13.0"
  },
  "event": {
    "action": "CREATE",
    "agent_id_status": "verified",
    "category": [
      "iam",
      "configuration"
    ],
    "dataset": "keycloak.log",
    "ingested": "2026-09-25T10:46:11+00:00",
    "kind": "event",
    "original": "2026-09-25 10:46:11,000 INFO  [org.keycloak.events] (executor-thread-1) operationType=\"CREATE\", realmId=\"523dd4a1-c4d0-4cf1-acb4-ea0f1de7e9c4\", realmName=\"corp\", clientId=\"security-admin-console\", userId=\"7c8c3984-477c-4ab0-8644-f19c6d159a4b\", ipAddress=\"198.51.100.91\", resourceType=\"REALM_ROLE_MAPPING\", resourcePath=\"users/977821e2-168b-4969-b157-2c1347957bdd/role-mappings/realm\", representation=\"[{\\\"id\\\": \\\"b18f4680-7b51-450e-89f2-65d98024e7b7\\\", \\\"name\\\": \\\"secops-admin\\\"}]\"",
    "outcome": "success",
    "timezone": "+00:00",
    "type": [
      "change"
    ]
  },
  "host": {
    "architecture": "x86_64",
    "containerized": true,
    "hostname": "keycloak-01.corp.example",
    "id": "5082ec46978249e68488c21de3f64030",
    "ip": [
      "10.20.1.15"
    ],
    "mac": [
      "02-42-0A-14-01-0F"
    ],
    "name": "keycloak-01.corp.example",
    "os": {
      "codename": "bookworm",
      "family": "debian",
      "kernel": "6.1.0",
      "name": "Debian",
      "platform": "debian",
      "type": "linux",
      "version": "12"
    }
  },
  "input": {
    "type": "filestream"
  },
  "keycloak": {
    "client_id": "security-admin-console",
    "event_type": "ADMIN_EVENT",
    "ip_address": "198.51.100.91",
    "operation_type": "CREATE",
    "realm": "corp",
    "realm_id": "523dd4a1-c4d0-4cf1-acb4-ea0f1de7e9c4",
    "representation": "[{\"id\": \"b18f4680-7b51-450e-89f2-65d98024e7b7\", \"name\": \"secops-admin\"}]",
    "resource_path": "users/977821e2-168b-4969-b157-2c1347957bdd/role-mappings/realm",
    "resource_type": "REALM_ROLE_MAPPING",
    "role_name": "secops-admin",
    "user_id": "7c8c3984-477c-4ab0-8644-f19c6d159a4b"
  },
  "log": {
    "file": {
      "device_id": "2049",
      "inode": "537921",
      "path": "/opt/keycloak/data/log/keycloak.log"
    },
    "level": "INFO",
    "logger": "org.keycloak.events",
    "offset": 35941
  },
  "message": "operationType=\"CREATE\", realmId=\"523dd4a1-c4d0-4cf1-acb4-ea0f1de7e9c4\", realmName=\"corp\", clientId=\"security-admin-console\", userId=\"7c8c3984-477c-4ab0-8644-f19c6d159a4b\", ipAddress=\"198.51.100.91\", resourceType=\"REALM_ROLE_MAPPING\", resourcePath=\"users/977821e2-168b-4969-b157-2c1347957bdd/role-mappings/realm\", representation=\"[{\\\"id\\\": \\\"b18f4680-7b51-450e-89f2-65d98024e7b7\\\", \\\"name\\\": \\\"secops-admin\\\"}]\"",
  "process": {
    "thread": {
      "name": "executor-thread-1"
    }
  },
  "related": {
    "ip": [
      "198.51.100.91"
    ],
    "user": [
      "svc-admin"
    ]
  },
  "source": {
    "ip": "198.51.100.91"
  },
  "tags": [
    "keycloak-log"
  ],
  "user": {
    "id": "7c8c3984-477c-4ab0-8644-f19c6d159a4b",
    "name": "svc-admin"
  }
}
```

## References

- [Keycloak Server Administration Guide: auditing events](https://www.keycloak.org/docs/latest/server_admin/#_events)
- [Keycloak AdminEvent model](https://github.com/keycloak/keycloak/blob/main/server-spi-private/src/main/java/org/keycloak/events/admin/AdminEvent.java)
- [Elastic Keycloak integration](https://github.com/elastic/integrations/tree/main/packages/keycloak/data_stream/log)

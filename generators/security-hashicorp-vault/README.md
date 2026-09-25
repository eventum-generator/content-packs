# HashiCorp Vault Audit Generator

Generates Vault audit request and response records as ECS-compatible JSON. Each pair shares the native `request.id`; `event.original` contains the native JSON audit entry. Response entries contain the original request context and either a result or an error.

## Event Types Covered

| Operation | Share of 1,200 request/response pairs | Category |
|---|---:|---|
| Secret or token `read` | 79.8% | iam, authentication |
| Secret metadata `list` | 12.3% | iam |
| Token `update` | 7.0% | authentication |
| Audit-device `delete` attempt | 0.8% | configuration |

`mode: chain` emits a request and response for each timestamp, so every operation contributes two events. The mix is configured for a useful test workload; no published production distribution is claimed.

## Anomaly Chain

Set `event.template.params.anomaly_mode` to `false` to emit only background activity. The default `true` includes this chain among routine events.

Every 120-operation cycle includes ten reads of distinct `secret/data/payroll/employee-*` paths by `svc-reports` from one external address, followed by a denied attempt to delete the `sys/audit/file` audit device. Requests and responses share stable actor, source IP, token HMACs, and request IDs. Rules can detect a read burst, rare access to the payroll prefix, audit-device tampering, or the ordered combination. Ordinary reads, lists, and token renewals continue between cycles.

The audit data contains only synthetic identities and HMAC-shaped values, never plaintext secrets. Shared state holds one current request and a scalar flow counter, with no growing collection.

## Reference Field Map

| Field group | Source | Generation strategy |
|---|---|---|
| `hashicorp_vault.audit.auth` | HashiCorp audit schema | Stable actor, entity ID, token accessor, policy and HMAC-shaped token |
| `hashicorp_vault.audit.request` | HashiCorp audit schema | Per-operation UUID, operation, path, namespace and source address |
| `hashicorp_vault.audit.response` | HashiCorp audit schema | Repeats request context; includes synthetic hashed data or permission error |
| ECS and collector fields | Elastic `hashicorp_vault.audit` sample | Stable collector/host identity and parsed operation metadata |

Generated output covers all **47/47** leaf fields in the Elastic audit `sample_event.json`. The vendor schema also defines optional fields beyond that one example; the generator covers the fields needed for these operations and omits unused enterprise namespace and forwarding fields.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Name | Default | Purpose |
|---|---|---|
| `anomaly_mode` | `true` | Emit the correlated anomaly chain alongside routine events; `false` emits only background |
| `vault_host` | `vault-01.corp.example` | Vault node and collector hostname |
| `vault_ip` | `10.20.2.18` | Vault node address |
| `collector_id` | `65fa5f58-a1d2-49d1-b4cc-05228dd270f3` | Stable collector ID |
| `collector_ephemeral_id` | `8dcba887-bc9d-44cb-bfcd-ed7aa7216748` | Collector process ID |
| `collector_version` | `8.10.1` | Collector version |
| `suspicious_ip` | `198.51.100.44` | External address in the anomaly |
| `suspicious_actor` | `svc-reports` | Account performing the read burst |
| `secret_mount` | `secret` | KV secret-engine mount |

### Output Parameters

The default output is the local `output/events.json` file and needs no output overrides. To index events, replace the file output with OpenSearch and use `${params.opensearch_host}` for the host plus keyring-backed `${secrets.opensearch_password}` for credentials. See the [OpenSearch output guide](https://eventum.run/docs/tutorials/delivery/opensearch).

## Usage

```bash
# Bounded batch run; --live-mode false generates as fast as possible.
timeout 3 eventum generate --path generators/security-hashicorp-vault/generator.yml --id vault --live-mode false

# Continuous 5 operations/second run (10 audit records/second).
eventum generate --path generators/security-hashicorp-vault/generator.yml --id vault --live-mode true
```

## Sample Output

This complete denied response event was produced by the generator:

```json
{
  "@timestamp": "2026-09-25T10:27:38+00:00",
  "agent": {
    "ephemeral_id": "8dcba887-bc9d-44cb-bfcd-ed7aa7216748",
    "id": "65fa5f58-a1d2-49d1-b4cc-05228dd270f3",
    "name": "vault-01.corp.example",
    "type": "filebeat",
    "version": "8.10.1"
  },
  "data_stream": {
    "dataset": "hashicorp_vault.audit",
    "namespace": "default",
    "type": "logs"
  },
  "ecs": {
    "version": "8.17.0"
  },
  "elastic_agent": {
    "id": "65fa5f58-a1d2-49d1-b4cc-05228dd270f3",
    "snapshot": false,
    "version": "8.10.1"
  },
  "event": {
    "action": "delete",
    "agent_id_status": "verified",
    "category": [
      "configuration"
    ],
    "dataset": "hashicorp_vault.audit",
    "id": "cfaebf26-dac7-448b-8f69-b3ce09171b25",
    "ingested": "2026-09-25T10:27:38+00:00",
    "kind": "event",
    "original": "{\"auth\": {\"accessor\": \"hmac-sha256:3194b146ed26568a373087b7f8305e160432c46f9655360703e8285edc23284e\", \"client_token\": \"hmac-sha256:9c8dff4841b6a430d26accdf48bb5cf5276c4b8f312920e0de8ca4691933bcff\", \"display_name\": \"userpass-svc-reports\", \"entity_id\": \"96fa6c68-63af-43dc-a9ea-f59556f4b5ea\", \"metadata\": {\"username\": \"svc-reports\"}, \"policies\": [\"default\", \"payroll-reader\"], \"token_policies\": [\"default\", \"payroll-reader\"], \"token_type\": \"service\"}, \"error\": \"permission denied\", \"request\": {\"client_token\": \"hmac-sha256:9c8dff4841b6a430d26accdf48bb5cf5276c4b8f312920e0de8ca4691933bcff\", \"client_token_accessor\": \"hmac-sha256:3194b146ed26568a373087b7f8305e160432c46f9655360703e8285edc23284e\", \"id\": \"cfaebf26-dac7-448b-8f69-b3ce09171b25\", \"mount_point\": \"sys/\", \"mount_type\": \"system\", \"namespace\": {\"id\": \"root\"}, \"operation\": \"delete\", \"path\": \"sys/audit/file\", \"remote_address\": \"198.51.100.44\", \"remote_port\": 52234}, \"response\": {\"mount_point\": \"sys/\", \"mount_type\": \"system\"}, \"time\": \"2026-09-25T10:27:38+00:00\", \"type\": \"response\"}",
    "outcome": "failure",
    "type": [
      "denied"
    ]
  },
  "hashicorp_vault": {
    "audit": {
      "auth": {
        "accessor": "hmac-sha256:3194b146ed26568a373087b7f8305e160432c46f9655360703e8285edc23284e",
        "client_token": "hmac-sha256:9c8dff4841b6a430d26accdf48bb5cf5276c4b8f312920e0de8ca4691933bcff",
        "display_name": "userpass-svc-reports",
        "entity_id": "96fa6c68-63af-43dc-a9ea-f59556f4b5ea",
        "metadata": {
          "username": "svc-reports"
        },
        "policies": [
          "default",
          "payroll-reader"
        ],
        "token_policies": [
          "default",
          "payroll-reader"
        ],
        "token_type": "service"
      },
      "error": "permission denied",
      "request": {
        "client_token": "hmac-sha256:9c8dff4841b6a430d26accdf48bb5cf5276c4b8f312920e0de8ca4691933bcff",
        "client_token_accessor": "hmac-sha256:3194b146ed26568a373087b7f8305e160432c46f9655360703e8285edc23284e",
        "id": "cfaebf26-dac7-448b-8f69-b3ce09171b25",
        "mount_point": "sys/",
        "mount_type": "system",
        "namespace": {
          "id": "root"
        },
        "operation": "delete",
        "path": "sys/audit/file",
        "remote_address": "198.51.100.44",
        "remote_port": 52234
      },
      "response": {
        "mount_point": "sys/",
        "mount_type": "system"
      },
      "time": "2026-09-25T10:27:38+00:00",
      "type": "response"
    }
  },
  "host": {
    "architecture": "x86_64",
    "containerized": false,
    "hostname": "vault-01.corp.example",
    "id": "f25e61f1c11d44bd9aee4a28a664ec18",
    "ip": [
      "10.20.2.18"
    ],
    "mac": [
      "02-42-0A-14-02-12"
    ],
    "name": "vault-01.corp.example",
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
  "log": {
    "file": {
      "path": "/var/log/vault/audit.json"
    },
    "offset": 21870
  },
  "related": {
    "ip": [
      "198.51.100.44"
    ],
    "user": [
      "svc-reports"
    ]
  },
  "source": {
    "ip": "198.51.100.44"
  },
  "tags": [
    "hashicorp-vault-audit"
  ],
  "user": {
    "name": "svc-reports"
  }
}
```

## References

- [HashiCorp Vault audit entry schema](https://developer.hashicorp.com/vault/docs/audit/schema)
- [HashiCorp Vault audit devices](https://developer.hashicorp.com/vault/docs/audit)
- [Elastic HashiCorp Vault audit integration](https://github.com/elastic/integrations/tree/main/packages/hashicorp_vault/data_stream/audit)

# HashiCorp Vault Audit Generator

Generates a selected Vault v1.18.0 file-audit profile for KV v2 reads and lists, token self-lookup and renewal, and denied audit-device deletion. Each API operation emits a linked request/response pair inside ECS-compatible JSON. `event.original` contains the synthetic native audit JSON, including its source timestamp.

## Event Types Covered

| Operation family | Native operation and path | Background selection | ECS category |
|---|---|---:|---|
| KV v2 secret read | `read`, `secret/data/{app,billing,payroll}/*` | 80% | authentication |
| KV v2 metadata list | `list`, `secret/metadata/{app,billing,payroll}` | 10% | authentication |
| Token self-lookup | `read`, `auth/token/lookup-self` | 9% | authentication |
| Denied audit-device deletion | `delete`, `sys/audit/file` | 1% | authentication |
| Token self-renewal | `update`, `auth/token/renew-self` | Scheduled maintenance | authentication |

These weights describe ordinary selection after mandatory renewal and episode scheduling. They are training assumptions, not measured production frequencies. Each operation produces two entries, `type: request` and `type: response`, with the same `request.id`. `mode: all` renders the request before the response for each input timestamp. The six-field cron expression with `count: 1` starts one operation every 30 seconds, or 2,880 operations and 5,760 audit entries per full day. Preserve output order with `--keep-order true`.

## Selected Source Profile

The profile follows tagged Vault v1.18.0 audit structures and request handling, with the KV plugin v0.20.0 pinned by that Vault release. It assumes root namespace, one enabled file device at `/var/log/vault/audit.json`, `log_raw=false`, `hmac_accessor=true`, `elide_list_responses=false`, and no ignored data keys. This represents JSON file output, not syslog or a network envelope.

Four existing userpass identities share the `default` and explicitly configured `training-reader` policies. The selected ACL grants reads and lists of the pre-existing secret inventory and no audit-management permission:

```hcl
# training-reader, for the default secret_mount
path "secret/data/*" {
  capabilities = ["read"]
}
path "secret/metadata/*" {
  capabilities = ["list"]
}
```

The default policy supplies self-lookup and self-renewal. The four userpass users are provisioned before the selected window with `token_policies=training-reader`, `token_period=24h`, `token_explicit_max_ttl=0`, and service tokens. There are no identity policies, use limits, or audit DELETE/sudo grants. Change the ACL mount paths too when changing `secret_mount`. Policy names alone do not prove authorization.

Initial logins and 52 version-1 secrets were created before the selected window. The tokens have original issue times one to four hours before its first timestamp. Visible self-renewal occurs every half period, normally 12 hours, and updates expiration only after the successful response. Stored `auth.token_ttl` remains the creation period of 86,400 seconds. Lookup `response.data.ttl` reports remaining lifetime. Renewal does not create a new token or change its original issue time.

The secret inventory contains 12 application/billing paths and 40 payroll paths, with synthetic values. Every read returns data plus KV version metadata. Lists contain the sorted child names from this inventory before hashing. No secret write, deletion, version change, token creation, or revocation is included.

## Anomaly Chain

`event.template.params.anomaly_mode` defaults to `true`. Setting it to `false` retains ordinary traffic, including all four actors, the same policies, IPs, payroll paths, and isolated denied audit DELETE attempts, without the complete sequence.

After the default 24-hour interval, an eligible existing actor reads ten distinct payroll secrets at 30-second spacing, then attempts to delete `sys/audit/file`. Its explicit reader ACL permits the reads and rejects the audit DELETE. The eleven operations produce 22 entries over 300.05 seconds. Both entries for the denied operation retain valid authentication, `policy_results.allowed=false`, the core permission error, and a hashed `response.data.error`. The audit device remains enabled.

Each episode has fresh operation UUIDs, rotates the eligible actor, and advances its ten-secret window through the existing 40 payroll paths. A pair joins on `request.id`; an episode joins on actor/entity, token and accessor HMACs, peer address, path family, and time. The interval is measured from the actual first read, not from a record counter. The first episode can be deferred by renewal or the actor's ordinary payroll cooldown. There is no backlog of missed episodes.

Ordinary payroll access is separated by at least 15 minutes per actor. All four actors also read ordinary secrets, list paths, look up and renew their token, and make isolated denied audit DELETE attempts in both modes. The `suspicious_*` parameter names configure the fourth ordinary identity too, rather than creating a mode-exclusive account.

Rules can correlate ten successful payroll read responses within five minutes and the following denied audit DELETE under the same token and entity. A read burst and a denied administrative operation can also be evaluated separately. These records do not prove exfiltration, a successful audit shutdown, or why a valid identity behaved this way.

State consists of four fixed token contexts, the fixed 52-secret inventory, one current pair, an eleven-step episode context, and bounded cursors and clocks. No request UUID history, new secret, account, or token collection grows during generation. Mandatory renewal precedes new work, and a sequence starts only with sufficient renewal headroom.

## Reference Field Map and Limits

| Field group | Primary basis and selected treatment |
|---|---|
| `type`, `time`, `request.id` | Tagged audit structures; fresh UUID per operation, linked pair, UTC source time |
| `auth`, client tokens and accessors | Tagged formatter and hash walker; keyed HMAC-SHA256 with one persistent synthetic device salt, plain auth metadata/policies/entity/display name |
| `auth.policy_results` | Tagged v1.18.0 formatter; successful single-policy results preserve its initial `{"type":""}` element before the named ACL grant; denied results have no granting array |
| Request mount context | Mount type/class/point available before ACL; read/list/lookup requests acquire `mount_accessor` only after routing in the response entry, renewal before request auditing through existence checking, denied DELETE never routes |
| KV response data and metadata | Tagged KV v0.20.0; string values HMAC, `version: 1`, `destroyed: false`, `custom_metadata: null` |
| LIST response keys | Inventory-consistent child names, sorted before string HMAC, no list-response elision |
| Lookup response data | Tagged token store; string values HMAC, numeric TTL and timestamps literal, original issue/creation information |
| Lookup `issue_time`, `expire_time`, `last_renewal` | Typed `time.Time` values remain readable RFC3339 through the tagged hash walker's `SkipEntry` exception; KV metadata timestamps are strings and are hashed |
| Renewal `response.auth` | Saved login lease authentication with the same token, policies and issue time, refreshed period, and no invented policy-result array |
| Denied request and response errors | Tagged core ACL rejection; plaintext top-level error and keyed HMAC of the error under response data |
| Parsed namespace and ECS fields | Maintained Elastic audit sample and pipeline; extract source time into `@timestamp`, remove parsed `audit.time`, retain it in `event.original` |
| `log.offset` | UTF-8 byte length of each exact native JSON serialization plus newline in the selected unrotated file |

All **47/47 leaf paths** in the pinned Elastic `sample_event.json` occur in the generated profile. Arrays count as a single leaf path. That reference is a small audit-device update request from an older fixture, not an endpoint-complete v1.18.0 trace. This count establishes normalized field presence only, not native parity, parser acceptance, or completeness of all Vault audit fields.

`BLOCKED_RAW_EVIDENCE` remains: tagged vendor code and older maintained raw examples support these selected structures, but a complete live v1.18.0 capture covering all five operation families and a run through a live SIEM parser were not obtained. Optional request headers, forwarding and enterprise fields, installed mount running-version/SHA fields, and other endpoints are omitted. Mount accessor strings and bindings are synthetic configured inventory, not an observed installed build. JSON key order and timestamp precision are selected serialization choices rather than byte parity with a captured Go encoder.

Source request time comes from the input in UTC, response time is 50 ms later, and collector ingestion is another 200 ms later. These fixed latencies are explicit training assumptions. Four fixed peer ports represent selected client inventory without claiming a TCP connection lifecycle. `user.name` is a collector enrichment from the userpass metadata. `event.agent_id_status: verified` is also synthetic collector context and does not establish verification by a live collector. `source`, `related`, host details and collector identity are enrichment; the output does not claim exact reproduction of the maintained Elastic pipeline. Error-derived ECS outcome and broad authentication category follow that pipeline, so a successful request entry alone is not evidence of backend completion.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Name | Default | Purpose |
|---|---|---|
| `anomaly_mode` | `true` | Periodic episodes mixed with ordinary activity; `false` retains background only |
| `anomaly_interval_hours` | `24` | Positive finite recurrence interval, supported range 6 to 8,760 hours |
| `vault_host` | `vault-01.corp.example` | Vault node and collector hostname |
| `vault_ip` | `10.20.2.18` | Vault node address |
| `collector_id` | `65fa5f58-a1d2-49d1-b4cc-05228dd270f3` | Stable collector ID |
| `collector_ephemeral_id` | `8dcba887-bc9d-44cb-bfcd-ed7aa7216748` | Collector process ID |
| `collector_version` | `8.10.1` | Collector version |
| `suspicious_ip` | `198.51.100.44` | Fourth identity's peer address in ordinary activity and eligible episodes |
| `suspicious_actor` | `svc-reports` | Fourth existing userpass account in ordinary activity and eligible episodes |
| `secret_mount` | `secret` | Selected KV v2 mount, without leading or trailing slash |

The configured fourth account must differ from `svc-api`, `svc-billing`, and `alice`. Synthetic tokens, accessors, inventory values and device salt are internal test fixtures, not credentials for a real Vault installation.

### Output Parameters

The shipped file output needs no substitutions. To deliver to OpenSearch, replace it with the output plugin configuration using `${params.opensearch_host}` and keyring-backed `${secrets.opensearch_password}`. See the [OpenSearch output guide](https://eventum.run/docs/tutorials/delivery/opensearch).

## Usage

Run from the content-packs repository root with the sibling Eventum checkout providing the existing uv environment:

```bash
# Initial bounded batch sample. Exit 124 from timeout is expected.
flock -x /tmp/eventum-generator-heavy.lock timeout 3 uv run --project ../eventum eventum generate --path generators/security-hashicorp-vault/generator.yml --id vault --live-mode false --keep-order true

# Continuous generation: one operation and two audit entries per 30 seconds.
uv run --project ../eventum eventum generate --path generators/security-hashicorp-vault/generator.yml --id vault --live-mode true --keep-order true
```

For complete batch validation, use a temporary configuration with finite cron `start` and `end`, an output path outside the pack, and a window long enough for at least two episodes. A short sample is not a recurrence check.

The final four 76-hour-20-minute captures each contain 18,322 entries and 9,161 operations. Default 24-hour mode produces 3/0 episodes with anomalies on/off; custom 12-hour mode produces 6/0. A 100-hour-20-minute run at the minimum 6-hour interval contains 24,082 entries, 12,041 operations, and 16 episodes. All four actors use all five operation families and all 52 secret paths occur in ordinary traffic. Visible renewals preserve valid token lifetime. Four causal negative cases are rejected: changing the actor inside the burst, returning a missing secret, claiming read permission from the default policy alone, and using a token after removing its renewals. These checks validate the selected synthetic behavior, not the missing live raw/parser gate.

## Sample Output

This complete denied response is copied from row 5,800 of the final default-on capture. Its correlated sequence begins with ten payroll reads. The native request and response share the operation UUID, and the denied DELETE does not disable auditing.

```json
{
  "@timestamp": "2026-09-27T00:09:30.050000+00:00",
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
      "authentication"
    ],
    "dataset": "hashicorp_vault.audit",
    "id": "7ea3a2f1-afc1-45aa-a5f7-589c43b91526",
    "ingested": "2026-09-27T00:09:30.250000+00:00",
    "kind": "event",
    "original": "{\"auth\":{\"accessor\":\"hmac-sha256:69580ad3726a6da4479f5008d8f4f12f2d6de2d17bcffa8555a94a61c68e2089\",\"client_token\":\"hmac-sha256:ba46a928fde74f55fd6f2d6059b180eb5b234332e0f745e7de3a228192dadb35\",\"display_name\":\"userpass-svc-billing\",\"entity_id\":\"09ae6e74-f30a-4713-83a5-c8be3496bdbe\",\"metadata\":{\"username\":\"svc-billing\"},\"policies\":[\"default\",\"training-reader\"],\"policy_results\":{\"allowed\":false},\"token_policies\":[\"default\",\"training-reader\"],\"token_issue_time\":\"2026-09-25T22:00:00Z\",\"token_ttl\":86400,\"token_type\":\"service\"},\"error\":\"1 error occurred:\\n\\t* permission denied\\n\\n\",\"request\":{\"client_id\":\"09ae6e74-f30a-4713-83a5-c8be3496bdbe\",\"client_token\":\"hmac-sha256:ba46a928fde74f55fd6f2d6059b180eb5b234332e0f745e7de3a228192dadb35\",\"client_token_accessor\":\"hmac-sha256:69580ad3726a6da4479f5008d8f4f12f2d6de2d17bcffa8555a94a61c68e2089\",\"id\":\"7ea3a2f1-afc1-45aa-a5f7-589c43b91526\",\"mount_class\":\"secret\",\"mount_point\":\"sys/\",\"mount_type\":\"system\",\"namespace\":{\"id\":\"root\"},\"operation\":\"delete\",\"path\":\"sys/audit/file\",\"remote_address\":\"10.20.8.31\",\"remote_port\":51002,\"request_uri\":\"/v1/sys/audit/file\"},\"response\":{\"mount_class\":\"secret\",\"mount_point\":\"sys/\",\"mount_type\":\"system\",\"data\":{\"error\":\"hmac-sha256:ec125ce39ac232369c1e227ed31f30b8b1a43010aa94029c6b423af8d061ce97\"}},\"time\":\"2026-09-27T00:09:30.050000Z\",\"type\":\"response\"}",
    "outcome": "failure",
    "type": [
      "info",
      "end"
    ]
  },
  "hashicorp_vault": {
    "audit": {
      "auth": {
        "accessor": "hmac-sha256:69580ad3726a6da4479f5008d8f4f12f2d6de2d17bcffa8555a94a61c68e2089",
        "client_token": "hmac-sha256:ba46a928fde74f55fd6f2d6059b180eb5b234332e0f745e7de3a228192dadb35",
        "display_name": "userpass-svc-billing",
        "entity_id": "09ae6e74-f30a-4713-83a5-c8be3496bdbe",
        "metadata": {
          "username": "svc-billing"
        },
        "policies": [
          "default",
          "training-reader"
        ],
        "policy_results": {
          "allowed": false
        },
        "token_issue_time": "2026-09-25T22:00:00Z",
        "token_policies": [
          "default",
          "training-reader"
        ],
        "token_ttl": 86400,
        "token_type": "service"
      },
      "error": "1 error occurred:\n\t* permission denied\n\n",
      "request": {
        "client_id": "09ae6e74-f30a-4713-83a5-c8be3496bdbe",
        "client_token": "hmac-sha256:ba46a928fde74f55fd6f2d6059b180eb5b234332e0f745e7de3a228192dadb35",
        "client_token_accessor": "hmac-sha256:69580ad3726a6da4479f5008d8f4f12f2d6de2d17bcffa8555a94a61c68e2089",
        "id": "7ea3a2f1-afc1-45aa-a5f7-589c43b91526",
        "mount_class": "secret",
        "mount_point": "sys/",
        "mount_type": "system",
        "namespace": {
          "id": "root"
        },
        "operation": "delete",
        "path": "sys/audit/file",
        "remote_address": "10.20.8.31",
        "remote_port": 51002,
        "request_uri": "/v1/sys/audit/file"
      },
      "response": {
        "data": {
          "error": "hmac-sha256:ec125ce39ac232369c1e227ed31f30b8b1a43010aa94029c6b423af8d061ce97"
        },
        "mount_class": "secret",
        "mount_point": "sys/",
        "mount_type": "system"
      },
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
    "offset": 8997472
  },
  "message": "1 error occurred:\n\t* permission denied\n\n",
  "related": {
    "ip": [
      "10.20.8.31"
    ],
    "user": [
      "svc-billing"
    ]
  },
  "source": {
    "ip": "10.20.8.31",
    "port": 51002
  },
  "tags": [
    "hashicorp-vault-audit"
  ],
  "user": {
    "name": "svc-billing"
  }
}
```

## References

- [Vault audit schema](https://developer.hashicorp.com/vault/docs/audit/schema) and [file audit device](https://developer.hashicorp.com/vault/docs/audit/file)
- [Vault v1.18.0 audit formatter](https://github.com/hashicorp/vault/blob/v1.18.0/audit/entry_formatter.go), [hash walker](https://github.com/hashicorp/vault/blob/v1.18.0/audit/hashstructure.go), and [time-value tests](https://github.com/hashicorp/vault/blob/v1.18.0/audit/hashstructure_test.go)
- [Vault v1.18.0 request handling](https://github.com/hashicorp/vault/blob/v1.18.0/vault/request_handling.go), [router](https://github.com/hashicorp/vault/blob/v1.18.0/vault/router.go), and [token store](https://github.com/hashicorp/vault/blob/v1.18.0/vault/token_store.go)
- [Vault v1.18.0 expiration handling](https://github.com/hashicorp/vault/blob/v1.18.0/vault/expiration.go), [userpass renewal](https://github.com/hashicorp/vault/blob/v1.18.0/builtin/credential/userpass/path_login.go), and [KV version pin](https://github.com/hashicorp/vault/blob/v1.18.0/go.mod)
- [KV v0.20.0 read data](https://github.com/hashicorp/vault-plugin-secrets-kv/blob/v0.20.0/path_data.go) and [metadata/listing](https://github.com/hashicorp/vault-plugin-secrets-kv/blob/v0.20.0/path_metadata.go)
- [Pinned Elastic Vault integration](https://github.com/elastic/integrations/tree/78fd455d22cdb74bd2a8e53249c25cc060f06010/packages/hashicorp_vault/data_stream/audit), [sample event](https://github.com/elastic/integrations/blob/78fd455d22cdb74bd2a8e53249c25cc060f06010/packages/hashicorp_vault/data_stream/audit/sample_event.json), and [pipeline](https://github.com/elastic/integrations/blob/78fd455d22cdb74bd2a8e53249c25cc060f06010/packages/hashicorp_vault/data_stream/audit/elasticsearch/ingest_pipeline/default.yml)

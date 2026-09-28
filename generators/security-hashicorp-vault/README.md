# HashiCorp Vault Audit Generator

Generates a selected Vault v1.18.0 file-audit profile for KV v2 reads and lists, token self-lookup and renewal, and denied audit-device deletion. Each API operation emits a linked request/response pair inside ECS-compatible JSON. `event.original` contains the synthetic native audit JSON, including its source timestamp.

## Event Types Covered

| Operation family | Native operation and path | Share, default on / off | ECS category |
|---|---|---:|---|
| KV v2 read, application/billing | `read`, `secret/data/{app,billing}/*` | 49.7% / 48.1% | authentication |
| KV v2 read, payroll | `read`, `secret/data/payroll/*` | 28.8% / 30.1% | authentication |
| Token self-lookup | `read`, `auth/token/lookup-self` | 10.4% / 10.5% | authentication |
| KV v2 metadata list | `list`, `secret/metadata/{app,billing,payroll}` | 10.4% / 10.8% | authentication |
| Denied audit-device deletion | `delete`, `sys/audit/file` | 0.54% / 0.36% | authentication |
| Token self-renewal | `update`, `auth/token/renew-self` | 0.20% / 0.19% | authentication |

Shares are measured over the 17,321 operations of the final default captures with anomalies on and off; the denied DELETE share varies between runs (0.32-0.50% over six default background captures). They are training assumptions, not production frequencies. Each operation produces two entries, `type: request` and `type: response`, with the same `request.id`. `mode: all` renders the request before the response for each input timestamp. The six-field cron expression with `count: 1` gives one operation per 30-second input slot, or 2,880 operations and 5,760 audit entries per full day. The source time of each operation is a random instant inside its slot. Preserve output order with `--keep-order true`.

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

Initial logins happened at random moments between 10 minutes and about 17 hours before the first timestamp. The 52 version-1 secrets were created at random moments 1 to 30 days before it. Each client renews its token the way the Vault API `LifetimeWatcher` schedules it: after two thirds of the 24-hour lease plus one third of a grace drawn from 10-20% of the lease. That is 16.8 to 17.6 hours after login or the previous renewal; in the final captures renewal gaps were 60,490 to 63,370 seconds. A long-running watcher keeps its first grace; here the grace is drawn again for every cycle. Renewal extends expiration while the request is handled, and the following lookups report that instant as `last_renewal`. Stored `auth.token_ttl` remains the creation period of 86,400 seconds. Lookup `response.data.ttl` reports remaining lifetime. Renewal does not create a new token or change its original issue time.

The secret inventory contains 12 application/billing paths and 40 payroll paths, with synthetic values. Every read returns data plus KV version metadata. Lists contain the sorted child names from this inventory before hashing. No secret write, deletion, version change, token creation, or revocation is included.

Background traffic comes from independent processes that behave the same with anomalies on and off:

- **Single operations.** Each input slot not taken by another process draws an actor (weights 45/25/20/10) and a read, list or lookup. A read targets a random payroll secret in 35% of cases, otherwise a random application/billing secret.
- **Payroll batches.** About 12 per day, one actor reads a run of distinct payroll secrets: an ascending employee range in 60% of batches, a random subset otherwise. Lengths are log-normal with a median of about 6 reads and runs of 10 or more reads occur several times a day. A batch takes each slot with probability 0.8, so it interleaves with other traffic.
- **Denied audit-device deletions.** About 8 attempts per day by an actor drawn by weight (30/25/25/20); 35% are retried by the same actor after a log-normal delay (median 45 seconds).
- **Token renewals** as described above, taking precedence over all other work.
- **Client connections.** A client reuses its ephemeral source port until it has been idle for more than 90 seconds, then connects from a new random port in 32768-60999.

**Guard.** One background rule keeps ordinary traffic from completing the anomaly by coincidence, and it acts only on the chain's last step. The template follows every emitted request with the same ordered matcher a detector uses: per actor, three distinct payroll reads followed by an audit DELETE, the first of those reads at most 400 seconds before the DELETE. An ordinary DELETE attempt or retry that would complete this sequence is dropped: no record is made, its actor is not replaced, and the input slot goes to the next pending work. DELETEs after 400 seconds, DELETEs by other actors, and DELETEs after repeated or earlier payroll reads remain in background.

## Anomaly Chain

`event.template.params.anomaly_mode` defaults to `true`. Setting it to `false` produces only the background above, without the complete sequence.

Each episode is one existing actor reading ten distinct payroll secrets, then attempting to delete `sys/audit/file`. The reads follow the payroll batch process: the same pacing, and an ascending employee range or a random subset. The DELETE follows at the actor's next step. Its explicit reader ACL permits the reads and rejects the audit DELETE. Both entries for the denied operation retain valid authentication, `policy_results.allowed=false`, the core permission error, and a hashed `response.data.error`. The audit device remains enabled. In the final captures an episode spanned 272 to 618 seconds from the first read to the DELETE.

Background rates do not vary by time of day, so start times are drawn uniformly. The first episode starts at a random time within the first interval, or the first 24 hours when the interval is longer. Each later one starts at a random time within a window of a quarter of the interval (at most 6 hours) centred on one interval after the actual first read of the previous episode; there is no backlog of missed episodes. An episode yields each slot to renewals, retries, pending deletion attempts and running batches, and waits while every eligible actor runs a batch, so it starts up to a few minutes after its drawn time. At the default interval the first episode started 22.6 hours after the window start and consecutive starts were 22.7 to 26.5 hours apart; at 12 hours they were 10.6 to 13.5 hours apart. Each episode uses a different actor from the previous one and a different starting payroll secret. Fresh operation UUIDs are drawn for every operation.

Every element of the chain also occurs on its own in both modes: runs of ten or more payroll reads by one actor, repeated payroll reads by one actor within a minute, and denied audit DELETEs by all four actors, including retries and DELETEs preceded by one or two payroll reads. A detection rule has to combine them: three or more distinct payroll reads by one token and entity, followed by that token's denied `sys/audit/file` DELETE within 400 seconds of the first of them. These records do not prove exfiltration, a successful audit shutdown, or why a valid identity behaved this way.

State consists of four token contexts, the fixed 52-secret inventory with creation times, at most three running batches, a few pending retries, one current pair, and one episode context. The chain guard keeps at most eight partial matches per actor, each for 400 seconds. No request UUID history, new secret, account, or token collection grows during generation.

## Reference Field Map and Limits

| Field group | Primary basis and selected treatment |
|---|---|
| `type`, `time`, `request.id` | Tagged audit structures; fresh UUID per operation, linked pair, UTC source time in Go `RFC3339Nano` form |
| `auth`, client tokens and accessors | Tagged formatter and hash walker; keyed HMAC-SHA256 with one persistent synthetic device salt, plain auth metadata/policies/entity/display name |
| `auth.policy_results` | Tagged v1.18.0 formatter; successful single-policy results preserve its initial `{"type":""}` element before the named ACL grant; denied results have no granting array |
| Request mount context | Mount type/class/point available before ACL; read/list/lookup requests acquire `mount_accessor` only after routing in the response entry, renewal before request auditing through existence checking, denied DELETE never routes |
| KV response data and metadata | Tagged KV v0.20.0; string values HMAC, `version: 1`, `destroyed: false`, `custom_metadata: null` |
| LIST response keys | Inventory-consistent child names, sorted before string HMAC, no list-response elision |
| Lookup response data | Tagged token store; string values HMAC, numeric TTL and timestamps literal, original issue/creation information |
| Lookup `issue_time`, `expire_time`, `last_renewal` | Typed `time.Time` values remain readable RFC3339 through the tagged hash walker's `SkipEntry` exception; KV metadata timestamps are strings and are hashed |
| Renewal `response.auth` | Saved login lease authentication with the same token, policies and issue time, refreshed period, and no invented policy-result array |
| Denied request and response errors | Tagged core ACL rejection; plaintext top-level error and keyed HMAC of the error under response data |
| Parsed namespace and ECS fields | Maintained Elastic audit sample and pipeline; extract source time into `@timestamp` at millisecond precision, remove parsed `audit.time`, retain it in `event.original`; `event.ingested` in whole seconds as in the sample |
| `log.offset` | UTF-8 byte length of each exact native JSON serialization plus newline in the selected unrotated file |

All **47/47 leaf paths** in the pinned Elastic `sample_event.json` occur in the generated profile. Arrays count as a single leaf path. That reference is a small audit-device update request from an older fixture, not an endpoint-complete v1.18.0 trace. This count establishes normalized field presence only, not native parity, parser acceptance, or completeness of all Vault audit fields.

`BLOCKED_RAW_EVIDENCE` remains: tagged vendor code and older maintained raw examples support these selected structures, but a complete live v1.18.0 capture covering all five operation families and a run through a live SIEM parser were not obtained. Optional request headers, forwarding and enterprise fields, installed mount running-version/SHA fields, and other endpoints are omitted. Mount accessor strings and bindings are synthetic configured inventory, not an observed installed build. JSON key order is a selected serialization choice rather than byte parity with a captured Go encoder.

Timing values are training assumptions, not measurements. Handling latency between request and response entries is log-normal, with medians of about 0.4 ms for a denied DELETE, 0.9 ms for lookup, 1.6 ms for reads, 2.1 ms for lists and 3 ms for renewals. Collector ingestion lags the source time by a log-normal delay with a median of about 2.5 seconds. The 90-second idle limit for client connections follows common HTTP client pools; it is not taken from a Vault client configuration. Only one operation is in flight at a time, so concurrent requests from different clients never interleave in the file. `user.name` is a collector enrichment from the userpass metadata. `event.agent_id_status: verified` is also synthetic collector context and does not establish verification by a live collector. `source`, `related`, host details and collector identity are enrichment; the output does not claim exact reproduction of the maintained Elastic pipeline. Error-derived ECS outcome and broad authentication category follow that pipeline, so a successful request entry alone is not evidence of backend completion.

Rates are stationary: there is no daily or weekly cycle. Near-identical renewal periods keep two tokens whose renewals start close together close for several cycles. Unlike a real `LifetimeWatcher`, which keeps one grace per watcher and renews once immediately at start, this model redraws the grace every cycle and does not emit the start-up renewal.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Name | Default | Purpose |
|---|---|---|
| `anomaly_mode` | `true` | Periodic episodes mixed with background; `false` produces background only |
| `anomaly_interval_hours` | `24` | Hours from one episode's first read to the centre of the next episode's start window, 6 to 8,760 |
| `vault_host` | `vault-01.corp.example` | Vault node and collector hostname |
| `vault_ip` | `10.20.2.18` | Vault node address |
| `collector_id` | `65fa5f58-a1d2-49d1-b4cc-05228dd270f3` | Stable collector ID |
| `collector_ephemeral_id` | `8dcba887-bc9d-44cb-bfcd-ed7aa7216748` | Collector process ID |
| `collector_version` | `8.10.1` | Collector version |
| `suspicious_ip` | `198.51.100.44` | Fourth identity's peer address, used in background and eligible episodes |
| `suspicious_actor` | `svc-reports` | Fourth existing userpass account, used in background and eligible episodes |
| `secret_mount` | `secret` | Selected KV v2 mount, without leading or trailing slash |

The configured fourth account must differ from `svc-api`, `svc-billing`, and `alice`. The `suspicious_*` names are historical; this identity is an ordinary account in both modes. Synthetic tokens, accessors, inventory values and device salt are internal test fixtures, not credentials for a real Vault installation.

### Output Parameters

The shipped file output needs no substitutions. To deliver to OpenSearch, replace the `output` section:

```yaml
output:
  - opensearch:
      hosts:
        - ${params.opensearch_host}
      username: ${params.opensearch_user}
      password: ${secrets.opensearch_password}
      index: ${params.opensearch_index}
```

| Parameter | Description |
|---|---|
| `${params.opensearch_host}` | OpenSearch host URL |
| `${params.opensearch_user}` | Username for authentication |
| `${secrets.opensearch_password}` | Password from the Eventum keyring |
| `${params.opensearch_index}` | Target index name |

See the [OpenSearch output guide](https://eventum.run/docs/tutorials/delivery/opensearch).

## Usage

Run from the `content-packs` repository root:

```bash
# Batch: generate as fast as possible and stop at the end of the input window
eventum generate --path generators/security-hashicorp-vault/generator.yml --id vault --live-mode false --keep-order true

# Live: one operation and two audit entries per 30 seconds
eventum generate --path generators/security-hashicorp-vault/generator.yml --id vault --live-mode true --keep-order true
```

The shipped cron input has no end, so a batch run continues until it is stopped. For a finite batch, add `start` and `end` to the cron input in a copy of the configuration and choose a window of at least two intervals.

Final validation used finite 144-hour-20-minute windows. The default and custom (12-hour interval, other host, fourth account and a Unicode KV mount) captures each contain 34,642 entries and 17,321 operations, with 5/0 and 12/0 episodes with anomalies on/off. Background decisions were compared between the modes and against five (default) and four (custom) further independent background-only captures. The calibrated `mode_compare.py` comparison returns OK for both pairs.

Near misses were measured over the eleven background captures, keyed to the matcher state (time since the first read of the latest three-distinct-read sequence). DELETEs by the same actor occur 0 times inside 400 seconds and 0.11-0.18 per hour in each 50-second bin from 400 to 800 seconds, close to an actor's ordinary DELETE rate of about 0.11 per hour. DELETEs by other actors occur 0.33 per hour inside the window and 0.36 outside it.

## Sample Output

This complete denied response is row 5,454 of the final default capture with anomalies on. It ends the first episode: `svc-api` read ten payroll secrets from 22:36:33 and attempted the DELETE at 22:43:25. The request and response share the operation UUID, and the denied DELETE does not disable auditing.

```json
{
  "@timestamp": "2026-09-26T22:43:25.293Z",
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
    "id": "0728bc8f-1033-462e-bc19-39a17b7e0c3d",
    "ingested": "2026-09-26T22:43:32Z",
    "kind": "event",
    "original": "{\"auth\":{\"accessor\":\"hmac-sha256:8bfe54d69390a4adc95d16a826f3792753ddd31cfe36ded64625ae4b0a765b3d\",\"client_token\":\"hmac-sha256:758dc31f91fd147aca412e25f6f312ca5e72641f15ddd6c21ee7ba78bd8f168a\",\"display_name\":\"userpass-svc-api\",\"entity_id\":\"49263c43-35ab-4df6-a747-1715203590ba\",\"metadata\":{\"username\":\"svc-api\"},\"policies\":[\"default\",\"training-reader\"],\"policy_results\":{\"allowed\":false},\"token_policies\":[\"default\",\"training-reader\"],\"token_issue_time\":\"2026-09-25T15:49:12Z\",\"token_ttl\":86400,\"token_type\":\"service\"},\"error\":\"1 error occurred:\\n\\t* permission denied\\n\\n\",\"request\":{\"client_id\":\"49263c43-35ab-4df6-a747-1715203590ba\",\"client_token\":\"hmac-sha256:758dc31f91fd147aca412e25f6f312ca5e72641f15ddd6c21ee7ba78bd8f168a\",\"client_token_accessor\":\"hmac-sha256:8bfe54d69390a4adc95d16a826f3792753ddd31cfe36ded64625ae4b0a765b3d\",\"id\":\"0728bc8f-1033-462e-bc19-39a17b7e0c3d\",\"mount_class\":\"secret\",\"mount_point\":\"sys/\",\"mount_type\":\"system\",\"namespace\":{\"id\":\"root\"},\"operation\":\"delete\",\"path\":\"sys/audit/file\",\"remote_address\":\"10.20.8.12\",\"remote_port\":38729,\"request_uri\":\"/v1/sys/audit/file\"},\"response\":{\"mount_class\":\"secret\",\"mount_point\":\"sys/\",\"mount_type\":\"system\",\"data\":{\"error\":\"hmac-sha256:ec125ce39ac232369c1e227ed31f30b8b1a43010aa94029c6b423af8d061ce97\"}},\"time\":\"2026-09-26T22:43:25.293801903Z\",\"type\":\"response\"}",
    "outcome": "failure",
    "type": [
      "info",
      "end"
    ]
  },
  "hashicorp_vault": {
    "audit": {
      "auth": {
        "accessor": "hmac-sha256:8bfe54d69390a4adc95d16a826f3792753ddd31cfe36ded64625ae4b0a765b3d",
        "client_token": "hmac-sha256:758dc31f91fd147aca412e25f6f312ca5e72641f15ddd6c21ee7ba78bd8f168a",
        "display_name": "userpass-svc-api",
        "entity_id": "49263c43-35ab-4df6-a747-1715203590ba",
        "metadata": {
          "username": "svc-api"
        },
        "policies": [
          "default",
          "training-reader"
        ],
        "policy_results": {
          "allowed": false
        },
        "token_issue_time": "2026-09-25T15:49:12Z",
        "token_policies": [
          "default",
          "training-reader"
        ],
        "token_ttl": 86400,
        "token_type": "service"
      },
      "error": "1 error occurred:\n\t* permission denied\n\n",
      "request": {
        "client_id": "49263c43-35ab-4df6-a747-1715203590ba",
        "client_token": "hmac-sha256:758dc31f91fd147aca412e25f6f312ca5e72641f15ddd6c21ee7ba78bd8f168a",
        "client_token_accessor": "hmac-sha256:8bfe54d69390a4adc95d16a826f3792753ddd31cfe36ded64625ae4b0a765b3d",
        "id": "0728bc8f-1033-462e-bc19-39a17b7e0c3d",
        "mount_class": "secret",
        "mount_point": "sys/",
        "mount_type": "system",
        "namespace": {
          "id": "root"
        },
        "operation": "delete",
        "path": "sys/audit/file",
        "remote_address": "10.20.8.12",
        "remote_port": 38729,
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
    "offset": 8467024
  },
  "message": "1 error occurred:\n\t* permission denied\n\n",
  "related": {
    "ip": [
      "10.20.8.12"
    ],
    "user": [
      "svc-api"
    ]
  },
  "source": {
    "ip": "10.20.8.12",
    "port": 38729
  },
  "tags": [
    "hashicorp-vault-audit"
  ],
  "user": {
    "name": "svc-api"
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

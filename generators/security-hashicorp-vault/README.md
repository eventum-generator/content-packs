# HashiCorp Vault Audit Generator

Generates a selected Vault v1.18.0 file-audit profile for KV v2 reads and lists, token self-lookup and renewal, and denied audit-device deletion. Each API operation emits a linked request/response pair inside ECS-compatible JSON. `event.original` contains the synthetic native audit JSON, including its source timestamp.

## Event Types Covered

| Operation family | Native operation and path | Share, anomalies on / off | ECS category |
|---|---|---:|---|
| KV v2 read, application/billing | `read`, `secret/data/{app,billing}/*` | 48.1% / 48.6% | authentication |
| KV v2 read, payroll | `read`, `secret/data/payroll/*` | 30.3% / 29.4% | authentication |
| Token self-lookup | `read`, `auth/token/lookup-self` | 10.9% / 10.7% | authentication |
| KV v2 metadata list | `list`, `secret/metadata/{app,billing,payroll}` | 10.4% / 10.8% | authentication |
| Denied audit-device deletion | `delete`, `sys/audit/file` | 0.25% / 0.24% | authentication |
| Token self-renewal | `update`, `auth/token/renew-self` | 0.19% / 0.19% | authentication |

Shares are over six days of operations with the default settings. The denied DELETE share varies between 0.13% and 0.27% from one six-day period to another. They are training assumptions, not production frequencies. Each operation produces two entries, `type: request` and `type: response`, with the same `request.id`; the request comes first. There is one operation per 30-second period, 2,880 operations and 5,760 audit entries per day, at a random moment inside the period.

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

Initial logins happened at random moments between 10 minutes and about 17 hours before the first timestamp. The 52 version-1 secrets were created at random moments 1 to 30 days before it. Each client renews its token the way the Vault API `LifetimeWatcher` schedules it: after two thirds of the 24-hour lease plus one third of a grace drawn from 10-20% of the lease. That is 16.8 to 17.6 hours, or about 60,480 to 63,390 seconds, after login or the previous renewal. The grace is drawn again for every cycle. Renewal extends expiration while the request is handled, and the following lookups report that instant as `last_renewal`. Stored `auth.token_ttl` remains the creation period of 86,400 seconds. Lookup `response.data.ttl` reports remaining lifetime. Renewal does not create a new token or change its original issue time.

The secret inventory contains 12 application/billing paths and 40 payroll paths, with synthetic values. Every read returns data plus KV version metadata. Lists contain the sorted child names from this inventory before hashing. No secret write, deletion, version change, token creation, or revocation is included.

Background activity is the same with anomalies on and off:

- **Single operations.** Most operations are independent reads, lists or lookups by an account chosen with weights 45/25/20/10. A read targets a random payroll secret in 35% of cases, otherwise a random application/billing secret.
- **Payroll batches.** About 12 per day, one actor reads a run of distinct payroll secrets: an ascending employee range in 60% of batches, a random subset otherwise. Lengths are log-normal with a median of about 6 reads, and runs of 10 or more reads occur several times a day. A batch reads about one secret every 37 seconds, interleaved with other traffic.
- **Denied audit-device deletions.** About 4 attempts per day, as from a misconfigured maintenance script, spread about evenly over the four accounts so that each account makes some every day or two. 35% of attempts are retried by the same account after a log-normal delay (median 45 seconds), and a retry can be retried again.
- **Token renewals** as described above.
- **Client connections.** A client reuses its ephemeral source port until it has been idle for more than 90 seconds, then connects from a new random port in 32768-60999.

**No complete sequence in background.** An account's audit DELETE never follows its reads of three or more distinct payroll secrets within 400 seconds, also right after an episode. DELETEs after 400 seconds, DELETEs by other accounts, and DELETEs after one or two distinct payroll reads do occur.

## Anomaly Chain

`event.template.params.anomaly_mode` defaults to `true`. Setting it to `false` produces only the background above, without the complete sequence.

Each episode is one existing account reading ten distinct payroll secrets, pausing for up to four minutes, then attempting to delete `sys/audit/file`. The reads look like a payroll batch: the same pacing, and an ascending employee range or a random subset. When other traffic spreads the reads so far apart that fewer than three of them fall within 400 seconds of the DELETE, the account reads one more payroll secret first. Its explicit reader ACL permits the reads and rejects the audit DELETE. Both entries for the denied operation retain valid authentication, `policy_results.allowed=false`, the core permission error, and a hashed `response.data.error`. The audit device remains enabled. An episode spans about 5 to 12 minutes from the first read to the DELETE.

Background rates do not vary by time of day, so episode start times are uniform over the day. The first episode starts at a random time within the first `anomaly_interval_hours`, or the first 24 hours when the interval is longer. Each later one starts at a random time within a window of a quarter of the interval (at most 6 hours) centred on one interval after the first read of the previous episode, so at the default interval consecutive episodes start 21 to 27 hours apart. Missed episodes are not made up later. Each episode uses a different account from the previous one and a different starting payroll secret. Every operation has a fresh UUID.

Every element of the chain also occurs on its own in both modes: runs of ten or more payroll reads by one account, repeated payroll reads by one account within a minute, and denied audit DELETEs by all four accounts, including retries and DELETEs preceded by one or two payroll reads. A detection rule has to combine them: three or more distinct payroll reads by one token and entity, followed by that token's denied `sys/audit/file` DELETE within 400 seconds of the first of them. Each episode completes this sequence exactly once. With `anomaly_mode: true` each episode adds its own records, so counts of the chain parts are about one per episode higher than with `false`: runs of ten payroll reads within ten minutes, audit DELETEs preceded by one or two distinct payroll reads of the same account, and that account's denied DELETEs. These records do not prove exfiltration, a successful audit shutdown, or why a valid identity behaved this way.

## Source Fidelity and Limits

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

The output contains all 47 leaf paths of the pinned Elastic `sample_event.json`, with arrays counted as a single leaf path. That reference is a small audit-device update request from an older fixture, not an endpoint-complete v1.18.0 trace, so field presence does not imply native parity, parser acceptance, or completeness of all Vault audit fields.

The structures follow tagged vendor code and older maintained raw examples rather than a complete live v1.18.0 audit log covering all five operation families. Optional request headers, forwarding and enterprise fields, installed mount running-version/SHA fields, and other endpoints are omitted. Mount accessor strings and bindings are synthetic configured inventory, not an observed installed build. JSON key order is a selected serialization choice rather than byte parity with a captured Go encoder.

Timing values are training assumptions, not measurements. Handling latency between request and response entries is log-normal, with medians of about 0.4 ms for a denied DELETE, 0.9 ms for lookup, 1.6 ms for reads, 2.1 ms for lists and 3 ms for renewals. Collector ingestion lags the source time by a log-normal delay with a median of about 2.5 seconds. The 90-second idle limit for client connections follows common HTTP client pools; it is not taken from a Vault client configuration. Operations never overlap: each request entry is followed by its response before the next request, so concurrent requests from different clients never interleave in the file. `user.name` is a collector enrichment from the userpass metadata. `event.agent_id_status: verified` is also synthetic collector context and does not establish verification by a live collector. `source`, `related`, host details and collector identity are enrichment; the output does not claim exact reproduction of the maintained Elastic pipeline. Error-derived ECS outcome and broad authentication category follow that pipeline, so a successful request entry alone is not evidence of backend completion.

Rates are stationary: there is no daily or weekly cycle, and there is exactly one operation per 30 seconds. Denied audit DELETEs come from all four accounts in about equal numbers. With anomalies on, counts of the chain parts are about one per episode higher, as described under Anomaly Chain. Unlike a real `LifetimeWatcher`, which keeps one grace per watcher and renews once immediately at start, this model redraws the grace every cycle and does not emit the start-up renewal.

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

Keep `--keep-order true` so that each request entry precedes its response. The shipped configuration has no end, so a batch run continues until it is stopped. For a finite batch, add `start` and `end` to the `cron` input in a copy of the configuration and choose a window of at least two intervals. In live mode an entry is written 0.5 to 30 seconds after its source time, never ahead of the clock.

## Performance

About 1,600 audit entries per second on one CPU core: 14 days (80,642 entries) take about 50 seconds.

## Sample Output

This complete denied response ends an episode: `svc-reports` read ten payroll secrets from 05:08:31 to 05:13:39, read a billing secret at 05:14:20 and attempted the DELETE at 05:16:22. The request and response share the operation UUID, and the denied DELETE does not disable auditing.

```json
{
  "@timestamp": "2026-10-01T05:16:22.035Z",
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
    "id": "a917f31c-f870-4214-8273-e7a6f7ad7d81",
    "ingested": "2026-10-01T05:16:24Z",
    "kind": "event",
    "original": "{\"auth\":{\"accessor\":\"hmac-sha256:89da18efff447c7106a0b567cc5ac92c9e615a04b982d217297980ba127f7647\",\"client_token\":\"hmac-sha256:03b219fc9970dfb36c081da9310016fd91bac6e4576222632e55786ba422829a\",\"display_name\":\"userpass-svc-reports\",\"entity_id\":\"96fa6c68-63af-43dc-a9ea-f59556f4b5ea\",\"metadata\":{\"username\":\"svc-reports\"},\"policies\":[\"default\",\"training-reader\"],\"policy_results\":{\"allowed\":false},\"token_policies\":[\"default\",\"training-reader\"],\"token_issue_time\":\"2026-09-30T19:03:00Z\",\"token_ttl\":86400,\"token_type\":\"service\"},\"error\":\"1 error occurred:\\n\\t* permission denied\\n\\n\",\"request\":{\"client_id\":\"96fa6c68-63af-43dc-a9ea-f59556f4b5ea\",\"client_token\":\"hmac-sha256:03b219fc9970dfb36c081da9310016fd91bac6e4576222632e55786ba422829a\",\"client_token_accessor\":\"hmac-sha256:89da18efff447c7106a0b567cc5ac92c9e615a04b982d217297980ba127f7647\",\"id\":\"a917f31c-f870-4214-8273-e7a6f7ad7d81\",\"mount_class\":\"secret\",\"mount_point\":\"sys/\",\"mount_type\":\"system\",\"namespace\":{\"id\":\"root\"},\"operation\":\"delete\",\"path\":\"sys/audit/file\",\"remote_address\":\"198.51.100.44\",\"remote_port\":35802,\"request_uri\":\"/v1/sys/audit/file\"},\"response\":{\"mount_class\":\"secret\",\"mount_point\":\"sys/\",\"mount_type\":\"system\",\"data\":{\"error\":\"hmac-sha256:ec125ce39ac232369c1e227ed31f30b8b1a43010aa94029c6b423af8d061ce97\"}},\"time\":\"2026-10-01T05:16:22.035826968Z\",\"type\":\"response\"}",
    "outcome": "failure",
    "type": [
      "info",
      "end"
    ]
  },
  "hashicorp_vault": {
    "audit": {
      "auth": {
        "accessor": "hmac-sha256:89da18efff447c7106a0b567cc5ac92c9e615a04b982d217297980ba127f7647",
        "client_token": "hmac-sha256:03b219fc9970dfb36c081da9310016fd91bac6e4576222632e55786ba422829a",
        "display_name": "userpass-svc-reports",
        "entity_id": "96fa6c68-63af-43dc-a9ea-f59556f4b5ea",
        "metadata": {
          "username": "svc-reports"
        },
        "policies": [
          "default",
          "training-reader"
        ],
        "policy_results": {
          "allowed": false
        },
        "token_issue_time": "2026-09-30T19:03:00Z",
        "token_policies": [
          "default",
          "training-reader"
        ],
        "token_ttl": 86400,
        "token_type": "service"
      },
      "error": "1 error occurred:\n\t* permission denied\n\n",
      "request": {
        "client_id": "96fa6c68-63af-43dc-a9ea-f59556f4b5ea",
        "client_token": "hmac-sha256:03b219fc9970dfb36c081da9310016fd91bac6e4576222632e55786ba422829a",
        "client_token_accessor": "hmac-sha256:89da18efff447c7106a0b567cc5ac92c9e615a04b982d217297980ba127f7647",
        "id": "a917f31c-f870-4214-8273-e7a6f7ad7d81",
        "mount_class": "secret",
        "mount_point": "sys/",
        "mount_type": "system",
        "namespace": {
          "id": "root"
        },
        "operation": "delete",
        "path": "sys/audit/file",
        "remote_address": "198.51.100.44",
        "remote_port": 35802,
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
    "offset": 1967148
  },
  "message": "1 error occurred:\n\t* permission denied\n\n",
  "related": {
    "ip": [
      "198.51.100.44"
    ],
    "user": [
      "svc-reports"
    ]
  },
  "source": {
    "ip": "198.51.100.44",
    "port": 35802
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

- [Vault audit schema](https://developer.hashicorp.com/vault/docs/audit/schema) and [file audit device](https://developer.hashicorp.com/vault/docs/audit/file)
- [Vault v1.18.0 audit formatter](https://github.com/hashicorp/vault/blob/v1.18.0/audit/entry_formatter.go), [hash walker](https://github.com/hashicorp/vault/blob/v1.18.0/audit/hashstructure.go), and [time-value tests](https://github.com/hashicorp/vault/blob/v1.18.0/audit/hashstructure_test.go)
- [Vault v1.18.0 request handling](https://github.com/hashicorp/vault/blob/v1.18.0/vault/request_handling.go), [router](https://github.com/hashicorp/vault/blob/v1.18.0/vault/router.go), and [token store](https://github.com/hashicorp/vault/blob/v1.18.0/vault/token_store.go)
- [Vault v1.18.0 expiration handling](https://github.com/hashicorp/vault/blob/v1.18.0/vault/expiration.go), [userpass renewal](https://github.com/hashicorp/vault/blob/v1.18.0/builtin/credential/userpass/path_login.go), and [KV version pin](https://github.com/hashicorp/vault/blob/v1.18.0/go.mod)
- [KV v0.20.0 read data](https://github.com/hashicorp/vault-plugin-secrets-kv/blob/v0.20.0/path_data.go) and [metadata/listing](https://github.com/hashicorp/vault-plugin-secrets-kv/blob/v0.20.0/path_metadata.go)
- [Pinned Elastic Vault integration](https://github.com/elastic/integrations/tree/78fd455d22cdb74bd2a8e53249c25cc060f06010/packages/hashicorp_vault/data_stream/audit), [sample event](https://github.com/elastic/integrations/blob/78fd455d22cdb74bd2a8e53249c25cc060f06010/packages/hashicorp_vault/data_stream/audit/sample_event.json), and [pipeline](https://github.com/elastic/integrations/blob/78fd455d22cdb74bd2a8e53249c25cc060f06010/packages/hashicorp_vault/data_stream/audit/elasticsearch/ingest_pipeline/default.yml)

# Yandex Cloud Audit Trails

Generates ECS JSON Lines with a native Yandex Cloud management-audit record in `event.original` and parsed fields in `yandex_cloud.audit`. The selected fields and event names follow the [Audit Trails management-log format](https://yandex.cloud/en/docs/audit-trails/concepts/format) and the event-specific references below. This pack models successful control-plane operations in one organization, cloud and folder. It does not model data-plane activity.

## Event Types

| Audit event | Routine selection or trigger | Modeled operation |
| --- | --- | --- |
| `compute.UpdateInstance` | 88% of ordinary choices | Label update on a live VM |
| `compute.CreateInstance` | 2% of ordinary choices | Create a temporary CI VM |
| `iam.CreateServiceAccount` | 3% of ordinary choices | Create a maintenance account with a unique name |
| `resourcemanager.UpdateFolderAccessBindings` | 4% of ordinary choices, plus cleanup | ADD an absent `viewer`/`editor` binding or REMOVE an existing one |
| `iam.CreateAccessKey` | 3% of ordinary choices | Issue a static key for an existing account |
| `iam.DeleteAccessKey` | Existing modeled key or 24-hour cleanup | Remove a previously issued key |
| `iam.DeleteServiceAccount` | 48-hour or pool-cap cleanup | Delete a temporary account after its keys and folder bindings are removed |
| `compute.DeleteInstance` | 6-hour or pool-cap cleanup | Delete a previously created temporary VM and its auto-delete boot disk |

These are synthetic selection weights, not measured production frequencies. Scheduled cleanup takes priority over weighted choices. If a key-issuance choice selects an account with an active modeled key, it emits key deletion instead. Static keys do not expire themselves; the maintenance policy explicitly removes them. This models completed short-lived jobs, not zero-downtime key rotation.

The inventory begins with 64 permanent VMs and 24 preexisting service accounts. Newly created accounts are scheduled for cleanup after 48 hours, with at most 48 in the managed pool (72 accounts total). Keys and folder bindings are tracked; ADD never repeats an existing binding and REMOVE requires a preceding ADD. There is at most one active modeled key per account. Ordinary permission/key maintenance on newly created accounts waits at least six hours after creation. Account cleanup removes modeled keys and roles before deletion, and these accounts are not attached to VMs or functions.

Temporary VMs have a separate pool of eight and are cleaned up after six hours or when that pool is full. Updates select only live VMs. Their three synthetic subnets have distinct `/24` address ranges in zones `ru-central1-a`, `-b` and `-d`; zone, subnet and private IP agree. VM deletion is ordinary CI cleanup, not an additional anomaly step.

One event is emitted every ten minutes (about 144 per day). Both modes emit all eight classes and both federated operators, including deletes. The modeled operators have folder `admin` permissions, and no access policy prohibits these account/key operations. The cloud has the approved Compute capacity for 64 permanent and up to eight temporary VMs; this exceeds the default VM quota. The modeled IAM inventory stays below the documented quotas of 100 service accounts and 1,000 static keys per cloud.

## Anomaly Chain

With `anomaly_mode: true` (default), a linked episode is scheduled every `anomaly_interval_hours` (24 hours by default). The first is scheduled after one interval and begins in the next ten-minute slot. If the account pool is full, its cleanup must free a slot first.

1. The second operator creates a new service account.
2. The same operator adds that account to the folder with the `editor` role through `UpdateFolderAccessBindings`.
3. The same operator creates a static access key for that account.

The records are ten minutes apart and span 20 minutes. Each episode gets a fresh account ID/name, key ID and request/event IDs; its three records share the new `service_account_id`. Detect this order for the same actor and account within a 20-minute window. The key supports AWS-compatible services; the sequence does not show subsequent use of that key.

Account creation, role changes and key issuance also occur independently in background, using the same operators, prefix and object types. Ordinary maintenance of a newly created account starts at least six hours later, so it does not form the complete 20-minute sequence. No static actor, source address or field identifies the mode. Set `anomaly_mode: false` for background only.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Meaning |
| --- | --- | --- |
| `cloud_id`, `folder_id`, `organization_id` | `b1g0a10235b15143e07a`, `b1g2a15c9bea04fe16e5`, `bpf8fce59da310dc940c` | Resource path |
| `normal_subject_id`, `normal_subject_name`, `normal_source_ip` | `aje29545c72dd3fe508a`, `cloud.operator`, `10.60.1.27` | Primary federated operator |
| `anomaly_subject_id`, `anomaly_subject_name`, `anomaly_source_ip` | `ajeead78627c1eb1858a`, `external.admin`, `198.51.100.105` | Secondary federated operator, also present in background |
| `service_account_prefix` | `svc-maint` | Lowercase account-name prefix, at most 45 characters; an opaque suffix keeps names unique |
| `anomaly_interval_hours` | `24` | Minimum hours between episode starts and delay before the first; use at least 1 |
| `anomaly_mode` | `true` | Include recurring linked episodes |

### Output Parameters

The shipped output writes JSON Lines to `output/events.json` relative to the generator. There are no top-level `${params.*}` or `${secrets.*}` overrides. Change the file output plugin to deliver events to a SIEM. The `samples/` directory holds stable VM and existing service-account identities.

## Usage

From the content-packs repository root:

```bash
uv run --project ../eventum eventum generate --path generators/cloud-yandex-audit-trails/generator.yml --id cloud-yandex-audit-trails --live-mode true
```

For a finite batch, copy `generator.yml` to `generator.batch.yml` beside the original and add `start` and `end` to `input.cron`. Allow at least two intervals plus 30 minutes to observe two complete episodes, then run:

```bash
uv run --project ../eventum eventum generate --path generators/cloud-yandex-audit-trails/generator.batch.yml --id yandex-batch --live-mode false --keep-order true
```

Timestamps are normalized to UTC even if the generator timezone differs. At the default cadence, the first complete episode ends 24 hours and 30 minutes after the first event.

## Sample output

This complete JSON Line is a `CreateAccessKey` record from the first episode of the final enabled-mode run, after the matching account creation and folder-role grant:

```json
{"@timestamp": "2026-09-28T00:30:00+00:00", "ecs": {"version": "8.17.0"}, "event": {"kind": "event", "module": "yandex_cloud", "dataset": "yandex_cloud.audit", "id": "32c8c883-881c-45e0-aeac-aed505b7d5cd", "action": "CreateAccessKey", "category": ["iam"], "type": ["creation"], "outcome": "success", "original": "{\"authentication\": {\"authenticated\": true, \"federation_id\": \"bpffd0b1506f5e3af1f1\", \"federation_name\": \"contoso\", \"federation_type\": \"PRIVATE_FEDERATION\", \"subject_id\": \"ajeead78627c1eb1858a\", \"subject_name\": \"external.admin\", \"subject_type\": \"FEDERATED_USER_ACCOUNT\"}, \"authorization\": {\"authorized\": true}, \"details\": {\"access_key_id\": \"ajeb3c51f84a1284ff18\", \"created_at\": \"2026-09-28T00:30:00+00:00\", \"description\": \"Maintenance automation\", \"key_id\": \"YCefb05499e4954ccb9a7099d\", \"service_account_id\": \"aje307aa1d4b2d442149\", \"service_account_name\": \"svc-maint-307aa1d4b2d442149\"}, \"event_id\": \"32c8c883-881c-45e0-aeac-aed505b7d5cd\", \"event_source\": \"iam\", \"event_status\": \"DONE\", \"event_time\": \"2026-09-28T00:30:00+00:00\", \"event_type\": \"yandex.cloud.audit.iam.CreateAccessKey\", \"request_metadata\": {\"remote_address\": \"198.51.100.105\", \"request_id\": \"1936d40e-86e2-436a-a76a-41bb6c9129e5\", \"user_agent\": \"yc/0.157\"}, \"resource_metadata\": {\"path\": [{\"resource_id\": \"bpf8fce59da310dc940c\", \"resource_name\": \"contoso-org\", \"resource_type\": \"organization-manager.organization\"}, {\"resource_id\": \"b1g0a10235b15143e07a\", \"resource_name\": \"contoso-cloud\", \"resource_type\": \"resource-manager.cloud\"}, {\"resource_id\": \"b1g2a15c9bea04fe16e5\", \"resource_name\": \"production\", \"resource_type\": \"resource-manager.folder\"}]}}"}, "source": {"ip": "198.51.100.105"}, "user": {"id": "ajeead78627c1eb1858a", "name": "external.admin"}, "related": {"ip": ["198.51.100.105"], "user": ["external.admin"]}, "cloud": {"provider": "yandex", "account": {"id": "b1g0a10235b15143e07a"}}, "yandex_cloud": {"audit": {"authentication": {"authenticated": true, "federation_id": "bpffd0b1506f5e3af1f1", "federation_name": "contoso", "federation_type": "PRIVATE_FEDERATION", "subject_id": "ajeead78627c1eb1858a", "subject_name": "external.admin", "subject_type": "FEDERATED_USER_ACCOUNT"}, "authorization": {"authorized": true}, "details": {"access_key_id": "ajeb3c51f84a1284ff18", "created_at": "2026-09-28T00:30:00+00:00", "description": "Maintenance automation", "key_id": "YCefb05499e4954ccb9a7099d", "service_account_id": "aje307aa1d4b2d442149", "service_account_name": "svc-maint-307aa1d4b2d442149"}, "event_id": "32c8c883-881c-45e0-aeac-aed505b7d5cd", "event_source": "iam", "event_status": "DONE", "event_time": "2026-09-28T00:30:00+00:00", "event_type": "yandex.cloud.audit.iam.CreateAccessKey", "request_metadata": {"remote_address": "198.51.100.105", "request_id": "1936d40e-86e2-436a-a76a-41bb6c9129e5", "user_agent": "yc/0.157"}, "resource_metadata": {"path": [{"resource_id": "bpf8fce59da310dc940c", "resource_name": "contoso-org", "resource_type": "organization-manager.organization"}, {"resource_id": "b1g0a10235b15143e07a", "resource_name": "contoso-cloud", "resource_type": "resource-manager.cloud"}, {"resource_id": "b1g2a15c9bea04fe16e5", "resource_name": "production", "resource_type": "resource-manager.folder"}]}}}}
```

## Source fidelity and limits

- [Management-log format and complete `CreateInstance` example](https://yandex.cloud/en/docs/audit-trails/concepts/format): native snake_case envelope, actor, authorization, resource path, request metadata and VM details.
- Event-specific schemas: [CreateInstance](https://yandex.cloud/en/docs/audit-trails/audit/compute/events-ref/CreateInstance), [UpdateInstance](https://yandex.cloud/en/docs/audit-trails/audit/compute/events-ref/UpdateInstance), [CreateServiceAccount](https://yandex.cloud/en/docs/audit-trails/audit/iam/events-ref/CreateServiceAccount), [UpdateFolderAccessBindings](https://yandex.cloud/en/docs/audit-trails/audit/resourcemanager/events-ref/UpdateFolderAccessBindings), [CreateAccessKey](https://yandex.cloud/en/docs/audit-trails/audit/iam/events-ref/CreateAccessKey), [DeleteAccessKey](https://yandex.cloud/en/docs/audit-trails/audit/iam/events-ref/DeleteAccessKey), [DeleteServiceAccount](https://yandex.cloud/en/docs/audit-trails/audit/iam/events-ref/DeleteServiceAccount) and [DeleteInstance](https://yandex.cloud/en/docs/audit-trails/audit/compute/events-ref/DeleteInstance): modeled `details` fields.
- [Folder access operations](https://yandex.cloud/en/docs/resource-manager/operations/folder/set-access-bindings): `UpdateFolderAccessBindings` adds a role; `SetFolderAccessBindings` replaces the full binding set, so it is not used for the grant step.
- [Service accounts](https://yandex.cloud/en/docs/iam/concepts/users/service-accounts), [deleting an account](https://yandex.cloud/en/docs/iam/operations/sa/delete), [IAM quotas](https://yandex.cloud/en/docs/iam/concepts/limits) and [Compute quotas](https://yandex.cloud/en/docs/compute/concepts/limits): name uniqueness, linked-resource restrictions and inventory assumptions.
- [Static access keys](https://yandex.cloud/en/docs/iam/concepts/authorization/access-key): key IDs start with `YC` and have 25 characters.

Audit Trails can deliver records through Object Storage, Cloud Logging or Data Streams, each with a different transport container. This pack emits one native JSON record inside ECS per line; it does not reproduce those containers. The NAT-enabled CreateInstance variant covers all 42 selected structural paths in the vendor example; a private-only VM omits the two public-address paths. Optional request/response, token-impersonation and error sections are omitted because their concrete values are not established for these successful synthetic operations. Event-specific references use protoJSON camelCase; the native record uses the snake_case exported-log style shown in the management-log example. The `status` and `expires_at` fields in DeleteServiceAccount are omitted because their captured values are unavailable. No live tenant capture has been compared; event-specific field sets establish selected-schema fidelity, not complete raw-record parity.

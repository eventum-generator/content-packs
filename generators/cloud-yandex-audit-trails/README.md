# Yandex Cloud Audit Trails

Generates ECS JSON Lines with a native Yandex Cloud management-audit record in `event.original` and parsed fields in `yandex_cloud.audit`. The selected fields and event names follow the [Audit Trails management-log format](https://yandex.cloud/en/docs/audit-trails/concepts/format) and the event-specific references below. This pack models successful control-plane operations in one organization, cloud and folder. It does not model data-plane activity.

## Event Types

| Audit event | Routine weight | Modeled operation |
| --- | ---: | --- |
| `compute.UpdateInstance` | 88% | Update a label on one of 64 stable VMs |
| `compute.CreateInstance` | 2% | Create a VM with a new ID, name, disk and private IP; some receive one-to-one NAT |
| `iam.CreateServiceAccount` | 3% | Create an independent maintenance account |
| `resourcemanager.UpdateFolderAccessBindings` | 4% | Add a `viewer` or `editor` folder binding to an existing account |
| `iam.CreateAccessKey` | 3% | Create a static key for an existing account |

The weights describe this synthetic environment, not measured Yandex Cloud production frequencies. Both modes use all five event types. One event is emitted every ten minutes, or about 144 events per day. The two federated operators and their IP addresses occur in both modes, so actor, source address and event type alone do not identify the anomaly.

## Anomaly Chain

With `anomaly_mode: true` (default), a single linked sequence begins after 144 routine events:

1. The second operator creates a new service account.
2. The same operator adds that account to the folder with the `editor` role through `UpdateFolderAccessBindings`.
3. The same operator creates a static access key for that account.

The three records are ten minutes apart and share the new `service_account_id` in event-specific `details`. A detection can require this order, matching actor and account IDs, and a 20-minute window. Routine account creation, access grants and key creation remain independent and do not form the same three-event sequence. The chain occurs once per generator run. Set `anomaly_mode: false` to emit background activity only.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Meaning |
| --- | --- | --- |
| `cloud_id`, `folder_id`, `organization_id` | `b1g0a10235b15143e07a`, `b1g2a15c9bea04fe16e5`, `bpf8fce59da310dc940c` | Resource path |
| `normal_subject_id`, `normal_subject_name`, `normal_source_ip` | `aje29545c72dd3fe508a`, `cloud.operator`, `10.60.1.27` | Primary federated operator |
| `anomaly_subject_id`, `anomaly_subject_name`, `anomaly_source_ip` | `ajeead78627c1eb1858a`, `external.admin`, `198.51.100.105` | Secondary federated operator, also present in background |
| `service_account_prefix` | `svc-maint` | Prefix for newly created accounts |
| `anomaly_interval_events` | `144` | Number of routine events before the one-shot chain |
| `anomaly_mode` | `true` | Include the linked chain |

### Output Parameters

The shipped output writes JSON Lines to `output/events.json` relative to the generator. There are no top-level `${params.*}` or `${secrets.*}` overrides. Change the file output plugin to deliver events to a SIEM. The `samples/` directory holds stable VM and existing service-account identities.

## Usage

Run in live mode from the content-packs repository root:

```bash
eventum generate --path generators/cloud-yandex-audit-trails/generator.yml --id cloud-yandex-audit-trails --live-mode true
```

For a bounded sample-mode run, use:

```bash
timeout 1 eventum generate --path generators/cloud-yandex-audit-trails/generator.yml --id cloud-yandex-audit-trails-sample --live-mode false --keep-order true
```

The first linked chain appears after about 24 hours of event time.

## Sample output

This complete JSON Line is a `CreateAccessKey` record from an enabled-mode run, immediately after the matching account creation and folder-role grant:

```json
{"@timestamp": "2026-09-26T17:40:00+00:00", "ecs": {"version": "8.17.0"}, "event": {"kind": "event", "module": "yandex_cloud", "dataset": "yandex_cloud.audit", "id": "16a449ed-a6b7-4a82-9852-dad0a9a4a9d8", "action": "CreateAccessKey", "category": ["iam"], "type": ["change"], "outcome": "success", "original": "{\"authentication\": {\"authenticated\": true, \"federation_id\": \"bpffd0b1506f5e3af1f1\", \"federation_name\": \"contoso\", \"federation_type\": \"PRIVATE_FEDERATION\", \"subject_id\": \"ajeead78627c1eb1858a\", \"subject_name\": \"external.admin\", \"subject_type\": \"FEDERATED_USER_ACCOUNT\"}, \"authorization\": {\"authorized\": true}, \"details\": {\"access_key_id\": \"ajeb23af260f79248318\", \"created_at\": \"2026-09-26T17:40:00+00:00\", \"description\": \"Maintenance automation\", \"key_id\": \"YCc2f24601f17841008fc2ccd\", \"service_account_id\": \"aje267f953d84dd4d7ba\", \"service_account_name\": \"svc-maint-000005\"}, \"event_id\": \"16a449ed-a6b7-4a82-9852-dad0a9a4a9d8\", \"event_source\": \"iam\", \"event_status\": \"DONE\", \"event_time\": \"2026-09-26T17:40:00+00:00\", \"event_type\": \"yandex.cloud.audit.iam.CreateAccessKey\", \"request_metadata\": {\"remote_address\": \"198.51.100.105\", \"request_id\": \"53a139f3-35bc-4a99-b4ab-2e97bcd68c4c\", \"user_agent\": \"yc/0.157\"}, \"resource_metadata\": {\"path\": [{\"resource_id\": \"bpf8fce59da310dc940c\", \"resource_name\": \"contoso-org\", \"resource_type\": \"organization-manager.organization\"}, {\"resource_id\": \"b1g0a10235b15143e07a\", \"resource_name\": \"contoso-cloud\", \"resource_type\": \"resource-manager.cloud\"}, {\"resource_id\": \"b1g2a15c9bea04fe16e5\", \"resource_name\": \"production\", \"resource_type\": \"resource-manager.folder\"}]}}"}, "source": {"ip": "198.51.100.105"}, "user": {"id": "ajeead78627c1eb1858a", "name": "external.admin"}, "related": {"ip": ["198.51.100.105"], "user": ["external.admin"]}, "cloud": {"provider": "yandex", "account": {"id": "b1g0a10235b15143e07a"}}, "yandex_cloud": {"audit": {"authentication": {"authenticated": true, "federation_id": "bpffd0b1506f5e3af1f1", "federation_name": "contoso", "federation_type": "PRIVATE_FEDERATION", "subject_id": "ajeead78627c1eb1858a", "subject_name": "external.admin", "subject_type": "FEDERATED_USER_ACCOUNT"}, "authorization": {"authorized": true}, "details": {"access_key_id": "ajeb23af260f79248318", "created_at": "2026-09-26T17:40:00+00:00", "description": "Maintenance automation", "key_id": "YCc2f24601f17841008fc2ccd", "service_account_id": "aje267f953d84dd4d7ba", "service_account_name": "svc-maint-000005"}, "event_id": "16a449ed-a6b7-4a82-9852-dad0a9a4a9d8", "event_source": "iam", "event_status": "DONE", "event_time": "2026-09-26T17:40:00+00:00", "event_type": "yandex.cloud.audit.iam.CreateAccessKey", "request_metadata": {"remote_address": "198.51.100.105", "request_id": "53a139f3-35bc-4a99-b4ab-2e97bcd68c4c", "user_agent": "yc/0.157"}, "resource_metadata": {"path": [{"resource_id": "bpf8fce59da310dc940c", "resource_name": "contoso-org", "resource_type": "organization-manager.organization"}, {"resource_id": "b1g0a10235b15143e07a", "resource_name": "contoso-cloud", "resource_type": "resource-manager.cloud"}, {"resource_id": "b1g2a15c9bea04fe16e5", "resource_name": "production", "resource_type": "resource-manager.folder"}]}}}}
```

## Source fidelity and limits

- [Management-log format and complete `CreateInstance` example](https://yandex.cloud/en/docs/audit-trails/concepts/format): native snake_case envelope, actor, authorization, resource path, request metadata and VM details.
- Event-specific schemas: [CreateInstance](https://yandex.cloud/en/docs/audit-trails/audit/compute/events-ref/CreateInstance), [UpdateInstance](https://yandex.cloud/en/docs/audit-trails/audit/compute/events-ref/UpdateInstance), [CreateServiceAccount](https://yandex.cloud/en/docs/audit-trails/audit/iam/events-ref/CreateServiceAccount), [UpdateFolderAccessBindings](https://yandex.cloud/en/docs/audit-trails/audit/resourcemanager/events-ref/UpdateFolderAccessBindings) and [CreateAccessKey](https://yandex.cloud/en/docs/audit-trails/audit/iam/events-ref/CreateAccessKey): modeled `details` fields.
- [Folder access operations](https://yandex.cloud/en/docs/resource-manager/operations/folder/set-access-bindings): `UpdateFolderAccessBindings` adds a role; `SetFolderAccessBindings` replaces the full binding set, so it is not used for the grant step.
- [Static access keys](https://yandex.cloud/en/docs/iam/concepts/authorization/access-key): key IDs start with `YC` and have 25 characters.

Audit Trails can deliver records through Object Storage, Cloud Logging or Data Streams, each with a different transport container. This pack emits one native JSON record inside ECS per line; it does not reproduce those containers. The NAT-enabled CreateInstance variant covers all 42 selected structural paths in the vendor example; a private-only VM omits the two public-address paths. Optional request/response, token-impersonation and error sections are omitted because their concrete values are not established for these successful synthetic operations. Event-specific references use protoJSON camelCase; the native record uses the snake_case exported-log style shown in the management-log example. No live tenant capture has been compared.

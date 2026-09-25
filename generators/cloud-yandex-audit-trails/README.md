# Yandex Cloud Audit Trails

Generates ECS-compatible JSON with a native Audit Trails control-plane record in `event.original` and parsed data under `yandex_cloud.audit`. The native record uses the snake_case JSON layout in the Audit Trails log format reference.

Reference coverage: **22/22 selected common fields and structural slots applicable to successful control-plane events, including subject, authorization, resource path and request metadata. Conditional error and token_info blocks are omitted because these emitted operations succeed and do not model token impersonation.**

## Event Types

| Native event | Routine weight | Category |
| --- | ---: | --- |
| `compute.CreateInstance` | 56% | Compute configuration |
| `compute.UpdateInstance` | 29% | Compute configuration |
| `resourcemanager.UpdateFolder` | 15% | Folder configuration |
| `iam.CreateServiceAccount` | Anomaly only | IAM |
| `resourcemanager.SetFolderAccessBindings` | Anomaly only | IAM |
| `iam.CreateAccessKey` | Anomaly only | IAM |

Weights are generator design values, not measured vendor production frequencies. One reusable template drives an FSM. The default input emits one event per second, preserving an observable order between anomaly steps.

## Anomaly Chain

With `event.template.params.anomaly_mode: true` (the default), the generator mixes background events with this sequence after every 240 routine events:

1. One unusual federated user creates service account `svc-maint-NNNN`.
2. The same actor grants that account the folder `editor` role via `SetFolderAccessBindings`.
3. The same actor creates a static access key for that service account.

Rules can detect service-account creation followed by privilege grant and key creation within a short window. Correlate by actor ID, folder ID and the service-account ID shared by all three `details` objects. Each chain uses a distinct service-account ID and key ID.

Set `anomaly_mode: false` to emit only background. No anomaly steps or transition into the chain occur in that mode.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Meaning |
| --- | --- | --- |
| `cloud_id`, `folder_id`, `organization_id` | `b1gcontosocloud01`, `b1gcontosofolder1`, `bpfcontosoorg001` | Resource path |
| `normal_subject_id`, `normal_subject_name`, `normal_source_ip` | `ajeoperator000001`, `cloud.operator`, `10.60.1.27` | Routine actor |
| `anomaly_subject_id`, `anomaly_subject_name`, `anomaly_source_ip` | `ajeoutsider000001`, `external.admin`, `198.51.100.105` | Anomaly actor |
| `created_service_account_id`, `created_service_account_name` | `ajebackdoor000001`, `svc-maint` | Prefixes for per-chain service accounts |
| `anomaly_interval_events` | `240` | Routine events between chains |
| `anomaly_mode` | `true` | Enable the chain; `false` emits only background |

### Output Parameters

The shipped configuration writes `output/events.json` relative to the generator. It declares no top-level `${params.*}` or `${secrets.*}` overrides. Change `output.file.path` or replace the output plugin to deliver to a SIEM.

## Usage

Run from the content-packs repository root:

```bash
eventum generate --path generators/cloud-yandex-audit-trails/generator.yml --id cloud-yandex-audit-trails --live-mode true
```

Use `--live-mode false` for a fast local sample run.

## Sample Output

This complete event was copied from an enabled-mode generator run:

```json
{"@timestamp": "2026-09-25T11:54:22+00:00", "ecs": {"version": "8.17.0"}, "event": {"kind": "event", "module": "yandex_cloud", "dataset": "yandex_cloud.audit", "id": "d7df01f7-21c4-443c-8569-2a4a32fb3550", "action": "CreateAccessKey", "category": ["iam"], "type": ["change"], "outcome": "success", "original": "{\"authentication\": {\"authenticated\": true, \"federation_id\": \"bpfcontosofed001\", \"federation_name\": \"contoso\", \"federation_type\": \"PRIVATE_FEDERATION\", \"subject_id\": \"ajeoutsider000001\", \"subject_name\": \"external.admin\", \"subject_type\": \"FEDERATED_USER_ACCOUNT\"}, \"authorization\": {\"authorized\": true}, \"details\": {\"access_key_id\": \"ajeaccesskey0001\", \"created_at\": \"2026-09-25T11:54:22+00:00\", \"description\": \"Maintenance automation\", \"key_id\": \"ajekey0001\", \"service_account_id\": \"ajebackdoor0000010001\", \"service_account_name\": \"svc-maint-0001\"}, \"event_id\": \"d7df01f7-21c4-443c-8569-2a4a32fb3550\", \"event_source\": \"iam\", \"event_status\": \"DONE\", \"event_time\": \"2026-09-25T11:54:22+00:00\", \"event_type\": \"yandex.cloud.audit.iam.CreateAccessKey\", \"request_metadata\": {\"remote_address\": \"198.51.100.105\", \"request_id\": \"be138890-703d-4ed4-bd86-a9d1367d2188\", \"user_agent\": \"yc/0.157\"}, \"request_parameters\": {}, \"resource_metadata\": {\"path\": [{\"resource_id\": \"bpfcontosoorg001\", \"resource_name\": \"contoso-org\", \"resource_type\": \"organization-manager.organization\"}, {\"resource_id\": \"b1gcontosocloud01\", \"resource_name\": \"contoso-cloud\", \"resource_type\": \"resource-manager.cloud\"}, {\"resource_id\": \"b1gcontosofolder1\", \"resource_name\": \"production\", \"resource_type\": \"resource-manager.folder\"}]}, \"response\": {}}"}, "source": {"ip": "198.51.100.105"}, "user": {"id": "ajeoutsider000001", "name": "external.admin"}, "cloud": {"provider": "yandex", "account": {"id": "b1gcontosocloud01"}}, "yandex_cloud": {"audit": {"authentication": {"authenticated": true, "federation_id": "bpfcontosofed001", "federation_name": "contoso", "federation_type": "PRIVATE_FEDERATION", "subject_id": "ajeoutsider000001", "subject_name": "external.admin", "subject_type": "FEDERATED_USER_ACCOUNT"}, "authorization": {"authorized": true}, "details": {"access_key_id": "ajeaccesskey0001", "created_at": "2026-09-25T11:54:22+00:00", "description": "Maintenance automation", "key_id": "ajekey0001", "service_account_id": "ajebackdoor0000010001", "service_account_name": "svc-maint-0001"}, "event_id": "d7df01f7-21c4-443c-8569-2a4a32fb3550", "event_source": "iam", "event_status": "DONE", "event_time": "2026-09-25T11:54:22+00:00", "event_type": "yandex.cloud.audit.iam.CreateAccessKey", "request_metadata": {"remote_address": "198.51.100.105", "request_id": "be138890-703d-4ed4-bd86-a9d1367d2188", "user_agent": "yc/0.157"}, "request_parameters": {}, "resource_metadata": {"path": [{"resource_id": "bpfcontosoorg001", "resource_name": "contoso-org", "resource_type": "organization-manager.organization"}, {"resource_id": "b1gcontosocloud01", "resource_name": "contoso-cloud", "resource_type": "resource-manager.cloud"}, {"resource_id": "b1gcontosofolder1", "resource_name": "production", "resource_type": "resource-manager.folder"}]}, "response": {}}}}
```

## References and Limits

- [Yandex Cloud Audit Trails JSON format](https://yandex.cloud/ru/docs/audit-trails/concepts/format): common control-plane schema and sample.
- [Yandex Cloud control-plane event list](https://yandex.cloud/ru/docs/audit-trails/concepts/events): event names and services.
- [CreateServiceAccount event schema](https://yandex.cloud/en/docs/audit-trails/audit/iam/events-ref/CreateServiceAccount) and [SetFolderAccessBindings schema](https://yandex.cloud/ru/docs/audit-trails/audit/resourcemanager/events-ref/SetFolderAccessBindings): chain detail fields.
- [KUMA 4.0 supported event sources](https://support.kaspersky.com/kuma/4.0/en-US/255782.htm): IAM, Compute and Resource Manager support inventory.

Yandex Cloud also publishes event-specific protoJSON references with camelCase names. This pack follows the Audit Trails exported-log example and general snake_case format, so consumers should select the matching parser. Service-specific `request_parameters` and `response` are empty because the generic format does not define their schemas. No data-plane events are modeled.

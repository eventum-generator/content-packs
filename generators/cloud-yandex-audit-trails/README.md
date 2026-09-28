# Yandex Cloud Audit Trails

Generates Yandex Cloud Audit Trails management events for one organization, cloud and folder, for SIEM content that watches cloud IAM and Compute changes. Each JSON Line is an ECS record with the native audit record in `event.original` and parsed under `yandex_cloud.audit`. The native fields and event names follow the [management-log format](https://yandex.cloud/en/docs/audit-trails/concepts/format) and the event references listed below. Only successful control-plane operations are modeled; data-plane events are out of scope.

## Event Types

Shares are measured on the final 100-hour default capture with `anomaly_mode: true` (737 records).

| Audit event | Share | Category | Modeled operation |
| --- | ---: | --- | --- |
| `compute.UpdateInstance` | 40.2% | configuration | Label update on a permanent or CI VM |
| `resourcemanager.UpdateFolderAccessBindings` | 14.8% | iam | ADD or REMOVE of one folder role for a service account |
| `iam.CreateAccessKey` | 10.3% | iam | Static access key for a service account |
| `iam.DeleteAccessKey` | 9.5% | iam | Key rotation or cleanup |
| `iam.CreateServiceAccount` | 7.3% | iam | New service account |
| `compute.CreateInstance` | 6.5% | configuration | Temporary CI VM |
| `compute.DeleteInstance` | 6.2% | configuration | Cleanup of a CI VM |
| `iam.DeleteServiceAccount` | 5.2% | iam | Cleanup of a created account after its keys and roles |

Six federated operators work in independent sessions. Session arrivals follow a random process per operator, thinned by an office-hours curve (UTC+3); each session holds a random number of operations separated by random gaps of seconds to minutes. Operators have different activity levels and use an office or a VPN address. Operations:

- label updates on 64 permanent VMs and on live CI VMs;
- temporary CI VMs, each deleted after a random lifetime of hours by the creator or another operator (at most eight at a time);
- service-account provisioning: a new account, then often a folder role (`viewer`, `editor`, `storage.editor` or `compute.editor`) and a static key within minutes, in either order;
- role and key maintenance on the 24 permanent and on created accounts, including an `editor` grant followed by a key, role removal and key rotation;
- cleanup of every created account after a random lifetime of about a day: keys are deleted, roles removed, then the account is deleted, one native call each.

ADD never repeats a binding held by the account, REMOVE only follows an ADD, and a key is deleted only once. An account holds at most two background keys. Rates, lifetimes and weights are synthetic, not measured production values.

## Anomaly Chain

With `anomaly_mode: true` (the default), an operator provisions a service account with persistent write access:

1. `iam.CreateServiceAccount` - a new account.
2. `resourcemanager.UpdateFolderAccessBindings` - ADD of the `editor` role on the folder for that account.
3. `iam.CreateAccessKey` - a static access key for that account.

Linking fields: the same `user.id` (`authentication.subject_id`) and the same account in `user.target.id` (`details.service_account_id`, or `access_binding.subject_id` in the binding delta), all three within 30 minutes of the account creation. The gaps between the steps come from the same distributions as background provisioning; an episode redraws them until the sequence fits the 30-minute window, so it usually spans a few minutes.

Recurrence: `anomaly_interval_hours` (default 24, minimum 2). The first episode starts within the first min(interval, 24 h) of generation; each later one within a window of width min(interval / 4, 6 h) centred one interval after the previous actual start. Start times inside a window are weighted by the square of the office-hours curve plus a small floor, so episodes mostly fall in working hours. The phase can move by at most half a window per episode, and when the interval is not close to a multiple of 24 hours some starts fall outside working hours: at 12 hours every other episode lands about 12 hours from the busy phase, and at 8 hours or less the windows cover the whole clock. After the drawn time the episode starts with a further random delay of a few minutes. Missed episodes are not replayed.

Variation: the operator changes with every episode, chosen with the background activity weights, and uses the address it uses in background; each episode has a fresh account, key and request IDs. The account then follows the ordinary cleanup, so its key deletion, role removal and account deletion appear in the log about a day later.

Background contains every step and every partial sequence of the chain for the same operators and addresses: a new account with an `editor` grant, a new account with a key, an `editor` grant followed by a key on an existing account, and the complete sequence spread over more than 30 minutes. A background key that would complete the chain within 30 minutes of the account creation (same operator created the account and granted it `editor`) is not issued; nothing else changes. Detection idea: alert on the three steps by one subject on one new account within 30 minutes, and on keys issued for accounts with fresh `editor` or `admin` bindings.

Set `anomaly_mode: false` for background only; it contains no complete chain.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Description |
| --- | --- | --- |
| `cloud_id` | `b1g0a10235b15143e07a` | Cloud in the resource path and `cloud.account.id` |
| `folder_id` | `b1g2a15c9bea04fe16e5` | Folder in the resource path and in binding changes |
| `organization_id` | `bpf8fce59da310dc940c` | Organization in the resource path |
| `service_account_prefix` | `svc-maint` | Name prefix of created service accounts; a random suffix keeps names unique |
| `anomaly_interval_hours` | `24` | Hours between episode starts, at least 2 |
| `anomaly_mode` | `true` | `true` adds recurring anomaly episodes; `false` emits background only |

Operators, their addresses and activity levels are in `samples/operators.json`; permanent VMs and service accounts are in `samples/instances.json` and `samples/service_accounts.json`.

### Output Parameters

The shipped output writes JSON Lines to `output/events.json`. To deliver to a SIEM, replace the output with, for example, an OpenSearch output that reads its connection from top-level parameters:

```yaml
output:
  - opensearch:
      hosts: ["${params.opensearch_host}"]
      username: ${params.opensearch_user}
      password: ${secrets.opensearch_password}
      index: yandex-cloud-audit
```

## Usage

Live mode:

```bash
eventum generate --path generators/cloud-yandex-audit-trails/generator.yml --id yandex-audit --live-mode true
```

Batch mode: add `start` and `end` to `input.cron` in a copy of `generator.yml` (at least 50 hours for two episodes at the default interval), then run:

```bash
eventum generate --path generators/cloud-yandex-audit-trails/generator.batch.yml --id yandex-audit --live-mode false --keep-order true
```

The input ticks once per second; a tick emits the next due record or nothing. Timestamps are UTC.

## Limitations

- No live tenant capture was compared. The native envelope follows the complete CreateInstance example in the format page; `details` follow the event references, converted to the snake_case of that example. Field-complete parity is not claimed.
- Optional `token_info`, `request_parameters`, `response`, `error` and `remote_port` are omitted; so are `status` and `expires_at` in `DeleteServiceAccount`, whose values are not documented. Failed and cancelled operations are not modeled.
- The transport containers of Object Storage, Cloud Logging and Data Streams are not reproduced; each line is one record.
- `event.original` keeps the field order of the vendor example on one line; the example is indented, so whitespace differs.
- `user_agent` is a fixed `yc` CLI string, VM MAC addresses use the `d0:0d` prefix seen on Yandex Cloud VMs, and product, subnet and federation IDs are synthetic.
- The CI VM pool assumes Compute quotas above the default of 12 VMs.
- `user.target.*` is an ECS mapping of the service account the event acts on, not a native field.
- Episode steps are redrawn to fit 30 minutes, while background gaps have no such limit; background complete sequences therefore only occur with spans above 30 minutes.

## References

- [Management event audit log format](https://yandex.cloud/en/docs/audit-trails/concepts/format)
- Event references: [CreateInstance](https://yandex.cloud/en/docs/audit-trails/audit/compute/events-ref/CreateInstance), [UpdateInstance](https://yandex.cloud/en/docs/audit-trails/audit/compute/events-ref/UpdateInstance), [DeleteInstance](https://yandex.cloud/en/docs/audit-trails/audit/compute/events-ref/DeleteInstance), [CreateServiceAccount](https://yandex.cloud/en/docs/audit-trails/audit/iam/events-ref/CreateServiceAccount), [DeleteServiceAccount](https://yandex.cloud/en/docs/audit-trails/audit/iam/events-ref/DeleteServiceAccount), [CreateAccessKey](https://yandex.cloud/en/docs/audit-trails/audit/iam/events-ref/CreateAccessKey), [DeleteAccessKey](https://yandex.cloud/en/docs/audit-trails/audit/iam/events-ref/DeleteAccessKey), [UpdateFolderAccessBindings](https://yandex.cloud/en/docs/audit-trails/audit/resourcemanager/events-ref/UpdateFolderAccessBindings)
- [Folder access bindings](https://yandex.cloud/en/docs/resource-manager/operations/folder/set-access-bindings), [service accounts](https://yandex.cloud/en/docs/iam/concepts/users/service-accounts), [static access keys](https://yandex.cloud/en/docs/iam/concepts/authorization/access-key), [IAM quotas](https://yandex.cloud/en/docs/iam/concepts/limits), [Compute quotas](https://yandex.cloud/en/docs/compute/concepts/limits)
- No Elastic integration exists for Yandex Cloud Audit Trails.

## Sample Output

A `CreateAccessKey` record completing the second episode of the final default capture (line 325):

```json
{"@timestamp": "2026-10-02T15:08:22.184694Z", "ecs": {"version": "8.17.0"}, "event": {"kind": "event", "module": "yandex_cloud", "dataset": "yandex_cloud.audit", "id": "458b6b34-9a4e-47cd-952b-4b86f163847f", "action": "CreateAccessKey", "category": ["iam"], "type": ["creation"], "outcome": "success", "original": "{\"event_id\": \"458b6b34-9a4e-47cd-952b-4b86f163847f\", \"event_source\": \"iam\", \"event_type\": \"yandex.cloud.audit.iam.CreateAccessKey\", \"event_time\": \"2026-10-02T15:08:22.184694Z\", \"authentication\": {\"authenticated\": true, \"subject_type\": \"FEDERATED_USER_ACCOUNT\", \"subject_id\": \"ajeb3f10c9e82a4d7c61\", \"subject_name\": \"platform.admin\", \"federation_id\": \"bpffd0b1506f5e3af1f1\", \"federation_name\": \"contoso\", \"federation_type\": \"PRIVATE_FEDERATION\"}, \"authorization\": {\"authorized\": true}, \"resource_metadata\": {\"path\": [{\"resource_type\": \"organization-manager.organization\", \"resource_id\": \"bpf8fce59da310dc940c\", \"resource_name\": \"contoso-org\"}, {\"resource_type\": \"resource-manager.cloud\", \"resource_id\": \"b1g0a10235b15143e07a\", \"resource_name\": \"contoso-cloud\"}, {\"resource_type\": \"resource-manager.folder\", \"resource_id\": \"b1g2a15c9bea04fe16e5\", \"resource_name\": \"production\"}]}, \"request_metadata\": {\"remote_address\": \"10.60.1.44\", \"user_agent\": \"yc/0.157\", \"request_id\": \"31558381-44b0-4d99-8454-978c38afef66\"}, \"event_status\": \"DONE\", \"details\": {\"access_key_id\": \"aje2ec020017dd5a2cbb\", \"service_account_id\": \"aje297789a6ce32a2b57\", \"service_account_name\": \"svc-maint-297789a6ce32a2b57\", \"key_id\": \"YCkGnuBifwTIKhuZSlVNoaauY\", \"description\": \"Maintenance automation\", \"created_at\": \"2026-10-02T15:08:22.184694Z\"}}"}, "source": {"ip": "10.60.1.44"}, "user": {"id": "ajeb3f10c9e82a4d7c61", "name": "platform.admin", "target": {"id": "aje297789a6ce32a2b57", "name": "svc-maint-297789a6ce32a2b57"}}, "related": {"ip": ["10.60.1.44"], "user": ["platform.admin", "svc-maint-297789a6ce32a2b57"]}, "cloud": {"provider": "yandex", "account": {"id": "b1g0a10235b15143e07a"}}, "yandex_cloud": {"audit": {"event_id": "458b6b34-9a4e-47cd-952b-4b86f163847f", "event_source": "iam", "event_type": "yandex.cloud.audit.iam.CreateAccessKey", "event_time": "2026-10-02T15:08:22.184694Z", "authentication": {"authenticated": true, "subject_type": "FEDERATED_USER_ACCOUNT", "subject_id": "ajeb3f10c9e82a4d7c61", "subject_name": "platform.admin", "federation_id": "bpffd0b1506f5e3af1f1", "federation_name": "contoso", "federation_type": "PRIVATE_FEDERATION"}, "authorization": {"authorized": true}, "resource_metadata": {"path": [{"resource_type": "organization-manager.organization", "resource_id": "bpf8fce59da310dc940c", "resource_name": "contoso-org"}, {"resource_type": "resource-manager.cloud", "resource_id": "b1g0a10235b15143e07a", "resource_name": "contoso-cloud"}, {"resource_type": "resource-manager.folder", "resource_id": "b1g2a15c9bea04fe16e5", "resource_name": "production"}]}, "request_metadata": {"remote_address": "10.60.1.44", "user_agent": "yc/0.157", "request_id": "31558381-44b0-4d99-8454-978c38afef66"}, "event_status": "DONE", "details": {"access_key_id": "aje2ec020017dd5a2cbb", "service_account_id": "aje297789a6ce32a2b57", "service_account_name": "svc-maint-297789a6ce32a2b57", "key_id": "YCkGnuBifwTIKhuZSlVNoaauY", "description": "Maintenance automation", "created_at": "2026-10-02T15:08:22.184694Z"}}}}
```

# Yandex Cloud Audit Trails

Generates Yandex Cloud Audit Trails management events for one organization, cloud and folder, for SIEM content that watches cloud IAM and Compute changes. Each JSON Line is an ECS record with the native audit record in `event.original` and parsed under `yandex_cloud.audit`. The native fields and event names follow the [management-log format](https://yandex.cloud/en/docs/audit-trails/concepts/format) and the event references listed below. Only successful control-plane operations are modeled; data-plane events are out of scope.

## Event Types

Approximate shares over six days of a default run with `anomaly_mode: true` (about 7,600 records); individual runs vary by about a percentage point per action.

| Audit event | Share | Operators | Autoscaler | Category | Modeled operation |
| --- | ---: | ---: | ---: | --- | --- |
| `compute.UpdateInstance` | 52.5% | 12.5% | 40.0% | configuration | Label update on a permanent, CI or runner VM |
| `compute.CreateInstance` | 15.4% | 1.8% | 13.6% | configuration | Temporary CI VM or CI runner VM |
| `compute.DeleteInstance` | 15.4% | 1.7% | 13.6% | configuration | Cleanup of a CI or runner VM |
| `resourcemanager.UpdateFolderAccessBindings` | 6.3% | 6.3% | — | iam | ADD or REMOVE of one folder role for a service account |
| `iam.CreateAccessKey` | 3.5% | 3.5% | — | iam | Static access key for a service account |
| `iam.DeleteAccessKey` | 3.1% | 3.1% | — | iam | Key rotation or cleanup |
| `iam.CreateServiceAccount` | 2.2% | 2.2% | — | iam | New service account |
| `iam.DeleteServiceAccount` | 1.6% | 1.6% | — | iam | Cleanup of a created account after its keys and roles |

Six federated operators (about a third of records) work in sessions on an office-hours curve (UTC+3); each session holds a random number of operations separated by gaps of one to a few minutes. Operators have different activity levels and use an office or a VPN address. Operations:

- label updates on 64 permanent VMs and on live CI VMs;
- temporary CI VMs, each deleted after a random lifetime of hours by the creator or another operator (at most eight at a time);
- service-account provisioning for pipelines and integrations: a new account, then usually a folder role (`editor`, `viewer`, `storage.editor` or `compute.editor`) and often a static key within minutes, in either order;
- role and key maintenance on the 24 permanent and on created accounts, including an `editor` grant followed by a key, role removal and key rotation;
- cleanup of every created account after a random lifetime of about a day: keys are deleted, roles removed, then the account is deleted, one call each, a few minutes apart.

The CI runner autoscaler, a service account (about two thirds of records), creates runner VMs for queued jobs, labels a runner `runner-state: busy` with the job ID for every job it takes and `runner-state: idle` after its last job and after some others, and deletes a runner once idle. It makes about 54 calls per hour in 06:00-18:00 UTC and 20 at night, and never touches IAM.

ADD never repeats a binding held by the account, REMOVE only follows an ADD, and a key is deleted only once. An account holds at most two background keys, and at most 70 created accounts are live at a time (with the 24 permanent ones, below the IAM quota of 100 per cloud); anomaly episodes obey the same limits. Rates, lifetimes and weights are synthetic, not measured production values.

## Volume and Timing

About 1,300 records per day on working days and weekends alike, with a ±10% day-to-day variation. Hourly volume in UTC:

| UTC hours | Operator sessions per hour | Autoscaler calls per hour | All records per hour |
| --- | ---: | ---: | ---: |
| 07-15 | 7.7 | 50-55 | 80-85 |
| 06-07, 15-16 | 5.3 | 55-60 | about 80 |
| 16-18 | 2.4 | about 64 | about 77 |
| 05-06 | 2.4 | about 18 | about 27 |
| 18-21 | 1.2 | about 18 | about 26 |
| 21-05 | 0.5 | about 21 | about 25 |

Operator sessions start at random times inside each hour; an operator's later operations in a session, and the role, key and cleanup calls that follow a new account, come one to a few minutes apart. Anomaly episodes do not change when operator sessions start; each episode's three records replace about three autoscaler calls.

## Anomaly Chain

With `anomaly_mode: true` (the default), an operator provisions a service account with persistent write access:

1. `iam.CreateServiceAccount` - a new account.
2. `resourcemanager.UpdateFolderAccessBindings` - ADD of the `editor` role on the folder for that account.
3. `iam.CreateAccessKey` - a static access key for that account.

Linking fields: the same `user.id` (`authentication.subject_id`) and the same account in `user.target.id` (`details.service_account_id`, or `access_binding.subject_id` in the binding delta), all three within 30 minutes of the account creation. The gaps between the steps come from the same distributions as background provisioning, limited so that the sequence usually ends within 15 minutes and always within 30; an episode usually spans a few minutes.

Recurrence: `anomaly_interval_hours` (default 24, minimum 2). The first episode starts within the first min(interval, 24 h) of generation; each later one within a window of width min(interval / 4, 6 h) centred one interval after the previous actual start. Start times inside a window are weighted by the square of the office-hours curve plus a small floor, so episodes mostly fall in working hours. The phase can move by at most half a window per episode, and when the interval is not close to a multiple of 24 hours some starts fall outside working hours: at 12 hours every other episode lands about 12 hours from the busy phase, and at 8 hours or less the windows cover the whole clock. After the drawn time the episode starts with a further random delay of a few minutes. An episode due while 70 created accounts are live is skipped, as background provisioning is at that limit. Missed episodes are not replayed.

Variation: the operator changes with every episode, chosen with the background activity weights, and uses the address it uses in background; each episode has a fresh account, key and request IDs. The account then follows the ordinary cleanup, so its key deletion, role removal and account deletion appear in the log about a day later.

Background contains every step and every partial sequence of the chain for the same operators and addresses: a new account with an `editor` grant, a new account with a key, an `editor` grant followed by a key on an existing account, and the complete sequence spread over more than 30 minutes. It never contains the complete sequence within 30 minutes: where an operator would complete it, the operator does another ordinary operation at that moment instead. Detection idea: alert on the three steps by one subject on one new account within 30 minutes, and on keys issued for accounts with fresh `editor` or `admin` bindings.

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

Operators, their addresses and activity levels are in `samples/operators.json`, the autoscaler's service account and addresses in `samples/automation.json`; permanent VMs and service accounts are in `samples/instances.json` and `samples/service_accounts.json`.

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

Batch mode: the timestamps come from the pattern files under `patterns/`, which carry `start` and `end` (`end: never` for live use). In a copy of `patterns/`, set every file to the same finite window that starts at midnight UTC, for example `start: "2026-09-27T00:00:00Z"` and `end: "2026-10-03T00:00:00Z"` (at least 50 hours for two episodes at the default interval); a window that starts at another time shifts the daily curve. Then run:

```bash
eventum generate --path generators/cloud-yandex-audit-trails/generator.yml --id yandex-audit --live-mode false --keep-order true
```

To change the volume, scale the `ratio` of the `human-*` files (operator sessions) or the `automation-*` files (autoscaler and the pace of operator follow-up calls) by one factor per group; fewer `automation` timestamps stretch the gaps between an operator's calls.

Timestamps are UTC.

## Performance

About 1,800 events per second: a 14-day default run (18,310 records) takes 10.3 s of wall time and 10.5 s of CPU, including startup.

## Limitations

- No live tenant log was compared. The native envelope follows the complete CreateInstance example in the format page; `details` follow the event references, converted to the snake_case of that example. Field-complete parity is not claimed.
- Optional `token_info`, `request_parameters`, `response`, `error` and `remote_port` are omitted; so are `status` and `expires_at` in `DeleteServiceAccount`, whose values are not documented. Failed and cancelled operations are not modeled.
- The transport containers of Object Storage, Cloud Logging and Data Streams are not reproduced; each line is one record.
- `event.original` keeps the field order of the vendor example on one line; the example is indented, so whitespace differs.
- The format page documents `user_agent` only as the subject's user agent. Each operator uses one `yc` CLI version (`yc/0.153` to `yc/0.157`) and the autoscaler a gRPC Go client string (`grpc-go/1.64.0`); these strings are synthetic. VM MAC addresses use the `d0:0d` prefix seen on Yandex Cloud VMs, and product, subnet and federation IDs are synthetic.
- The VM pools assume Compute quotas above the default of 12 VMs.
- `user.target.*` is an ECS mapping of the service account the event acts on, not a native field.
- Consecutive calls of one operator job are one to a few minutes apart, never seconds (cleanup calls of one account: median about 4 minutes); scripted work would usually be faster.
- Anomaly episodes usually span up to about 15 minutes, while the same partial sequences in background may take longer; complete sequences in background span more than 30 minutes.
- With `anomaly_mode: true` each episode adds its own records, so counts of the chain parts (a new account with a role, a key or both within 30 minutes, an `editor` grant followed by a key) are about one per episode higher than without episodes.

## References

- [Management event audit log format](https://yandex.cloud/en/docs/audit-trails/concepts/format)
- Event references: [CreateInstance](https://yandex.cloud/en/docs/audit-trails/audit/compute/events-ref/CreateInstance), [UpdateInstance](https://yandex.cloud/en/docs/audit-trails/audit/compute/events-ref/UpdateInstance), [DeleteInstance](https://yandex.cloud/en/docs/audit-trails/audit/compute/events-ref/DeleteInstance), [CreateServiceAccount](https://yandex.cloud/en/docs/audit-trails/audit/iam/events-ref/CreateServiceAccount), [DeleteServiceAccount](https://yandex.cloud/en/docs/audit-trails/audit/iam/events-ref/DeleteServiceAccount), [CreateAccessKey](https://yandex.cloud/en/docs/audit-trails/audit/iam/events-ref/CreateAccessKey), [DeleteAccessKey](https://yandex.cloud/en/docs/audit-trails/audit/iam/events-ref/DeleteAccessKey), [UpdateFolderAccessBindings](https://yandex.cloud/en/docs/audit-trails/audit/resourcemanager/events-ref/UpdateFolderAccessBindings)
- [Folder access bindings](https://yandex.cloud/en/docs/resource-manager/operations/folder/set-access-bindings), [service accounts](https://yandex.cloud/en/docs/iam/concepts/users/service-accounts), [static access keys](https://yandex.cloud/en/docs/iam/concepts/authorization/access-key), [IAM quotas](https://yandex.cloud/en/docs/iam/concepts/limits), [Compute quotas](https://yandex.cloud/en/docs/compute/concepts/limits)
- No Elastic integration exists for Yandex Cloud Audit Trails.

## Sample Output

A `CreateAccessKey` record completing an anomaly episode:

```json
{"@timestamp": "2026-09-28T12:46:42.251134Z", "ecs": {"version": "8.17.0"}, "event": {"kind": "event", "module": "yandex_cloud", "dataset": "yandex_cloud.audit", "id": "e22f1c47-2596-4cba-8d4d-514812201ddf", "action": "CreateAccessKey", "category": ["iam"], "type": ["creation"], "outcome": "success", "original": "{\"event_id\": \"e22f1c47-2596-4cba-8d4d-514812201ddf\", \"event_source\": \"iam\", \"event_type\": \"yandex.cloud.audit.iam.CreateAccessKey\", \"event_time\": \"2026-09-28T12:46:42.251134Z\", \"authentication\": {\"authenticated\": true, \"subject_type\": \"FEDERATED_USER_ACCOUNT\", \"subject_id\": \"aje4a90f6b1d3c28e57d\", \"subject_name\": \"sre.oncall\", \"federation_id\": \"bpffd0b1506f5e3af1f1\", \"federation_name\": \"contoso\", \"federation_type\": \"PRIVATE_FEDERATION\"}, \"authorization\": {\"authorized\": true}, \"resource_metadata\": {\"path\": [{\"resource_type\": \"organization-manager.organization\", \"resource_id\": \"bpf8fce59da310dc940c\", \"resource_name\": \"contoso-org\"}, {\"resource_type\": \"resource-manager.cloud\", \"resource_id\": \"b1g0a10235b15143e07a\", \"resource_name\": \"contoso-cloud\"}, {\"resource_type\": \"resource-manager.folder\", \"resource_id\": \"b1g2a15c9bea04fe16e5\", \"resource_name\": \"production\"}]}, \"request_metadata\": {\"remote_address\": \"10.60.1.85\", \"user_agent\": \"yc/0.155\", \"request_id\": \"5ed5ca15-21fa-4baf-b540-59e4ad785929\"}, \"event_status\": \"DONE\", \"details\": {\"access_key_id\": \"ajecf34ee1c532cf2805\", \"service_account_id\": \"aje7dae6f30b3b2df237\", \"service_account_name\": \"svc-maint-7dae6f30b3b2df237\", \"key_id\": \"YCMnoToREoyxIiOvrAxpojejX\", \"description\": \"Maintenance automation\", \"created_at\": \"2026-09-28T12:46:42.251134Z\"}}"}, "source": {"ip": "10.60.1.85"}, "user": {"id": "aje4a90f6b1d3c28e57d", "name": "sre.oncall", "target": {"id": "aje7dae6f30b3b2df237", "name": "svc-maint-7dae6f30b3b2df237"}}, "related": {"ip": ["10.60.1.85"], "user": ["sre.oncall", "svc-maint-7dae6f30b3b2df237"]}, "cloud": {"provider": "yandex", "account": {"id": "b1g0a10235b15143e07a"}}, "yandex_cloud": {"audit": {"event_id": "e22f1c47-2596-4cba-8d4d-514812201ddf", "event_source": "iam", "event_type": "yandex.cloud.audit.iam.CreateAccessKey", "event_time": "2026-09-28T12:46:42.251134Z", "authentication": {"authenticated": true, "subject_type": "FEDERATED_USER_ACCOUNT", "subject_id": "aje4a90f6b1d3c28e57d", "subject_name": "sre.oncall", "federation_id": "bpffd0b1506f5e3af1f1", "federation_name": "contoso", "federation_type": "PRIVATE_FEDERATION"}, "authorization": {"authorized": true}, "resource_metadata": {"path": [{"resource_type": "organization-manager.organization", "resource_id": "bpf8fce59da310dc940c", "resource_name": "contoso-org"}, {"resource_type": "resource-manager.cloud", "resource_id": "b1g0a10235b15143e07a", "resource_name": "contoso-cloud"}, {"resource_type": "resource-manager.folder", "resource_id": "b1g2a15c9bea04fe16e5", "resource_name": "production"}]}, "request_metadata": {"remote_address": "10.60.1.85", "user_agent": "yc/0.155", "request_id": "5ed5ca15-21fa-4baf-b540-59e4ad785929"}, "event_status": "DONE", "details": {"access_key_id": "ajecf34ee1c532cf2805", "service_account_id": "aje7dae6f30b3b2df237", "service_account_name": "svc-maint-7dae6f30b3b2df237", "key_id": "YCMnoToREoyxIiOvrAxpojejX", "description": "Maintenance automation", "created_at": "2026-09-28T12:46:42.251134Z"}}}}
```

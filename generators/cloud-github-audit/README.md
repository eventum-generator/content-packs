# GitHub Organization REST Audit Generator

Generates the selected GitHub Enterprise Cloud organization audit JSON object profile and its ECS projection. `event.original` holds the complete generated native object, not a webhook. The pack models successful selected actions, rather than API authentication, polling, invitations or pagination.

The synthetic inventory has three persistent initialized private repositories and one disposable recovery-drill repository. `alice`, `bob` and `ops-admin` are organization owners with permission to manage repositories, collaborators and protection rules. Organization policy permits these operations, and the external collaborator satisfies its access requirements. The outside collaborator already has read access to the three persistent repositories. The drill initially exists with `main` protected and no collaborator. Its later creation initializes a README/default branch. No production payroll contents or actual restored backup are implied. `repo.add_member` represents accepted access; invitation and authentication events are outside this selected subset.

## Event Types Covered

| Action | Ordinary behavior |
|---|---|
| `repo.download_zip` | Selected archive access on an existing repository |
| `repo.add_topic`, `repo.remove_topic` | Add/remove one of three tracked topics |
| `repo.add_member`, `repo.update_member`, `repo.remove_member` | Existing collaborator grant, write-to-admin change, then removal |
| `protected_branch.create`, `protected_branch.destroy` | Enable/disable existing `main` protection |
| `repo.create`, `repo.destroy` | Create/delete the disposable initialized drill |
| `org.add_member`, `org.remove_member` | Add/remove one existing test identity |

The FSM emits a sparse synthetic active organization workload on five-minute slots with 0–999 ms timestamp jitter. Permanent-repository archive access dominates. Topic mutation is selected on 20% of eligible owner background slots and keeps its previous state. Neither timing nor action ratios are measured GitHub production frequencies.

Ordinary drill maintenance has a bounded 72-slot cycle, about six hours, paused during an episode. Its grant, permission change, protection removal, archive access, collaborator removal and deletion stages are separated by about 30 minutes and intervening routine records. It operates on the same drill and owner/external identities as the episode. Some stages are skipped if an episode or recovery already changed the required state. After deletion, recovery becomes eligible one hour later and visibly creates a new repository incarnation, then creates its protection rule on the next slot. No action occurs against a deleted incarnation. Deleting a repository naturally removes that incarnation's collaborator/protection state. The ordinary test-member lifecycle is independent and does not grow the organization indefinitely.

## Anomaly Chain

`anomaly_mode: true` is the default. After `anomaly_interval_hours` of generated source time, 24 hours by default, five ordered records show:

1. The owner grants `external-collab` write access to the drill.
2. The owner changes that collaborator from write to admin.
3. The owner removes `main` protection.
4. The collaborator downloads a ZIP archive of that repository.
5. The owner deletes it.

Five consecutive selected records span about 20 minutes. Join the organization, repository **ID** and name, actor/target identities, native document IDs and ordered source timestamps. A 25-minute correlation window separates this dense sequence from the spaced ordinary maintenance. A ZIP audit record does not report bytes, network destination, archive contents or exfiltration. The last deletion is the owner's action, not inferred from the collaborator's admin permission.

An episode waits for a live protected drill with no collaborator and for current recovery to finish. Its recurrence starts at the actual grant, with no catch-up burst. The supported minimum is six hours. Ordinary state changes can delay the next eligible episode. In the retained daily run, first grants were at 24h10m, 48h15m and 72h25m. Custom twelve-hour recurrence produced six complete episodes, and minimum six-hour collision stress produced twelve over the same 76h20 window. Repository names are reused after deletion, while each recreation has a new numeric ID. Each event has a new synthetic opaque 22-character document ID. The bounded incarnation counter wraps after one billion recreations; it is not a claim about GitHub's internal ID allocator.

`anomaly_mode: false` retains the same actors, target, all twelve action classes and visible recovery, with zero complete dense sequences. A finite capture can end with a live unprotected drill, an ordinary collaborator grant, a deleted drill waiting for recovery, or an organization test member. The generator preserves that state and does not fabricate final cleanup.

## Reference Field Map

| Field group | Source and strategy |
|---|---|
| Native object | GitHub organization audit catalog, reduced REST object examples; documented common keys plus selected action-specific keys |
| Native clock/document | Source UNIX-millisecond `@timestamp`/`created_at` and synthetic opaque `_document_id`; UTC ECS time and `event.id` |
| Actor/target | `actor`/numeric `actor_id` and optional `user`/`user_id` map to `user.name/id`, `user.target`, `github.*` and `related.user` |
| Organization/repository | Preserve names and IDs in `github.*`, with normalized ID strings; organization membership records omit unrelated repository fields |
| Permission/protection/topic | Preserve `permission`, `old_repo_permission`, `new_repo_permission`, `name`, `admin_enforced` or `topic` for their selected actions |
| Collector context | Stable explicitly synthetic Filebeat/Elastic Agent identity, namespace and immediate collection timestamps |

All **32/32** leaf paths from the pinned Elastic `github.audit` `repo.destroy` sample occur in generated events. Relevant native extra fields are retained using its pipeline mapping. Its configured ECS version is `8.11.0`. Organization operations also receive IAM/group/target-group fields. The maintained pipeline maps `repo.destroy` and `repo.download_zip` to `event.type: ["change"]`; this pack follows that integration convention rather than inferring type from the English action meaning.

Field presence is not a realism score. The primary catalog documents fields without proving every combination or optional value. The reduced membership/protection/topic objects and lowercase write/admin audit values are selected documented-role/catalog inferences. Complete raw captures for those actions, GitHub's document-ID allocation, live Elastic ingestion and applied organization configuration were not established. No exact-build/native byte parity or source-generated collector metadata is claimed. The sample and older maintained native fixtures support JSON framing and selected classes, not the entire correlated trace.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Name | Default | Purpose |
|---|---|---|
| `anomaly_mode` | `true` | Include recurring dense sequences |
| `anomaly_interval_hours` | `24` | Source-time recurrence, at least six hours |
| `org`, `org_id` | `contoso-security`, `71234567` | Organization name/numeric ID |
| `sensitive_repo` | `contoso-security/payroll-service-drill` | Existing disposable initialized recovery-drill repository |
| `sensitive_repo_id` | `981234567` | Initial repository ID, incremented at recreation |
| `suspicious_actor`, `suspicious_actor_id` | `ops-admin`, `139876543` | Owner also active in ordinary maintenance |
| `external_user`, `external_user_id` | `external-collab`, `98234567` | Existing outside identity with accepted repository access when granted |
| `collector_id` | `5630df5f-562b-4c5a-bcc1-b151fbca02c4` | Synthetic collector identity |
| `collector_ephemeral_id` | `df3107a1-9f4a-4336-ae3a-ecad098902d4` | Synthetic collector process identity |
| `collector_version` | `9.4.4` | Synthetic collector version |

Use positive distinct numeric IDs and distinct actor names, separate from fixed `alice`, `bob` and `new-hire-test`. Set the drill name under the configured organization, separate from fixed `api-gateway`, `billing-web` and `infra-modules`. Keep the shipped five-minute/count-one cadence for documented timing.

### Output Parameters

The shipped local `output/events.json` output requires no top-level params/secrets. Replace the output plugin to deliver to a SIEM. A real collector needs authorized Enterprise Cloud organization REST audit access, for example an owner token with `read:audit_log`, subject to the current supported token permissions. No token is embedded in this generator.

## Usage

From the content-packs repository root:

```bash
uv run --project ../eventum eventum generate --path generators/cloud-github-audit/generator.yml --id github --live-mode true
```

For a finite sample, copy the configuration next to the original, set cron `start: 2026-09-25T00:00:00Z` and `end: 2026-09-28T04:20:00Z`, then run the copied path with `--live-mode false --keep-order true`. Batch mode alone does not bound an open-ended schedule. Serialize heavy commands with `flock -x /tmp/eventum-generator-heavy.lock`.

## Validation

Four finite 76h20 runs and a minimum-interval collision run completed with exit0. Custom runs changed organization, identities, repository, collector and recurrence, with Europe/Moscow input/CLI time normalized to UTC. Streaming checks covered native/normalized fields, permission and repository lifecycles, topic/org membership transitions, ordinary constituent/actor overlap and source timing.

| Capture | Records | Complete dense episodes | Visible recreations |
|---|---:|---:|---:|
| `default_on` | 914 | 3 | 15 |
| `default_off` | 917 | 0 | 13 |
| `custom_on` | 911 | 6 | 18 |
| `custom_off` | 917 | 0 | 13 |
| `stress_on` | 905 | 12 | 23 |

The model keeps four repository slots, three topic bitsets, one test-member flag and bounded scalar scheduling/incarnation state. It keeps no deleted-repository or event history.

## Sample Output

A complete protection-removal record copied from the final default enabled capture:

```json
{
  "@timestamp": "2026-09-26T00:20:00.153+00:00",
  "agent": {
    "ephemeral_id": "df3107a1-9f4a-4336-ae3a-ecad098902d4",
    "id": "5630df5f-562b-4c5a-bcc1-b151fbca02c4",
    "name": "github-audit-collector",
    "type": "filebeat",
    "version": "9.4.4"
  },
  "data_stream": {
    "dataset": "github.audit",
    "namespace": "default",
    "type": "logs"
  },
  "ecs": {
    "version": "8.11.0"
  },
  "elastic_agent": {
    "id": "5630df5f-562b-4c5a-bcc1-b151fbca02c4",
    "snapshot": false,
    "version": "9.4.4"
  },
  "event": {
    "action": "protected_branch.destroy",
    "agent_id_status": "verified",
    "category": [
      "configuration",
      "web"
    ],
    "created": "2026-09-26T00:20:00.153+00:00",
    "dataset": "github.audit",
    "id": "U0r7vYLjRAu0Nyr9QZP9jw",
    "ingested": "2026-09-26T00:20:00.153+00:00",
    "kind": "event",
    "module": "github",
    "original": "{\"@timestamp\": 1790382000153, \"_document_id\": \"U0r7vYLjRAu0Nyr9QZP9jw\", \"action\": \"protected_branch.destroy\", \"actor\": \"ops-admin\", \"actor_id\": 139876543, \"admin_enforced\": true, \"created_at\": 1790382000153, \"name\": \"main\", \"org\": \"contoso-security\", \"org_id\": 71234567, \"public_repo\": false, \"repo\": \"contoso-security/payroll-service-drill\", \"repo_id\": 981234571}",
    "type": [
      "change"
    ]
  },
  "github": {
    "actor_id": "139876543",
    "admin_enforced": true,
    "category": "protected_branch",
    "name": "main",
    "org": "contoso-security",
    "org_id": "71234567",
    "public_repo": false,
    "repo": "contoso-security/payroll-service-drill",
    "repo_id": "981234571"
  },
  "input": {
    "type": "httpjson"
  },
  "related": {
    "user": [
      "ops-admin",
      "139876543"
    ]
  },
  "tags": [
    "forwarded",
    "github-audit",
    "preserve_original_event"
  ],
  "user": {
    "id": "139876543",
    "name": "ops-admin"
  }
}
```

## References

- [GitHub Enterprise Cloud organization audit catalog](https://docs.github.com/en/enterprise-cloud@latest/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/audit-log-events-for-your-organization) and [REST audit endpoint](https://docs.github.com/en/enterprise-cloud@latest/rest/orgs/orgs#get-the-audit-log-for-an-organization).
- [Repository deletion permissions](https://docs.github.com/en/repositories/creating-and-managing-repositories/deleting-a-repository), [branch protection rules](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/managing-a-branch-protection-rule), [repository creation options](https://docs.github.com/en/rest/repos/repos#create-an-organization-repository) and [archive downloads](https://docs.github.com/en/repositories/working-with-files/using-files/downloading-source-code-archives).
- [Elastic GitHub integration](https://www.elastic.co/docs/reference/integrations/github), [pinned sample](https://github.com/elastic/integrations/blob/4e7455b3bdfdea9a51b9b8cfe4141eeb43ae07cc/packages/github/data_stream/audit/sample_event.json), [pipeline](https://github.com/elastic/integrations/blob/4e7455b3bdfdea9a51b9b8cfe4141eeb43ae07cc/packages/github/data_stream/audit/elasticsearch/ingest_pipeline/default.yml) and [native fixtures](https://github.com/elastic/integrations/blob/4e7455b3bdfdea9a51b9b8cfe4141eeb43ae07cc/packages/github/data_stream/audit/_dev/test/pipeline/test-organisation-audit-json.log).

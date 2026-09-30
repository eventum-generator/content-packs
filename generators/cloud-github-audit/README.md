# GitHub Organization REST Audit Generator

Generates GitHub Enterprise Cloud organization audit log records as returned by the REST audit endpoint, projected to ECS the way the Elastic GitHub integration maps them. `event.original` holds the complete generated native object. The pack covers a selected set of successful repository-administration actions; API authentication, git events, invitations and pagination are outside it.

The synthetic organization has three owners (`alice`, `bob` and the configurable `ops-admin`), two members with read access through the base permission and write access to the persistent repositories through a developer team (`carol`, `dmitri`; team grants produce no records here), two build-automation machine accounts that are members (`build-runner-svc`, `release-sync-svc`), and three outside collaborators (the configurable `external-collab`, plus `vendor-qa` and `contract-sre`). It holds three persistent private repositories (`api-gateway`, `billing-web`, `infra-modules`) and three disposable sandbox repositories (the configurable `payroll-service-drill`, plus `ci-sandbox-drill` and `docs-preview-drill`); owners also create review repositories (`vendor-review-N`, `partner-poc-N`, `audit-evidence-N`, `support-repro-N`) for one outside collaborator and delete them again. At start every repository exists with `main` protected; `external-collab` has read access to the persistent repositories and `vendor-qa` has write access to `billing-web`. `repo.add_member` represents accepted access; invitation records are not generated.

## Event Types Covered

Approximate shares over six days with `anomaly_mode: false` (about 1,600 records per day); they vary from run to run because repository, collaborator and pull request states change which tasks are possible.

| Action | Share | `event.category` | Ordinary behavior |
|---|---:|---|---|
| `workflows.prepared_workflow_job` | 35.4% | configuration, web | A job of a workflow run starts on a GitHub-hosted runner; only the release `publish` job lists a secret (`RELEASE_TOKEN`) in `secrets_passed` |
| `workflows.completed_workflow_run` | 21.1% | configuration, web | A run attempt completes: `success` 88%, `failure` 10%, `cancelled` 2% |
| `workflows.created_workflow_run` | 20.4% | configuration, web | A run of `CI` (61%), `CodeQL` (35%) or `Release` (5%) of a persistent repository starts on a pull request (53%), a push (43%) or a dispatch (5%) |
| `repo.download_zip` | 15.1% | configuration, web | Archive downloads by owners, members and collaborators with access (73% of downloads, sometimes 2–3 in a row), and release archives fetched by `release-sync-svc` (27%) |
| `repo.add_member` | 1.45% | configuration, web | An owner grants an outside collaborator `read`, `write` or `admin` |
| `repo.update_member` | 1.19% | configuration, web | Quick corrections after a grant, later permission changes and reverts |
| `protected_branch.create` | 0.98% | configuration, web | Protection set on a new or recreated repository, or restored after a hotfix or onboarding |
| `protected_branch.destroy` | 0.79% | configuration, web | Temporary removal for a hotfix, onboarding, teardown or review |
| `repo.create`, `repo.destroy` | 0.77%, 0.77% | configuration, web | A deleted sandbox recreated under the same name with a new ID, or a review repository created; sandbox teardown, the end of a short sandbox collaboration, or the end of a review |
| `workflows.rerun_workflow_run` | 0.74% | configuration, web | The developer who triggered a failed run re-runs it (about a third of failures); attempt 2 has its jobs and completion again |
| `repo.remove_member` | 0.69% | configuration, web | Access revoked hours later, or during teardown |
| `repo.add_topic`, `repo.remove_topic` | 0.27%, 0.21% | configuration, web | Topic edits on persistent repositories |
| `org.add_member`, `org.remove_member` | 0.07%, 0.06% | configuration, web, iam | One test identity joining and leaving the organization |

Workflow records are about 78% of all records, about 1,200 per day. Each persistent repository keeps three to six open pull requests, each with a number, a head branch and an author; a merge closes one and a new one opens with a higher number (about 25–50 distinct pull requests per repository in six days). A developer's push to an open pull request starts `CI` on the push (`refs/heads/<branch>`) and `CI` and `CodeQL` on the pull request (`refs/pull/<number>/merge`); a merge by the author or another developer starts `CI`, `CodeQL` and, one time in four, `Release` on `main`. The developers are the owners and the two members. The build accounts only dispatch runs on `main` (`release-sync-svc` the release, `build-runner-svc` CI or CodeQL) and fetch release archives. A run has one to three jobs and completes after a run time around a per-workflow median (4, 9 and 7 minutes). The workflow actions and fields are the catalog's records of a GitHub Actions run; the catalog states that they are available through the REST API, streaming and exports, which is the endpoint this pack models.

People's administration adds about 290 records per day, with more activity from 08:00 to 18:00 UTC than at night. It is a set of independent tasks: archive downloads, topic edits, collaborator grants (with an optional quick permission correction, a later download by the grantee and a later removal), permission changes, revocations, hotfixes (optional elevation of a collaborator, protection removal, optional archive, protection restored later), collaborator onboarding to a sandbox (write grant, optional elevation to admin, optional protection removal, optional download by the collaborator), sandbox teardown (optional revocations, protection removal and backup archive, then deletion), short sandbox collaborations that end with the sandbox deleted, and reviews.

In a review an owner creates a repository for one outside collaborator, often protects it, and shares it. Quick handoffs of one to four repositories in a row go through four of the five steps listed under Anomaly Chain: one step is left out, or the grant comes more than 30 minutes before the rest, or the deletion more than 30 minutes after. Other reviews share `write` access for a download and a deletion within minutes, without elevation or protection change, or share `read` or `write` access for hours to days with zero to two downloads. Reviews create about six repositories per day (median lifetime about half an hour, 90th percentile about 9 hours, up to about three days) and make up about a tenth of people's administration records. Every delay between steps is drawn at random, from about a minute for corrections to hours for revocations and recreation. No task runs on a fixed schedule or rotation. Owners choose actions, collaborators and repositories at random.

`event.created` is the next poll of a synthetic Elastic Agent `httpjson` input polling every two minutes (within the integration's 2m–1h range), 0.3–122 s after the source time; `event.ingested` follows it by a few seconds and is truncated to whole seconds, as the Fleet final pipeline does. Neither timing nor action ratios are measured GitHub production frequencies.

## Volume and Timing

The data holds about 1,600 records per day in two streams with their own hour-of-day curves (UTC):

| Stream | Records per day | Hour-of-day shape (UTC) |
|---|---:|---|
| People's administration and archive downloads | about 290 | Relative activity 0.35 at 00–06, 0.8 at 06–08, 1.5 at 08–18, 0.9 at 18–21, 0.5 at 21–24 |
| GitHub Actions activity and release archive downloads | about 1,300 | About 45 records per hour, 75 per hour from 07:00 to 19:00 |

Every follow-up action comes after a random think time: a quick permission correction a minute or two after a grant, the next step of a teardown or review a few minutes later, a revocation hours later, a sandbox recreation a few hours after its deletion. New workflow activity starts as a push to an open pull request (about 44% of new activity), a merge (13%), a dispatch by a build account (9%) or a release archive download (33%); the jobs of a run follow within a minute and its completion after the run time. The two build accounts do not take part in administration or in the anomaly chain and act on persistent repositories only.

Anomaly episodes interleave with this traffic without pausing or moving it: their records take the place of about five to seven ordinary records, mostly workflow records, and ordinary tasks continue on their own schedule. Episode steps follow the same think times as ordinary reviews.

## Anomaly Chain

`anomaly_mode: true` is the default. Roughly once per `anomaly_interval_hours` of source time (see Recurrence), one owner and one outside collaborator act on one repository incarnation. Nine episodes in ten use a new review repository, named like ordinary ones, which the owner creates and protects first with the ordinary review setup delays; one in ten uses a sandbox:

1. The owner grants the collaborator `write` access.
2. The owner changes that access from `write` to `admin`.
3. The owner removes `main` protection.
4. The collaborator downloads a ZIP archive of the repository.
5. The owner deletes the repository.

The five records keep this order within 30 minutes of the grant (typically 8–25 minutes), interleaved with ordinary records. Correlate them by organization, repository name and ID, owner, collaborator (`user.target`) and source time. A ZIP audit record reports no bytes, destination or contents, so it is not evidence of exfiltration by itself.

**Recurrence.** The first episode starts at a random time within the first `min(interval, 24 h)` of the data, more likely at busy hours. Each later episode starts within a window of a quarter of the interval (at most 6 hours) centred on one interval after the previous episode's first grant, leaning towards busy hours. An episode on a sandbox waits until a sandbox is protected and free of the chosen collaborator. There is no catch-up. The default is 24 hours; values below 6 hours are raised to 6. At the default, consecutive episodes are about 21–27 hours apart and, once in daytime, stay in daytime; at 12 hours they are 11–14 hours apart and alternate between day and night; at the 6-hour minimum they are 5–7 hours apart.

**Rotation and consistency.** Consecutive episodes differ in owner, collaborator and repository when an eligible combination exists, and never repeat all three. Deleting the repository ends that incarnation's access and protection; a sandbox is recreated later by the ordinary recovery path with a new repository ID and has protection set again, and a review repository name is never reused. No action targets a deleted incarnation.

**What separates the modes.** Every step of the chain, every owner–collaborator pair of the grant and of the `write` → `admin` change, every pair of consecutive steps and every four-step part of the sequence also occur in ordinary traffic: a grant corrected to admin within minutes, protection removed right after a permission change, an archive downloaded right after protection removal, a deletion right after an archive or protection removal, and reviews that go through four of the five steps. Only the complete ordered sequence by one owner and one collaborator within 30 minutes of the grant is absent from `anomaly_mode: false`; when ordinary work would complete it, that sandbox is not deleted and stays as it is. Complete sequences over a longer span (grant to deletion 30–60 minutes) do occur in ordinary traffic. With `anomaly_mode: true` each episode adds its own records, so counts of the chain parts (the steps, their pairs and their three- and four-step parts) are about one per episode higher than without episodes; at intervals near 6 hours this is about four more of each per day.

`anomaly_mode: false` keeps the same identities, repositories, all sixteen action classes and the same task mix, without episodes. A finite run can end with an unprotected sandbox, a live collaborator grant, a deleted sandbox waiting for recreation, or the test identity still in the organization; the generator does not fabricate cleanup.

## Reference Field Map

| Field group | Source and strategy |
|---|---|
| Native object | GitHub organization audit catalog and reduced REST examples; documented common keys plus selected action-specific keys |
| Native clock and document | UNIX-millisecond `@timestamp`/`created_at` and a synthetic opaque 22-character `_document_id`; UTC ECS `@timestamp` and `event.id` |
| Actor and target | `actor`/numeric `actor_id` and `user`/`user_id` map to `user.name/id`, `user.target`, `github.*` and `related.user` |
| Organization and repository | Names and IDs kept in `github.*` as strings; organization membership records omit repository fields |
| Permission, protection, topic | `permission`, `old_repo_permission`, `new_repo_permission`, `name`, `admin_enforced` or `topic` on their actions |
| Collector context | Synthetic Filebeat/Elastic Agent identity, `httpjson` input, poll-time `event.created` and truncated `event.ingested` |

All 32/32 leaf paths of the pinned Elastic `github.audit` `repo.destroy` sample occur in generated events. The ECS version is the sample's `8.11.0`. Organization membership records also carry IAM, group and target-group fields. The maintained pipeline maps `repo.destroy` and `repo.download_zip` to `event.type: ["change"]`, and this pack follows it.

## Parameters

### Event Parameters

Override values in `event.template.params` of `generator.yml`:

| Name | Default | Purpose |
|---|---|---|
| `anomaly_mode` | `true` | Include recurring anomaly episodes |
| `anomaly_interval_hours` | `24` | Source-time recurrence, at least 6 hours |
| `org`, `org_id` | `contoso-security`, `71234567` | Organization name and numeric ID |
| `sensitive_repo` | `contoso-security/payroll-service-drill` | One of the three sandbox repositories |
| `sensitive_repo_id` | `981234567` | Its initial ID; the other sandboxes start below it and recreated sandboxes get larger IDs |
| `suspicious_actor`, `suspicious_actor_id` | `ops-admin`, `139876543` | Third organization owner |
| `external_user`, `external_user_id` | `external-collab`, `98234567` | First outside collaborator |
| `collector_id` | `5630df5f-562b-4c5a-bcc1-b151fbca02c4` | Synthetic collector identity |
| `collector_ephemeral_id` | `df3107a1-9f4a-4336-ae3a-ecad098902d4` | Synthetic collector process identity |
| `collector_version` | `9.4.4` | Synthetic collector version |

Keep names and numeric IDs distinct from the fixed identities `alice` (32100011), `bob` (32100012), `carol` (32100013), `dmitri` (32100014), `build-runner-svc` (41200021), `release-sync-svc` (41200022), `vendor-qa` (98234611), `contract-sre` (98234612) and `new-hire-test` (32100099). Keep `sensitive_repo` under the configured organization and different from the fixed repository names.

### Output Parameters

The shipped output writes `output/events.json` and needs no top-level params or secrets. Replace the output plugin to deliver elsewhere. A real collector needs authorized Enterprise Cloud organization audit access, for example a token with `read:audit_log`; no token is embedded here.

## Usage

From the content-packs repository root, live mode:

```bash
eventum generate --path generators/cloud-github-audit/generator.yml --id github --live-mode true
```

For a finite batch, copy the generator directory, set `start` in every file under its `patterns/` to the batch start (for example `"2026-09-25T00:00:00Z"`) and `end` to its end or a duration (for example `"+145h"`), and run:

```bash
eventum generate --path <copy>/generator.yml --id github --live-mode false --keep-order true
```

The shipped pattern files start on 2026-01-01 and never end, for live use. `--keep-order true` keeps records in source order for stateful consumers.

The volume lives in the pattern files under `patterns/`: `multiplier.ratio` is the number of records per day of each band. The `human-*.yml` files set people's administration (keep their bands in step with the `hour_weight` table in the template, which places episode starts), and the two `automation*.yml` files set GitHub Actions activity.

The first episode appears at a random time within the first `min(interval, 24 h)`; at 24 hours a window of about 51 hours contains at least two episodes.

Performance: a 14-day batch (about 22,200 records) takes about 14 s of wall time on one core of a loaded machine, about 1,500 records per second including start-up.

## Limits

- Membership, protection and topic objects are reduced; their field combinations and the lowercase `read`/`write`/`admin` values are inferences from the catalog and role documentation, not observed GitHub records. No raw byte parity, live Elastic ingestion or GitHub document-ID allocation is claimed.
- Workflow records carry a reduced field set: no runner IDs, calling workflows, re-run type or programmatic-access fields.
- `event.original` is serialized with sorted keys and spaces after separators.
- Rates, delays, the daily profile, the workflow set and volume, developers' push volume (about 16 pushes a day each), the pull request model, the review practice and the two-minute poll are synthetic choices, not measured GitHub frequencies.
- Records are spread out in time: consecutive records are about 36 s apart in median and up to about 12 minutes apart at night, so records of one moment, such as the runs started by one push or merge, are tens of seconds apart instead of within a second.
- Workflow records are the large majority; filter on `event.action` to study administration alone.
- With `anomaly_mode: true`, counts of the chain parts are about one per episode higher than in ordinary traffic alone (see What separates the modes).
- Complete grant–elevation–protection removal–download–deletion sequences spanning more than 30 minutes occur in ordinary traffic.

## Sample Output

The permission change of an anomaly episode (`anomaly_mode: true`):

```json
{
  "@timestamp": "2026-09-25T15:00:42.849+00:00",
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
    "action": "repo.update_member",
    "agent_id_status": "verified",
    "category": [
      "configuration",
      "web"
    ],
    "created": "2026-09-25T15:02:39.294+00:00",
    "dataset": "github.audit",
    "id": "ldBHYi-VQYO__uBPL5S84A",
    "ingested": "2026-09-25T15:02:42+00:00",
    "kind": "event",
    "module": "github",
    "original": "{\"@timestamp\": 1790348442849, \"_document_id\": \"ldBHYi-VQYO__uBPL5S84A\", \"action\": \"repo.update_member\", \"actor\": \"alice\", \"actor_id\": 32100011, \"created_at\": 1790348442849, \"new_repo_permission\": \"admin\", \"old_repo_permission\": \"write\", \"org\": \"contoso-security\", \"org_id\": 71234567, \"public_repo\": false, \"repo\": \"contoso-security/support-repro-101\", \"repo_id\": 981400473, \"user\": \"contract-sre\", \"user_id\": 98234612, \"visibility\": \"private\"}",
    "type": [
      "change"
    ]
  },
  "github": {
    "actor_id": "32100011",
    "category": "repo",
    "new_repo_permission": "admin",
    "old_repo_permission": "write",
    "org": "contoso-security",
    "org_id": "71234567",
    "public_repo": false,
    "repo": "contoso-security/support-repro-101",
    "repo_id": "981400473",
    "user_id": "98234612",
    "visibility": "private"
  },
  "input": {
    "type": "httpjson"
  },
  "related": {
    "user": [
      "alice",
      "32100011",
      "contract-sre",
      "98234612"
    ]
  },
  "tags": [
    "forwarded",
    "github-audit",
    "preserve_original_event"
  ],
  "user": {
    "id": "32100011",
    "name": "alice",
    "target": {
      "id": "98234612",
      "name": "contract-sre"
    }
  }
}
```

## References

- [GitHub Enterprise Cloud organization audit log events](https://docs.github.com/en/enterprise-cloud@latest/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/audit-log-events-for-your-organization) and [REST audit endpoint](https://docs.github.com/en/enterprise-cloud@latest/rest/orgs/orgs#get-the-audit-log-for-an-organization).
- [Repository deletion permissions](https://docs.github.com/en/repositories/creating-and-managing-repositories/deleting-a-repository), [branch protection rules](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/managing-a-branch-protection-rule), [repository creation](https://docs.github.com/en/rest/repos/repos#create-an-organization-repository) and [archive downloads](https://docs.github.com/en/repositories/working-with-files/using-files/downloading-source-code-archives).
- [Elastic GitHub integration](https://www.elastic.co/docs/reference/integrations/github), [pinned sample](https://github.com/elastic/integrations/blob/4e7455b3bdfdea9a51b9b8cfe4141eeb43ae07cc/packages/github/data_stream/audit/sample_event.json), [pipeline](https://github.com/elastic/integrations/blob/4e7455b3bdfdea9a51b9b8cfe4141eeb43ae07cc/packages/github/data_stream/audit/elasticsearch/ingest_pipeline/default.yml), [httpjson stream](https://github.com/elastic/integrations/blob/4e7455b3bdfdea9a51b9b8cfe4141eeb43ae07cc/packages/github/data_stream/audit/agent/stream/httpjson.yml.hbs), [data stream manifest](https://github.com/elastic/integrations/blob/4e7455b3bdfdea9a51b9b8cfe4141eeb43ae07cc/packages/github/data_stream/audit/manifest.yml) and [native fixtures](https://github.com/elastic/integrations/blob/4e7455b3bdfdea9a51b9b8cfe4141eeb43ae07cc/packages/github/data_stream/audit/_dev/test/pipeline/test-organisation-audit-json.log).

# GitHub Organization REST Audit Generator

Generates GitHub Enterprise Cloud organization audit log records as returned by the REST audit endpoint, projected to ECS the way the Elastic GitHub integration maps them. `event.original` holds the complete generated native object. The pack covers a selected set of successful repository-administration actions; API authentication, git events, invitations and pagination are outside it.

The synthetic organization has three owners (`alice`, `bob` and the configurable `ops-admin`), two members with read access through the base permission (`carol`, `dmitri`), and three outside collaborators (the configurable `external-collab`, plus `vendor-qa` and `contract-sre`). It holds three persistent private repositories (`api-gateway`, `billing-web`, `infra-modules`) and three disposable sandbox repositories (the configurable `payroll-service-drill`, plus `ci-sandbox-drill` and `docs-preview-drill`). At start every repository exists with `main` protected; `external-collab` has read access to the persistent repositories and `vendor-qa` has write access to `billing-web`. `repo.add_member` represents accepted access; invitation records are not generated.

## Event Types Covered

Shares are measured on the final 100h20 `anomaly_mode: false` capture (1,040 records); they vary between runs because repository and collaborator states change which tasks are possible.

| Action | Share | `event.category` | Ordinary behavior |
|---|---:|---|---|
| `repo.download_zip` | 69.9% | configuration, web | Archive downloads by owners, members, and collaborators with access; sometimes 2–3 in a row |
| `protected_branch.create` | 5.0% | configuration, web | Protection restored after a hotfix or onboarding, or set on a recreated sandbox |
| `protected_branch.destroy` | 4.5% | configuration, web | Temporary removal for a hotfix, onboarding or teardown |
| `repo.add_member` | 4.1% | configuration, web | An owner grants an outside collaborator `read`, `write` or `admin` |
| `repo.update_member` | 3.7% | configuration, web | Quick corrections after a grant, later permission changes and reverts |
| `repo.remove_member` | 3.0% | configuration, web | Access revoked hours later, or during teardown |
| `repo.destroy` | 2.5% | configuration, web | Sandbox teardown, or the end of a short sandbox collaboration |
| `repo.create` | 2.5% | configuration, web | A deleted sandbox recreated under the same name with a new ID |
| `repo.add_topic`, `repo.remove_topic` | 2.2%, 1.7% | configuration, web | Topic edits on persistent repositories |
| `org.add_member`, `org.remove_member` | 0.5%, 0.4% | configuration, web, iam | One test identity joining and leaving the organization |

Ordinary activity is a set of independent tasks that start at random, about 240–275 records per day, with more activity from 08:00 to 18:00 UTC than at night. Tasks are archive downloads, topic edits, collaborator grants (with an optional quick permission correction, a later download by the grantee and a later removal), permission changes, revocations, hotfixes (optional elevation of a collaborator, protection removal, optional archive, protection restored later), collaborator onboarding to a sandbox (write grant, optional elevation to admin, optional protection removal, optional download by the collaborator), sandbox teardown (optional revocations, protection removal and backup archive, then deletion), and short sandbox collaborations that end with the sandbox deleted. Every delay between steps is drawn at random, from about a minute for corrections to hours for revocations and recreation. No task runs on a fixed schedule or rotation. Owners choose actions, collaborators and repositories at random.

Each record is emitted at a random second and millisecond within its source minute. `event.created` is the next poll of a synthetic Elastic Agent `httpjson` input polling every two minutes (within the integration's 2m–1h range), 0.7–122 s after the source time; `event.ingested` follows it by a few seconds and is truncated to whole seconds, as the Fleet final pipeline does. Neither timing nor action ratios are measured GitHub production frequencies.

## Anomaly Chain

`anomaly_mode: true` is the default. Roughly once per `anomaly_interval_hours` of source time (see Recurrence for the start draw and eligibility wait), one owner and one outside collaborator act on one sandbox repository incarnation:

1. The owner grants the collaborator `write` access.
2. The owner changes that access from `write` to `admin`.
3. The owner removes `main` protection.
4. The collaborator downloads a ZIP archive of the repository.
5. The owner deletes the repository.

The five records keep this order within 30 minutes (7–29 minutes in the final captures), interleaved with ordinary records. Correlate them by organization, repository name and ID, owner, collaborator (`user.target`) and source time. A ZIP audit record reports no bytes, destination or contents, so it is not evidence of exfiltration by itself.

**Recurrence.** The first episode is due one interval after the start of generation. Once an episode is due, its start time is drawn from the following `min(interval, 24 h)` with the same hour-of-day weighting as ordinary task starts; it begins at that time, or at the first later minute when a sandbox exists, is protected and is not in another workflow and a collaborator has no access to it. The next episode is due one interval after the actual first grant, with no catch-up, so consecutive starts are usually one to two intervals apart (at 24 h and above, one interval to one interval plus 24 hours), plus any wait for an eligible sandbox (measured up to 73 minutes). The default is 24 hours; values below 6 hours are raised to 6.

| Capture | Interval | Episodes in 100h20 | Start after due | Start hours (UTC) |
|---|---|---:|---|---|
| `default_on` | 24 h | 2 | 1183, 1265 min | 19, 16 |
| `custom_on` | 12 h | 5 | 22–720 min | 21, 21, 13, 10, 22 |
| `stress_on` | 1 h → 6 h | 12 | 15–333 min | 7, 14, 0, 8, 16, 22, 8, 15, 2, 14, 21, 3 |

Over 18 episodes of nine default captures, none started between 00:00 and 06:00 UTC (ordinary administration: 12.9% of records in that band) and 10 started between 08:00 and 18:00 (ordinary: 59.1%).

**Rotation and consistency.** Consecutive episodes differ in owner, collaborator and repository when an eligible combination exists, and never repeat all three. Deleting the repository ends that incarnation's access and protection; the sandbox is recreated later by the ordinary recovery path with a new repository ID and has protection set again. No action targets a deleted incarnation.

**What separates the modes.** Every step of the chain and every pair of steps also occurs in ordinary traffic of both modes: a grant corrected to admin within minutes, protection removed right after a permission change, an archive downloaded right after protection removal, a deletion right after an archive or protection removal, and a grant followed by deletion within 30 minutes. At the 24-hour default their counts are within the spread of two `false` runs. Four-step subsequences that end in deletion are rare in ordinary traffic (0–3 each per 100 hours), so a detector keyed on four of the five steps comes close to the full-sequence detector. Only the complete ordered sequence by one owner and one collaborator within 30 minutes is absent from `anomaly_mode: false`: ordinary teardown postpones a deletion that would complete it. A detector with a window longer than 30 minutes therefore also finds complete sequences in ordinary traffic (0–3 per 100 hours between 30 and 45 minutes in the final captures).

Short intervals raise daily volumes. Each episode adds one sandbox write grant, one `write` → `admin` change, one protection removal and one deletion. At the 6-hour minimum (four episodes per day) the stress capture averaged 7.25 `write` → `admin` changes per day against 4.29 in `false` captures (+69%), 8.25 sandbox write grants against 5.62 (+47%), 9.75 deletions against 7.81 (+25%) and 10.5 protection removals against 9.79 (+7%). A detector counting these actions per day can therefore separate the modes at intervals near 6 hours, without the order; at 12 hours the `write` → `admin` uplift is roughly +30% (estimate), and at the 24-hour default no daily-count difference was measured.

`anomaly_mode: false` keeps the same identities, repositories, all twelve action classes and the same task mix, without episodes. A finite capture can end with an unprotected sandbox, a live collaborator grant, a deleted sandbox waiting for recreation, or the test identity still in the organization; the generator does not fabricate cleanup.

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

Keep names and numeric IDs distinct from the fixed identities `alice` (32100011), `bob` (32100012), `carol` (32100013), `dmitri` (32100014), `vendor-qa` (98234611), `contract-sre` (98234612) and `new-hire-test` (32100099). Keep `sensitive_repo` under the configured organization and different from the fixed repository names. Keep the shipped one-minute, count-one cron for the documented timing.

### Output Parameters

The shipped output writes `output/events.json` and needs no top-level params or secrets. Replace the output plugin to deliver elsewhere. A real collector needs authorized Enterprise Cloud organization audit access, for example a token with `read:audit_log`; no token is embedded here.

## Usage

From the content-packs repository root, live mode:

```bash
eventum generate --path generators/cloud-github-audit/generator.yml --id github --live-mode true
```

For a finite batch, copy `generator.yml` inside the generator directory, add `start` and `end` to its cron input (for example `2026-09-25T00:00:00Z` and `2026-09-29T04:20:00Z`), and run:

```bash
eventum generate --path generators/cloud-github-audit/<copy>.yml --id github --live-mode false --keep-order true
```

Batch mode alone does not end an open-ended schedule. `--keep-order true` keeps records in source order for stateful consumers.

## Validation

Finite 100h20 captures were generated from the final source and checked by a streaming verifier:
- native and ECS fields, collector clocks, and an independent repository, permission, protection, topic and membership state machine;
- recurrence, the start horizon and rotation;
- on/off comparisons of per-action, per-actor and per-hour counts, second-of-minute uniformity, minima and extremes of global, per-actor, per-repository and member-action gaps, of grant-to-correction, grant-to-removal, protection, recreation and deletion delays, and counts of chain step pairs and partial sequences;
- the hour of episode starts against ordinary administration, and per-day counts of chain actions in the stress capture against `false` captures.

The gates are calibrated on off-vs-off pairs of ten further `false` captures for a 5% false-alarm rate per verifier run. The custom runs change organization, identities, sandbox, collector and interval, with `+03:00` cron bounds normalized to UTC.

| Capture | Records | Complete sequences | Sandbox recreations |
|---|---:|---:|---:|
| `default_on` | 1,035 | 2 | 32 |
| `default_off` | 1,040 | 0 | 26 |
| `custom_on` | 1,138 | 5 | 40 |
| `custom_off` | 1,016 | 0 | 33 |
| `stress_on` | 1,141 | 12 | 39 |

State is bounded: six repositories with at most three collaborators each, six topics, one test-member flag, a step queue capped at 96 entries and a 30-minute memory of at most 16 records per sandbox.

## Limits

- Membership, protection and topic objects are reduced; their field combinations and the lowercase `read`/`write`/`admin` values are inferences from the catalog and role documentation, not live captures. No raw byte parity, live Elastic ingestion or GitHub document-ID allocation is claimed.
- `event.original` is serialized with sorted keys and spaces after separators.
- Rates, delays, the daily profile and the two-minute poll are synthetic choices. Waits for an eligible sandbox after the drawn start time are not capped.
- At intervals near 6 hours, daily counts of the chain actions rise (see above).
- The first episode appears only after one full interval, and a 24-hour interval needs a window of about 100 hours to guarantee two episodes.
- Detectors with windows longer than 30 minutes see complete sequences in ordinary traffic; four-of-five subsequences ending in deletion are rare in ordinary traffic (see above).

## Sample Output

The permission change of the first episode in the final `default_on` capture (row 469):

```json
{
  "@timestamp": "2026-09-26T19:47:09.886+00:00",
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
    "created": "2026-09-26T19:47:24.084+00:00",
    "dataset": "github.audit",
    "id": "Upnt3E9XQjazZSRd-M-n0A",
    "ingested": "2026-09-26T19:47:25+00:00",
    "kind": "event",
    "module": "github",
    "original": "{\"@timestamp\": 1790452029886, \"_document_id\": \"Upnt3E9XQjazZSRd-M-n0A\", \"action\": \"repo.update_member\", \"actor\": \"ops-admin\", \"actor_id\": 139876543, \"created_at\": 1790452029886, \"new_repo_permission\": \"admin\", \"old_repo_permission\": \"write\", \"org\": \"contoso-security\", \"org_id\": 71234567, \"public_repo\": false, \"repo\": \"contoso-security/payroll-service-drill\", \"repo_id\": 981726064, \"user\": \"vendor-qa\", \"user_id\": 98234611, \"visibility\": \"private\"}",
    "type": [
      "change"
    ]
  },
  "github": {
    "actor_id": "139876543",
    "category": "repo",
    "new_repo_permission": "admin",
    "old_repo_permission": "write",
    "org": "contoso-security",
    "org_id": "71234567",
    "public_repo": false,
    "repo": "contoso-security/payroll-service-drill",
    "repo_id": "981726064",
    "user_id": "98234611",
    "visibility": "private"
  },
  "input": {
    "type": "httpjson"
  },
  "related": {
    "user": [
      "ops-admin",
      "139876543",
      "vendor-qa",
      "98234611"
    ]
  },
  "tags": [
    "forwarded",
    "github-audit",
    "preserve_original_event"
  ],
  "user": {
    "id": "139876543",
    "name": "ops-admin",
    "target": {
      "id": "98234611",
      "name": "vendor-qa"
    }
  }
}
```

## References

- [GitHub Enterprise Cloud organization audit log events](https://docs.github.com/en/enterprise-cloud@latest/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/audit-log-events-for-your-organization) and [REST audit endpoint](https://docs.github.com/en/enterprise-cloud@latest/rest/orgs/orgs#get-the-audit-log-for-an-organization).
- [Repository deletion permissions](https://docs.github.com/en/repositories/creating-and-managing-repositories/deleting-a-repository), [branch protection rules](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/managing-a-branch-protection-rule), [repository creation](https://docs.github.com/en/rest/repos/repos#create-an-organization-repository) and [archive downloads](https://docs.github.com/en/repositories/working-with-files/using-files/downloading-source-code-archives).
- [Elastic GitHub integration](https://www.elastic.co/docs/reference/integrations/github), [pinned sample](https://github.com/elastic/integrations/blob/4e7455b3bdfdea9a51b9b8cfe4141eeb43ae07cc/packages/github/data_stream/audit/sample_event.json), [pipeline](https://github.com/elastic/integrations/blob/4e7455b3bdfdea9a51b9b8cfe4141eeb43ae07cc/packages/github/data_stream/audit/elasticsearch/ingest_pipeline/default.yml), [httpjson stream](https://github.com/elastic/integrations/blob/4e7455b3bdfdea9a51b9b8cfe4141eeb43ae07cc/packages/github/data_stream/audit/agent/stream/httpjson.yml.hbs), [data stream manifest](https://github.com/elastic/integrations/blob/4e7455b3bdfdea9a51b9b8cfe4141eeb43ae07cc/packages/github/data_stream/audit/manifest.yml) and [native fixtures](https://github.com/elastic/integrations/blob/4e7455b3bdfdea9a51b9b8cfe4141eeb43ae07cc/packages/github/data_stream/audit/_dev/test/pipeline/test-organisation-audit-json.log).

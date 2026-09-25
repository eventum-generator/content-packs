# GitHub Organization Audit Generator

Generates GitHub organization audit events as ECS-compatible JSON. `event.original` contains the native audit API object, including its action, actor, organization, repository, and document ID.

## Event Types Covered

| Action | Share in a 2,500-event validation run | Category |
|---|---:|---|
| `repo.add_topic` | 60.3% | configuration |
| `repo.download_zip` | 19.0% | access |
| `repo.create` | 15.1% | configuration |
| `org.add_member` | 4.6% | iam |
| `repo.add_member`, `repo.update_member`, `protected_branch.destroy`, `repo.destroy` | 0.2% each | iam, configuration |

The generator uses `mode: fsm`. Routine actions are weighted; each anomaly step follows the previous one. Percentages describe this configured test workload, not published GitHub production frequencies.

## Anomaly Chain

Set `event.template.params.anomaly_mode` to `false` to emit only background activity. The default `true` includes this chain among routine events.

After 400 routine events, `ops-admin` adds `external-collab` to a sensitive repository, raises the collaborator's permission from write to admin, removes protection from `main`, downloads a ZIP archive, and deletes the repository. All five records share the actor and repository. Each cycle uses a new repository name derived from `sensitive_repo`, so deletion does not leave later events referring to the deleted repository. The ordinary organization audit stream continues between chains.

Rules can separately flag external collaboration, privilege escalation, protection removal, archive download, repository deletion, or the full sequence. The generator adds no anomaly label to the events. State consists of scalar counters and the current repository name; no collection grows with runtime.

## Reference Field Map

| Field group | Source | Generation strategy |
|---|---|---|
| Native audit object | GitHub audit event catalog and REST API example | Emit documented action names and their relevant actor, user, repository and permission fields |
| `event.*`, `github.*`, `user.*`, `related.*` | Elastic `github.audit` sample | Normalize action, actor and repository while preserving the API object in `event.original` |
| Collector metadata | Elastic sample | Stable synthetic collector identity |

Generated events cover all **32/32** leaf fields in the Elastic `github.audit` sample. The integration sample shows `repo.destroy`; other native actions are based on GitHub's event catalog. This generator models audit records, not API authentication, pagination, or polling behavior.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Name | Default | Purpose |
|---|---|---|
| `anomaly_mode` | `true` | Emit the correlated anomaly chain alongside routine events; `false` emits only background |
| `org` | `contoso-security` | Organization name |
| `org_id` | `71234567` | Stable organization ID |
| `sensitive_repo` | `contoso-security/payroll-service` | Prefix for anomaly repositories |
| `sensitive_repo_id` | `981234567` | Base ID for anomaly repositories |
| `suspicious_actor` | `ops-admin` | Actor across the anomaly |
| `suspicious_actor_id` | `139876543` | Stable actor ID |
| `external_user` | `external-collab` | New collaborator |
| `external_user_id` | `98234567` | Collaborator ID |
| `collector_id` | `5630df5f-562b-4c5a-bcc1-b151fbca02c4` | Stable collector ID |
| `collector_ephemeral_id` | `df3107a1-9f4a-4336-ae3a-ecad098902d4` | Collector process ID |
| `collector_version` | `9.4.4` | Collector version |

### Output Parameters

The default output is the local `output/events.json` file and needs no output overrides. To index events, replace the file output with OpenSearch and use `${params.opensearch_host}` for the host plus keyring-backed `${secrets.opensearch_password}` for credentials. See the [OpenSearch output guide](https://eventum.run/docs/tutorials/delivery/opensearch).

## Usage

```bash
# Bounded batch run; --live-mode false generates as fast as possible.
timeout 3 eventum generate --path generators/cloud-github-audit/generator.yml --id github --live-mode false

# Continuous 5 events/second run.
eventum generate --path generators/cloud-github-audit/generator.yml --id github --live-mode true
```

## Sample Output

This complete branch-protection event was produced by the generator:

```json
{
  "@timestamp": "2026-09-25T10:31:27+00:00",
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
    "version": "8.17.0"
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
    "created": "2026-09-25T10:31:27+00:00",
    "dataset": "github.audit",
    "id": "WrFJXUIxpQnXXAFAOQdK",
    "ingested": "2026-09-25T10:31:27+00:00",
    "kind": "event",
    "module": "github",
    "original": "{\"@timestamp\": 1790332287000, \"_document_id\": \"WrFJXUIxpQnXXAFAOQdK\", \"action\": \"protected_branch.destroy\", \"actor\": \"ops-admin\", \"actor_id\": 139876543, \"admin_enforced\": true, \"created_at\": 1790332287000, \"name\": \"main\", \"org\": \"contoso-security\", \"org_id\": 71234567, \"repo\": \"contoso-security/payroll-service-1\", \"repo_id\": 981234568, \"visibility\": \"private\"}",
    "type": [
      "change"
    ]
  },
  "github": {
    "category": "protected_branch",
    "org": "contoso-security",
    "repo": "contoso-security/payroll-service-1",
    "visibility": "private"
  },
  "input": {
    "type": "httpjson"
  },
  "related": {
    "user": [
      "ops-admin"
    ]
  },
  "tags": [
    "forwarded",
    "github-audit",
    "preserve_original_event"
  ],
  "user": {
    "name": "ops-admin"
  }
}
```

## References

- [GitHub organization audit event catalog](https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/audit-log-events-for-your-organization)
- [GitHub audit log REST API example](https://docs.github.com/en/enterprise-cloud@latest/rest/enterprise-admin/audit-log)
- [Elastic GitHub audit integration](https://github.com/elastic/integrations/tree/main/packages/github/data_stream/audit)

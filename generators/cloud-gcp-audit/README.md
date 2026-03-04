# GCP Cloud Audit Logs

Generates realistic GCP Cloud Audit Log events matching the [Elastic GCP Audit integration](https://www.elastic.co/docs/reference/integrations/gcp/audit) field structure. Simulates the audit log stream from a multi-project GCP organization with IAM users, service accounts, and GCP service-originated operations.

GCP Cloud Audit Logs record API calls and actions within Google Cloud projects, providing an audit trail of who performed what action, on which resource, when, and from where. Admin Activity logs capture control plane changes (creating/deleting resources, modifying IAM policies), while Data Access logs capture reads and metadata queries.

## Event Types

| Event Action | Service | Read/Write | Description | Weight | ECS Category |
|---|---|---|---|---|---|
| `v1.compute.instances.list` | Compute | Read | List instances in a zone | 60 | `host` |
| `v1.compute.instances.get` | Compute | Read | Get instance details | 40 | `host` |
| `v1.compute.instances.aggregatedList` | Compute | Read | List instances across zones | 30 | `host` |
| `v1.compute.instances.insert` | Compute | Write | Create a new VM instance | 25 | `host` |
| `v1.compute.instances.stop` | Compute | Write | Stop a running instance | 15 | `host` |
| `v1.compute.instances.start` | Compute | Write | Start a stopped instance | 15 | `host` |
| `v1.compute.instances.delete` | Compute | Write | Delete a VM instance | 10 | `host` |
| `GetIamPolicy` | IAM | Read | Get project IAM policy | 50 | `iam` |
| `google.login.LoginService.loginSuccess` | Login | Write | Console login | 40 | `authentication` |
| `SetIamPolicy` | IAM | Write | Modify project IAM policy | 30 | `iam` |
| `google.iam.admin.v1.CreateServiceAccount` | IAM | Write | Create a service account | 10 | `iam` |
| `google.iam.admin.v1.CreateServiceAccountKey` | IAM | Write | Create SA key | 5 | `iam` |
| `storage.objects.get` | Storage | Read | Get a GCS object | 45 | `file` |
| `storage.objects.list` | Storage | Read | List objects in a bucket | 30 | `file` |
| `storage.buckets.create` | Storage | Write | Create a GCS bucket | 5 | `file` |
| `google.container.v1.ClusterManager.GetCluster` | GKE | Read | Get GKE cluster details | 40 | `configuration` |
| `google.container.v1.ClusterManager.CreateCluster` | GKE | Write | Create a GKE cluster | 5 | `configuration` |
| `google.cloud.bigquery.v2.JobService.InsertJob` | BigQuery | Read | Run BQ query/load/extract | 30 | `database` |
| `google.cloud.bigquery.v2.TableService.InsertTable` | BigQuery | Write | Create a BQ table | 5 | `database` |
| `v1.compute.firewalls.insert` | Compute | Write | Create a firewall rule | 15 | `network` |
| `v1.compute.subnetworks.insert` | Compute | Write | Create a subnetwork | 8 | `network` |
| `v1.compute.networks.insert` | Compute | Write | Create a VPC network | 5 | `network` |

## Realism Features

- **Jinja2 macros** (`_base.json.jinja`) eliminate boilerplate across 22 templates
- **3 caller identity types** — Service Account (55%), User (40%), GCP Service (5%) with realistic email formats
- **Error injection** (~4%) — 20 realistic error scenarios (permission denied, quota exceeded, resource not found, etc.) mapped to specific API methods
- **Console login flow** — Google login events with ~5% failure rate
- **Multi-project environment** — 3 GCP projects (production, staging, development)
- **10 IAM users** across 7 departments with unique @acme.io emails
- **10 service accounts** with realistic naming (deploy-sa, gke-node-sa, dataflow-sa, etc.)
- **15 Compute instances** with realistic names, machine types, and availability zones
- **3 GKE clusters** (prod, staging, dev) with location-aware operations
- **5 BigQuery datasets** with realistic job types (QUERY, LOAD, EXTRACT, COPY)
- **6 GCS buckets** with realistic naming and storage classes
- **User agent diversity** — gcloud CLI, Python/Go/Java SDKs, Terraform, Console browsers, GCP services
- **ECS-compatible output** — ready for Elasticsearch/OpenSearch ingestion via the Elastic GCP integration

## Parameters

| Parameter | Default | Description |
|---|---|---|
| `agent_id` | `b2c3d4e5-...` | Filebeat agent UUID |
| `agent_version` | `8.17.0` | Elastic Agent version |
| `error_rate` | `4` | Error injection rate (percentage, 0-100) |

## Output Parameters

For production deployment with OpenSearch/Elasticsearch:

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
| `${params.opensearch_host}` | OpenSearch/Elasticsearch host URL |
| `${params.opensearch_user}` | Username for authentication |
| `${secrets.opensearch_password}` | Password (from Eventum keyring) |
| `${params.opensearch_index}` | Target index name |

## Usage

```bash
# Live mode (5 events/second)
eventum generate \
  --path generators/cloud-gcp-audit/generator.yml \
  --id gcp-audit \
  --live-mode

# Batch mode (generate as fast as possible)
eventum generate \
  --path generators/cloud-gcp-audit/generator.yml \
  --id gcp-audit \
  --live-mode false
```

### startup.yml example

```yaml
generators:
  gcp-audit:
    path: generators/cloud-gcp-audit/generator.yml
    params:
      error_rate: 2
```

## Sample Output

```json
{
  "@timestamp": "2026-03-04T14:22:31+00:00",
  "agent": {
    "ephemeral_id": "c3d4e5f6-a7b8-9012-cdef-123456789abc",
    "id": "b2c3d4e5-f6a7-8901-bcde-f12345678901",
    "name": "gcp-audit-forwarder",
    "type": "filebeat",
    "version": "8.17.0"
  },
  "client": {
    "user": {
      "email": "michael.chen@acme.io"
    }
  },
  "cloud": {
    "availability_zone": "us-central1-a",
    "project": {
      "id": "acme-prod-001",
      "name": "Acme Production"
    },
    "provider": "gcp",
    "region": "us-central1"
  },
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "v1.compute.instances.insert",
    "category": ["host", "configuration"],
    "dataset": "gcp.audit",
    "id": "a1b2c3d4e5f67890",
    "kind": "event",
    "module": "gcp",
    "outcome": "success",
    "provider": "activity",
    "type": ["creation", "allowed"]
  },
  "gcp": {
    "audit": {
      "authorization_info": [
        {
          "granted": true,
          "permission": "compute.instances.create",
          "resource_attributes": {
            "name": "projects/acme-prod-001/zones/us-central1-a/instances/web-server-a1b2",
            "service": "compute",
            "type": "compute.instances"
          }
        }
      ],
      "receive_timestamp": "2026-03-04T14:22:31+00:00",
      "request": {
        "@type": "type.googleapis.com/compute.instances.insert",
        "name": "web-server-a1b2",
        "machineType": "projects/acme-prod-001/zones/us-central1-a/machineTypes/e2-medium"
      },
      "resource": {
        "type": "gce_instance"
      },
      "resource_location": {
        "current_locations": ["us-central1-a"]
      },
      "resource_name": "projects/acme-prod-001/zones/us-central1-a/instances/web-server-a1b2",
      "response": {
        "@type": "type.googleapis.com/operation",
        "operationType": "insert",
        "status": "RUNNING"
      },
      "type": "type.googleapis.com/google.cloud.audit.AuditLog"
    }
  },
  "log": {
    "level": "NOTICE",
    "logger": "projects/acme-prod-001/logs/cloudaudit.googleapis.com%2Factivity"
  },
  "related": {
    "ip": ["198.51.100.25"],
    "user": ["michael.chen@acme.io"]
  },
  "service": {
    "name": "compute.googleapis.com"
  },
  "source": {
    "ip": "198.51.100.25"
  },
  "tags": ["forwarded", "gcp-audit"],
  "user_agent": {
    "original": "google-cloud-sdk gcloud/467.0.0 command/gcloud.compute.instances.list invocation-id/abcdef123456 environment/None environment-version/None interactive/True from-script/False python/3.11.8 term/xterm-256color (Macintosh; Intel Mac OS X 14.3.1)"
  }
}
```

## File Structure

```
generators/cloud-gcp-audit/
  generator.yml                                    # Pipeline config
  README.md                                        # This file
  templates/
    _base.json.jinja                               # Shared macros (agent, ecs, cloud, identity, errors)
    compute-instances-list.json.jinja              # Compute DescribeInstances
    compute-instances-get.json.jinja               # Compute GetInstance (data_access)
    compute-instances-aggregated-list.json.jinja   # Compute AggregatedList (data_access)
    compute-instances-insert.json.jinja            # Compute CreateInstance
    compute-instances-delete.json.jinja            # Compute DeleteInstance
    compute-instances-stop.json.jinja              # Compute StopInstance
    compute-instances-start.json.jinja             # Compute StartInstance
    compute-firewalls-insert.json.jinja            # Compute CreateFirewall
    compute-networks-insert.json.jinja             # Compute CreateNetwork
    compute-subnetworks-insert.json.jinja          # Compute CreateSubnetwork
    iam-set-iam-policy.json.jinja                  # IAM SetIamPolicy
    iam-get-iam-policy.json.jinja                  # IAM GetIamPolicy (data_access)
    iam-create-service-account.json.jinja          # IAM CreateServiceAccount
    iam-create-service-account-key.json.jinja      # IAM CreateServiceAccountKey
    console-login.json.jinja                       # Console login
    storage-objects-get.json.jinja                 # Storage GetObject (data_access)
    storage-objects-list.json.jinja                # Storage ListObjects (data_access)
    storage-buckets-create.json.jinja              # Storage CreateBucket
    gke-clusters-get.json.jinja                    # GKE GetCluster (data_access)
    gke-clusters-create.json.jinja                 # GKE CreateCluster
    bigquery-insert-job.json.jinja                 # BigQuery InsertJob (data_access)
    bigquery-insert-table.json.jinja               # BigQuery InsertTable
  samples/
    projects.csv                                   # 3 GCP projects (prod, staging, dev)
    users.csv                                      # 10 IAM users across 7 departments
    service_accounts.csv                           # 10 service accounts
    source_ips.csv                                 # 15 source IPs (corporate, VPN, CI/CD)
    zones.csv                                      # 8 availability zones across 5 regions
    instances.csv                                  # 15 Compute Engine instances
    buckets.csv                                    # 6 GCS buckets
    gke_clusters.csv                               # 3 GKE clusters
    networks.csv                                   # 4 VPC networks/subnets
    datasets.csv                                   # 5 BigQuery datasets
    user_agents.json                               # 15 user agents (gcloud, SDK, Terraform, console)
    error_scenarios.json                           # 20 error scenarios per API method
  output/
    events.json                                    # Generated events (overwritten each run)
```

## References

- [GCP Cloud Audit Logs Overview](https://docs.cloud.google.com/logging/docs/audit)
- [AuditLog Schema Reference](https://docs.cloud.google.com/logging/docs/reference/audit/auditlog/rest/Shared.Types/AuditLog)
- [Elastic GCP Audit Integration](https://www.elastic.co/docs/reference/integrations/gcp/audit)
- [Elastic Integrations — gcp](https://github.com/elastic/integrations/tree/main/packages/gcp)
- [GCP Compute Engine API Reference](https://cloud.google.com/compute/docs/reference/rest/v1)
- [GCP IAM API Reference](https://cloud.google.com/iam/docs/reference/rest)
- [GCP Cloud Storage JSON API Reference](https://cloud.google.com/storage/docs/json_api/v1)
- [GCP GKE API Reference](https://cloud.google.com/kubernetes-engine/docs/reference/rest)
- [GCP BigQuery API Reference](https://cloud.google.com/bigquery/docs/reference/rest)

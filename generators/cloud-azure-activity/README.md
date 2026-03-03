# Azure Activity Log Events

Generates realistic Azure Activity Log events matching the [Elastic Azure activitylogs integration](https://docs.elastic.co/integrations/azure/activitylogs) field structure. Simulates the Azure Monitor activity log stream from a multi-subscription Azure environment covering all 7 activity log categories.

Azure Activity Log provides insight into subscription-level events in Azure. It records who did what, when, and from where for operations on Azure resources. Events span resource management operations, service health incidents, autoscale actions, policy evaluations, and security alerts.

## Event Types

| Template | Category | Description | Weight | ECS Category |
|---|---|---|---|---|
| `admin-write.json.jinja` | Administrative | Create/update resources (VM, Storage, NSG, etc.) | 400 (~40%) | `configuration` |
| `admin-action.json.jinja` | Administrative | Actions (start/stop/restart VM, regenerate keys) | 250 (~25%) | `configuration` |
| `admin-delete.json.jinja` | Administrative | Delete resources | 50 (~5%) | `configuration` |
| `policy-compliance.json.jinja` | Policy | Azure Policy evaluation results (Audit, Deny, etc.) | 120 (~12%) | `configuration` |
| `security-alert.json.jinja` | Security | Microsoft Defender for Cloud alerts | 50 (~5%) | `threat` |
| `service-health.json.jinja` | ServiceHealth | Service incidents, maintenance, advisories | 50 (~5%) | `configuration` |
| `autoscale.json.jinja` | Autoscale | Autoscale scale-up/scale-down actions | 30 (~3%) | `configuration` |
| `resource-health.json.jinja` | ResourceHealth | Resource availability status changes | 30 (~3%) | `host` |
| `alert.json.jinja` | Alert | Azure Monitor metric/log alert activations | 20 (~2%) | `configuration` |

## Realism Features

- **Jinja2 macros** (`_base.json.jinja`) eliminate boilerplate across 9 templates
- **All 7 activity log categories** with production-accurate distribution weights
- **Weighted operation distributions** -- Administrative events use realistic operation weights matching real Azure environments
- **Error injection** (~5%) -- Administrative operations produce failures (403 Forbidden, 409 Conflict, 400 BadRequest, 404 NotFound) with appropriate HTTP status codes
- **Azure resource ID format** -- proper `/subscriptions/{sub}/resourceGroups/{rg}/providers/{provider}/{type}/{name}` structure
- **Identity with claims** -- Azure AD identity block with JWT claims, UPN, object ID, tenant ID, and authorization scope
- **Policy evaluation** -- compliance checks vs new resource deployments with policy definition IDs, effects (Audit/Deny/AuditIfNotExists/DeployIfNotExists), and assignment details
- **Service health realism** -- 5 incident types (Incident, Maintenance, Informational, ActionRequired, Security) affecting 12 Azure services
- **Autoscale events** -- scale-up/scale-down with instance count tracking and target resource references
- **Resource health transitions** -- Available/Unavailable/Degraded states with PlatformInitiated/UserInitiated causes
- **Alert rules** -- 6 metric types (CPU, Memory, HTTP Errors, DTU, Network, Disk) with thresholds and aggregation windows
- **Multi-subscription environment** -- 3 Azure subscriptions (production, staging, development)
- **12 Azure AD users** across 8 departments including service accounts
- **12 resource groups** with realistic naming conventions
- **User agent diversity** -- Azure Portal, Azure CLI, PowerShell, Python/Go SDKs, and internal Azure service agents
- **ECS-compatible output** -- ready for Elasticsearch/OpenSearch ingestion via the Elastic Azure integration

## Parameters

| Parameter | Default | Description |
|---|---|---|
| `agent_id` | `f1a2b3c4-...` | Filebeat agent UUID |
| `agent_version` | `8.17.0` | Elastic Agent version |
| `tenant_id` | `aaaabbbb-0000-cccc-1111-dddd2222eeee` | Azure AD tenant ID |
| `error_rate` | `5` | Error injection rate for Administrative events (percentage, 0-100) |

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
  --path generators/cloud-azure-activity/generator.yml \
  --id azure-activity \
  --live-mode

# Batch mode (generate as fast as possible)
eventum generate \
  --path generators/cloud-azure-activity/generator.yml \
  --id azure-activity \
  --live-mode false
```

### startup.yml example

```yaml
generators:
  azure-activity:
    path: generators/cloud-azure-activity/generator.yml
    params:
      error_rate: 3
      tenant_id: "your-tenant-id-here"
```

## Sample Output

```json
{
  "@timestamp": "2026-03-04T14:22:31+00:00",
  "agent": {
    "ephemeral_id": "b3f8a1c2-d4e5-6789-abcd-ef0123456789",
    "id": "f1a2b3c4-d5e6-7890-abcd-ef1234567890",
    "name": "azure-activity-forwarder",
    "type": "filebeat",
    "version": "8.17.0"
  },
  "cloud": {
    "account": {
      "id": "a1b2c3d4-e5f6-7890-abcd-100000000001",
      "name": "contoso-production"
    },
    "provider": "azure",
    "region": "eastus"
  },
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "Microsoft.Compute/virtualMachines/write",
    "category": ["configuration"],
    "dataset": "azure.activitylogs",
    "kind": "event",
    "module": "azure",
    "outcome": "success",
    "type": ["creation", "change"]
  },
  "source": {
    "ip": "198.51.100.25"
  },
  "user": {
    "id": "f409edeb-4d29-44b5-9763-ee9348ad91bb",
    "name": "john.smith@contoso.com",
    "email": "john.smith@contoso.com"
  },
  "user_agent": {
    "original": "AZURECLI/2.56.0 azsdk-python-azure-mgmt-resource/23.1.0b2 Python/3.11.7 (Linux-6.1.0-amd64)"
  },
  "related": {
    "ip": ["198.51.100.25"],
    "user": ["john.smith@contoso.com"]
  },
  "azure": {
    "activitylogs": {
      "category": "Administrative",
      "event_category": "Administrative",
      "identity": {
        "claims_initiated_by_user": {
          "name": "John Smith",
          "givenname": "John",
          "surname": "Smith",
          "fullname": "John Smith",
          "schema": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims"
        },
        "claims": {
          "aud": "https://management.azure.com/",
          "iss": "https://sts.windows.net/aaaabbbb-0000-cccc-1111-dddd2222eeee/",
          "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn": "john.smith@contoso.com",
          "http://schemas.microsoft.com/identity/claims/objectidentifier": "f409edeb-4d29-44b5-9763-ee9348ad91bb",
          "http://schemas.microsoft.com/identity/claims/tenantid": "aaaabbbb-0000-cccc-1111-dddd2222eeee"
        },
        "authorization": {
          "scope": "",
          "action": ""
        }
      },
      "level": "Informational",
      "operation_name": "Microsoft.Compute/virtualMachines/write",
      "result_type": "Success",
      "result_signature": "Succeeded.",
      "properties": {
        "statusCode": "201",
        "serviceRequestId": "c7d8e9f0-a1b2-3456-cdef-789012345678",
        "statusMessage": "Succeeded."
      },
      "status": {
        "value": "Succeeded"
      },
      "sub_status": {
        "value": "Created"
      },
      "correlation_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "resource_id": "/subscriptions/a1b2c3d4-e5f6-7890-abcd-100000000001/resourceGroups/rg-web-prod/providers/Microsoft.Compute/virtualMachines/vm-web-042",
      "tenant_id": "aaaabbbb-0000-cccc-1111-dddd2222eeee",
      "subscription_id": "a1b2c3d4-e5f6-7890-abcd-100000000001"
    }
  }
}
```

## File Structure

```
generators/cloud-azure-activity/
  generator.yml                                  # Pipeline config
  README.md                                      # This file
  templates/
    _base.json.jinja                             # Shared macros (agent, ecs, cloud, identity, status)
    admin-write.json.jinja                       # Administrative: create/update resources
    admin-delete.json.jinja                      # Administrative: delete resources
    admin-action.json.jinja                      # Administrative: resource actions (start/stop/etc.)
    policy-compliance.json.jinja                 # Policy: Azure Policy evaluations
    security-alert.json.jinja                    # Security: Defender for Cloud alerts
    service-health.json.jinja                    # ServiceHealth: incidents and maintenance
    autoscale.json.jinja                         # Autoscale: scale-up/scale-down actions
    resource-health.json.jinja                   # ResourceHealth: resource availability changes
    alert.json.jinja                             # Alert: metric/log alert activations
  samples/
    subscriptions.csv                            # 3 Azure subscriptions (prod, staging, dev)
    resource_groups.csv                          # 12 resource groups
    users.csv                                    # 12 Azure AD users across 8 departments
    regions.csv                                  # 8 Azure regions
    source_ips.csv                               # 15 source IPs (corporate, VPN, automation, remote)
    operations.json                              # Operations, alerts, policies, and user agents
  output/
    events.json                                  # Generated events (overwritten each run)
```

## References

- [Azure Activity Log Overview](https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log)
- [Azure Activity Log Event Schema](https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log-schema)
- [Azure Activity Log Categories](https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log-schema#categories)
- [Elastic Azure Integration](https://docs.elastic.co/integrations/azure)
- [Elastic Integrations -- azure](https://github.com/elastic/integrations/tree/main/packages/azure)
- [Azure Resource Providers and Types](https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/resource-providers-and-types)
- [Azure Policy Overview](https://learn.microsoft.com/en-us/azure/governance/policy/overview)
- [Microsoft Defender for Cloud Alerts](https://learn.microsoft.com/en-us/azure/defender-for-cloud/alerts-overview)

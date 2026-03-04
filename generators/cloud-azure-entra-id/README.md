# Azure Entra ID (Azure AD) Sign-In and Audit Logs

Generates realistic Microsoft Entra ID events matching the [Elastic Azure integration](https://docs.elastic.co/integrations/azure/adlogs) field structure for `signinlogs` and `auditlogs` data streams. Simulates the authentication and directory change event stream from a multi-tenant enterprise Azure AD environment.

Microsoft Entra ID (formerly Azure Active Directory) is the cloud-based identity and access management service for Azure. Sign-in logs capture every authentication attempt (interactive, non-interactive, and service principal), while audit logs record directory changes such as user/group management, role assignments, and policy updates.

## Event Types

| Template | Category | Description | Weight | ECS Category |
|---|---|---|---|---|
| `signin-interactive-success.json.jinja` | SignInLogs | Interactive user sign-ins (browser, desktop apps) | 300 (~30%) | `authentication` |
| `signin-interactive-failure.json.jinja` | SignInLogs | Failed interactive sign-ins (AADSTS errors) | 100 (~10%) | `authentication` |
| `signin-noninteractive-success.json.jinja` | NonInteractiveUserSignInLogs | Token refresh, SSO, background auth | 250 (~25%) | `authentication` |
| `signin-noninteractive-failure.json.jinja` | NonInteractiveUserSignInLogs | Expired tokens, revoked sessions | 50 (~5%) | `authentication` |
| `signin-service-principal.json.jinja` | ServicePrincipalSignInLogs | App/service principal authentication | 150 (~15%) | `authentication` |
| `audit-directory-change.json.jinja` | AuditLogs | Directory changes (user/group/role/app mgmt) | 150 (~15%) | `iam` / `configuration` |

## Realism Features

- **Jinja2 macros** (`_base.json.jinja`) eliminate boilerplate across 6 templates
- **14 AADSTS error codes** — realistic failure distribution including `50126` (bad password), `50053` (locked), `530032` (CA block), `500121` (MFA required), `50140` (KMSI interrupt)
- **Conditional Access policies** — 7 policies with enforced/reportOnly modes, grant controls (MFA), and per-sign-in evaluation results
- **MFA and authentication methods** — Password, FIDO2, Windows Hello, Microsoft Authenticator (push + passwordless)
- **Service principal sign-ins** — client secrets, certificates, and federated identity credentials with SP-specific error codes
- **21 audit operations** across 6 categories — UserManagement, GroupManagement, ApplicationManagement, RoleManagement, Policy, DeviceManagement
- **Risk assessment** — aggregated and per-sign-in risk levels (none/low/medium/high) correlated with sign-in outcome
- **Device details** — OS, browser, trust type (Hybrid AAD joined, AAD joined, registered) per user agent type
- **Geo-location** — 8 global office locations with city/state/country and lat/long coordinates
- **Session tracking** — active sessions stored in shared state for correlation
- **18 users** across 9 departments including 2 admins and 2 service accounts
- **10 target applications** with weighted selection matching real M365 traffic patterns
- **6 service principals** for app-to-app authentication scenarios
- **ECS-compatible output** — ready for Elasticsearch/OpenSearch ingestion via the Elastic Azure integration

## Parameters

| Parameter | Default | Description |
|---|---|---|
| `agent_id` | `e3f4a5b6-...` | Filebeat agent UUID |
| `agent_version` | `8.17.0` | Elastic Agent version |
| `tenant_id` | `aaaabbbb-0000-cccc-1111-dddd2222eeee` | Azure AD / Entra ID tenant ID |

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
  --path generators/cloud-azure-entra-id/generator.yml \
  --id entra-id \
  --live-mode

# Batch mode (generate as fast as possible)
eventum generate \
  --path generators/cloud-azure-entra-id/generator.yml \
  --id entra-id \
  --live-mode false
```

### startup.yml example

```yaml
generators:
  entra-id:
    path: generators/cloud-azure-entra-id/generator.yml
    params:
      tenant_id: "your-tenant-id-here"
```

## Sample Output

```json
{
    "@timestamp": "2026-03-04T10:15:22+00:00",
    "agent": {
        "ephemeral_id": "b3f8a1c2-d4e5-6789-abcd-ef0123456789",
        "id": "e3f4a5b6-c7d8-9012-ef01-234567890abc",
        "name": "azure-entra-forwarder",
        "type": "filebeat",
        "version": "8.17.0"
    },
    "cloud": {
        "provider": "azure",
        "account": {
            "id": "aaaabbbb-0000-cccc-1111-dddd2222eeee"
        }
    },
    "ecs": {
        "version": "8.17.0"
    },
    "event": {
        "action": "UserLoggedIn",
        "category": ["authentication"],
        "dataset": "azure.signinlogs",
        "id": "f1e2d3c4-b5a6-7890-cdef-123456789abc",
        "kind": "event",
        "module": "azure",
        "outcome": "success",
        "type": ["start", "allowed"]
    },
    "source": {
        "ip": "198.51.100.25"
    },
    "user": {
        "domain": "contoso.com",
        "email": "sarah.jones@contoso.com",
        "full_name": "Sarah Jones",
        "id": "a1b2c3d4-0002-4000-8000-000000000002",
        "name": "sarah.jones"
    },
    "user_agent": {
        "original": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
    },
    "related": {
        "ip": ["198.51.100.25"],
        "user": ["sarah.jones", "sarah.jones@contoso.com"]
    },
    "azure": {
        "signinlogs": {
            "category": "SignInLogs",
            "operation_name": "Sign-in activity",
            "result_type": "0",
            "result_description": "",
            "properties": {
                "app_display_name": "Microsoft Graph",
                "app_id": "00000003-0000-0000-c000-000000000000",
                "client_app_used": "Browser",
                "conditional_access_status": "success",
                "is_interactive": true,
                "risk_level_aggregated": "none",
                "status": {
                    "error_code": 0,
                    "failure_reason": ""
                },
                "location": {
                    "city": "San Francisco",
                    "state": "California",
                    "country_or_region": "US"
                },
                "device_detail": {
                    "browser": "Chrome 122.0.0",
                    "operating_system": "Windows 10",
                    "trust_type": "Hybrid Azure AD joined"
                },
                "authentication_details": [
                    {
                        "authentication_method": "Microsoft Authenticator (push notification)",
                        "succeeded": true
                    }
                ]
            }
        }
    }
}
```

## File Structure

```
generators/cloud-azure-entra-id/
  generator.yml                                    # Pipeline config
  README.md                                        # This file
  templates/
    _base.json.jinja                               # Shared macros (agent, ecs, cloud, device, CA, risk)
    signin-interactive-success.json.jinja          # Interactive sign-in — success
    signin-interactive-failure.json.jinja          # Interactive sign-in — failure (AADSTS errors)
    signin-noninteractive-success.json.jinja       # Non-interactive sign-in — success (token refresh)
    signin-noninteractive-failure.json.jinja       # Non-interactive sign-in — failure
    signin-service-principal.json.jinja            # Service principal sign-in (client credentials)
    audit-directory-change.json.jinja              # Audit: directory changes (user/group/role/app)
  samples/
    users.csv                                      # 18 users across 9 departments
    source_ips.csv                                 # 15 source IPs (corporate, VPN, mobile, remote)
    locations.json                                 # 8 global office locations
    applications.json                              # 10 Microsoft/custom applications
    service_principals.json                        # 6 service principals
    user_agents.json                               # 15 user agents (browsers, Outlook, Teams, SDKs)
    conditional_access_policies.json               # 7 CA policies (enforced + report-only)
    audit_operations.json                          # 21 audit operations across 6 categories
    groups.json                                    # 8 Azure AD groups
    directory_roles.json                           # 8 directory roles
  output/
    events.json                                    # Generated events (overwritten each run)
```

## References

- [Microsoft Entra ID Sign-In Logs](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-ins)
- [Microsoft Entra ID Audit Logs](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-audit-logs)
- [Microsoft Entra Activity Log Schemas](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-activity-log-schemas)
- [Azure AD Error Codes (AADSTS)](https://learn.microsoft.com/en-us/entra/identity-platform/reference-error-codes)
- [Elastic Azure Integration — Entra ID Logs](https://docs.elastic.co/integrations/azure/adlogs)
- [Elastic Integrations — azure](https://github.com/elastic/integrations/tree/main/packages/azure)
- [Conditional Access in Microsoft Entra ID](https://learn.microsoft.com/en-us/entra/identity/conditional-access/overview)

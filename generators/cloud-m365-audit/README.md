# Microsoft 365 Unified Audit Log

Generates realistic Microsoft 365 Unified Audit Log events matching the [Elastic O365 integration](https://docs.elastic.co/integrations/o365) field structure. Simulates the audit event stream from an enterprise M365 tenant covering Azure AD / Entra ID, Exchange Online, SharePoint / OneDrive, Microsoft Teams, and admin operations.

The Microsoft 365 Unified Audit Log provides a single source of truth for user and admin activity across all M365 services. Events are captured via the Office 365 Management Activity API and include authentication, file operations, email access, Teams collaboration, and administrative changes.

## Event Types

| Operation | Workload | Record Type | Description | Weight | ECS Category |
|---|---|---|---|---|---|
| `UserLoggedIn` | AzureActiveDirectory | 15 | Successful user sign-in | 200 | `authentication` |
| `UserLoginFailed` | AzureActiveDirectory | 15 | Failed user sign-in | 50 | `authentication` |
| `Change user password.` | AzureActiveDirectory | 8 | Password change | 20 | `iam` |
| `Add member to group.` | AzureActiveDirectory | 8 | Add user to group/role | 30 | `iam` |
| `MailItemsAccessed` | Exchange | 2 | Email message accessed | 150 | `email` |
| `Send` | Exchange | 2 | Email message sent | 80 | `email` |
| `MailboxLogin` | Exchange | 2 | Mailbox sign-in | 20 | `authentication` |
| `FileAccessed` | SharePoint | 6 | File opened/viewed | 150 | `file` |
| `FileModified` | SharePoint | 6 | File content changed | 50 | `file` |
| `SharingSet` | SharePoint | 6 | File/folder shared | 30 | `file` |
| `FileDownloaded` | SharePoint | 6 | File downloaded | 30 | `file` |
| `FileDeleted` | SharePoint | 6 | File moved to recycle bin | 20 | `file` |
| `FileUploaded` | SharePoint | 6 | File uploaded | 20 | `file` |
| `MessageSent` | MicrosoftTeams | 25 | Teams chat/channel message | 50 | `web` |
| `MeetingParticipantJoined` | MicrosoftTeams | 25 | Joined a Teams meeting | 30 | `session` |
| `MemberAdded` | MicrosoftTeams | 25 | Member added to team | 20 | `iam` |
| Various admin ops | Mixed | 1/4/8/25 | Admin cmdlets and policies | 50 | `configuration` |

## Realism Features

- **Jinja2 macros** (`_base.json.jinja`) eliminate boilerplate across 17 templates
- **5 workloads** — Azure AD / Entra ID, Exchange Online, SharePoint / OneDrive, Microsoft Teams, and admin operations
- **Shared state correlations** — UserLoggedIn stores sessions; subsequent MailItemsAccessed and FileAccessed events reuse the same user+IP pair for realistic session chaining
- **Record type accuracy** — correct M365 audit record type numbers (2=ExchangeItem, 6=SharePointFileOperation, 8=AzureActiveDirectory, 15=AzureADStsLogon, 25=MicrosoftTeams)
- **8 login failure scenarios** — AADSTS error codes (50126 InvalidPassword, 50053 Locked, 50057 Disabled, 50076 MFA required, 530032 Conditional Access blocked, etc.)
- **SharePoint site diversity** — 8 sites (6 team sites + 2 OneDrive personal) with weighted usage, multiple document libraries, and realistic folder paths
- **File operation realism** — 20 file types with weighted distributions across Reports, Campaigns, Architecture, Meetings, etc.
- **Teams collaboration** — 7 teams with 25 channels, weighted by activity; chat messages (35%) vs. channel messages (65%)
- **Email realism** — varied subjects, internal (80%) vs. external (20%) recipients, folder context (Inbox/Sent/Drafts/Archive)
- **10 admin operation types** — Exchange cmdlets, Conditional Access, DLP policies, retention, Teams meeting policies
- **User agent diversity** — 18 user agents across Edge, Chrome, Firefox, Safari, Outlook desktop/mobile, Teams desktop/mobile, OneDrive sync, PowerShell, Graph API
- **15 users** across 7 departments (Engineering, Marketing, Sales, Finance, HR, Legal, IT Operations) + admin and service accounts
- **User type mapping** — Regular (0), Admin (2), Application (5) based on account type
- **ECS-compatible output** — ready for Elasticsearch/OpenSearch ingestion via the Elastic O365 integration

## Parameters

| Parameter | Default | Description |
|---|---|---|
| `agent_id` | `f7a1b2c3-...` | Filebeat agent UUID |
| `agent_version` | `8.17.0` | Elastic Agent version |
| `error_rate` | `5` | Error injection rate (percentage, 0-100) |

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
  --path generators/cloud-m365-audit/generator.yml \
  --id m365-audit \
  --live-mode

# Batch mode (generate as fast as possible)
eventum generate \
  --path generators/cloud-m365-audit/generator.yml \
  --id m365-audit \
  --live-mode false
```

### startup.yml example

```yaml
generators:
  m365-audit:
    path: generators/cloud-m365-audit/generator.yml
    params:
      error_rate: 3
```

## Sample Output

```json
{
  "@timestamp": "2026-03-04T14:22:31+00:00",
  "agent": {
    "ephemeral_id": "c8d9e0f1-a2b3-4567-cdef-890123456789",
    "id": "f7a1b2c3-d4e5-6789-abcd-ef1234567890",
    "name": "o365-audit-forwarder",
    "type": "filebeat",
    "version": "8.17.0"
  },
  "cloud": {
    "provider": "azure"
  },
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "FileAccessed",
    "category": ["file"],
    "dataset": "o365.audit",
    "id": "d4e5f6a7-b8c9-0123-def4-567890abcdef",
    "kind": "event",
    "module": "o365",
    "outcome": "success",
    "type": ["access"]
  },
  "source": {
    "ip": "198.51.100.25"
  },
  "user": {
    "domain": "contoso.com",
    "email": "sarah.jones@contoso.com",
    "id": "a1b2c3d4-0002-4000-8000-000000000002",
    "name": "sarah.jones"
  },
  "user_agent": {
    "original": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
  },
  "organization": {
    "id": "b5c6d7e8-f9a0-4b1c-2d3e-f4a5b6c7d8e9",
    "name": "Contoso Ltd"
  },
  "file": {
    "directory": "sites/Engineering/Shared Documents/Architecture",
    "extension": "docx",
    "name": "Architecture-Overview.docx"
  },
  "related": {
    "ip": ["198.51.100.25"],
    "user": ["sarah.jones", "sarah.jones@contoso.com"]
  },
  "o365": {
    "audit": {
      "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "record_type": "6",
      "result_status": "Succeeded",
      "operation": "FileAccessed",
      "workload": "SharePoint",
      "user_id": "sarah.jones@contoso.com",
      "user_type": {
        "value": 0
      },
      "client_ip": "198.51.100.25",
      "object_id": "https://contoso.sharepoint.com/sites/Engineering/Shared Documents/Architecture/Architecture-Overview.docx",
      "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
      "item_type": "File",
      "site_url": "https://contoso.sharepoint.com/sites/Engineering",
      "source_file_name": "Architecture-Overview.docx",
      "source_file_extension": "docx",
      "source_relative_url": "sites/Engineering/Shared Documents/Architecture",
      "site": "e1a2b3c4-d5e6-4f7a-8b9c-0d1e2f3a4b5c",
      "list_item_unique_id": "f6a7b8c9-d0e1-2345-f6a7-b8c9d0e12345",
      "event_source": "SharePoint",
      "correlation_id": "e5f6a7b8-c9d0-1234-e5f6-a7b8c9d01234"
    }
  }
}
```

## File Structure

```
generators/cloud-m365-audit/
  generator.yml                                     # Pipeline config
  README.md                                         # This file
  templates/
    _base.json.jinja                                # Shared macros (agent, ecs, cloud, event, user, o365)
    aad-user-logged-in.json.jinja                   # Azure AD: successful sign-in (RecordType 15)
    aad-user-login-failed.json.jinja                # Azure AD: failed sign-in (RecordType 15)
    aad-password-change.json.jinja                  # Azure AD: password change (RecordType 8)
    aad-add-member.json.jinja                       # Azure AD: add member to group/role (RecordType 8)
    exchange-mail-accessed.json.jinja               # Exchange: MailItemsAccessed (RecordType 2)
    exchange-mail-sent.json.jinja                   # Exchange: Send (RecordType 2)
    exchange-mailbox-login.json.jinja               # Exchange: MailboxLogin (RecordType 2)
    sharepoint-file-accessed.json.jinja             # SharePoint: FileAccessed (RecordType 6)
    sharepoint-file-modified.json.jinja             # SharePoint: FileModified (RecordType 6)
    sharepoint-file-shared.json.jinja               # SharePoint: SharingSet (RecordType 6)
    sharepoint-file-downloaded.json.jinja           # SharePoint: FileDownloaded (RecordType 6)
    sharepoint-file-deleted.json.jinja              # SharePoint: FileDeleted (RecordType 6)
    sharepoint-file-uploaded.json.jinja             # SharePoint: FileUploaded (RecordType 6)
    teams-message-sent.json.jinja                   # Teams: MessageSent (RecordType 25)
    teams-meeting-joined.json.jinja                 # Teams: MeetingParticipantJoined (RecordType 25)
    teams-member-added.json.jinja                   # Teams: MemberAdded (RecordType 25)
    admin-operation.json.jinja                      # Admin: Exchange/AAD/SP/Teams cmdlets (RecordType 1/4/8/25)
  samples/
    users.csv                                       # 15 M365 users (12 regular + 1 admin + 2 service)
    organizations.csv                               # 2 tenants (primary + subsidiary)
    source_ips.csv                                  # 15 source IPs (corporate, VPN, mobile, remote, service)
    sharepoint_sites.json                           # 8 SharePoint sites (6 team + 2 OneDrive) with libraries
    files.json                                      # 20 files with weighted distributions and folder paths
    teams.json                                      # 7 Teams with 25 channels
    user_agents.json                                # 18 user agents (browsers, Outlook, Teams, OneDrive, PowerShell)
  output/
    events.json                                     # Generated events (overwritten each run)
```

## References

- [Microsoft 365 Audit Log Activities](https://learn.microsoft.com/en-us/purview/audit-log-activities)
- [Office 365 Management Activity API Schema](https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema)
- [Elastic O365 Integration](https://docs.elastic.co/integrations/o365)
- [Elastic Integrations — o365](https://github.com/elastic/integrations/tree/main/packages/o365)
- [Microsoft Entra ID Sign-in Error Codes](https://learn.microsoft.com/en-us/entra/identity-platform/reference-error-codes)
- [SharePoint File Operations Audit](https://learn.microsoft.com/en-us/purview/audit-log-activities#file-and-page-activities)
- [Exchange Mailbox Audit Logging](https://learn.microsoft.com/en-us/exchange/policy-and-compliance/mailbox-audit-logging/mailbox-audit-logging)

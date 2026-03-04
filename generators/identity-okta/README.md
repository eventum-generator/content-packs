# Okta Identity Provider

Generates realistic Okta System Log events matching the [Elastic Okta integration](https://docs.elastic.co/integrations/okta) field structure. Simulates the complete authentication and identity management event stream from an enterprise Okta tenant covering SSO sign-in logs, MFA events, admin audit events, user lifecycle management, group and application membership changes, and sign-on policy evaluations.

The Okta System Log provides a comprehensive audit trail of all user, admin, and system activity within an Okta organization. Events are captured via the Okta System Log API (`/api/v1/logs`) and include authentication, single sign-on to applications, MFA challenges, user provisioning, group management, and administrative operations.

## Event Types

| Event Type | Display Message | Description | Weight | ECS Category |
|---|---|---|---|---|
| `user.session.start` | User login to Okta | Successful user sign-in | 200 | `authentication` |
| `user.session.start` (failed) | User login to Okta | Failed user sign-in | 40 | `authentication` |
| `user.session.end` | User logout from Okta | User sign-out | 80 | `session` |
| `user.authentication.sso` | User single sign on to app | SSO to application | 180 | `authentication` |
| `user.authentication.auth_via_mfa` | Authentication of user via MFA | MFA challenge | 120 | `authentication` |
| `user.mfa.factor.verify` | Verify MFA factor | MFA factor verification | 80 | `authentication` |
| `user.mfa.factor.update` | User set up MFA factor | MFA factor enrollment/update | 15 | `iam` |
| `policy.evaluate_sign_on` | Evaluation of sign-on policy | Sign-on policy evaluation | 100 | `configuration` |
| `user.account.lock` | Okta user locked out | Account lockout | 10 | `iam` |
| `user.account.update_password` | User update password for Okta | Self-service password change | 20 | `iam` |
| `user.account.reset_password` | User password reset by admin | Admin password reset | 10 | `iam` |
| `user.lifecycle.create` | Create Okta user | New user provisioning | 10 | `iam` |
| `user.lifecycle.activate` | Activate Okta user | User activation | 10 | `iam` |
| `user.lifecycle.deactivate` | Deactivate Okta user | User deactivation | 5 | `iam` |
| `group.user_membership.add` | Add user to group membership | Group membership change | 30 | `iam` |
| `application.user_membership.add` | Add user to application membership | App assignment | 25 | `iam` |
| `user.session.access_admin_app` | User accessing Okta admin app | Admin console access | 20 | `configuration` |
| `system.api_token.create` | Create API token | API token creation | 5 | `configuration` |

## Realism Features

- **Jinja2 macros** (`_base.json.jinja`) eliminate boilerplate across 18 templates
- **6 event categories** — SSO sign-in, MFA, policy evaluation, account management, user lifecycle, admin operations
- **Shared state correlations** — `user.session.start` stores sessions; subsequent SSO and session end events reuse the same user identity for realistic session chaining
- **6 login failure scenarios** — `INVALID_CREDENTIALS`, `LOCKED_OUT`, `PASSWORD_EXPIRED`, `VERIFICATION_ERROR`, `AUTH_FAILED`, `INVALID_LOGIN` with weighted distributions
- **6 MFA factor types** — Okta Verify Push, Okta Verify TOTP, SMS, Email, WebAuthn/FIDO, YubiKey hardware token
- **5 sign-on policies** — Global, Corporate Network, Remote Access, High Security Apps, Contractor Access with ALLOW/CHALLENGE/DENY outcomes
- **15 SSO applications** — Salesforce, Slack, AWS, Jira, GitHub, Google Workspace, ServiceNow, Zoom, M365, Box, Workday, Datadog, Confluence, PagerDuty, Okta Admin Console
- **22 users** across 10 departments (Engineering, IT Ops, Security, Finance, Marketing, HR, Sales, Legal, Product, Support) + 2 admin accounts
- **15 source IPs** across 7 cities (New York, San Francisco, London, Seattle, Austin, Denver, Chicago, Portland, Boston, Toronto, Berlin) with corporate, remote, and VPN classifications
- **10 user agents** — Chrome, Firefox, Edge, Safari (desktop + mobile), Okta Verify (iOS + Android)
- **Admin-only operations** — lifecycle, group, app membership, API token, and admin console events use admin actor accounts
- **Full geolocation context** — city, state/region, country, lat/lon, postal code on every event
- **ECS-compatible output** — ready for Elasticsearch/OpenSearch ingestion via the Elastic Okta integration

## Parameters

| Parameter | Default | Description |
|---|---|---|
| `agent_id` | `a1b2c3d4-...` | Filebeat agent UUID |
| `agent_name` | `okta-system-forwarder` | Agent hostname |
| `agent_version` | `8.17.0` | Elastic Agent version |

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
  --path generators/identity-okta/generator.yml \
  --id okta \
  --live-mode

# Batch mode (generate as fast as possible)
eventum generate \
  --path generators/identity-okta/generator.yml \
  --id okta \
  --live-mode false
```

### startup.yml example

```yaml
generators:
  okta:
    path: generators/identity-okta/generator.yml
```

## Sample Output

```json
{
    "@timestamp": "2026-03-04T14:22:31+00:00",
    "agent": {
        "ephemeral_id": "c8d9e0f1-a2b3-4567-cdef-890123456789",
        "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        "name": "okta-system-forwarder",
        "type": "filebeat",
        "version": "8.17.0"
    },
    "client": {
        "geo": {
            "city_name": "San Francisco",
            "country_name": "United States",
            "location": {
                "lat": 37.7749,
                "lon": -122.4194
            },
            "region_name": "California"
        },
        "ip": "198.51.100.25",
        "user": {
            "email": "sarah.jones@acmecorp.com",
            "full_name": "Sarah Jones",
            "id": "00u2b3c4d5e6f7g8h9i0",
            "name": "sarah.jones@acmecorp.com"
        }
    },
    "ecs": {
        "version": "8.11.0"
    },
    "event": {
        "action": "user.session.start",
        "category": ["session", "authentication"],
        "dataset": "okta.system",
        "id": "3aeede38-4f67-11ea-abd3-1f5d113f2546",
        "kind": "event",
        "module": "okta",
        "outcome": "success",
        "type": ["start", "info"]
    },
    "source": {
        "ip": "198.51.100.25",
        "user": {
            "email": "sarah.jones@acmecorp.com",
            "full_name": "Sarah Jones",
            "id": "00u2b3c4d5e6f7g8h9i0",
            "name": "sarah.jones@acmecorp.com"
        }
    },
    "user": {
        "email": "sarah.jones@acmecorp.com",
        "full_name": "Sarah Jones",
        "id": "00u2b3c4d5e6f7g8h9i0",
        "name": "sarah.jones@acmecorp.com"
    },
    "user_agent": {
        "device": {
            "name": "Computer"
        },
        "name": "CHROME",
        "original": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "os": {
            "name": "Mac OS X"
        }
    },
    "related": {
        "ip": ["198.51.100.25"],
        "user": ["Sarah Jones", "sarah.jones@acmecorp.com"]
    },
    "okta": {
        "actor": {
            "alternate_id": "sarah.jones@acmecorp.com",
            "display_name": "Sarah Jones",
            "id": "00u2b3c4d5e6f7g8h9i0",
            "type": "User"
        },
        "authentication_context": {
            "authentication_step": 0,
            "credential_type": "PASSWORD",
            "external_session_id": "102bZDNFfWaQSyEZQuDgWt-uQ"
        },
        "client": {
            "device": "Computer",
            "ip": "198.51.100.25",
            "user_agent": {
                "browser": "CHROME",
                "os": "Mac OS X",
                "raw_user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
            },
            "zone": "null"
        },
        "debug_context": {
            "debug_data": {
                "request_id": "XkcAsWb8WjwDP76xh@1v8wAABp0",
                "request_uri": "/api/v1/authn",
                "threat_suspected": "false",
                "url": "/api/v1/authn"
            }
        },
        "display_message": "User login to Okta",
        "event_type": "user.session.start",
        "outcome": {
            "reason": null,
            "result": "SUCCESS"
        },
        "request": {
            "ip_chain": [
                {
                    "geographical_context": {
                        "city": "San Francisco",
                        "country": "United States",
                        "geolocation": {
                            "lat": 37.7749,
                            "lon": -122.4194
                        },
                        "postal_code": "94105",
                        "state": "California"
                    },
                    "ip": "198.51.100.25",
                    "version": "V4"
                }
            ]
        },
        "transaction": {
            "id": "XkcAsWb8WjwDP76xh@1v8wAABp0",
            "type": "WEB"
        },
        "uuid": "3aeede38-4f67-11ea-abd3-1f5d113f2546"
    },
    "tags": ["forwarded", "okta-system"]
}
```

## File Structure

```
generators/identity-okta/
  generator.yml                                       # Pipeline config
  README.md                                           # This file
  templates/
    _base.json.jinja                                  # Shared macros (agent, ecs, event, client, okta.*)
    user-session-start.json.jinja                     # Successful user login
    user-session-start-failed.json.jinja              # Failed user login (6 failure reasons)
    user-session-end.json.jinja                       # User logout
    user-authentication-sso.json.jinja                # SSO to application
    user-authentication-auth-via-mfa.json.jinja       # MFA challenge
    user-mfa-factor-verify.json.jinja                 # MFA factor verification
    user-mfa-factor-update.json.jinja                 # MFA factor enrollment/update
    policy-evaluate-sign-on.json.jinja                # Sign-on policy evaluation
    user-account-lock.json.jinja                      # Account lockout
    user-account-update-password.json.jinja           # Self-service password change
    user-account-reset-password.json.jinja            # Admin password reset
    user-lifecycle-create.json.jinja                  # User creation
    user-lifecycle-activate.json.jinja                # User activation
    user-lifecycle-deactivate.json.jinja              # User deactivation
    group-user-membership-add.json.jinja              # Group membership change
    application-user-membership-add.json.jinja        # Application assignment
    user-session-access-admin-app.json.jinja          # Admin console access
    system-api-token-create.json.jinja                # API token creation
  samples/
    users.csv                                         # 22 Okta users (20 regular + 2 admin)
    applications.json                                 # 15 SSO applications
    source_ips.csv                                    # 15 source IPs (corporate, remote, VPN)
    user_agents.json                                  # 10 user agents (browsers + Okta Verify)
    mfa_factors.json                                  # 6 MFA factor types
  output/
    events.json                                       # Generated events (overwritten each run)
```

## References

- [Okta System Log API](https://developer.okta.com/docs/reference/api/system-log/)
- [Okta Event Types](https://developer.okta.com/docs/reference/api/event-types/)
- [Elastic Okta Integration](https://docs.elastic.co/integrations/okta)
- [Elastic Integrations — Okta](https://github.com/elastic/integrations/tree/main/packages/okta)
- [Okta Security Events Cheat Sheet](https://github.com/OktaSecurityLabs/CheatSheets/blob/master/SecurityEvents.md)
- [Okta User Sign-in and Recovery Events](https://sec.okta.com/articles/2023/02/user-sign-and-recovery-events-okta-system-log/)

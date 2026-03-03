# AWS CloudTrail Management Events

Generates realistic AWS CloudTrail management events matching the [Elastic AWS CloudTrail integration](https://docs.elastic.co/integrations/aws/cloudtrail) field structure. Simulates the CloudTrail management event log stream from a multi-account AWS organization with IAM users, assumed roles, and service-originated API calls.

AWS CloudTrail records API calls and actions made in an AWS account, providing an audit trail of who did what, when, and from where. Management events capture control plane operations like creating/deleting resources, modifying IAM policies, and console sign-ins.

## Event Types

| Event Name | Service | Read/Write | Description | Weight | ECS Category |
|---|---|---|---|---|---|
| `AssumeRole` | STS | Write | Assume an IAM role (temp credentials) | 180 | `authentication` |
| `DescribeInstances` | EC2 | Read | List/describe EC2 instances | 80 | `host` |
| `GetCallerIdentity` | STS | Read | Retrieve caller identity | 50 | `authentication` |
| `DescribeSecurityGroups` | EC2 | Read | List/describe security groups | 40 | `network` |
| `ConsoleLogin` | Sign-In | Write | AWS Management Console sign-in | 30 | `authentication` |
| `DescribeVolumes` | EC2 | Read | List/describe EBS volumes | 30 | `host` |
| `DescribeVpcs` | EC2 | Read | List/describe VPCs | 25 | `network` |
| `DescribeRegions` | EC2 | Read | List available AWS regions | 20 | `configuration` |
| `ListBuckets` | S3 | Read | List S3 buckets | 20 | `database` |
| `GetUserPolicy` | IAM | Read | Get inline policy for a user | 15 | `iam` |
| `GetPolicy` | IAM | Read | Get managed policy details | 15 | `iam` |
| `ListRoles` | IAM | Read | List IAM roles | 15 | `iam` |
| `ListUsers` | IAM | Read | List IAM users | 10 | `iam` |
| `RunInstances` | EC2 | Write | Launch new EC2 instances | 10 | `host` |
| `StopInstances` | EC2 | Write | Stop running EC2 instances | 8 | `host` |
| `StartInstances` | EC2 | Write | Start stopped EC2 instances | 8 | `host` |
| `CreateSecurityGroup` | EC2 | Write | Create a new security group | 3 | `network` |
| `AuthorizeSecurityGroupIngress` | EC2 | Write | Add inbound rule to SG | 3 | `network` |
| `AttachRolePolicy` | IAM | Write | Attach managed policy to role | 2 | `iam` |
| `CreateUser` | IAM | Write | Create a new IAM user | 1 | `iam` |
| `CreateAccessKey` | IAM | Write | Create access key for user | 1 | `iam` |
| `TerminateInstances` | EC2 | Write | Terminate EC2 instances | 1 | `host` |

## Realism Features

- **Jinja2 macros** (`_base.json.jinja`) eliminate boilerplate across 22 templates
- **4 identity types** — AssumedRole (65%), IAMUser (20%), AWSService (12%), Root (0.5%) with accurate credential formats
- **Shared state correlations** — AssumeRole generates temp credentials reused by subsequent API calls; RunInstances populates an instance pool consumed by Stop/Start/TerminateInstances
- **Error injection** (~4%) — 20 realistic error scenarios (AccessDenied, UnauthorizedOperation, InstanceLimitExceeded, etc.) mapped to specific API operations
- **Console login flow** — AwsConsoleSignIn event type with MFA tracking and ~5% login failure rate
- **accessKeyId format accuracy** — AKIA prefix for permanent keys, ASIA prefix for temporary STS credentials
- **TLS details** — TLSv1.3 (75%) / TLSv1.2 (25%) with matching cipher suites
- **Multi-account environment** — 3 AWS accounts (production, staging, development)
- **10 IAM users** across 7 departments with unique principal IDs and access key IDs
- **12 IAM roles** with distinct trust services (STS, EC2, Lambda, CloudFormation, ECS)
- **15 EC2 instances** with realistic naming, types, and availability zones
- **User agent diversity** — AWS CLI, Python SDK (Boto3), JS SDK, Console, and service user agents
- **ECS-compatible output** — ready for Elasticsearch/OpenSearch ingestion via the Elastic AWS integration

## Parameters

| Parameter | Default | Description |
|---|---|---|
| `agent_id` | `a1b2c3d4-...` | Filebeat agent UUID |
| `agent_version` | `8.17.0` | Elastic Agent version |
| `event_version` | `1.09` | CloudTrail event version |
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
  --path generators/cloud-aws-cloudtrail/generator.yml \
  --id cloudtrail \
  --live-mode

# Batch mode (generate as fast as possible)
eventum generate \
  --path generators/cloud-aws-cloudtrail/generator.yml \
  --id cloudtrail \
  --live-mode false
```

### startup.yml example

```yaml
generators:
  cloudtrail:
    path: generators/cloud-aws-cloudtrail/generator.yml
    params:
      error_rate: 2
```

## Sample Output

```json
{
  "@timestamp": "2026-03-04T14:22:31+00:00",
  "agent": {
    "ephemeral_id": "b3f8a1c2-d4e5-6789-abcd-ef0123456789",
    "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "name": "cloudtrail-forwarder",
    "type": "filebeat",
    "version": "8.17.0"
  },
  "cloud": {
    "account": {
      "id": "123456789012",
      "name": "acme-production"
    },
    "provider": "aws",
    "region": "us-east-1"
  },
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "AssumeRole",
    "category": ["authentication"],
    "dataset": "aws.cloudtrail",
    "id": "c7d8e9f0-a1b2-3456-cdef-789012345678",
    "kind": "event",
    "module": "aws",
    "outcome": "success",
    "provider": "cloudtrail",
    "type": ["info"]
  },
  "source": {
    "address": "198.51.100.25",
    "ip": "198.51.100.25"
  },
  "user": {
    "name": "michael.chen",
    "id": "AIDAEXAMPLE3MCHEN001"
  },
  "user_agent": {
    "original": "aws-cli/2.15.22 md/Botocore#1.34.43 ua/2.0 os/macosx#14.3.1 md/arch#arm64 lang/python#3.11.8 md/pyimpl#CPython"
  },
  "related": {
    "ip": ["198.51.100.25"],
    "user": ["michael.chen"]
  },
  "aws": {
    "cloudtrail": {
      "event_version": "1.09",
      "event_source": "sts.amazonaws.com",
      "event_name": "AssumeRole",
      "event_type": "AwsApiCall",
      "event_category": "Management",
      "management_event": true,
      "read_only": false,
      "recipient_account_id": "123456789012",
      "request_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "user_identity": {
        "type": "IAMUser",
        "principal_id": "AIDAEXAMPLE3MCHEN001",
        "arn": "arn:aws:iam::123456789012:user/michael.chen",
        "account_id": "123456789012",
        "access_key_id": "AKIAEXAMPLE3MCHEN001",
        "user_name": "michael.chen"
      },
      "request_parameters": {
        "roleArn": "arn:aws:iam::123456789012:role/DevOpsDeployRole",
        "roleSessionName": "deploy-a1b2c3d4",
        "durationSeconds": 3600
      },
      "response_elements": {
        "credentials": {
          "accessKeyId": "ASIAXYZEXAMPLE01234",
          "expiration": "2026-03-04T15:22:31Z",
          "sessionToken": "FwoGZXIvYXdzE..."
        },
        "assumedRoleUser": {
          "assumedRoleId": "AROAEXAMPLE4DEVOP001:deploy-a1b2c3d4",
          "arn": "arn:aws:sts::123456789012:assumed-role/DevOpsDeployRole/deploy-a1b2c3d4"
        }
      },
      "tls_details": {
        "tls_version": "TLSv1.3",
        "cipher_suite": "TLS_AES_128_GCM_SHA256",
        "client_provided_host_header": "sts.amazonaws.com"
      }
    }
  }
}
```

## File Structure

```
generators/cloud-aws-cloudtrail/
  generator.yml                                    # Pipeline config
  README.md                                        # This file
  templates/
    _base.json.jinja                               # Shared macros (agent, ecs, cloud, tls, identity)
    assume-role.json.jinja                          # STS AssumeRole
    get-caller-identity.json.jinja                  # STS GetCallerIdentity
    console-login.json.jinja                        # Console sign-in (AwsConsoleSignIn)
    describe-instances.json.jinja                   # EC2 DescribeInstances
    describe-security-groups.json.jinja             # EC2 DescribeSecurityGroups
    describe-volumes.json.jinja                     # EC2 DescribeVolumes
    describe-vpcs.json.jinja                        # EC2 DescribeVpcs
    describe-regions.json.jinja                     # EC2 DescribeRegions
    list-buckets.json.jinja                         # S3 ListBuckets
    get-user-policy.json.jinja                      # IAM GetUserPolicy
    get-policy.json.jinja                           # IAM GetPolicy
    list-roles.json.jinja                           # IAM ListRoles
    list-users.json.jinja                           # IAM ListUsers
    run-instances.json.jinja                        # EC2 RunInstances
    stop-instances.json.jinja                       # EC2 StopInstances
    start-instances.json.jinja                      # EC2 StartInstances
    terminate-instances.json.jinja                  # EC2 TerminateInstances
    create-security-group.json.jinja                # EC2 CreateSecurityGroup
    authorize-sg-ingress.json.jinja                 # EC2 AuthorizeSecurityGroupIngress
    attach-role-policy.json.jinja                   # IAM AttachRolePolicy
    create-user.json.jinja                          # IAM CreateUser
    create-access-key.json.jinja                    # IAM CreateAccessKey
  samples/
    accounts.csv                                    # 3 AWS accounts (prod, staging, dev)
    users.csv                                       # 10 IAM users across 7 departments
    roles.csv                                       # 12 IAM roles with trust services
    regions.csv                                     # 5 AWS regions
    source_ips.csv                                  # 15 source IPs (corporate, VPN, CI/CD, remote)
    instances.csv                                   # 15 EC2 instances
    buckets.csv                                     # 6 S3 buckets
    security_groups.csv                             # 8 security groups
    user_agents.json                                # 15 user agents (CLI, SDK, console, service)
    error_scenarios.json                            # 20 error scenarios per API operation
  output/
    events.json                                     # Generated events (overwritten each run)
```

## References

- [AWS CloudTrail User Guide](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html)
- [CloudTrail Record Contents](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html)
- [CloudTrail userIdentity Element](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html)
- [Elastic AWS CloudTrail Integration](https://docs.elastic.co/integrations/aws/cloudtrail)
- [Elastic Integrations — aws](https://github.com/elastic/integrations/tree/main/packages/aws)
- [AWS STS API Reference](https://docs.aws.amazon.com/STS/latest/APIReference/welcome.html)
- [AWS EC2 API Reference](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/Welcome.html)
- [AWS IAM API Reference](https://docs.aws.amazon.com/IAM/latest/APIReference/welcome.html)

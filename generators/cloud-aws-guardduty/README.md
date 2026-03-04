# AWS GuardDuty Findings

Generates realistic AWS GuardDuty security findings matching the [Elastic AWS GuardDuty integration](https://docs.elastic.co/integrations/aws/guardduty) field structure. Simulates the GuardDuty finding stream from a multi-account AWS environment with EC2 instances, IAM users, and S3 buckets under various threat scenarios.

AWS GuardDuty is a continuous security monitoring service that analyzes and processes data from AWS CloudTrail, VPC Flow Logs, and DNS logs to identify unexpected and potentially unauthorized or malicious activity in your AWS environment.

## Event Types

| Finding Type | Category | Resource | Action | Severity | Weight |
|---|---|---|---|---|---|
| `Recon:EC2/PortProbeUnprotectedPort` | Recon | Instance | PORT_PROBE | Low | 150 |
| `Recon:EC2/Portscan` | Recon | Instance | PORT_PROBE | Medium | 150 |
| `Recon:EC2/PortProbeEMRUnprotectedPort` | Recon | Instance | PORT_PROBE | Low | 150 |
| `Recon:IAMUser/TorIPCaller` | Recon | AccessKey | AWS_API_CALL | Medium | 100 |
| `Recon:IAMUser/MaliciousIPCaller.Custom` | Recon | AccessKey | AWS_API_CALL | Medium | 100 |
| `UnauthorizedAccess:EC2/TorIPCaller` | UnauthorizedAccess | Instance | NETWORK_CONNECTION | Medium | 120 |
| `UnauthorizedAccess:EC2/MaliciousIPCaller.Custom` | UnauthorizedAccess | Instance | NETWORK_CONNECTION | Medium | 120 |
| `UnauthorizedAccess:EC2/RDPBruteForce` | UnauthorizedAccess | Instance | NETWORK_CONNECTION | Low | 120 |
| `UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B` | UnauthorizedAccess | AccessKey | AWS_API_CALL | Medium | 80 |
| `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` | UnauthorizedAccess | AccessKey | AWS_API_CALL | High | 80 |
| `Policy:IAMUser/RootCredentialUsage` | Policy | AccessKey | AWS_API_CALL | Low | 50 |
| `Policy:S3/BucketBlockPublicAccessDisabled` | Policy | S3Bucket | AWS_API_CALL | Low | 100 |
| `Policy:S3/AccountBlockPublicAccessDisabled` | Policy | S3Bucket | AWS_API_CALL | Low | 100 |
| `Policy:S3/BucketAnonymousAccessGranted` | Policy | S3Bucket | AWS_API_CALL | High | 100 |
| `Trojan:EC2/BlackholeTraffic` | Trojan | Instance | NETWORK_CONNECTION | Medium | 55 |
| `Trojan:EC2/DropPoint` | Trojan | Instance | NETWORK_CONNECTION | Medium | 55 |
| `Trojan:EC2/DGADomainRequest.B` | Trojan | Instance | DNS_REQUEST | High | 45 |
| `Impact:EC2/BitcoinDomainRequest.Reputation` | Impact | Instance | DNS_REQUEST | High | 45 |
| `Impact:EC2/PortSweep` | Impact | Instance | NETWORK_CONNECTION | Medium | 55 |
| `Impact:EC2/WinRMBruteForce` | Impact | Instance | NETWORK_CONNECTION | Low | 55 |
| `CryptoCurrency:EC2/BitcoinTool.B!DNS` | CryptoCurrency | Instance | DNS_REQUEST | High | 40 |
| `CryptoCurrency:EC2/BitcoinTool.B` | CryptoCurrency | Instance | NETWORK_CONNECTION | High | 40 |
| `Stealth:IAMUser/CloudTrailLoggingDisabled` | Stealth | AccessKey | AWS_API_CALL | Low | 40 |
| `Stealth:IAMUser/PasswordPolicyChange` | Stealth | AccessKey | AWS_API_CALL | Low | 40 |
| `Stealth:S3/ServerAccessLoggingDisabled` | Stealth | S3Bucket | AWS_API_CALL | Low | 30 |
| `Backdoor:EC2/DenialOfService.Tcp` | Backdoor | Instance | NETWORK_CONNECTION | High | 25 |
| `Backdoor:EC2/C&CActivity.B!DNS` | Backdoor | Instance | DNS_REQUEST | High | 25 |

## Realism Features

- **8 finding categories** — Recon (~25%), UnauthorizedAccess (~20%), Policy (~15%), Trojan (~10%), Impact (~10%), CryptoCurrency (~8%), Stealth (~7%), Backdoor (~5%)
- **3 resource types** — Instance (EC2), AccessKey (IAM), S3Bucket with complete resource metadata
- **4 action types** — NETWORK_CONNECTION, PORT_PROBE, AWS_API_CALL, DNS_REQUEST with full detail blocks
- **Jinja2 macros** (`_base.json.jinja`) eliminate boilerplate across 16 templates
- **Multi-account environment** — 3 AWS accounts (production, staging, development)
- **15 EC2 instances** with realistic naming, types, private/public IPs, VPC/subnet/security group details
- **10 threat actor IPs** from 8 countries with realistic ASN/ISP/geo data, including Tor exit nodes
- **14 DNS domains** — DGA-generated, crypto mining pools, C&C servers, drop points
- **Severity distribution** — Low, Medium, and High findings with accurate GuardDuty severity codes
- **Evidence blocks** — threat intelligence details with threat list names
- **ECS rule fields** — `rule.category`, `rule.name`, `rule.ruleset` for SIEM correlation
- **Temporal realism** — `first_seen` / `last_seen` windows spanning 1-72 hours with realistic finding counts
- **ECS-compatible output** — ready for Elasticsearch/OpenSearch ingestion via the Elastic AWS GuardDuty integration

## Parameters

| Parameter | Default | Description |
|---|---|---|
| `agent_id` | `b2c3d4e5-...` | Filebeat agent UUID |
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
  --path generators/cloud-aws-guardduty/generator.yml \
  --id guardduty \
  --live-mode

# Batch mode (generate as fast as possible)
eventum generate \
  --path generators/cloud-aws-guardduty/generator.yml \
  --id guardduty \
  --live-mode false
```

### startup.yml example

```yaml
generators:
  guardduty:
    path: generators/cloud-aws-guardduty/generator.yml
```

## Sample Output

```json
{
  "@timestamp": "2026-03-04T18:45:12.000Z",
  "agent": {
    "ephemeral_id": "c4d5e6f7-a8b9-0123-cdef-456789012345",
    "id": "b2c3d4e5-f6a7-8901-bcde-fa2345678901",
    "name": "guardduty-forwarder",
    "type": "filebeat",
    "version": "8.17.0"
  },
  "aws": {
    "guardduty": {
      "account_id": "123456789012",
      "arn": "arn:aws:guardduty:us-east-1:123456789012:detector/abc123/finding/def456",
      "created_at": "2026-03-04T06:45:12.000Z",
      "description": "EC2 instance i-0a1b2c3d4e5f67890 has an unprotected port which is being probed by a known malicious host.",
      "id": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
      "partition": "aws",
      "region": "us-east-1",
      "resource": {
        "instance_details": {
          "availability_zone": "us-east-1a",
          "instance_id": "i-0a1b2c3d4e5f67890",
          "instance_state": "running",
          "instance_type": "t3.medium",
          "network_interfaces": [
            {
              "private_ip_address": "10.0.1.10",
              "public_ip": "54.210.45.12",
              "security_groups": [
                {"group_id": "sg-0a1b2c3d4e5f6789", "group_name": "web-tier-sg"}
              ]
            }
          ]
        },
        "type": "Instance"
      },
      "schema_version": "2.0",
      "service": {
        "action": {
          "port_probe_action": {
            "blocked": false,
            "port_probe_details": [
              {
                "local_port_details": {"port": 22, "port_name": "SSH"},
                "remote_ip_details": {
                  "city": {"name": "Moscow"},
                  "country": {"code": "RU", "name": "Russia"},
                  "ip_address_v4": "198.51.100.200",
                  "organization": {"asn": "12389", "isp": "Rostelecom"}
                }
              }
            ]
          },
          "type": "PORT_PROBE"
        },
        "count": 15,
        "resource_role": "TARGET",
        "service_name": "guardduty"
      },
      "severity": {"code": 2, "value": "Low"},
      "title": "Unprotected port on EC2 instance i-0a1b2c3d4e5f67890 is being probed.",
      "type": "Recon:EC2/PortProbeUnprotectedPort"
    }
  },
  "cloud": {
    "account": {"id": "123456789012"},
    "provider": "aws",
    "region": "us-east-1",
    "service": {"name": "guardduty"}
  },
  "ecs": {"version": "8.17.0"},
  "event": {
    "action": "PORT_PROBE",
    "dataset": "aws.guardduty",
    "kind": ["event"],
    "module": "aws",
    "severity": 2,
    "type": ["info"]
  },
  "rule": {
    "category": "Recon",
    "name": "Recon:EC2/PortProbeUnprotectedPort",
    "ruleset": "Recon:EC2"
  },
  "source": {
    "address": ["198.51.100.200"],
    "as": {"number": [12389], "organization": {"name": ["PJSC Rostelecom"]}},
    "geo": {"city_name": "Moscow", "country_iso_code": "RU"},
    "ip": ["198.51.100.200"]
  }
}
```

## File Structure

```
generators/cloud-aws-guardduty/
  generator.yml                                    # Pipeline config
  README.md                                        # This file
  templates/
    _base.json.jinja                               # Shared macros (agent, ecs, cloud, resource, severity)
    recon-port-probe.json.jinja                    # Recon: port probe/scan findings (EC2)
    recon-iam-tor.json.jinja                       # Recon: IAM API from Tor/malicious IP
    unauth-network.json.jinja                      # UnauthorizedAccess: EC2 network (Tor, brute force)
    unauth-iam.json.jinja                          # UnauthorizedAccess: IAM (console login, cred exfil)
    policy-iam.json.jinja                          # Policy: root credential usage
    policy-s3.json.jinja                           # Policy: S3 bucket access/policy changes
    trojan-network.json.jinja                      # Trojan: blackhole/drop point traffic
    trojan-dns.json.jinja                          # Trojan: DGA domain requests
    impact-network.json.jinja                      # Impact: port sweep, WinRM brute force
    impact-dns.json.jinja                          # Impact: cryptocurrency domain requests
    crypto-dns.json.jinja                          # CryptoCurrency: mining pool DNS
    crypto-network.json.jinja                      # CryptoCurrency: mining pool connections
    stealth-iam.json.jinja                         # Stealth: CloudTrail/password policy changes
    stealth-s3.json.jinja                          # Stealth: S3 logging disabled
    backdoor-network.json.jinja                    # Backdoor: DDoS activity
    backdoor-dns.json.jinja                        # Backdoor: C&C DNS communication
  samples/
    accounts.csv                                   # 3 AWS accounts (prod, staging, dev)
    regions.csv                                    # 5 AWS regions
    instances.csv                                  # 15 EC2 instances with network details
    users.csv                                      # 9 IAM users/roles
    buckets.csv                                    # 6 S3 buckets
    threat_actors.json                             # 10 threat actor IPs with geo/ASN data
    finding_types.json                             # 27 finding type definitions
    dns_domains.json                               # 14 malicious domains (DGA, mining, C&C)
    api_calls.json                                 # 16 AWS API calls for IAM-based findings
  output/
    events.json                                    # Generated events (overwritten each run)
```

## References

- [AWS GuardDuty User Guide](https://docs.aws.amazon.com/guardduty/latest/ug/what-is-guardduty.html)
- [GuardDuty Finding Types](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html)
- [GuardDuty Finding Format](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings.html)
- [Elastic AWS GuardDuty Integration](https://docs.elastic.co/integrations/aws/guardduty)
- [Elastic Integrations — aws](https://github.com/elastic/integrations/tree/main/packages/aws)
- [GuardDuty EventBridge Events](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings_eventbridge.html)

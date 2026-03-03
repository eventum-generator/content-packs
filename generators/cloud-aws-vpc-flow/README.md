# AWS VPC Flow Logs

Generates realistic AWS VPC Flow Log events matching the [Elastic AWS VPC Flow integration](https://docs.elastic.co/integrations/aws/vpcflow) field structure. Simulates network traffic captured by VPC Flow Logs across multiple accounts, VPCs, subnets, and availability zones with realistic protocol, port, and traffic volume distributions.

AWS VPC Flow Logs capture information about IP traffic going to and from network interfaces in a VPC. They are a fundamental network monitoring tool for security analysis, troubleshooting connectivity issues, and tracking traffic patterns across AWS infrastructure.

## Event Types

| Template | Protocol | Action | Description | Weight | ECS Outcome |
|---|---|---|---|---|---|
| `accepted-tcp` | TCP (6) | ACCEPT | Standard TCP connections (HTTPS, HTTP, SSH, DB) | 500 | `success` |
| `accepted-udp` | UDP (17) | ACCEPT | UDP traffic (DNS, NTP, syslog, SNMP) | 150 | `success` |
| `accepted-tcp-bulk` | TCP (6) | ACCEPT | High-volume TCP transfers (S3, API, large uploads) | 100 | `success` |
| `rejected-tcp` | TCP (6) | REJECT | Security group denies, port scans, unauthorized access | 80 | `failure` |
| `nodata` | - | - | No traffic on interface during aggregation interval | 50 | - |
| `rejected-udp` | UDP (17) | REJECT | Blocked DNS probes, SNMP scans | 30 | `failure` |
| `accepted-icmp` | ICMP (1) | ACCEPT | Ping, traceroute, path MTU discovery | 20 | `success` |
| `rejected-icmp` | ICMP (1) | REJECT | Blocked external pings, ICMP probes | 10 | `failure` |
| `skipdata` | - | - | Internal capacity skip during aggregation | 10 | - |

## Realism Features

- **Jinja2 macros** (`_base.json.jinja`) eliminate boilerplate across 9 templates with shared agent, ECS, cloud, and VPC flow block helpers
- **Weighted port distributions** -- HTTPS (443) dominates at ~35%, followed by DNS (53), HTTP (80), SSH (22), MySQL (3306), PostgreSQL (5432), and 17 other services
- **Lognormal traffic volumes** -- packets and bytes follow lognormal distributions matching real network traffic patterns; bulk transfers produce 10KB-500MB flows
- **Network direction detection** -- automatically classifies flows as inbound, outbound, internal, or external based on RFC 1918 address analysis
- **Realistic reject patterns** -- rejected TCP targets common attack surfaces (SSH, RDP, SMB, databases); rejected UDP targets DNS, SNMP, and discovery protocols
- **ICMP type accuracy** -- uses actual ICMP type numbers (8=Echo Request, 0=Echo Reply, 3=Dest Unreachable, 11=Time Exceeded) in the port fields
- **Flow duration realism** -- rejected flows last 0-10s (SYN-only), normal TCP 1-300s, bulk transfers 10-600s, UDP 1-60s
- **NODATA/SKIPDATA events** -- simulates idle interfaces and internal capacity constraints at realistic 5%/1% rates
- **Multi-account environment** -- 3 AWS accounts (production, staging, development) across 5 regions
- **15 network interfaces** spanning 3 VPCs with EC2, NAT gateway, ALB, Lambda, and ECS task ENI types
- **Raw log preservation** -- `event.original` contains the v2 space-delimited format matching actual CloudWatch/S3 delivery
- **ECS-compatible output** -- ready for Elasticsearch/OpenSearch ingestion via the Elastic AWS integration

## Parameters

| Parameter | Default | Description |
|---|---|---|
| `agent_id` | `c4d5e6f7-...` | Filebeat agent UUID |
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
  --path generators/cloud-aws-vpc-flow/generator.yml \
  --id vpcflow \
  --live-mode

# Batch mode (generate as fast as possible)
eventum generate \
  --path generators/cloud-aws-vpc-flow/generator.yml \
  --id vpcflow \
  --live-mode false
```

### startup.yml example

```yaml
generators:
  vpcflow:
    path: generators/cloud-aws-vpc-flow/generator.yml
```

## Sample Output

### Accepted TCP Connection (HTTPS)

```json
{
  "@timestamp": "2026-03-04T14:22:31+00:00",
  "agent": {
    "ephemeral_id": "b3f8a1c2-d4e5-6789-abcd-ef0123456789",
    "id": "c4d5e6f7-a8b9-0123-cdef-456789abcdef",
    "name": "vpcflow-forwarder",
    "type": "filebeat",
    "version": "8.17.0"
  },
  "cloud": {
    "account": {
      "id": "123456789012",
      "name": "acme-production"
    },
    "availability_zone": "use1-az2",
    "provider": "aws",
    "region": "us-east-1"
  },
  "destination": {
    "address": "52.94.233.17",
    "ip": "52.94.233.17",
    "port": 443
  },
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "accept",
    "category": ["network"],
    "dataset": "aws.vpcflow",
    "end": "2026-03-04T14:22:31+00:00",
    "kind": "event",
    "module": "aws",
    "original": "2 123456789012 eni-0a1b2c3d4e5f60001 10.0.1.47 52.94.233.17 49832 443 6 24 18560 1741097491 1741097551 ACCEPT OK",
    "outcome": "success",
    "start": "2026-03-04T14:21:31+00:00",
    "type": ["connection", "allowed"]
  },
  "network": {
    "bytes": 18560,
    "direction": "outbound",
    "iana_number": "6",
    "packets": 24,
    "transport": "tcp",
    "type": "ipv4"
  },
  "related": {
    "ip": ["10.0.1.47", "52.94.233.17"]
  },
  "source": {
    "address": "10.0.1.47",
    "bytes": 18560,
    "ip": "10.0.1.47",
    "packets": 24,
    "port": 49832
  },
  "aws": {
    "vpcflow": {
      "version": 2,
      "account_id": "123456789012",
      "interface_id": "eni-0a1b2c3d4e5f60001",
      "srcaddr": "10.0.1.47",
      "dstaddr": "52.94.233.17",
      "srcport": 49832,
      "dstport": 443,
      "protocol": 6,
      "packets": 24,
      "bytes": 18560,
      "start": 1741097491,
      "end": 1741097551,
      "action": "ACCEPT",
      "log_status": "OK",
      "instance_id": "i-0a1b2c3d4e5f6001",
      "vpc_id": "vpc-0abc1234",
      "subnet_id": "subnet-0aaa1111",
      "type": "IPv4"
    }
  }
}
```

### Rejected TCP Connection (SSH brute force)

```json
{
  "@timestamp": "2026-03-04T14:23:05+00:00",
  "event": {
    "action": "reject",
    "category": ["network"],
    "dataset": "aws.vpcflow",
    "kind": "event",
    "module": "aws",
    "original": "2 123456789012 eni-0a1b2c3d4e5f60003 185.220.101.42 10.0.2.15 54321 22 6 3 180 1741097580 1741097585 REJECT OK",
    "outcome": "failure",
    "type": ["connection", "denied"]
  },
  "source": {
    "address": "185.220.101.42",
    "ip": "185.220.101.42",
    "port": 54321
  },
  "destination": {
    "address": "10.0.2.15",
    "ip": "10.0.2.15",
    "port": 22
  },
  "network": {
    "bytes": 180,
    "direction": "inbound",
    "iana_number": "6",
    "packets": 3,
    "transport": "tcp",
    "type": "ipv4"
  },
  "aws": {
    "vpcflow": {
      "action": "REJECT",
      "log_status": "OK",
      "protocol": 6
    }
  }
}
```

## File Structure

```
generators/cloud-aws-vpc-flow/
  generator.yml                            # Pipeline config
  README.md                                # This file
  templates/
    _base.json.jinja                       # Shared macros (agent, ecs, cloud, vpcflow, direction)
    accepted-tcp.json.jinja                # TCP ACCEPT — web, SSH, database traffic
    accepted-tcp-bulk.json.jinja           # TCP ACCEPT — high-volume transfers (S3, API)
    accepted-udp.json.jinja                # UDP ACCEPT — DNS, NTP, syslog
    accepted-icmp.json.jinja               # ICMP ACCEPT — ping, traceroute
    rejected-tcp.json.jinja                # TCP REJECT — security group denies, scans
    rejected-udp.json.jinja                # UDP REJECT — blocked probes
    rejected-icmp.json.jinja               # ICMP REJECT — blocked external pings
    nodata.json.jinja                      # NODATA — idle interface
    skipdata.json.jinja                    # SKIPDATA — internal capacity skip
  samples/
    accounts.csv                           # 3 AWS accounts (prod, staging, dev)
    regions.csv                            # 5 AWS regions with AZ IDs
    enis.csv                               # 15 ENIs across 3 VPCs (EC2, NAT GW, ALB, Lambda, ECS)
    common_services.json                   # 23 services with weighted port distributions
  output/
    events.json                            # Generated events (overwritten each run)
```

## References

- [AWS VPC Flow Logs](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html)
- [VPC Flow Log Records](https://docs.aws.amazon.com/vpc/latest/userguide/flow-log-records.html)
- [IANA Protocol Numbers](https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml)
- [Elastic AWS VPC Flow Integration](https://docs.elastic.co/integrations/aws/vpcflow)
- [Elastic Integrations -- aws](https://github.com/elastic/integrations/tree/main/packages/aws)
- [Elastic Common Schema (ECS)](https://www.elastic.co/guide/en/ecs/current/index.html)

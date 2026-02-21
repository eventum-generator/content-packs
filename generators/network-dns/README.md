# Network DNS Traffic Generator

Produces realistic DNS transaction events (query + response pairs) matching the output of **Packetbeat / Elastic Agent** (`network_traffic.dns` dataset). Events follow the Elastic Common Schema (ECS) and can be ingested directly into OpenSearch or Elasticsearch.

## Event Types Covered

| Query Type | Description | Frequency | Category |
|------------|-------------|-----------|----------|
| A | IPv4 address lookup | ~60% | network |
| AAAA | IPv6 address lookup | ~16% | network |
| PTR | Reverse DNS lookup | ~8% | network |
| CNAME | Alias resolution | ~4% | network |
| HTTPS | SVCB/HTTPS service binding | ~3% | network |
| TXT | Text records (SPF/DKIM/DMARC) | ~3% | network |
| MX | Mail exchange lookup | ~2% | network |
| SRV | Service location (AD, SIP) | ~2% | network |
| NS | Nameserver delegation | ~1% | network |
| SOA | Zone authority info | ~0.6% | network |

## Realism Features

- **Weighted query type distribution** matching typical enterprise DNS traffic
- **Mixed internal/external domains** — each template uses a realistic split (e.g., 35% internal for A records, 90% internal for SRV)
- **Response code distribution** — ~86% NOERROR, ~10% NXDOMAIN, ~3% SERVFAIL, ~1% REFUSED, with per-type tuning (AAAA has higher NXDOMAIN for internal hosts, PTR has ~20% NXDOMAIN)
- **Authoritative flag** set for internal domain responses
- **Realistic answer data** — CNAME chains with CDN aliases, MX records with priorities, SRV records for Active Directory services (_ldap._tcp, _kerberos._tcp), SOA with date-based serial numbers
- **40 real-world external domains** — Google, Microsoft, AWS, GitHub, Slack, Zoom, CDN providers, certificate services, package registries
- **30 internal service hostnames** — domain controllers, mail servers, file servers, monitoring, CI/CD
- **Monotonic record IDs** — sequential across all events via `shared` state
- **Realistic timing** — event duration (1-120ms), TTL values appropriate per record type
- **Community ID** — deterministic flow hash from source/destination tuple
- **Transport variation** — UDP (~97%) vs TCP (~3%), with higher TCP rates for TXT and SOA queries

## Parameters

### Event Parameters

Edit the `params` section under `event.template` in `generator.yml`:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `hostname` | `SENSOR01` | Hostname of the Packetbeat sensor |
| `dns_server_ip` | `10.0.0.10` | IP address of the monitored DNS server |
| `internal_domain` | `contoso.local` | Internal domain suffix for AD/enterprise queries |
| `agent_id` | `b59c76de-...` | Packetbeat agent ID |
| `agent_version` | `8.17.0` | Packetbeat version string |

### Output Parameters

Provide via `startup.yml` params/secrets (used by the OpenSearch output):

| Parameter | Variable | Description |
|-----------|----------|-------------|
| `opensearch_host` | `${params.opensearch_host}` | OpenSearch URL (e.g. `https://localhost:9200`) |
| `opensearch_user` | `${params.opensearch_user}` | OpenSearch username |
| `opensearch_password` | `${secrets.opensearch_password}` | OpenSearch password (stored in keyring) |
| `opensearch_index` | `${params.opensearch_index}` | Target index name (e.g. `packetbeat-8.17.0`) |

## Usage

```bash
# Install Eventum
uv tool install eventum-generator

# Run with console output only (for testing)
eventum generate \
  --path generators/network-dns/generator.yml \
  --id dns \
  --live-mode
```

### OpenSearch Configuration

The OpenSearch output uses `${params.*}` / `${secrets.*}` placeholders resolved from `startup.yml`:

```yaml
# startup.yml
- id: dns
  path: network-dns
  params:
    opensearch_host: https://localhost:9200
    opensearch_user: admin
    opensearch_index: packetbeat-8.17.0
```

Secrets (e.g. `opensearch_password`) are managed via the Eventum keyring. See [Eventum docs](https://eventum.run) for details.

### Adjusting Event Rate

Change the `count` in the input section:

```yaml
input:
  - cron:
      expression: "* * * * * *"
      count: 5    # 5 events/second (300/min, 18K/hour)
```

## Sample Output

### A Record Query — NOERROR

```json
{
    "@timestamp": "2026-02-21T12:00:01.234567+00:00",
    "client": {
        "bytes": 34,
        "ip": "192.168.0.42",
        "port": 52431
    },
    "destination": {
        "bytes": 50,
        "ip": "10.0.0.10",
        "port": 53
    },
    "dns": {
        "answers": [
            {
                "class": "IN",
                "data": "142.250.80.4",
                "name": "www.google.com",
                "ttl": "300",
                "type": "A"
            }
        ],
        "header_flags": ["RD", "RA"],
        "id": 34521,
        "op_code": "QUERY",
        "question": {
            "class": "IN",
            "name": "www.google.com",
            "registered_domain": "google.com",
            "subdomain": "www",
            "top_level_domain": "com",
            "type": "A"
        },
        "resolved_ip": ["142.250.80.4"],
        "response_code": "NOERROR",
        "type": "answer"
    },
    "event": {
        "category": ["network"],
        "dataset": "network_traffic.dns",
        "duration": 12345678,
        "kind": "event",
        "type": ["connection", "protocol"]
    },
    "network": {
        "bytes": 84,
        "protocol": "dns",
        "transport": "udp",
        "type": "ipv4"
    },
    "network_traffic": {
        "dns": {
            "answers_count": 1,
            "flags": {
                "recursion_available": true,
                "recursion_desired": true
            },
            "method": "QUERY",
            "query": "class IN, type A, www.google.com"
        },
        "status": "OK"
    }
}
```

## File Structure

```
network-dns/
  generator.yml                              # Pipeline configuration
  README.md                                  # This file
  templates/
    a-query.json.jinja                       # A record (IPv4 address) queries
    aaaa-query.json.jinja                    # AAAA record (IPv6 address) queries
    ptr-query.json.jinja                     # PTR (reverse DNS) queries
    cname-query.json.jinja                   # CNAME (alias) queries with CDN chains
    mx-query.json.jinja                      # MX (mail exchange) queries
    txt-query.json.jinja                     # TXT (SPF/DKIM/DMARC) queries
    srv-query.json.jinja                     # SRV (service location) queries
    ns-query.json.jinja                      # NS (nameserver) queries
    soa-query.json.jinja                     # SOA (zone authority) queries
    https-query.json.jinja                   # HTTPS/SVCB (service binding) queries
  samples/
    domains.json                             # 40 real-world external domains with IPs
    internal_services.json                   # 30 internal service hostname prefixes
```

## References

- [RFC 1035 — Domain Names (Implementation)](https://datatracker.ietf.org/doc/html/rfc1035)
- [Elastic Network Traffic DNS Integration](https://github.com/elastic/integrations/tree/main/packages/network_traffic/data_stream/dns)
- [Elastic Common Schema — DNS Fields](https://www.elastic.co/guide/en/ecs/current/ecs-dns.html)
- [Packetbeat DNS Reference](https://www.elastic.co/guide/en/beats/packetbeat/current/packetbeat-dns-options.html)

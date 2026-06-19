# Traefik Access Log Generator

Realistic synthetic [Traefik](https://traefik.io/) access log events in ECS-compatible JSON, matching the [Elastic Traefik integration](https://www.elastic.co/docs/reference/integrations/traefik) (data stream `access`). Output ingests directly into Elasticsearch or OpenSearch.

Operational telemetry for SRE/DevOps, not audit: every event carries the dual-latency breakdown (origin duration + Traefik overhead), upstream status, retry attempts and a monotonic request counter — the signals that drive latency SLOs and error budgets. Unlike a static web-server access log, Traefik fronts a dynamic routing table: each request is matched to a **router** and forwarded to a backend **service**, and the log records the total request duration and the upstream (origin) duration separately.

## Event types

| Template | Frequency | Description |
|----------|-----------|-------------|
| `access_success` | ~90% | 2xx/3xx responses. Origin status mirrors the downstream status; plain-http requests return 308 redirects to https (Traefik-generated, origin status 0). Latency follows a per-route log-normal distribution whose tail produces slow-request outliers. |
| `access_client_error` | ~7% | 4xx responses. 400/401/403/404 come from the backend (origin status equals the downstream status); 429 is produced by Traefik's rateLimit middleware before the backend is reached (origin status 0). |
| `access_upstream_error` | ~3% | 5xx responses Traefik generates when the backend fails: 502 (connection reset/refused), 503 (no healthy server), 504 (response timeout). Origin status is 0 and retry attempts correlate with the failure mode. |

`event.outcome` is `success` for 2xx/3xx and `failure` for 4xx/5xx. Status codes observed: 200, 201, 204, 206, 302, 304, 308, 400, 401, 403, 404, 429, 502, 503, 504.

## Realism

- **Dual-latency model** — `event.duration` equals `traefik.access.origin.duration` plus `traefik.access.overhead`, so upstream time and proxy overhead are always consistent.
- **Per-route latency classes** — fast / normal / slow services draw from distinct log-normal distributions (median ~4 ms / ~35 ms / ~220 ms) with a heavy tail; gateway timeouts reach ~30 s.
- **Routing table** — requests are matched to routers and forwarded to backend services from `samples/routes.json`, modelling an e-commerce Kubernetes platform (storefront, catalog, cart, checkout, payments, auth, search, media, ...).
- **Correlated failure modes** — 5xx errors carry origin status 0, zero origin content size, and retry attempts that match the failure type.
- **Monotonic request counter** — `traefik.access.request_count` increases per event, as a Traefik process does.

## Parameters

### Event Parameters

Edit the `params` section under `event.template` in `generator.yml`:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `traefik_provider` | `kubernetes` | Provider suffix on router and service names (`@kubernetes`, `@docker`, `@file`, `@kubernetescrd`). |

The routing table itself lives in `samples/routes.json` — edit it to model your own hosts, services, ports and latency profiles.

### Output Parameters

The shipped `generator.yml` writes to a local file, so it runs out of the box. To deliver events to a backend instead, edit the `output` section with `${params.*}` / `${secrets.*}` placeholders and supply their values via `--params`, `startup.yml`, or the keyring:

```yaml
# OpenSearch example
- opensearch:
    hosts:
      - ${params.opensearch_host}
    username: ${params.opensearch_user}
    password: ${secrets.opensearch_password}
    index: ${params.opensearch_index}
```

| Parameter | Description |
|-----------|-------------|
| `${params.opensearch_host}` | OpenSearch / Elasticsearch host URL |
| `${params.opensearch_user}` | Connection username |
| `${secrets.opensearch_password}` | Connection password (resolved from the keyring) |
| `${params.opensearch_index}` | Target index name |

## Usage

```bash
# Install Eventum
uv tool install eventum-generator

# Live mode — continuous stream
eventum generate \
  --path generators/proxy-traefik/generator.yml \
  --id traefik \
  --live-mode true

# Batch mode — generate as fast as possible until stopped
eventum generate \
  --path generators/proxy-traefik/generator.yml \
  --id traefik \
  --live-mode false
```

Events are written to `output/events.json` inside the generator directory.

## Sample output

```json
{
    "@timestamp": "2026-06-19T18:22:44+00:00",
    "destination": {
        "address": "10.1.10.36:8080",
        "ip": "10.1.10.36",
        "port": 8080
    },
    "ecs": {
        "version": "8.11.0"
    },
    "event": {
        "category": ["web"],
        "created": "2026-06-19T18:22:44+00:00",
        "duration": 29956413,
        "ingested": "2026-06-19T18:22:44.266000+00:00",
        "kind": "event",
        "outcome": "success",
        "type": ["access"]
    },
    "http": {
        "request": {
            "body": { "bytes": 0 },
            "method": "GET"
        },
        "response": {
            "body": { "bytes": 1397 },
            "status_code": 200
        },
        "version": "2.0"
    },
    "log": { "level": "info" },
    "network": {
        "community_id": "1:YPIKJmLuQRcy3BDjhM84xxtnl2g=",
        "transport": "tcp"
    },
    "observer": {
        "egress": { "interface": { "name": "shop-cart-api-8080@kubernetes" } },
        "ingress": { "interface": { "name": "websecure" } },
        "product": "traefik",
        "type": "proxy",
        "vendor": "traefik"
    },
    "related": {
        "ip": ["192.0.1.60", "10.1.10.36"]
    },
    "source": {
        "address": "192.0.1.60:53566",
        "ip": "192.0.1.60",
        "port": 53566
    },
    "traefik": {
        "access": {
            "origin": {
                "content_size": 1397,
                "duration": 29847534,
                "status_code": 200
            },
            "overhead": 108879,
            "request_count": 57,
            "retry_attempts": 0,
            "router": { "name": "shop-cart-api-example-com-cart@kubernetes" },
            "service": {
                "url": {
                    "domain": "10.1.10.36:8080",
                    "force_query": false,
                    "fragment": "",
                    "opaque": "",
                    "path": "",
                    "raw_path": "",
                    "raw_query": "",
                    "user": null
                }
            }
        }
    },
    "url": {
        "domain": "api.example.com",
        "original": "/cart/v1/items/add",
        "scheme": "https"
    },
    "user": { "name": "-" }
}
```

## References

- [Traefik access logs documentation](https://doc.traefik.io/traefik/observability/access-logs/)
- [Elastic Traefik integration](https://www.elastic.co/docs/reference/integrations/traefik) — ECS field mappings (data stream `access`)
- [Elastic Common Schema (ECS)](https://www.elastic.co/guide/en/ecs/current/index.html)

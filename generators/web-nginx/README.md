# Nginx Access & Error Log Generator

Produces realistic nginx access and error log entries matching the output of **Filebeat / Elastic Agent** with the nginx module. Events follow the Elastic Common Schema (ECS) and can be ingested directly into OpenSearch or Elasticsearch.

## Event Types Covered

| Template | Description | Frequency | ECS Fields |
|----------|-------------|-----------|------------|
| access-success | HTTP 2xx/3xx responses | ~84% | `event.type: ["access"]`, `event.outcome: "success"` |
| access-failure | HTTP 4xx/5xx responses | ~11% | `event.type: ["access"]`, `event.outcome: "failure"` |
| error-upstream | Upstream connect/timeout/reset errors | ~2.5% | `event.type: ["error"]`, `log.level: "error"` |
| error-filesystem | File not found, permission denied | ~1.5% | `event.type: ["error"]`, `log.level: "error"` |
| error-client | Body too large, premature close | ~0.5% | `event.type: ["error"]`, `log.level: "error"/"info"` |
| error-ssl | TLS handshake failures | ~0.3% | `event.type: ["error"]`, `log.level: "crit"/"error"` |
| error-system | Bind failures, worker crashes, signals | ~0.2% | `event.type: ["error"]`, `log.level: varies` |

## Realism Features

- **Weighted event distribution** matching production nginx traffic (~95% access, ~5% error)
- **URL category distribution** — static assets (40%), HTML pages (30%), API endpoints (18%), well-known files (12%)
- **HTTP method correlation** — GET 85%, POST 10%, with method-specific status codes
- **Status code distribution** — 200 (82%), 304 (9%), 301/302 (7%), 206 (2%) for success; 404/401/403/500/502 for failure
- **Response size correlation** — sizes match content type (JS bundles 80-450KB, API 50B-20KB, 304→0 bytes, 502→157 bytes)
- **User agent distribution** — desktop browsers (55%), mobile (20%), bots (10%), tools (8%), monitors (7%)
- **Referer patterns** — direct traffic, same-site navigation, search engines, social media
- **Scanner probe simulation** — wp-login.php, .env, .git/config with realistic 404 responses
- **Error message accuracy** — real nginx error formats with client/server/upstream context fields
- **Monotonic connection IDs** across error events via shared state

## Parameters

### Event Parameters

Edit the `params` section under `event.template` in `generator.yml`:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `hostname` | `web-srv-01` | Nginx server hostname |
| `server_name` | `example.com` | Virtual host domain name |
| `upstream_addr` | `127.0.0.1:8080` | Backend upstream address |
| `doc_root` | `/var/www/html` | Document root path (for error messages) |
| `nginx_pid` | `1234` | Nginx master process PID |
| `agent_id` | `a7b8c9d0-...` | Filebeat agent ID |
| `agent_version` | `8.17.0` | Filebeat version string |

### Output Parameters

Provide via `startup.yml` params/secrets (used by the OpenSearch output):

| Parameter | Variable | Description |
|-----------|----------|-------------|
| `opensearch_host` | `${params.opensearch_host}` | OpenSearch URL (e.g. `https://localhost:9200`) |
| `opensearch_user` | `${params.opensearch_user}` | OpenSearch username |
| `opensearch_password` | `${secrets.opensearch_password}` | OpenSearch password (stored in keyring) |
| `opensearch_index` | `${params.opensearch_index}` | Target index name (e.g. `filebeat-8.17.0`) |

## Usage

```bash
# Install Eventum
uv tool install eventum-generator

# Run with console output only (for testing)
eventum generate \
  --path generators/web-nginx/generator.yml \
  --id nginx \
  --live-mode
```

### OpenSearch Configuration

The OpenSearch output uses `${params.*}` / `${secrets.*}` placeholders resolved from `startup.yml`:

```yaml
# startup.yml
- id: nginx
  path: web-nginx
  params:
    opensearch_host: https://localhost:9200
    opensearch_user: admin
    opensearch_index: filebeat-8.17.0
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

### Access Log — HTTP 200

```json
{
    "@timestamp": "2026-02-21T14:32:07.123456+00:00",
    "event": {
        "category": ["web"],
        "dataset": "nginx.access",
        "kind": "event",
        "module": "nginx",
        "outcome": "success",
        "type": ["access"]
    },
    "http": {
        "request": {
            "method": "GET",
            "referrer": "https://www.google.com/"
        },
        "response": {
            "body": { "bytes": 18432 },
            "status_code": 200
        },
        "version": "1.1"
    },
    "source": {
        "address": "203.0.113.50",
        "ip": "203.0.113.50"
    },
    "url": {
        "original": "/products",
        "path": "/products"
    },
    "user_agent": {
        "name": "Chrome",
        "original": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML like Gecko) Chrome/133.0.0.0 Safari/537.36",
        "os": { "name": "Windows", "version": "10" }
    }
}
```

### Error Log — Upstream Timeout

```json
{
    "@timestamp": "2026-02-21T14:32:09.654321+00:00",
    "event": {
        "category": ["web"],
        "dataset": "nginx.error",
        "kind": "event",
        "module": "nginx",
        "type": ["error"]
    },
    "log": {
        "level": "error"
    },
    "message": "upstream timed out (110: Connection timed out) while reading response header from upstream, client: 198.51.100.23, server: example.com, request: \"POST /api/v1/orders HTTP/1.1\", upstream: \"http://127.0.0.1:8080/api/v1/orders\", host: \"example.com\"",
    "nginx": {
        "error": { "connection_id": 1042 }
    },
    "process": {
        "pid": 1234,
        "thread": { "id": 1234 }
    }
}
```

## File Structure

```
web-nginx/
  generator.yml                          # Pipeline configuration
  README.md                              # This file
  templates/
    access-success.json.jinja            # HTTP 2xx/3xx access log events
    access-failure.json.jinja            # HTTP 4xx/5xx access log events
    error-upstream.json.jinja            # Upstream/proxy errors (502/504)
    error-filesystem.json.jinja          # File not found, permission denied
    error-client.json.jinja              # Client body too large, premature close
    error-ssl.json.jinja                 # TLS/SSL handshake failures
    error-system.json.jinja              # Process crashes, bind failures, signals
  samples/
    urls.json                            # 56 URL paths with methods, categories, sizes
    user_agents.csv                      # 24 user agents (browsers, bots, tools, monitors)
    referers.csv                         # 24 referer patterns (direct, internal, search, social)
    error_messages.json                  # Structured error messages by category
```

## References

- [Nginx Documentation — Log Module](https://nginx.org/en/docs/http/ngx_http_log_module.html)
- [Nginx Documentation — Error Log](https://nginx.org/en/docs/ngx_core_module.html#error_log)
- [Elastic Nginx Integration](https://github.com/elastic/integrations/tree/main/packages/nginx)
- [Elastic Common Schema (ECS)](https://www.elastic.co/guide/en/ecs/current/index.html)
- [Filebeat Nginx Module](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-module-nginx.html)

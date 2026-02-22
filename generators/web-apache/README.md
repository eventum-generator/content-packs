# Apache HTTP Server Log Generator

Produces realistic Apache HTTP Server access and error log events matching the output of **Filebeat / Elastic Agent** with the [Apache integration](https://github.com/elastic/integrations/tree/main/packages/apache). Events follow the Elastic Common Schema (ECS) and can be ingested directly into OpenSearch or Elasticsearch.

## Event Types Covered

| Event Type | Template | Frequency | Category |
|------------|----------|-----------|----------|
| Successful request (2xx/304) | `access-success` | ~68% | access |
| Bot/crawler request | `access-bot` | ~11% | access |
| Client error (4xx) | `access-client-error` | ~9% | access |
| Redirect (3xx) | `access-redirect` | ~5% | access |
| Server error (5xx) | `access-server-error` | ~1.4% | access |
| File not found (error log) | `error-file-not-found` | ~3.2% | error |
| Module error/warning | `error-module` | ~1.4% | error |
| Operational notice | `error-notice` | ~0.9% | error |

## Realism Features

- **Weighted event distribution** matching production Apache web server traffic
- **Correlated access/error logs** — 404 access events produce matching "File does not exist" error log entries via shared state pool
- **Correlated server errors** — 5xx access events produce matching module error log entries
- **Realistic URL distribution** — pages (30%), static assets (50%), API endpoints (20%) with appropriate response sizes
- **Content-aware response sizes** — CSS/JS/image sizes match real-world ranges; 304 responses return 0 bytes
- **Browser user agent diversity** — Chrome, Firefox, Safari, Edge, mobile browsers with realistic market share weights
- **Bot traffic simulation** — Googlebot, bingbot, YandexBot, AhrefsBot, GPTBot with correct UA strings
- **Attack surface probing** — 404 paths include common scanner targets (`.env`, `wp-admin`, `phpMyAdmin`, `.git/config`)
- **Method-aware status codes** — POST for 400/405 errors, GET-heavy for regular traffic
- **Response time ranges** — fast for static assets (0.5-15ms), slow for server errors (100ms-3s)

## Parameters

### Event Parameters

Edit the `params` section under `event.template` in `generator.yml`:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `hostname` | `webserver01` | Server hostname |
| `domain` | `example.com` | Website domain name |
| `os_family` | `debian` | Host OS family |
| `os_name` | `Ubuntu` | Host OS name |
| `agent_id` | `9326664e-...` | Filebeat agent ID |
| `agent_version` | `8.17.0` | Filebeat version string |

## Usage

```bash
# Install Eventum
uv tool install eventum-generator

# Run the generator
eventum generate \
  --path generators/web-apache/generator.yml \
  --id apache \
  --live-mode
```

### Adjusting Event Rate

Change the `count` in the input section:

```yaml
input:
  - cron:
      expression: "* * * * * *"
      count: 5    # 5 events/second (300/min, 18K/hour)
```

## Sample Output

### Access Log — Successful Request

```json
{
    "@timestamp": "2026-02-21T12:00:01.234567+00:00",
    "apache": {
        "access": {
            "remote_addresses": ["203.0.113.42"],
            "response_time": 45230
        }
    },
    "data_stream": {
        "dataset": "apache.access",
        "namespace": "default",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "event": {
        "category": ["web"],
        "dataset": "apache.access",
        "kind": "event",
        "module": "apache",
        "outcome": "success"
    },
    "host": {
        "hostname": "webserver01",
        "name": "webserver01"
    },
    "http": {
        "request": {
            "method": "GET",
            "referrer": "https://www.google.com/"
        },
        "response": {
            "body": {
                "bytes": 12847
            },
            "status_code": 200
        },
        "version": "1.1"
    },
    "source": {
        "address": "203.0.113.42",
        "ip": "203.0.113.42"
    },
    "tags": ["apache-access"],
    "url": {
        "domain": "example.com",
        "original": "/products",
        "path": "/products"
    },
    "user_agent": {
        "device": {"name": "Other"},
        "name": "Chrome",
        "original": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ...",
        "version": "120.0.0.0"
    }
}
```

### Error Log — File Not Found

```json
{
    "@timestamp": "2026-02-21T12:00:02.456789+00:00",
    "apache": {
        "error": {
            "module": "core"
        }
    },
    "data_stream": {
        "dataset": "apache.error",
        "namespace": "default",
        "type": "logs"
    },
    "event": {
        "category": ["web"],
        "dataset": "apache.error",
        "kind": "event",
        "module": "apache",
        "type": ["error"]
    },
    "file": {
        "path": "/var/www/html/wp-admin"
    },
    "log": {
        "level": "error"
    },
    "message": "File does not exist: /var/www/html/wp-admin",
    "process": {
        "pid": 12345,
        "thread": {"id": 140234567890123}
    },
    "source": {
        "address": "198.51.100.15",
        "ip": "198.51.100.15"
    },
    "tags": ["apache-error"]
}
```

## File Structure

```
web-apache/
  generator.yml                              # Pipeline configuration
  README.md                                  # This file
  templates/
    access-success.json.jinja               # 2xx/304 — pages, static assets, API
    access-redirect.json.jinja              # 301/302 redirects
    access-client-error.json.jinja          # 4xx errors (correlates with error log)
    access-server-error.json.jinja          # 5xx errors (correlates with error log)
    access-bot.json.jinja                   # Search engine crawler traffic
    error-file-not-found.json.jinja         # "File does not exist" errors
    error-notice.json.jinja                 # Server operational notices
    error-module.json.jinja                 # Module warnings and errors
  samples/
    urls.json                               # 40 URL paths with content types
    user_agents.json                        # 20 browser + bot User-Agent strings
```

## References

- [Apache HTTP Server Documentation](https://httpd.apache.org/docs/2.4/)
- [Apache Log Format](https://httpd.apache.org/docs/2.4/logs.html)
- [Elastic Apache Integration](https://github.com/elastic/integrations/tree/main/packages/apache)
- [Elastic Common Schema (ECS)](https://www.elastic.co/guide/en/ecs/current/index.html)
- [Filebeat Apache Module](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-module-apache.html)

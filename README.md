# Content Packs for Eventum

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

Ready-to-use generator projects for [Eventum](https://github.com/eventum-generator/eventum) that produce realistic synthetic events mimicking real SIEM data sources. Each generator outputs **ECS-compatible JSON** that can be ingested directly into Elasticsearch, OpenSearch, or any SIEM platform.

## Quick Start

### With Docker (recommended)

```bash
git clone https://github.com/eventum-generator/content-packs.git
cd content-packs
docker compose up -d
```

This starts the Eventum server on port **9474** with all generators available. Manage instances through the [REST API](https://eventum.run/en/docs/api) at `http://localhost:9474`.

### With CLI

```bash
# Install Eventum
uv tool install eventum-generator

# Clone this repository
git clone https://github.com/eventum-generator/content-packs.git
cd content-packs

# Run a generator (outputs to generators/windows-security/output/events.json)
eventum generate \
  --path generators/windows-security/generator.yml \
  --id winlog \
  --live-mode
```

Events are written to `output/events.json` inside the generator directory as JSON, one per line:

```json
{
    "@timestamp": "2026-02-21T12:00:01.234567+00:00",
    "event": {
        "action": "logged-in",
        "category": ["authentication"],
        "code": "4624",
        "kind": "event",
        "outcome": "success"
    },
    "user": {
        "domain": "CONTOSO",
        "name": "jsmith"
    },
    "winlog": {
        "channel": "Security",
        "event_id": "4624",
        "logon": { "type": "Network" }
    }
}
```

## Available Generators

Each generator directory contains a `README.md` with event types covered, parameters, usage examples, and sample output.

## Repository Structure

```text
content-packs/
├── config/
│   ├── eventum.yml              # Eventum server configuration
│   └── startup.yml              # Generator instance startup config
├── generators/
│   └── <category>-<source>/     # e.g. windows-security
│       ├── generator.yml        # Pipeline config (input → event → output)
│       ├── README.md            # Data source docs, parameters, usage
│       ├── templates/           # Jinja2 templates (.json.jinja)
│       ├── samples/             # CSV/JSON data files
│       └── scripts/             # Python scripts (if needed)
├── logs/                        # Runtime log output
├── docker-compose.yml           # Docker Compose for Eventum server
└── LICENSE                      # Apache 2.0
```

Each generator is **self-contained** — all file paths are relative to the generator directory, so generators can be copied, moved, or combined independently.

## Usage

### Single Generator (CLI)

```bash
# Live mode — generates events continuously
eventum generate \
  --path generators/windows-security/generator.yml \
  --id winlog \
  --live-mode

# Batch mode — generates a batch and exits
eventum generate \
  --path generators/windows-security/generator.yml \
  --id winlog \
  --live-mode false
```

Events are written to `output/events.json` inside the generator directory.

### Multiple Generators (Server Mode)

Define instances in `config/startup.yml` and run the server:

```yaml
# config/startup.yml
- id: winlog
  path: windows-security
```

```bash
# With CLI
eventum run

# Or with Docker
docker compose up -d
```

The Docker setup mounts `config/`, `generators/`, and `logs/` into the container. Server configuration lives in `config/eventum.yml`.

### Adjusting Event Rate

Edit the `input` section in any `generator.yml`:

```yaml
input:
  - cron:
      expression: "* * * * * *"
      count: 5    # 5 events/second (~18K/hour)
```

### Output

By default, generators write events to `output/events.json` inside the generator directory. To change the output destination (e.g., OpenSearch, ClickHouse, HTTP), edit the `output` section in `generator.yml`. See the [Eventum documentation](https://eventum.run) for details on available output plugins.

## Realism Techniques

- **Weighted distributions** — Event types, user types, and status codes follow realistic frequency ratios
- **Correlated events** — Shared state tracks active sessions and processes so that logon/logoff and process creation/termination events correlate
- **Sample data** — CSV and JSON files provide realistic usernames, hostnames, process trees, and more
- **Monotonic counters** — Sequential record IDs across all events, matching real log behavior
- **Parameterization** — Hostnames, domains, SIDs, and output connections are configurable without modifying templates

## Contributing

Contributions are welcome! If you've built a generator for your own use case and think others would benefit from it, we'd be happy to include it.

### Generator Conventions

- **Naming**: `<category>-<source>` in lowercase with hyphens (e.g., `linux-auditd`, `web-nginx`)
- **Output format**: ECS-compatible JSON matching [Elastic Integration](https://github.com/elastic/integrations/tree/main/packages) field schemas
- **Templates**: Named as `<event-id-or-type>.json.jinja`
- **Configuration**: Must work out-of-the-box with `eventum generate` (file output to `output/events.json`)
- **Parameterization**: Use `params` for environment-specific values (hostnames, domains, etc.) — never hardcode them in templates
- **Documentation**: Include a `README.md` with event types, parameters, usage examples, and sample output

## References

- [Eventum Documentation](https://eventum.run)
- [Eventum GitHub](https://github.com/eventum-generator/eventum)
- [Elastic Integrations](https://github.com/elastic/integrations/tree/main/packages) — field schemas and event structure reference
- [Elastic Common Schema (ECS)](https://www.elastic.co/guide/en/ecs/current/index.html)

## License

This project is licensed under the [Apache License 2.0](LICENSE).

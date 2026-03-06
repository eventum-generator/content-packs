# CLAUDE.md

This is the **content-packs** repository for [Eventum](https://github.com/eventum-generator/eventum) — ready-to-use generator projects that produce realistic synthetic events mimicking real SIEM data sources. Each generator outputs ECS-compatible JSON matching Elastic integration field schemas.

**Reference**: Field schemas follow [Elastic Integrations](https://github.com/elastic/integrations/tree/main/packages).

## Commands

```bash
# Run a generator (from repo root)
eventum generate --path generators/<name>/generator.yml --id test --live-mode

# Run without live mode (generate a batch and exit)
eventum generate --path generators/<name>/generator.yml --id test --live-mode false
```

## Dependencies

- **Eventum >= 2.0.0** — install with `uv tool install eventum-generator`
- **Python >= 3.14**
- No other dependencies; generators use only Eventum's built-in modules

## Conventions

### Generator naming

- Format: `<category>-<source>` — lowercase, hyphen-separated
- Categories: `windows`, `linux`, `network`, `web`, `cloud`, `security`, `email`, `vpn`, `proxy`, `database`, `identity`

### Template naming

- Format: `<event-id-or-type>.json.jinja`
- Windows: `4624-logon-success.json.jinja`, `4625-logon-failure.json.jinja`
- Linux: `syscall-execve.json.jinja`, `user-auth.json.jinja`
- Web: `access.json.jinja`, `error.json.jinja`

### Output format

- All generators produce **JSON events following ECS (Elastic Common Schema)**
- Top-level fields: `@timestamp`, `event.*`, `host.*`, `user.*`, `process.*`, `source.*`, `destination.*`, `related.*`
- Source-specific fields under their namespace: `winlog.*`, `auditd.*`, `system.*`, `nginx.*`, etc.
- Match the exact field structure from Elastic integration `sample_event.json` files

### Generator design principles

1. **Realistic by default** — weighted distributions for event types, correlated fields, stateful sessions
2. **Performant** — prefer Jinja2 templates over scripts; use `module.rand.*` over Faker for hot paths
3. **Parameterized** — use `${params.*}` for hostnames, domains, IPs; never hardcode environment-specific values
4. **Self-contained** — all paths relative to generator directory; no external dependencies
5. **Composable** — each generator handles one data source; combine via `startup.yml` for multi-source scenarios

### Realism techniques

- **Picking mode**: Choose based on data source behavior — `fsm` for sessions (VPN, auth), `chance` for independent events, `chain` for ordered pairs, `time_patterns` input for time-varying sources. See decision trees in `../eventum/.claude/agents/generator-builder.md`.
- Use `shared` state for cross-template correlation (session pools, record IDs)
- Use `locals` for per-template counters and drift values
- Use `vars` to reuse one template with different bindings when event types share >70% structure
- Use `module.rand.weighted_choice()` for status codes, logon types, protocols
- Use appropriate distributions: `lognormal` for bytes, `exponential` for durations, `gauss` for metrics — never `integer(a,b)` for naturally skewed data
- Use sample CSV/JSON files for usernames, hostnames, process paths, URLs
- Use `time_patterns` input for sources with time-varying frequency (web, auth, email)
- Use macros to DRY shared JSON blocks across templates
- Always include `related.*` fields for SIEM correlation

### generator.yml conventions

```yaml
# Default input: 5 events/second for live mode testing
input:
  - cron:
      expression: "* * * * * *"
      count: 5

# Default output: file with JSON formatter
output:
  - file:
      path: output/events.json
      write_mode: overwrite
      formatter:
        format: json
```

- Every generator.yml must work out-of-the-box with `eventum generate`
- Use `params` for all configurable values with sensible defaults in templates (`params.get('key', 'default')`)
- Include comments in generator.yml explaining each section

### Output parameterization

- Output plugin configs **must** use `${params.*}` and `${secrets.*}` placeholders — never hardcode connection details
- Passwords and tokens use `${secrets.*}` (resolved from Eventum keyring); other values use `${params.*}`
- Document all required params/secrets in the generator's README.md under an "Output Parameters" section

### README.md per generator

Each generator directory must have a README.md with: data source description, event types/IDs covered, required/optional params, usage example, sample output (one complete JSON event), references to real data source docs.

## Agent Architecture

This repo is part of the Eventum agent-orchestrated platform. When running from `../eventum/`, the **Team Lead** (main Claude session) delegates content pack work to specialized agents:

- **generator-builder** — creates/updates generator projects (YAML config, Jinja2 templates, sample data, README). Primary agent for this repo.
- **researcher** — researches data source specs, Elastic integration schemas, event structures before building.
- **qa-engineer** — runs generator validation (sample mode, JSON validity, ECS fields, live mode smoke test).
- **code-reviewer** — reviews template quality, parameterization, realism, README completeness.

All agent definitions live in `../eventum/.claude/agents/`. If working standalone in this repo (not via TL), follow the conventions above directly.

## Git

- Main branch: `master`
- Don't commit unless asked

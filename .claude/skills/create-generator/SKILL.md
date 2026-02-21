---
name: create-generator
description: Create a new Eventum event generator that produces realistic synthetic events mimicking a real SIEM data source. Use when the user wants to implement a new generator for a specific data source (e.g. linux-auditd, web-nginx, network-dns).
disable-model-invocation: true
allowed-tools: Bash, Read, Write, Edit, Grep, Glob, WebSearch, WebFetch
argument-hint: "[data-source-name]"
---

# Create Event Generator

You are building a new Eventum event generator that produces realistic synthetic events mimicking a real SIEM data source.

The user will specify the data source name (e.g. "linux-auditd", "web-nginx"). Use $ARGUMENTS as the generator name if provided.

## Phase 1: Research

Before writing any code, thoroughly research the target data source:

1. **Official specification** — Search for and read the official specification or documentation of the event source:
   - Protocol RFCs (e.g. RFC 5424 for syslog, RFC 5952 for audit)
   - Vendor documentation (e.g. Microsoft Learn for Windows events, man pages for auditd)
   - Log format specifications (e.g. Common Log Format, CEF, LEEF)
   - Event ID catalogs with field descriptions and possible values
   - Investigate real-world log samples from security blogs, DFIR resources, and vendor examples
   - Understand the full lifecycle of events (what triggers them, what fields change between states)

2. **Elastic integration fields** — Fetch the Elastic integrations package for this data source from `https://github.com/elastic/integrations/tree/main/packages/<name>`. Look at:
   - `data_stream/*/fields/*.yml` — field definitions
   - `data_stream/*/sample_event.json` — example documents
   - `data_stream/*/elasticsearch/ingest_pipeline/*.yml` — ECS enrichment pipelines
   - Golden test files in `https://github.com/elastic/beats` for processed event examples

3. **Real event structure** — Cross-reference the specification with the Elastic integration to understand:
   - What event types / IDs exist and their meaning
   - Which fields are present in each event type
   - Realistic value ranges, enumerations, and distributions
   - How events correlate (sessions, parent-child, request-response)
   - Field interdependencies (e.g. a field's value determines which other fields are present)

4. **Frequency distribution** — Determine realistic ratios between event types in production environments. Use security research, SIEM tuning guides, and real-world telemetry data as references.

Present your research findings to the user before proceeding to implementation.

## Phase 2: Implementation

First, read the **Eventum documentation** at `https://eventum.run/llms-full.txt` to understand all available features: input plugins (cron, sample, time_patterns), event plugins (template, script), output plugins (stdout, opensearch, file, etc.), picking modes (chance, fsm, spin, all), and the full template API. This ensures you leverage the right Eventum features for each data source.

Then read the project's `CLAUDE.md` for conventions (naming, parameterization, output format). Also study the existing generators (e.g. `generators/windows-security/`) as reference implementations — but adapt the approach to fit the specific data source. Different sources may need different template structures, sample data shapes, and correlation strategies.

For the full Eventum template API reference (available variables, module.rand, Faker/Mimesis, shared state, samples), see [api-reference.md](api-reference.md).

### Directory structure

```
generators/<category>-<source>/
  generator.yml
  README.md
  templates/                    # Jinja2 templates (.json.jinja)
  samples/                      # CSV (header: true) or JSON sample data
```

### Key decisions to make per data source

Based on your research, decide:

- **Template granularity** — One template per event type? Per event category? Per log format? Choose whatever maps naturally to the data source.
- **Picking mode** — `chance` for independent events with frequency distribution, `fsm` for stateful session flows, `spin` for round-robin, `all` for always-on. Pick what fits the source.
- **Correlation strategy** — Does this source have paired events (start/end, request/response)? Use `shared` state pools if so. Not every source needs correlation.
- **Sample data** — What data needs to vary realistically? Usernames, IPs, URLs, file paths, hostnames? Create CSV for flat lists, JSON for nested structures.
- **Parameterization** — What environment-specific values should be configurable via `params`? Hostnames, domains, network ranges, index names?
- **Performance and stability** — create templates that does not have memory leaks or undefined behavior.
- **Performance and stability** — You can use `module.<any python module>` in templates for complex cases. 

### Correlation via shared state

For event types that naturally pair (create/destroy, start/end), use a capped pool in `shared` state. The producer template appends entries; the consumer template pops them. Always include a fallback for when the pool is empty (generate standalone values). Cap pools to prevent unbounded growth.

### Output requirements

- Events must produce **ECS-compatible JSON** matching the Elastic integration's field structure
- Include `@timestamp` and appropriate ECS fields (`event.*`, `host.*`, etc.)
- Include source-specific namespace fields as discovered during research
- Use `${params.*}` / `${secrets.*}` for output plugin connection details — never hardcode

### README.md

Each generator README must include:
- Data source description
- Table of event types with frequency and category
- Realism features
- Event parameters (with defaults) and output parameters (with variable names)
- Usage example and OpenSearch/startup.yml configuration
- Sample JSON output (one representative event)
- File structure tree
- References to vendor docs and Elastic integration

## Phase 3: Validation

After implementation:
1. Review all templates for valid JSON (no trailing commas, proper quoting)
2. Verify all sample files and template paths referenced in `generator.yml` exist
3. Check that `chance` weights produce a reasonable distribution
4. Ensure shared state is managed consistently (counters incremented, pools capped)
5. Check that generator is working properly by running it (e.g. with `eventum generate`)

## Phase 4: Improvement Proposals

After completing the generator, reflect on the development experience and append any improvement proposals to `eventum` repo in `PROPOSALS.md`. Consider:

- **Template API gaps** — Were there missing `module.rand.*` helpers, timestamp formatters, or filters that you had to work around?
- **Shared state boilerplate** — Did the correlation pool pattern (push/pop/cap/fallback) feel repetitive? Were counters tedious to manage?
- **Generator architecture** — Would a different picking mode or template grouping have been more natural for this data source?
- **Sample data** — Was there anything you couldn't express with the current CSV/JSON sample format?
- **Developer experience** — Were errors hard to debug? Was iteration slow?
- **Other** — any other additions from you.

Only add **new** proposals not already in the file. Each proposal should include: the problem encountered, a concrete example from this generator, and a suggested improvement. Mark with prefix and emoji whether it is a bug or new feature or something other. 

---
name: create-generator
description: Create a new Eventum event generator that produces realistic synthetic events mimicking a real SIEM data source. Use when the user wants to implement a new generator for a specific data source (e.g. linux-auditd, web-nginx, network-dns).
disable-model-invocation: true
allowed-tools: Bash, Read, Write, Edit, Grep, Glob, WebSearch, WebFetch
argument-hint: "[data-source-name]"
---

# Create Event Generator

Build a production-quality Eventum generator — a self-contained project that produces realistic synthetic events mimicking a real SIEM data source. Every generator is unique. Choose the Eventum features, template architecture, and data strategies that best fit this specific source.

The user will specify the data source name (e.g. "linux-auditd", "web-nginx"). Use $ARGUMENTS as the generator name if provided.

**Template API reference**: [api-reference.md](api-reference.md) has the full list of available variables, `module.rand` functions (including statistical distributions), Faker/Mimesis libraries, state management, sample access methods, picking modes, and FSM conditions. Consult it while designing templates.

---

## Phase 1: Research

Before writing any code, deeply understand what you're simulating.

### What to research

1. **Official specification** — Protocol RFCs, vendor docs (Microsoft Learn, man pages), log format specs (CLF, CEF, LEEF), event ID catalogs with field descriptions and possible values. Investigate real-world samples from security blogs, DFIR resources, and vendor examples. Understand the full lifecycle of events.

2. **Elastic integration** — Fetch from `https://github.com/elastic/integrations/tree/main/packages/<name>`:
   - `data_stream/*/fields/*.yml` — field definitions
   - `data_stream/*/sample_event.json` — this is your ground truth for JSON structure
   - `data_stream/*/elasticsearch/ingest_pipeline/*.yml` — ECS enrichment pipelines
   - Golden test files in `https://github.com/elastic/beats` for processed examples

3. **Event structure** — Cross-reference specs with Elastic integration: what event types exist, which fields belong to each, realistic value ranges and enumerations, how events correlate (sessions, parent-child, request-response), field interdependencies.

4. **Frequency distribution** — Real production ratios between event types. Use security research, SIEM tuning guides, telemetry data.

### Research deliverable

Present to the user before proceeding:
- Table of event types with frequencies and ECS categories
- Key field interdependencies and correlation patterns
- Proposed architecture (template count, picking mode, shared state strategy)
- Which Eventum features you plan to leverage and why

---

## Phase 2: Learn Eventum

Read these resources (in this order — most important first):

1. **[api-reference.md](api-reference.md)** — Comprehensive template API: all variables, `module.rand` (including statistical distributions), Faker/Mimesis, state management, samples, picking modes, FSM conditions. This is your primary reference for building templates.

2. **`CLAUDE.md`** in this repo — Conventions for naming, parameterization, output format, generator.yml structure.

3. **Specific doc pages** — Fetch only what you need from `https://eventum.run/llms.mdx/docs/<path>/` (individual page markdown). Key pages:
   - `plugins/event/template` — Template plugin deep dive (context, modules, samples, state, picking modes)
   - `plugins/input/cron` / `time-patterns` / etc. — Input plugins (for choosing scheduling strategy)
   - `plugins/output/opensearch` / `stdout` / etc. — Output plugins (for output section)
   - `core/config/generator-yml` — Generator config reference
   - Use `https://eventum.run/llms.txt` (lightweight index) to discover other pages if needed

   **Do NOT fetch `llms-full.txt`** — it dumps the entire site and wastes context. Fetch specific pages instead.

Study 2-3 existing generators in `generators/` to understand what's been done. When choosing Eventum features for your generator, pick what fits the data source best — but be aware of the full toolkit. If `fsm` mode is the natural fit for a session-based source, use it even if existing generators haven't. If `lognormal` distribution better models your byte counts than `integer(a, b)`, use it. The best generator is one that uses the right features for the job, which naturally leads to variety across the repository.

---

## Phase 3: Design

Think through the architecture before writing templates. Each data source is different — the design should reflect that.

### Directory structure

```
generators/<category>-<source>/
  generator.yml              # Pipeline config (input → event → output)
  README.md                  # Documentation
  templates/                 # Jinja2 templates (.json.jinja)
  samples/                   # CSV (header: true) or JSON sample data
```

### Design decisions

These are the choices that shape the generator. There's no single right answer — pick what fits naturally:

- **Host cardinality** — Decide whether this generator simulates a data stream from a single host or from many hosts. This must reflect how the data source actually appears in a SIEM:

  - **Multi-host** (endpoint agents, per-machine logging): Windows event logs (Security, Sysmon, PowerShell), Linux auditd, EDR agents, endpoint AV — these are installed on every workstation and server. A SIEM typically ingests from dozens to hundreds of endpoints. Use a `hosts.csv` sample file with realistic hostnames, IPs, and OS versions, and pick a random host per event.
  - **Single-host** (centralized infrastructure): Firewalls, web servers, mail servers, DNS servers, IDS/IPS sensors, VPN concentrators, wireless controllers — these are dedicated appliances or servers where one instance serves the whole network. Use a fixed `hostname` parameter. The generator represents one appliance's log stream.

  Think about the real deployment: "If I walked into a SOC and looked at this data source in Splunk/Elastic, would I see events from one box or hundreds?" Match that. If unsure, research typical deployment architectures for the source. For multi-host sources, the sample `hosts.csv` should contain a realistic fleet (e.g., mix of workstations and servers with appropriate naming conventions).

- **Template granularity** — One per event type? Per category? One shared template with `vars` for variations? The answer depends on how much structure the event types share.

- **Picking mode** — `chance` for frequency-weighted independent events. `fsm` for stateful session flows. `spin` for deterministic cycling. `all` for multi-event sources. `chain` for ordered sequences. Think about what the data source actually does — does it have sessions? State transitions? Independent events?

- **Correlation strategy** — Not every source needs it. But if events naturally pair (start/end, request/response, create/destroy), plan how they'll share state. Pools, counters, session IDs.

- **Sample data** — CSV for flat lists. JSON for nested structures. Include `weight` columns for weighted picking where distributions matter. Think about what should be configurable via samples vs what can be procedurally generated.

- **Data generation strategy** — Mix `module.rand` (fast, for hot paths), Faker/Mimesis (realistic, for names/emails/agents), samples (structured, for domain-specific data), and statistical distributions (for realistic metrics/durations/bytes).

- **Parameterization** — Everything environment-specific goes in `params`. Hostnames, domains, network ranges, agent versions, ECS version. Include sensible defaults so the generator works out-of-the-box.

### Eventum features to consider

The template API is rich. Don't limit yourself to the basics:

| Feature | When It Shines |
|---|---|
| `chance` mode | Most event sources — weighted random selection |
| `fsm` mode | Session-based sources (login→activity→logout, TCP lifecycle) |
| `vars` per template | Event types sharing 90% structure, differing in a few fields |
| `samples.weighted_pick('weight')` | Sample data with built-in frequency distribution |
| `module.rand.number.lognormal()` | Byte counts, file sizes — always positive, right-skewed |
| `module.rand.number.exponential()` | Session durations, inter-arrival times — most short, some very long |
| `module.rand.number.gauss()` | Metrics clustering around a mean (response times) |
| `module.rand.number.pareto()` | Extremely skewed data (network flow sizes) |
| `module.rand.chance(prob)` | Branching without generating unused alternatives |
| `module.faker.*` / `module.mimesis.*` | Realistic names, emails, user agents, URLs. [Full docs](https://faker.readthedocs.io/en/master/providers.html) / [Mimesis docs](https://mimesis.name/en/master/api.html) |
| `locals` state | Per-template counters, value drift, gradual metric changes |
| `shared` state | Cross-template correlation pools, monotonic IDs, session tracking |
| `globals` state | Cross-generator coordination (rare but powerful) |
| Jinja2 macros/imports | Reusable blocks to eliminate boilerplate across templates |
| `module.<any_python_package>` | hashlib, base64, datetime, ipaddress — any stdlib or installed package |
| `subprocess.run()` | Shell commands during generation (use sparingly) |

---

## Phase 4: Implementation

### generator.yml conventions

```yaml
# Default input: 5 events/second for live-mode testing
input:
  - cron:
      expression: "* * * * * *"
      count: 5

event:
  template:
    mode: chance    # Choose the mode that fits your source
    params:
      # All configurable values with sensible defaults
    samples:
      # All data files with explicit type
    templates:
      # Event types with frequency weights

# Output: file-based for portability
output:
  - file:
      path: output/events.json
      write_mode: overwrite
      formatter:
        format: json
```

Every generator.yml must work out-of-the-box with `eventum generate`.

### Template quality guidelines

These aren't strict rules — they're awareness of patterns that lead to better generators:

**Eliminate unnecessary repetition.** If every template starts with the same 30-line agent/ecs/host block, extract it. Jinja2 macros (`{% macro %}`) and imports (`{% from '_base.json.jinja' import ... %}`) are one approach. Using `vars` to share a template is another. Sometimes a small amount of duplication is fine if it keeps templates self-contained and readable. Use your judgment.

**Parameterize environment-specific values.** Hostnames, domains, ECS version, agent version, interface names, zone names — these shouldn't be hardcoded in templates. Put them in `params` with defaults, or in sample files. The generator should work in any environment by changing `params`.

**Use the right tool for the data.**
- `samples.weighted_pick('weight')` — when sample data has natural frequency distributions. This is cleaner than manually building parallel arrays for `weighted_choice()`.
- `module.rand.chance(0.3)` with if/else — when you need probability branching. Avoids generating both options and throwing one away.
- Statistical distributions — byte counts, durations, latencies aren't uniform in real systems. `lognormal`, `exponential`, `pareto` produce more realistic patterns.
- Faker/Mimesis — when you need realistic contextual data (names, emails, user agents). Slower than `module.rand`, so use for variety, not on every field.

**Manage shared state carefully.** Cap pool sizes (and make the cap configurable via params). Wrap counters to prevent unbounded integer growth. Always provide fallbacks for when pools are empty. Document what each shared state key is for.

**Produce valid, consistent JSON.** Always include required ECS fields. Don't leave optional fields inconsistent (sometimes present, sometimes missing) — either always include them or use `null`. Test that output is valid JSON.

**Keep templates readable.** Comment non-obvious magic numbers (port ranges, protocol IDs). Keep logic flow clear. If a template grows unwieldy, consider whether macros, `vars`, or splitting would help.

### ECS output requirements

- Match the Elastic integration's `sample_event.json` field structure
- Always include: `@timestamp`, `agent.*`, `ecs.version`, `event.*` (action, category, code, kind, module, outcome, type), `host.*`
- Include `related.*` arrays (ip, user, hash) for cross-referencing
- Include source-specific namespace fields (e.g. `winlog.*`, `dns.*`, `http.*`)
- Output goes to `output/events.json` via the file output plugin

---

## Phase 5: Validation

### Correctness

- All templates produce valid JSON (no trailing commas, no conditional gaps)
- All sample/template paths in `generator.yml` exist
- `chance` weights produce a realistic distribution
- Shared state pools are capped and consumers have fallbacks
- Parameters have sensible defaults — generator works out-of-the-box

### Runtime test

```bash
# 1. Generate a batch (output goes to generators/<name>/output/events.json)
#    Use -vvvvv to surface any template errors (missing variables, Jinja2 syntax, etc.)
# This can generate many events because live mode is disabled! Events will be generated as fast as possible. Recommended to use short timeouts.
eventum generate \
  --path generators/<name>/generator.yml \
  --id test \
  --live-mode false \
  -vvvvv

# 2. Validate output: JSON syntax + has required ECS fields
python3 -c "
import json, sys

path = 'generators/<name>/output/events.json'
required_keys = {'@timestamp', 'event', 'ecs'}

with open(path) as f:
    lines = [l.strip() for l in f if l.strip()]

if not lines:
    print(f'FAIL: {path} is empty — no events generated')
    sys.exit(1)

for i, line in enumerate(lines, 1):
    try:
        doc = json.loads(line)
    except json.JSONDecodeError as e:
        print(f'FAIL: Invalid JSON on line {i}: {e}')
        sys.exit(1)
    missing = required_keys - doc.keys()
    if missing:
        print(f'FAIL: Line {i} missing required ECS keys: {missing}')
        sys.exit(1)

print(f'OK: {len(lines)} events, all valid JSON with required ECS fields')
"

# 3. Live mode smoke test
timeout 5 eventum generate \
  --path generators/<name>/generator.yml \
  --id test \
  --live-mode \
  -vvvvv || true
```

**Debugging failures**: If the generator produces 0 events or errors silently, always run with `-vvvvv` and check stderr. Common causes: missing sample files, undefined template variables, invalid Jinja2 syntax.

### Meaningful result

We can look at results in generated file to understand whether the structure of event is proper for this data source.

### Self-review

Before presenting to the user, check your work against these common problems found in existing generators:

| Problem | Check |
|---|---|
| Duplicated boilerplate across templates | Could macros, imports, or `vars` reduce it? |
| Hardcoded values in templates | Should they be in `params` or samples? |
| Manual weight-building loops | Could `weighted_pick('weight')` replace them? |
| Generating unused alternatives | Could `module.rand.chance()` + if/else avoid waste? |
| Uniform distributions for everything | Would `lognormal`/`exponential` be more realistic? |
| Unbounded counters or pools | Are they capped and wrapped? |
| Empty pool with no fallback | What happens when consumers read from an empty pool? |
| Feature fit | Are you using the Eventum features that best match this data source's characteristics? |

---

## Phase 6: README.md

Each generator needs clear documentation:

1. **Data source description** — what system/service, version, log format
2. **Event types table** — event ID/type, description, frequency (%), ECS category
3. **Realism features** — techniques used (correlation, distributions, weighted data)
4. **Parameters** — all `params` with defaults and descriptions
5. **Output parameters** — `${params.*}` and `${secrets.*}` for output plugins
6. **Usage** — `eventum generate` command and startup.yml example
7. **Sample output** — one complete representative JSON event
8. **File structure** — tree of all files
9. **References** — vendor docs, Elastic integration links

---

## Phase 7: Improvement Proposals

After completing the generator, create GitHub issues for improvements discovered during development:

- Template API gaps — missing helpers or filters you had to work around?
- Shared state boilerplate — was the pool pattern tedious?
- Generator architecture — would a different mode or structure have been more natural?
- Sample data limitations — anything you couldn't express with current formats?
- Developer experience — errors hard to debug? Iteration slow?

First check existing issues: `gh issue list --repo eventum-generator/eventum --limit 100 --state open`.

```bash
gh issue create \
    --repo eventum-generator/eventum \
    --title "<concise title>" \
    --body "<problem + concrete example from this generator + proposed solution>" \
    --project "Task tracker"
```

After creating each issue, set project fields:

```bash
NODE_ID=$(gh api graphql -f query='query { repository(owner: "eventum-generator", name: "eventum") { issue(number: ISSUE_NUM) { id } } }' --jq '.data.repository.issue.id')

# Set issue type (Bug: IT_kwDOCiUXlc4BVM0Y, Feature: IT_kwDOCiUXlc4BVM0Z)
gh api graphql -f query="mutation { updateIssue(input: { id: \"$NODE_ID\" issueTypeId: \"TYPE_ID\" }) { issue { id } } }" --silent

ITEM_ID=$(gh api graphql -f query='query { node(id: "'"$NODE_ID"'") { ... on Issue { projectItems(first: 10) { nodes { id project { id } } } } } }' --jq '.data.node.projectItems.nodes[] | select(.project.id == "PVT_kwDOCiUXlc4BP0JC") | .id')

# Priority (High: 79628723, Medium: 0a877460, Low: da944a9c)
gh api graphql -f query="mutation { updateProjectV2ItemFieldValue(input: { projectId: \"PVT_kwDOCiUXlc4BP0JC\" itemId: \"$ITEM_ID\" fieldId: \"PVTSSF_lADOCiUXlc4BP0JCzg-HXEM\" value: { singleSelectOptionId: \"PRIORITY_ID\" } }) { projectV2Item { id } } }" --silent

# Component (Core: 73c7da0c, Plugins: b0be8b34, API/CLI: a93c596c, Other: 79a07051)
gh api graphql -f query="mutation { updateProjectV2ItemFieldValue(input: { projectId: \"PVT_kwDOCiUXlc4BP0JC\" itemId: \"$ITEM_ID\" fieldId: \"PVTSSF_lADOCiUXlc4BP0JCzg-HX4I\" value: { singleSelectOptionId: \"COMPONENT_ID\" } }) { projectV2Item { id } } }" --silent

# Size (XS: 6c6483d2, S: f784b110, M: 7515a9f1, L: 817d0097, XL: db339eb2)
gh api graphql -f query="mutation { updateProjectV2ItemFieldValue(input: { projectId: \"PVT_kwDOCiUXlc4BP0JC\" itemId: \"$ITEM_ID\" fieldId: \"PVTSSF_lADOCiUXlc4BP0JCzg-HXEQ\" value: { singleSelectOptionId: \"SIZE_ID\" } }) { projectV2Item { id } } }" --silent

# Status to Backlog (f75ad846)
gh api graphql -f query="mutation { updateProjectV2ItemFieldValue(input: { projectId: \"PVT_kwDOCiUXlc4BP0JC\" itemId: \"$ITEM_ID\" fieldId: \"PVTSSF_lADOCiUXlc4BP0JCzg-HW5U\" value: { singleSelectOptionId: \"f75ad846\" } }) { projectV2Item { id } } }" --silent
```

---

## Important

- Do NOT commit or push unless the user explicitly asks. When committing, use conventional commits: `feat:`, `fix:`, etc.
- Track progress with the todo list throughout.
- If blocked or uncertain, ask the user rather than guessing.
- When done, check in with the user before creating improvement issues.

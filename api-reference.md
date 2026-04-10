# Template API Reference

Quick reference for variables and functions available inside `.jinja` templates. For full documentation, see the [Eventum docs](https://eventum.run/en/docs/plugins/event/template).

## Context Variables

| Variable | Type | Description |
|----------|------|-------------|
| `timestamp` | `datetime` | Timezone-aware datetime of the current event. |
| `tags` | `tuple[str, ...]` | Tags from the input plugin that produced this timestamp. |
| `module` | module provider | Gateway to data-generation libraries (`module.rand.*`, `module.faker.*`, `module.mimesis.*`) and any Python module. |
| `params` | `dict` | User-defined constant parameters from the `params` config field. |
| `vars` | `dict` | Per-template variables from the `vars` config field. |
| `samples` | sample reader | Named datasets from the `samples` config field. |
| `locals` | state | Per-template state that persists across renders. |
| `shared` | state | State shared across all templates in one generator. |
| `globals` | state | State shared across all generators (thread-safe). |
| `dispatch` | dispatch API | Control event flow: `dispatch.drop()`, `dispatch.next()`, `dispatch.exhaust()`. |
| `subprocess` | subprocess runner | Execute shell commands via `subprocess.run()`. |

## State Methods

All state scopes (`locals`, `shared`, `globals`) provide these methods:

| Method | Signature | Description |
|--------|-----------|-------------|
| `get` | `(key, default=None) -> Any` | Get a value. |
| `set` | `(key, value) -> None` | Set a value. |
| `pop` | `(key, default=None) -> Any` | Remove and return a value. |
| `update` | `(mapping) -> None` | Set multiple values from a dict. |
| `clear` | `() -> None` | Remove all values. |
| `as_dict` | `() -> dict` | Get a shallow copy of the state. |

## Dispatch Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `dispatch.drop` | `() -> Never` | Drop all output for this timestamp. Returns `[]`. |
| `dispatch.next` | `(max_repicks=64) -> Never` | Discard output and restart with a fresh pick. |
| `dispatch.exhaust` | `() -> Never` | Signal generation is complete; generator shuts down. |

## Module Packages

| Package | Description |
|---------|-------------|
| `module.rand.*` | Random data generation (integers, floats, choices, UUIDs, IPs). |
| `module.faker.*` | Faker-based realistic data (names, addresses, etc.). |
| `module.mimesis.*` | Mimesis-based realistic data. |
| `module.<package>.*` | Any installed Python package via dynamic import. |

# Generator validation tools

Checks for the anomaly chain of a content-pack generator, run on captures of its output. A capture is a JSON-lines file (`.jsonl` or `.jsonl.gz`) produced with `--live-mode false --keep-order true` over a finite window.

| Tool | What it answers |
|---|---|
| `quickaccept.py SPEC --off OFF... --on ON...` | Complete chains in every capture (off must be 0), every chain step present in each off capture, and every chain key that completed a chain in an on capture also present in each off capture. Exit 1 on any miss. |
| `allbind_chains.py SPEC CAPTURE...` | Complete chains per capture with every binding kept alive (no caps, no reset on completion) - the strict count. In an on capture it must equal the number of episodes. |
| `mode_compare.py calibrate` / `compare` | Optional deep comparison of on and off captures (per-actor counts, gaps, rotations, lockstep, holds). `python mode_compare.py --help`. |

Run them with the Eventum environment, from the repository root:

```bash
uv run --project ../eventum python tools/quickaccept.py tools/specs/<name>.json --off off1.jsonl off2.jsonl --on on1.jsonl on2.jsonl
uv run --project ../eventum python tools/allbind_chains.py tools/specs/<name>.json on1.jsonl on2.jsonl
```

`quickaccept.py` checks only the spec key. When that key is a single field (a user) or a random ID (a session, an incident), check the presence of each actor and actor pair an episode can use yourself.

## Specs

One spec per generator in `specs/<name>.json`. It describes the chain the way a detector would see it. Update it in the same PR as the generator whenever the chain changes.

Minimal spec:

```json
{
 "timestamp": {"path": "@timestamp"},
 "actors": [{"name": "user", "path": "user.name"}],
 "action": {"paths": ["event.action"]},
 "chain_seq": {
  "key": {"path": "source.ip"},
  "within": 3600,
  "steps": [
   {"match": {"path": "event.action", "values": ["role-created"]}, "bind": {"R": "user.target.name"}},
   {"match": {"path": "event.action", "values": ["role-granted"]}, "eq": {"R": "user.target.name"}},
   {"match": {"path": "event.action", "values": ["role-deleted"]}, "eq": {"R": "user.target.name"}}
  ]
 }
}
```

Paths are dotted (`event.action`); a literal key containing dots (`@timestamp`) is tried first.

| Field | Meaning |
|---|---|
| `timestamp` | `{"path": ...}` - ISO 8601, epoch seconds or milliseconds; optional `format` (strptime) and `regex`. |
| `actors` | Actor keys `{"name", "path" \| "paths", "regex"?, "when"?, "target"?}`; `paths` joins values with `\|`, `regex` keeps group 1, `when` restricts the key to matching rows. Required; used by `mode_compare.py`. |
| `action` | `{"paths": [...]}` - the event type. |
| `target` | Optional `{"paths": [...]}` - the object acted on. |
| `include` | Condition; rows that fail it are ignored. |
| `failure`, `success` | Conditions for failed and successful attempts (used by `mode_compare.py`). |
| `chain_seq` | The chain: `{"key": actor-spec, "same": [paths], "within": seconds, "steps": [...]}`. A step is `{"match": cond, "bind": {"A": path}, "eq": {"A": path}, "ne": {"A,B": path}}`: `bind` stores a value, `eq` requires the stored value, `ne` requires distinct values. Steps may skip unrelated rows of the key. `within` counts from the first step. |
| `pairs` | Lifecycles `[{"name", "key", "open": cond, "close": cond}]` (e.g. role create/drop), for hold durations in `mode_compare.py`. |
| `features` | Extra ordered sequences with `chain_seq` syntax, counted as near misses by `mode_compare.py`. |

Conditions: `{"path": p, "values": [...]}` or `{"path": p, "regex": r}` (a list value matches if any element matches; `"missing": true` matches an absent field), combined with `{"any": [...]}`, `{"all": [...]}` and `{"not": cond}`.

Write the chain exactly as a detector would: the linking key, same-target constraints through `bind`/`eq`, distinct values through `ne`, and a window a little above the generator's episode span.

"""Uncapped, all-bindings chain matcher over a mode_compare spec.

Unlike mode_compare.SeqMatcher, a row that advances a partial match
keeps the unadvanced copy too (every candidate run and binding stays
alive), no partial is dropped by a cap, and a completion does not reset
the key (unlike the spec matcher), so a later row that completes a
chain together with rows of an earlier chain counts too. Partials
expire `within` seconds after their first step. A row counts once
however many partials it completes.
Usage: allbind_chains.py SPEC CAPTURE [...]
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mode_compare as mc  # noqa: E402


def chains(spec_path, capture):
    """Return [(t_first, t_last, key)], one per completing row."""
    spec = mc.compile_spec(json.load(open(spec_path)))
    seq = spec['chain_seq']
    steps, within = seq['steps'], seq['within']
    keyer = mc.SeqMatcher(steps, within, seq['_key'], seq.get('same', ()))
    state, found = {}, []
    with mc.open_capture(capture) as fh:
        for raw in fh:
            obj = json.loads(raw)
            if spec['_include'] is not None and not mc.matches(
                    obj, spec['_include']):
                continue
            k = keyer._key(obj)
            if k is None:
                continue
            t = mc.parse_ts(mc.extract(obj, spec['timestamp']))
            parts = [p for p in state.get(k, ()) if t - p[1] <= within]
            new, seen, done = [], set(), None
            for st, t0, binds in parts:
                sig = (st, t0, tuple(sorted(binds.items())))
                if sig not in seen:
                    seen.add(sig)
                    new.append((st, t0, binds))
                if st == len(steps):
                    continue
                nb = mc.SeqMatcher._step_ok(steps[st], obj, binds)
                if nb is None:
                    continue
                if st + 1 == len(steps):
                    if done is None or t0 < done[0]:
                        done = (t0, t, k)
                    continue
                sig = (st + 1, t0, tuple(sorted(nb.items())))
                if sig not in seen:
                    seen.add(sig)
                    new.append((st + 1, t0, nb))
            if done:
                found.append(done)
            nb = mc.SeqMatcher._step_ok(steps[0], obj, {})
            if nb is not None:
                if len(steps) == 1:
                    found.append((t, t, k))
                else:
                    new.append((1, t, nb))
            if new:
                state[k] = new
            else:
                state.pop(k, None)
    return found


if __name__ == '__main__':
    for path in sys.argv[2:]:
        print(path, 'allbind_uncapped_chains', len(chains(sys.argv[1], path)))

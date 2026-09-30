"""Simplified-acceptance checks over a mode_compare spec, in one pass.

For every capture it counts complete chains with the uncapped
all-bindings matcher. For every off capture it also checks that each
chain step occurs in ordinary traffic and that every key (actor or
actor pair) that completed a chain in an on capture also appears there.
Episode counts come from the pack's own checker; compare them with the
chain counts printed here.

Usage: quickaccept.py SPEC --off OFF [OFF ...] --on ON [ON ...]
Exit status 1 when an off capture holds a chain, misses a chain step,
or misses a key used by an on-capture chain.
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import allbind_chains  # noqa: E402
import mode_compare as mc  # noqa: E402


def scan(spec, path):
    """Return the set of keys and per-step match counts of a capture."""
    seq = spec['chain_seq']
    steps = seq['steps']
    keyer = mc.SeqMatcher(steps, seq['within'], seq['_key'],
                          seq.get('same', ()))
    keys, step_hits = set(), [0] * len(steps)
    with mc.open_capture(path) as fh:
        for raw in fh:
            obj = json.loads(raw)
            if spec['_include'] is not None and not mc.matches(
                    obj, spec['_include']):
                continue
            k = keyer._key(obj)
            if k is None:
                continue
            keys.add(k)
            for i, step in enumerate(steps):
                if mc.SeqMatcher._step_ok(step, obj, {}) is not None:
                    step_hits[i] += 1
    return keys, step_hits


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('spec')
    ap.add_argument('--off', nargs='+', required=True)
    ap.add_argument('--on', nargs='+', required=True)
    args = ap.parse_args()

    spec = mc.compile_spec(json.load(open(args.spec)))
    report, bad = {'on': {}, 'off': {}}, False

    chain_keys = set()
    for path in args.on:
        found = allbind_chains.chains(args.spec, path)
        chain_keys |= {k for _, _, k in found}
        report['on'][path] = {'chains': len(found)}

    for path in args.off:
        found = allbind_chains.chains(args.spec, path)
        keys, hits = scan(spec, path)
        missing_keys = sorted(map(str, chain_keys - keys))
        missing_steps = [i for i, n in enumerate(hits) if n == 0]
        report['off'][path] = {
            'chains': len(found),
            'step_hits': hits,
            'missing_steps': missing_steps,
            'missing_chain_keys': missing_keys,
        }
        bad |= bool(found or missing_steps or missing_keys)

    report['chain_keys_in_on'] = len(chain_keys)
    report['ok'] = not bad
    print(json.dumps(report, indent=1, ensure_ascii=False))
    sys.exit(1 if bad else 0)


if __name__ == '__main__':
    main()

"""Check that every record of a smoke capture is one JSON object.

    python3 check_capture.py RESULT.json

RESULT.json is the JSON printed by `capture.py one`; its `capture` key
names the gzipped JSON Lines file. Exit 1 when the capture is missing,
empty, or holds a line that is not a JSON object.

Standard library only; Python 3.9+.
"""

import gzip
import json
import sys

SHOWN = 5  # bad lines reported


def main(argv):
    if len(argv) != 1:
        print(__doc__.strip())
        return 2
    with open(argv[0], encoding='utf-8') as fh:
        result = json.load(fh)
    path = result.get('capture')
    if not path:
        print('::error::the smoke run produced no capture: %s' % json.dumps(result))
        return 1
    records, bad = 0, []
    with gzip.open(path, 'rt', encoding='utf-8', errors='replace') as fh:
        for n, line in enumerate(fh, 1):
            if not line.strip():
                continue
            records += 1
            try:
                ok = isinstance(json.loads(line), dict)
            except ValueError:
                ok = False
            if not ok:
                bad.append(n)
                if len(bad) <= SHOWN:
                    print('::error::record %d is not a JSON object: %s' % (n, line.strip()[:300]))
    print(json.dumps({'capture': path, 'records': records, 'not_json_objects': len(bad)}))
    return 1 if bad or not records else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))

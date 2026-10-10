"""Generator directories a pull request changes, as a JSON list.

    python3 changed_generators.py --base origin/master [--canary NAME] [NAME ...]

With names, those are checked instead of the diff. Otherwise the names come
from `git diff --name-only BASE...HEAD` under generators/; when nothing
there changed but .github/ did, the canary generator is checked, so a
change to the checks runs them. Only existing directories with safe names
are listed: a deleted generator is skipped.

Standard library only; Python 3.9+.
"""

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

NAME = re.compile(r'[a-z0-9][a-z0-9._-]*')


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--base', required=True, help='base revision, e.g. origin/master')
    ap.add_argument('--canary', help='generator checked when only .github/ changed')
    ap.add_argument('names', nargs='*')
    args = ap.parse_args()
    names = args.names
    if not names:
        changed = subprocess.run(['git', 'diff', '--name-only', args.base + '...HEAD'],
                                 check=True, capture_output=True, text=True).stdout.split('\n')
        names = [p.split('/')[1] for p in changed if p.startswith('generators/') and p.count('/') >= 2]
        if not names and args.canary and any(p.startswith('.github/') for p in changed):
            names = [args.canary]
    found = sorted({n for n in names if NAME.fullmatch(n) and Path('generators', n).is_dir()})
    print(json.dumps(found))
    return 0


if __name__ == '__main__':
    sys.exit(main())

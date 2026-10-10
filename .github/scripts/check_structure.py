"""Structure check of generator directories.

    python3 check_structure.py generators/<name> [generators/<name> ...]

Errors (exit 1):
- generator.yml and README.md are missing;
- a symbolic link anywhere in the directory;
- a root entry outside the conventions (generator.yml, README.md,
  templates/, samples/, patterns/, scripts/), output/ and .content-design/
  included;
- the README does not open with a `#` title followed by a paragraph;
- the README lacks a section on event types (`## Event Types`, `## Events`,
  ...), `## Parameters`, `## Usage` (or `## Run`) or `## Sample Output`;
- the first fenced block under `## Sample Output` is not one JSON object.

Warnings: no `## Limitations` (any heading with "limit") or
`## References` section.

Messages are GitHub workflow commands, readable outside Actions too.
Standard library only; Python 3.9+.
"""

import json
import os
import re
import sys
from pathlib import Path

ROOT_FILES = {'generator.yml', 'README.md'}
ROOT_DIRS = {'templates', 'samples', 'patterns', 'scripts'}
FENCE = re.compile(r'^(\s*)(`{3,}|~{3,})')
# Required sections: (name in messages, predicate on the lower-cased heading).
REQUIRED = [
    ('## Event Types', lambda h: h.startswith('event') or 'types covered' in h),
    ('## Parameters', lambda h: h == 'parameters'),
    ('## Usage', lambda h: h in ('usage', 'run')),
    ('## Sample Output', lambda h: h.startswith('sample output')),
]
RECOMMENDED = [
    ('## Limitations', lambda h: 'limit' in h),
    ('## References', lambda h: h.startswith('references')),
]


def annotate(level, path, message, line=None):
    loc = 'file=%s' % path + (',line=%d' % line if line else '')
    print('::%s %s::%s' % (level, loc, message))


def outline(lines):
    """[(level, text, line index)] of headings outside fenced blocks, and fence spans."""
    heads, fences, open_at, marker = [], [], None, None
    for i, line in enumerate(lines):
        m = FENCE.match(line)
        if m:
            if open_at is None:
                open_at, marker = i, m.group(2)
                continue
            if m.group(2)[0] == marker[0] and len(m.group(2)) >= len(marker) \
                    and not line.strip()[len(m.group(2)):].strip():
                fences.append((open_at, i))
                open_at = None
                continue
        if open_at is None:
            h = re.match(r'^(#{1,6})\s+(.*?)\s*#*\s*$', line)
            if h:
                heads.append((len(h.group(1)), h.group(2), i))
    return heads, fences


def check_readme(path, errors, warnings):
    lines = path.read_text(encoding='utf-8').splitlines()
    heads, fences = outline(lines)
    body = [(i, ln) for i, ln in enumerate(lines) if ln.strip()]
    if not body or not re.match(r'^#\s+\S', body[0][1]):
        errors.append(('README.md must open with a `# Title` line', 1, True))
    elif len(body) < 2 or re.match(r'^\s*(#|```|~~~|\||>|[-*+]\s|\d+\.\s|<)', body[1][1]):
        errors.append(('the README title must be followed by a summary paragraph',
                       body[0][0] + 1, True))
    sections = [(text.lower(), i) for level, text, i in heads if level == 2]
    for name, match in REQUIRED:
        if not any(match(h) for h, _ in sections):
            errors.append(('README.md lacks the section `%s`' % name, None, True))
    for name, match in RECOMMENDED:
        if not any(match(h) for h, _ in sections):
            warnings.append(('README.md lacks the section `%s`' % name, None, True))
    for n, (h, start) in enumerate(sections):
        if not h.startswith('sample output'):
            continue
        end = sections[n + 1][1] if n + 1 < len(sections) else len(lines)
        block = next(((a, b) for a, b in fences if start < a < end), None)
        if block is None:
            errors.append(('`## Sample Output` has no fenced code block', start + 1, True))
            break
        a, b = block
        try:
            value = json.loads('\n'.join(lines[a + 1:b]))
        except ValueError as exc:
            msg = ('the sample under `## Sample Output` holds more than one JSON value: show one event'
                   if str(exc).startswith('Extra data')
                   else 'the sample under `## Sample Output` is not valid JSON: %s' % exc)
            errors.append((msg, a + 1, True))
            break
        if not isinstance(value, dict):
            errors.append(('the sample under `## Sample Output` is not one JSON object', a + 1, True))
        break


def check(gen):
    errors, warnings = [], []
    if not gen.is_dir():
        return [('%s is not a directory' % gen, None, False)], []
    for root, dirs, files in os.walk(gen):
        for name in dirs + files:
            p = Path(root) / name
            if p.is_symlink():
                errors.append(('symbolic link %s: ship a regular file' % p.relative_to(gen), None, False))
    for entry in sorted(gen.iterdir()):
        name = entry.name
        if name == 'output':
            errors.append(('output/ is generated and never shipped', None, False))
        elif name == '.content-design':
            errors.append(('.content-design/ holds design work files and is never shipped', None, False))
        elif name in ROOT_FILES and entry.is_file():
            continue
        elif name in ROOT_DIRS and entry.is_dir():
            continue
        else:
            errors.append(('%s at the generator root is outside the conventions '
                           '(generator.yml, README.md, templates/, samples/, patterns/, scripts/)'
                           % name, None, False))
    for name in sorted(ROOT_FILES):
        if not (gen / name).is_file():
            errors.append(('%s is missing' % name, None, False))
    readme = gen / 'README.md'
    if readme.is_file() and not readme.is_symlink():
        check_readme(readme, errors, warnings)
    return errors, warnings


def main(argv):
    if not argv:
        print(__doc__.strip())
        return 2
    failed = False
    for arg in argv:
        gen = Path(arg)
        errors, warnings = check(gen)
        for level, items in (('error', errors), ('warning', warnings)):
            for msg, line, in_readme in items:
                annotate(level, gen / 'README.md' if in_readme else gen, msg, line)
        print('%s: %d error(s), %d warning(s)' % (gen, len(errors), len(warnings)))
        failed = failed or bool(errors)
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))

"""Public IPv4 literals in a generator's README.md, templates/ and samples/.

    python3 check_public_ips.py generators/<name> [generators/<name> ...]

Generators use private (RFC 1918), loopback and documentation addresses
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24). Any other globally
routable address is reported as a GitHub warning annotation, one per file
with its first line and the addresses found; it may be a real host, or a
deliberate public address (a known resolver, a vendor endpoint) that a
reviewer accepts. Special-purpose ranges that address no public host
(link-local, multicast, shared 100.64.0.0/10, reserved, unspecified,
benchmarking) are not reported, nor are literals that read as versions
rather than hosts: `a.0.0.0`, one right after a slash or backslash (user agents,
file paths), or one shortly after the word version, build or release.
The exit status is always 0.

Standard library only; Python 3.9+.
"""

import ipaddress
import os
import re
import sys
from pathlib import Path

IPV4 = re.compile(r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?!\w|\.\d)')
SHARED = ipaddress.ip_network('100.64.0.0/10')
VERSION_CONTEXT = re.compile(r'version|build|release', re.I)
SHOWN = 8  # addresses listed in one annotation


def version_like(line, m):
    before = line[:m.start()]
    return (m.group().endswith('.0.0.0') or before.endswith(('/', '\\'))
            or bool(VERSION_CONTEXT.search(before[-24:])))


def public(text):
    try:
        ip = ipaddress.IPv4Address(text)
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
                or ip.is_reserved or ip.is_unspecified or ip in SHARED)


def files(gen):
    readme = gen / 'README.md'
    if readme.is_file():
        yield readme
    for sub in ('templates', 'samples'):
        for root, _, names in os.walk(gen / sub):
            for name in sorted(names):
                yield Path(root) / name


def scan(path):
    """{address: first line number}"""
    found = {}
    try:
        text = path.read_text(encoding='utf-8', errors='replace')
    except OSError:
        return found
    for n, line in enumerate(text.splitlines(), 1):
        for m in IPV4.finditer(line):
            if m.group() not in found and public(m.group()) and not version_like(line, m):
                found[m.group()] = n
    return found


def main(argv):
    total = 0
    for arg in argv:
        for path in files(Path(arg)):
            found = scan(path)
            if not found:
                continue
            total += len(found)
            addrs = sorted(found, key=found.get)
            more = ' and %d more' % (len(addrs) - SHOWN) if len(addrs) > SHOWN else ''
            print('::warning file=%s,line=%d,title=Public IPv4 address::%s%s: use RFC 1918 or '
                  'documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) unless '
                  'the address is deliberate' % (path, found[addrs[0]], ', '.join(addrs[:SHOWN]), more))
    print('%d public IPv4 address(es) found' % total)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))

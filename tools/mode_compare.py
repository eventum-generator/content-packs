"""Calibrated on/off mode comparison for Eventum content-pack captures.

Proves that anomaly_mode=true and anomaly_mode=false captures of one
generator are indistinguishable except through the full anomaly chain.
Supersedes mode_separability_probe.py; its specs remain valid input.

Commands:
    mode_compare.py calibrate --spec S --off a.jsonl b.jsonl ... --out C
        [--split B]
    mode_compare.py compare --spec S --calib C --on x.jsonl --off y.jsonl
        [--out report.json]

Exit codes of compare: 0 OK, 1 SUSPECT, 2 FAIL, 3 usage/input error.

Two kinds of checks:

- comparative: one test per statistic, on capture against the pooled
  off reference (the calibration captures plus --off).  Raw p-values
  are rescaled by the per-statistic inflation measured on off-vs-off
  leave-one-out comparisons during calibration, converted with a
  Student t, and Holm-adjusted across all statistics.  When the spec
  defines the chain, every statistic also gets a precision view: how
  well its instances alone locate the chain occurrences.
- absolute: determinism of the off background itself (rotations,
  lockstep, fixed periods and durations, constants), judged against
  chance models of the same capture.

See tools/README.md for the spec format.
Files are streamed; state is bounded by actors, fields, capped
heaps (HEAP_L), reservoirs (RES_R) and capped instance lists.
"""

import argparse
import gzip
import hashlib
import heapq
import json
import math
import os
import random
import re
import sys
import zlib
from collections import Counter, deque
from datetime import datetime, timezone

try:
    import msgspec

    _decode = msgspec.json.decode
except ImportError:  # pragma: no cover
    _decode = json.loads

VERSION = 1
WINDOWS = [60, 300, 600, 1800, 3600]
FAIL_WINDOWS = [60, 300, 3600]
SAME_ACTION_WINDOWS = [60, 600]
HEAP_L = 2000
RES_R = 1500
MAX_TRANS = 60000
MAX_CAT = 20000
CAT_INST = 5
MAX_WAVE_TIMES = 300000
ALPHA_FAIL = 0.01
ALPHA_SUSPECT = 0.10
PRIOR_DF = 4
GIVEUP_S = 600
SEQ_LEN = 40
RR_MAX_K = 200
WAVE_BUCKET_S = 1800
EMPTY_BUCKET_S = 600
PHASE_BINS = 12
PHASE_PERIODS = [600, 1200, 3600]
TOP_ACTIONS = 12
CLASSES = ['cooldown', 'chain_features', 'actor_counts', 'rotation',
           'holds', 'tails', 'lockstep', 'constants', 'rephase', 'mix']
LEVELS = ['OK', 'SUSPECT', 'FAIL']
ISO_RE = re.compile(r'^\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(\.\d+)?'
                    r'(Z|[+-]\d\d:?\d\d)?$')
FRAC_RE = re.compile(r'\d\d:\d\d:\d\d[.,]\d')
CLOCK_RE = re.compile(r'\d\d:\d\d:\d\d(?:[.,](\d{1,9}))?')
IDLIKE_RE = re.compile(
    r'(^|[._])(id|uuid|guid|time|timestamp|created|ingested|sequence|seq'
    r'|offset|duration|nonce|session|pid|port|hash|request_id|trace)'
    r'($|[._])', re.I)
TIMEISH_RE = re.compile(r'(created|ingested|sequence|seq|offset|duration'
                        r'|time|record_id|request_id)', re.I)
COUNTER_RE = re.compile(r'(id|seq|sequence|record|offset|counter|number'
                        r'|serial)$', re.I)


def up(cur, new):
    return new if LEVELS.index(new) > LEVELS.index(cur) else cur


# ---------------------------------------------------------------- math

def _betacf(a, b, x):
    tiny = 1e-300
    qab, qap, qam = a + b, a + 1.0, a - 1.0
    c, d = 1.0, 1.0 - qab * x / qap
    d = 1.0 / (d if abs(d) > tiny else tiny)
    h = d
    for m in range(1, 400):
        m2 = 2 * m
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa * d
        d = 1.0 / (d if abs(d) > tiny else tiny)
        c = 1.0 + aa / c
        c = c if abs(c) > tiny else tiny
        h *= d * c
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1.0 + aa * d
        d = 1.0 / (d if abs(d) > tiny else tiny)
        c = 1.0 + aa / c
        c = c if abs(c) > tiny else tiny
        de = d * c
        h *= de
        if abs(de - 1.0) < 3e-14:
            break
    return h


def betainc(a, b, x):
    """Regularized incomplete beta I_x(a, b)."""
    if x <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0
    lbt = (math.lgamma(a + b) - math.lgamma(a) - math.lgamma(b)
           + a * math.log(x) + b * math.log1p(-x))
    if x < (a + 1.0) / (a + b + 2.0):
        return math.exp(lbt) * _betacf(a, b, x) / a
    return 1.0 - math.exp(lbt) * _betacf(b, a, 1.0 - x) / b


def gammaq(a, x):
    """Regularized upper incomplete gamma Q(a, x)."""
    if x <= 0:
        return 1.0
    gln = math.lgamma(a)
    if x < a + 1.0:
        ap, s, d = a, 1.0 / a, 1.0 / a
        for _ in range(1000):
            ap += 1.0
            d *= x / ap
            s += d
            if abs(d) < abs(s) * 3e-14:
                break
        return max(0.0, 1.0 - s * math.exp(-x + a * math.log(x) - gln))
    tiny = 1e-300
    b = x + 1.0 - a
    c, d = 1.0 / tiny, 1.0 / b
    h = d
    for i in range(1, 1000):
        an = -i * (i - a)
        b += 2.0
        d = an * d + b
        d = 1.0 / (d if abs(d) > tiny else tiny)
        c = b + an / c
        c = c if abs(c) > tiny else tiny
        de = d * c
        h *= de
        if abs(de - 1.0) < 3e-14:
            break
    return math.exp(-x + a * math.log(x) - gln) * h


def norm_sf(z):
    return 0.5 * math.erfc(z / math.sqrt(2.0))


def norm_isf(p):
    """z with P(Z > z) = p, for p in (0, 0.5]; capped at 38."""
    if p >= 0.5:
        return 0.0
    if p <= 0:
        return 38.0
    lo, hi = 0.0, 38.0
    for _ in range(80):
        mid = 0.5 * (lo + hi)
        if norm_sf(mid) > p:
            lo = mid
        else:
            hi = mid
    return 0.5 * (lo + hi)


def t_sf2(t, df):
    """Two-sided Student t tail P(|T| > t)."""
    t = abs(t)
    return betainc(df / 2.0, 0.5, df / (df + t * t))


def chi2_sf(x, df):
    return gammaq(df / 2.0, x / 2.0) if df > 0 else 1.0


def ks_q(lam):
    if lam < 0.2:
        return 1.0
    s = 0.0
    for k in range(1, 101):
        term = 2 * (-1) ** (k - 1) * math.exp(-2 * k * k * lam * lam)
        s += term
        if abs(term) < 1e-12:
            break
    return min(1.0, max(0.0, s))


def p_to_z(p, sign=1):
    return sign * norm_isf(max(p, 1e-300) / 2.0)


def count_test(x, e, s, big_e, phi=1.0, side='two'):
    """Negative-binomial predictive test of a new count.

    x counts in exposure e against a reference of s counts in exposure
    big_e.  phi is the quasi-Poisson overdispersion.  The upper side
    uses a flat prior (r = s + 1), the lower side r = s, so each side
    is conservative.  Returns (p, z, rate_on, rate_ref).
    """
    if e <= 0 or big_e <= 0:
        return 1.0, 0.0, 0.0, 0.0
    phi = max(1.0, phi)
    xs, ss = x / phi, s / phi
    q = big_e / (big_e + e)
    p_up = betainc(xs, ss + 1.0, 1.0 - q) if xs > 0 else 1.0
    p_lo = betainc(ss, xs + 1.0, q) if ss > 0 else 1.0
    if side == 'up':
        p = p_up
    elif side == 'down':
        p = p_lo
    else:
        p = min(1.0, 2 * min(p_up, p_lo))
    r_on, r_ref = x / e, s / big_e
    sign = 1 if r_on >= r_ref else -1
    return p, p_to_z(p, sign), r_on, r_ref


def holm(pvals):
    """Holm step-down adjusted p-values, same order as input."""
    m = len(pvals)
    order = sorted(range(m), key=lambda i: pvals[i])
    adj = [1.0] * m
    run = 0.0
    for rank, i in enumerate(order):
        run = max(run, min(1.0, (m - rank) * pvals[i]))
        adj[i] = run
    return adj


# ------------------------------------------------------------- parsing

def resolve(obj, path):
    if isinstance(obj, dict) and path in obj:
        return obj[path]
    cur = obj
    for part in path.split('.') if path else []:
        if isinstance(cur, dict):
            if part not in cur:
                return None
            cur = cur[part]
        elif isinstance(cur, list):
            if part.isdigit() and int(part) < len(cur):
                cur = cur[int(part)]
            else:
                return None
        else:
            return None
    return cur


def extract(obj, spec):
    """Scalar string per a {path|paths, regex} spec, or None."""
    if spec is None:
        return None
    paths = spec.get('paths') or [spec['path']]
    vals = []
    for p in paths:
        v = resolve(obj, p)
        if isinstance(v, list):
            v = v[0] if v else None
        if v is None:
            vals.append('')
            continue
        if not isinstance(v, str):
            v = json.dumps(v, sort_keys=True)
        rx = spec.get('_rx')
        if rx is not None:
            m = rx.search(v)
            v = (m.group(1) if m.groups() else m.group(0)) if m else ''
        vals.append(v)
    if all(v == '' for v in vals):
        return None
    return '|'.join(vals)


def parse_ts(v, fmt=None):
    if v is None:
        return None
    if isinstance(v, (int, float)):
        return float(v) / (1000.0 if v > 1e11 else 1.0)
    s = str(v)
    if fmt:
        d = datetime.strptime(s, fmt)
    else:
        if s.endswith('Z'):
            s = s[:-1] + '+00:00'
        if ' ' in s and 'T' not in s:
            s = s.replace(' ', 'T', 1)
        d = datetime.fromisoformat(s)
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return d.timestamp()


def compile_cond(c):
    """Compile a condition: {any|all: [clause], not: cond} or clause."""
    if not c:
        return None
    if 'path' in c:
        c = {'any': [c]}
    for key in ('any', 'all'):
        for cl in c.get(key, []):
            if 'path' in cl:
                if cl.get('regex'):
                    cl['_rx'] = re.compile(cl['regex'])
                if 'values' in cl:
                    cl['_vals'] = set(str(x) for x in cl['values'])
            else:
                compile_cond(cl)
    if c.get('not'):
        c['not'] = compile_cond(c['not'])
    return c


def _clause(obj, cl):
    if 'path' not in cl:
        return matches(obj, cl)
    v = resolve(obj, cl['path'])
    if v is None:
        return bool(cl.get('missing'))
    vs = [str(x) if not isinstance(x, str) else x for x in v] \
        if isinstance(v, list) else [v if isinstance(v, str)
                                     else json.dumps(v)]
    for s in vs:
        if '_vals' in cl and s in cl['_vals']:
            return True
        if cl.get('_rx') is not None and cl['_rx'].search(s):
            return True
    return False


def matches(obj, cond):
    if cond is None:
        return False
    ok = True
    if 'any' in cond:
        ok = any(_clause(obj, cl) for cl in cond['any'])
    if ok and 'all' in cond:
        ok = all(_clause(obj, cl) for cl in cond['all'])
    if ok and cond.get('not') is not None:
        ok = not matches(obj, cond['not'])
    return ok


def compile_actor(a):
    if a.get('regex'):
        a['_rx'] = re.compile(a['regex'])
    a['_when'] = compile_cond(a.get('when'))
    if a.get('target') and a['target'].get('regex'):
        a['target']['_rx'] = re.compile(a['target']['regex'])
    return a


def compile_spec(spec):
    spec = json.loads(json.dumps(spec))
    for key in ('timestamp', 'action', 'target'):
        s = spec.get(key)
        if s and s.get('regex'):
            s['_rx'] = re.compile(s['regex'])
    for a in spec['actors']:
        compile_actor(a)
    for key in ('chain', 'include', 'episode', 'failure', 'success'):
        spec['_' + key] = compile_cond(spec.get(key))
    skip = spec.get('skip_const_paths_regex')
    spec['_skip'] = re.compile(skip) if skip else None
    seq = spec.get('chain_seq')
    if seq:
        seq['_key'] = compile_actor(dict(seq['key'])) \
            if isinstance(seq['key'], dict) else None
        for st in seq['steps']:
            st['_c'] = compile_cond(st['match'])
    for f in spec.get('features', []):
        f['_key'] = compile_actor(dict(f['key']))
        for st in f['steps']:
            st['_c'] = compile_cond(st['match'])
    for pr in spec.get('pairs', []):
        pr['_key'] = compile_actor(dict(pr['key']))
        pr['_open'] = compile_cond(pr['open'])
        pr['_close'] = compile_cond(pr['close'])
    return spec


def actor_by_name(spec, name):
    for a in spec['actors']:
        if a['name'] == name:
            return a
    raise SystemExit(f'unknown actor key {name!r}')


def spec_hash(path):
    return hashlib.sha256(open(path, 'rb').read()).hexdigest()


def open_capture(path):
    if path.endswith('.gz'):
        return gzip.open(path, 'rb')
    return open(path, 'rb')


def file_id(path):
    st = os.stat(path)
    return f'{os.path.realpath(path)}|{st.st_size}|{int(st.st_mtime)}'


# ----------------------------------------------------- sequence matcher

class SeqMatcher:
    """Ordered same-key step sequences within a window, streamed.

    A step is {match: cond, bind: {var: path}, eq: {var: path},
    ne: {var: path}}.  Steps may skip unrelated rows of the key.
    Completion resets the key, so occurrences never overlap.
    """

    def __init__(self, steps, within, key_spec, same=()):
        self.steps = steps
        self.within = within
        self.key = key_spec
        self.same = list(same)
        self.state = {}

    def _key(self, obj):
        k = extract(obj, self.key) if self.key else ''
        if k is None:
            return None
        for p in self.same:
            v = resolve(obj, p)
            if v is None:
                return None
            k += '\x1f' + (v if isinstance(v, str) else json.dumps(v))
        return k

    @staticmethod
    def _step_ok(st, obj, binds):
        if not matches(obj, st['_c']):
            return None
        for var, path in (st.get('eq') or {}).items():
            if var in binds and _sval(resolve(obj, path)) != binds[var]:
                return None
        for var, path in (st.get('ne') or {}).items():
            vars_ = var.split(',')
            val = _sval(resolve(obj, path))
            if any(v in binds and binds[v] == val for v in vars_):
                return None
        nb = binds
        if st.get('bind'):
            nb = dict(binds)
            for var, path in st['bind'].items():
                nb[var] = _sval(resolve(obj, path))
        return nb

    def feed(self, obj, t, line):
        k = self._key(obj)
        if k is None:
            return None
        parts = [p for p in self.state.get(k, ())
                 if t - p[1] <= self.within]
        new = []
        done = None
        for p in parts:
            nb = self._step_ok(self.steps[p[0]], obj, p[2])
            if nb is not None:
                lines = p[3] + [line]
                if p[0] + 1 == len(self.steps):
                    done = (p[1], t, lines, k)
                    break
                new.append((p[0] + 1, p[1], nb, lines))
            else:
                new.append(p)
        if done:
            self.state.pop(k, None)
            return done
        nb = self._step_ok(self.steps[0], obj, {})
        if nb is not None:
            if len(self.steps) == 1:
                self.state.pop(k, None)
                return (t, t, [line], k)
            new.append((1, t, nb, [line]))
        if new:
            self.state[k] = new[-8:]
        else:
            self.state.pop(k, None)
        return None


def _sval(v):
    if v is None:
        return None
    return v if isinstance(v, str) else json.dumps(v, sort_keys=True)


def sub_sequences(steps):
    """Contiguous proper sub-sequences (length >= 2) of chain steps."""
    out = []
    n = len(steps)
    for ln in range(2, n):
        for i in range(0, n - ln + 1):
            sub = [dict(s) for s in steps[i:i + ln]]
            bound = set()
            for s in sub:
                for key in ('eq', 'ne'):
                    if s.get(key):
                        kept = {}
                        for var, path in s[key].items():
                            vs = [v for v in var.split(',') if v in bound]
                            if vs:
                                kept[','.join(vs)] = path
                        s[key] = kept
                bound.update((s.get('bind') or {}).keys())
            out.append((f'steps{i + 1}-{i + ln}', sub))
    return out


# ------------------------------------------------------------- samples

class Sample:
    """Bounded summary of a value stream: n, extreme heaps, reservoir."""

    def __init__(self, name):
        self.n = 0
        self.low = []   # max-heap by -v: (-v, t, l1, l2)
        self.high = []  # min-heap: (v, t, l1, l2)
        self.res = []
        self.rng = random.Random(zlib.crc32(name.encode()))

    def add(self, v, t, l1, l2):
        self.n += 1
        e = (-v, t, l1, l2)
        if len(self.low) < HEAP_L:
            heapq.heappush(self.low, e)
        elif v < -self.low[0][0]:
            heapq.heapreplace(self.low, e)
        e = (v, t, l1, l2)
        if len(self.high) < HEAP_L:
            heapq.heappush(self.high, e)
        elif v > self.high[0][0]:
            heapq.heapreplace(self.high, e)
        if len(self.res) < RES_R:
            self.res.append(v)
        else:
            j = self.rng.randrange(self.n)
            if j < RES_R:
                self.res[j] = v

    def dump(self):
        low = sorted([[-e[0], e[1], e[2], e[3]] for e in self.low])
        high = sorted([list(e) for e in self.high], key=lambda x: -x[0])
        return {'n': self.n, 'low': _r(low), 'high': _r(high),
                'res': [round(v, 4) for v in self.res]}


def _r(rows):
    return [[round(r[0], 4), round(r[1], 3), r[2], r[3]] for r in rows]


class Cat:
    """Categorical table with a few instances per rare category."""

    def __init__(self):
        self.c = Counter()
        self.inst = {}
        self.overflow = 0

    def add(self, key, t=None, l1=-1, l2=-1):
        if key not in self.c and len(self.c) >= MAX_CAT:
            self.overflow += 1
            return
        self.c[key] += 1
        if t is not None:
            li = self.inst.setdefault(key, [])
            if len(li) < CAT_INST:
                li.append([round(t, 3), l1, l2])

    def dump(self):
        return {'c': dict(self.c), 'inst': self.inst,
                'overflow': self.overflow}


# ------------------------------------------------------------ analyzer

class KeyState:
    def __init__(self, a, an):
        self.name = a['name']
        self.spec = a
        self.an = an
        self.last = {}
        self.last_bg = {}
        self.last_act = {}
        self.events = Counter()
        self.ngaps = 0
        self.ngaps_bg = 0
        self.period = Counter()
        self.fail_period = Counter()
        self.chain_ap = set()
        self.nfail = 0
        self.fail_times = {}
        self.fail_run = {}
        self.last_succ = {}
        self.pending = deque()
        # absolute
        self.prev_actor = None
        self.cur_run = 0
        self.runs = Counter()
        self.succ = {}
        self.trans = []
        self.tsucc = {}
        self.ttrans = []
        self.last_tgt = {}
        self.idx = 0
        self.last_idx = {}
        self.rr_hits = [0] * (RR_MAX_K + 1)
        self.rr_n = 0
        self.seq = {}
        self.gapc = {}
        self.lastgap = {}
        self.repeat_gaps = 0
        self.long_gaps = 0
        self.gap_values = Counter()
        self.gap_overflow = 0

    def _actor_id(self, v):
        return self.an.intern(v)

    def add(self, t, actor, action, tgt, ln, ch, fail, succ):
        an = self.an
        k = self.name
        self.events[actor] += 1
        if an.day_s:
            j = int((t - an.t0) // an.day_s)
            self.period[(actor, j)] += 1
            if fail:
                self.fail_period[(actor, j)] += 1
            if ch:
                self.chain_ap.add((actor, j))
        # actor sequence (absolute + rotation)
        if self.prev_actor is not None and actor != self.prev_actor:
            sc = self.succ.setdefault(self.prev_actor, Counter())
            if actor in sc or len(sc) < 50:
                sc[actor] += 1
            if len(self.trans) < MAX_TRANS:
                self.trans.append((self.prev_actor, actor, round(t, 3), ln))
        if actor == self.prev_actor:
            self.cur_run += 1
        else:
            if self.cur_run:
                self.runs[self.cur_run] += 1
            self.cur_run = 1
        self.prev_actor = actor
        self.rr_n += 1
        li = self.last_idx.get(actor)
        if li is not None and self.idx - li <= RR_MAX_K:
            self.rr_hits[self.idx - li] += 1
        self.last_idx[actor] = self.idx
        self.idx += 1
        sq = self.seq.setdefault(actor, [])
        if len(sq) < SEQ_LEN:
            sq.append(action)
        if tgt is not None:
            pt = self.last_tgt.get(actor)
            if pt is not None and pt != tgt:
                d = self.tsucc.setdefault(actor, {})
                c = d.setdefault(pt, Counter())
                if tgt in c or len(c) < 50:
                    c[tgt] += 1
                if len(self.ttrans) < MAX_TRANS:
                    self.ttrans.append((actor + '\x1f' + pt, tgt,
                                        round(t, 3), ln))
            self.last_tgt[actor] = tgt
        # gaps (all rows)
        prev = self.last.get(actor)
        self.last[actor] = (t, ln, action)
        if prev is not None:
            g = t - prev[0]
            self.ngaps += 1
            for w in WINDOWS:
                if g < w:
                    an.cnt(f'{k}.gap_lt_{w}', t, ln, prev[1])
            an.sample(f'{k}.gap', g, t, ln, prev[1])
            if g < 600:
                an.cat(f'{k}.trans600', f'{prev[2]}>{action}', t, ln,
                       prev[1])
            gr = int(round(g))
            if gr in self.gap_values or len(self.gap_values) < 5000:
                self.gap_values[gr] += 1
            else:
                self.gap_overflow += 1
            if g > an.tick:
                ac = self.gapc.setdefault(actor, Counter())
                if gr in ac or len(ac) < 64:
                    ac[gr] += 1
                self.long_gaps += 1
                if self.lastgap.get(actor) == gr:
                    self.repeat_gaps += 1
                self.lastgap[actor] = gr
        pa = self.last_act.get((actor, action))
        self.last_act[(actor, action)] = (t, ln)
        if pa is not None:
            for w in SAME_ACTION_WINDOWS:
                if t - pa[0] < w:
                    an.cnt(f'{k}.same_action_lt_{w}', t, ln, pa[1])
        # background-only gaps
        if not ch:
            pb = self.last_bg.get(actor)
            self.last_bg[actor] = (t, ln)
            if pb is not None:
                g = t - pb[0]
                self.ngaps_bg += 1
                an.sample(f'{k}.gap_bg', g, t, ln, pb[1])
                an.cat(f'{k}.gapmin_bg', str(int(g // 60)), t, ln, pb[1])
        # failures
        if an.has_failure:
            self._pop_pending(t)
            if fail:
                self.nfail += 1
                dq = self.fail_times.setdefault(actor, deque(maxlen=3))
                if dq:
                    g = t - dq[-1][0]
                    for w in FAIL_WINDOWS:
                        if g < w:
                            an.cnt(f'{k}.fail_lt_{w}', t, ln, dq[-1][1])
                dq.append((t, ln))
                if len(dq) == 3 and t - dq[0][0] <= 3600:
                    an.cnt(f'{k}.fail3_3600', t, ln, dq[0][1])
                    dq.clear()
                r = self.fail_run.get(actor, 0) + 1
                self.fail_run[actor] = r
                if r == 2:
                    an.cnt(f'{k}.failrun2', t, ln, -1)
                elif r == 3:
                    an.cnt(f'{k}.failrun3', t, ln, -1)
                self.pending.append((t, actor, ln))
            elif succ:
                self.fail_run[actor] = 0
                self.last_succ[actor] = t

    def _pop_pending(self, t):
        while self.pending and self.pending[0][0] + GIVEUP_S < t:
            tf, actor, ln = self.pending.popleft()
            if self.last_succ.get(actor, -1e18) <= tf:
                self.an.cnt(f'{self.name}.giveup', tf, ln, -1)

    def finish(self, t_end):
        an = self.an
        k = self.name
        if an.has_failure:
            self._pop_pending(t_end)
        if self.cur_run:
            self.runs[self.cur_run] += 1
        an.expo[f'{k}.gaps'] = self.ngaps
        an.expo[f'{k}.gaps_bg'] = self.ngaps_bg
        an.expo[f'{k}.fails'] = self.nfail
        if an.day_s:
            nfull = int((t_end - an.t0) // an.day_s)
            actors = list(self.events)
            for j in range(nfull):
                tm = an.t0 + (j + 0.5) * an.day_s
                for a in actors:
                    at = 1 if (a, j) in self.chain_ap else 0
                    an.sample(f'{k}.per_period', self.period.get((a, j), 0),
                              tm, -1, at)
                    if an.has_failure:
                        an.sample(f'{k}.fail_per_period',
                                  self.fail_period.get((a, j), 0), tm, -1,
                                  at)

    def absolute(self, action_probs, rng):
        """Rotation and lockstep metrics of this key."""
        out = {'actors': len(self.events), 'gaps': self.ngaps}
        tot = sum(sum(c.values()) for c in self.succ.values())
        top = sum(c.most_common(1)[0][1] for c in self.succ.values() if c)
        out['succ_det'] = round(top / tot, 4) if tot else 0.0
        out['succ_n'] = tot
        out['succ_det_expected'] = expected_det(self.succ, self.events, rng)
        best_k, best = None, 0.0
        if self.rr_n > 50:
            for kk in range(2, RR_MAX_K + 1):
                s = self.rr_hits[kk] / max(self.rr_n - kk, 1)
                if s > best:
                    best_k, best = kk, s
        n = sum(self.events.values()) or 1
        out['rr_lag'] = best_k
        out['rr_share'] = round(best, 4)
        out['rr_expected'] = round(sum((c / n) ** 2 for c in
                                       self.events.values()), 4)
        # target successor determinism per actor
        ttot = ttop = 0
        for d in self.tsucc.values():
            for c in d.values():
                ttot += sum(c.values())
                ttop += c.most_common(1)[0][1]
        out['tsucc_det'] = round(ttop / ttot, 4) if ttot else 0.0
        out['tsucc_n'] = ttot
        texp = []
        for d in self.tsucc.values():
            marg = Counter()
            for c in d.values():
                marg.update(c)
            texp.append((sum(sum(c.values()) for c in d.values()),
                         expected_det(d, marg, rng)))
        out['tsucc_det_expected'] = round(
            sum(a * b for a, b in texp) / max(sum(a for a, _ in texp), 1), 4)
        # dominant period per actor
        dom = []
        for a, c in self.gapc.items():
            s = sum(c.values())
            if s >= 5:
                g, kk = c.most_common(1)[0]
                dom.append((a, g, kk / s))
        dominated = [d for d in dom if d[2] >= 0.8]
        out['actors_5plus_gaps'] = len(dom)
        out['dominant_period_share'] = round(len(dominated) / len(dom), 4) \
            if dom else None
        out['dominant_periods'] = Counter(d[1] for d in dominated
                                          ).most_common(5)
        out['repeat_gap_share'] = round(self.repeat_gaps
                                        / max(self.long_gaps, 1), 4)
        out['long_gaps'] = self.long_gaps
        full = [tuple(s) for s in self.seq.values() if len(s) == SEQ_LEN]
        out['seq_full'] = len(full)
        out['seq_distinct'] = len(set(full))
        out['seq_types'] = len({a for s in full for a in s})
        out['seq_expected'] = round(sum(p * p for p in
                                        action_probs.values()), 4)
        agree = None
        if len(full) >= 5:
            pairs = same = 0
            smp = full[:40]
            for i in range(len(smp)):
                for j in range(i + 1, len(smp)):
                    pairs += 1
                    same += sum(x == y for x, y in zip(smp[i], smp[j])
                                ) / SEQ_LEN
            agree = same / pairs
        out['seq_agreement'] = None if agree is None else round(agree, 4)
        out['top_gaps'] = self.gap_values.most_common(6)
        out['distinct_gaps'] = len(self.gap_values) + (
            1 if self.gap_overflow else 0)
        return out


def expected_det(succ, marg, rng, raw=False):
    """Expected successor determinism under random order.

    For each predecessor x with n_x changes, the successor is drawn
    from the marginal frequencies excluding x (raw=True keeps x).
    """
    tot = sum(marg.values())
    if not tot:
        return 0.0
    keys = list(marg)
    num = den = 0.0
    for x, c in succ.items():
        nx = sum(c.values())
        if nx == 0:
            continue
        w = [0 if (k == x and not raw) else marg[k] for k in keys]
        if not any(w):
            continue
        reps = 3 if nx <= 3000 else 1
        acc = 0.0
        for _ in range(reps):
            dr = Counter(rng.choices(keys, weights=w, k=min(nx, 3000)))
            acc += dr.most_common(1)[0][1] / min(nx, 3000)
        num += nx * acc / reps
        den += nx
    return round(num / den, 4) if den else 0.0


class Analyzer:
    """One pass over one capture (or one block of it)."""

    def __init__(self, spec, tick, chains, chain_lines, t0, label):
        self.spec = spec
        self.tick = tick
        self.chains = chains
        self.chain_lines = chain_lines
        self.t0 = t0
        self.label = label
        self.day_s = spec.get('day_s', 86400)
        self.near_s = spec.get('near_s', 1800)
        self.pre_s = spec.get('pre_s', 0)
        self.has_failure = spec.get('_failure') is not None
        self.win = sorted((c[0] - self.pre_s, c[1] + self.near_s)
                          for c in chains)
        self.counts = {}
        self.samples = {}
        self.cats = {}
        self.expo = Counter()
        self.ids = {}
        self.keys = [KeyState(a, self) for a in spec['actors']]
        self.rows = 0
        self.chain_rows = 0
        self.tfirst = self.tlast = None
        self.backwards = 0
        self.actions = Counter()
        self.actions_bg = Counter()
        self.act_last = {}
        self.act_gapc = {}
        self.n_act_samples = 0
        self.prev_bg_action = None
        self.cur_run = 0
        self.lag_hits = [0] * (RR_MAX_K + 1)
        self.ring = deque(maxlen=RR_MAX_K)
        self.run_max = {}
        self.runs_all = Counter()
        self.run_actors = set()
        self.prev_action = None
        self.cur_run_all = 0
        self.count_buckets = Counter()
        self.phase = {}
        self.phase_all = {P: [0] * PHASE_BINS for P in PHASE_PERIODS}
        self.phase_last = {}
        self.frac_rows = 0
        self.wave_times = {}
        self.wave_n = 0
        self.ts_frac = Counter()
        self.sec_of_min = Counter()
        self.fields = {}
        self.iso_delta = {}
        self.iso_frac = {}
        self.text_frac = {}
        self.incr = {}
        self.const_rows = 0
        self.pairs_state = [dict(open={}, closed={}, durc=Counter())
                            for _ in spec.get('pairs', [])]
        seq = spec.get('chain_seq')
        self.submatch = []
        if seq:
            for name, sub in sub_sequences(seq['steps']):
                self.submatch.append((f'seq:{name}', SeqMatcher(
                    sub, seq['within'], seq['_key'], seq.get('same', ()))))
        for f in spec.get('features', []):
            self.submatch.append((f'feat:{f["name"]}', SeqMatcher(
                f['steps'], f['within'], f['_key'], f.get('same', ()))))
        self.rng = random.Random(1)

    def intern(self, v):
        return v

    def cnt(self, name, t, l1, l2):
        st = self.counts.get(name)
        if st is None:
            st = self.counts[name] = {'n': 0, 'at': 0, 'at_rows': 0,
                                      'ex_at': [], 'ex_far': [], 'hit': [],
                                      'hit_nr': []}
        st['n'] += 1
        on_rows = l1 in self.chain_lines or l2 in self.chain_lines
        st['at_rows'] += on_rows
        at = on_rows or in_windows(self.win, t)
        if at:
            st['at'] += 1
            ci = window_index(self.win, t)
            if ci is not None and ci not in st['hit']:
                st['hit'].append(ci)
            # chains hit by instances outside the chain rows (near
            # misses around an episode, not the episode itself)
            if ci is not None and not on_rows and ci not in st['hit_nr']:
                st['hit_nr'].append(ci)
            if len(st['ex_at']) < 3:
                st['ex_at'].append([round(t, 3), l1, l2])
        elif len(st['ex_far']) < 3:
            st['ex_far'].append([round(t, 3), l1, l2])

    def sample(self, name, v, t, l1, l2):
        s = self.samples.get(name)
        if s is None:
            s = self.samples[name] = Sample(name)
        s.add(v, t, l1, l2)

    def cat(self, name, key, t=None, l1=-1, l2=-1):
        c = self.cats.get(name)
        if c is None:
            c = self.cats[name] = Cat()
        c.add(key, t, l1, l2)

    def row(self, obj, t, ln, raw_ts=None):
        spec = self.spec
        self.rows += 1
        if self.tlast is not None and t < self.tlast:
            self.backwards += 1
        self.tfirst = t if self.tfirst is None else min(self.tfirst, t)
        self.tlast = t if self.tlast is None else max(self.tlast, t)
        ch = ln in self.chain_lines
        self.chain_rows += ch
        action = extract(obj, spec.get('action')) or ''
        tgt = extract(obj, spec.get('target'))
        fail = matches(obj, spec['_failure']) if self.has_failure else False
        if spec.get('_success') is not None:
            succ = matches(obj, spec['_success'])
        else:
            succ = self.has_failure and not fail
        self.actions[action] += 1
        self.cat('mix.action_all', action, t, ln, -1)
        if not ch:
            self.actions_bg[action] += 1
            if action == self.prev_bg_action:
                self.cur_run += 1
            else:
                if self.prev_bg_action is not None:
                    self.cat('rephase.runlen', str(self.cur_run), t, ln, -1)
                self.prev_bg_action, self.cur_run = action, 1
        # per-action inter-occurrence gaps
        la = self.act_last.get(action)
        if la is not None and t >= la[0]:
            g = t - la[0]
            nm = f'act:{action}.gap'
            if nm in self.samples or self.n_act_samples < 30:
                if nm not in self.samples:
                    self.n_act_samples += 1
                self.sample(nm, g, t, ln, la[1])
            gr = int(round(g))
            ag = self.act_gapc.setdefault(action, Counter())
            if gr in ag or len(ag) < 64:
                ag[gr] += 1
            if not ch:
                self.cat('act.gapmin_bg', f'{action}|{int(g // 60)}', t, ln,
                         la[1])
        self.act_last[action] = (t, ln)
        # global action sequence (absolute)
        for kk in range(1, len(self.ring) + 1):
            if self.ring[-kk] == action:
                self.lag_hits[kk] += 1
        self.ring.append(action)
        a0 = extract(obj, self.keys[0].spec)
        if action == self.prev_action:
            self.cur_run_all += 1
            if a0 is not None and len(self.run_actors) < 64:
                self.run_actors.add(a0)
        else:
            if self.prev_action is not None:
                self._close_run()
            self.prev_action, self.cur_run_all = action, 1
            self.run_actors = {a0} if a0 is not None else set()
        self.count_buckets[int(t // EMPTY_BUCKET_S)] += 1
        # phases; one count per actor burst (a burst lands in one bin and
        # would otherwise weigh as many independent draws)
        if isinstance(raw_ts, str) and FRAC_RE.search(raw_ts):
            self.frac_rows += 1
        lp = self.phase_last.get((action, a0))
        self.phase_last[(action, a0)] = t
        for P in PHASE_PERIODS:
            b = int((t % P) / P * PHASE_BINS) % PHASE_BINS
            if lp is not None and t - lp < P / PHASE_BINS:
                continue
            self.phase_all[P][b] += 1
            if len(self.phase) < 60 * len(PHASE_PERIODS) or \
                    (action, P) in self.phase:
                ph = self.phase.setdefault((action, P), [0] * PHASE_BINS)
                ph[b] += 1
        # keys
        actor0 = None
        for i, ks in enumerate(self.keys):
            a = ks.spec
            if a['_when'] is not None and not matches(obj, a['_when']):
                continue
            v = extract(obj, a)
            if v is None:
                continue
            if i == 0:
                actor0 = v
            ks.add(t, v, action, extract(obj, a['target']) if a.get('target')
                   else tgt, ln, ch, fail, succ)
            if a['_when'] is not None:
                for P in PHASE_PERIODS:
                    b = int((t % P) / P * PHASE_BINS) % PHASE_BINS
                    ph = self.phase.setdefault(('key:' + a['name'], P),
                                               [0] * PHASE_BINS)
                    ph[b] += 1
        if actor0 is not None and self.wave_n < MAX_WAVE_TIMES:
            self.wave_times.setdefault(action, {}).setdefault(
                actor0, []).append(t)
            self.wave_n += 1
        # holds
        for pr, stt in zip(spec.get('pairs', []), self.pairs_state):
            is_open = matches(obj, pr['_open'])
            is_close = (not is_open) and matches(obj, pr['_close'])
            if not (is_open or is_close):
                continue
            k = extract(obj, pr['_key'])
            if k is None:
                continue
            nm = pr['name']
            if is_open:
                c = stt['closed'].pop(k, None)
                if c is not None:
                    self.sample(f'hold:{nm}.absence', t - c[0], t, ln, c[1])
                stt['open'][k] = (t, ln)
            else:
                o = stt['open'].pop(k, None)
                if o is not None:
                    d = t - o[0]
                    self.sample(f'hold:{nm}.duration', d, t, ln, o[1])
                    dr = int(round(d))
                    if dr in stt['durc'] or len(stt['durc']) < 5000:
                        stt['durc'][dr] += 1
                stt['closed'][k] = (t, ln)
        # sub-sequence and custom features
        for name, m in self.submatch:
            r = m.feed(obj, t, ln)
            if r is not None:
                self.cnt(name, r[1], r[2][0], r[2][-1])
        # constants (sampled)
        frac = round(t - math.floor(t), 3)
        if frac in self.ts_frac or len(self.ts_frac) < 2000:
            self.ts_frac[frac] += 1
        self.sec_of_min[int(t) % 60] += 1
        if self.rows <= 20000 or self.rows % 5 == 0:
            self._constants(obj, t, action)

    def _constants(self, obj, t, action):
        self.const_rows += 1
        flat = flatten(obj)
        for k, v in flat.items():
            st = self.fields.get(k)
            vs = v if isinstance(v, str) else json.dumps(v)
            if st is None:
                self.fields[k] = [vs, 1, False]
            else:
                st[1] += 1
                if not st[2] and st[0] != vs:
                    st[2] = True
            if isinstance(v, str) and len(v) >= 19 and ISO_RE.match(v):
                try:
                    tv = parse_ts(v)
                except ValueError:
                    tv = None
                if tv is not None:
                    ds = self.iso_delta.setdefault(k, Counter())
                    d = round(tv - t, 3)
                    if d in ds or len(ds) < 20:
                        ds[d] += 1
                    m = ISO_RE.match(v)
                    fs = self.iso_frac.setdefault(k, Counter())
                    fv = m.group(1) or 'none'
                    if fv in fs or len(fs) < 20:
                        fs[fv] += 1
            elif isinstance(v, int) and not isinstance(v, bool) and \
                    COUNTER_RE.search(k.split('.')[-1]) and \
                    self.rows <= 20000:
                key = (k, action)
                st2 = self.incr.get(key)
                if st2 is None:
                    self.incr[key] = [v, Counter()]
                else:
                    d = v - st2[0]
                    st2[0] = v
                    if d in st2[1] or len(st2[1]) < 20:
                        st2[1][d] += 1
        for tp in self.spec.get('text_time_paths', []):
            v = resolve(obj, tp)
            if isinstance(v, str):
                m = CLOCK_RE.search(v)
                if m:
                    fs = self.text_frac.setdefault(tp, Counter())
                    fv = m.group(1) or 'none'
                    if fv in fs or len(fs) < 20:
                        fs[fv] += 1

    def finish(self):
        t_end = self.tlast if self.tlast is not None else self.t0
        for ks in self.keys:
            ks.finish(t_end)
        if self.prev_bg_action is not None:
            self.cat('rephase.runlen', str(self.cur_run))
        if self.prev_action is not None:
            self._close_run()
        span = (t_end - self.tfirst) if self.tfirst is not None else 0.0
        self.expo['rows'] = self.rows
        self.expo['span_h'] = span / 3600.0
        self.expo['rows_bg'] = self.rows - self.chain_rows
        return self._features(span)

    def _features(self, span):
        total = max(self.rows, 1)
        probs = {a: c / total for a, c in self.actions.items()}
        keys_abs = {ks.name: ks.absolute(probs, self.rng)
                    for ks in self.keys}
        rot = {}
        for ks in self.keys:
            rot[ks.name] = {
                'succ': {x: dict(c) for x, c in ks.succ.items()},
                'trans': ks.trans,
                'tsucc': {a + '\x1f' + pt: dict(c)
                          for a, d in ks.tsucc.items()
                          for pt, c in d.items()},
                'ttrans': ks.ttrans}
        feats = {
            'label': self.label,
            'rows': self.rows,
            'chain_rows': self.chain_rows,
            'span_s': span,
            't0': self.tfirst,
            'chains': [[round(c[0], 3), round(c[1], 3), c[2][:12], c[3]]
                       for c in self.chains],
            'chain_lines': sorted(self.chain_lines)[:5000],
            'win': [[round(a, 3), round(b, 3)] for a, b in self.win],
            'counts': self.counts,
            'expo': dict(self.expo),
            'samples': {k: s.dump() for k, s in self.samples.items()},
            'cats': {k: c.dump() for k, c in self.cats.items()},
            'phase': {f'{a}@{P}': v for (a, P), v in self.phase.items()},
            'phase_all': {str(P): v for P, v in self.phase_all.items()},
            'rot': rot,
            'absolute': self._absolute(keys_abs, probs, span),
        }
        return feats

    def _close_run(self):
        a, n = self.prev_action, self.cur_run_all
        self.runs_all[n] += 1
        if n > self.run_max.get(a, (0, 0))[0]:
            self.run_max[a] = (n, len(self.run_actors))

    def _absolute(self, keys_abs, probs, span):
        rows = max(self.rows, 1)
        run_excess = []
        for a, (mx, distinct) in self.run_max.items():
            p = probs.get(a, 0)
            if p >= 0.999 or p <= 0:
                continue
            exp = max(1.0, math.log(rows * (1 - p)) / -math.log(p))
            run_excess.append((a, mx, round(exp, 1), round(mx / exp, 2),
                               distinct))
        run_excess.sort(key=lambda x: -x[3])
        best_k, best = None, 0.0
        for kk in range(2, len(self.lag_hits)):
            if rows - kk > 0:
                sh = self.lag_hits[kk] / (rows - kk)
                if sh > best + 1e-9:
                    best_k, best = kk, sh
        periodic = []
        for a, c in self.act_gapc.items():
            n = sum(c.values())
            if n >= 9:
                g, kk = c.most_common(1)[0]
                if kk / n >= 0.6 and g >= 60 and g > self.tick:
                    periodic.append((a, g, round(kk / n, 3), n))
        periodic.sort(key=lambda x: -x[2])
        empty = []
        if self.tfirst is not None:
            for b in range(int(self.tfirst // EMPTY_BUCKET_S),
                           int(self.tlast // EMPTY_BUCKET_S) + 1):
                if self.count_buckets.get(b, 0) == 0:
                    empty.append(b)
        spacing = Counter(b - a for a, b in zip(empty, empty[1:]))
        skip = self.spec['_skip']
        const = {k: v[0][:80] for k, v in self.fields.items()
                 if not v[2] and v[1] == self.const_rows
                 and not (skip and skip.search(k))}
        const_time = [k for k, v in const.items() if IDLIKE_RE.search(k)
                      and TIMEISH_RE.search(k) and v not in ('', '0', 'null')]
        incr = []
        for (k, a), (_, c) in self.incr.items():
            n = sum(c.values())
            if n >= 50:
                d, kk = c.most_common(1)[0]
                if d != 0 and kk / n >= 0.99:
                    incr.append((k, a, d, round(kk / n, 4), n))
        holds = []
        for pr, stt in zip(self.spec.get('pairs', []), self.pairs_state):
            n = sum(stt['durc'].values())
            if n:
                v, kk = stt['durc'].most_common(1)[0]
                holds.append((pr['name'], v, round(kk / n, 4), n,
                              len(stt['durc'])))
        phase_conc = []
        for (a, P), hist in self.phase.items():
            n = sum(hist)
            glob = self.phase_all[P]
            gn = sum(glob)
            if n >= 30 and P > 2 * max(self.tick, 1) and gn:
                sh = max(hist) / n
                gsh = max(glob) / gn
                phase_conc.append((a, P, round(sh, 3), round(gsh, 3), n))
        phase_conc.sort(key=lambda x: -(x[2] - x[3]))
        return {
            'keys': keys_abs,
            'run_excess': run_excess[:5],
            'action_period': {'lag': best_k, 'share': round(best, 4),
                              'expected': round(sum(p * p for p in
                                                    probs.values()), 4),
                              'n_actions': len(self.actions)},
            'periodic_actions': periodic[:10],
            'empty_buckets': len(empty),
            'empty_spacing': spacing.most_common(3),
            'waves': waves(self.wave_times, self.tfirst, self.tlast),
            'ts_frac_top': [(str(k), c) for k, c in
                            self.ts_frac.most_common(3)],
            'ts_frac_distinct': len(self.ts_frac),
            'frac_rows': self.frac_rows,
            'sec_of_min_distinct': len(self.sec_of_min),
            'iso_delta': {k: [(str(a), b) for a, b in v.most_common(3)]
                          + [len(v)] for k, v in self.iso_delta.items()},
            'iso_frac': {k: [v.most_common(3), len(v)]
                         for k, v in self.iso_frac.items()},
            'text_frac': {k: [v.most_common(3), len(v)]
                          for k, v in self.text_frac.items()},
            'const_time_fields': const_time[:10],
            'increments': incr[:10],
            'holds': holds,
            'phase_conc': phase_conc[:10],
            'rows': self.rows,
            'backwards': self.backwards,
        }


def window_index(win, t):
    """Index of a window containing t (windows sorted by start)."""
    if not win or t is None:
        return None
    lo, hi = 0, len(win)
    while lo < hi:
        mid = (lo + hi) // 2
        if win[mid][0] <= t:
            lo = mid + 1
        else:
            hi = mid
    for i in range(lo - 1, max(-1, lo - 4), -1):
        if win[i][0] <= t <= win[i][1]:
            return i
    return None


def in_windows(win, t):
    return window_index(win, t) is not None


def flatten(obj, prefix='', out=None):
    if out is None:
        out = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            flatten(v, f'{prefix}{k}.', out)
    else:
        key = prefix[:-1]
        if isinstance(obj, list):
            if obj and all(not isinstance(x, (dict, list)) for x in obj):
                out[key] = json.dumps(obj)
            else:
                for i, x in enumerate(obj[:3]):
                    flatten(x, f'{prefix}{i}.', out)
        else:
            out[key] = obj
    return out


def waves(wave_times, t0, t1, reps=10):
    """Global waves: >=80% of an action's actors in one window.

    The observed count of such windows is compared with a null in
    which every actor's own event times are circularly shifted by an
    independent random offset (keeps each actor's process, destroys
    cross-actor synchrony).
    """
    if t0 is None or t1 is None or t1 - t0 < 4 * WAVE_BUCKET_S:
        return []
    span = t1 - t0
    rng = random.Random(7)
    out = []
    for a, per in wave_times.items():
        pop = len(per)
        if pop < 5:
            continue
        obs, spacing_share, spacing = _wave_hits(per, pop, t0, 0)
        if obs < 3:
            continue
        null = []
        for _ in range(reps):
            sh = {k: [t0 + ((x - t0 + rng.random() * span) % span)
                      for x in v] for k, v in per.items()}
            null.append(_wave_hits(sh, pop, t0, 0)[0])
        with_ = len({int((x - t0) // WAVE_BUCKET_S) for v in per.values()
                     for x in v})
        out.append((a, obs, with_, spacing, spacing_share, max(null),
                    round(sum(null) / len(null), 2)))
    out.sort(key=lambda x: -x[1])
    return out[:6]


def _wave_hits(per, pop, t0, off):
    buckets = {}
    for actor, ts in per.items():
        for x in ts:
            buckets.setdefault(int((x - t0 + off) // WAVE_BUCKET_S),
                               set()).add(actor)
    hits = sorted(b for b, s in buckets.items() if len(s) >= 0.8 * pop)
    sp = Counter(y - x for x, y in zip(hits, hits[1:]))
    if sp:
        g, c = sp.most_common(1)[0]
        return len(hits), round(c / max(len(hits) - 1, 1), 3), g
    return len(hits), 0.0, None


# ------------------------------------------------------------ captures

def pass1(path, spec):
    """Rows, timestamps, chain occurrences and the input tick."""
    from array import array
    ts_spec = spec['timestamp']
    seq = spec.get('chain_seq')
    matcher = SeqMatcher(seq['steps'], seq['within'], seq['_key'],
                         seq.get('same', ())) if seq else None
    epi = spec.get('_episode') or spec.get('_chain')
    gap = spec.get('episode_gap_s', 600)
    chains = []
    ep_cur = None
    first = []
    row_lines = array('l')
    with open_capture(path) as fh:
        for ln, raw in enumerate(fh, 1):
            if not raw.strip():
                continue
            obj = _decode(raw)
            if spec['_include'] is not None and not matches(
                    obj, spec['_include']):
                continue
            t = parse_ts(extract(obj, ts_spec), ts_spec.get('format'))
            if t is None:
                continue
            row_lines.append(ln)
            if len(first) < 3000:
                first.append(t)
            if matcher is not None:
                r = matcher.feed(obj, t, ln)
                if r is not None:
                    chains.append(r)
            elif epi is not None and matches(obj, epi):
                if ep_cur is not None and t - ep_cur[1] <= gap:
                    ep_cur[1] = t
                    ep_cur[2].append(ln)
                else:
                    if ep_cur is not None:
                        chains.append(tuple(ep_cur) + ('',))
                    ep_cur = [t, t, [ln]]
    if ep_cur is not None:
        chains.append(tuple(ep_cur) + ('',))
    d = sorted(b - a for a, b in zip(first, first[1:]) if b > a)
    tick = 2 * d[len(d) // 2] if d else 0.0
    return {'rows': len(row_lines), 'row_lines': row_lines,
            'chains': chains, 'tick': tick}


def analyse(path, spec, blocks=1, tick=None):
    """Features of a capture, or of B contiguous row blocks of it."""
    p1 = pass1(path, spec)
    tick = p1['tick'] if tick is None else tick
    rl = p1['row_lines']
    per = max(1, math.ceil(len(rl) / blocks))
    bounds = [(rl[i], rl[min(i + per, len(rl)) - 1])
              for i in range(0, len(rl), per)]
    ts_spec = spec['timestamp']
    outs = []
    an = None
    bi = -1
    k = 0
    with open_capture(path) as fh:
        for ln, raw in enumerate(fh, 1):
            if not raw.strip():
                continue
            obj = _decode(raw)
            if spec['_include'] is not None and not matches(
                    obj, spec['_include']):
                continue
            raw_ts = extract(obj, ts_spec)
            t = parse_ts(raw_ts, ts_spec.get('format'))
            if t is None:
                continue
            if k // per != bi:
                if an is not None:
                    outs.append(an.finish())
                bi = k // per
                lo, hi = bounds[bi]
                chains = [c for c in p1['chains'] if lo <= c[2][0] <= hi]
                cl = set()
                for c in chains:
                    cl.update(c[2])
                label = path if blocks == 1 else f'{path}#{bi + 1}/{blocks}'
                an = Analyzer(spec, tick, chains, cl, t, label)
            an.row(obj, t, ln, raw_ts)
            k += 1
    if an is not None:
        outs.append(an.finish())
    for f in outs:
        f['path'] = path
        f['file_id'] = file_id(path) + (f'#{f["label"]}' if blocks > 1
                                        else '')
        f['tick'] = tick
        f['blocks'] = blocks
    return outs


# --------------------------------------------------------- comparisons

def pool_counts(refs, name, expo_key):
    xs, es = [], []
    for r in refs:
        es.append(r['expo'].get(expo_key, 0))
        xs.append(r['counts'].get(name, {}).get('n', 0))
    return xs, es


def dispersion(xs, es):
    s, big_e = sum(xs), sum(es)
    m = len([e for e in es if e > 0])
    if m < 3 or s < 5 or big_e <= 0:
        return 1.0
    chi = 0.0
    for x, e in zip(xs, es):
        if e <= 0:
            continue
        ex = e * s / big_e
        chi += (x - ex) ** 2 / ex
    return max(1.0, chi / (m - 1))


def count_below(smp, t):
    """Values strictly below t (exact within the low heap)."""
    n = smp['n']
    low = smp['low']
    c = 0
    for row in low:
        if row[0] < t:
            c += 1
        else:
            break
    if n <= len(low) or (low and low[-1][0] >= t):
        return c
    res = smp['res']
    if not res:
        return c
    return max(c, n * sum(1 for v in res if v < t) / len(res))


def exact_beyond(smp, t, lower):
    side = smp['low'] if lower else smp['high']
    if smp['n'] <= len(side):
        return True
    if not side:
        return False
    return side[-1][0] >= t if lower else side[-1][0] <= t


def count_above(smp, t):
    n = smp['n']
    high = smp['high']
    c = 0
    for row in high:
        if row[0] > t:
            c += 1
        else:
            break
    if n <= len(high) or (high and high[-1][0] <= t):
        return c
    res = smp['res']
    if not res:
        return c
    return max(c, n * sum(1 for v in res if v > t) / len(res))


def pooled_quantile(refs, q, lower=True):
    """Quantile of the pooled reference samples (by bisection)."""
    big_n = sum(s['n'] for s in refs)
    target = q * big_n
    cand = set()
    for s in refs:
        side = s['low'] if lower else s['high']
        cand.update(r[0] for r in side)
        cand.update(s['res'])
    cand = sorted(cand)
    if not cand:
        return None
    fn = count_below if lower else count_above
    if lower:
        lo, hi = 0, len(cand) - 1
        while lo < hi:
            mid = (lo + hi) // 2
            if sum(fn(s, cand[mid]) for s in refs) < target:
                lo = mid + 1
            else:
                hi = mid
        return cand[lo]
    lo, hi = 0, len(cand) - 1
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if sum(fn(s, cand[mid]) for s in refs) < target:
            hi = mid - 1
        else:
            lo = mid
    return cand[lo]


def weighted_ks(on, refs):
    pts = [(v, on['n'] / len(on['res']), 0) for v in on['res']] \
        if on['res'] else []
    wref = 0.0
    for s in refs:
        if s['res']:
            w = s['n'] / len(s['res'])
            pts.extend((v, w, 1) for v in s['res'])
            wref += s['n']
    if not on['res'] or wref <= 0:
        return None
    pts.sort()
    fa = fb = 0.0
    d = 0.0
    i = 0
    while i < len(pts):
        v = pts[i][0]
        while i < len(pts) and pts[i][0] == v:
            if pts[i][2] == 0:
                fa += pts[i][1] / on['n']
            else:
                fb += pts[i][1] / wref
            i += 1
        d = max(d, abs(fa - fb))
    n1 = min(on['n'], len(on['res']))
    n2 = min(wref, sum(len(s['res']) for s in refs))
    ne = n1 * n2 / (n1 + n2)
    return d, ne, ks_q(math.sqrt(ne) * d)


def gtest_tables(on, refs, min_exp=5.0):
    """G-test of on against the pooled refs, dispersion from refs."""
    ref_tot = Counter()
    for r in refs:
        ref_tot.update(r)
    n1, n2 = sum(on.values()), sum(ref_tot.values())
    if n1 < 20 or n2 < 20:
        return None
    cats = set(on) | set(ref_tot)
    merged_on, merged_ref = Counter(), Counter()
    per_ref = [Counter() for _ in refs]
    for c in cats:
        tot = on.get(c, 0) + ref_tot.get(c, 0)
        e1 = tot * n1 / (n1 + n2)
        key = c if min(e1, tot - e1) >= min_exp else '__other__'
        merged_on[key] += on.get(c, 0)
        merged_ref[key] += ref_tot.get(c, 0)
        for pr, r in zip(per_ref, refs):
            pr[key] += r.get(c, 0)
    keys = list(merged_on.keys() | merged_ref.keys())
    if len(keys) < 2:
        return None
    g = 0.0
    for c in keys:
        tot = merged_on[c] + merged_ref[c]
        for obs, n in ((merged_on[c], n1), (merged_ref[c], n2)):
            ex = tot * n / (n1 + n2)
            if obs > 0 and ex > 0:
                g += 2 * obs * math.log(obs / ex)
    df = len(keys) - 1
    delta = 1.0
    good = [pr for pr in per_ref if sum(pr.values()) >= 20]
    if len(good) >= 3:
        tot_c = Counter()
        for pr in good:
            tot_c.update(pr)
        big = sum(tot_c.values())
        gr = 0.0
        for pr in good:
            npr = sum(pr.values())
            for c in keys:
                ex = tot_c[c] * npr / big
                if pr[c] > 0 and ex > 0:
                    gr += 2 * pr[c] * math.log(pr[c] / ex)
        dfr = (len(good) - 1) * (len([c for c in keys if tot_c[c]]) - 1)
        if dfr > 0:
            delta = max(1.0, gr / dfr)
    x = g / delta
    p = chi2_sf(x, df)
    # worst cell for the report
    worst = max(keys, key=lambda c: abs(
        merged_on[c] / n1 - merged_ref[c] / n2))
    return p, g, df, delta, worst, merged_on[worst] / n1, \
        merged_ref[worst] / n2


def novelty(on_cat, ref_cats):
    ref = Counter()
    for r in ref_cats:
        ref.update(r['c'])
    n_ref = sum(ref.values())
    n_on = sum(on_cat['c'].values())
    if n_ref < 20 or n_on < 5:
        return None
    novel = {c: k for c, k in on_cat['c'].items() if c not in ref}
    items = sum(novel.values())
    f1 = sum(1 for v in ref.values() if v == 1)
    phi = items / len(novel) if novel else 1.0
    p, z, r_on, r_ref = count_test(items, n_on, f1, n_ref, phi, side='up')
    inst = []
    for c in novel:
        for i in on_cat['inst'].get(c, []):
            inst.append((i[0], i[1], i[2], novel[c] / max(
                len(on_cat['inst'].get(c, [])), 1), c))
    return p, z, items, len(novel), f1, n_ref, n_on, novel, inst


class Test:
    __slots__ = ('stat', 'cls', 'kind', 'p', 'z', 'detail', 'inst',
                 'rate_ref', 'e_on', 'p_cal', 'p_adj', 'prec')

    def __init__(self, stat, cls, kind, p, z, detail, inst=None,
                 rate_ref=None, e_on=None):
        self.stat, self.cls, self.kind = stat, cls, kind
        self.p, self.z, self.detail = p, z, detail
        self.inst = inst or []
        self.rate_ref, self.e_on = rate_ref, e_on
        self.p_cal = self.p_adj = None
        self.prec = None


def key_class(stat):
    tail = stat.split('.', 1)[-1] if '.' in stat else stat
    if stat.startswith('seq:') or stat.startswith('feat:'):
        return 'chain_features'
    if tail.startswith('gap_lt_'):
        return 'cooldown'
    if tail.startswith(('same_action', 'fail', 'giveup', 'trans600')):
        return 'chain_features'
    if tail.startswith(('per_period', 'fail_per_period')):
        return 'actor_counts'
    return 'tails'


def compare_features(on, refs, spec):
    """All comparative tests of on against the pooled refs."""
    tests = []
    # counts: actor-key windows, failures, sequences
    names = set(on['counts'])
    for r in refs:
        names.update(r['counts'])
    for name in sorted(names):
        if name.startswith(('seq:', 'feat:')):
            ek = 'rows'
        else:
            k, tail = name.split('.', 1)
            if tail.startswith(('fail', 'giveup')):
                ek = f'{k}.fails'
            else:
                ek = f'{k}.gaps'
        xs, es = pool_counts(refs, name, ek)
        e_on = on['expo'].get(ek, 0)
        st = on['counts'].get(name, {'n': 0, 'at': 0, 'at_rows': 0,
                                     'ex_at': [], 'ex_far': [], 'hit': []})
        x = st['n']
        extra = {}
        near_miss = name.startswith(('seq:', 'feat:'))
        if near_miss:
            # a chain sub-sequence (or custom sequence) is a background
            # near miss: instances on chain rows are the chain itself,
            # so they leave both the count test and the precision view
            x -= st.get('at_rows', 0)
            xs = [r['counts'].get(name, {}).get('n', 0)
                  - r['counts'].get(name, {}).get('at_rows', 0)
                  for r in refs]
            extra = {'ref_all': sum(r['counts'].get(name, {}).get('n', 0)
                                    for r in refs),
                     'ref_chains': sum(len(r['chains']) for r in refs),
                     'on_on_chain_rows': st.get('at_rows', 0)}
        if e_on <= 0 or sum(es) <= 0:
            continue
        phi = dispersion(xs, es)
        p, z, r_on, r_ref = count_test(x, e_on, sum(xs), sum(es), phi)
        t = Test(name, key_class(name), 'count', p, z, {
            'on': x, 'on_exposure': e_on, 'ref': sum(xs),
            'ref_exposure': sum(es), 'refs': len(refs),
            'phi': round(phi, 2), 'rate_on': round(r_on, 6),
            'rate_ref': round(r_ref, 6), 'on_at_chain': st['at'], **extra},
            rate_ref=(sum(xs) + 1) / sum(es), e_on=e_on)
        if near_miss:
            ar = st.get('at_rows', 0)
            t.detail['on_at_chain'] = st['at'] - ar
            ex_at = [e for e in st['ex_at']
                     if e[1] not in on['chain_lines']
                     and e[2] not in on['chain_lines']]
            t.inst = [('agg', st['n'] - ar, st['at'] - ar, ex_at,
                       st['ex_far'], st.get('hit_nr', []))]
        else:
            t.inst = [('agg', st['n'], st['at'], st['ex_at'],
                       st['ex_far'], st.get('hit', []))]
        tests.append(t)
    # samples: tails and bodies
    snames = set(on['samples'])
    for sname in sorted(snames):
        rs = [r['samples'][sname] for r in refs if sname in r['samples']]
        so = on['samples'][sname]
        if not rs or so['n'] < 20 or sum(s['n'] for s in rs) < 20:
            continue
        base = sname
        if sname.startswith('hold:'):
            cls = 'holds'
        elif sname.endswith('.gap_bg'):
            cls = 'rephase'
        elif sname.startswith('act:'):
            cls = 'tails'
        else:
            cls = key_class(sname)
        big_n = sum(s['n'] for s in rs)
        if sname.endswith('.gap_bg') or sname.startswith('hold:'):
            ks = weighted_ks(so, rs)
            if ks:
                d, ne, p = ks
                tests.append(Test(f'{base}:body', 'rephase' if
                                  sname.endswith('.gap_bg') else 'holds',
                                  'ks', p, p_to_z(p), {
                                      'D': round(d, 4), 'n_eff': round(ne)}))
            if sname.endswith('.gap_bg'):
                continue
        if sname.endswith(('per_period', 'fail_per_period')):
            sides = [('max', None, False), ('q0.95', 0.05, False)]
        elif sname.startswith('act:'):
            sides = [('min', None, True), ('q0.01', 0.01, True),
                     ('max', None, False)]
        else:
            sides = [('min', None, True), ('q0.001', 0.001, True),
                     ('q0.01', 0.01, True), ('q0.05', 0.05, True),
                     ('max', None, False), ('q0.99', 0.01, False)]
        for lab, q, lower in sides:
            if q is not None and q * big_n < 5:
                continue
            if q is None:
                thr = min(s['low'][0][0] for s in rs if s['low']) if lower \
                    else max(s['high'][0][0] for s in rs if s['high'])
                s_ref = 0.0
                xs_i = [0.0] * len(rs)
            else:
                thr = pooled_quantile(rs, q, lower)
                if thr is None:
                    continue
                # only exact counts: a reservoir estimate adds sampling
                # noise the count model does not know about
                if not all(exact_beyond(s, thr, lower) for s in rs + [so]):
                    continue
                fn = count_below if lower else count_above
                xs_i = [fn(s, thr) for s in rs]
                s_ref = sum(xs_i)
            fn = count_below if lower else count_above
            c_on = fn(so, thr)
            phi = dispersion(xs_i, [s['n'] for s in rs]) if q else 1.0
            side = 'up' if q is None else 'two'
            p, z, r_on, r_ref = count_test(c_on, so['n'], s_ref, big_n, phi,
                                           side=side)
            if sname.endswith(('per_period', 'fail_per_period')):
                side_rows = so['high']
            else:
                side_rows = so['low'] if lower else so['high']
            inst = [r for r in side_rows
                    if (r[0] < thr if lower else r[0] > thr)]
            tests.append(Test(f'{base}:{"low" if lower else "high"}-{lab}',
                              cls, 'tail', p, z, {
                                  'threshold': round(thr, 4),
                                  'on_beyond': round(c_on, 1),
                                  'on_n': so['n'],
                                  'ref_beyond': round(s_ref, 1),
                                  'ref_n': big_n, 'phi': round(phi, 2),
                                  'on_extreme': (so['low'][0][0] if lower
                                                 else so['high'][0][0])
                                  if (so['low'] and so['high']) else None,
                                  'ref_extreme': thr if q is None else (
                                      min(s['low'][0][0] for s in rs
                                          if s['low']) if lower else
                                      max(s['high'][0][0] for s in rs
                                          if s['high']))},
                              inst=[('rows', inst)],
                              rate_ref=(s_ref + 1) / big_n, e_on=so['n']))
    # categorical novelty and mixes
    for cname in sorted(on['cats']):
        rc = [r['cats'][cname] for r in refs if cname in r['cats']]
        if not rc:
            continue
        oc = on['cats'][cname]
        if cname == 'mix.action_all':
            g = gtest_tables(Counter(oc['c']), [Counter(r['c']) for r in rc])
            if g:
                p, gg, df, delta, worst, a1, a2 = g
                tests.append(Test('mix.action:chi2', 'mix', 'chi2', p,
                                  p_to_z(p), {'G': round(gg, 1), 'df': df,
                                              'dispersion': round(delta, 2),
                                              'worst': worst,
                                              'share_on': round(a1, 4),
                                              'share_ref': round(a2, 4)}))
            cls = 'chain_features'
        elif cname == 'rephase.runlen':
            binned = [Counter(), *[Counter() for _ in rc]]
            for i, src in enumerate([oc] + rc):
                for kk, v in src['c'].items():
                    binned[i][run_bin(int(kk))] += v
            g = gtest_tables(binned[0], binned[1:])
            if g:
                p, gg, df, delta, worst, a1, a2 = g
                tests.append(Test('rephase.runlen:chi2', 'rephase', 'chi2',
                                  p, p_to_z(p), {
                                      'G': round(gg, 1), 'df': df,
                                      'dispersion': round(delta, 2),
                                      'worst_bin': worst,
                                      'share_on': round(a1, 4),
                                      'share_ref': round(a2, 4)}))
            cls = 'rephase'
        elif cname.endswith(('gapmin_bg',)):
            cls = 'rephase'
        else:
            cls = 'chain_features'
        nv = novelty(oc, rc)
        if nv:
            p, z, items, ncat, f1, n_ref, n_on, novel, inst = nv
            top = sorted(novel.items(), key=lambda x: -x[1])[:6]
            tests.append(Test(f'{cname}:novel', cls, 'novelty', p, z, {
                'novel_items': items, 'novel_categories': ncat,
                'ref_singletons': f1, 'ref_items': n_ref, 'on_items': n_on,
                'top_novel': top},
                inst=[('novel', inst)], rate_ref=(f1 + 1) / n_ref,
                e_on=n_on))
    # volume
    xs = [r['rows'] for r in refs]
    es = [r['span_s'] / 3600 for r in refs]
    if sum(es) > 0 and on['span_s'] > 0:
        phi = dispersion(xs, es)
        p, z, r_on, r_ref = count_test(on['rows'], on['span_s'] / 3600,
                                       sum(xs), sum(es), phi)
        tests.append(Test('mix.volume', 'mix', 'count', p, z, {
            'rows_per_h_on': round(r_on, 2), 'rows_per_h_ref': round(r_ref, 2),
            'phi': round(phi, 2)}))
    # phases of busy actions and subclass keys
    busy = {a for a, _ in Counter({k.rsplit('@', 1)[0]: sum(v) for k, v in
                                   on['phase'].items()}).most_common(
        TOP_ACTIONS)}
    for pk in sorted(on['phase']):
        a, P = pk.rsplit('@', 1)
        if a not in busy and not a.startswith('key:'):
            continue
        rph = [Counter(dict(enumerate(r['phase'][pk]))) for r in refs
               if pk in r['phase']]
        if not rph:
            continue
        g = gtest_tables(Counter(dict(enumerate(on['phase'][pk]))), rph)
        if g:
            p, gg, df, delta, worst, a1, a2 = g
            tests.append(Test(f'phase:{a}@{P}', 'rephase', 'chi2', p,
                              p_to_z(p), {'G': round(gg, 1), 'df': df,
                                          'dispersion': round(delta, 2),
                                          'worst_bin': worst,
                                          'share_on': round(a1, 4),
                                          'share_ref': round(a2, 4)}))
    # rotation deviations (deterministic successors of the refs)
    for kname in on['rot']:
        for kind, tab, tr in (('actor', 'succ', 'trans'),
                              ('target', 'tsucc', 'ttrans')):
            t = rotation_test(on, refs, kname, tab, tr)
            if t is not None:
                p, z, detail, inst, rate, e_on = t
                tests.append(Test(f'{kname}.rot_{kind}', 'rotation', 'count',
                                  p, z, detail, inst=[('rows', inst)],
                                  rate_ref=rate, e_on=e_on))
    return tests


def run_bin(n):
    for lim, lab in ((1, '1'), (2, '2'), (3, '3'), (4, '4'), (7, '5-7'),
                     (15, '8-15'), (31, '16-31'), (63, '32-63')):
        if n <= lim:
            return lab
    return '64+'


def modal_map(tabs):
    pooled = {}
    for tab in tabs:
        for x, c in tab.items():
            pc = pooled.setdefault(x, Counter())
            pc.update(c)
    out = {}
    for x, c in pooled.items():
        n = sum(c.values())
        if n >= 10:
            y, k = c.most_common(1)[0]
            if k / n >= 0.8:
                out[x] = y
    return out


def rotation_test(on, refs, kname, tab, tr):
    rtabs = [r['rot'][kname][tab] for r in refs if kname in r['rot']]
    if not rtabs:
        return None
    mp = modal_map(rtabs)
    if not mp:
        return None
    s = big_e = 0
    for i, rt in enumerate(rtabs):
        others = [o for j, o in enumerate(rtabs) if j != i]
        m_i = modal_map(others) if others else mp
        for x, c in rt.items():
            if x in m_i and x in mp:
                n = sum(c.values())
                big_e += n
                s += n - c.get(m_i[x], 0)
    e_on = 0
    dev = []
    for x, y, t, ln in on['rot'][kname][tr]:
        if x in mp:
            e_on += 1
            if y != mp[x]:
                dev.append([0, t, ln, -1])
    if e_on < 10 or big_e < 10:
        return None
    p, z, r_on, r_ref = count_test(len(dev), e_on, s, big_e, 1.0)
    detail = {'deterministic_predecessors': len(mp), 'on_changes': e_on,
              'on_deviations': len(dev), 'ref_changes': big_e,
              'ref_deviations': s, 'rate_on': round(r_on, 4),
              'rate_ref': round(r_ref, 4)}
    return p, z, detail, dev, (s + 1) / big_e, e_on


# --------------------------------------------------- precision view

def precision_view(test, on):
    """How well the statistic's on instances locate chain occurrences.

    An instance is episode-attributable when one of its rows is a chain
    row or its time falls in [chain start - pre_s, chain end + near_s].
    precision = excess attributable instances / (excess + expected
    background instances in the whole on capture), where the background
    rate comes from the reference pool with a +1 prior.

    Near-miss statistics (chain sub-sequences, custom sequences) arrive
    here without their instances on chain rows: an episode always
    contains its own sub-sequences, so counting them would measure the
    episode rate, not a tell.  Their precision says whether near misses
    outside the chain rows cluster around episodes.
    """
    chains = on['chains']
    if not chains or test.rate_ref is None or not test.inst:
        return None
    win = on['win']
    lines = set(on['chain_lines'])
    kind, *payload = test.inst[0]
    at = far = 0.0
    hit = set()
    if kind == 'agg':
        n, n_at, _, _, hits = payload
        at, far = float(n_at), float(n - n_at)
        hit = set(hits)
    else:
        for r in payload[0]:
            if kind == 'novel':
                t, l1, l2, w = r[0], r[1], r[2], r[3]
            else:
                t, l1, l2, w = r[1], r[2], r[3], 1.0
            if l1 == -1 and kind == 'rows' and 'per_period' in test.stat:
                ok = l2 == 1
            else:
                ok = l1 in lines or l2 in lines or in_windows(win, t)
            if ok:
                at += w
                ci = window_index(win, t)
                if ci is not None:
                    hit.add(ci)
            else:
                far += w
    recall = len(hit) / len(chains)
    if at <= 0:
        return {'at': 0, 'far': round(far, 1), 'precision': 0.0,
                'recall': round(recall, 3), 'chains': len(chains)}
    span = max(on['span_s'], 1.0)
    frac = min(1.0, sum(b - a for a, b in win) / span)
    exp_bg = test.rate_ref * test.e_on
    mu_in = exp_bg * frac
    excess = max(0.0, at - mu_in)
    prec = excess / (excess + exp_bg) if excess + exp_bg > 0 else 0.0
    return {'at': round(at, 1), 'far': round(far, 1),
            'expected_bg': round(exp_bg, 2),
            'expected_in_windows': round(mu_in, 2),
            'precision': round(prec, 3), 'recall': round(recall, 3),
            'chains': len(chains)}


def precision_level(pv):
    if not pv:
        return 'OK'
    if pv['precision'] >= 0.8 and pv['recall'] >= 0.5 and pv['at'] >= 3:
        return 'FAIL'
    if pv['precision'] >= 0.5 and pv['recall'] >= 0.3 and pv['at'] >= 2:
        return 'SUSPECT'
    return 'OK'


# -------------------------------------------------------- calibration

def calibrate_tests(tests, lam):
    """Rescale raw z by per-statistic inflation, t-tail, Holm."""
    for t in tests:
        info = lam.get(t.stat)
        if info is None:
            cl = lam.get('__class__:' + t.cls, {'lam': 1.0, 'df': PRIOR_DF})
            lm, df = cl['lam'], PRIOR_DF
        else:
            lm, df = info['lam'], info['df']
        zc = t.z / math.sqrt(max(lm, 1.0))
        t.p_cal = min(1.0, t_sf2(zc, df)) if df < 1000 else t.p
    adj = holm([t.p_cal for t in tests])
    for t, a in zip(tests, adj):
        t.p_adj = a


def lambdas_from(nulls):
    """Per-statistic inflation from null z values (prior toward 1)."""
    lam = {}
    by_cls = {}
    for stat, (cls, zs) in nulls.items():
        s2 = sum(z * z for z in zs)
        lm = max(1.0, (s2 + PRIOR_DF) / (len(zs) + PRIOR_DF))
        lam[stat] = {'lam': round(lm, 3), 'df': len(zs) + PRIOR_DF,
                     'null_z': [round(z, 2) for z in zs]}
        by_cls.setdefault(cls, []).append(lm)
    for cls, v in by_cls.items():
        lam['__class__:' + cls] = {'lam': round(sorted(v)[len(v) // 2], 3),
                                   'df': PRIOR_DF}
    return lam


def loo_nulls(feats, spec, idx=None):
    nulls = {}
    rng = range(len(feats)) if idx is None else idx
    for i in rng:
        refs = [f for j, f in enumerate(feats) if j != i and (
            idx is None or j in idx)]
        if not refs:
            continue
        for t in compare_features(feats[i], refs, spec):
            nulls.setdefault(t.stat, (t.cls, []))[1].append(t.z)
    return nulls


def strip_for_calib(f):
    g = dict(f)
    g['samples'] = {k: {'n': s['n'], 'low': [[r[0], 0, -1, -1]
                                            for r in s['low']],
                        'high': [[r[0], 0, -1, -1] for r in s['high']],
                        'res': s['res']}
                    for k, s in f['samples'].items()}
    g['cats'] = {k: {'c': c['c'], 'inst': {}, 'overflow': c['overflow']}
                 for k, c in f['cats'].items()}
    g['rot'] = {k: {'succ': v['succ'], 'tsucc': v['tsucc'], 'trans': [],
                    'ttrans': []} for k, v in f['rot'].items()}
    return g


def verdict(tests, on, absolute, spec):
    classes = {c: {'level': 'OK', 'findings': []} for c in CLASSES}
    for t in tests:
        lvl = 'OK'
        why = []
        if t.p_adj is not None and t.p_adj < ALPHA_FAIL:
            lvl = 'FAIL'
            why.append('calibrated')
        elif t.p_adj is not None and t.p_adj < ALPHA_SUSPECT:
            lvl = 'SUSPECT'
            why.append('calibrated')
        t.prec = precision_view(t, on)
        pl = precision_level(t.prec)
        if pl != 'OK' and t.z > 0:
            lvl = up(lvl, pl)
            why.append('precision')
        if lvl != 'OK':
            classes[t.cls]['level'] = up(classes[t.cls]['level'], lvl)
            classes[t.cls]['findings'].append({
                'level': lvl, 'stat': t.stat, 'kind': t.kind,
                'basis': why, 'p_raw': _sig(t.p), 'p_cal': _sig(t.p_cal),
                'p_holm': _sig(t.p_adj), 'z': round(t.z, 2),
                'detail': t.detail, 'precision': t.prec,
                'examples': examples_of(t, on)})
    for cls, lvl, text, ex in absolute:
        classes[cls]['level'] = up(classes[cls]['level'], lvl)
        classes[cls]['findings'].append({'level': lvl, 'stat': 'absolute',
                                         'basis': ['absolute'],
                                         'detail': text, 'examples': ex})
    for c in classes.values():
        c['findings'].sort(key=lambda f: (-LEVELS.index(f['level']),
                                          f.get('p_holm') or 1))
    return classes


def _sig(p):
    return None if p is None else float(f'{p:.3g}')


def examples_of(t, on):
    if not t.inst:
        return []
    kind, *payload = t.inst[0]
    out = []
    if kind == 'agg':
        n, n_at, ex_at, ex_far, _ = payload
        for e in (ex_at + ex_far)[:4]:
            out.append({'t': e[0], 'lines': [x for x in e[1:] if x != -1]})
        return out
    rows = payload[0]
    if kind == 'novel':
        for r in rows[:4]:
            out.append({'t': r[0], 'category': r[4],
                        'lines': [x for x in r[1:3] if x != -1]})
        return out
    for r in rows[:4]:
        lines = [] if r[2] == -1 else [x for x in r[2:4] if x != -1]
        out.append({'value': r[0], 't': r[1], 'lines': lines})
    return out


# ----------------------------------------------------- absolute checks

def absolute_checks(f, spec):
    """Determinism of one capture's background, judged against chance."""
    a = f['absolute']
    out = []
    for name, k in a['keys'].items():
        if k['actors'] >= 5 and k['succ_n'] >= 50:
            sd, ex = k['succ_det'], k['succ_det_expected']
            if sd >= 0.85 and sd - ex >= 0.5:
                out.append(('rotation', 'FAIL',
                            f'{name}: fixed actor rotation, next actor is '
                            f'the modal successor in {sd:.0%} of changes '
                            f'(chance {ex:.0%})', []))
            elif sd >= 0.6 and sd - ex >= 0.3:
                out.append(('rotation', 'SUSPECT',
                            f'{name}: successor determinism {sd:.0%} '
                            f'(chance {ex:.0%})', []))
        if k['tsucc_n'] >= 20:
            sd, ex = k['tsucc_det'], k['tsucc_det_expected']
            if sd >= 0.85 and sd - ex >= 0.5:
                out.append(('rotation', 'FAIL',
                            f'{name}: per-actor target order is fixed, next '
                            f'target is the modal successor in {sd:.0%} '
                            f'(chance {ex:.0%})', []))
            elif sd >= 0.6 and sd - ex >= 0.3:
                out.append(('rotation', 'SUSPECT',
                            f'{name}: per-actor target successor '
                            f'determinism {sd:.0%} (chance {ex:.0%})', []))
        if k['actors'] >= 3 and k['rr_share'] - k['rr_expected'] >= 0.5 \
                and k['rr_share'] >= 0.9:
            out.append(('lockstep', 'FAIL',
                        f'{name}: strict round-robin, actor(i)=actor(i-'
                        f'{k["rr_lag"]}) in {k["rr_share"]:.0%} (chance '
                        f'{k["rr_expected"]:.0%})', []))
        elif k['actors'] >= 3 and k['rr_share'] >= 0.6 and \
                k['rr_share'] - k['rr_expected'] >= 0.3:
            out.append(('lockstep', 'SUSPECT',
                        f'{name}: near round-robin lag {k["rr_lag"]} share '
                        f'{k["rr_share"]:.0%}', []))
        ds = k['dominant_period_share']
        if ds is not None and k['actors_5plus_gaps'] >= 5:
            if ds >= 0.8 and len(k['dominant_periods']) <= 2:
                out.append(('lockstep', 'FAIL',
                            f'{name}: {ds:.0%} of actors repeat one period '
                            f'{k["dominant_periods"]}', []))
            elif ds >= 0.5:
                out.append(('lockstep', 'SUSPECT',
                            f'{name}: {ds:.0%} of actors on a fixed period '
                            f'{k["dominant_periods"]}', []))
        if k['long_gaps'] >= 50:
            if k['repeat_gap_share'] >= 0.8:
                out.append(('lockstep', 'FAIL',
                            f'{name}: {k["repeat_gap_share"]:.0%} of gaps '
                            'repeat the previous gap exactly', []))
            elif k['repeat_gap_share'] >= 0.5:
                out.append(('lockstep', 'SUSPECT',
                            f'{name}: repeat-gap share '
                            f'{k["repeat_gap_share"]:.0%}', []))
        ag, ex = k['seq_agreement'], k['seq_expected']
        if (ag is not None and ag >= 0.9 and ex < 0.6
                and k['seq_distinct'] == 1 and k['seq_types'] >= 3):
            out.append(('lockstep', 'FAIL',
                        f'{name}: every actor runs the same action sequence '
                        f'(agreement {ag:.0%}, chance {ex:.0%})', []))
    hard = [p for p in a['periodic_actions'] if p[2] >= 0.9]
    if hard:
        out.append(('lockstep', 'FAIL', 'action types on a fixed period '
                    f'(action, gap s, share, n): {hard[:4]}', []))
    elif a['periodic_actions']:
        out.append(('lockstep', 'SUSPECT', 'action types near-periodic '
                    f'(action, gap s, share, n): '
                    f'{a["periodic_actions"][:4]}', []))
    ap = a['action_period']
    if ap['lag'] and ap['lag'] > 2 and ap['n_actions'] >= 3:
        sh, ex = ap['share'], ap['expected']
        if (sh >= 0.95 and ex < 0.6) or (sh >= 0.99 and ex < 0.9):
            out.append(('lockstep', 'FAIL',
                        f'action sequence repeats with period {ap["lag"]} '
                        f'rows in {sh:.0%} of rows (chance {ex:.0%})', []))
        elif sh >= 0.8 and sh - ex >= 0.3:
            out.append(('lockstep', 'SUSPECT',
                        f'action sequence near-periodic, lag {ap["lag"]} '
                        f'share {sh:.0%} (chance {ex:.0%})', []))
    # A long single-type run is lockstep only when many actors share it
    # (a population wave); one actor's retry burst is ordinary.
    for act, mx, exp, ratio, distinct in a['run_excess'][:3]:
        wave = distinct >= 5 and distinct >= 0.3 * mx
        if not wave:
            continue
        if mx >= 20 and ratio >= 5:
            out.append(('lockstep', 'FAIL',
                        f'action run {act!r} x{mx} over {distinct} actors '
                        f'(expected ~{exp})', []))
            break
        if mx >= 10 and ratio >= 3:
            out.append(('lockstep', 'SUSPECT',
                        f'action run {act!r} x{mx} over {distinct} actors '
                        f'(expected ~{exp})', []))
            break
    for w in a['waves']:
        act, obs, with_, spacing, share, nmax, nmean = w
        if obs >= 3 and obs <= 0.5 * with_ and share >= 0.6 and \
                (spacing or 0) >= 2 and obs > 2 * nmax + 2:
            out.append(('lockstep', 'FAIL',
                        f'global waves of {act!r}: {obs} windows with >=80% '
                        f'of its actors, every {spacing * 30} min; '
                        f'circular-shift null max {nmax}', []))
        elif obs >= 3 and obs > 2 * nmax + 2:
            out.append(('lockstep', 'SUSPECT',
                        f'synchronised actors for {act!r}: {obs} windows vs '
                        f'null max {nmax}', []))
    for act, P, sh, gsh, n in a['phase_conc']:
        if sh >= 0.5 and gsh <= 0.25:
            out.append(('lockstep', 'FAIL',
                        f'{act!r} sits on a {P} s grid: {sh:.0%} of {n} in '
                        f'one phase bin (all events {gsh:.0%})', []))
        elif sh >= 0.3 and sh >= 2.5 * gsh:
            out.append(('lockstep', 'SUSPECT',
                        f'{act!r} phase-concentrated at {P} s: {sh:.0%} in '
                        f'one bin (all events {gsh:.0%})', []))
    if a['empty_buckets'] >= 3 and a['empty_spacing']:
        sp, c = a['empty_spacing'][0]
        n_sp = max(a['empty_buckets'] - 1, 1)
        if sp > 1 and c >= 5 and c / n_sp >= 0.6:
            out.append(('lockstep', 'SUSPECT',
                        f'empty 10 min windows at fixed spacing {sp}x10 min '
                        f'({c} times)', []))
    for name, v, share, n, distinct in a['holds']:
        if n >= 20 and share >= 0.5:
            out.append(('holds', 'FAIL',
                        f'{name}: {share:.0%} of {n} durations are exactly '
                        f'{v} s ({distinct} distinct values)', []))
        elif n >= 20 and share >= 0.2:
            out.append(('holds', 'SUSPECT',
                        f'{name}: {share:.0%} of durations are exactly {v} s',
                        []))
    low = []
    if a['ts_frac_distinct'] == 1 and a.get('frac_rows'):
        low.append(f'timestamp fraction always {a["ts_frac_top"][0][0]}')
    if a['sec_of_min_distinct'] == 1:
        low.append('every timestamp shares one second-of-minute')
    for k, v in a['iso_delta'].items():
        if v[-1] == 1 and v[0][0] not in ('0.0', '-0.0'):
            low.append(f'{k} = timestamp + {v[0][0]} s in every row')
    for k, v in a['iso_frac'].items():
        if v[1] == 1 and v[0][0][0] != 'none':
            low.append(f'{k} fraction always {v[0][0][0]}')
    for k, v in a['text_frac'].items():
        if v[1] == 1 and v[0][0][0] != 'none':
            low.append(f'{k} clock fraction always {v[0][0][0]}')
    if a['const_time_fields']:
        low.append(f'constant time-like fields {a["const_time_fields"][:5]}')
    for k, act, d, share, n in a['increments'][:4]:
        low.append(f'{k} increments by exactly {d} between consecutive '
                   f'{act or "rows"} ({share:.0%} of {n})')
    if low:
        lvl = 'FAIL' if spec.get('strict_constants') else 'SUSPECT'
        out.append(('constants', lvl, 'LOW: ' + '; '.join(low), []))
    return out


# ------------------------------------------------------------ commands

def cmd_calibrate(args):
    spec = compile_spec(json.load(open(args.spec)))
    feats = []
    whole = []
    for path in args.off:
        print(f'analysing {path}', file=sys.stderr)
        feats.extend(analyse(path, spec, blocks=args.split))
        if args.split > 1:
            # whole captures stay the comparison reference; blocks only
            # measure the inflation of each statistic
            whole.extend(analyse(path, spec))
    if len(feats) < 4:
        print('calibration needs at least 4 off captures or blocks '
              '(use --split)', file=sys.stderr)
        return 3
    print(f'leave-one-out over {len(feats)} captures', file=sys.stderr)
    nulls = loo_nulls(feats, spec)
    lam = lambdas_from(nulls)
    # nested leave-one-out: empirical false-failure rate
    per = []
    held = list(range(len(feats)))[:args.max_nested]
    for i in held:
        others = [j for j in range(len(feats)) if j != i]
        if len(others) < 3:
            continue
        lam_i = lambdas_from(loo_nulls(feats, spec, others))
        refs = [feats[j] for j in others]
        tests = compare_features(feats[i], refs, spec)
        calibrate_tests(tests, lam_i)
        cls = verdict(tests, feats[i], [], spec)
        lv = 'OK'
        worst = []
        for c, v in cls.items():
            lv = up(lv, v['level'])
            for fd in v['findings'][:2]:
                worst.append((c, fd['level'], fd['stat']))
        per.append({'capture': feats[i]['label'], 'level': lv,
                    'findings': worst[:6], 'tests': len(tests)})
        print(f'  nested {feats[i]["label"]}: {lv} {worst[:3]}',
              file=sys.stderr)
    nf = sum(1 for p in per if p['level'] == 'FAIL')
    ns = sum(1 for p in per if p['level'] != 'OK')
    out = {
        'tool': 'mode_compare', 'version': VERSION,
        'spec': os.path.realpath(args.spec),
        'spec_sha256': spec_hash(args.spec),
        'split': args.split,
        'alpha': {'fail': ALPHA_FAIL, 'suspect': ALPHA_SUSPECT,
                  'prior_df': PRIOR_DF},
        'captures': [strip_for_calib(f) for f in feats + whole],
        'lambda': lam,
        'null_tests_per_comparison': round(
            sum(len(v[1]) for v in nulls.values()) / max(len(feats), 1)),
        'nested_loo': per,
        'false_failure': {
            'nominal_fail': ALPHA_FAIL, 'nominal_suspect': ALPHA_SUSPECT,
            'empirical_fail': f'{nf}/{len(per)}',
            'empirical_suspect_or_fail': f'{ns}/{len(per)}'},
    }
    with open(args.out, 'w') as fh:
        json.dump(out, fh, default=str, separators=(',', ':'))
    inflated = sorted(((k, v['lam']) for k, v in lam.items()
                       if not k.startswith('__') and v['lam'] > 2),
                      key=lambda x: -x[1])[:8]
    print(f'calibration: {len(feats)} captures, {len(lam)} statistics, '
          f'nested LOO FAIL {nf}/{len(per)}, SUSPECT-or-FAIL {ns}/{len(per)}')
    print(f'most inflated statistics (lambda): {inflated}')
    return 0


def read_lines(path, wanted):
    got = {}
    if not wanted:
        return got
    with open_capture(path) as fh:
        for ln, raw in enumerate(fh, 1):
            if ln in wanted:
                got[ln] = raw.decode('utf-8', 'replace').strip()
                if len(got) == len(wanted):
                    break
    return got


def excerpt(raw, spec):
    try:
        obj = json.loads(raw)
    except ValueError:
        return raw[:160]
    parts = []
    ts = extract(obj, spec['timestamp'])
    parts.append(str(ts))
    for a in spec['actors'][:2]:
        v = extract(obj, a)
        if v is not None:
            parts.append(f'{a["name"]}={v}')
    act = extract(obj, spec.get('action'))
    if act:
        parts.append(f'action={act}')
    tgt = extract(obj, spec.get('target'))
    if tgt:
        parts.append(f'target={tgt[:60]}')
    return ' '.join(parts)


def cmd_compare(args):
    spec = compile_spec(json.load(open(args.spec)))
    cal = json.load(open(args.calib))
    if cal.get('spec_sha256') != spec_hash(args.spec):
        print('warning: spec differs from the calibration spec',
              file=sys.stderr)
    print(f'analysing {args.on}', file=sys.stderr)
    on = analyse(args.on, spec)[0]
    print(f'analysing {args.off}', file=sys.stderr)
    off = analyse(args.off, spec)[0]
    # Blocks of a split calibration serve the inflation estimates only:
    # a block is shorter than a capture, so its long gaps and per-period
    # counts are censored.  The reference pool holds whole captures.
    refs = [c for c in cal['captures'] if c.get('blocks', 1) == 1]
    ids = {c.get('file_id') for c in refs}
    if off['file_id'] not in ids:
        refs.append(off)
    lam = cal['lambda']
    tests = compare_features(on, refs, spec)
    calibrate_tests(tests, lam)
    absolute = absolute_checks(off, spec)
    classes = verdict(tests, on, absolute, spec)
    # off against the calibration pool: config sanity
    sanity = None
    full = [c for c in cal['captures'] if c.get('blocks', 1) == 1]
    if off['file_id'] not in ids and full:
        st = compare_features(off, full, spec)
        calibrate_tests(st, lam)
        bad = [t.stat for t in st if t.p_adj < ALPHA_FAIL]
        sanity = {'off_vs_calibration_fail_stats': bad[:10],
                  'n': len(bad)}
    overall = 'OK'
    for c in classes.values():
        overall = up(overall, c['level'])
    on_abs = absolute_checks(on, spec)
    wanted = set()
    for c in classes.values():
        for fd in c['findings'][:3]:
            for e in fd.get('examples', [])[:3]:
                wanted.update(e.get('lines', []))
    rows = read_lines(args.on, wanted)
    for c in classes.values():
        for fd in c['findings'][:3]:
            for e in fd.get('examples', [])[:3]:
                e['rows'] = [f'{ln}: {excerpt(rows[ln], spec)}'
                             for ln in e.get('lines', []) if ln in rows]
    report = {
        'tool': 'mode_compare', 'version': VERSION,
        'on': args.on, 'off': args.off, 'calib': args.calib,
        'verdict': overall,
        'classes': classes,
        'tests': len(tests),
        'references': len(refs),
        'episodes_on': len(on['chains']),
        'episodes_off': len(off['chains']),
        'rows': {'on': on['rows'], 'off': off['rows']},
        'false_failure': cal.get('false_failure'),
        'off_sanity': sanity,
        'on_absolute': [(c, lv, t) for c, lv, t, _ in on_abs],
    }
    if args.out:
        with open(args.out, 'w') as fh:
            json.dump(report, fh, indent=1, default=str)
    print_report(report)
    return {'OK': 0, 'SUSPECT': 1, 'FAIL': 2}[overall]


def print_report(r):
    print(f'VERDICT {r["verdict"]}  on={r["on"]}  off={r["off"]}')
    print(f'  rows on/off {r["rows"]["on"]}/{r["rows"]["off"]}, chain '
          f'occurrences on/off {r["episodes_on"]}/{r["episodes_off"]}, '
          f'{r["tests"]} tests vs {r["references"]} reference captures')
    ff = r.get('false_failure') or {}
    print(f'  expected false-failure: nominal FAIL {ff.get("nominal_fail")}'
          f' / SUSPECT {ff.get("nominal_suspect")}, calibration nested LOO '
          f'FAIL {ff.get("empirical_fail")}, SUSPECT-or-FAIL '
          f'{ff.get("empirical_suspect_or_fail")}')
    if r.get('off_sanity') and r['off_sanity']['n']:
        print(f'  WARNING off differs from calibration pool in '
              f'{r["off_sanity"]["n"]} statistics: '
              f'{r["off_sanity"]["off_vs_calibration_fail_stats"]}')
    for cls, c in r['classes'].items():
        print(f'  [{c["level"]:7}] {cls}')
        for fd in c['findings'][:4]:
            if fd['stat'] == 'absolute':
                print(f'      {fd["level"]}: {fd["detail"]}')
                continue
            pv = fd.get('precision') or {}
            ptxt = (f' precision {pv.get("precision")} recall '
                    f'{pv.get("recall")} at-chain {pv.get("at")}'
                    if pv else '')
            print(f'      {fd["level"]}: {fd["stat"]} p_holm={fd["p_holm"]}'
                  f' z={fd["z"]}{ptxt} {short(fd["detail"])}')
            for e in fd.get('examples', [])[:2]:
                for row in e.get('rows', [])[:2]:
                    print(f'          e.g. {row}')


def short(d):
    s = json.dumps(d, default=str)
    return s if len(s) < 260 else s[:257] + '...'


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    sub = ap.add_subparsers(dest='cmd', required=True)
    c = sub.add_parser('calibrate')
    c.add_argument('--spec', required=True)
    c.add_argument('--off', nargs='+', required=True)
    c.add_argument('--out', required=True)
    c.add_argument('--split', type=int, default=1,
                   help='treat each capture as B contiguous row blocks')
    c.add_argument('--max-nested', type=int, default=8)
    m = sub.add_parser('compare')
    m.add_argument('--spec', required=True)
    m.add_argument('--calib', required=True)
    m.add_argument('--on', required=True)
    m.add_argument('--off', required=True)
    m.add_argument('--out')
    args = ap.parse_args(argv)
    try:
        if args.cmd == 'calibrate':
            return cmd_calibrate(args)
        return cmd_compare(args)
    except (OSError, ValueError, KeyError) as e:
        print(f'error: {e}', file=sys.stderr)
        return 3


if __name__ == '__main__':
    sys.exit(main())

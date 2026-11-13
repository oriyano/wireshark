#!/usr/bin/env python3
#
# Kitsune passive fingerprint reference matcher
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''Reference implementation of the matching and scoring rules in
kitsune/data/fingerprints/README.md.

This is the executable form of the spec: the C++ inventory engine should
give the same answer for every vector in test_vectors.json. It uses only
the Python standard library.

Usage as a script:
    kitsune_fp.py VECTORS.json      # print the guess for each vector
'''

import json
import math
import re
import sys
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent
TTL_CLASSES = (32, 64, 128, 255)
REGEX_SOURCES = ('dhcp_vendor_class', 'http_user_agent', 'http_server', 'ssh_banner')


def initial_ttl(observed):
    '''The smallest common initial TTL that is at least the observed one.'''
    for ttl in TTL_CLASSES:
        if observed <= ttl:
            return ttl
    raise ValueError(f'TTL {observed} out of range')


def normalize_options(options):
    '''Collapse trailing EOL padding to a single "eol".'''
    parts = [p for p in options.split(',') if p]
    while len(parts) >= 2 and parts[-1] == 'eol' and parts[-2] == 'eol':
        parts.pop()
    return ','.join(parts)


class Database:
    def __init__(self, data_dir=DATA_DIR):
        data_dir = Path(data_dir)
        self.labels = {}
        for label in _load(data_dir / 'labels.json')['labels']:
            self.labels[label['id']] = label
        self.scoring = _load(data_dir / 'scoring.json')
        self.files = {}
        for path in sorted((data_dir / 'signatures').glob('*.json')):
            doc = _load(path)
            for sig in doc['signatures']:
                for key, pattern in sig['match'].items():
                    if key in ('pattern', 'native_os', 'native_lanman'):
                        sig.setdefault('_re', {})[key] = re.compile(pattern)
            for svc in doc.get('services', []):
                svc['_re'] = re.compile(svc['pattern'])
            self.files[doc['source']] = doc

    # -- taxonomy --------------------------------------------------------

    def ancestors(self, label_id):
        '''label_id and all its parents, most specific first.'''
        chain = []
        while label_id is not None:
            chain.append(label_id)
            label_id = self.labels[label_id]['parent']
        return chain

    def depth(self, label_id):
        return len(self.ancestors(label_id)) - 1

    def related(self, a, b):
        '''True when one label is the other or an ancestor of it.'''
        return a in self.ancestors(b) or b in self.ancestors(a)

    # -- matching --------------------------------------------------------

    def match(self, source, value):
        '''Return (signature, version) for the first signature that matches, or None.'''
        doc = self.files.get(source)
        if doc is None:
            return None
        for sig in doc['signatures']:
            ok, version = _match_one(source, sig, value)
            if ok:
                return sig, version
        return None

    def services(self, source, value):
        doc = self.files.get(source)
        if doc is None:
            return []
        found = []
        for svc in doc.get('services', []):
            field = svc.get('field')
            text = value.get(field) if field else value
            if not isinstance(text, str):
                continue
            m = svc['_re'].search(text)
            if m:
                version = m.groupdict().get('version')
                found.append(svc['product'] + (f' {version}' if version else ''))
                break
        return found

    # -- scoring ---------------------------------------------------------

    def guess(self, observations):
        '''Combine observations into one OS guess.

        observations: iterable of {"source": ..., "value": ...}.
        Returns a dict with label, display, confidence, band, detail,
        matched (signature ids) and services.
        '''
        strengths = self.scoring['strengths']
        sources = self.scoring['sources']
        evidence = {}     # signature id -> evidence (deduplicated)
        services = []
        for obs in observations:
            source, value = obs['source'], obs['value']
            for svc in self.services(source, value):
                if svc not in services:
                    services.append(svc)
            hit = self.match(source, value)
            if hit is None:
                continue
            sig, version = hit
            support = strengths[sig['strength']] * sources[source]['reliability']
            evidence[sig['id']] = {
                'id': sig['id'], 'source': source, 'label': sig['label'],
                'support': support, 'version': version, 'detail': sig.get('detail'),
            }

        result = {'label': None, 'display': 'Unknown', 'confidence': 0.0,
                  'band': self._band(0.0), 'detail': None,
                  'matched': sorted(evidence), 'services': services}
        if not evidence:
            return result

        candidates = set()
        for ev in evidence.values():
            candidates.update(self.ancestors(ev['label']))

        scores = {}
        for label in candidates:
            support = _noisy_or(_best_per_source(
                ev for ev in evidence.values() if label in self.ancestors(ev['label'])))
            conflict = _noisy_or(_best_per_source(
                ev for ev in evidence.values() if not self.related(label, ev['label'])))
            scores[label] = support * (1.0 - self.scoring['conflict_penalty'] * conflict)

        specific = self.scoring['thresholds']['specific']
        coarse = self.scoring['thresholds']['coarse']
        pool = [l for l in candidates if scores[l] >= specific]
        if pool:
            chosen = max(pool, key=lambda l: (self.depth(l), scores[l], l))
        else:
            pool = [l for l in candidates if scores[l] >= coarse]
            if not pool:
                return result
            # Keep a little slack so float rounding does not decide ties.
            best = max(scores[l] for l in pool)
            near = [l for l in pool if scores[l] >= best - 1e-9]
            chosen = max(near, key=lambda l: (self.depth(l), l))

        confidence = round(scores[chosen], 4)
        result.update(label=chosen, display=self.labels[chosen]['display'],
                      confidence=confidence, band=self._band(confidence))

        detailed = [ev for ev in evidence.values()
                    if ev['detail'] and chosen in self.ancestors(ev['label'])
                    and (ev['version'] or '{version}' not in ev['detail'])]
        if detailed:
            best = max(detailed, key=lambda ev: (ev['support'], ev['id']))
            version = (best['version'] or '').replace('_', '.')
            result['detail'] = best['detail'].replace('{version}', version)
        return result

    def _band(self, confidence):
        for band in sorted(self.scoring['bands'], key=lambda b: -b['min']):
            if confidence >= band['min']:
                return band['name']
        return self.scoring['bands'][-1]['name']


def _load(path):
    with open(path, encoding='utf-8') as f:
        return json.load(f)


def _best_per_source(evidence):
    best = {}
    for ev in evidence:
        best[ev['source']] = max(best.get(ev['source'], 0.0), ev['support'])
    return best.values()


def _noisy_or(values):
    return 1.0 - math.prod(1.0 - v for v in values)


def _wild(expected, actual):
    return expected == '*' or expected == actual


def _match_one(source, sig, value):
    m = sig['match']
    if source == 'ip_ttl':
        return initial_ttl(value['ttl']) == m['initial_ttl'], None

    if source == 'tcp_syn':
        if initial_ttl(value['ttl']) != m['initial_ttl']:
            return False, None
        if not _wild(m['df'], value['df']) or not _wild(m['mss'], value.get('mss')):
            return False, None
        if normalize_options(value['options']) != m['options']:
            return False, None
        if 'wscale' in m and not _wild(m['wscale'], value.get('wscale')):
            return False, None
        window = m['window']
        if isinstance(window, str) and window.startswith('mss*'):
            mss = value.get('mss')
            if mss is None or value['window'] != mss * int(window[4:]):
                return False, None
        elif not _wild(window, value['window']):
            return False, None
        return True, None

    if source == 'dhcp_option55':
        return list(value) == m['option55'], None

    if source in REGEX_SOURCES:
        hit = sig['_re']['pattern'].search(value)
        return (hit is not None), (hit.groupdict().get('version') if hit else None)

    if source == 'smb_native_os':
        hit = sig['_re']['native_os'].search(value.get('native_os', ''))
        if not hit:
            return False, None
        if 'native_lanman' in sig['_re'] and not sig['_re']['native_lanman'].search(value.get('native_lanman', '')):
            return False, None
        return True, hit.groupdict().get('version')

    if source == 'ntlmssp_version':
        if not _wild(m['major'], value['major']) or not _wild(m['minor'], value['minor']):
            return False, None
        build = value['build']
        if build < m.get('build_min', 0) or build > m.get('build_max', 65535):
            return False, None
        return True, None

    raise ValueError(f'unknown source {source}')


def main(argv):
    db = Database()
    path = Path(argv[1]) if len(argv) > 1 else DATA_DIR / 'test_vectors.json'
    for vector in _load(path)['vectors']:
        g = db.guess(vector['observations'])
        detail = f" ({g['detail']})" if g['detail'] else ''
        print(f"{vector['name']}: {g['display']}{detail} [{g['band']} {g['confidence']:.2f}] "
              f"via {', '.join(g['matched']) or 'nothing'}")
        for svc in g['services']:
            print(f'    service: {svc}')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))

#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''Validation tests for the Kitsune passive fingerprint data.

Run with either of:
    python3 -m pytest kitsune/data/fingerprints/tests
    python3 -m unittest discover -s kitsune/data/fingerprints/tests

Only the standard library is required. If the jsonschema package is
installed, every file is also checked against fingerprints.schema.json.
'''

import copy
import json
import re
import sys
import unittest
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(DATA_DIR / 'reference'))

import format_json  # noqa: E402
import kitsune_fp  # noqa: E402

REGEX_SOURCES = {'dhcp_vendor_class', 'http_user_agent', 'http_server', 'ssh_banner', 'smb_native_os'}
SYN_OPTION = re.compile(r'^(mss|nop|ws|sok|sack|ts|eol|\?\d+)$')

# Constructs that Python's re and PCRE2 (QRegularExpression) read
# differently, or that only one of them supports.
NON_PORTABLE_REGEX = [
    (re.compile(r'\(\?<(?![=!])'), '(?<name>...) named group: use (?P<name>...)'),
    (re.compile(r'\\[AzZ]'), '\\A, \\z or \\Z anchor: use ^ and $'),
    (re.compile(r'\(\?[aiLmsux]+\)'), 'inline flags: write the case variants out'),
    (re.compile(r'[*+?}][+]'), 'possessive quantifier'),
    (re.compile(r'\(\?>'), 'atomic group'),
    (re.compile(r'\\[pP]\{'), 'Unicode property'),
    (re.compile(r'\(\?P[=>]'), 'named backreference'),
    (re.compile(r'\\[0-9]'), 'numbered backreference'),
]


def load(path):
    with open(path, encoding='utf-8') as f:
        return json.load(f)


def signature_files():
    return sorted((DATA_DIR / 'signatures').glob('*.json'))


def all_json_files():
    return sorted(DATA_DIR.glob('*.json')) + signature_files()


class TestSchema(unittest.TestCase):
    def setUp(self):
        try:
            import jsonschema
        except ImportError:
            self.skipTest('jsonschema is not installed')
        self.jsonschema = jsonschema
        self.schema = load(DATA_DIR / 'fingerprints.schema.json')
        jsonschema.Draft202012Validator.check_schema(self.schema)

    def test_every_file_matches_schema(self):
        for path in all_json_files():
            if path.name == 'fingerprints.schema.json':
                continue
            with self.subTest(file=path.name):
                self.jsonschema.validate(load(path), self.schema)

    def test_schema_rejects_bad_data(self):
        syn = load(DATA_DIR / 'signatures' / 'tcp_syn.json')
        bad_options = copy.deepcopy(syn)
        bad_options['signatures'][0]['match']['options'] = 'mss,bogus'
        bad_strength = copy.deepcopy(syn)
        bad_strength['signatures'][0]['strength'] = 'certain'
        wrong_match = copy.deepcopy(syn)
        wrong_match['signatures'][0]['match'] = {'pattern': '^x'}
        for doc in (bad_options, bad_strength, wrong_match):
            with self.assertRaises(self.jsonschema.ValidationError):
                self.jsonschema.validate(doc, self.schema)


class TestLayout(unittest.TestCase):
    def test_files_are_valid_json_in_canonical_layout(self):
        for path in all_json_files():
            with self.subTest(file=path.name):
                text = path.read_text(encoding='utf-8')
                json.loads(text)
                self.assertEqual(text, format_json.canonical(path),
                                 'run reference/format_json.py on this file')


class TestLabels(unittest.TestCase):
    def setUp(self):
        self.labels = load(DATA_DIR / 'labels.json')['labels']
        self.by_id = {l['id']: l for l in self.labels}

    def test_ids_and_display_names_are_unique(self):
        ids = [l['id'] for l in self.labels]
        self.assertEqual(len(ids), len(set(ids)))
        names = [l['display'] for l in self.labels]
        self.assertEqual(len(names), len(set(names)))

    def test_parents_exist_and_form_a_forest(self):
        for label in self.labels:
            seen = set()
            cur = label['id']
            while cur is not None:
                self.assertIn(cur, self.by_id, f'unknown parent {cur}')
                self.assertNotIn(cur, seen, f'cycle through {cur}')
                seen.add(cur)
                cur = self.by_id[cur]['parent']

    def test_parents_are_declared_first(self):
        seen = set()
        for label in self.labels:
            if label['parent'] is not None:
                self.assertIn(label['parent'], seen, label['id'])
            seen.add(label['id'])

    def test_family_matches_root(self):
        compatible = {'windows': {'windows'}, 'unix': {'unix', 'linux', 'android', 'apple', 'bsd'},
                      'network': {'network'}}
        for label in self.labels:
            root = label
            while root['parent'] is not None:
                root = self.by_id[root['parent']]
            self.assertIn(label['family'], compatible[root['family']], label['id'])


class TestScoring(unittest.TestCase):
    def setUp(self):
        self.scoring = load(DATA_DIR / 'scoring.json')

    def test_strengths_are_ordered(self):
        s = self.scoring['strengths']
        order = ['definitive', 'strong', 'moderate', 'weak', 'hint']
        values = [s[k] for k in order]
        self.assertEqual(values, sorted(values, reverse=True))
        for v in values:
            self.assertTrue(0 < v <= 1)

    def test_thresholds_and_bands(self):
        t = self.scoring['thresholds']
        self.assertLess(t['coarse'], t['specific'])
        mins = [b['min'] for b in self.scoring['bands']]
        self.assertEqual(mins, sorted(mins, reverse=True))
        self.assertEqual(mins[-1], 0)

    def test_every_signature_file_has_a_source_weight(self):
        sources = set(self.scoring['sources'])
        files = {load(p)['source'] for p in signature_files()}
        self.assertEqual(files, sources)


class TestSignatures(unittest.TestCase):
    def setUp(self):
        self.labels = {l['id'] for l in load(DATA_DIR / 'labels.json')['labels']}
        self.strengths = set(load(DATA_DIR / 'scoring.json')['strengths'])
        self.docs = {p.name: load(p) for p in signature_files()}

    def _sigs(self):
        for name, doc in self.docs.items():
            for sig in doc['signatures']:
                yield name, doc, sig

    def test_one_file_per_source(self):
        sources = [doc['source'] for doc in self.docs.values()]
        self.assertEqual(len(sources), len(set(sources)))
        for name, doc in self.docs.items():
            self.assertEqual(name, doc['source'] + '.json')

    def test_ids_unique_across_all_files(self):
        ids = [sig['id'] for _, _, sig in self._sigs()]
        for doc in self.docs.values():
            ids += [svc['id'] for svc in doc.get('services', [])]
        dupes = sorted({i for i in ids if ids.count(i) > 1})
        self.assertEqual(dupes, [])

    def test_labels_and_strengths_are_known(self):
        for name, _, sig in self._sigs():
            with self.subTest(sig=sig['id']):
                self.assertIn(sig['label'], self.labels)
                self.assertIn(sig['strength'], self.strengths)

    def test_regexes_compile_and_are_portable(self):
        for name, doc in self.docs.items():
            patterns = []
            for sig in doc['signatures']:
                for key in ('pattern', 'native_os', 'native_lanman'):
                    if key in sig['match']:
                        patterns.append((sig['id'], sig['match'][key]))
            patterns += [(svc['id'], svc['pattern']) for svc in doc.get('services', [])]
            for sid, pattern in patterns:
                with self.subTest(sig=sid):
                    compiled = re.compile(pattern)
                    self.assertTrue(set(compiled.groupindex) <= {'version'},
                                    'the only named group allowed is "version"')
                    for bad, why in NON_PORTABLE_REGEX:
                        self.assertIsNone(bad.search(pattern), f'{why}: {pattern}')

    def test_detail_placeholder_has_a_version_group(self):
        for name, doc, sig in self._sigs():
            if '{version}' not in sig.get('detail', ''):
                continue
            with self.subTest(sig=sig['id']):
                self.assertIn(doc['source'], REGEX_SOURCES)
                key = 'pattern' if 'pattern' in sig['match'] else 'native_os'
                self.assertIn('version', re.compile(sig['match'][key]).groupindex)

    def test_regex_signatures_have_examples_that_reach_them(self):
        db = kitsune_fp.Database()
        for name, doc, sig in self._sigs():
            if doc['source'] not in REGEX_SOURCES:
                continue
            with self.subTest(sig=sig['id']):
                self.assertTrue(sig.get('examples'), 'regex signatures need examples')
                for example in sig['examples']:
                    hit = db.match(doc['source'], example)
                    self.assertIsNotNone(hit, f'{example!r} matches nothing')
                    self.assertEqual(hit[0]['id'], sig['id'],
                                     f'{example!r} is caught earlier by {hit[0]["id"]}')

    def test_dhcp_option55_lists(self):
        doc = self.docs['dhcp_option55.json']
        seen = {}
        for sig in doc['signatures']:
            with self.subTest(sig=sig['id']):
                opts = sig['match']['option55']
                self.assertEqual(len(opts), len(set(opts)), 'duplicate option code')
                self.assertTrue(all(1 <= o <= 254 for o in opts))
                key = tuple(opts)
                self.assertNotIn(key, seen, f'same list as {seen.get(key)}')
                seen[key] = sig['id']

    def test_tcp_syn_fields(self):
        for sig in self.docs['tcp_syn.json']['signatures']:
            m = sig['match']
            with self.subTest(sig=sig['id']):
                opts = m['options'].split(',')
                for opt in opts:
                    self.assertRegex(opt, SYN_OPTION)
                self.assertEqual(opts.count('eol'), int(opts[-1] == 'eol'),
                                 'only one trailing eol (padding is collapsed)')
                if 'ws' in opts:
                    self.assertIn('wscale', m, 'say "*" when any window scale is fine')
                else:
                    self.assertNotIn('wscale', m)
                if m['mss'] != '*':
                    self.assertIn('mss', opts)
                if isinstance(m['window'], str) and m['window'].startswith('mss*'):
                    self.assertIn('mss', opts)

    def test_tcp_syn_no_signature_is_shadowed(self):
        sigs = self.docs['tcp_syn.json']['signatures']

        def covers(a, b):
            for key in ('initial_ttl', 'df', 'mss', 'window', 'wscale', 'options'):
                va, vb = a.get(key), b.get(key)
                if va == '*' or va == vb:
                    continue
                return False
            return True

        for i, later in enumerate(sigs):
            for earlier in sigs[:i]:
                with self.subTest(earlier=earlier['id'], later=later['id']):
                    self.assertFalse(covers(earlier['match'], later['match']),
                                     f'{later["id"]} can never match')

    def test_ntlm_ranges(self):
        sigs = self.docs['ntlmssp_version.json']['signatures']

        def span(m):
            return m.get('build_min', 0), m.get('build_max', 65535)

        for i, later in enumerate(sigs):
            lo, hi = span(later['match'])
            with self.subTest(sig=later['id']):
                self.assertLessEqual(lo, hi)
            for earlier in sigs[:i]:
                em, lm = earlier['match'], later['match']
                same_version = all(em[k] == '*' or em[k] == lm[k] for k in ('major', 'minor'))
                elo, ehi = span(em)
                with self.subTest(earlier=earlier['id'], later=later['id']):
                    self.assertFalse(same_version and elo <= lo and hi <= ehi,
                                     f'{later["id"]} can never match')


class TestMatcher(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.db = kitsune_fp.Database()

    def test_initial_ttl(self):
        self.assertEqual(kitsune_fp.initial_ttl(1), 32)
        self.assertEqual(kitsune_fp.initial_ttl(64), 64)
        self.assertEqual(kitsune_fp.initial_ttl(65), 128)
        self.assertEqual(kitsune_fp.initial_ttl(240), 255)

    def test_option_padding_is_collapsed(self):
        self.assertEqual(kitsune_fp.normalize_options('mss,nop,ws,nop,nop,ts,sok,eol,eol,eol'),
                         'mss,nop,ws,nop,nop,ts,sok,eol')

    def test_repeated_observations_do_not_inflate_confidence(self):
        ua = {'source': 'http_user_agent', 'value': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        once = self.db.guess([ua])
        many = self.db.guess([ua] * 50)
        self.assertEqual(once['confidence'], many['confidence'])

    def test_same_source_does_not_stack(self):
        a = {'source': 'ssh_banner', 'value': 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10'}
        b = {'source': 'ssh_banner', 'value': 'SSH-2.0-OpenSSH_9.9p1 Ubuntu-3ubuntu3'}
        self.assertEqual(self.db.guess([a])['confidence'], self.db.guess([a, b])['confidence'])

    def test_independent_sources_raise_confidence(self):
        syn = {'source': 'tcp_syn', 'value': {'ttl': 128, 'df': True, 'mss': 1460, 'window': 64240,
                                              'wscale': 8, 'options': 'mss,nop,ws,nop,nop,sok'}}
        ssh = {'source': 'ssh_banner', 'value': 'SSH-2.0-OpenSSH_for_Windows_9.5'}
        one = self.db.guess([syn])['confidence']
        two = self.db.guess([syn, ssh])['confidence']
        self.assertGreater(two, one)


class TestVectors(unittest.TestCase):
    def test_vectors(self):
        db = kitsune_fp.Database()
        vectors = load(DATA_DIR / 'test_vectors.json')['vectors']
        for vector in vectors:
            with self.subTest(vector=vector['name']):
                got = db.guess(vector['observations'])
                expect = vector['expect']
                if 'label' in expect:
                    self.assertEqual(got['label'], expect['label'])
                if 'band' in expect:
                    self.assertEqual(got['band'], expect['band'])
                if 'detail' in expect:
                    self.assertEqual(got['detail'], expect['detail'])
                if 'matched' in expect:
                    self.assertEqual(got['matched'], sorted(expect['matched']))
                if 'services' in expect:
                    self.assertEqual(sorted(got['services']), sorted(expect['services']))

    def test_every_label_family_has_a_vector(self):
        labels = {l['id']: l for l in load(DATA_DIR / 'labels.json')['labels']}
        vectors = load(DATA_DIR / 'test_vectors.json')['vectors']
        families = {labels[v['expect']['label']]['family'] for v in vectors if v['expect'].get('label')}
        self.assertEqual(families, {l['family'] for l in labels.values()})


if __name__ == '__main__':
    unittest.main()

#!/usr/bin/env python3
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''Rewrite fingerprint JSON files in the canonical layout.

Objects are indented two spaces per level; objects and arrays that hold
only scalars, and small "match" objects, stay on one line so that each
signature reads as a short block.

Usage: format_json.py FILE.json [...]
       format_json.py --check FILE.json [...]
'''

import json
import sys

INLINE_KEYS = {'match', 'value', 'expect'}


def _scalar(v):
    return not isinstance(v, (dict, list))


def _inline(v):
    if isinstance(v, list):
        return all(_scalar(x) for x in v)
    if isinstance(v, dict):
        return all(_scalar(x) or (isinstance(x, list) and all(_scalar(y) for y in x)) for x in v.values())
    return True


def dump(value, indent=0, key=None):
    pad = '  ' * indent
    if _scalar(value):
        return json.dumps(value, ensure_ascii=False)
    if (key in INLINE_KEYS or isinstance(value, list)) and _inline(value):
        return json.dumps(value, ensure_ascii=False, separators=(', ', ': ')).replace('{"', '{ "').replace('"}', '" }') \
            if isinstance(value, list) else '{ ' + ', '.join(
                f'{json.dumps(k)}: {json.dumps(v, ensure_ascii=False, separators=(", ", ": "))}' for k, v in value.items()) + ' }'
    inner = '  ' * (indent + 1)
    if isinstance(value, list):
        if not value:
            return '[]'
        return '[\n' + ',\n'.join(inner + dump(v, indent + 1, 'value' if isinstance(v, dict) and _inline(v) else None)
                                   for v in value) + '\n' + pad + ']'
    if not value:
        return '{}'
    return '{\n' + ',\n'.join(f'{inner}{json.dumps(k)}: {dump(v, indent + 1, k)}' for k, v in value.items()) + '\n' + pad + '}'


def canonical(path):
    with open(path, encoding='utf-8') as f:
        return dump(json.load(f)) + '\n'


def main(argv):
    check = '--check' in argv
    bad = 0
    for path in [a for a in argv[1:] if a != '--check']:
        text = canonical(path)
        with open(path, encoding='utf-8') as f:
            current = f.read()
        if text != current:
            if check:
                print(f'{path}: not in canonical layout (run reference/format_json.py on it)')
                bad += 1
            else:
                with open(path, 'w', encoding='utf-8') as f:
                    f.write(text)
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))

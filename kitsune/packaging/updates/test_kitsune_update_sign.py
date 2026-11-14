#!/usr/bin/env python3
#
# Tests for kitsune_update_sign.py: python3 -m unittest test_kitsune_update_sign
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
import base64
import datetime
import json
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import kitsune_update_sign as k

EXAMPLE = (Path(__file__).parent / "example-manifest.json").read_bytes()
NOW = datetime.datetime(2026, 11, 20, tzinfo=datetime.timezone.utc)


def sign(key, data):
    raw = k.public_raw(key.public_key())
    return json.dumps({"alg": "ed25519", "keyid": k.key_id(raw),
                       "sig": base64.b64encode(key.sign(data)).decode()})


def modified(**changes):
    m = json.loads(EXAMPLE)
    for path, value in changes.items():
        obj = m
        *parents, last = path.split("__")
        for p in parents:
            obj = obj[p]
        obj[last] = value
    return json.dumps(m).encode()


class VerifyTests(unittest.TestCase):
    def setUp(self):
        self.key = Ed25519PrivateKey.generate()
        self.raw = k.public_raw(self.key.public_key())

    def test_good_manifest(self):
        m = k.verify(EXAMPLE, sign(self.key, EXAMPLE), [self.raw], now=NOW)
        self.assertEqual(m["latest"]["version"], "0.2.0")

    def test_second_trusted_key_for_rotation(self):
        other = k.public_raw(Ed25519PrivateKey.generate().public_key())
        k.verify(EXAMPLE, sign(self.key, EXAMPLE), [other, self.raw], now=NOW)

    def test_tampered_bytes(self):
        sig = sign(self.key, EXAMPLE)
        with self.assertRaisesRegex(k.ManifestError, "does not match"):
            k.verify(EXAMPLE.replace(b"0.2.0", b"9.9.9"), sig, [self.raw], now=NOW)

    def test_unknown_key(self):
        other = Ed25519PrivateKey.generate()
        with self.assertRaisesRegex(k.ManifestError, "unknown key"):
            k.verify(EXAMPLE, sign(other, EXAMPLE), [self.raw], now=NOW)

    def test_expired(self):
        later = datetime.datetime(2027, 1, 1, tzinfo=datetime.timezone.utc)
        with self.assertRaisesRegex(k.ManifestError, "expired"):
            k.verify(EXAMPLE, sign(self.key, EXAMPLE), [self.raw], now=later)

    def test_wrong_channel(self):
        with self.assertRaisesRegex(k.ManifestError, "expected beta"):
            k.verify(EXAMPLE, sign(self.key, EXAMPLE), [self.raw], now=NOW, expected_channel="beta")

    def test_garbage_signature_file(self):
        with self.assertRaisesRegex(k.ManifestError, "bad signature file"):
            k.verify(EXAMPLE, "not json", [self.raw], now=NOW)


class ContentTests(unittest.TestCase):
    def bad(self, data, pattern):
        with self.assertRaisesRegex(k.ManifestError, pattern):
            k.check_manifest(data, now=NOW)

    def test_http_url(self):
        m = json.loads(EXAMPLE)
        m["latest"]["files"][0]["url"] = "http://example.com/x.msi"
        self.bad(json.dumps(m).encode(), "must be https")

    def test_bad_hash(self):
        m = json.loads(EXAMPLE)
        m["latest"]["files"][0]["sha256"] = "ABC"
        self.bad(json.dumps(m).encode(), "sha256")

    def test_lifetime_too_long(self):
        self.bad(modified(expires="2027-06-01T00:00:00Z"), "at most")

    def test_bool_is_not_a_serial(self):
        self.bad(modified(serial=True), "wrong type")

    def test_min_supported_newer_than_latest(self):
        self.bad(modified(min_supported_version="1.0.0"), "newer than")

    def test_unknown_product(self):
        self.bad(modified(product="wireshark"), "product")


if __name__ == "__main__":
    unittest.main()

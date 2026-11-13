#!/usr/bin/env python3
#
# kitsune_update_sign.py - make, sign and check Kitsune update manifests
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
"""Make, sign and check Kitsune update manifests.

The manifest is signed as raw bytes with Ed25519. The signature lives in
a separate file next to it (manifest.json.sig), so no JSON
canonicalization is needed: Kitsune verifies the exact bytes it
downloaded, then parses them.

  keygen   Make a key pair. Keep the private key offline.
  sign     Sign a manifest, after checking it.
  verify   Check a manifest's signature and contents, as Kitsune will.
  entry    Print the "files" entry (size, SHA-256) for an installer.

Needs the "cryptography" package (pip install cryptography).

  kitsune_update_sign.py keygen --out release-key
  kitsune_update_sign.py sign --key release-key.pem manifest.json
  kitsune_update_sign.py verify --pubkey <base64> manifest.json
"""

import argparse
import base64
import datetime
import hashlib
import json
import re
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

SCHEMA_VERSION = 1
CHANNELS = ("stable", "beta")
PLATFORMS = ("windows-x64",)
KINDS = ("msi",)
VERSION_RE = re.compile(r"^\d+\.\d+\.\d+(\.\d+)?$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
# A manifest may be valid for at most this long, so a stale one cannot
# be replayed to hide a security fix for months.
MAX_LIFETIME = datetime.timedelta(days=45)


class ManifestError(Exception):
    pass


def key_id(public_raw: bytes) -> str:
    """First 8 bytes of the SHA-256 of the raw public key, as hex."""
    return hashlib.sha256(public_raw).hexdigest()[:16]


def public_raw(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def parse_time(value, field):
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ManifestError(f"{field} must be a UTC time like 2026-11-13T00:00:00Z")
    try:
        return datetime.datetime.fromisoformat(value[:-1]).replace(tzinfo=datetime.timezone.utc)
    except ValueError as e:
        raise ManifestError(f"{field}: {e}") from None


def version_tuple(value):
    return tuple(int(p) for p in value.split("."))


def check_manifest(data: bytes, now=None, expected_channel=None):
    """Check a manifest the way Kitsune does after the signature."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    try:
        m = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise ManifestError(f"not JSON: {e}") from None
    if not isinstance(m, dict):
        raise ManifestError("top level must be an object")

    def need(obj, field, kind, where="manifest"):
        if field not in obj:
            raise ManifestError(f"{where}: missing {field}")
        if not isinstance(obj[field], kind) or isinstance(obj[field], bool) and kind is not bool:
            raise ManifestError(f"{where}: {field} has the wrong type")
        return obj[field]

    if need(m, "schema", int) != SCHEMA_VERSION:
        raise ManifestError(f"schema must be {SCHEMA_VERSION}")
    if need(m, "product", str) != "kitsune":
        raise ManifestError("product must be kitsune")
    channel = need(m, "channel", str)
    if channel not in CHANNELS:
        raise ManifestError(f"channel must be one of {CHANNELS}")
    if expected_channel and channel != expected_channel:
        raise ManifestError(f"manifest is for channel {channel}, expected {expected_channel}")
    if need(m, "serial", int) < 1:
        raise ManifestError("serial must be a positive integer")

    published = parse_time(need(m, "published", str), "published")
    expires = parse_time(need(m, "expires", str), "expires")
    if expires <= published:
        raise ManifestError("expires must be after published")
    if expires - published > MAX_LIFETIME:
        raise ManifestError(f"a manifest may be valid for at most {MAX_LIFETIME.days} days")
    if now >= expires:
        raise ManifestError(f"manifest expired at {expires.isoformat()}")
    if published > now + datetime.timedelta(minutes=10):
        raise ManifestError("published is in the future")

    for field in ("min_supported_version",):
        if field in m and not VERSION_RE.match(str(m[field])):
            raise ManifestError(f"{field} must look like 1.2.3")

    latest = need(m, "latest", dict)
    version = need(latest, "version", str, "latest")
    if not VERSION_RE.match(version):
        raise ManifestError("latest.version must look like 1.2.3")
    need(latest, "notes_url", str, "latest")
    if not latest["notes_url"].startswith("https://"):
        raise ManifestError("latest.notes_url must be https")
    if "critical" in latest and not isinstance(latest["critical"], bool):
        raise ManifestError("latest.critical must be true or false")
    if "min_supported_version" in m and version_tuple(m["min_supported_version"]) > version_tuple(version):
        raise ManifestError("min_supported_version is newer than latest.version")

    files = need(latest, "files", list, "latest")
    if not files:
        raise ManifestError("latest.files is empty")
    seen = set()
    for i, f in enumerate(files):
        where = f"latest.files[{i}]"
        if not isinstance(f, dict):
            raise ManifestError(f"{where} must be an object")
        platform = need(f, "platform", str, where)
        kind = need(f, "kind", str, where)
        if platform not in PLATFORMS or kind not in KINDS:
            raise ManifestError(f"{where}: unknown platform or kind")
        if (platform, kind) in seen:
            raise ManifestError(f"{where}: duplicate {platform} {kind}")
        seen.add((platform, kind))
        if not need(f, "url", str, where).startswith("https://"):
            raise ManifestError(f"{where}: url must be https")
        if need(f, "size", int, where) <= 0:
            raise ManifestError(f"{where}: size must be positive")
        if not SHA256_RE.match(need(f, "sha256", str, where)):
            raise ManifestError(f"{where}: sha256 must be 64 lowercase hex digits")
    return m


def load_private(path):
    key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise SystemExit(f"{path} is not an Ed25519 private key")
    return key


def cmd_keygen(args):
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    out = Path(args.out + ".pem")
    if out.exists():
        raise SystemExit(f"{out} already exists; not overwriting a key")
    out.write_bytes(pem)
    out.chmod(0o600)
    raw = public_raw(key.public_key())
    print(f"Private key: {out}  (move it offline; never commit it)")
    print(f"Public key:  {base64.b64encode(raw).decode()}")
    print(f"Key id:      {key_id(raw)}")


def cmd_sign(args):
    data = Path(args.manifest).read_bytes()
    check_manifest(data)
    key = load_private(args.key)
    raw = public_raw(key.public_key())
    sig = {
        "alg": "ed25519",
        "keyid": key_id(raw),
        "sig": base64.b64encode(key.sign(data)).decode(),
    }
    out = Path(args.manifest + ".sig")
    out.write_text(json.dumps(sig, indent=2) + "\n")
    print(f"Wrote {out} (key {sig['keyid']})")


def verify(data: bytes, sig_text: str, trusted_keys, now=None, expected_channel=None):
    """Signature first, then contents. trusted_keys: list of raw keys."""
    try:
        sig = json.loads(sig_text)
        if sig.get("alg") != "ed25519":
            raise ManifestError("unsupported signature algorithm")
        signature = base64.b64decode(sig["sig"], validate=True)
        keyid = sig["keyid"]
    except (ValueError, KeyError, TypeError, AttributeError) as e:
        raise ManifestError(f"bad signature file: {e}") from None
    for raw in trusted_keys:
        if key_id(raw) != keyid:
            continue
        try:
            Ed25519PublicKey.from_public_bytes(raw).verify(signature, data)
        except InvalidSignature:
            raise ManifestError("signature does not match") from None
        return check_manifest(data, now=now, expected_channel=expected_channel)
    raise ManifestError(f"signed by unknown key {keyid}")


def cmd_verify(args):
    data = Path(args.manifest).read_bytes()
    sig_text = Path(args.signature or args.manifest + ".sig").read_text()
    keys = [base64.b64decode(k) for k in args.pubkey]
    m = verify(data, sig_text, keys, expected_channel=args.channel)
    print(f"OK: {m['channel']} serial {m['serial']}, latest {m['latest']['version']}, expires {m['expires']}")


def cmd_entry(args):
    path = Path(args.installer)
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    print(json.dumps({
        "platform": args.platform,
        "kind": "msi",
        "url": args.url or f"https://example.invalid/{path.name}",
        "size": path.stat().st_size,
        "sha256": h.hexdigest(),
    }, indent=2))


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("keygen", help="make a key pair")
    s.add_argument("--out", required=True, help="private key file name, without .pem")
    s.set_defaults(func=cmd_keygen)

    s = sub.add_parser("sign", help="check and sign a manifest")
    s.add_argument("--key", required=True, help="Ed25519 private key (PEM)")
    s.add_argument("manifest")
    s.set_defaults(func=cmd_sign)

    s = sub.add_parser("verify", help="verify a manifest as Kitsune does")
    s.add_argument("--pubkey", action="append", required=True, help="trusted public key, base64 (repeatable)")
    s.add_argument("--signature", help="signature file (default: <manifest>.sig)")
    s.add_argument("--channel", choices=CHANNELS)
    s.add_argument("manifest")
    s.set_defaults(func=cmd_verify)

    s = sub.add_parser("entry", help="print the files entry for an installer")
    s.add_argument("--platform", default="windows-x64", choices=PLATFORMS)
    s.add_argument("--url")
    s.add_argument("installer")
    s.set_defaults(func=cmd_entry)

    args = p.parse_args(argv)
    try:
        args.func(args)
    except ManifestError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

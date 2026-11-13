# Kitsune passive fingerprint data

This directory holds the data Kitsune uses to guess a host's operating
system, and the software behind its services, from traffic it has
already captured. Nothing here sends a packet. Every guess comes with a
confidence and the list of signatures that produced it, so the map can
show *why* Kitsune thinks a host runs Windows 11 and not just that it
does.

The files are plain JSON with no code in them. The C++ inventory engine
loads them at start-up; `reference/kitsune_fp.py` is a small Python
implementation of the same rules that the tests use as the
specification.

## Files

| File | What it holds |
|------|---------------|
| `labels.json` | The OS labels, as a tree. Each label has a coarser parent to fall back to. |
| `scoring.json` | Strength weights, per-source reliability, thresholds and confidence bands. |
| `signatures/ip_ttl.json` | Initial IP TTL / hop limit. |
| `signatures/tcp_syn.json` | TCP SYN layout: TTL, DF, MSS, window, window scale, option order. |
| `signatures/dhcp_option55.json` | DHCP option 55 parameter request list, in order. |
| `signatures/dhcp_vendor_class.json` | DHCP option 60 vendor class identifier. |
| `signatures/http_user_agent.json` | HTTP `User-Agent` request header. |
| `signatures/http_server.json` | HTTP `Server` response header, plus service (product/version) rules. |
| `signatures/ssh_banner.json` | SSH identification string, plus service rules. |
| `signatures/smb_native_os.json` | SMB1 Session Setup NativeOS / NativeLanMan strings, plus a Samba service rule. |
| `signatures/ntlmssp_version.json` | NTLMSSP VERSION structure (Windows major.minor.build), seen in SMB2/3, HTTP, LDAP and RPC. |
| `fingerprints.schema.json` | JSON Schema (draft 2020-12) for all of the above. |
| `test_vectors.json` | Example hosts with the answer any implementation must give. |
| `reference/kitsune_fp.py` | Reference matcher and scorer (standard library only). |
| `reference/format_json.py` | Rewrites the JSON files in the layout the tests expect. |
| `tests/test_fingerprints.py` | Validation tests. |
| `SOURCES.md` | Where the data comes from and the licenses of other databases. |

## Labels and fallback

Labels form a tree, for example:

```
windows
├── windows-legacy (XP to 8.1)
│   ├── windows-xp, windows-vista, windows-7, windows-8, windows-8.1
└── windows-nt10 "Windows 10/11 or Server 2016+"
    ├── windows-client "Windows 10/11"
    │   ├── windows-10
    │   └── windows-11
    └── windows-server "Windows Server 2016+"
        └── windows-server-2016 … windows-server-2025
unix-like
├── linux
│   ├── debian-family → debian (10, 11, 12), ubuntu (18.04 … 24.04)
│   ├── rhel-family, android, chromeos, embedded-linux
├── apple → macos, ios
└── bsd → freebsd, openbsd
network-device → cisco-ios, mikrotik-routeros
```

A signature names the most specific label the evidence really supports.
When evidence can't separate two releases it points at their common
parent: Windows build 17763 is both Windows 10 1809 and Server 2019, so
`ntlm-1809` names `windows-nt10`, and browsers send `Windows NT 10.0` on
both Windows 10 and 11, so `ua-windows-nt10` names `windows-client`.

When the combined confidence for a specific label is too low, Kitsune
shows the parent instead (see *Choosing the answer*), which is how a host
seen only through its browser comes out as "Windows 10/11" rather than a
guess at one of them.

`display` is the text shown in the UI. A signature may also carry
`detail`, a short line shown under the label, such as `Android {version}`;
`{version}` is filled from the regular expression's `version` group (with
`_` turned into `.`).

## Signature files

Every signature file has the same outer shape:

```json
{
  "kind": "signatures",
  "source": "ssh_banner",
  "schema_version": 1,
  "review_status": "draft",
  "description": "...",
  "signatures": [
    {
      "id": "ssh-ubuntu-22.04",
      "label": "ubuntu-22.04",
      "strength": "strong",
      "match": { "pattern": "^SSH-2\\.0-OpenSSH_8\\.9p1 Ubuntu-3ubuntu" },
      "examples": ["SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10"],
      "notes": "Why this is true and what else could send it."
    }
  ],
  "services": [
    { "id": "svc-openssh", "pattern": "^SSH-[\\d.]+-OpenSSH_(?P<version>[\\w.]+)", "product": "OpenSSH" }
  ]
}
```

**Signatures in a file are tried in order and the first match wins.**
Put specific signatures before general ones. One observation therefore
yields at most one signature per source. `services` rules are tried
separately (also first match wins) and give a product name and version
for the inventory's service list; they don't affect the OS guess.

`review_status` is `draft` until the file has been checked against real
captures, and `reviewed` after.

### What each source matches

| Source | Observation the engine passes in | Match fields |
|--------|----------------------------------|--------------|
| `ip_ttl` | `{ "ttl": 117 }` (observed TTL or hop limit) | `initial_ttl`: 32, 64, 128 or 255 |
| `tcp_syn` | `{ "ttl", "df", "mss", "window", "wscale", "options" }` from a SYN the host sent | see below |
| `dhcp_option55` | list of option codes, in packet order | `option55`: exact list, same order |
| `dhcp_vendor_class` | option 60 string | `pattern` |
| `http_user_agent` | `User-Agent` value | `pattern` |
| `http_server` | `Server` value | `pattern` |
| `ssh_banner` | identification line without CR LF | `pattern` |
| `smb_native_os` | `{ "native_os", "native_lanman" }` | `native_os` and optional `native_lanman` patterns; both must match |
| `ntlmssp_version` | `{ "major", "minor", "build" }` | `major`, `minor` (number or `"*"`), optional inclusive `build_min`/`build_max` |

Only use observations that the host itself sent: its own SYNs, its own
DHCP requests, its own User-Agent, the banner it sends as an SSH
server or client. Don't attribute a server's banner to the client that
connected to it.

**Initial TTL.** The engine rounds the observed TTL up to the next of
32, 64, 128 and 255; the difference is the hop count. A TTL seen on a
router's far side is still usable this way.

**TCP SYN matching.** `options` is the TCP option kinds in order, written
`mss`, `nop`, `ws` (window scale), `sok` (SACK permitted), `sack`, `ts`
(timestamps), `eol`, or `?N` for any other kind number. Trailing EOL
padding is collapsed to a single `eol`. `mss`, `wscale` and `df` may be
`"*"` for "any". `window` is a number, `"*"`, or `"mss*N"` for a window
of exactly N times the SYN's own MSS (Linux 3.x and 4.x advertise
`mss*20`). `wscale` is present exactly when `options` contains `ws`.

**Regular expressions.** Patterns are searched for anywhere in the value
(use `^` and `$` to anchor) and are case-sensitive. They must work the
same in Python's `re` and in PCRE2, which `QRegularExpression` uses, so
the tests reject inline flags, `\A`/`\Z`, possessive quantifiers, atomic
groups, backreferences and `(?<name>…)`. The only named group is
`(?P<version>…)`, which both engines accept. Every regular-expression
signature lists `examples` that must match it *and* not be caught by an
earlier signature, which is how the tests catch ordering mistakes.

## Confidence scheme

All the numbers below live in `scoring.json`, so they can be tuned
without code changes.

1. **Support of one piece of evidence.** Each matched signature gives
   `support = strength × reliability`, where `strength` maps
   `definitive` 0.95, `strong` 0.8, `moderate` 0.6, `weak` 0.35,
   `hint` 0.15, and `reliability` is per source (for example SMB
   NativeOS 0.95, User-Agent 0.65 because it is easy to fake and
   browsers freeze it).
2. **Deduplicate.** The same signature seen many times counts once,
   and for any one label only the strongest piece of evidence *from each
   source* counts. Fifty identical SYNs or three Ubuntu SSH banners do
   not add up to certainty; a SYN, a DHCP request and an NTLM message
   that agree do.
3. **Support for a label** is the noisy-OR of those per-source
   supports, over evidence that names the label itself or any label
   below it: `S(L) = 1 − Π (1 − sᵢ)`. Evidence for `windows-11` supports
   `windows-client`, `windows-nt10` and `windows` too. Evidence for a
   parent (TTL 128 says only `windows`) does not support the children,
   but it doesn't count against them either.
4. **Conflict** is the noisy-OR, computed the same way, over evidence
   for labels on a different branch (neither above nor below `L`):
   a Linux User-Agent conflicts with a Windows SYN. Then
   `confidence(L) = S(L) × (1 − conflict_penalty × C(L))`, with
   `conflict_penalty` 0.6.
5. **Choosing the answer.**
   - If any label reaches `thresholds.specific` (0.6), pick the deepest
     such label, breaking ties by confidence.
   - Otherwise, if any label reaches `thresholds.coarse` (0.3), pick the
     one with the highest confidence, preferring the deeper label on a
     tie. This is the coarse fallback.
   - Otherwise the OS is **Unknown**. The matched signatures are still
     reported so the evidence panel can show them.
6. **Bands** for the UI badge: `high` from 0.85, `medium` from 0.6,
   `low` below.

Worked examples (from `test_vectors.json`):

| Evidence | Result |
|----------|--------|
| DHCP `MSFT 5.0` + Windows option 55 + Windows 10/11 SYN + Chrome UA + NTLM build 22631 | Windows 11, high (0.90) |
| DHCP `MSFT 5.0` + Windows 10/11 SYN + Firefox `Windows NT 10.0` | Windows 10/11 or Server 2016+, medium (0.80) |
| Chrome UA `Windows NT 10.0` only | Windows 10/11, low (0.39) |
| SSH `OpenSSH_8.9p1 Ubuntu-3ubuntu0.10` + Apache `(Ubuntu)` + Linux SYN | Ubuntu 22.04, medium (0.72) |
| Windows SYN + Linux desktop UA | Windows 10/11 or Server 2016+, low (0.52) |
| TTL 50 only | Unknown |

The UI should show the band, the label, the `detail` if any, and the
evidence list, with spoofable sources (`scoring.json` marks them) shown
as such.

## Working on the data

Run the tests from the top of the source tree:

```sh
python3 -m unittest discover -s kitsune/data/fingerprints/tests
```

or with pytest (the `-c /dev/null` skips Wireshark's own `pytest.ini`,
which needs pytest-xdist):

```sh
python3 -m pytest -c /dev/null kitsune/data/fingerprints/tests
```

Only the Python standard library is needed. If `jsonschema` is installed
the files are also validated against the schema.

To try a set of observations, add a vector to `test_vectors.json` and
run `python3 kitsune/data/fingerprints/reference/kitsune_fp.py`, which
prints the guess, confidence and evidence for every vector.

When adding a signature:

1. Point it at the most specific label the evidence really supports;
   add a label to `labels.json` if needed (parents come before
   children).
2. Pick a strength honestly and say in `notes` what else could send the
   same thing.
3. Put it before any more general signature in the same file, and give
   regular-expression signatures at least one `examples` entry.
4. Only add data you wrote yourself or that comes from a source whose
   license allows it; record the source in `SOURCES.md`.
5. Run `reference/format_json.py` on the file and run the tests.

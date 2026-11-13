# Sources and licensing

## License of this data

Everything in this directory was written for Kitsune and is distributed
under the same license as the rest of the source tree,
GPL-2.0-or-later. No signature, pattern or list was copied from another
fingerprint database.

The data records facts about how operating systems and programs behave
on the wire (default TTLs, TCP option order, DHCP request lists, banner
formats, version numbers). It was compiled from:

- Protocol specifications: RFC 791 and RFC 8200 (TTL and hop limit),
  RFC 9293, RFC 7323 and RFC 2018 (TCP options), RFC 2131 and RFC 2132
  (DHCP options 55 and 60), RFC 9110 (`User-Agent`, `Server`), RFC 4253
  (SSH identification string), [MS-CIFS] and [MS-NLMP] (SMB1 session
  setup strings, NTLMSSP VERSION).
- Vendor documentation and release notes: Windows release and build
  number tables, IIS version history, the Chromium and Safari
  User-Agent reduction announcements, Android's DHCP client.
- Distribution package archives for the OpenSSH package version shipped
  by each Debian and Ubuntu release.
- Common knowledge of default stack behaviour.

All files are marked `"review_status": "draft"` because the values have
not yet been checked against a corpus of real captures. Before a file is
marked `reviewed`, each signature should be confirmed with at least one
capture from a known host, and ideally the captures added to the test
suite.

## Other databases

These are the well-known passive fingerprint databases and what their
licenses would mean for Kitsune. None of them is included today.

| Database | License | Can Kitsune include it? |
|----------|---------|-------------------------|
| p0f v3 `p0f.fp` (TCP/HTTP) | GNU LGPL 2.1, per the p0f source headers | Yes. LGPL-2.1 is compatible with GPL-2.0-or-later. Keep it as a separate file with its copyright notice (Michal Zalewski) and the LGPL text, and convert it with a script rather than by hand. Note that it was last updated around 2014 and lacks current OS releases. |
| Satori fingerprint XML (TCP, DHCP, HTTP, SMB, SSH and more), github.com/xnih/satori | GPL-2.0 per the repository | Probably, since GPL-2.0 matches Kitsune's license, but check the LICENSE file and whether the repository says "or later". Some fingerprint sets there (for example TLS) are compiled from third-party lists with their own terms, which need checking one by one. |
| Fingerbank (DHCP, User-Agent and more), fingerbank.org | Commercial; the SQLite database is sold under license, and the public API has its own terms | No, not without a written agreement. The old GPL `dhcp_fingerprints.conf` shipped with PacketFence predates the current database; if used, take it only from a GPL release of PacketFence and keep its notice. |
| Nmap `nmap-os-db` | Nmap Public Source License (NPSL) | No. The NPSL adds restrictions that are not compatible with redistribution under the GPL. It is also built for active probing, which Kitsune does not do. |
| pf.os (OpenBSD/FreeBSD pf) | BSD-style, per the file header | Possibly, but much of it derives from early p0f data, so check provenance first. It covers TCP SYN only and is largely out of date. |

If data from any of these is added later, put it in its own file, record
the source, version and license here, and keep its notices in the
file's `description`.

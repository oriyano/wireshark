# Kitsune automatic updates

Kitsune checks a small signed file, the **update manifest**, to learn
whether a newer release exists. If one does, it downloads the .msi,
checks it three ways, and asks the user to install it. Nothing is
installed without the user saying yes, and nothing runs as
administrator except Windows Installer itself.

## Where things live

| What                 | Where                                                                                     |
|----------------------|-------------------------------------------------------------------------------------------|
| Installers           | GitHub Releases, tag `kitsune-v<version>`                                                 |
| Manifest + signature | `https://oriyano.github.io/wireshark/kitsune/<channel>/manifest.json` and `manifest.json.sig` |
| Release signing key  | Offline (hardware key or protected CI environment); never in the repository              |

The manifests are served by GitHub Pages for this repository, so there is
nothing to host or pay for. A custom domain can be added later by
pointing Pages at it; Kitsune keeps the GitHub address as a fallback.
Channels are `stable` and `beta`.

To turn it on, in the repository's Settings > Pages, publish from a
`gh-pages` branch, and put each channel's files under `kitsune/<channel>/`
on that branch.

## The manifest

`manifest.json` (see `example-manifest.json`):

| Field                      | Meaning                                                                 |
|----------------------------|-------------------------------------------------------------------------|
| `schema`                   | Format version, currently 1                                             |
| `product`, `channel`       | Must match what Kitsune asked for                                       |
| `serial`                   | Grows with every manifest published; Kitsune refuses a smaller one      |
| `published`, `expires`     | UTC; at most 45 days apart; Kitsune refuses an expired manifest         |
| `min_supported_version`    | Older versions say "please update" more firmly                          |
| `latest.version`           | Newest release on this channel                                          |
| `latest.notes_url`         | Release notes, shown before installing                                  |
| `latest.critical`          | A security fix; Kitsune asks sooner and more visibly                    |
| `latest.files[]`           | `platform`, `kind`, `url`, `size`, `sha256` for each installer           |

`manifest.json.sig` is a detached Ed25519 signature over the manifest's
exact bytes, with the id of the signing key:

```json
{ "alg": "ed25519", "keyid": "a2d757b53d6c3f43", "sig": "<base64>" }
```

Signing raw bytes means there is no JSON canonicalization to get wrong:
Kitsune checks the signature on the bytes it downloaded, and only then
parses them.

## What Kitsune checks

1. **Signature.** Kitsune has two public keys built in, the current one
   and a spare for rotation. The `keyid` must name one of them, and the
   Ed25519 signature must verify. Kitsune already links libgcrypt
   through the engine, which does Ed25519, so no new library is needed.
2. **Freshness.** `expires` is in the future and `serial` is at least
   the last serial seen (kept in Kitsune's settings). This stops an
   attacker from replaying an old, validly signed manifest to hide a
   security update.
3. **Contents.** Same product and channel, https URLs, a version newer
   than the running one.
4. **Download.** The .msi's size and SHA-256 match the manifest.
5. **Publisher.** `WinVerifyTrust` accepts the .msi's Authenticode
   signature and the signer is the pinned Kitsune publisher name. This
   is a second, independent check: a stolen manifest key alone cannot
   push an installer, and neither can a stolen code-signing certificate
   alone.

### Before releases are code-signed

Code signing comes later, so builds are unsigned for now. Until the
first signed release, Kitsune's updater runs in **notify-only** mode:
it still fetches and verifies the manifest (checks 1 to 3, which need
only our own free Ed25519 key, not a certificate), tells the user a
newer version exists, and links to the release page. It does not
download or launch an installer it cannot check with step 5.

The pinned publisher name is a build setting. A build without one is
notify-only; the first build with one, installed by hand, can update
itself from then on. Nothing else about the protocol changes.

`kitsune_update_sign.py verify` applies checks 1 to 3 the same way, and
its tests (`python3 -m unittest test_kitsune_update_sign`) cover
tampering, unknown keys, expiry, wrong channel and malformed fields.

## When and how Kitsune checks

- About a minute after start-up, then once a day, with random jitter
  so a whole classroom does not hit the server at the same moment.
- Never while a capture is running, and never interrupts one: the
  prompt waits until the capture stops.
- The request sends nothing but the URL (no user or machine id). The
  only thing it reveals is that a Kitsune install exists at that IP.
- Downloads go to `%LOCALAPPDATA%\Kitsune\updates` and are deleted
  after installing or after 30 days.
- To install, Kitsune asks the user, saves state, starts
  `msiexec /i <file> /passive` (Windows Installer shows UAC), and
  exits. The `MajorUpgrade` in the .msi replaces the old version.
- **Help > Check for updates** does the same on demand.

## Settings and school policy

Kitsune reads, in order, the first that is set:

1. `HKLM\SOFTWARE\Policies\Kitsune\Updates` (Group Policy / Intune)
2. `HKLM\SOFTWARE\Kitsune\Updates` (written by the .msi from
   `UPDATES`, `UPDATE_CHANNEL`, `UPDATE_MANIFEST`)
3. The user's own choice in Settings (only where 1 is not set)

| Value         | Type   | Meaning                                                      |
|---------------|--------|--------------------------------------------------------------|
| `Enabled`     | DWORD  | 0 turns update checks off                                    |
| `Channel`     | string | `stable` or `beta`                                           |
| `ManifestUrl` | string | A school's own mirror; still must be signed by our key       |

A mirror can host the same manifest and installers inside a school
network. It cannot change them: the signature and publisher checks
still apply.

In **Instructor mode** (behind the instructor-mode switch, like every
instructor feature), an instructor can hold the version for the length
of a lab, so every student sees the same screens. Policy still wins.

## Publishing a release

1. Build and sign the .msi (`../windows/build-msi.ps1 -Sign ...`). It
   prints the `files` entry.
2. Upload the .msi to the GitHub release `kitsune-v<version>`.
3. Edit the channel's manifest: new `latest`, the `files` entry,
   `serial` + 1, `published` = now, `expires` = now + 30 days.
4. Sign it offline: `kitsune_update_sign.py sign --key release.pem manifest.json`.
5. Upload `manifest.json` and `manifest.json.sig` together.

Because manifests expire, re-sign and re-upload each channel's manifest
at least monthly even without a release; a scheduled CI job can do this
with a key kept in a protected environment.

## Key rotation

Make a new pair with `kitsune_update_sign.py keygen`, ship its public
key as the spare in a release, and once most installs have that
release, start signing with it and retire the old one. If a key leaks,
sign with the spare at once and ship a release that drops the leaked key.

## Not done yet

- The in-app update checker itself (a `kitsune/updater/` C++ module and
  a small QML prompt). This change only fixes the protocol and tools.
- Signed plugins (same idea, separate key), from the roadmap.

# Kitsune packaging

| Path                               | Contents                                                   |
|------------------------------------|------------------------------------------------------------|
| `windows/Kitsune.wxs`              | Windows Installer (.msi) package, WiX Toolset v5+          |
| `windows/build-msi.ps1`            | Stages a build, runs windeployqt, signs, builds the .msi   |
| `updates/README.md`                | How automatic updates work, and how to publish a release   |
| `updates/kitsune_update_sign.py`   | Makes, signs and verifies update manifests                 |
| `updates/example-manifest.json`    | A sample manifest                                          |

## WiX (.msi) or NSIS (.exe)?

Upstream Wireshark ships both, under `packaging/nsis` and
`packaging/wix`. NSIS is its main installer; the WiX one is marked
experimental, uses the old WiX 3 schema, and does not handle Npcap.
Kitsune uses **WiX v5, producing an .msi**, for these reasons:

- **Schools deploy with MSI.** Intune, Group Policy and Configuration
  Manager install an .msi silently and report its state, and
  `msiexec /i Kitsune.msi /qn UPDATES=0` is something lab IT staff
  already know. An NSIS .exe can be pushed too, but without the
  inventory, repair and rollback that Windows Installer gives.
- **Upgrades are clean.** Every release shares one `UpgradeCode`, so a
  new .msi replaces the old one in a single transaction; if it fails,
  the old version is left as it was. Automatic updates rely on this.
- **NSIS's main advantage does not apply.** Upstream's NSIS installer
  exists largely to run the bundled Npcap installer. Kitsune cannot
  bundle Npcap (below), so that advantage is gone.
- **WiX v5 harvests files itself.** The `<Files>` element picks up
  everything windeployqt staged, so there is no generated file list
  to keep in step with Qt.

Costs to know about: an .msi cannot be built on Linux (WiX needs
Windows Installer), and WiX v4 and later are a rewrite, so upstream's
`packaging/wix` files are a reference, not something to share. WiX v6
adds the "Open Source Maintenance Fee" for organizations that earn
revenue from using it; v5 has no fee and is enough here. Check the
current terms on wixtoolset.org before release.

## Npcap

Npcap's free license allows installing it, but not redistributing its
installer inside another product; that needs an
[Npcap OEM](https://npcap.com/oem/) license (Wireshark has its own
arrangement). So the .msi:

1. looks for Npcap in the registry (`NpcapInst` uninstall key, both
   registry views);
2. if it is missing, shows a checked box on the last page, "Open the
   Npcap download page", which opens <https://npcap.com/#download>
   as the user, not as administrator.

Kitsune repeats the check at run time and explains, in plain words,
that opening capture files works without Npcap but live capture needs
it. It also warns when Npcap was installed with "Restrict driver access
to Administrators only" (`AdminOnly` = 1 under
`HKLM\SYSTEM\CurrentControlSet\Services\npcap\Parameters`), because
then only an administrator can capture.

**Decision (2026-11-14): no OEM license for now.** Revisit before a
classroom roll-out. If the project gets an OEM license, a WiX Burn bundle (an .exe that
chains `npcap-oem.exe /S` and the .msi) can give classrooms a one-step,
silent install with live capture working. That is a later step.

## Never running as administrator

- The .msi installs per machine (Program Files), so installing and
  updating ask for admin rights through UAC.
- There is deliberately no "Launch Kitsune" box after install, because
  the installer may be elevated and Kitsune would inherit that.
- Live capture goes through `dumpcap.exe`, which the .msi installs next
  to `kitsune.exe`. Kitsune starts it as a normal, unprivileged process;
  Npcap lets non-admin users capture unless `AdminOnly` is set.
- Updates are installed by handing the verified .msi to Windows
  Installer, which raises its own UAC prompt. Kitsune never elevates.

## Building the .msi

On Windows, after building Kitsune (`-DBUILD_kitsune=ON`, see
`../README.md`), from a VS x64 developer prompt:

```powershell
dotnet tool install --global wix --version 5.*
wix extension add --global WixToolset.UI.wixext/5.0.2 WixToolset.Util.wixext/5.0.2
.\kitsune\packaging\windows\build-msi.ps1 -BuildDir C:\path\to\build -Version 0.2.0
```

Add `-Sign -SignArgs ...` for a release (see the script's help). The
script prints the `files` entry for the update manifest.

## Code signing

**Status: deferred.** Builds are unsigned for now (run `build-msi.ps1`
without `-Sign`). Unsigned installers show a SmartScreen warning
("More info", then "Run anyway"), and the updater only notifies about
new versions instead of installing them; see `updates/README.md`. Get a
certificate before the first public or classroom release.

Once in place, every release signs, with Authenticode, `kitsune.exe`, `dumpcap.exe`,
our DLLs and the .msi. Unsigned installers get SmartScreen warnings
and cannot be verified by the updater. Two ways to get a certificate:

- **Azure Artifact Signing** (formerly Trusted Signing): a monthly
  subscription, keys held by Microsoft, works from CI. Eligibility
  depends on the publisher's country and identity validation.
- **An OV code-signing certificate** from a CA; these now have to live
  on a hardware token or cloud HSM, which makes CI signing harder.

The publisher name on that certificate is pinned in Kitsune's updater,
so choose it once.

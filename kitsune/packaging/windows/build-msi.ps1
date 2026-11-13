<#
.SYNOPSIS
    Builds the Kitsune .msi from a finished Windows build.

.DESCRIPTION
    1. Copies kitsune.exe, dumpcap.exe, the engine DLLs and data files
       from <BuildDir>\run into a clean staging folder.
    2. Runs windeployqt for the Qt DLLs and QML modules, and copies the
       Visual C++ runtime next to the program (app-local), so the .msi
       has no prerequisites besides Windows.
    3. Optionally Authenticode-signs every .exe and .dll.
    4. Runs "wix build" on Kitsune.wxs.
    5. Optionally signs the .msi, then prints the file entry (size and
       SHA-256) for the update manifest.

    Run it from a "x64 Native Tools" prompt (or after build\env.cmd) so
    that windeployqt and the MSVC redist folder are found. It needs the
    WiX .NET tool, version 5 or later, and its UI and Util extensions:

        dotnet tool install --global wix
        wix extension add --global WixToolset.UI.wixext WixToolset.Util.wixext

.EXAMPLE
    .\build-msi.ps1 -BuildDir C:\Users\me\kitsune\build -Version 0.2.0

.EXAMPLE
    # Signed release build with a certificate from the Windows store
    .\build-msi.ps1 -BuildDir ..\build -Version 0.2.0 -Sign `
        -SignArgs '/sha1','<thumbprint>'

    SPDX-License-Identifier: GPL-2.0-or-later
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $BuildDir,
    [Parameter(Mandatory = $true)] [string] $Version,
    [string] $OutDir = (Join-Path $BuildDir 'kitsune-msi'),
    [string] $IconPath,
    [switch] $Sign,
    # Arguments that pick the certificate, passed straight to signtool,
    # e.g. '/sha1','<thumbprint>' or, for Azure Artifact Signing,
    # '/dlib','<path>\Azure.CodeSigning.Dlib.dll','/dmdf','<metadata.json>'
    [string[]] $SignArgs = @(),
    [string] $TimestampUrl = 'http://timestamp.acs.microsoft.com'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$PackagingDir = $PSScriptRoot
$SourceDir    = (Resolve-Path (Join-Path $PackagingDir '..\..\..')).Path
$RunDir       = Join-Path $BuildDir 'run'
$StagingDir   = Join-Path $OutDir 'staging'

# Windows Installer versions have at most four parts, each 0-65535 (the
# first three are compared for upgrades).
$parts = $Version.Split('.')
if ($parts.Count -lt 3 -or $parts.Count -gt 4 -or ($parts | Where-Object { $_ -notmatch '^\d+$' -or [int]$_ -gt 65535 })) {
    throw "Version must look like 1.2.3 or 1.2.3.4, got '$Version'"
}
while ($parts.Count -lt 4) { $parts += '0' }
$MsiVersion = $parts -join '.'

foreach ($exe in 'kitsune.exe', 'dumpcap.exe') {
    if (-not (Test-Path (Join-Path $RunDir $exe))) {
        throw "$exe not found in $RunDir. Build with -DBUILD_kitsune=ON first."
    }
}

function Invoke-Tool([string] $Tool, [string[]] $Arguments) {
    Write-Host "> $Tool $($Arguments -join ' ')"
    & $Tool @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Tool failed with exit code $LASTEXITCODE" }
}

function Invoke-Sign([string[]] $Files) {
    if (-not $Sign -or $Files.Count -eq 0) { return }
    $common = @('sign', '/fd', 'sha256', '/tr', $TimestampUrl, '/td', 'sha256') + $SignArgs
    # signtool takes many files per call; batch to stay under the
    # command-line length limit.
    for ($i = 0; $i -lt $Files.Count; $i += 50) {
        $batch = $Files[$i..([Math]::Min($i + 49, $Files.Count - 1))]
        Invoke-Tool 'signtool' ($common + $batch)
    }
}

# ---- 1. Stage the program and engine files -------------------------------
Write-Host "Staging into $StagingDir"
if (Test-Path $StagingDir) { Remove-Item -Recurse -Force $StagingDir }
New-Item -ItemType Directory -Force $StagingDir | Out-Null

# The run folder also holds Wireshark's own programs and build leftovers.
# Keep kitsune.exe and dumpcap.exe, every DLL, and the data files the
# engine loads at run time (manuf, services, dtds, radius, diameter, ...).
$skipExtensions = '.pdb', '.ilk', '.lib', '.exp', '.manifest'
Get-ChildItem $RunDir -Recurse -File | ForEach-Object {
    $relative = $_.FullName.Substring($RunDir.Length).TrimStart('\')
    if ($_.Extension -in $skipExtensions) { return }
    if ($_.Extension -eq '.exe' -and $_.Name -notin 'kitsune.exe', 'dumpcap.exe') { return }
    # Wireshark's Qt Widgets translations and docs are not Kitsune's.
    if ($relative -match '^(translations|share\\doc)\\') { return }
    $target = Join-Path $StagingDir $relative
    New-Item -ItemType Directory -Force (Split-Path $target) | Out-Null
    Copy-Item $_.FullName $target
}

# ---- 2. Qt and the C++ runtime -------------------------------------------
Invoke-Tool 'windeployqt' @(
    '--release', '--no-translations', '--no-compiler-runtime',
    '--qmldir', (Join-Path $SourceDir 'kitsune\qml'),
    (Join-Path $StagingDir 'kitsune.exe'))

if (-not $env:VCToolsRedistDir) {
    throw 'VCToolsRedistDir is not set. Run from a Visual Studio x64 developer prompt.'
}
$crt = Get-ChildItem (Join-Path $env:VCToolsRedistDir 'x64') -Directory -Filter 'Microsoft.VC*.CRT' | Select-Object -First 1
if (-not $crt) { throw "No Microsoft.VC*.CRT folder under $env:VCToolsRedistDir\x64" }
Copy-Item (Join-Path $crt.FullName '*.dll') $StagingDir

# ---- 3. Sign what we ship ------------------------------------------------
# Sign only our own binaries and those without a signature yet; Qt and
# Microsoft DLLs that are already signed keep their vendor's signature.
$unsigned = Get-ChildItem $StagingDir -Recurse -File -Include *.exe, *.dll |
    Where-Object { (Get-AuthenticodeSignature $_.FullName).Status -ne 'Valid' } |
    ForEach-Object { $_.FullName }
Invoke-Sign $unsigned

# ---- 4. Build the .msi ---------------------------------------------------
$msi = Join-Path $OutDir "Kitsune-$Version-x64.msi"
$wixArgs = @(
    'build', (Join-Path $PackagingDir 'Kitsune.wxs'),
    '-arch', 'x64',
    '-ext', 'WixToolset.UI.wixext',
    '-ext', 'WixToolset.Util.wixext',
    '-d', "StagingDir=$StagingDir",
    '-d', "KitsuneVersion=$MsiVersion",
    '-d', "LicenseRtf=$(Join-Path $SourceDir 'packaging\wix\COPYING.rtf')",
    '-o', $msi)
if ($IconPath) { $wixArgs += @('-d', "IconPath=$IconPath") }
Invoke-Tool 'wix' $wixArgs

# ---- 5. Sign the .msi and describe it for the update manifest ------------
Invoke-Sign @($msi)

$item = Get-Item $msi
$entry = [ordered]@{
    platform = 'windows-x64'
    kind     = 'msi'
    url      = "https://github.com/oriyano/wireshark/releases/download/kitsune-v$Version/$($item.Name)"
    size     = $item.Length
    sha256   = (Get-FileHash $msi -Algorithm SHA256).Hash.ToLowerInvariant()
}
Write-Host ''
Write-Host "Built $msi"
Write-Host 'Update manifest file entry:'
$entry | ConvertTo-Json

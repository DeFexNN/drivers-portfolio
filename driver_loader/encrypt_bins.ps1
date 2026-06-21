#Requires -Version 5.1
<#
.SYNOPSIS
    Pre-build script for driver_loader:
      1. Builds MidnightSoftwareDriver.sys (WDK project) via MSBuild
      2. Builds MidnightSoftware.exe       via MSBuild
      3. Generates a fresh AES-256 key (split into 3 XOR parts for obfuscation)
      4. Encrypts kvc.sys / MidnightSoftwareDriver.sys / MidnightSoftware.exe  →  *.bin
      5. Writes src\crypto_key.hpp  (included by embedded.hpp at compile time)

    Called automatically by the driver_loader Pre-Build event.
    Can also be run manually:
        .\encrypt_bins.ps1 -Configuration Release -Platform x64

.PARAMETER Configuration
    MSBuild configuration to pass to dependency projects. Default: Release
.PARAMETER Platform
    MSBuild platform.  Default: x64
.PARAMETER SkipBuild
    Skip MSBuild calls (use when the IDE already built the dependencies).
#>
param(
    [string]$Configuration = "Release",
    [string]$Platform      = "x64",
    [switch]$SkipBuild
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path

# ── Source file paths ─────────────────────────────────────────────────────────
$kvcSrc    = Join-Path $root "kvc.sys"
$drvSrc    = Join-Path $root "..\MidnightSoftwareDriver\MidnightSoftwareDriver\x64\$Configuration\MidnightSoftwareDriver.sys"
# Prefer the VMProtect-protected binary if it already exists (built externally).
$sdkDir    = Join-Path $root "..\..\Menus\War_Thunder\war_thunder_sdk\x64\$Configuration"
$exeVmp    = Join-Path $sdkDir "MidnightSoftware_vmp.exe"
$exePlain  = Join-Path $sdkDir "MidnightSoftware.exe"
$exeSrc    = if (Test-Path $exeVmp) { $exeVmp } else { $exePlain }

# ── Output paths (.bin = AES-encrypted, embedded by driver_loader.rc) ─────────
$kvcBin    = Join-Path $root "kvc.bin"
$drvBin    = Join-Path $root "MidnightSoftwareDriver.bin"
$exeBin    = Join-Path $root "MidnightSoftware.bin"

# ── Generated header  ─────────────────────────────────────────────────────────
$keyHpp    = Join-Path $root "src\crypto_key.hpp"

# ── Find EWDK (used for WDK driver builds to avoid InfVerif issues) ───────────
function Get-EwdkInfo {
    $ewdkRoot = "C:\ewdk"
    if (Test-Path $ewdkRoot) {
        $latest = Get-ChildItem $ewdkRoot -Directory |
                  Where-Object { Test-Path (Join-Path $_.FullName "BuildEnv\SetupBuildEnv.cmd") } |
                  Sort-Object Name -Descending |
                  Select-Object -First 1
        if ($latest) {
            $setup   = Join-Path $latest.FullName "BuildEnv\SetupBuildEnv.cmd"
            # find the amd64 MSBuild inside the EWDK
            $ms = Get-ChildItem (Join-Path $latest.FullName "Program Files") `
                      -Recurse -Filter "MSBuild.exe" -ErrorAction SilentlyContinue |
                  Where-Object { $_.DirectoryName -like "*amd64*" } |
                  Select-Object -First 1
            if ($ms) { return @{ Setup = $setup; MSBuild = $ms.FullName } }
        }
    }
    return $null
}

# ── Find VS MSBuild (for non-WDK projects) ───────────────────────────────────
function Get-MSBuildPath {
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vswhere) {
        $p = & $vswhere -latest -requires Microsoft.Component.MSBuild `
                        -find "MSBuild\**\Bin\MSBuild.exe" 2>$null |
             Select-Object -First 1
        if ($p -and (Test-Path $p)) { return $p }
    }
    return "msbuild.exe"
}

# ── Build dependencies ────────────────────────────────────────────────────────
if (-not $SkipBuild) {
    $msbuild  = Get-MSBuildPath
    $drvProj  = Join-Path $root "..\MidnightSoftwareDriver\MidnightSoftwareDriver\MidnightSoftwareDriver.vcxproj"
    $sdkProj  = Join-Path $root "..\..\Menus\War_Thunder\war_thunder_sdk\sdk.vcxproj"

    foreach ($proj in @($drvProj, $sdkProj)) {
        if (-not (Test-Path $proj)) {
            Write-Host "[encrypt_bins] ERROR: Project not found: $proj"
            exit 1
        }
    }

    Write-Host "[encrypt_bins] Building MidnightSoftware driver ($Configuration|$Platform)..."
    $ewdk = Get-EwdkInfo
    if ($ewdk) {
        # Use EWDK so InfVerif.dll is available and the build exits cleanly.
        # /nodeReuse:false is critical: prevents EWDK worker nodes (which have
        # WDK env vars like WDKContentRoot) from persisting and being reused by
        # VS MSBuild when it later compiles driver_loader itself, which would
        # cause WDK toolset validation to apply to a regular C++ project.
        $drvProjEsc = $drvProj -replace '"', '""'
        $cmdLine = "call `"$($ewdk.Setup)`" && `"$($ewdk.MSBuild)`" `"$drvProjEsc`" /p:Configuration=$Configuration /p:Platform=$Platform /v:minimal /nologo /nodeReuse:false"
        cmd /C $cmdLine
    } else {
        # Fallback: regular MSBuild (InfVerif warning expected but .sys still produced)
        & $msbuild $drvProj /p:Configuration=$Configuration /p:Platform=$Platform /v:minimal /nologo 2>&1 | ForEach-Object { Write-Host $_ }
    }
    if (-not (Test-Path $drvSrc)) {
        Write-Host "[encrypt_bins] ERROR: MidnightSoftware driver build failed - output not found: $drvSrc"
        exit 1
    }

    Write-Host "[encrypt_bins] Building MidnightSoftware SDK ($Configuration|$Platform)..."
    & $msbuild $sdkProj /p:Configuration=$Configuration /p:Platform=$Platform `
               /v:minimal /nologo
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[encrypt_bins] ERROR: MidnightSoftware SDK build failed (exit $LASTEXITCODE)"
        exit 1
    }

    # ── VMProtect: protect MidnightSoftware.exe ──────────────────────────────────────
    # VMProtect_Con writes the protected binary as  <name>_vmp.exe
    # (configured via Output File in the .vmp project).
    $vmpCon   = "C:\Users\DeFexGG\Downloads\VMProtect\VMProtect\VMProtect_Con.exe"
    $vmpProj  = Join-Path $root "..\..\Menus\War_Thunder\war_thunder_sdk\x64\$Configuration\MidnightSoftware.exe.vmp"
    $vmpDir   = Split-Path -Parent $vmpProj
    $vmpOut   = Join-Path $vmpDir "MidnightSoftware_vmp.exe"   # <── underscore convention

    if (-not (Test-Path $vmpCon)) {
        Write-Host "[encrypt_bins] WARNING: VMProtect_Con.exe not found at $vmpCon – skipping protection"
        # $exeSrc already points to the plain exe – fall through
    } elseif (-not (Test-Path $vmpProj)) {
        Write-Host "[encrypt_bins] WARNING: .vmp project not found at $vmpProj – skipping protection"
        # $exeSrc already points to the plain exe – fall through
    } else {
        Write-Host "[encrypt_bins] Running VMProtect on MidnightSoftware.exe..."
        Push-Location $vmpDir
        & $vmpCon "MidnightSoftware.exe.vmp"
        $vmpExit = $LASTEXITCODE
        Pop-Location
        if ($vmpExit -ne 0) {
            Write-Host "[encrypt_bins] ERROR: VMProtect_Con.exe failed (exit $vmpExit)"
            exit 1
        }
        if (-not (Test-Path $vmpOut)) {
            Write-Host "[encrypt_bins] ERROR: VMProtect output not found: $vmpOut"
            exit 1
        }
        $exeSrc = $vmpOut
        Write-Host "[encrypt_bins] VMProtect OK -> MidnightSoftware_vmp.exe"
    }
}

# ── Verify sources exist ──────────────────────────────────────────────────────
foreach ($f in @($kvcSrc, $drvSrc, $exeSrc)) {
    if (-not (Test-Path $f)) {
        Write-Host "[encrypt_bins] ERROR: Source file not found: $f"
        exit 1
    }
}

# ── Generate fresh AES-256 key + per-file IVs ────────────────────────────────
$rng      = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$realKey  = [byte[]]::new(32)
$ivKvc    = [byte[]]::new(16)
$ivDrv    = [byte[]]::new(16)
$ivExe    = [byte[]]::new(16)

$rng.GetBytes($realKey)
$rng.GetBytes($ivKvc)
$rng.GetBytes($ivDrv)
$rng.GetBytes($ivExe)

# 3-part XOR split:  P1 ^ P2 ^ P3 = realKey
$p1 = [byte[]]::new(32)
$p2 = [byte[]]::new(32)
$p3 = [byte[]]::new(32)
$rng.GetBytes($p1)
$rng.GetBytes($p2)
for ($i = 0; $i -lt 32; $i++) { $p3[$i] = $p1[$i] -bxor $p2[$i] -bxor $realKey[$i] }

# ── AES-256-CBC helper ────────────────────────────────────────────────────────
function Invoke-AES256CBC {
    param([byte[]]$Data, [byte[]]$Key, [byte[]]$IV)

    $aes         = [System.Security.Cryptography.Aes]::Create()
    $aes.KeySize = 256
    $aes.Key     = $Key
    $aes.IV      = $IV
    $aes.Mode    = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

    $enc = $aes.CreateEncryptor()
    return $enc.TransformFinalBlock($Data, 0, $Data.Length)
}

# ── Encrypt and write .bin files ──────────────────────────────────────────────
Write-Host "[encrypt_bins] Encrypting binaries..."

$kvcEnc = Invoke-AES256CBC -Data ([IO.File]::ReadAllBytes($kvcSrc)) -Key $realKey -IV $ivKvc
$drvEnc = Invoke-AES256CBC -Data ([IO.File]::ReadAllBytes($drvSrc)) -Key $realKey -IV $ivDrv
$exeEnc = Invoke-AES256CBC -Data ([IO.File]::ReadAllBytes($exeSrc)) -Key $realKey -IV $ivExe

[IO.File]::WriteAllBytes($kvcBin, $kvcEnc)
[IO.File]::WriteAllBytes($drvBin, $drvEnc)
[IO.File]::WriteAllBytes($exeBin, $exeEnc)

# ── Generate crypto_key.hpp ───────────────────────────────────────────────────
function ConvertTo-CppArray {
    param([byte[]]$Bytes, [string]$Name)
    $hex = ($Bytes | ForEach-Object { "0x{0:X2}u" -f $_ }) -join ", "
    return "    static constexpr uint8_t ${Name}[] = { $hex };"
}

$hpp = @"
// AUTO-GENERATED by encrypt_bins.ps1 — DO NOT EDIT, DO NOT COMMIT
// A new random AES-256 key is generated on every build.
// The key is split into 3 XOR parts so it cannot be trivially extracted.
//   Runtime reconstruction:  key[i] = KEY_P1[i] ^ KEY_P2[i] ^ KEY_P3[i]
#pragma once
#include <cstdint>

namespace crypto_key {
$(ConvertTo-CppArray -Bytes $p1    -Name "KEY_P1")
$(ConvertTo-CppArray -Bytes $p2    -Name "KEY_P2")
$(ConvertTo-CppArray -Bytes $p3    -Name "KEY_P3")
$(ConvertTo-CppArray -Bytes $ivKvc -Name "IV_KVC")
$(ConvertTo-CppArray -Bytes $ivDrv -Name "IV_DRIVER")
$(ConvertTo-CppArray -Bytes $ivExe -Name "IV_PAYLOAD")
} // namespace crypto_key
"@

[System.IO.File]::WriteAllText($keyHpp, $hpp, [System.Text.Encoding]::UTF8)

Write-Host "[encrypt_bins] Generated crypto_key.hpp"
Write-Host ("[encrypt_bins] kvc.bin={0} B  MidnightSoftwareDriver.bin={1} B  MidnightSoftware.bin={2} B" -f
    $kvcEnc.Length, $drvEnc.Length, $exeEnc.Length)

exit 0

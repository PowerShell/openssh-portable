<#
.SYNOPSIS
    MCP tool that bootstraps vcpkg and installs Win32-OpenSSH dependencies.

.DESCRIPTION
    This script automates the vcpkg setup required by the Win32-OpenSSH build.
    It mirrors the recipe in .azdo/templates/install-vcpkg-dependencies.yml so
    the same install path works locally and in CI.

    The script:
    - Locates a vcpkg clone (parameter, $env:VCPKG_ROOT, or ..\vcpkg).
    - Optionally bootstraps it (-Bootstrap).
    - Verifies the LibreSSL vcpkg.json override matches the FileVersion field
      in vcpkg_overlay_ports/libressl/add-version-file.patch (cross-check).
    - Runs `vcpkg install` from contrib/win32/openssh against the manifest,
      using --overlay-triplets=.\vcpkg_triplets and
      --overlay-ports=.\vcpkg_overlay_ports.
    - Verifies that vcpkg_installed/<triplet>/bin/libcrypto.dll was produced.

    Output is consumed by OpenSSHBuildHelper.psm1 which reads from
    contrib\win32\openssh\vcpkg_installed\<triplet>-custom\<triplet>-custom\bin\.

.PARAMETER Architecture
    One or more architectures to install. Each value maps to the
    corresponding `<arch>-custom` triplet. Default is 'x64' to match the
    default of Start-OpenSSHBuild.ps1. Pass multiple values to install for
    several triplets in one run, matching what CI builds.

.PARAMETER VcpkgRoot
    Path to a vcpkg clone. If omitted, the script tries (in order):
        1. $env:VCPKG_ROOT
        2. ..\vcpkg relative to the repo root
    If neither exists, the script errors with a clone command.

.PARAMETER Bootstrap
    If specified, runs bootstrap-vcpkg.bat when vcpkg.exe is missing.
    Without this switch, a missing vcpkg.exe is treated as an error.

.PARAMETER Clean
    If specified, deletes contrib/win32/openssh/vcpkg_installed before
    installing. Forces a from-scratch install.

.PARAMETER BinaryCache
    Optional path to a vcpkg binary cache directory. When supplied, the
    script sets VCPKG_BINARY_SOURCES=clear;files,<path>,readwrite for the
    install invocation, mirroring the AzDO pipeline.

.PARAMETER SkipVersionCheck
    Skip the LibreSSL vcpkg.json <-> add-version-file.patch cross-check.
    Use only when intentionally bumping the manifest before regenerating
    the patch.

.OUTPUTS
    Returns a hashtable with:
    - Success: Boolean indicating overall success
    - VcpkgRoot: Resolved vcpkg root path
    - VcpkgExecutable: Path to vcpkg.exe used
    - TripletsInstalled: Array of triplets that completed install
    - InstalledPath: Path to vcpkg_installed
    - VersionCheckPassed: Boolean (or $null if skipped)
    - Errors: Array of error strings
    - Message: Summary message

.EXAMPLE
    .\Install-VcpkgDependencies.ps1 -Bootstrap

    First-time setup. Bootstraps vcpkg if needed and installs the x64-custom
    triplet.

.EXAMPLE
    .\Install-VcpkgDependencies.ps1 -Architecture x64,x86,ARM,ARM64

    Installs all four custom triplets (matches CI artifact set).

.EXAMPLE
    .\Install-VcpkgDependencies.ps1 -Clean -BinaryCache C:\vcpkg-cache

    Wipes vcpkg_installed and reinstalls, using a shared binary cache.

.NOTES
    - Mirrors .azdo/templates/install-vcpkg-dependencies.yml.
    - Must complete before Start-OpenSSHBuild.ps1.
    - Does not run `vcpkg integrate install`; that is optional and global.
#>

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet('x64', 'x86', 'ARM', 'ARM64')]
    [string[]]$Architecture = @('x64'),

    [Parameter(Mandatory=$false)]
    [string]$VcpkgRoot,

    [Parameter(Mandatory=$false)]
    [switch]$Bootstrap,

    [Parameter(Mandatory=$false)]
    [switch]$Clean,

    [Parameter(Mandatory=$false)]
    [string]$BinaryCache,

    [Parameter(Mandatory=$false)]
    [switch]$SkipVersionCheck
)

$ErrorActionPreference = 'Stop'

$scriptRoot = $PSScriptRoot
if ([string]::IsNullOrEmpty($scriptRoot)) {
    $scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
}
$repoRoot = (Get-Item $scriptRoot).Parent.Parent.FullName
$opensshDir = Join-Path $repoRoot 'contrib\win32\openssh'
$installedDir = Join-Path $opensshDir 'vcpkg_installed'
$overlayPortsDir = Join-Path $opensshDir 'vcpkg_overlay_ports'
$overlayTripletsDir = Join-Path $opensshDir 'vcpkg_triplets'
$manifestPath = Join-Path $opensshDir 'vcpkg.json'
$libresslPatchPath = Join-Path $overlayPortsDir 'libressl\add-version-file.patch'

$result = @{
    Success = $false
    VcpkgRoot = $null
    VcpkgExecutable = $null
    TripletsInstalled = @()
    InstalledPath = $installedDir
    VersionCheckPassed = $null
    Errors = @()
    Message = ''
}

function Resolve-VcpkgRoot {
    param([string]$Explicit, [string]$RepoRoot)

    $candidates = @()
    if (-not [string]::IsNullOrWhiteSpace($Explicit)) {
        $candidates += $Explicit
    }
    if (-not [string]::IsNullOrWhiteSpace($env:VCPKG_ROOT)) {
        $candidates += $env:VCPKG_ROOT
    }
    $candidates += (Join-Path (Split-Path -Parent $RepoRoot) 'vcpkg')

    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate -PathType Container) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }
    return $null
}

function Test-LibreSSLVersionMatch {
    param([string]$ManifestPath, [string]$PatchPath)

    if (-not (Test-Path -LiteralPath $ManifestPath)) {
        throw "vcpkg.json not found at $ManifestPath"
    }
    if (-not (Test-Path -LiteralPath $PatchPath)) {
        throw "LibreSSL patch not found at $PatchPath"
    }

    $manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
    $manifestVersion = $manifest.overrides |
        Where-Object { $_.name -eq 'libressl' } |
        Select-Object -ExpandProperty version

    if ([string]::IsNullOrWhiteSpace($manifestVersion)) {
        throw "No 'libressl' override found in $ManifestPath"
    }

    $patchContent = Get-Content -LiteralPath $PatchPath -Raw
    $match = [regex]::Match($patchContent, '"FileVersion",\s*"(\d+\.\d+\.\d+\.\d+)"')
    if (-not $match.Success) {
        throw "FileVersion field not found in $PatchPath"
    }
    $patchVersionFull = $match.Groups[1].Value
    $patchVersionShort = ($patchVersionFull -split '\.')[0..2] -join '.'

    return [pscustomobject]@{
        ManifestVersion = $manifestVersion
        PatchVersion = $patchVersionFull
        PatchVersionShort = $patchVersionShort
        Match = ($manifestVersion -eq $patchVersionShort)
    }
}

try {
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Install Win32-OpenSSH vcpkg Dependencies" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Repository Root: $repoRoot" -ForegroundColor Gray
    Write-Host "Architectures:   $($Architecture -join ', ')" -ForegroundColor White
    Write-Host "========================================`n" -ForegroundColor Cyan

    # Step 1: Resolve vcpkg root
    Write-Host "[1/5] Locating vcpkg..." -ForegroundColor Cyan
    $resolvedRoot = Resolve-VcpkgRoot -Explicit $VcpkgRoot -RepoRoot $repoRoot
    if (-not $resolvedRoot) {
        $msg = "vcpkg clone not found. Tried: -VcpkgRoot, `$env:VCPKG_ROOT, $(Join-Path (Split-Path -Parent $repoRoot) 'vcpkg').`n" +
               "Clone it with: git clone https://github.com/Microsoft/vcpkg.git $(Join-Path (Split-Path -Parent $repoRoot) 'vcpkg')"
        $result.Errors += $msg
        Write-Host "  ✗ $msg" -ForegroundColor Red
        $result.Message = 'vcpkg clone not found.'
        return $result
    }
    $result.VcpkgRoot = $resolvedRoot
    Write-Host "  ✓ vcpkg root: $resolvedRoot" -ForegroundColor Green

    $vcpkgExe = Join-Path $resolvedRoot 'vcpkg.exe'
    $bootstrapScript = Join-Path $resolvedRoot 'bootstrap-vcpkg.bat'

    # Step 2: Bootstrap if needed
    Write-Host "`n[2/5] Checking vcpkg.exe..." -ForegroundColor Cyan
    if (-not (Test-Path -LiteralPath $vcpkgExe)) {
        if ($Bootstrap) {
            if (-not (Test-Path -LiteralPath $bootstrapScript)) {
                $msg = "bootstrap-vcpkg.bat not found at $bootstrapScript"
                $result.Errors += $msg
                Write-Host "  ✗ $msg" -ForegroundColor Red
                $result.Message = 'Bootstrap script missing.'
                return $result
            }
            Write-Host "  → Bootstrapping vcpkg..." -ForegroundColor Yellow
            Push-Location $resolvedRoot
            try {
                & $bootstrapScript
                $bootstrapExit = $LASTEXITCODE
            } finally {
                Pop-Location
            }
            if ($bootstrapExit -ne 0 -or -not (Test-Path -LiteralPath $vcpkgExe)) {
                $msg = "bootstrap-vcpkg.bat exited with code $bootstrapExit; vcpkg.exe still missing."
                $result.Errors += $msg
                Write-Host "  ✗ $msg" -ForegroundColor Red
                $result.Message = 'Bootstrap failed.'
                return $result
            }
            Write-Host "  ✓ vcpkg bootstrapped" -ForegroundColor Green
        } else {
            $msg = "vcpkg.exe not found at $vcpkgExe. Re-run with -Bootstrap to build it."
            $result.Errors += $msg
            Write-Host "  ✗ $msg" -ForegroundColor Red
            $result.Message = 'vcpkg.exe missing; pass -Bootstrap.'
            return $result
        }
    } else {
        Write-Host "  ✓ vcpkg.exe found" -ForegroundColor Green
    }
    $result.VcpkgExecutable = $vcpkgExe

    # Step 3: LibreSSL version cross-check
    Write-Host "`n[3/5] Verifying LibreSSL version cross-check..." -ForegroundColor Cyan
    if ($SkipVersionCheck) {
        Write-Host "  ⊘ Skipped (-SkipVersionCheck)" -ForegroundColor Yellow
        $result.VersionCheckPassed = $null
    } else {
        $versionInfo = Test-LibreSSLVersionMatch -ManifestPath $manifestPath -PatchPath $libresslPatchPath
        if ($versionInfo.Match) {
            Write-Host "  ✓ LibreSSL versions match: $($versionInfo.ManifestVersion)" -ForegroundColor Green
            $result.VersionCheckPassed = $true
        } else {
            $msg = "LibreSSL version mismatch: vcpkg.json has $($versionInfo.ManifestVersion), patch file has $($versionInfo.PatchVersion). " +
                   "Update FileVersion in $libresslPatchPath, or pass -SkipVersionCheck."
            $result.Errors += $msg
            $result.VersionCheckPassed = $false
            Write-Host "  ✗ $msg" -ForegroundColor Red
            $result.Message = 'LibreSSL version cross-check failed.'
            return $result
        }
    }

    # Step 4: Optional clean
    Write-Host "`n[4/5] Preparing vcpkg_installed..." -ForegroundColor Cyan
    if ($Clean -and (Test-Path -LiteralPath $installedDir)) {
        Write-Host "  → Removing $installedDir" -ForegroundColor Yellow
        Remove-Item -LiteralPath $installedDir -Recurse -Force
    }
    Write-Host "  ✓ Ready" -ForegroundColor Green

    # Step 5: Install per triplet
    Write-Host "`n[5/5] Running vcpkg install..." -ForegroundColor Cyan
    $previousBinarySources = $env:VCPKG_BINARY_SOURCES
    if (-not [string]::IsNullOrWhiteSpace($BinaryCache)) {
        if (-not (Test-Path -LiteralPath $BinaryCache)) {
            New-Item -ItemType Directory -Path $BinaryCache -Force | Out-Null
        }
        $env:VCPKG_BINARY_SOURCES = "clear;files,$BinaryCache,readwrite"
        Write-Host "  Binary cache: $BinaryCache" -ForegroundColor Gray
    }

    try {
        foreach ($arch in $Architecture) {
            $triplet = "$($arch.ToLowerInvariant())-custom"
            Write-Host "`n  → Installing triplet: $triplet" -ForegroundColor Yellow
            Push-Location $opensshDir
            try {
                & $vcpkgExe install `
                    --triplet $triplet `
                    --overlay-triplets=$overlayTripletsDir `
                    --overlay-ports=$overlayPortsDir
                $exit = $LASTEXITCODE
            } finally {
                Pop-Location
            }

            if ($exit -ne 0) {
                $msg = "vcpkg install for triplet $triplet failed with exit code $exit"
                $result.Errors += $msg
                Write-Host "  ✗ $msg" -ForegroundColor Red
                continue
            }

            # Verify expected artifact
            $libcryptoPath = Join-Path $installedDir "$triplet\$triplet\bin\libcrypto.dll"
            if (Test-Path -LiteralPath $libcryptoPath) {
                Write-Host "  ✓ $triplet installed (libcrypto.dll present)" -ForegroundColor Green
                $result.TripletsInstalled += $triplet
            } else {
                $msg = "vcpkg install for $triplet completed but libcrypto.dll not found at $libcryptoPath"
                $result.Errors += $msg
                Write-Host "  ✗ $msg" -ForegroundColor Red
            }
        }
    } finally {
        $env:VCPKG_BINARY_SOURCES = $previousBinarySources
    }

    # Final evaluation
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "INSTALL SUMMARY" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    $result.Success = ($result.Errors.Count -eq 0) -and ($result.TripletsInstalled.Count -eq $Architecture.Count)
    if ($result.Success) {
        Write-Host "✓ ALL TRIPLETS INSTALLED" -ForegroundColor Green
        Write-Host "  Triplets: $($result.TripletsInstalled -join ', ')" -ForegroundColor White
        Write-Host "  Output:   $installedDir" -ForegroundColor Gray
        $result.Message = "Installed $($result.TripletsInstalled.Count) triplet(s) successfully."
    } else {
        Write-Host "✗ INSTALL INCOMPLETE" -ForegroundColor Red
        foreach ($err in $result.Errors) {
            Write-Host "  • $err" -ForegroundColor Red
        }
        $result.Message = "$($result.Errors.Count) error(s) during install."
    }
    Write-Host ""

    return $result

} catch {
    Write-Host "`n========================================" -ForegroundColor Red
    Write-Host "ERROR" -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor Gray

    $result.Success = $false
    $result.Errors += "Tool error: $($_.Exception.Message)"
    $result.Message = "Install failed with error: $($_.Exception.Message)"
    return $result
}

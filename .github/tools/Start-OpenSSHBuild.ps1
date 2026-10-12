<#
.SYNOPSIS
    MCP tool to build OpenSSH on Windows using Visual Studio.

.DESCRIPTION
    This script wraps the Start-OpenSSHBuild function from OpenSSHBuildHelper.psm1
    to provide a standardized MCP interface for building OpenSSH. It supports
    incremental and clean builds, multiple architectures, and various build configurations.

    The tool invokes MSBuild on the Win32-OpenSSH.sln solution and captures
    all build output to a log file.

.PARAMETER Configuration
    Build configuration type. Valid values: 'Debug', 'Release'
    Default: 'Release'

.PARAMETER Architecture
    Target architecture for the build. Valid values: 'x64', 'x86', 'ARM', 'ARM64'
    Default: the host machine's architecture (auto-detected). If you explicitly pass an
    architecture that does not match the host, the build is refused unless -AllowArchMismatch
    is also specified.

.PARAMETER AllowArchMismatch
    Permit building for an architecture that differs from the host machine's architecture
    (e.g. cross-building ARM64 on an x64 host). Without this switch, a mismatched -Architecture
    is rejected so you don't accidentally produce binaries you can't run or test locally.

.PARAMETER Clean
    When specified, performs a clean build by deleting existing build artifacts first.
    Default: false (incremental build)

.PARAMETER NoOpenSSL
    Build without OpenSSL support.
    Default: false

.PARAMETER OneCore
    Build for Windows OneCore API subset.
    Default: false

.OUTPUTS
    Returns a hashtable with:
    - Success: Boolean indicating build success
    - ExitCode: MSBuild exit code
    - LogFile: Path to build log file
    - BuildPath: Path to build output directory
    - Message: Status message

.EXAMPLE
    .\Start-OpenSSHBuild.ps1 -Configuration Release -Architecture x64

    Performs an incremental release build for x64 architecture.

.EXAMPLE
    .\Start-OpenSSHBuild.ps1 -Configuration Debug -Architecture x64 -Clean

    Performs a clean debug build for x64 architecture.

.EXAMPLE
    .\Start-OpenSSHBuild.ps1 -Architecture ARM64 -OneCore

    Performs an incremental OneCore release build for ARM64.

.NOTES
    - Requires Visual Studio 2019 or later with C++ tools
    - Requires Windows SDK 10.0.17763.0 or later
    - Build artifacts output to: contrib\win32\openssh\{Architecture}\{Configuration}\
    - Build log written to: OpenSSH{Configuration}{Architecture}.log
#>

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',

    [Parameter(Mandatory=$false)]
    [ValidateSet('x64', 'x86', 'ARM', 'ARM64')]
    [string]$Architecture,

    [Parameter(Mandatory=$false)]
    [switch]$AllowArchMismatch,

    [Parameter(Mandatory=$false)]
    [switch]$Clean,

    [Parameter(Mandatory=$false)]
    [switch]$NoOpenSSL,

    [Parameter(Mandatory=$false)]
    [switch]$OneCore
)

# ── Resolve target architecture (default = host arch; forbid mismatch unless overridden) ──
function Get-HostArchitecture {
    $archEnv = $env:PROCESSOR_ARCHITEW6432
    if ([string]::IsNullOrEmpty($archEnv)) { $archEnv = $env:PROCESSOR_ARCHITECTURE }
    switch (($archEnv | ForEach-Object { $_.ToUpperInvariant() })) {
        'AMD64' { 'x64' }
        'X86'   { 'x86' }
        'ARM64' { 'ARM64' }
        'ARM'   { 'ARM' }
        default { 'x64' }
    }
}

$hostArch = Get-HostArchitecture
if (-not $PSBoundParameters.ContainsKey('Architecture') -or [string]::IsNullOrEmpty($Architecture)) {
    $Architecture = $hostArch
    Write-Host "Architecture not specified; defaulting to host architecture: $Architecture" -ForegroundColor Gray
} elseif ($Architecture -ne $hostArch -and -not $AllowArchMismatch) {
    throw "Requested architecture '$Architecture' does not match the host architecture '$hostArch'. Re-run with -AllowArchMismatch to build for a different architecture on purpose."
}

# Determine repository root (go up from .github\tools to repo root)
$scriptRoot = $PSScriptRoot
$repoRoot = Split-Path -Parent (Split-Path -Parent $scriptRoot)

# Navigate to repository root
Push-Location $repoRoot

try {
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "OpenSSH Build Tool (MCP)" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Configuration: $Configuration" -ForegroundColor White
    Write-Host "Architecture:  $Architecture" -ForegroundColor White
    Write-Host "Clean Build:   $Clean" -ForegroundColor White
    Write-Host "No OpenSSL:    $NoOpenSSL" -ForegroundColor White
    Write-Host "OneCore:       $OneCore" -ForegroundColor White
    Write-Host "========================================`n" -ForegroundColor Cyan

    # Import OpenSSH build helper module
    $buildHelperPath = Join-Path $repoRoot "contrib\win32\openssh\OpenSSHBuildHelper.psm1"
    if (-not (Test-Path $buildHelperPath)) {
        throw "OpenSSHBuildHelper.psm1 not found at: $buildHelperPath"
    }

    Import-Module $buildHelperPath -Force -ErrorAction Stop
    Write-Host "✓ Loaded OpenSSHBuildHelper module" -ForegroundColor Green

    # Define build output path (matches OpenSSHBuildHelper.psm1: bin\<folderName>\<Configuration>,
    # where x86 maps to the "Win32" folder name)
    $folderName = if ($Architecture -eq 'x86') { 'Win32' } else { $Architecture }
    $buildPath = Join-Path $repoRoot "bin\$folderName\$Configuration"

    # Perform clean if requested
    if ($Clean -and (Test-Path $buildPath)) {
        Write-Host "`nCleaning previous build artifacts..." -ForegroundColor Yellow
        Remove-Item $buildPath -Recurse -Force -ErrorAction Stop
        Write-Host "✓ Cleaned: $buildPath" -ForegroundColor Green
    }

    # Build log file path (align with other tools under contrib\win32\openssh)
    $logFile = Join-Path $repoRoot "contrib\win32\openssh\OpenSSH$Configuration$Architecture.log"
    Write-Host "`nBuild log: $logFile" -ForegroundColor Gray

    # Prepare parameters for Start-OpenSSHBuild
    $buildParams = @{
        Configuration = $Configuration
        NativeHostArch = $Architecture
    }

    if ($NoOpenSSL) {
        $buildParams['NoOpenSSL'] = $true
    }

    if ($OneCore) {
        $buildParams['OneCore'] = $true
    }

    # Execute build
    Write-Host "`nStarting build..." -ForegroundColor Cyan
    Write-Host "Command: Start-OpenSSHBuild -Configuration $Configuration -NativeHostArch $Architecture$(if($NoOpenSSL){' -NoOpenSSL'})$(if($OneCore){' -OneCore'})" -ForegroundColor Gray

    $buildResult = Start-OpenSSHBuild @buildParams

    # Determine build success primarily via log markers, not exit code
    $successByLog = $null
    $buildLogTime = $null
    if (Test-Path $logFile) {
        $buildLogTime = (Get-Item $logFile -ErrorAction SilentlyContinue).LastWriteTime
        $logLines = Get-Content $logFile -ErrorAction SilentlyContinue
        if ($logLines) {
            $lastMarker = $null
            foreach ($line in $logLines) {
                if ($line -match '(?i)Build\s+(FAILED|Failed)') { $lastMarker = 'FAILED' }
                elseif ($line -match '(?i)Build\s+(SUCCEEDED|Succeeded)') { $lastMarker = 'SUCCEEDED' }
            }
            if ($lastMarker) { $successByLog = ($lastMarker -eq 'SUCCEEDED') }
        }
    }

    $derivedSuccess = if ($successByLog -ne $null) { $successByLog } else { $buildResult -eq 0 }

    if ($derivedSuccess) {
        Write-Host "`n========================================" -ForegroundColor Green
        Write-Host "BUILD SUCCEEDED" -ForegroundColor Green
        Write-Host "========================================" -ForegroundColor Green
        Write-Host "Build artifacts: $buildPath" -ForegroundColor White

        $result = @{
            Success = $true
            ExitCode = $buildResult
            LogFile = $logFile
            BuildPath = $buildPath
            BuildLogTimestamp = $buildLogTime
            Message = "Build completed successfully"
        }
    } else {
        Write-Host "`n========================================" -ForegroundColor Red
        Write-Host "BUILD FAILED" -ForegroundColor Red
        Write-Host "========================================" -ForegroundColor Red
        Write-Host "Exit code: $buildResult" -ForegroundColor Red
        Write-Host "Check log file: $logFile" -ForegroundColor Yellow

        $result = @{
            Success = $false
            ExitCode = $buildResult
            LogFile = $logFile
            BuildPath = $buildPath
            BuildLogTimestamp = $buildLogTime
            Message = "Build failed (determined from log markers or exit code). Check log file for details."
        }
    }

    # Output result as JSON for MCP consumption
    return $result

} catch {
    Write-Host "`n========================================" -ForegroundColor Red
    Write-Host "ERROR" -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor Gray

    $result = @{
        Success = $false
        ExitCode = -1
        LogFile = $logFile
        BuildPath = $buildPath
        Message = "Build tool error: $($_.Exception.Message)"
    }

    return $result

} finally {
    Pop-Location
}

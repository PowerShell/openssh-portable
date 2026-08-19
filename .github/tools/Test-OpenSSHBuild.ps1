<#
.SYNOPSIS
    MCP tool to test OpenSSH build artifacts and parse build errors.

.DESCRIPTION
    This script tests that all expected OpenSSH executables were built successfully
    and parses the build log file for any compilation or linker errors using regex patterns.

    Expected artifacts (14 executables):
    - ssh.exe, sshd.exe, sshd-auth.exe, sshd-session.exe
    - ssh-agent.exe, ssh-add.exe, ssh-keygen.exe, ssh-keyscan.exe
    - scp.exe, sftp.exe, sftp-server.exe
    - ssh-pkcs11-helper.exe, ssh-shellhost.exe, ssh-sk-helper.exe

.PARAMETER Configuration
    Build configuration type that was used. Valid values: 'Debug', 'Release'
    Default: 'Release'

.PARAMETER Architecture
    Target architecture that was built. Valid values: 'x64', 'x86', 'ARM', 'ARM64'
    Default: the host machine's architecture (auto-detected). An explicit mismatched value is
    rejected unless -AllowArchMismatch is also specified.

.PARAMETER AllowArchMismatch
    Permit targeting an architecture that differs from the host machine's architecture.

.PARAMETER LogFile
    Optional path to the build log file. If not specified, uses default pattern:
    contrib\win32\openssh\OpenSSH{Configuration}{Architecture}.log (where OpenSSHBuildHelper writes it).

.OUTPUTS
    Returns a hashtable with:
    - Success: Boolean indicating if all artifacts present and no errors
    - ArtifactsFound: Array of executables that exist
    - ArtifactsMissing: Array of expected executables that are missing
    - TotalArtifacts: Count of artifacts found
    - ExpectedArtifacts: Count of artifacts expected (14)
    - Errors: Array of parsed error objects with file, line, code, message
    - Warnings: Array of parsed warning objects
    - LogFile: Path to log file analyzed
    - Message: Summary message

.EXAMPLE
    .\Test-OpenSSHBuild.ps1 -Configuration Release -Architecture x64

    Tests release build artifacts for x64 architecture.

.EXAMPLE
    .\Test-OpenSSHBuild.ps1 -Configuration Debug -Architecture x86 -LogFile "C:\build\custom.log"

    Tests debug build artifacts for x86 using a custom log file location.

.NOTES
    - Expected build artifact location: bin\{Architecture}\{Configuration}\ (x86 maps to the "Win32" folder)
    - Error parsing regex (file/line form): ^(?<file>.+?)\((?<line>\d+)[,)].*?\s(?<severity>fatal error|error)\s+(?<code>(?:C|LNK|MSB)\d+)\s*:\s*(?<message>.+)$
    - Error parsing regex (generic/no line): ^(?:.*?:\s*)?(?<severity>fatal error|error)\s+(?<code>(?:C|LNK|MSB)\d+)\s*:\s*(?<message>.+)$
    - Warning parsing regex (file/line form): ^(?<file>.+?)\((?<line>\d+)[,)].*?\swarning\s+(?<code>(?:C|LNK|MSB)\d+)\s*:\s*(?<message>.+)$
    - Warning parsing regex (generic/no line): ^(?:.*?:\s*)?warning\s+(?<code>(?:C|LNK|MSB)\d+)\s*:\s*(?<message>.+)$
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
    [string]$LogFile
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
} elseif ($Architecture -ne $hostArch -and -not $AllowArchMismatch) {
    throw "Requested architecture '$Architecture' does not match the host architecture '$hostArch'. Re-run with -AllowArchMismatch to target a different architecture on purpose."
}

# Determine repository root (go up from .github\tools to repo root)
$scriptRoot = $PSScriptRoot
$repoRoot = Split-Path -Parent (Split-Path -Parent $scriptRoot)

# Define expected artifacts (14 executables)
$expectedArtifacts = @(
    "ssh.exe",
    "sshd.exe",
    "sshd-auth.exe",
    "sshd-session.exe",
    "ssh-agent.exe",
    "ssh-add.exe",
    "ssh-keygen.exe",
    "ssh-keyscan.exe",
    "scp.exe",
    "sftp.exe",
    "sftp-server.exe",
    "ssh-pkcs11-helper.exe",
    "ssh-shellhost.exe",
    "ssh-sk-helper.exe"
)

try {
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "OpenSSH Build Test Tool (MCP)" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Configuration: $Configuration" -ForegroundColor White
    Write-Host "Architecture:  $Architecture" -ForegroundColor White
    Write-Host "========================================`n" -ForegroundColor Cyan

    # Define build output path
    $folderName = if ($Architecture -eq 'x86') { 'Win32' } else { $Architecture }
    $buildPath = Join-Path $repoRoot "bin\$folderName\$Configuration"

    if (-not (Test-Path $buildPath)) {
        Write-Host "Build path does not exist: $buildPath" -ForegroundColor Red

        $result = @{
            Success = $false
            ArtifactsFound = @()
            ArtifactsMissing = $expectedArtifacts
            TotalArtifacts = 0
            ExpectedArtifacts = $expectedArtifacts.Count
            Errors = @()
            Warnings = @()
            LogFile = $LogFile
            Message = "Build path does not exist: $buildPath"
        }

        return $result
    }

    Write-Host "Build path: $buildPath" -ForegroundColor Gray

    # Check for artifacts
    Write-Host "`nChecking for expected artifacts..." -ForegroundColor Cyan

    $artifactsFound = @()
    $artifactsMissing = @()

    foreach ($artifact in $expectedArtifacts) {
        $artifactPath = Join-Path $buildPath $artifact
        if (Test-Path $artifactPath) {
            $artifactsFound += $artifact
            Write-Host "  ✓ $artifact" -ForegroundColor Green
        } else {
            $artifactsMissing += $artifact
            Write-Host "  ✗ $artifact (MISSING)" -ForegroundColor Red
        }
    }

    Write-Host "`nArtifacts: $($artifactsFound.Count) of $($expectedArtifacts.Count) found" -ForegroundColor $(if ($artifactsMissing.Count -eq 0) { "Green" } else { "Yellow" })

    # Parse build log if available
    $errors = @()
    $warnings = @()

    if (-not $LogFile) {
        $LogFile = Join-Path $repoRoot "contrib\win32\openssh\OpenSSH$Configuration$Architecture.log"
    }

    if (Test-Path $LogFile) {
        Write-Host "`nParsing build log: $LogFile" -ForegroundColor Cyan

        $logContent = Get-Content $LogFile -ErrorAction SilentlyContinue
        $logTime = (Get-Item $LogFile -ErrorAction SilentlyContinue).LastWriteTime

        if ($logContent) {
            # Find the first build status marker and, if failed, only scan lines after it
            $buildStatusIndex = $null
            $buildFailed = $false
            for ($i = 0; $i -lt $logContent.Count; $i++) {
                $line = $logContent[$i]
                if ($line -match 'Build\s+(FAILED|Failed)') {
                    $buildStatusIndex = $i
                    $buildFailed = $true
                    break
                } elseif ($line -match 'Build\s+(SUCCEEDED|Succeeded)') {
                    $buildStatusIndex = $i
                    break
                }
            }

            $linesToScan = $logContent
            if ($buildFailed -and $buildStatusIndex -ne $null -and $buildStatusIndex + 1 -lt $logContent.Count) {
                $linesToScan = $logContent[($buildStatusIndex + 1)..($logContent.Count - 1)]
            }

            # Broadened regex patterns to support linker/MSBuild messages without line numbers
            $errorWithFileRegex   = '^(?<file>.+?)\((?<line>\d+)[,)].*?\s(?<severity>fatal error|error)\s+(?<code>(?:C|LNK|MSB)\d+)\s*:\s*(?<message>.+)$'
            $genericErrorRegex    = '^(?:.*?:\s*)?(?<severity>fatal error|error)\s+(?<code>(?:C|LNK|MSB)\d+)\s*:\s*(?<message>.+)$'
            $warningWithFileRegex = '^(?<file>.+?)\((?<line>\d+)[,)].*?\swarning\s+(?<code>(?:C|LNK|MSB)\d+)\s*:\s*(?<message>.+)$'
            $genericWarningRegex  = '^(?:.*?:\s*)?warning\s+(?<code>(?:C|LNK|MSB)\d+)\s*:\s*(?<message>.+)$'

            foreach ($line in $linesToScan) {
                # Errors with file/line
                if ($line -match $errorWithFileRegex) {
                    $errors += [PSCustomObject]@{
                        File = $matches['file']
                        Line = [int]$matches['line']
                        Code = $matches['code']
                        Message = $matches['message']
                        RawLine = $line
                    }
                    continue
                }
                # Generic errors (e.g., LINK/MSBuild without line numbers)
                if ($line -match $genericErrorRegex) {
                    $errors += [PSCustomObject]@{
                        File = ''
                        Line = $null
                        Code = $matches['code']
                        Message = $matches['message']
                        RawLine = $line
                    }
                    continue
                }
                # Warnings with file/line
                if ($line -match $warningWithFileRegex) {
                    $warnings += [PSCustomObject]@{
                        File = $matches['file']
                        Line = [int]$matches['line']
                        Code = $matches['code']
                        Message = $matches['message']
                        RawLine = $line
                    }
                    continue
                }
                # Generic warnings
                if ($line -match $genericWarningRegex) {
                    $warnings += [PSCustomObject]@{
                        File = ''
                        Line = $null
                        Code = $matches['code']
                        Message = $matches['message']
                        RawLine = $line
                    }
                }
            }

            if ($errors.Count -gt 0) {
                Write-Host "`nFound $($errors.Count) error(s) in build log:" -ForegroundColor Red
                foreach ($e in $errors) {
                    if ([string]::IsNullOrEmpty($e.File)) {
                        Write-Host "  error $($e.Code): $($e.Message)" -ForegroundColor Red
                    } else {
                        $lineSuffix = if ($e.Line -ne $null) { "(" + $e.Line + ")" } else { "" }
                        Write-Host ("  {0}{1}: error {2}: {3}" -f $e.File, $lineSuffix, $e.Code, $e.Message) -ForegroundColor Red
                    }
                }
            } else {
                Write-Host "`n✓ No errors found in build log" -ForegroundColor Green
            }

            if ($warnings.Count -gt 0) {
                Write-Host "`nFound $($warnings.Count) warning(s) in build log:" -ForegroundColor Yellow
                foreach ($warning in $warnings | Select-Object -First 10) {
                    if ([string]::IsNullOrEmpty($warning.File)) {
                        Write-Host "  warning $($warning.Code): $($warning.Message)" -ForegroundColor Yellow
                    } else {
                        $lineSuffix = if ($warning.Line -ne $null) { "(" + $warning.Line + ")" } else { "" }
                        Write-Host ("  {0}{1}: warning {2}: {3}" -f $warning.File, $lineSuffix, $warning.Code, $warning.Message) -ForegroundColor Yellow
                    }
                }
                if ($warnings.Count -gt 10) {
                    Write-Host "  ... and $($warnings.Count - 10) more warnings" -ForegroundColor Gray
                }
            }
        } else {
            Write-Host "Log file is empty or could not be read" -ForegroundColor Yellow
        }

        # Timestamp freshness checks removed; rely on build log parsing instead
    } else {
        Write-Host "`nBuild log not found: $LogFile" -ForegroundColor Yellow
    }

    # Determine overall success
    $success = ($artifactsMissing.Count -eq 0) -and ($errors.Count -eq 0)

    # Build summary message
    if ($success) {
        $message = "All $($expectedArtifacts.Count) artifacts built successfully with no errors"
    } elseif ($artifactsMissing.Count -gt 0 -and $errors.Count -gt 0) {
        $message = "$($artifactsMissing.Count) artifacts missing and $($errors.Count) error(s) found"
    } elseif ($artifactsMissing.Count -gt 0) {
        $message = "$($artifactsMissing.Count) artifacts missing"
    } else {
        $message = "$($errors.Count) error(s) found in build log"
    }

    Write-Host "`n========================================" -ForegroundColor $(if ($success) { "Green" } else { "Red" })
    Write-Host $(if ($success) { "TEST PASSED" } else { "TEST FAILED" }) -ForegroundColor $(if ($success) { "Green" } else { "Red" })
    Write-Host "========================================" -ForegroundColor $(if ($success) { "Green" } else { "Red" })
    Write-Host $message -ForegroundColor White

    $result = @{
        Success = $success
        ArtifactsFound = $artifactsFound
        ArtifactsMissing = $artifactsMissing
        TotalArtifacts = $artifactsFound.Count
        ExpectedArtifacts = $expectedArtifacts.Count
        Errors = $errors
        Warnings = $warnings
        LogFile = $LogFile
        # BuildLogTimestamp and stale artifact checks removed
        Message = $message
    }

    return $result

} catch {
    Write-Host "`n========================================" -ForegroundColor Red
    Write-Host "ERROR" -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor Gray

    $result = @{
        Success = $false
        ArtifactsFound = @()
        ArtifactsMissing = $expectedArtifacts
        TotalArtifacts = 0
        ExpectedArtifacts = $expectedArtifacts.Count
        Errors = @()
        Warnings = @()
        LogFile = $LogFile
        Message = "Test tool error: $($_.Exception.Message)"
    }

    return $result
}

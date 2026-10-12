<#
.SYNOPSIS
    Runs the OpenSSH full CI test suite (unit tests, bash tests, and E2E/Pester tests).

.DESCRIPTION
    This script automates the full OpenSSH CI test workflow on Windows using the
    OpenSSHTestHelper module. It supports running all test suites together or
    individual suites, with optional single-test targeting for bash tests.

    Test suites:
    - Unit:  Runs unittest-*.exe binaries found under the binary path
    - Bash:  Runs upstream bash regression tests via Cygwin sh.exe
    - E2E:   Runs Windows Pester-based end-to-end tests (requires Pester < 5)

    The workflow is:
      1. Import OpenSSHTestHelper module
      2. Set-OpenSSHTestEnvironment (installs test accounts, sshd test service, etc.)
      3. Run selected test suites
      4. Clear-OpenSSHTestEnvironment (unless -NoCleanup)

    Reference: https://github.com/PowerShell/Win32-OpenSSH/wiki/Run-OpenSSH-Pester-Tests

.PARAMETER Configuration
    Build configuration. Valid values: 'Debug', 'Release'. Default: 'Release'.

.PARAMETER Architecture
    Target architecture. Valid values: 'x64', 'x86', 'ARM', 'ARM64'. Default: the host
    machine's architecture (auto-detected). A mismatched explicit value is rejected unless
    -AllowArchMismatch is specified.

.PARAMETER AllowArchMismatch
    Permit targeting an architecture that differs from the host machine's architecture.

.PARAMETER TestSuite
    Which test suites to run. Valid values: 'All', 'Unit', 'Bash', 'E2E'.
    Default: 'All'. Multiple values allowed.

.PARAMETER BashTestFilePath
    Run a single bash test file instead of the full bash suite.
    Must be an absolute path to a .sh file under the regress folder.
    Example: C:\repos\openssh-portable\regress\banner.sh
    Only applies when TestSuite includes 'Bash'.

.PARAMETER BashShellPath
    Path to sh.exe (Cygwin or WSL). Auto-detected from common Cygwin locations
    if not specified. Example: C:\cygwin64\bin\sh.exe

.PARAMETER NoCleanup
    Skip Clear-OpenSSHTestEnvironment at the end. Useful for debugging failures.

.PARAMETER SkipSetup
    Skip Set-OpenSSHTestEnvironment. Use when environment is already configured.

.EXAMPLE
    .\Invoke-OpenSSHTests.ps1
    Runs all test suites with Release x64 binaries.

.EXAMPLE
    .\Invoke-OpenSSHTests.ps1 -TestSuite Unit
    Runs only unit tests.

.EXAMPLE
    .\Invoke-OpenSSHTests.ps1 -TestSuite E2E -Configuration Debug
    Runs only Pester E2E tests using Debug binaries.

.EXAMPLE
    .\Invoke-OpenSSHTests.ps1 -TestSuite Bash -BashTestFilePath C:\repos\openssh-portable\regress\banner.sh
    Runs a single bash test.

.NOTES
    Requires Administrator privileges.
    Pester < 5 required for E2E tests (the helper will install via chocolatey if needed).
    Cygwin (sh.exe) required for bash tests.

    Known gotchas:
    - cfginclude.sh calls powershell.exe; if running under pwsh.exe, edit the test to use pwsh.exe.
      See https://github.com/PowerShell/PowerShell/issues/18530#issuecomment-1325691850
    - WSMan and Port Forwarding tests may be disallowed on some VMs by default.
      Enable the features or skip the affected tests.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',

    [Parameter()]
    [ValidateSet('x64', 'x86', 'ARM', 'ARM64')]
    [string]$Architecture,

    [Parameter()]
    [switch]$AllowArchMismatch,

    [Parameter()]
    [ValidateSet('All', 'Unit', 'Bash', 'E2E')]
    [string[]]$TestSuite = @('All'),

    [Parameter()]
    [string]$BashTestFilePath = '',

    [Parameter()]
    [string]$BashShellPath = '',

    [Parameter()]
    [switch]$NoCleanup,

    [Parameter()]
    [switch]$SkipSetup
)

# ──────────────────────────────────────────────────────────────────────────────
# Resolve target architecture (default = host arch; forbid mismatch unless overridden)
# ──────────────────────────────────────────────────────────────────────────────
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
    throw "Requested architecture '$Architecture' does not match the host architecture '$hostArch'. Tests must run against host-native binaries; re-run with -AllowArchMismatch only if the target binaries can execute here."
}

# ──────────────────────────────────────────────────────────────────────────────
# Resolve paths
# ──────────────────────────────────────────────────────────────────────────────
$scriptRoot     = Split-Path -Parent $PSCommandPath
$repoRoot       = Split-Path -Parent (Split-Path -Parent $scriptRoot)
$binPath        = Join-Path $repoRoot "bin\$Architecture\$Configuration"
$helperModule   = Join-Path $repoRoot "contrib\win32\openssh\OpenSSHTestHelper.psm1"
$bashIterator   = Join-Path $repoRoot "contrib\win32\openssh\bash_tests_iterator.ps1"
$regressPath    = Join-Path $repoRoot "regress"

# ──────────────────────────────────────────────────────────────────────────────
# Result object
# ──────────────────────────────────────────────────────────────────────────────
$result = [PSCustomObject]@{
    Success          = $false
    UnitTestsPassed  = $null   # $true/$false/$null (not run)
    BashTestsPassed  = $null
    E2ETestsPassed   = $null
    UnitTestOutput   = $null
    BashTestOutput   = $null
    E2ETestOutput    = $null
    Errors           = @()
    Warnings         = @()
    Message          = ''
}

$moduleImported = $false
$setupCompleted = $false

function Write-StepHeader([string]$msg) {
    Write-Host ""
    Write-Host "=== $msg ===" -ForegroundColor Cyan
}

$runUnit = $TestSuite -contains 'All' -or $TestSuite -contains 'Unit'
$runBash = $TestSuite -contains 'All' -or $TestSuite -contains 'Bash'
$runE2E  = $TestSuite -contains 'All' -or $TestSuite -contains 'E2E'

try {
    # ── Admin check ──────────────────────────────────────────────────────────
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]"Administrator")
    if (-not $isAdmin) {
        $result.Errors += "Administrator privileges required."
        $result.Message = "FAILED: Must be run as Administrator."
        Write-Host "✗ Administrator privileges required." -ForegroundColor Red
        return $result
    }

    # ── Verify binaries ──────────────────────────────────────────────────────
    if (-not (Test-Path (Join-Path $binPath "ssh.exe"))) {
        $result.Errors += "Binaries not found at $binPath. Build the project first."
        $result.Message = "FAILED: Build artifacts not found at $binPath."
        Write-Host "✗ Binaries not found at $binPath" -ForegroundColor Red
        return $result
    }
    Write-Host "✓ Binaries found at $binPath" -ForegroundColor Green

    # ── Import helper module ─────────────────────────────────────────────────
    Write-StepHeader "Importing OpenSSHTestHelper"
    if (-not (Test-Path $helperModule)) {
        $result.Errors += "OpenSSHTestHelper.psm1 not found at $helperModule"
        $result.Message = "FAILED: OpenSSHTestHelper module not found."
        Write-Host "✗ Module not found: $helperModule" -ForegroundColor Red
        return $result
    }
    Import-Module $helperModule -Force
    $moduleImported = $true
    Write-Host "✓ Module imported" -ForegroundColor Green

    # ── Set-OpenSSHTestEnvironment ───────────────────────────────────────────
    if (-not $SkipSetup) {
        Write-StepHeader "Setting Up Test Environment"
        Write-Host "  OpenSSHBinPath: $binPath"
        Set-OpenSSHTestEnvironment -OpenSSHBinPath $binPath -Confirm:$false
        $setupCompleted = $true
        Write-Host "✓ Test environment configured" -ForegroundColor Green
    } else {
        Write-Host "⚠ Skipping Set-OpenSSHTestEnvironment (-SkipSetup specified)" -ForegroundColor Yellow
        $result.Warnings += "Setup skipped — environment must already be configured."
    }

    # ── Unit Tests ───────────────────────────────────────────────────────────
    if ($runUnit) {
        Write-StepHeader "Running Unit Tests"
        try {
            # Force unit test discovery to the selected build output path.
            $unitOutput = Invoke-OpenSSHUnitTest -UnitTestDirectory $binPath *>&1 | Tee-Object -Variable unitCapture
            $unitText = $unitCapture | Out-String
            $result.UnitTestOutput = $unitText

            # Detect failure: unit test runner writes "failed" to output or exits non-zero
            if ($unitText -match 'failed') {
                $result.UnitTestsPassed = $false
                $result.Errors += "Unit tests reported failures. See UnitTestOutput for details."
                Write-Host "✗ Unit tests: FAILED" -ForegroundColor Red
            } else {
                $result.UnitTestsPassed = $true
                Write-Host "✓ Unit tests: PASSED" -ForegroundColor Green
            }
        } catch {
            $result.UnitTestsPassed = $false
            $result.Errors += "Unit test exception: $_"
            Write-Host "✗ Unit tests threw an exception: $_" -ForegroundColor Red
        }
    }

    # ── Bash Tests ───────────────────────────────────────────────────────────
    if ($runBash) {
        Write-StepHeader "Running Bash Tests"
        $result.Warnings += "cfginclude.sh gotcha: calls powershell.exe; if running under pwsh, edit the test to use pwsh.exe (see https://github.com/PowerShell/PowerShell/issues/18530#issuecomment-1325691850)."

        try {
            if (-not [string]::IsNullOrEmpty($BashTestFilePath)) {
                # Single bash test via iterator.
                $resolvedShellPath = $BashShellPath
                if ([string]::IsNullOrEmpty($resolvedShellPath) -or -not (Test-Path $resolvedShellPath)) {
                    throw "BashShellPath is required for single-test mode."
                }

                Write-Host "  Shell: $resolvedShellPath"
                Write-Host "  Running single test: $BashTestFilePath"
                $bashOutput = & $bashIterator `
                    -OpenSSHBinPath $binPath `
                    -BashTestsPath  $regressPath `
                    -ShellPath      $resolvedShellPath `
                    -TestFilePath   $BashTestFilePath `
                    *>&1 | Tee-Object -Variable bashCapture
            } else {
                # Full bash suite via helper (helper handles Cygwin install/detection).
                Write-Host "  Running full bash test suite..."
                $bashOutput = Invoke-OpenSSHBashTests *>&1 | Tee-Object -Variable bashCapture
            }

            $bashText = $bashCapture | Out-String
            $result.BashTestOutput = $bashText

            if ($bashText -match 'FAILED|not ok') {
                $result.BashTestsPassed = $false
                $result.Errors += "Bash tests reported failures. See BashTestOutput for details."
                Write-Host "✗ Bash tests: FAILED" -ForegroundColor Red
            } else {
                $result.BashTestsPassed = $true
                Write-Host "✓ Bash tests: PASSED" -ForegroundColor Green
            }
        } catch {
            $result.BashTestsPassed = $false
            $result.Errors += "Bash test exception: $_"
            Write-Host "✗ Bash tests threw an exception: $_" -ForegroundColor Red
        }
    }

    # ── E2E / Pester Tests ───────────────────────────────────────────────────
    if ($runE2E) {
        Write-StepHeader "Running E2E Pester Tests"
        $result.Warnings += "WSMan and Port Forwarding tests may fail on some VMs where those features are disabled. Enable them in Windows Features or skip those test files."
        Write-Host "  ⚠ Note: WSMan/Port Forwarding may need to be enabled on this machine." -ForegroundColor Yellow

        try {
            $e2eOutput = Invoke-OpenSSHE2ETest *>&1 | Tee-Object -Variable e2eCapture
            $e2eText = $e2eCapture | Out-String
            $result.E2ETestOutput = $e2eText

            if ($e2eText -match 'Failed\s*:\s*[1-9]|Tests failed') {
                $result.E2ETestsPassed = $false
                $result.Errors += "E2E tests reported failures. See E2ETestOutput for details."
                Write-Host "✗ E2E Pester tests: FAILED" -ForegroundColor Red
            } else {
                $result.E2ETestsPassed = $true
                Write-Host "✓ E2E Pester tests: PASSED" -ForegroundColor Green
            }
        } catch {
            $result.E2ETestsPassed = $false
            $result.Errors += "E2E test exception: $_"
            Write-Host "✗ E2E tests threw an exception: $_" -ForegroundColor Red
        }
    }

    # ── Overall result ───────────────────────────────────────────────────────
    $anyFailed = ($result.UnitTestsPassed -eq $false) -or
                 ($result.BashTestsPassed -eq $false) -or
                 ($result.E2ETestsPassed  -eq $false)

    $result.Success = -not $anyFailed
    $result.Message = if ($result.Success) { "All selected test suites passed." } `
                      else { "One or more test suites failed. See Errors for details." }

} catch {
    $result.Errors += "Unexpected error: $_"
    $result.Message = "FAILED: Unexpected error — $_"
    Write-Host "✗ Unexpected error: $_" -ForegroundColor Red
} finally {
    # ── Cleanup ──────────────────────────────────────────────────────────────
    if (-not $NoCleanup -and -not $SkipSetup -and $moduleImported -and $setupCompleted) {
        Write-StepHeader "Cleaning Up Test Environment"
        try {
            Clear-OpenSSHTestEnvironment
            Write-Host "✓ Test environment cleaned up" -ForegroundColor Green
        } catch {
            $result.Warnings += "Cleanup warning: $_"
            Write-Host "⚠ Cleanup encountered an issue: $_" -ForegroundColor Yellow
        }
    } elseif (-not $NoCleanup -and -not $SkipSetup -and (-not $moduleImported -or -not $setupCompleted)) {
        $result.Warnings += "Cleanup skipped because setup did not complete."
        Write-Host "⚠ Cleanup skipped because setup did not complete." -ForegroundColor Yellow
    } elseif ($NoCleanup) {
        Write-Host "⚠ Skipping cleanup (-NoCleanup specified). Run Clear-OpenSSHTestEnvironment manually." -ForegroundColor Yellow
    }
}

# ── Summary ───────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "=== Test Summary ===" -ForegroundColor Cyan
Write-Host "Overall:    $(if ($result.Success) { '✓ PASSED' } else { '✗ FAILED' })" -ForegroundColor $(if ($result.Success) { 'Green' } else { 'Red' })
if ($null -ne $result.UnitTestsPassed) {
    Write-Host "Unit Tests: $(if ($result.UnitTestsPassed) { '✓ PASSED' } else { '✗ FAILED' })" -ForegroundColor $(if ($result.UnitTestsPassed) { 'Green' } else { 'Red' })
}
if ($null -ne $result.BashTestsPassed) {
    Write-Host "Bash Tests: $(if ($result.BashTestsPassed) { '✓ PASSED' } else { '✗ FAILED' })" -ForegroundColor $(if ($result.BashTestsPassed) { 'Green' } else { 'Red' })
}
if ($null -ne $result.E2ETestsPassed) {
    Write-Host "E2E Tests:  $(if ($result.E2ETestsPassed) { '✓ PASSED' } else { '✗ FAILED' })" -ForegroundColor $(if ($result.E2ETestsPassed) { 'Green' } else { 'Red' })
}
if ($result.Warnings.Count -gt 0) {
    Write-Host ""
    Write-Host "Warnings:" -ForegroundColor Yellow
    $result.Warnings | ForEach-Object { Write-Host "  ⚠ $_" -ForegroundColor Yellow }
}
if ($result.Errors.Count -gt 0) {
    Write-Host ""
    Write-Host "Errors:" -ForegroundColor Red
    $result.Errors | ForEach-Object { Write-Host "  ✗ $_" -ForegroundColor Red }
}

return $result

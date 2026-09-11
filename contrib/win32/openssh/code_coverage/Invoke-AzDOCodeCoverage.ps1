# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
    .SYNOPSIS
    Azure DevOps entry point for Win32-OpenSSH code coverage.

    .DESCRIPTION
    Runs one OpenSSH test suite (the "Core" flow - setup + unit + E2E - or the
    "Bash" flow) under Microsoft.CodeCoverage.Console against an
    already-installed OpenSSH directory, using the same AzDOBuildTools entry
    points the CI test jobs use.

    The installed OpenSSH binaries (built with /PROFILE by the coverage build
    job) are statically instrumented with a per-suite session id, then the suite
    runs while a background server-mode collector owns that session. This
    captures every instrumented OpenSSH process - including sshd.exe running as a
    Windows service, which is not a child of this script. `shutdown` flushes a
    per-suite .coverage file that is converted to Cobertura.

    By default the script then aggregates every per-suite report found under
    -OutputDirectory into a combined, de-duplicated report plus per-suite/overlap
    summaries (useful for local, single-agent runs). In CI the Core and Bash
    suites run in separate jobs (each on its own agent with a clean install, so
    there is no cross-suite file-lock or service-state contention); those jobs
    pass -SkipAggregation and publish their per-suite artifact, and a dependent
    job runs Invoke-AzDOCoverageAggregate.ps1 to combine them.

    This script assumes the solution is already built (with /PROFILE) and
    installed. It never builds.

    .PARAMETER Suite
    Which suite to measure this invocation: Core or Bash.

    .PARAMETER OpenSSHBinPath
    Installed OpenSSH directory containing the binaries, their PDBs and the
    unittest-*.exe binaries (CI installs this to $env:SystemDrive\OpenSSH).

    .PARAMETER SourceRoot
    Repository root used to scope coverage to OpenSSH source files.

    .PARAMETER OutputDirectory
    Where per-suite and merged coverage artifacts are written.

    .PARAMETER SkipAggregation
    Produce only this suite's per-suite .coverage + Cobertura report and skip the
    combined merge/summary (the dedicated CI aggregation job does that).

    .EXAMPLE
    .\Invoke-AzDOCodeCoverage.ps1 -Suite Core -OutputDirectory C:\cov
    .\Invoke-AzDOCodeCoverage.ps1 -Suite Bash -OutputDirectory C:\cov
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Core', 'Bash')]
    [string] $Suite,

    [string] $OpenSSHBinPath = "$env:SystemDrive\OpenSSH",

    [string] $SourceRoot,

    [Parameter(Mandatory = $true)]
    [string] $OutputDirectory,

    # Skip the aggregation/merge/summary pass; only produce this suite's per-suite
    # .coverage + Cobertura report. Used by the split CI jobs, where a dedicated
    # dependent job aggregates the per-suite artifacts from Core and Bash.
    [switch] $SkipAggregation
)

$ErrorActionPreference = 'Stop'

$opensshDir = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if (-not $SourceRoot) {
    $SourceRoot = (Resolve-Path (Join-Path $PSScriptRoot '..' '..' '..' '..')).Path
}
$azdoModule = Join-Path $opensshDir 'AzDOBuildTools'

Import-Module (Join-Path $PSScriptRoot 'OpenSSHCodeCoverage.psm1') -Force

$null = New-Item -ItemType Directory -Path $OutputDirectory -Force
$tool = Find-CodeCoverageConsole
Write-Host "CodeCoverage.Console : $tool"
Write-Host "Suite                : $Suite"
Write-Host "OpenSSHBinPath       : $OpenSSHBinPath"
Write-Host "SourceRoot           : $SourceRoot"

switch ($Suite) {
    'Core' {
        $name = 'core'
        $cmd = "Import-Module '$azdoModule' -Force; Invoke-OpenSSHTests -OpenSSHBinPath '$OpenSSHBinPath'"
    }
    'Bash' {
        $name = 'bash'
        $cmd = "Import-Module '$azdoModule' -Force; Invoke-OpenSSHBashTestsOnly -OpenSSHBinPath '$OpenSSHBinPath'"
    }
}

# Instrument the installed OpenSSH binaries with a per-suite session id, then
# run the suite while a server-mode collector owns that session.
$targets = Get-OpenSSHCoverageTarget -BinaryDirectory $OpenSSHBinPath
if (-not $targets) {
    throw "No OpenSSH binaries to instrument were found under '$OpenSSHBinPath'."
}
Write-Host "Instrumenting $($targets.Count) binaries for suite '$name'..."

$sessionId = [guid]::NewGuid().ToString()
Invoke-CoverageInstrument -BinaryPath $targets -SessionId $sessionId -ToolPath $tool | Out-Null

# The current PowerShell host re-invokes itself so its ssh/sshd/unittest
# children (all instrumented) run inside the collection window.
$pwshHost = (Get-Process -Id $PID).Path

try {
    $session = Invoke-CoverageSession -Name $name `
        -Program $pwshHost -ArgumentList @('-NoProfile', '-NonInteractive', '-Command', $cmd) `
        -SessionId $sessionId `
        -OutputDirectory (Join-Path $OutputDirectory $name) `
        -ToolPath $tool
    Write-Host "Suite '$name' coverage exit code: $($session.ExitCode)"
}
finally {
    # Restore the binaries so a subsequent suite step starts from clean images.
    Invoke-CoverageUninstrument -BinaryPath $targets -ToolPath $tool
}

if ($SkipAggregation) {
    Write-Host "SkipAggregation set; produced per-suite report only under $OutputDirectory."
    return
}

# Aggregate every per-suite report collected so far (single-job / local usage).
Invoke-CoverageAggregation -OutputDirectory $OutputDirectory -SourceRoot $SourceRoot -ToolPath $tool | Out-Null

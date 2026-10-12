# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
    .SYNOPSIS
    Azure DevOps aggregation entry point for Win32-OpenSSH code coverage.

    .DESCRIPTION
    The Core and Bash suites are measured in separate CI jobs (each on its own
    agent with a clean OpenSSH install, so there is no cross-suite file-lock or
    service-state contention). Each job publishes its per-suite .coverage +
    Cobertura report as an artifact. This script runs in a dependent job that has
    downloaded those artifacts into -InputDirectory; it aggregates every per-suite
    report it finds into a single de-duplicated report plus per-suite/overlap
    summaries under -OutputDirectory.

    .PARAMETER InputDirectory
    Directory containing the downloaded per-suite coverage artifacts (searched
    recursively for *.coverage and *.cobertura.xml).

    .PARAMETER OutputDirectory
    Where the merged report and summaries are written. Defaults to
    -InputDirectory.

    .PARAMETER SourceRoot
    Repository root used to scope coverage to OpenSSH source files.

    .EXAMPLE
    .\Invoke-AzDOCoverageAggregate.ps1 -InputDirectory C:\cov -SourceRoot C:\src
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $InputDirectory,

    [string] $OutputDirectory,

    [string] $SourceRoot
)

$ErrorActionPreference = 'Stop'

if (-not $OutputDirectory) { $OutputDirectory = $InputDirectory }
if (-not $SourceRoot) {
    $SourceRoot = (Resolve-Path (Join-Path $PSScriptRoot '..' '..' '..' '..')).Path
}

Import-Module (Join-Path $PSScriptRoot 'OpenSSHCodeCoverage.psm1') -Force

$null = New-Item -ItemType Directory -Path $OutputDirectory -Force

Write-Host "InputDirectory  : $InputDirectory"
Write-Host "OutputDirectory : $OutputDirectory"
Write-Host "SourceRoot      : $SourceRoot"

# If aggregating into a different directory than the inputs, bring the per-suite
# artifacts across so the native .coverage merge and the Cobertura scan see them.
if ((Resolve-Path -LiteralPath $OutputDirectory).Path -ne (Resolve-Path -LiteralPath $InputDirectory).Path) {
    Copy-Item -Path (Join-Path $InputDirectory '*') -Destination $OutputDirectory -Recurse -Force
}

$result = Invoke-CoverageAggregation -OutputDirectory $OutputDirectory -SourceRoot $SourceRoot
if (-not $result) {
    throw "No per-suite coverage reports were found under '$InputDirectory'; nothing to aggregate."
}

Write-Host "Merged report : $($result.MergedReport)"

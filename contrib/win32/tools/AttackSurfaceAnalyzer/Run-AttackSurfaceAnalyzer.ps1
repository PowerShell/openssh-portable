# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    Run Attack Surface Analyzer on OpenSSH MSI installation on a Windows VM.

.DESCRIPTION
    This script performs the following steps:
    1. Installs Attack Surface Analyzer as a .NET global tool
    2. Takes a baseline snapshot before installation
    3. Installs the OpenSSH MSI
    4. Takes a post-installation snapshot
    5. Exports comparison results to JSON and SQLite database
    6. Generates reports in the asa-results directory

.PARAMETER MsiPath
    Path to the OpenSSH MSI file to test. If not specified, will look for *.msi in current directory.

.PARAMETER WorkingDirectory
    Directory to use for ASA operations. Defaults to current directory.

.PARAMETER OutputDirectory
    Directory where results will be saved. Defaults to .\asa-results

.PARAMETER AsaVersion
    Version of Attack Surface Analyzer to install. Defaults to 2.3.328

.PARAMETER SkipAsaInstall
    Skip installing ASA if it's already installed.

.PARAMETER KeepInstallation
    Keep OpenSSH installed after the test. By default, the MSI will be uninstalled.

.EXAMPLE
    .\Run-AttackSurfaceAnalyzer.ps1 -MsiPath "C:\builds\OpenSSH-Win64.msi"

.EXAMPLE
    .\Run-AttackSurfaceAnalyzer.ps1 -MsiPath ".\OpenSSH-Win64.msi" -KeepInstallation

.EXAMPLE
    .\Run-AttackSurfaceAnalyzer.ps1 -SkipAsaInstall
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$MsiPath,

    [Parameter()]
    [string]$WorkingDirectory = $PWD,

    [Parameter()]
    [string]$OutputDirectory = (Join-Path $PWD "asa-results"),

    [Parameter()]
    [string]$AsaVersion = "2.3.328",

    [Parameter()]
    [switch]$SkipAsaInstall,

    [Parameter()]
    [switch]$KeepInstallation
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Write-Section {
    param([string]$Message)
    Write-Host "=========================================" -ForegroundColor Green
    Write-Host $Message -ForegroundColor Green
    Write-Host "=========================================" -ForegroundColor Green
}

function Write-ErrorSection {
    param([string]$Message)
    Write-Host "=========================================" -ForegroundColor Red
    Write-Host $Message -ForegroundColor Red
    Write-Host "=========================================" -ForegroundColor Red
}

function Test-MsiSignature {
    param(
        [Parameter(Mandatory)]
        [string]$MsiPath
    )

    Write-Host "Verifying MSI signature..." -ForegroundColor Green

    try {
        # Get the digital signature information
        $signature = Get-AuthenticodeSignature -FilePath $MsiPath

        if ($signature.Status -ne 'Valid') {
            Write-Host "MSI signature is not valid. Status: $($signature.Status)" -ForegroundColor Red
            return $false
        }

        # Check if signed by Microsoft Corporation
        $signerCertificate = $signature.SignerCertificate
        if (-not $signerCertificate) {
            Write-Host "No signer certificate found" -ForegroundColor Red
            return $false
        }

        $subject = $signerCertificate.Subject
        Write-Host "Certificate subject: $subject" -ForegroundColor Green

        # Check for Microsoft Corporation in the subject
        if ($subject -notmatch "Microsoft Corporation" -and $subject -notmatch "CN=Microsoft Corporation") {
            Write-Host "MSI is not signed by Microsoft Corporation" -ForegroundColor Red
            Write-Host "Expected: Microsoft Corporation" -ForegroundColor Red
            Write-Host "Found: $subject" -ForegroundColor Red
            return $false
        }

        # Check certificate validity
        $validFrom = $signerCertificate.NotBefore
        $validTo = $signerCertificate.NotAfter
        $now = Get-Date

        if ($now -lt $validFrom -or $now -gt $validTo) {
            Write-Host "Certificate is not valid for current date" -ForegroundColor Red
            Write-Host "Valid from: $validFrom to: $validTo" -ForegroundColor Red
            return $false
        }

        Write-Host "MSI signature verification passed" -ForegroundColor Green
        Write-Host "Signed by: $($signerCertificate.Subject)" -ForegroundColor Green
        Write-Host "Valid from: $validFrom to: $validTo" -ForegroundColor Green

        return $true
    }
    catch {
        Write-Host "Error verifying MSI signature: $_" -ForegroundColor Red
        return $false
    }
}

try {
    # Validate running as Administrator
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        throw "This script must be run as Administrator"
    }

    # Find MSI file if not specified
    if (-not $MsiPath) {
        Write-Host "MSI path not specified, searching for *.msi in current directory..." -ForegroundColor Yellow
        $msiFiles = Get-ChildItem -Path $WorkingDirectory -Filter "*.msi" -File
        if ($msiFiles.Count -eq 0) {
            throw "No MSI files found in $WorkingDirectory. Please specify -MsiPath parameter."
        }
        if ($msiFiles.Count -gt 1) {
            Write-Host "Multiple MSI files found:" -ForegroundColor Yellow
            $msiFiles | ForEach-Object { Write-Host "  - $($_.Name)" }
            $MsiPath = $msiFiles[0].FullName
            Write-Host "Using first MSI: $($MsiPath)" -ForegroundColor Yellow
        } else {
            $MsiPath = $msiFiles[0].FullName
            Write-Host "Found MSI: $MsiPath" -ForegroundColor Green
        }
    }

    # Validate MSI exists
    if (-not (Test-Path $MsiPath)) {
        throw "MSI file not found: $MsiPath"
    }
    $MsiPath = Resolve-Path $MsiPath
    Write-Host "Using MSI: $MsiPath" -ForegroundColor Cyan

    # Verify MSI signature
    if (-not (Test-MsiSignature -MsiPath $MsiPath)) {
        Write-Host "MSI signature verification failed. Only official signed PowerShell MSIs are supported." -ForegroundColor Red
        Write-Host "Please download an official PowerShell MSI from: https://github.com/PowerShell/PowerShell/releases" -ForegroundColor Red
        exit 1
    }

    # Create output directory
    if (-not (Test-Path $OutputDirectory)) {
        Write-Host "Creating output directory: $OutputDirectory"
        New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    }
    $OutputDirectory = Resolve-Path $OutputDirectory

    # Change to working directory
    Set-Location $WorkingDirectory

    # Check for .NET 9 SDK
    Write-Section "Checking for .NET 9 SDK..."

    $dotnetCommand = Get-Command dotnet -ErrorAction SilentlyContinue
    $hasDotnet9 = $false

    if ($dotnetCommand) {
        Write-Host "dotnet found at: $($dotnetCommand.Source)" -ForegroundColor Cyan

        # Get installed SDKs
        $dotnetSdks = dotnet --list-sdks 2>$null
        if ($dotnetSdks) {
            Write-Host "Installed .NET SDKs:" -ForegroundColor Cyan
            $dotnetSdks | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }

            # Check for .NET 9.x SDK
            $hasDotnet9 = $dotnetSdks | Where-Object { $_ -match '^9\.' }
        }
    }

    if (-not $hasDotnet9) {
        Write-Host ""
        Write-Host ".NET 9 SDK is required but not found!" -ForegroundColor Yellow
        Write-Host "Please install .NET 9 SDK manually from:" -ForegroundColor Yellow
        Write-Host "  https://dotnet.microsoft.com/download/dotnet/9.0" -ForegroundColor Cyan
        Write-Host ""
        throw ".NET 9 SDK is not installed"
    } else {
        Write-Host "✓ .NET 9 SDK is installed" -ForegroundColor Green
        $hasDotnet9 | ForEach-Object { Write-Host "  Using: $_" -ForegroundColor Green }
    }

    # Install Attack Surface Analyzer
    if (-not $SkipAsaInstall) {
        Write-Section "Installing Attack Surface Analyzer CLI..."
        Write-Host "Version: $AsaVersion"

        # Check if already installed
        $asaInstalled = $null
        try {
            $asaInstalled = & dotnet tool list -g | Select-String "microsoft.cst.attacksurfaceanalyzer.cli"
        } catch {
            # dotnet not found or tool not installed
        }

        if ($asaInstalled) {
            Write-Host "ASA is already installed. Updating to version $AsaVersion..." -ForegroundColor Yellow
            dotnet tool update -g Microsoft.CST.AttackSurfaceAnalyzer.CLI --version $AsaVersion
        } else {
            dotnet tool install -g Microsoft.CST.AttackSurfaceAnalyzer.CLI --version $AsaVersion
        }

        if ($LASTEXITCODE -ne 0) {
            throw "Failed to install Attack Surface Analyzer"
        }

        # Ensure ASA is in PATH
        $dotnetToolsPath = Join-Path $env:USERPROFILE ".dotnet\tools"
        if ($env:PATH -notlike "*$dotnetToolsPath*") {
            $env:PATH += ";$dotnetToolsPath"
            Write-Host "Added .NET tools to PATH for this session" -ForegroundColor Yellow
        }

        # Verify ASA is available
        $asaCommand = Get-Command asa -ErrorAction SilentlyContinue
        if (-not $asaCommand) {
            throw "ASA command not found in PATH after installation. You may need to restart your PowerShell session."
        }

        Write-Host "Attack Surface Analyzer installed successfully!" -ForegroundColor Green
    } else {
        Write-Host "Skipping ASA installation (using existing installation)" -ForegroundColor Yellow

        # Verify ASA is available
        $asaCommand = Get-Command asa -ErrorAction SilentlyContinue
        if (-not $asaCommand) {
            throw "ASA command not found. Install it first or run without -SkipAsaInstall"
        }
    }

    # Uninstall OpenSSH Client via DISM (optional feature)
    Write-Section "Removing OpenSSH Client (Windows Optional Feature)..."

    # Check if OpenSSH Client is installed
    $opensshClientFeature = Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Client*'

    if ($opensshClientFeature -and $opensshClientFeature.State -eq 'Installed') {
        Write-Host "OpenSSH Client is installed. Removing..." -ForegroundColor Yellow
        Write-Host "Feature: $($opensshClientFeature.Name)" -ForegroundColor Cyan

        # Remove using DISM
        $dismResult = dism /online /Remove-Capability /CapabilityName:$($opensshClientFeature.Name) /NoRestart

        if ($LASTEXITCODE -eq 0) {
            Write-Host "OpenSSH Client removed successfully!" -ForegroundColor Green
        } else {
            Write-Warning "Failed to remove OpenSSH Client (exit code: $LASTEXITCODE)"
            Write-Host "DISM output: $dismResult" -ForegroundColor Yellow
        }
    } else {
        Write-Host "OpenSSH Client is not installed (skipping removal)" -ForegroundColor Gray
    }

    # Also check and remove OpenSSH Server if present
    $opensshServerFeature = Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Server*'

    if ($opensshServerFeature -and $opensshServerFeature.State -eq 'Installed') {
        Write-Host "OpenSSH Server is also installed. Removing..." -ForegroundColor Yellow
        Write-Host "Feature: $($opensshServerFeature.Name)" -ForegroundColor Cyan

        $dismResult = dism /online /Remove-Capability /CapabilityName:$($opensshServerFeature.Name) /NoRestart

        if ($LASTEXITCODE -eq 0) {
            Write-Host "OpenSSH Server removed successfully!" -ForegroundColor Green
        } else {
            Write-Warning "Failed to remove OpenSSH Server (exit code: $LASTEXITCODE)"
        }
    }

    # Take baseline snapshot
    Write-Section "Taking baseline snapshot..."
    asa collect -f -r -u -l -p -F -s --directories 'C:\Program Files\OpenSSH' --runid before
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to take baseline snapshot (exit code: $LASTEXITCODE)"
    }
    Write-Host "Baseline snapshot completed!" -ForegroundColor Green

    # Install OpenSSH MSI
    Write-Section "Installing OpenSSH MSI..."
    Write-Host "MSI file: $MsiPath"
    $installLogPath = Join-Path $OutputDirectory "install.log"
    Write-Host "Install log: $installLogPath"

    $argumentList = "/i `"$MsiPath`" /l*vx `"$installLogPath`" /qn /norestart"
    Write-Host "Running: msiexec.exe $argumentList" -ForegroundColor Cyan

    $msiProcess = Start-Process msiexec.exe -ArgumentList $argumentList -Wait -NoNewWindow -PassThru

    Write-Host "MSI Exit Code: $($msiProcess.ExitCode)"

    if ($msiProcess.ExitCode -notin @(0, 3010)) {
        Write-ErrorSection "MSI installation failed with exit code: $($msiProcess.ExitCode)"

        if (Test-Path $installLogPath) {
            Write-Host "Last 30 lines of install log:" -ForegroundColor Yellow
            Get-Content $installLogPath -Tail 30 | ForEach-Object { Write-Host $_ }
        }

        throw "MSI installation failed. Check install.log for details: $installLogPath"
    }

    # Verify installation
    if (Test-Path 'C:\Program Files\OpenSSH\sshd.exe') {
        Write-Host "OpenSSH installation verified (files found)" -ForegroundColor Green
    } else {
        throw "OpenSSH installation failed - sshd.exe not found in C:\Program Files\OpenSSH"
    }

    # Take post-installation snapshot
    Write-Section "Taking post-installation snapshot..."
    asa collect -f -r -u -l -p -F -s --directories 'C:\Program Files\OpenSSH' --runid after
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to take post-installation snapshot (exit code: $LASTEXITCODE)"
    }
    Write-Host "Post-installation snapshot completed!" -ForegroundColor Green

    # Export comparison results (with database)
    Write-Section "Exporting comparison results to database..."
    asa export-collect --savetodatabase --resultlevels WARNING,ERROR,FATAL --firstrunid before --secondrunid after
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Failed to export results with exit code: $LASTEXITCODE"
    } else {
        Write-Host "Results exported to database successfully!" -ForegroundColor Green
    }

    # Export comparison results (JSON)
    Write-Section "Exporting comparison results to JSON..."
    asa export-collect --readfromsavedcomparisons
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Failed to export JSON results with exit code: $LASTEXITCODE"
    } else {
        Write-Host "JSON results exported successfully!" -ForegroundColor Green
    }

    # Copy results to output directory
    Write-Section "Copying results to output directory..."

    # Find and copy JSON files
    $jsonFiles = Get-ChildItem -Path $WorkingDirectory -Filter "*.json.txt" -ErrorAction SilentlyContinue
    if ($jsonFiles.Count -eq 0) {
        Write-Warning "No JSON.TXT files found - checking for .json files..."
        $jsonFiles = Get-ChildItem -Path $WorkingDirectory -Filter "*.json" -ErrorAction SilentlyContinue
    }

    if ($jsonFiles.Count -eq 0) {
        Write-Warning "No JSON files found - ASA may not have generated results"
    } else {
        foreach ($jsonFile in $jsonFiles) {
            Write-Host "Found JSON file: $($jsonFile.Name)"
            $destPath = Join-Path $OutputDirectory "asa-results.json"
            Copy-Item -Path $jsonFile.FullName -Destination $destPath -Force
            Write-Host "Copied to: $destPath" -ForegroundColor Green
        }
    }

    # Copy SQLite database
    $sqliteDbPath = Join-Path $WorkingDirectory "asa.sqlite"
    if (Test-Path $sqliteDbPath) {
        Write-Host "Copying SQLite database..."
        Copy-Item -Path $sqliteDbPath -Destination $OutputDirectory -Force
        Write-Host "Copied: asa.sqlite" -ForegroundColor Green
    } else {
        Write-Warning "SQLite database (asa.sqlite) not found"
    }

    # Install log was already written to output directory
    if (Test-Path $installLogPath) {
        Write-Host "Install log saved: $installLogPath" -ForegroundColor Green
    }

    # Uninstall OpenSSH if requested
    if (-not $KeepInstallation) {
        Write-Section "Uninstalling OpenSSH MSI..."

        # Find the product code from the log or use MSI path
        $uninstallLogPath = Join-Path $OutputDirectory "uninstall.log"
        $argumentList = "/x `"$MsiPath`" /l*vx `"$uninstallLogPath`" /qn /norestart"
        Write-Host "Running: msiexec.exe $argumentList" -ForegroundColor Cyan

        $uninstallProcess = Start-Process msiexec.exe -ArgumentList $argumentList -Wait -NoNewWindow -PassThru

        if ($uninstallProcess.ExitCode -notin @(0, 3010, 1605)) {  # 1605 = already uninstalled
            Write-Warning "Uninstallation returned exit code: $($uninstallProcess.ExitCode)"
        } else {
            Write-Host "OpenSSH uninstalled successfully" -ForegroundColor Green
        }
    } else {
        Write-Host "Keeping OpenSSH installation as requested" -ForegroundColor Yellow
    }

    # Summary
    Write-Section "Attack Surface Analyzer Test Completed!"
    Write-Host "Results saved to: $OutputDirectory" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Files generated:" -ForegroundColor Cyan
    Get-ChildItem $OutputDirectory | ForEach-Object {
        Write-Host "  - $($_.Name) ($([math]::Round($_.Length/1KB, 2)) KB)" -ForegroundColor White
    }
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor Yellow
    Write-Host "  1. Review asa-results.json for detected changes" -ForegroundColor White
    Write-Host "  2. Check install.log for any installation warnings" -ForegroundColor White
    Write-Host "  3. Run .\Summarize-AsaResults.ps1 to generate a summary report" -ForegroundColor White

} catch {
    Write-ErrorSection "ERROR: $($_.Exception.Message)"
    Write-Host $_.ScriptStackTrace -ForegroundColor Red
    exit 1
}

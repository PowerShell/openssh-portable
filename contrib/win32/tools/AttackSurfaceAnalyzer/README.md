# Attack Surface Analyzer Testing

This directory contains tools for running Attack Surface Analyzer (ASA) tests on OpenSSH MSI installations directly on Windows with PowerShell 7 and .NET 9 SDK installed.

## Overview

Attack Surface Analyzer is a Microsoft tool that helps analyze changes to a system's attack surface. These scripts allow you to run ASA tests directly on Windows to analyze what changes when OpenSSH is installed.

## Files

- **Run-AttackSurfaceAnalyzer.ps1** - PowerShell script to run ASA tests with official MSIs
- **Summarize-AsaResults.ps1** - PowerShell script to analyze and summarize ASA results
- **README.md** - This documentation file

## Prerequisites

- Windows 10/11 or Windows Server
- PowerShell 7
- .NET 9 SDK
- **An official signed OpenSSH MSI file** from a released build

### MSI Requirements

**Important:** This tool now requires an official, digitally signed OpenSSH MSI from Microsoft releases:

- **Must be signed** by Microsoft Corporation
- **Must be from an official release** (downloaded from [OpenSSH Releases](https://github.com/PowerShell/Win32-OpenSSH/releases))
- **Local builds are not supported** - unsigned or development MSIs will be rejected
- The script automatically verifies the digital signature before proceeding

**Where to get official MSIs:**

- Download from: https://github.com/PowerShell/Win32-OpenSSH/releases
- Look for files like: `OpenSSH-Win64-v10.x.x.x.msi`

## Quick Start

### Option 1: Using the PowerShell Script (Recommended)

The script requires an official signed OpenSSH MSI file:

```powershell
# Run ASA test with official MSI (MsiPath is required)
.contrib\win32\tools\AttackSurfaceAnalyzer\Run-AttackSurfaceAnalyzer.ps1 -MsiPath "C:\path\to\OpenSSH-Win64-v10.0.0.0.msi"

# Specify custom output directory for results
.contrib\win32\tools\AttackSurfaceAnalyzer\Run-AttackSurfaceAnalyzer.ps1 -MsiPath ".\OpenSSH-Win64-v10.0.0.0.msi" -OutputPath "C:\asa-results"

# Keep the temporary work directory for debugging
.\tools\AttackSurfaceAnalyzer\Run-AttackSurfaceAnalyzer.ps1 -MsiPath ".\OpenSSH-Win64-v10.0.0.0.msi" -KeepWorkDirectory
```

The script will:

1. **Verify MSI signature** - Ensures the MSI is officially signed by Microsoft Corporation
1. Install the Attack Surface Analyzer
1. Start the Attack Surface Analyzer
1. Take a baseline snapshot
1. Install the OpenSSH MSI
1. Take a post-installation snapshot
1. Export comparison results
1. Copy results back to your specified output directory

**Security Note:** The script will reject any MSI that is not digitally signed by Microsoft Corporation to ensure analysis is performed only on official releases.

## Output Files

The test will generate output files in the `./asa-results/` directory (or your specified `-OutputPath`):

- **`asa.sqlite`** - SQLite database with full analysis data (primary result file)
- **`install.log`** - MSI installation log file
- **`*_summary.json.txt`** - Summary of detected changes (if generated)
- **`*_results.json.txt`** - Detailed results in JSON format (if generated)
- **`*.sarif`** - SARIF format results (if generated, can be viewed in VS Code)

## Analyzing Results

### Using the Summary Script (Recommended)

Use the included summary script to get a comprehensive analysis:

```powershell
# Basic summary of ASA results
.contrib\win32\tools\AttackSurfaceAnalyzer\Summarize-AsaResults.ps1

# Detailed analysis with rule breakdowns
.contrib\win32\tools\AttackSurfaceAnalyzer\Summarize-AsaResults.ps1 -ShowDetails

# Analyze results from a specific location
.contrib\win32\tools\AttackSurfaceAnalyzer\Summarize-AsaResults.ps1 -Path "C:\custom\path\asa-results.json" -ShowDetails
```

The summary script provides:

- **Overall statistics** - Total findings, analysis levels, category breakdowns
- **Rule analysis** - Which security rules were triggered and how often
- **File analysis** - Detailed breakdown of file-related security issues by rule type
- **Category cross-reference** - Shows which rules affect which categories

### Using VS Code

The SARIF files can be opened directly in VS Code with the SARIF Viewer extension to see a formatted view of the findings.

### Using PowerShell

```powershell
# Read the JSON results directly
$results = Get-Content "asa-results\asa-results.json" | ConvertFrom-Json
$results.Results.FILE_CREATED.Count  # Number of files created

# Query the SQLite database (requires SQLite tools)
# Example: List all file changes
# sqlite3 asa.sqlite "SELECT * FROM file_system WHERE change_type != 'NONE'"
```

## Troubleshooting

### MSI Signature Verification Fails

If you get signature verification errors:

- **Ensure you're using an official MSI** from [OpenSSH Releases](https://github.com/PowerShell/Win32-OpenSSH/releases)
- **Do not use local builds** - only signed release MSIs are supported
- **Check certificate validity** - very old MSIs may have expired certificates
- **Verify file integrity** - redownload the MSI if it may be corrupted

### No Results Generated

- Check the install.log file for MSI installation errors
- Run with `-KeepWorkDirectory` to inspect the temporary work directory
- Verify the MSI file is valid and not corrupted

## Advanced Usage

### Parameters

The `Run-AttackSurfaceAnalyzer.ps1` script supports these parameters:

- **`-MsiPath`** (Required) - Path to the official signed OpenSSH MSI file
- **`-WorkingDirectory`** (Optional) - Directory for MSI, if not provided (defaults to current directory)
- **`-OutputDirectory`** (Optional) - Directory for results (defaults to `./asa-results`)
- **`-AsaVersion`** (Optional) - ASA Tool Version (defaults to "2.3.328")
- **`-SkipAsaInstall** (Optional) - Switch to skip ASA Tool install (defaults to false)
- **`-KeepInstallation** (Optional) - Switch to skip MSI uninstall, recommended for debugging only (defaults to false)

### Debugging

To debug issues, keep the MSI install and examine the files:

```powershell
.contrib\win32\tools\AttackSurfaceAnalyzer\Run-AttackSurfaceAnalyzer.ps1 -KeepInstallation

# The script will print the work directory path
# You can then examine:
# - C:\Program Files\OpenSSH - install directory
# - install.log - MSI installation log
# - Any other generated files
```

## Integration with CI/CD

These tools were extracted from the GitHub Actions workflow to allow local testing. If you need to integrate ASA testing back into a CI/CD pipeline, you can use the PowerShell script directly in your pipeline

## More Information

- [Attack Surface Analyzer on GitHub](https://github.com/microsoft/AttackSurfaceAnalyzer)
- [SARIF Documentation](https://sarifweb.azurewebsites.net/)

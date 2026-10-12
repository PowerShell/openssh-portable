---
applyTo: "**/*"
---

# Testing Instructions for AI Agents

## Overview
This document provides comprehensive testing procedures for validating OpenSSH-Portable merges on Windows. Testing should be performed after successful compilation to ensure functionality is preserved.

## Automated Testing with MCP Tools (Recommended)

### Using Test-OpenSSHFunctionality Tool

The repository includes an MCP tool that automates end-to-end functional testing of OpenSSH on Windows.

Use the Test-OpenSSHFunctionality MCP tool:
- **MCP Tool Name**: `mcp_openssh-server_Test_OpenSSHFunctionality`
- **Parameters**:
  - `Configuration` (optional): "Debug" or "Release" (default: "Release")
  - `Architecture` (optional): "x64", "x86", "ARM", "ARM64" (default: "x64")
  - `SkipFirewall` (optional): Skip firewall configuration (default: false)
  - `NoCleanup` (optional): Skip cleanup for debugging (default: false)

**Examples:**
- Run with defaults: (no parameters needed)
- Test with specific configuration: `Configuration="Debug"`, `Architecture="x64"`
- Skip firewall configuration: `SkipFirewall=true`

**What the tool does:**
1. Verifies Administrator privileges
2. Creates a temporary test user with random password
3. Installs and starts the SSH service
4. Configures Windows Firewall (unless -SkipFirewall is used)
5. Tests SSH connection with password authentication
6. Executes "echo hello world" command via SSH
7. Cleans up all resources (user, service, firewall rule)

**Expected output on success:**
```
=== OpenSSH Functionality Test ===
[1/6] Checking Administrator privileges...
✓ Running with Administrator privileges
[2/6] Creating temporary test user...
✓ Created test user: openssh_test_1234
[3/6] Installing SSH service...
✓ SSH service installed successfully
[4/6] Starting SSH service...
✓ SSH service started successfully
[5/6] Configuring Windows Firewall...
✓ Firewall rule created
[6/6] Testing SSH connection...
✓ SSH connection successful
  Command output: hello world

=== Cleanup ===
✓ SSH service uninstalled
✓ Firewall rule removed
✓ Test user removed

=== Test Summary ===
Status: PASSED
```

**The tool returns a structured result object with:**
- `Success`: Boolean indicating overall test success
- `ServiceInstalled`: Whether service installation succeeded
- `ServiceStarted`: Whether service started successfully
- `ConnectionSuccessful`: Whether SSH connection test passed
- `CommandOutput`: Output from the test command
- `TestUser`: Name of the temporary test user created
- `Errors`: Array of any errors encountered
- `Message`: Summary message

## Primary Testing Approach

**Use the automated Test-OpenSSHFunctionality MCP tool for all testing.**

The MCP tool performs comprehensive end-to-end testing including:
- Administrator privilege verification
- Temporary test user creation
- SSH service installation and startup
- Windows Firewall configuration
- SSH connection testing with password authentication
- Command execution verification
- Complete cleanup of all test resources

**MCP Tool Name**: `mcp_openssh-server_Test_OpenSSHFunctionality`

**Parameters**:
- `Configuration` (optional): "Debug" or "Release" (default: "Release")
- `Architecture` (optional): "x64", "x86", "ARM", "ARM64" (default: "x64")
- `SkipFirewall` (optional): Skip firewall configuration (default: false)
- `NoCleanup` (optional): Skip cleanup for debugging (default: false)

**When to use**:
- After successful build to validate functionality
- During merge process at CI checkpoints
- Before creating pull requests
- When debugging SSH connectivity issues

## Full CI Test Suite

For thorough validation (e.g., before submitting a PR or after a significant merge), run the complete CI test suite: unit tests, bash regression tests, and Pester E2E tests.

Reference: https://github.com/PowerShell/Win32-OpenSSH/wiki/Run-OpenSSH-Pester-Tests

### Using the Invoke-OpenSSHTests MCP Tool (Recommended)

Use the Invoke-OpenSSHTests MCP tool:
- **MCP Tool Name**: `mcp_openssh-server_Invoke_OpenSSHTests`
- **Parameters**:
  - `Configuration` (optional): "Debug" or "Release" (default: "Release")
  - `Architecture` (optional): "x64", "x86", "ARM", "ARM64" (default: "x64")
  - `TestSuite` (optional): "All", "Unit", "Bash", "E2E" — one or more values (default: "All")
  - `BashTestFilePath` (optional): Absolute path to a single `.sh` test file for targeted bash testing (e.g., `C:\repos\openssh-portable\regress\banner.sh`)
  - `BashShellPath` (optional): Path to `sh.exe` — auto-detected from common Cygwin locations if omitted
  - `NoCleanup` (optional): Skip `Clear-OpenSSHTestEnvironment` after the run (default: false)
  - `SkipSetup` (optional): Skip `Set-OpenSSHTestEnvironment` when environment is already configured (default: false)

**The tool returns a structured result with:**
- `Success`: Overall pass/fail
- `UnitTestsPassed`, `BashTestsPassed`, `E2ETestsPassed`: Per-suite results (`$true`/`$false`/`$null` if not run)
- `UnitTestOutput`, `BashTestOutput`, `E2ETestOutput`: Captured output for each suite
- `Errors`: Array of failure messages
- `Warnings`: Known gotchas and environment notes
- `Message`: Summary

**Examples:**
- Run full suite: (no parameters needed)
- Run only E2E tests: `TestSuite="E2E"`
- Run a single bash test: `TestSuite="Bash"`, `BashTestFilePath="C:\repos\openssh-portable\regress\banner.sh"`

### Manually Running the Full CI Suite

Binaries are expected at `C:\repos\openssh-portable\bin\{Architecture}\{Configuration}`.

```pwsh
# 1. Import the test helper module
Import-Module C:\repos\openssh-portable\contrib\win32\openssh\OpenSSHTestHelper.psm1 -Force

# 2. Configure the test environment (installs test accounts, sshd test service, etc.)
#    This modifies known_hosts and ssh_config; run Clear-OpenSSHTestEnvironment to undo.
Set-OpenSSHTestEnvironment -OpenSSHBinPath "C:\repos\openssh-portable\bin\x64\Release" -Confirm:$false

# 3. Run unit tests (unittest-*.exe binaries in the bin folder)
Invoke-OpenSSHUnitTest

# 4. Run bash regression tests (requires Cygwin sh.exe)
Invoke-OpenSSHBashTests

# 5. Run Pester E2E tests
Invoke-OpenSSHE2ETest

# 6. Clean up test accounts, service, and ssh config changes
Clear-OpenSSHTestEnvironment
```

### Running a Single Bash Test

Use `bash_tests_iterator.ps1` to run one bash test file in isolation:

```pwsh
.\contrib\win32\openssh\bash_tests_iterator.ps1 `
    -OpenSSHBinPath "C:\repos\openssh-portable\bin\x64\Release" `
    -BashTestsPath  "C:\repos\openssh-portable\regress" `
    -ShellPath      "C:\cygwin64\bin\sh.exe" `
    -TestFilePath   "C:\repos\openssh-portable\regress\banner.sh"
```

### Known CI Test Gotchas

**`cfginclude.sh` — wrong PowerShell executable:**
The test calls `powershell.exe` directly. When running under `pwsh.exe`, the test will fail unless the file is edited to replace `powershell.exe` with `pwsh.exe`.
See: https://github.com/PowerShell/PowerShell/issues/18530#issuecomment-1325691850

**WSMan / Port Forwarding tests — disabled on some VMs:**
The WSMan and port-forwarding Pester tests may fail on VMs where these Windows features are disabled by default. Options:
- Enable the features: turn on "Windows Remote Management" and ensure port-forward firewall rules are allowed.
- Skip the affected test files (e.g., `PortForwarding.Tests.ps1`) when running `Invoke-OpenSSHE2ETest` for routine validation.

**Pester version requirement:**
The E2E tests require **Pester version < 5**. The helper module will attempt to install Pester 3.4.6 via chocolatey if a compatible version is not found.

**Cygwin required for bash tests:**
`Invoke-OpenSSHBashTests` auto-detects `sh.exe` at `%SystemDrive%\cygwin64\bin\sh.exe`, `%SystemDrive%\cygwin\bin\sh.exe`, or `%SystemDrive%\tools\cygwin\bin\sh.exe`. If none is found it installs Cygwin via chocolatey. Provide `-BashShellPath` to the MCP tool to override.

## Manual Testing Procedures (For Troubleshooting Only)

If the automated MCP tool fails and you need to troubleshoot specific issues manually, follow these procedures:

### Prerequisites Check
```pwsh
# Verify Windows version compatibility
Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion

# Check if running as Administrator - REQUIRED for service installation
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{
    Write-Error "Administrative privileges are REQUIRED for service installation and testing."
    Write-Host "Please restart PowerShell or VS Code as Administrator and try again." -ForegroundColor Yellow
    Write-Host "To elevate: Right-click PowerShell/VS Code -> 'Run as Administrator'" -ForegroundColor Yellow
    exit 1
}

Write-Host "✓ Running with Administrator privileges" -ForegroundColor Green

# Verify build artifacts exist
$buildPath = ".\contrib\win32\openssh\x64\Release"
if (-not (Test-Path "$buildPath\sshd.exe") -or -not (Test-Path "$buildPath\ssh.exe")) {
    Write-Error "Build artifacts not found. Please build the project first."
    exit 1
}

Write-Host "✓ Build artifacts verified" -ForegroundColor Green
```

### Test Environment Setup

### Service Installation and Configuration

#### Step 1: Install SSH Service
```pwsh
# Navigate to build directory
cd .\contrib\win32\openssh\x64\Release

# Install SSH server service with PowerShell script
.\install-sshd.ps1

# Verify service installation
Get-Service sshd -ErrorAction SilentlyContinue | Select-Object Name, Status, StartType
```

#### Step 2: Configure SSH Service
```pwsh
# Start SSH service
Start-Service sshd

# Verify service is running
Get-Service sshd | Select-Object Name, Status
```

#### Step 3: Configure Windows Firewall (if needed)
```pwsh
# Allow SSH through Windows Firewall
New-NetFirewallRule -DisplayName "SSH Server (sshd)" -Direction Inbound -Port 22 -Protocol TCP -Action Allow -ErrorAction SilentlyContinue
```

## Basic Functionality Tests

### Test 1: SSH Client Connection
```pwsh
# Test local connection (most basic test)
$username = $env:USERNAME
$hostname = "localhost"

Write-Host "Testing SSH connection: ssh $username@$hostname"

# Basic connection test
.\ssh.exe $username@$hostname "echo 'SSH connection successful'"
```

**Expected Output:**
```
SSH connection successful
```

## Error Diagnosis and Troubleshooting

### Run SSH Server in Debug Mode
```pwsh
# Enable SSH daemon debug logging
Stop-Service sshd
.\sshd.exe -ddd

# In another terminal, test connection with verbose client logging
.\ssh.exe -vvv $username@$hostname
```

### Common Issues and Solutions

#### Issue 1: Service Won't Start
**Symptoms:**
- Service fails to start
- Event log shows service errors

**Diagnosis:**
```pwsh
# Check event logs
Get-WinEvent -LogName System | Where-Object {$_.ProviderName -eq "Service Control Manager" -and $_.Id -eq 7034} | Select-Object -First 5

# Check sshd configuration
.\sshd.exe -T
```

**Common Solutions:**
- Verify configuration file syntax

#### Issue 2: Connection Timeouts
**Symptoms:**
- SSH client hangs
- Connection timeout errors

**Diagnosis:**
```pwsh
# Check network connectivity
Test-NetConnection -ComputerName localhost -Port 22

# Check Windows Firewall rules
Get-NetFirewallRule | Where-Object {$_.DisplayName -like "*SSH*"}
```

## Success Criteria

**Testing is successful when:**
- [ ] All expected executables are present after build (verified by Test-OpenSSHBuild MCP tool)
- [ ] SSH service installs and starts without errors
- [ ] SSH validation succeeds via password authentication
- [ ] Test command executes successfully via SSH connection
- [ ] All resources cleaned up properly after testing


## AI Agent Guidelines

1. **Use automated testing tools** whenever possible - use the Test-OpenSSHFunctionality MCP tool over manual procedures
2. **Run tests incrementally** during the merge process, not just at the end
3. **Document any test failures** and their resolutions in commit messages
4. **Pay special attention to Windows-specific functionality** that might be affected by upstream changes
5. **Always verify cleanup** - ensure test users, services, and firewall rules are removed
6. **Report any new functionality** that needs additional testing procedures

### Recommended Testing Workflow for AI Agents

1. **After successful build**, run the automated functionality test:
   - **MCP Tool Name**: `mcp_openssh-server_Test_OpenSSHFunctionality`
   - **Parameters**: (use defaults)

2. **If test passes**, the merge is validated for basic SSH functionality

3. **If test fails**, use manual procedures and debug mode to diagnose issues

4. **For full CI validation** (e.g., before creating a PR), run the complete test suite:
   - **MCP Tool Name**: `mcp_openssh-server_Invoke_OpenSSHTests`
   - **Parameters**: (use defaults to run all suites)
   - If a specific suite fails, re-run it in isolation using `TestSuite="Unit"`, `TestSuite="Bash"`, or `TestSuite="E2E"`
   - For a single failing bash test: `TestSuite="Bash"`, `BashTestFilePath="<path-to-test.sh>"`

5. **Document results** in commit message or merge documentation

## Manual Test Environment Cleanup

If you ran manual tests instead of using the automated tool:

```pwsh
# Clean up test environment
Stop-Service sshd -ErrorAction SilentlyContinue
cd .\contrib\win32\openssh\x64\Release
.\uninstall-sshd.ps1

# Remove firewall rule
Remove-NetFirewallRule -DisplayName "SSH Server (sshd)" -ErrorAction SilentlyContinue

# Remove any test users manually created
Remove-LocalUser -Name "test_username" -ErrorAction SilentlyContinue

Write-Host "Test environment cleaned up"
```

**Note:** The automated Test-OpenSSHFunctionality.ps1 tool handles all cleanup automatically, even on failure.

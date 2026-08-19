---
applyTo: "**/*"
---

# Build Instructions for AI Agents

## Overview
This document provides comprehensive build instructions for OpenSSH-Portable on Windows, specifically tailored for AI agents performing upstream merges.

## Prerequisites Verification

### Check Required Tools
```pwsh
# Verify PowerShell version
$PSVersionTable.PSVersion

# Verify Visual Studio installation
Get-ChildItem "C:\Program Files*\Microsoft Visual Studio\*\*\MSBuild\Current\Bin\msbuild.exe"

# Verify Windows SDK
Get-ChildItem "C:\Program Files*\Windows Kits\10\bin" -Directory

# Verify Git
git --version
```

### vcpkg Dependencies
The build links against vendored libraries (`libressl`, `libfido2`, `libcbor`,
`zlib`) installed via vcpkg. The build will **fail** if
`contrib/win32/openssh/vcpkg_installed/<triplet>-custom/` is missing.

To install (or refresh) dependencies:
```pwsh
.\.github\tools\Install-VcpkgDependencies.ps1 -Bootstrap
```

See [setup.instructions.md](./setup.instructions.md) Step 6 for first-time
setup and [vcpkg.instructions.md](./vcpkg.instructions.md) for the full
reference (overlay ports, custom triplets, version-bump workflow).

## Build Process

### Using MCP Build Tools (Recommended)

The repository includes MCP tools that automate the build and error analysis process.

#### Build
Use the Start-OpenSSHBuild MCP tool:
- **MCP Tool Name**: `mcp_openssh-server_Start_OpenSSHBuild`
- **Parameters**:
  - `Configuration` (optional): "Debug" or "Release" (default: "Release")
  - `Architecture` (optional): "x64", "x86", "ARM", "ARM64" (default: the host machine's architecture, auto-detected; a mismatched value is rejected unless `AllowArchMismatch` is set)
  - `Clean` (optional): Perform clean build (default: false)

**Examples:**
- Incremental build: `Configuration="Release"` (Architecture defaults to the host machine's architecture)
- Clean build: `Configuration="Release"`, `Clean=true`

#### Test Existing Build (on failure only)
Use the Test-OpenSSHBuild MCP tool when a build fails:
- **MCP Tool Name**: `mcp_openssh-server_Test_OpenSSHBuild`
- **Parameters**: `Configuration="Release"` (Architecture defaults to the host machine's architecture; only pass it when intentionally cross-building)

## Compiler Warning Policy

### Overview
All new compiler warnings introduced during the merge process must be reported to users and require approval before proceeding. This ensures code quality is maintained and potential issues are not overlooked.

### Baseline Establishment
1. **Before starting the merge**, establish a baseline warning count:
   - Run Test-OpenSSHBuild on the current branch (before any merge commits)
   - Document the total warning count and warning categories
   - Store this as the baseline for comparison

2. **After each build during merge**, compare warnings against baseline:
   - Run Test-OpenSSHBuild after every successful build (not just failures)
   - Compare current warning count to baseline
   - Identify any new warnings introduced

### Warning Categorization
Attempt to categorize warnings to help users make informed decisions:

**Common Warning Categories:**
- **Deprecated APIs**: Use of functions/APIs marked as deprecated
- **Type Conversions**: Implicit type conversions that may lose data
- **Unused Variables/Functions**: Declared but unused code elements
- **Potential Bugs**: Logic issues that may cause runtime problems
- **Security-Related**: Potential security vulnerabilities (buffer overruns, etc.)
- **Platform-Specific**: Windows-specific compatibility warnings

**Note:** Categorization helps users make decisions, but **all new warnings require user approval regardless of predicted severity**.

### User Approval Requirement
**Critical Rule**: No threshold - every new warning requires user input.

1. **When new warnings are detected:**
   - Report warning count delta (baseline vs current)
   - List each new warning with:
     - File and line number
     - Warning code and message
     - Attempted category classification
   - Request user decision: fix warnings or proceed as-is

2. **User must explicitly approve:**
   - Fixing warnings before continuing
   - Proceeding with warnings (acknowledging they will remain)
   - Do NOT automatically proceed if new warnings appear

3. **Update baseline if user approves proceeding:**
   - If user approves proceeding with new warnings, update baseline
   - This prevents re-reporting the same warnings in subsequent batches

## Compilation Error Resolution

### Common Error Categories

#### 1. Missing Preprocessor Definitions
**Symptoms:**
```
error C2065: 'SOME_DEFINE': undeclared identifier
```

**Resolution:**
```pwsh
# Edit config.h.vs file
notepad .\contrib\win32\openssh\config.h.vs

# Add missing definitions (example)
#define SOME_DEFINE 1
```

#### 2. Missing Windows Equivalents
**Symptoms:**
```
error C3861: 'fork': identifier not found
error C3861: 'signal': identifier not found
```

**Resolution Pattern:**
```c
// In source file, add Windows compatibility
#ifdef WINDOWS
    // Use Windows equivalent or win32compat function
    HANDLE process = CreateProcess(...);
#else
    // Original Unix code
    pid_t pid = fork();
#endif
```

#### 3. Build System Inconsistencies
**Symptoms:**
```
error MSB3073: The command exited with code 1
fatal error C1083: Cannot open source file: 'newfile.c'
```

**AI Agent Resolution Process:**
1. **Check Makefile changes:**
   ```pwsh
   # MCP Tool: mcp_openssh-server_Invoke_Git
   # Operation="Diff", Range="upstream-pwsh/latestw_all..upstream/<version>", Path="Makefile.in"
   ```

2. **Identify new/removed source files:**
   ```bash
   # Look for patterns like:
   # ssh_SOURCES = ssh.c readconf.c clientloop.c sshtty.c \
   #               sshconnect.c sshconnect2.c mux.c newfile.c
   ```

3. **Update Visual Studio projects:**
   ```xml
   <!-- Add to appropriate .vcxproj file -->
   <ClCompile Include="newfile.c" />
   ```
   
   **Important:** Visual Studio project files (`.vcxproj`) use Windows-style line endings (`\r\n`). When programmatically adding lines to these files, ensure you use `\r\n` instead of just `\n` to maintain consistency with the existing file format. This prevents Git from showing the entire file as changed.

4. **Update solution if new binaries added:**
   ```
   # Check for new programs in Makefile:
   # bin_PROGRAMS = ssh sshd ssh-add ssh-keygen ssh-keyscan ssh-copy-id scp sftp sftp-server ssh-pkcs11-helper ssh-sk-helper ssh-agent new-binary
   ```

### Step-by-Step Error Resolution

#### AI Agent Workflow:
1. **Run the build**
   - Use: **Start-OpenSSHBuild** — `mcp_openssh-server_Start_OpenSSHBuild` with `Configuration` and `Architecture`.
2. **If build succeeded**, skip log parsing and proceed.
3. **If build failed**, **parse errors** using **Test-OpenSSHBuild** — `mcp_openssh-server_Test_OpenSSHBuild`.
4. **Categorize error types** (preprocessor, Windows compatibility, build system).
5. **Apply appropriate resolution strategy** (see error categories above) and **rebuild** with Start-OpenSSHBuild.
6. **CRITICAL: Before committing, restore paths.targets**:
   ```pwsh
   # MCP Tool: mcp_openssh-server_Invoke_Git
   # Operation="Checkout", Target=".\contrib\win32\openssh\paths.targets"
   ```
7. **Commit fixes with detailed message** (only actual code changes, not paths.targets).

#### Reading Build Logs and Errors (on failure only)
Use the **Test-OpenSSHBuild** MCP tool to read build logs and parse errors **only when the build fails**:
- **MCP Tool Name**: `mcp_openssh-server_Test_OpenSSHBuild`
- **Parameters**: `Configuration="Release"`, `Architecture="x64"`

**Why use this tool:**
- Automatically locates and parses the build log file
- Provides structured error output with file paths, codes, and messages
- Groups errors and warnings for easier analysis
- Works reliably in MCP context where direct file reading may not be available

**DO NOT** attempt to read log files directly with `Get-Content` or similar commands.
**DO NOT** try to locate log files manually.

### Build Tools Invocation Policy

- Use `Start-OpenSSHBuild.ps1` to run the build for each chunk/batch.
- **ALWAYS invoke `Test-OpenSSHBuild.ps1` after every build** (success or failure):
  - On build failure: Parse errors and warnings to fix issues
  - On build success: Parse warnings to compare against baseline
- Compare warning count against established baseline
- If new warnings detected, report to user and request approval before proceeding
- Do NOT skip `Test-OpenSSHBuild.ps1` even when build succeeds - warning checks are mandatory.

#### Alternative: Direct MSBuild (Terminal Only)
Only use this when running directly in a terminal (not via MCP):
```pwsh
& "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\MSBuild.exe" .\contrib\win32\openssh\Win32-OpenSSH.sln /p:Configuration=Release /p:Platform=x64 /v:detailed
```

### Important Note: paths.targets File Modification

**The build process automatically modifies `.\contrib\win32\openssh\paths.targets`** to update SDK version paths based on the currently installed Windows SDK. This is normal and expected behavior.

**Before committing any changes:**
```pwsh
# Check if paths.targets was modified by the build:
# MCP Tool: mcp_openssh-server_Invoke_Git
# Operation="Status"
# Check if paths.targets appears in result.ModifiedFiles

# If it shows as modified, restore it to a clean state:
# MCP Tool: mcp_openssh-server_Invoke_Git
# Operation="Checkout", Target=".\contrib\win32\openssh\paths.targets"
```

**Why this happens:**
- MSBuild automatically updates SDK paths to match your local environment
- These changes are environment-specific and should not be committed
- The file will be modified on every build

**AI Agent Workflow (CRITICAL):**
1. **ALWAYS restore paths.targets before committing**:
   ```pwsh
   # This MUST be done before every commit
   # MCP Tool: mcp_openssh-server_Invoke_Git
   # Operation="Checkout", Target=".\contrib\win32\openssh\paths.targets"
   ```
2. Only commit actual code changes, not build-generated path updates
3. Verify with Invoke-Git `Operation="Status"` that paths.targets is not in `ModifiedFiles` before committing

## Project File Management

### Understanding the Project Structure
```
contrib\win32\openssh\
├── Win32-OpenSSH.sln          # Main solution file
├── libssh.vcxproj             # Core SSH library
├── ssh.vcxproj                # SSH client
├── sshd.vcxproj               # SSH server listener handling
├── sshd-auth.vcxproj          # SSH server authentication handling
├── sshd-session.vcxproj       # SSH server session handling
├── ssh-add.vcxproj            # Key agent utility
├── ssh-agent.vcxproj          # Authentication agent
├── ssh-keygen.vcxproj         # Key generation utility
├── ssh-keyscan.vcxproj        # Key scanning utility
└── ssh-pkcs11-helper.vcxproj  # SSH PKCS11 helper
└── ssh-shell-host.vcxproj     # SSH shell host
└── ssh-sk-helper.vcxproj      # SSH SK helper
├── scp.vcxproj                # Secure copy
├── sftp.vcxproj               # Secure file transfer client
└── sftp-server.vcxproj        # Secure file transfer server
```

### Adding New Projects (AI Agent Process)
1. **Identify new binary in Makefile:**
   ```bash
   grep "bin_PROGRAMS\|sbin_PROGRAMS" Makefile.in
   ```

2. **Check Windows applicability:**
   ```bash
   # Skip Unix-only binaries like ssh-keysign
   # Include utilities that work on Windows
   ```

3. **Create new project file:**
   ```pwsh
   # Copy existing similar project
   Copy-Item ssh.vcxproj ssh-newutil.vcxproj
   ```

4. **Update project references:**
   ```xml
   <!-- Update project name, output file, and source files -->
   <PropertyGroup>
     <ProjectName>ssh-newutil</ProjectName>
     <TargetName>ssh-newutil</TargetName>
   </PropertyGroup>
   ```

5. **Add to solution:**
   ```
   # Edit Win32-OpenSSH.sln to include new project
   ```

**Important Note on Line Endings:**
Both `.vcxproj` and `.sln` files use Windows-style line endings (`\r\n`). When programmatically modifying these files:
- Use `\r\n` instead of `\n` when inserting new lines
- Maintain consistent line endings to avoid Git showing spurious changes
- Example in PowerShell: `$newLine = "<ClCompile Include=`"newfile.c`" />`r`n"`
- Example in Python: `new_line = "<ClCompile Include=\"newfile.c\" />\r\n"`

## Validation and Testing

### Build Verification Using MCP Tools
```pwsh
Use the Start-OpenSSHBuild MCP tool (recommended):
- **MCP Tool Name**: `mcp_openssh-server_Start_OpenSSHBuild`
- **Parameters**: `Configuration="Release"`, `Architecture="x64"`

If the build fails, parse errors with:
- **MCP Tool Name**: `mcp_openssh-server_Test_OpenSSHBuild`
- **Parameters**: `Configuration="Release"`, `Architecture="x64"`
**Expected Output (on failure):**
- Build failure status
- Parsed errors and warnings
- Build log location
```
**Expected Artifacts (14 executables):**
- ssh.exe, sshd.exe, sshd-auth.exe, sshd-session.exe
- ssh-agent.exe, ssh-add.exe, ssh-keygen.exe, ssh-keyscan.exe
- scp.exe, sftp.exe, sftp-server.exe
- ssh-pkcs11-helper.exe, ssh-shellhost.exe, ssh-sk-helper.exe

### Quick Functionality Test
```pwsh
# Verify version reporting
& ".\contrib\win32\openssh\x64\Release\ssh.exe" -V
```

## Troubleshooting Guide

### Build Helper Module Issues
```pwsh
# Force reload module
Remove-Module OpenSSHBuildHelper -Force -ErrorAction SilentlyContinue
Import-Module .\contrib\win32\openssh\OpenSSHBuildHelper.psm1 -Force
```

### Path and Environment Issues
```pwsh
# Verify Visual Studio environment
& "${env:ProgramFiles}\Microsoft Visual Studio\2022\Enterprise\Common7\Tools\VsDevCmd.bat"

# Check MSBuild path
where.exe msbuild
```

### Permission Issues
```pwsh
# Ensure running as Administrator if needed
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{
    Write-Warning "Build may require Administrator privileges"
}
```

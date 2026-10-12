---
applyTo: "**/*"
---

# Repository Structure and Windows Compatibility Layer

## Overview

This repository is a **downstream fork** of [openssh/openssh-portable](https://github.com/openssh/openssh-portable) maintained by the PowerShell team to provide Windows compatibility for OpenSSH.

## Repository Organization

### Upstream Code (Base Directory)
The root of the repository contains the upstream OpenSSH code:
- Core SSH implementation files (`.c`, `.h`)
- Unix/POSIX-focused codebase
- Maintained to stay close to upstream for easier merging

### Windows Compatibility Layer

#### Primary Windows Code Locations

**1. `.\contrib\win32\openssh\`**
- Visual Studio project files (`.vcxproj`, `.sln`)
- Windows-specific build configuration
- Project organization for Windows builds

**2. `.\contrib\win32\win32compat\`**
- Windows compatibility implementation layer
- Provides Windows equivalents for POSIX functions
- Contains platform abstraction code

#### Compatibility Strategy

The Windows port follows a **separation of concerns** approach to minimize divergence from upstream:

1. **Preferred: Compatibility Layer**
   - Windows-specific implementations prefixed with `w32_`
   - Example: `w32_mkdir()`, `w32_stat()`, `w32_open()`
   - Macro redefinition in headers to redirect POSIX calls
   - Located in `contrib\win32\win32compat\`

2. **When Necessary: Conditional Compilation**
   - Use `#ifdef WINDOWS` blocks in upstream files
   - Keep Windows-specific code minimal and well-documented
   - Only when compatibility layer approach is insufficient

**Example Pattern:**
```c
// In win32compat header (e.g., sys/stat.h)
int w32_mkdir(const char *pathname, unsigned short mode);
#undef mkdir  // Clear any existing definition
#define mkdir w32_mkdir  // Redirect to Windows implementation

// In upstream code - no changes needed
mkdir(path, 0700);  // Automatically uses w32_mkdir on Windows
```

## Special Case: SSH-Agent

### Important: Separate Windows Implementation

The **ssh-agent** is a special case that **does not follow** the standard compatibility layer pattern:

- **Windows ssh-agent location**: `.\contrib\win32\win32compat\ssh-agent\`
- Built from **completely separate code** from the upstream ssh-agent
- Uses Windows-native APIs and service architecture

### Implications for Upstream Merges

When merging changes to `ssh-agent.c` or related agent files from upstream:

1. **Simple changes** (bug fixes, small improvements):
   - Manually port functionality to `contrib\win32\win32compat\ssh-agent\`
   - Adapt logic to Windows implementation

2. **Complex changes** (architectural changes, new features):
   - Document as TODO in merge commit
   - Flag for Windows team review
   - May require significant redesign work

3. **New files** (additional agent-related source files):
   - **Not all new upstream files need to be ported** to the Windows ssh-agent
   - Evaluate whether the functionality is relevant to the Windows implementation
   - If not applicable, document the decision and skip porting

4. **Do NOT**:
   - Directly apply upstream ssh-agent patches to Windows version
   - Assume one-to-one code correspondence
   - Merge without understanding Windows implementation differences

### Other Binaries

All other OpenSSH binaries (ssh, sshd, scp, sftp, etc.) follow the standard compatibility layer approach and can be merged more directly from upstream with appropriate Windows compatibility adjustments.

## Best Practices for Merging

### 1. Minimize Direct Modifications
- Prefer extending compatibility layer over adding `#ifdef WINDOWS` blocks
- Keep upstream code as clean as possible

### 2. Document Windows-Specific Changes
- Clear comments explaining why Windows needs different approach
- Reference related compatibility layer functions

### 3. Test on Windows
- Always build and test on Windows after merging
- Use provided automation tools in `.github\tools\`
- Verify both functionality and build process

### 4. Upstream Alignment
- Track which upstream commits have been merged
- Maintain clear merge history
- Document any deviations from upstream behavior

## Key Files to Know

### Build System
- `contrib\win32\openssh\Win32-OpenSSH.sln` - Main Visual Studio solution
- `contrib\win32\openssh\*.vcxproj` - Individual project files
- `contrib\win32\openssh\OpenSSHBuildHelper.psm1` - Build helper module

### Compatibility Headers
- `contrib\win32\win32compat\inc\sys\*` - POSIX header replacements
- `contrib\win32\win32compat\inc\*.h` - Windows compatibility declarations
- `contrib\win32\win32compat\inc\crtheaders.h` - CRT header mappings

### Compatibility Implementation
- `contrib\win32\win32compat\*.c` - Windows function implementations
- `contrib\win32\win32compat\ssh-agent\*` - Separate Windows ssh-agent

## Getting Help

- **Build issues**: See [build.instructions.md](./build.instructions.md)
- **Merge conflicts**: See [merge/merge-details.instructions.md](./merge/merge-details.instructions.md)
- **Testing**: See [testing.instructions.md](./testing.instructions.md)

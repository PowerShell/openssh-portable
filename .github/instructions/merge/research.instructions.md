---
applyTo: "**/*"
---

# References for AI Agents

## AI Agent Instructions
This file provides reference materials and links that AI agents should review before and during the merge process. Each section contains specific guidance on what to look for and how to use the information.

## Upstream Release Notes
**URL:** https://www.openssh.com/releasenotes.html

**AI Agent Task:**
1. Navigate to the release notes page
2. Focus ONLY on the latest release section (at the top of the page)
3. Look for these specific types of changes that require Windows compatibility work:
   - Signal handling modifications
   - File handling changes
   - Inter-process communication (IPC) updates
   - New system calls or POSIX-specific functionality
   - Changes to build system or dependencies
   - Security fixes that might affect Windows implementations

**Example Analysis:**
```
If release notes mention "Added support for new signal handling in sshd",
the AI should flag this as requiring Windows event mechanism adaptation.
```

## Previous Merge Pull Requests

**AI Agent Task:** Review these PRs in order of recency for conflict resolution patterns:

1. **Most Recent:** https://github.com/PowerShell/openssh-portable/pull/737
2. https://github.com/PowerShell/openssh-portable/pull/703
3. https://github.com/PowerShell/openssh-portable/pull/684
4. https://github.com/PowerShell/openssh-portable/pull/657
5. https://github.com/PowerShell/openssh-portable/pull/626
6. https://github.com/PowerShell/openssh-portable/pull/577
7. https://github.com/PowerShell/openssh-portable/pull/504
8. https://github.com/PowerShell/openssh-portable/pull/351

**What to Extract from Each PR:**
1. **Commit Messages:** Look for commits added AFTER the initial merge commit
2. **File Patterns:** Note which files commonly have conflicts
3. **Resolution Strategies:** Document how specific types of conflicts were resolved
4. **Build Fixes:** Note compilation issues and their solutions
5. **Test Failures:** Understand common CI/test failures and fixes

**Key Contributors to Follow:**
- Regular PowerShell/OpenSSH-Portable contributors
- Their commit patterns and resolution strategies
- Comments and review feedback

## Upstream Repository Analysis

**Commands for AI Agent (use Invoke-Git MCP tool):**
```pwsh
# Get commit history for target version:
# MCP Tool: mcp_openssh-server_Invoke_Git
# Operation="Log", Range="<last-merged-commit>..upstream/<target-version>"

# Analyze specific commits:
# MCP Tool: mcp_openssh-server_Invoke_Git
# Operation="Show", CommitHash="<commit-hash>"

# Compare branches:
# MCP Tool: mcp_openssh-server_Invoke_Git
# Operation="Diff", Range="HEAD..upstream/<target-version>"
```

## Windows-Specific Knowledge Base

### Common Conflict Areas
1. **Process Management:** fork() vs CreateProcess()
2. **Signal Handling:** Unix signals vs Windows events
3. **File Permissions:** POSIX permissions vs Windows ACLs
4. **Path Handling:** Unix paths vs Windows paths
5. **Build System:** Makefile vs Visual Studio projects

### Resolution Pattern Library
```c
// Pattern 1: Platform-specific implementation
#ifdef WINDOWS
    // Windows implementation
#else
    // Unix implementation
#endif

// Pattern 2: Exclude Unix-only features
#ifndef WINDOWS
    // Unix-only code
#endif

// Pattern 3: Windows compatibility layer
#ifdef WINDOWS
    #include "win32compat.h"
#endif
```

## Decision Matrix for AI Agents

| Conflict Type | Resolution Strategy | Example |
|---------------|-------------------|---------|
| Security Fix | Accept upstream completely | CVE patches |
| Build System | Update VS project files | New source files |
| System Calls | Add Windows equivalent | fork() → CreateProcess() |
| Configuration | Update config.h.vs | New preprocessor defines |
| Test Code | Platform-specific guards | Unix-only tests |

---
applyTo: "**/*"
---

# AI Agent Communication Guidelines

## Overview
This document establishes how AI agents should communicate with users throughout their interactions. These guidelines apply to **all agent operations** in this workspace. For merge-specific communication templates, see [agent-communication-merge.instructions.md](./merge/agent-communication-merge.instructions.md).

## Core Principle: Tool Output vs Agent Communication

### Distinction

**1. MCP Tool Execution (Write-Host is acceptable):**
- When MCP tools execute PowerShell scripts, those scripts may use `Write-Host` for output
- This is normal and expected behavior for the tool itself
- The agent receives this output and can parse it
- Example: `Test-OpenSSHFunctionality.ps1` uses `Write-Host` to display test progress

**2. Agent-to-User Communication (Use chat messages ONLY):**
- AI agents **MUST** communicate with users through chat messages, not `Write-Host`
- **DO NOT** invoke `Write-Host` or other console output commands from the agent
- Instead, present information conversationally in your responses
- Parse tool output and summarize it in chat messages

## Communication Standards

### ❌ INCORRECT: Agent Using Write-Host
```pwsh
Write-Host "Starting merge process..."
Write-Host "Build succeeded!" -ForegroundColor Green
Write-Host "Found 3 conflicts in auth.c"
```

### ✅ CORRECT: Agent Using Chat Messages
```
Starting the merge process. I'll cherry-pick the commits in this batch and then build.

The build succeeded! All 14 executables were created successfully.

Found 3 conflicts in auth.c. Analyzing the conflict types to determine the resolution strategy.
```

## Pseudocode Implementation Guidance

When you see pseudocode functions in instruction files like:
- `update_progress()`
- `generate_test_report()`
- `log()`
- `append_to_progress_log()`

These represent **conceptual operations**. Implement them by:
1. Generating the information/report internally
2. Communicating the results to the user via chat messages
3. **NOT** by executing `Write-Host` or similar PowerShell output commands

### Example: Pseudocode to Implementation

**Pseudocode:**
```pseudocode
FUNCTION update_progress(phase, status, details):
    log(f"Phase {phase}: {status}")
    IF status == "FAILURE":
        generate_failure_report(details)
```

**Correct Agent Implementation:**
```
[Agent analyzes the phase and status]
[Agent sends chat message]: "Phase 1: Conflict Resolution - Completed successfully. Resolved 5 conflicts across 3 files."
```

**Incorrect Agent Implementation:**
```pwsh
Write-Host "Phase 1: Conflict Resolution - Completed successfully"
```

## Best Practices

### 1. Be Conversational
- Write naturally, as if speaking to a colleague
- Avoid overly formal or robotic language
- Use active voice

### 2. Provide Context
- Explain what you're doing and why
- Help users understand the current state
- Highlight important information

### 3. Use Structured Formatting When Helpful
- Use markdown formatting for clarity
- Use bullet points for lists
- Use code blocks for commands or file paths
- Use file links when referencing specific files

### 4. Progressive Disclosure
- Start with high-level summaries
- Provide details when relevant
- Don't overwhelm with unnecessary information

### 5. Clear Status Indicators
Use clear language for status:
- ✅ "succeeded", "completed successfully", "passed"
- ❌ "failed", "encountered errors", "did not pass"
- ⚠️ "warning", "requires attention", "partial success"

## Examples

### Good: Progress Update
```
Analyzing the upstream changes between the last merge commit and V_10_0_P2. Found 127 commits with 8 security fixes and 3 build system changes that will require Visual Studio project updates.
```

### Good: Error Report
```
The build failed with 4 compilation errors:
- auth.c: Missing include for Windows compatibility header
- sshd.c: Undefined reference to fork() - needs Windows equivalent
- config.h.vs: Missing preprocessor definition for HAVE_SETRESUID

I'll add the Windows compatibility fixes now.
```

### Good: Success Report
```
Testing completed successfully! The SSH service installed, started, and accepted connections. The test command executed correctly with expected output.
```

## Merge-Specific Guidelines

For detailed merge workflow communication templates, including exact formats for tool output summaries and commit batch summaries, see:
- [Merge-Specific Agent Communication Guidelines](./merge/agent-communication-merge.instructions.md)

## Summary

- **Tools can use Write-Host** - MCP tools and PowerShell scripts may output to console
- **Agents use chat only** - All agent communication must be via chat messages
- **Parse, don't echo** - Parse tool output and present summaries conversationally
- **Be clear and helpful** - Provide context, use formatting, and communicate status clearly

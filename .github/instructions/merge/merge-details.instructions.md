---
applyTo: "**/*"
---

# Merge Instructions for AI Agents

## Overview
This AI-specific documentation provides comprehensive instructions and algorithmic frameworks that AI agents can use to systematically approach the OpenSSH merge process with minimal human intervention while maintaining high quality and consistency. It combines conflict resolution strategies with automated decision-making processes.

**Key Approach: Two-Phase Merge with Scratch Branch**
Instead of cherry-picking commits (which rewrites history), this framework implements a two-phase approach:

1. **Scratch branch** — All work happens here: incremental `git merge` at batch boundaries (grouped by CI presence or success), conflict resolution, build fixes, and a `Test-OpenSSHFunctionality` smoke test after each built batch. The full CI suite (`Invoke-OpenSSHTests`) is only run when the user explicitly requests it.
2. **Real merge branch** — Created from the same starting commit as the scratch branch, after all scratch-branch work is complete. A single `git merge` of the final upstream target is performed; any conflicts are resolved by copying the already-resolved files from the scratch branch (`git checkout scratch-branch -- <file>`). This produces one merge commit with all upstream SHAs intact and a tree matching the validated scratch-branch state.

No `git rerere`, no resolution log, and no Save/Replay tooling is needed.

Benefits:
- Preserves upstream commit history exactly (original SHAs, authors, timestamps)
- Conflicts on the real branch are resolved in seconds via file copy from the validated scratch branch
- Builds after each batch on scratch branch (mandatory when the batch touches `*.c` or `*.h` files) for early error detection
- Runs the `Test-OpenSSHFunctionality` smoke test after each built batch (mandatory when build ran), independent of upstream CI status. The full CI suite is only run when the user explicitly requests it.
- Requires user approval before proceeding to next batch
- Allows for incremental progress and easier rollback
- Reduces complexity of conflict resolution

## Decision Framework for AI Agents

### Pre-Merge Analysis Algorithm
```pseudocode
FUNCTION analyze_upstream_changes(target_version):
    // Step 1: Find last merged commit and determine range
    last_upstream_commit = find_last_upstream_commit_in_fork()
    commit_range = get_commit_range(last_upstream_commit, target_version)

    // Step 2: Fetch and analyze release notes
    release_notes = fetch_release_notes(target_version)
    risk_factors = []

    FOR EACH change IN release_notes:
        IF change.contains(["signal", "fork", "pipe", "process", "daemon", "service"]):
            risk_factors.append({type: "PROCESS_MANAGEMENT", change: change})
        IF change.contains(["auth", "pam", "kerberos", "gssapi"]):
            risk_factors.append({type: "AUTHENTICATION", change: change})
        IF change.contains(["build", "makefile", "configure", "autotools"]):
            risk_factors.append({type: "BUILD_SYSTEM", change: change})
        IF change.contains(["security", "cve", "vulnerability"]):
            risk_factors.append({type: "SECURITY", change: change, priority: "HIGH"})
```

### Conflict Resolution Decision Tree
```pseudocode
FUNCTION resolve_conflict(file_path, conflict_content):
    conflict_type = analyze_conflict_type(conflict_content)

    SWITCH conflict_type:
        CASE "SECURITY_FIX":
            // Always accept upstream security fixes
            RETURN accept_upstream(conflict_content)

        CASE "BUILD_SYSTEM_CHANGE":
            // Need to update Visual Studio projects
            upstream_changes = extract_upstream_changes(conflict_content)
            RETURN combine_with_windows_build_system(upstream_changes)

        CASE "PROCESS_MANAGEMENT":
            // Unix fork/exec vs Windows CreateProcess
            IF contains_fork_or_exec(conflict_content):
                RETURN wrap_with_platform_ifdef(conflict_content)
            ELSE:
                RETURN analyze_compatibility(conflict_content)

        CASE "AUTHENTICATION":
            // PAM/Kerberos vs Windows auth
            RETURN preserve_windows_auth_with_upstream_features(conflict_content)

        CASE "CONFIGURATION":
            // config.h vs config.h.vs changes
            new_defines = extract_new_defines(conflict_content)
            RETURN update_config_h_vs(new_defines)

        DEFAULT:
            // Use historical pattern matching
            similar_resolutions = find_similar_conflicts(file_path, conflict_content)
            RETURN apply_similar_resolution_pattern(similar_resolutions[0])
```

## Information Sources and Analysis

### Primary References
- [Upstream release notes](https://www.openssh.com/releasenotes.html) - Pay special attention when merging new versions
- [Previous merge PRs](./research.instructions.md) - Review conflict resolution patterns
- Commit history and messages - Use Invoke-Git `Operation="Log"`, `Range="<last-commit>..upstream/<version>"` to understand changes
- Local repository file comparison - Use 3-way diff tools

### Analysis Commands
```pwsh
# View commit details for understanding changes:
# MCP Tool: mcp_openssh-server_Invoke_Git
# Operation="Show", CommitHash="<commit-hash>"

# Compare files between branches:
# MCP Tool: mcp_openssh-server_Invoke_Git
# Operation="Diff", Range="HEAD..upstream/<version>", Path="<filepath>"
```

## Conflict Resolution Strategies

### Guiding Principle: Prefer Upstream, Adapt for Windows

Before choosing a strategy below, apply this bias: **take the upstream change and
add Windows adjustments around it — do not keep the fork's old behavior just
because it was there.** Upstream owns the protocol/logic direction; the fork's
job is to make that direction work on Windows (preferably via the `win32compat`
layer, and via `#ifdef WINDOWS` only where unavoidable).

The common mistake is **dragging upstream's relocated logic back to where the
fork used to have it** to minimize diff. Do not do this. Follow upstream's new
structure and add the Windows handling in the new location.

> **Real example (OpenSSH 10.3 split-sshd):** upstream moved pre-auth / KEX and
> banner-exchange work between `sshd-session` and `sshd-auth`. The correct
> resolution follows upstream and performs the Windows-specific handling in
> `sshd-auth` where upstream placed it — **not** forcing that work to remain in
> `sshd-session` for Windows. Keeping it in the old location to reduce change
> caused state/message-ordering bugs (banner/KEX/post-auth failures). See
> [Pattern 4](#pattern-4-openssh-103-split-sshd-state-ordering-windows).

Only deviate from "prefer upstream" when the upstream code genuinely does not
apply to Windows (then use `#ifndef WINDOWS`, wrapping — never deleting).

### 1. Taking Upstream Changes
**When to use:** Security fixes, bug fixes, feature improvements that don't conflict with Windows functionality.

```c
// Example: Accept upstream security patch
<<<<<<< HEAD
// Windows-specific code
=======
// New upstream security fix
>>>>>>> upstream/V_X_Y_PZ
```
**Resolution:** Take the upstream change completely.

### 2. Combining Changes with Preprocessor Directives
**When to use:** Upstream changes that conflict with Windows-specific functionality but both are needed.

```c
// Example: Combining platform-specific implementations
#ifdef WINDOWS
    // Windows-specific implementation
    return windows_specific_function();
#else
    // Upstream Unix implementation
    return unix_specific_function();
#endif /* WINDOWS */
```

### 3. Excluding Changes with #ifndef WINDOWS
**When to use:** Upstream changes are not applicable to Windows or would break Windows functionality.

```c
// Example: Excluding Unix-only functionality
#ifndef WINDOWS
    // Unix-only code that doesn't apply to Windows
    setup_unix_specific_feature();
#endif /* !WINDOWS */
```

## Automated Conflict Resolution Patterns

### Pattern 1: Platform-Specific Code Wrapping
```c
// Input conflict:
<<<<<<< HEAD
void windows_specific_function() {
    // Windows implementation
}
=======
void unix_specific_function() {
    // New upstream Unix implementation
}
>>>>>>> upstream/version

// AI Resolution:
#ifdef WINDOWS
void windows_specific_function() {
    // Windows implementation
}
#else
void unix_specific_function() {
    // New upstream Unix implementation
}
#endif /* WINDOWS */
```

### Pattern 2: Configuration File Updates
```pseudocode
FUNCTION update_config_h_vs(upstream_config_changes):
    config_vs_path = "./contrib/win32/openssh/config.h.vs"
    current_config = read_file(config_vs_path)

    FOR EACH define IN upstream_config_changes:
        IF define.is_windows_compatible():
            IF define NOT IN current_config:
                add_define_to_config_vs(define, determine_windows_value(define))
        ELSE:
            // Add comment explaining why it's not included
            add_comment_to_config_vs(f"// {define.name} - Unix only, not applicable to Windows")

    write_file(config_vs_path, current_config)
```

### Pattern 3: Build System Synchronization
```pseudocode
FUNCTION sync_build_system():
    makefile_changes = get_makefile_changes()

    FOR EACH binary IN makefile_changes.new_binaries:
        IF binary.is_windows_applicable():
            create_visual_studio_project(binary)
            add_to_solution_file(binary)
        ELSE:
            log(f"Skipping {binary} - Unix only")

    FOR EACH binary IN makefile_changes.removed_binaries:
        remove_visual_studio_project(binary)
        remove_from_solution_file(binary)

    FOR EACH source_file IN makefile_changes.new_source_files:
        target_project = determine_target_project(source_file)
        add_source_to_project(target_project, source_file)

// CRITICAL: When modifying .vcxproj or .sln files programmatically,
// ALWAYS use Windows line endings (\r\n) instead of Unix (\n).
// This prevents Git from showing the entire file as modified.
FUNCTION add_source_to_project(project_file, source_file):
    // Example: Use \r\n for line endings
    new_line = f"    <ClCompile Include=\"{source_file}\" />\r\n"
    insert_into_project_file(project_file, new_line)
```

### Pattern 4: OpenSSH 10.3 Split-sshd State Ordering (Windows)

When upstream changes split pre-auth work between `sshd-session` and `sshd-auth`, preserve the state/message ordering exactly.

- `sshd-session` (listener/monitor side) should not perform banner exchange that upstream moved to `sshd-auth`.
- For Windows `FORK_NOT_SUPPORTED` post-auth child (`sshd-session -z`), monitor message order matters:
    - Receive identification-exchange state first.
    - Then receive authenticated user context.

If this ordering is wrong, common symptoms are:
- pre-auth failures such as banner parsing or signature mismatches
- post-auth `Invalid user` with empty username
- monitor keystate errors like `incomplete message`

### Pattern 5: Upstream Changes to Regress Tests With Existing Windows Adaptations

Many bash regression tests under `regress/*.sh` have already been adapted for
Windows in this fork using `if [ "$os" == "windows" ]; then ... else ... fi`
blocks. The most common adaptation wraps `diff` so it tolerates the CRLF line
endings that Windows binaries (e.g. `sshd -T`) emit:

```sh
if [ "$os" == "windows" ]; then
	# Ignore the CR (carriage return) during diff
	diff --strip-trailing-cr $OBJ/expected $OBJ/actual || fail "..."
else
	diff $OBJ/expected $OBJ/actual || fail "..."
fi
```

**The risk:** When upstream adds a *new* test case (or modifies an existing
one) inside a file that already contains these Windows blocks, the new code is
merged verbatim from upstream and arrives with a plain `diff` (or other
Unix-only assumption). Git does not flag a conflict because the surrounding
Windows blocks are untouched, so the regression only surfaces later as a
Windows-specific test failure (the plain `diff` reports trailing-`\r`
mismatches).

**Required check during merge:** For every `regress/*.sh` file touched by an
upstream batch, determine whether the file *already* contains
`if [ "$os" == "windows" ]` blocks. If it does, inspect each upstream addition
or modification in that file and apply the same Windows adaptation to the new
code:

```pseudocode
FUNCTION check_regress_test_windows_adaptations(changed_files):
    FOR EACH file IN changed_files WHERE file MATCHES "regress/*.sh":
        IF file CONTAINS 'if [ "$os" == "windows" ]':
            // File is already Windows-aware
            FOR EACH upstream_added_or_modified_block IN file:
                IF block USES diff AND NOT wrapped_in_windows_conditional(block):
                    wrap_with_windows_conditional(block)  // use diff --strip-trailing-cr
                IF block USES other Unix-only assumption (paths, perms, signals):
                    apply_matching_windows_adaptation(block)
```

Real example: the OpenSSH 10.3 merge brought in a new "MaxStartups idempotence"
case in `regress/cfgparse.sh`. The surrounding `listenaddress` tests already had
`diff --strip-trailing-cr` Windows blocks, but the new case used a plain `diff`
and failed on Windows until it was wrapped in the same conditional.

**When a bash regression test fails, check whether it is a *newly added* upstream
test first.** A failure in a test that upstream added or substantially changed in
this merge is a strong signal that the test needs Windows adaptation before it is
expected to pass — not that the merge broke existing behavior. Triage:

```pseudocode
FUNCTION triage_failing_bash_test(test_file, batch_range):
    // Was this test (or the failing case) introduced/changed by the upstream batch?
    added_or_changed = git_diff(batch_range, test_file).touches_failing_case()
    IF added_or_changed:
        // Likely needs Windows adaptation, not a real regression.
        // Apply Pattern 5 adaptations: diff --strip-trailing-cr, path/perm/signal fixes,
        // or skip the case on Windows if the feature is Unix-only.
        adapt_for_windows(test_file)
    ELSE:
        // Pre-existing test now failing => investigate as a genuine regression from the merge.
        investigate_regression(test_file)
```

Run a single failing bash test in isolation with
`mcp_openssh-server_Invoke_OpenSSHTests` (`TestSuite="Bash"`,
`BashTestFilePath="<absolute-path>"`) while iterating on the adaptation.

### Pattern 6: Upstream Changes That Merge Cleanly but Need Windows Follow-up

Git only flags **textual** conflicts. Many upstream changes merge cleanly yet
still require Windows work that git cannot know about. These are the most
dangerous because nothing stops the merge — the gap surfaces later as a build
break or runtime bug. **After every batch, diff the range and actively hunt for
these**, even when there were zero conflicts:

```pwsh
# MCP Tool: mcp_openssh-server_Invoke_Git
# Operation="Diff", Range="<prev_batch_end>..<cur_batch_end>", NameOnly=true
```

Classes to check:

- **ssh-agent:** the Windows ssh-agent is a **separate implementation** under
  `contrib/win32/win32compat/ssh-agent/`. Upstream changes to `ssh-agent.c` or
  the agent protocol merge into the upstream file but are **not** reflected in
  the Windows agent. Port relevant logic by hand, or record an explicit TODO for
  Windows-team review. (See [repository-overview.instructions.md](../repository-overview.instructions.md).)
- **config.h.vs:** new feature `#define`s that autoconf would set in `config.h`
  must be added to `contrib/win32/openssh/config.h.vs` for Windows to get them.
- **Build system:** new source files added to `Makefile.in` must be added to the
  correct `.vcxproj` (and the solution) using `\r\n` line endings; removed files
  must be dropped.
- **New POSIX usage:** newly introduced `fork`/`exec`/`signal`/`pipe`/socket
  options need a `w32_*` equivalent in `win32compat` or a guard.

The `conflict-review` agent's checklist covers this class explicitly — delegate a
batch to it for a second pass if unsure.

### Pattern 7: version.h Resolution and version.rc Sync (Windows)

`version.h` conflicts most upstream merges because upstream bumps the OpenBSD
version tag and `SSH_PORTABLE`. Resolution rule:

- **Keep** the Windows-only fields the fork owns: `SSH_WINDOWS_VERSION`
  (`OpenSSH_for_Windows_<major>.<minor>`) and `SSH_WINDOWS_BANNER`.
- **Take upstream** for the OpenBSD `$OpenBSD$` version comment and the value of
  `SSH_PORTABLE` (`"pN"`), then update `SSH_WINDOWS_VERSION`'s `<major>.<minor>`
  to match the new upstream release.

Then sync the Windows resource file so built binaries report the right version:

```pwsh
# MCP Tool: mcp_openssh-server_Sync_VersionResource
# (add -DryRun to preview)
```

The tool reads `version.h` and rewrites `contrib/win32/openssh/version.rc`:
`FILEVERSION`/`PRODUCTVERSION` become `<major>,<minor>,0,0` and the
`FileVersion` string `<major>.<minor>.0.0`; the patch (`pN`) is reflected in the
`ProductVersion` **text** only (`OpenSSH_<major>.<minor>pN for Windows`); the
descriptive text (`OpenSSH for Windows`) is preserved. The numeric third field
stays `0` by fork convention.

## Common Conflict Patterns

### File System Operations
- **Fork/exec calls** → Use Windows process creation APIs
- **Signal handling** → Use Windows event mechanisms
- **File permissions** → Adapt to Windows ACL model

### Privsep and Monitor State Transitions (Windows)
- For split `sshd-session` / `sshd-auth` flows, keep sender/receiver message ordering identical across monitor channels.
- Do not add ad-hoc state shuttling unless both sender and receiver are updated in lockstep.
- When debugging, verify the first protocol failure point (banner exchange vs KEX vs post-auth keystate) before changing multiple stages at once.

### Build System Changes
- **Makefile additions** → Update Visual Studio project files (use `\r\n` line endings)
- **New dependencies** → Check Windows compatibility
- **Compiler flags** → Translate to MSVC equivalents
- **Project file edits** → Maintain Windows line endings (`\r\n`) to avoid Git diffs

### Configuration Changes
- **New config options** → Add to `./contrib/win32/openssh/config.h.vs`
- **Feature detection** → Verify Windows support
- **Default values** → Adjust for Windows environment

### Regress Test Changes (`regress/*.sh`)
- **File already has `if [ "$os" == "windows" ]` blocks** → Check every upstream
  addition/modification in that file and apply the same Windows adaptation
  (e.g. `diff --strip-trailing-cr`). Git will not flag a conflict because the
  existing Windows blocks are untouched. See [Pattern 5](#pattern-5-upstream-changes-to-regress-tests-with-existing-windows-adaptations).
- **New `diff` comparisons** → Wrap with `diff --strip-trailing-cr` on Windows
  to tolerate CRLF output from Windows binaries.
- **A bash test fails after the merge** → First check whether it is a *newly
  added* or newly changed upstream test in this batch. If so, it likely needs
  Windows adaptation (Pattern 5) before it is expected to pass — treat it as an
  adaptation task, not a regression. Only if the failing test pre-existed the
  merge should you investigate it as a genuine regression.

### Silent (Clean-Merged) Changes Needing Windows Work
- After every batch, `Diff` the range (`NameOnly=true`) even when there were no
  conflicts, and check ssh-agent (`win32compat/ssh-agent/`), `config.h.vs`,
  `.vcxproj`/solution, and new POSIX calls. See
  [Pattern 6](#pattern-6-upstream-changes-that-merge-cleanly-but-need-windows-follow-up).

### version.h / version.rc
- Keep Windows fields in `version.h`; take upstream's portable version; then run
  `mcp_openssh-server_Sync_VersionResource`. See
  [Pattern 7](#pattern-7-versionh-resolution-and-versionrc-sync-windows).

## Resolution Workflow

### For Each Conflict:
1. **Analyze the change**
   ```pwsh
   # MCP Tool: mcp_openssh-server_Invoke_Git
   # Operation="Show", CommitHash="upstream/<version>", Path="<conflicted-file>"
   ```

2. **Check previous resolutions**
   - Search previous merge PRs for similar conflicts
   - Look for patterns in Windows-specific handling

3. **Choose resolution strategy**
   - Upstream change: Complete replacement
   - Combined: Add preprocessor directives
   - Excluded: Use `#ifndef WINDOWS`

4. **Test the resolution**
   - Ensure code compiles
   - Verify simple ssh connection to local host works
   - Check that upstream functionality is preserved where applicable

5. **Document the decision**
   - Add comments explaining the Windows-specific handling
   - Note in commit message why this approach was chosen

## Build Validation Automation

### Iterative Build and Fix Process
```pseudocode
FUNCTION automated_build_fix():
    MAX_ITERATIONS = 10
    iteration = 0

    WHILE iteration < MAX_ITERATIONS:
        // Always start with Start-OpenSSHBuild.ps1
        build_result = start_openssh_build(Configuration="Release", Architecture="x64")

        // ALWAYS invoke Test-OpenSSHBuild.ps1 to check warnings (success or failure)
        test_result = test_openssh_build(Configuration="Release", Architecture="x64", LogFile=build_result.log)

        IF build_result.success:
            // Check for new warnings against baseline
            new_warnings = compare_warnings_to_baseline(test_result.warnings, baseline_warnings)
            IF new_warnings.count > 0:
                categorized_warnings = categorize_warnings(new_warnings)
                request_user_approval(categorized_warnings)
                // Wait for user decision: fix warnings or proceed
            RETURN SUCCESS

        // Build failed - parse errors
        errors = test_result.errors
        fixes_applied = []

        FOR EACH error IN errors:
            fix = determine_fix_strategy(error)
            IF fix:
                apply_fix(fix)
                fixes_applied.append(fix)

        IF fixes_applied.empty():
            RETURN MANUAL_INTERVENTION_REQUIRED

        commit_build_fixes(fixes_applied, f"Build fixes iteration {iteration + 1}")
        iteration += 1

    RETURN MAX_ITERATIONS_EXCEEDED

FUNCTION determine_fix_strategy(error):
    SWITCH error.type:
        CASE "MISSING_INCLUDE":
            RETURN add_windows_include(error.missing_header)
        CASE "UNDEFINED_FUNCTION":
            RETURN add_windows_equivalent(error.function_name)
        CASE "MISSING_DEFINE":
            RETURN add_to_config_h_vs(error.define_name)
        CASE "MISSING_SOURCE_FILE":
            RETURN add_source_to_project(error.file_name)
        DEFAULT:
            RETURN null
```

### Build Tools Invocation Policy

- Use `Start-OpenSSHBuild.ps1` to run the build for each chunk/batch.
- **ALWAYS invoke `Test-OpenSSHBuild.ps1` after every build** (success or failure):
  - On build failure: Parse errors and warnings to fix issues
  - On build success: Parse warnings to compare against baseline
- Compare warning count against established baseline
- If new warnings detected, report to user with categorization and request approval before proceeding
- Do NOT skip `Test-OpenSSHBuild.ps1` even when build succeeds - warning checks are mandatory.
- On the scratch branch, commit build fixes after each batch merge commit.
- On the real branch, apply the same build fixes as separate commits after the single merge commit.

### Batch Test Invocation Policy (Scratch Branch)

- After each batch merge is completed and builds cleanly, run the functionality smoke test:
    - **MCP Tool Name**: `mcp_openssh-server_Test_OpenSSHFunctionality`
    - **Parameters**: `Configuration="Release"`, `Architecture="x64"`
- This is mandatory for every batch **that was built** (i.e., the batch touched `*.c` or `*.h` files), regardless of whether the upstream endpoint commit had successful CI.
- For batches that only modify documentation, regress scripts, or other non-compiled files, skip both build and smoke-test invocation.
- **Full CI suite (`Invoke-OpenSSHTests` with `TestSuite="All"`) is NOT run per-batch by default.** Only invoke it when the user explicitly requests it for a batch, before transitioning to the real merge branch, or before opening the PR.
- If the smoke test fails, fix and re-run before proceeding to the next batch.
- When a full-suite run is requested and any sub-suite fails, re-run only the failing suite while fixing (`TestSuite="Unit"`, `TestSuite="Bash"`, `TestSuite="E2E"`). For bash triage, run a single failing test with `BashTestFilePath`.

## Testing Automation Framework

### Automated Test Execution
```pseudocode
FUNCTION execute_test_suite():
    test_results = {}

    // Phase 1: Build verification
    test_results["build"] = verify_build_artifacts()
    IF NOT test_results["build"].success:
        RETURN test_results

    // Phase 2: Service setup
    test_results["service_setup"] = setup_ssh_service()
    IF NOT test_results["service_setup"].success:
        RETURN test_results

    // Phase 3: Basic connectivity
    test_results["connectivity"] = test_basic_ssh_connection()

    // Cleanup
    cleanup_test_environment()

    RETURN test_results

FUNCTION generate_test_report(test_results):
    report = "# Automated Test Results\n\n"

    FOR EACH category, result IN test_results:
        status = result.success ? "✅ PASS" : "❌ FAIL"
        report += f"## {category}: {status}\n"

        IF NOT result.success:
            report += f"Error: {result.error}\n"
            report += f"Suggested Fix: {result.suggested_fix}\n"

    RETURN report
```

## Error Recovery Strategies

### Automatic Rollback Points
```pseudocode
FUNCTION create_checkpoint(phase_name):
    current_commit = get_current_commit_hash()
    checkpoints[phase_name] = current_commit
    tag_commit(f"checkpoint-{phase_name}", current_commit)

FUNCTION rollback_to_checkpoint(phase_name):
    IF phase_name IN checkpoints:
        reset_to_commit(checkpoints[phase_name])
        RETURN SUCCESS
    ELSE:
        RETURN CHECKPOINT_NOT_FOUND

// Usage in main workflow
create_checkpoint("pre-merge")
execute_merge()

IF merge_conflicts_too_complex():
    rollback_to_checkpoint("pre-merge")
    request_manual_intervention()
```

### Conflict Complexity Assessment
```pseudocode
FUNCTION assess_conflict_complexity(conflicts):
    complexity_score = 0

    FOR EACH conflict IN conflicts:
        // File-based scoring
        IF conflict.file.ends_with(".c", ".h"):
            complexity_score += 2
        IF conflict.file.contains("auth", "pam", "kerberos"):
            complexity_score += 5
        IF conflict.file == "config.h":
            complexity_score += 3

        // Content-based scoring
        lines_in_conflict = conflict.content.split('\n').length
        complexity_score += lines_in_conflict * 0.1

        // Pattern-based scoring
        IF conflict.content.contains("fork", "exec", "signal"):
            complexity_score += 10
        IF conflict.content.contains("WIN32", "WINDOWS", "#ifdef"):
            complexity_score -= 2  // Already has platform guards

    IF complexity_score > 50:
        RETURN "HIGH_COMPLEXITY"
    ELIF complexity_score > 20:
        RETURN "MEDIUM_COMPLEXITY"
    ELSE:
        RETURN "LOW_COMPLEXITY"
```

### Using Get-ConflictContext for High-Complexity Conflicts

When `assess_conflict_complexity()` returns `HIGH_COMPLEXITY`, invoke the `Get-ConflictContext` MCP tool **before** attempting to edit the file. It provides three-way context anchored to the actual changed regions, accounting for the fact that our fork's line numbers differ from upstream.

```pseudocode
FUNCTION resolve_conflict(file_path, conflict_content, merge_batch_commit):
    complexity = assess_conflict_complexity([{file: file_path, content: conflict_content}])

    IF complexity == "HIGH_COMPLEXITY":
        // Fetch three-way context before editing
        // MCP Tool: mcp_openssh-server_Get_ConflictContext
        // FilePath=file_path, CommitHash=merge_batch_commit
        //
        // If the default MaxTotalLines=150 is insufficient (e.g., many hunks or
        // a large function), re-invoke with a higher value such as MaxTotalLines=300.
        context = get_conflict_context(file_path, merge_batch_commit)

        FOR EACH hunk IN context.Hunks:
            // Use all three excerpts to understand:
            //   hunk.UpstreamBefore — what the upstream code looked like before the commit
            //   hunk.UpstreamAfter  — what the upstream commit changed it to
            //   hunk.OurFork        — what our fork has in the corresponding region
            //                        (Note field explains how the region was located)
            determine_resolution_strategy(hunk)

        // Check Message for budget warnings and increase MaxTotalLines if needed
        IF context.Message contains "minimum floor":
            re_invoke_with_larger_budget(file_path, merge_batch_commit)

    resolved = apply_resolution_strategy(file_path, conflict_content)

    // The resolved file on the scratch branch is the source of truth.
    // It will be copied directly to the real merge branch in the Real Branch Phase
    // via `git checkout scratch-branch -- <file_path>`. No resolution log is recorded.

    RETURN resolved
```

**Key behaviours of the tool:**
- **Binary files**: Returns `IsBinary=true` and no excerpts — resolve manually.
- **Unavailable versions**: A version returns `Lines=null` with a `Note` explaining why (e.g. file newly added by this commit).
- **Fork region location**: Uses sliding-window content matching against the diff's unchanged context lines. Falls back to the function name from the `@@` hunk header if the anchor score is too low. The `Note` field on each `OurFork` excerpt describes which strategy was used.
- **Budget warning**: If `MaxTotalLines` is too small to give each hunk 10 lines per version, a warning appears in `Message` — increase `MaxTotalLines` and re-invoke.

## Anti-Patterns to Avoid

### ❌ Don't Remove Upstream Code
```c
// WRONG: This will cause future merge conflicts
// Completely removing upstream additions
```

### ❌ Don't Modify Upstream Logic Without Guards
```c
// WRONG: Modifying upstream code without preprocessor protection
upstream_function_with_windows_modifications();
```

### ✅ Do Use Preprocessor Guards
```c
// CORRECT: Preserve upstream code with conditional compilation
#ifdef WINDOWS
    windows_alternative();
#else
    upstream_function();
#endif
```

## Progress Tracking and Reporting

### Automated Progress Updates
```pseudocode
FUNCTION update_progress(phase, status, details):
    progress_entry = {
        timestamp: current_timestamp(),
        phase: phase,
        status: status,  // SUCCESS, FAILURE, IN_PROGRESS
        details: details,
        commit_hash: get_current_commit_hash()
    }

    append_to_progress_log(progress_entry)

    IF status == "FAILURE":
        generate_failure_report(phase, details)
        suggest_recovery_actions(phase, details)

FUNCTION generate_merge_summary():
    summary = {
        total_conflicts: count_resolved_conflicts(),
        build_iterations: count_build_fix_iterations(),
        test_results: get_final_test_results(),
        time_elapsed: calculate_total_time(),
        commits_created: count_commits_since_start(),
        complexity_rating: assess_overall_complexity()
    }

    RETURN format_summary_report(summary)
```

## Integration with Development Workflow

### Pull Request Preparation
```pseudocode
FUNCTION prepare_pull_request():
    // Generate comprehensive commit history
    commit_history = get_commits_since_branch_creation()

    // Create PR description
    pr_description = f"""
# Merge OpenSSH {target_version} to Windows Fork

## Summary
{generate_merge_summary()}

## Conflict Resolutions
{generate_conflict_resolution_summary()}

## Testing Results
{generate_test_report(final_test_results)}

## Files Modified
{list_modified_files()}

## Breaking Changes
{identify_breaking_changes()}
"""

    RETURN {
        title: f"Merge upstream OpenSSH {target_version}",
        description: pr_description,
        labels: ["upstream-merge", determine_complexity_label()],
        assignees: get_default_reviewers()
    }

FUNCTION normalize_fork_workflow_triggers():
    workflow_files = list_files(".github/workflows/*.yml")

    FOR EACH wf IN workflow_files:
        // Policy for PowerShell Windows fork: dispatch-only upstream workflows
        ensure_trigger_enabled(wf, "workflow_dispatch")
        disable_trigger(wf, "push")
        disable_trigger(wf, "pull_request")
        disable_trigger(wf, "schedule")

    RETURN "workflow triggers normalized for fork policy"
```

### Workflow Trigger Policy (Windows Fork)
- Upstream workflow files merged into this fork should default to manual invocation only.
- Keep `workflow_dispatch` active.
- Disable automatic triggers (`push`, `pull_request`, `schedule`) unless the Windows fork explicitly depends on them.
- During final merge review, verify `.github/workflows/*.yml` trigger blocks are policy-compliant.

## Commit Message Template

Desired commit object (header, blank line, body):
```
Resolve merge conflicts for <upstream-version>

Major conflict resolutions:
- <file1>: Combined upstream <feature> with Windows <implementation> using #ifdef
- <file2>: Excluded upstream <unix-feature> with #ifndef WINDOWS due to <reason>
- <file3>: Accepted upstream <bugfix> completely

Reasoning: <brief explanation of overall strategy>
```

Invoke via terminal — the MCPServerPS wrapper around `Invoke-Git` mangles embedded newlines in `Message`, so use repeated `-m` flags (git inserts the blank-line separators between them automatically):
```pwsh
git commit -m "Resolve merge conflicts for <upstream-version>" `
           -m "Major conflict resolutions:`n- <file1>: Combined upstream <feature> with Windows <implementation> using #ifdef`n- <file2>: Excluded upstream <unix-feature> with #ifndef WINDOWS due to <reason>`n- <file3>: Accepted upstream <bugfix> completely" `
           -m "Reasoning: <brief explanation of overall strategy>"
```

## Troubleshooting

### If Unsure About a Conflict:
1. Check if the upstream change addresses a CVE or security issue (prioritize)
2. Look for similar code patterns elsewhere in the Windows codebase
3. Consult the OpenSSH-portable issue tracker for context
4. When in doubt, use conditional compilation to preserve both approaches

### Testing Your Resolution:
- Build the project after each major conflict resolution
- Run ssh connection to local host to ensure basic functionality
- Check that removed functionality wasn't critical to Windows operation
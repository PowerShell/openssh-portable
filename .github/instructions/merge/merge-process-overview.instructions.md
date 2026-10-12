---
applyTo: "**/*"
---

# OpenSSH-Portable: Merge From Upstream Instructions

## Overview
This documentation provides comprehensive instructions for merging OpenBSD's OpenSSH-Portable changes into the PowerShell team's Windows-compatible fork. It is designed to be used by both human developers and AI agents to complete a full merge process that results in a ready-to-merge Pull Request.

## Prerequisites
Ensure the following tools are installed and configured before proceeding:
- **Git**
- **PowerShell**
- **Visual Studio** with:
  - Latest C/C++ development tools
  - Latest Windows 10/11 SDK

## Process Overview
The merge process uses a **two-phase approach** to preserve upstream commit history while keeping conflict resolution manageable:

1. **Scratch branch** — All work happens here: incremental `git merge` at batch boundaries, conflict resolution, build fixes, and a `Test-OpenSSHFunctionality` smoke test after each built batch. The full CI suite (`Invoke-OpenSSHTests`) is only run when the user explicitly requests it (e.g., before the real branch / PR).
2. **Real merge branch** — Created from the same starting commit as the scratch branch, after all scratch-branch work is complete. A single `git merge` of the final upstream target is performed; any conflicts are resolved by copying the already-resolved files from the scratch branch (`git checkout scratch-branch -- <file>`). This produces one merge commit with all upstream SHAs intact and a tree that matches the validated scratch-branch state.

No `git rerere` recording, no resolution log, and no Save/Replay tooling is required.

The process consists of several interconnected phases:

1. **[Setup Phase](#setup-phase)** - Repository configuration and preparation
2. **[Research Phase](#research-phase)** - Understanding changes and conflicts
3. **[Scratch Branch Phase](#scratch-branch-phase)** - Incremental merging, conflict resolution, build fixes, validation
4. **[Real Branch Phase](#real-branch-phase)** - Single merge with conflict resolution by copy from scratch branch
5. **[Build Phase](#build-phase)** - Resolving compilation issues
6. **[Testing Phase](#testing-phase)** - Validating functionality
7. **[Submission Phase](#submission-phase)** - Creating the Pull Request

## Setup Phase

**📖 Detailed Instructions:** [Setup Instructions](../setup.instructions.md)

**Quick Overview:**
1. Clone your fork of the openssh-portable repository
2. Configure upstream remotes (PowerShell team fork + original OpenSSH)
3. Fetch latest changes

## Research Phase

**📖 Detailed Instructions:** [Research Instructions](./research.instructions.md)

**Key Resources:**
- **Upstream Release Notes:** [OpenSSH Release Notes](https://www.openssh.com/releasenotes.html)
- **Previous Merge PRs:** such as https://github.com/PowerShell/openssh-portable/pull/737

## Merge Phase

### Initial Preparation
1. **Verify prerequisites and baseline**
   Use the Test-MergePrerequisites MCP tool:
   ```pwsh
   # Run prerequisite check via MCP tool
   # MCP Tool Name: mcp_openssh-server_Test_MergePrerequisites
   # Parameters: TargetVersion (required)

   # Example invocation (replace <VERSION> with target like "V_10_0_P2"):
   # The MCP tool will verify:
   # - Git, PowerShell, Visual Studio installed
   # - Repository remotes configured (origin, upstream, upstream-pwsh)
   # - Target version exists in upstream
   # - Working directory is clean

   # Proceed only if tool reports "ALL PREREQUISITES MET"
   ```

2. **Configure git:**
    ```pwsh
    # Set non-interactive editor so MergeContinue does not block.
    # MCP Tool: mcp_openssh-server_Invoke_Git
    # Operation="Config", Key="core.editor", Value="true"
    ```

    **Disable `git rerere` for this merge.** The two-phase workflow does not
    use rerere — resolutions are copied wholesale from the scratch branch in
    the Real Branch Phase. Cached rerere resolutions from prior sessions can
    silently auto-apply (possibly incomplete) resolutions during batch merges,
    making conflict decisions opaque. Disable it explicitly:
    ```pwsh
    git config --local rerere.enabled false
    git config --local rerere.autoupdate false
    ```

3. **Create the scratch branch only (record the starting commit):**
    ```pwsh
    # Note the current HEAD — this is the starting commit. The real merge
    # branch will be created from this same commit in the Real Branch Phase.
    # Use a terminal command here: the MCPServerPS wrapper rejects string
    # parameter values that start with "-" (e.g. Invoke-Git Log Range="-1"
    # yields MCP error -32603, even though Invoke-Git.ps1 itself accepts it).
    git log -1 --oneline

    # Create the scratch branch (all work happens here)
    # MCP Tool: mcp_openssh-server_Invoke_Git
    # Operation="CreateBranch", Branch="scratch-merge-v<VERSION>-<YYYYMMDD>"
    ```

### Scratch Branch Phase
4. **Identify merge range and group commits:**
    Use the Get-CommitGroups MCP tool with `-FirstChunkOnly` and a user-selected CI grouping mode.

   **CI grouping mode (user input required):**
   Before invoking the tool, confirm with the user which mode to use:
   - `presence` (recommended) → `GroupByCIPresence=true`: batches end at any commit with CI runs (passing or failing). Smaller batches, more frequent build/test checkpoints.
   - `success` → `GroupByCIPresence=false`: batches end only at commits with successful CI. Larger batches, fewer checkpoints.

   Do not assume a default — ask the user if not provided. Use the same value for every `Get-CommitGroups` call in the merge.

   **MCP Tool Name**: `mcp_openssh-server_Get_CommitGroups`

   **Parameters**:
   - `GitHubTag` (string, optional): Start from last merged tag (e.g., "V_10_0_P2")
   - `StartCommit` (string, optional): Start from specific commit SHA
   - `EndCommit` (string, optional): End at specific commit SHA (default: HEAD - most recent upstream commit)
   - `FirstChunkOnly` (boolean): Set to `true`
   - `GroupByCIPresence` (boolean): Set per the user-selected CI grouping mode above

   **Example for first batch**:
   - Find the last upstream tag in the fork
   - Call tool with `GitHubTag=<last-upstream-tag>`, `EndCommit=<target-end-commit>`, `FirstChunkOnly=true`, `GroupByCIPresence=<user_choice>`
   - Omit `EndCommit` to merge all commits up to HEAD (most recent upstream commit)
   - With `GroupByCIPresence=true`, this gets commits ending with any commit that has CI runs; with `false`, only commits with successful CI

   **Example output:**
   ```json
   {
     "ChunkNumber": 1,
     "StartCommit": "609fe2c",
     "EndCommit": "6fb728d",
     "StartCommitFull": "609fe2cae2459d721ac11d23cd27b8a94397ef3c",
     "EndCommitFull": "6fb728df50c1afd338cb0223a84ce24579577eff",
     "CommitCount": 57,
     "StartMessage": "upstream: rework the text for -3 to make it clearer what default",
     "EndMessage": "Run all tests on Cygwin again."
   }
   ```

   Display batch details for verification, then proceed with merging.

   **After completing steps below, get next batch**:
   - Call tool with `StartCommit=<end-commit-sha>`, `EndCommit=<target-end-commit>`, `FirstChunkOnly=true`, `GroupByCIPresence=<user_choice>` (use the same mode chosen for the first batch)
   - Continue this process until the target end commit is reached (or HEAD if no end commit specified)

5. **Execute batch merge on scratch branch:**

   Merge the batch's end commit to bring in all commits in the range at once:

   ```pwsh
   # Merge all commits up to the batch endpoint
   # MCP Tool: mcp_openssh-server_Invoke_Git
   # Operation="Merge", CommitHash=$result.EndCommitFull
   ```

   This uses `--no-ff` to always create a merge commit checkpoint.

7. **Resolve merge conflicts directly:**
    **📖 Detailed Instructions** ([Merge Details](./merge-details.instructions.md)):

   - Resolve conflicts in place for all conflicted files
   - Follow established Windows compatibility patterns
   - Reference previous merge PRs for similar conflicts
   - The resolved files on the scratch branch are the source of truth that will be copied to the real merge branch in the Real Branch Phase. No resolution log or rerere recording is needed.

8. **Complete the merge after resolution:**
   ```pwsh
   # Stage all resolved files using Invoke-Git MCP tool:
   # MCP Tool: mcp_openssh-server_Invoke_Git
   # Operation="Add", Path="."

   # Continue merge using Invoke-Git MCP tool:
   # MCP Tool: mcp_openssh-server_Invoke_Git
   # Operation="MergeContinue"
   ```

9. **Build after completing the batch (only if the batch touched compiled sources):**
     **Gating rule:** Build and validation steps (this step and step 10) are only required for batches whose commit range touches at least one C source or header file (`*.c` or `*.h`). For batches that only modify non-compiled files (e.g., `*.md`, man pages, `regress/*.sh`, `.github/**`, documentation), skip steps 9 and 10 and proceed to step 11; note in the batch summary that build/validation were skipped because no compiled sources changed.

     Detect code impact with:
     ```pwsh
     # MCP Tool: mcp_openssh-server_Invoke_Git
     # Operation="Diff", Range="<previous_batch_end>..<current_batch_end>", NameOnly=true
     ```
     If any returned path matches `*.c` or `*.h`, perform the build below. Otherwise, skip to step 11.

     Use the Start-OpenSSHBuild MCP tool:
     - **MCP Tool Name**: `mcp_openssh-server_Start_OpenSSHBuild`
     - **Parameters**: `Configuration="Release"` (Architecture defaults to the host machine's architecture; only pass `Architecture` when intentionally cross-building)

     **ALWAYS check warnings after build (success or failure):**
     - **Use Test-OpenSSHBuild MCP tool to parse errors and warnings**:
         - **MCP Tool Name**: `mcp_openssh-server_Test_OpenSSHBuild`
         - **Parameters**: `Configuration="Release"` (Architecture defaults to the host machine's architecture)
     - **DO NOT** try to read log files directly with `Get-Content` or locate them manually

     If build failed:
     - Fix issues based on parsed error output
     - Rebuild and verify

     If build succeeded:
     - Compare warnings against baseline established in Phase 1
     - If new warnings detected:
       - Categorize warnings (deprecated APIs, type conversions, potential bugs, etc.)
       - Report to user with warning details and categories
       - Request user decision: fix warnings or proceed
       - Wait for user approval before continuing
       - If user approves proceeding, update baseline to include new warnings

     **CRITICAL: Before committing, restore paths.targets**:
     ```pwsh
     # MCP Tool: mcp_openssh-server_Invoke_Git
     # Operation="Checkout", Target=".\contrib\win32\openssh\paths.targets"
     ```
     Commit any build fixes separately with descriptive messages (only actual code changes)

10. **Run the functionality smoke test after every batch that was built (mandatory when build ran):**
    If step 9 was skipped (no `*.c`/`*.h` changes in the batch), skip this step as well.
    Otherwise, run the cheap end-to-end SSH smoke test:
    - **MCP Tool Name**: `mcp_openssh-server_Test_OpenSSHFunctionality`
    - **Parameters**: `Configuration="Release"`, `Architecture="x64"`

    If the smoke test fails, fix issues before proceeding to the next batch.

    **Full CI suite (`Invoke-OpenSSHTests` with `TestSuite="All"`) is NOT run per-batch by default.** Run it only when:
    - The user explicitly requests it for a given batch, or
    - Before transitioning to the real merge branch (Phase 6), or
    - Before creating the PR.

    When you do run it and any suite fails, re-run only the failing suite to iterate faster (`TestSuite="Unit"`, `TestSuite="Bash"`, or `TestSuite="E2E"`). For a single failing bash case, use `TestSuite="Bash"` and `BashTestFilePath="<absolute-path-to-test.sh>"`.

11. **Provide summary and get approval:**
    - Summarize batch changes, conflicts resolved, build status, and smoke-test status (and full CI suite status if it was run)
    - Wait for user approval before proceeding to next batch
    - Document next steps (starting commit for next batch)
    - After all batches complete on the scratch branch, proceed to the scratch base-sync step below

**Before the Real Branch Phase — sync the scratch branch with its base branch (re-fetched):**

Merge work can take long enough that other PRs land on the base branch (e.g.
`latestw_all`) while it is in progress. Because the real merge branch's tree is
taken wholesale from the scratch branch, the scratch branch must be current with
the base branch **before** it becomes the source of truth. Do this once, after
all batches are merged and validated on the scratch branch:

```pwsh
# 1. Re-fetch the base branch the scratch/merge was started from (its upstream tracking branch)
git fetch <base-remote>            # e.g. origin or upstream-pwsh

# 2. Merge the refreshed base into the scratch branch (still checked out)
# MCP Tool: mcp_openssh-server_Invoke_Git
# Operation="Merge", CommitHash="<base-remote>/<base-branch>"   # e.g. origin/latestw_all
```

- Resolve any conflicts from this merge the same way as batch conflicts.
- After it completes cleanly, verify no markers remain
  (`mcp_openssh-server_Test_MergeConflictMarkers`) and re-run the build +
  `Test-OpenSSHFunctionality` smoke test so the scratch tip is known-good.
- In the Real Branch Phase, create the real branch from **this same re-fetched
  base branch tip** (not the stale original starting commit), so the real
  branch already contains the newly landed base commits and its post-merge tree
  can match the synced scratch tip.

### Real Branch Phase
12. **Create the real merge branch from the re-fetched base branch tip** (see the scratch base-sync step above; this is the updated base, e.g. `origin/latestw_all`, which coincides with the original starting commit only if no PRs landed since):
    ```pwsh
    # Check out the re-fetched base branch tip (updated base)
    # MCP Tool: mcp_openssh-server_Invoke_Git
    # Operation="Checkout", Target="<base-remote>/<base-branch>"   # e.g. origin/latestw_all

    # Create the real merge branch from there
    # MCP Tool: mcp_openssh-server_Invoke_Git
    # Operation="CreateBranch", Branch="merge-v<VERSION>-<YYYYMMDD>"
    ```

13. **Perform a single merge** of the final upstream target:
    ```pwsh
    # MCP Tool: mcp_openssh-server_Invoke_Git
    # Operation="Merge", CommitHash="<final-upstream-commit-or-tag>"
    ```
    This creates one merge commit covering all upstream commits in the range.

14. **Resolve conflicts by copying the resolved files from the scratch branch:**
    For each conflicted file, replace it with the already-resolved version from the scratch branch and stage it:
    ```pwsh
    # In a terminal (no dedicated MCP wrapper needed):
    git checkout scratch-merge-v<VERSION>-<YYYYMMDD> -- <conflicted_file>

    # Then stage:
    # MCP Tool: mcp_openssh-server_Invoke_Git
    # Operation="Add", Path="<conflicted_file>"
    ```

    > **⚠️ Copying only the conflicted files is not sufficient.** Many fixes on
    > the scratch branch were made to files that **auto-merged without conflict**
    > — build fixes, `config.h.vs` defines, `.vcxproj` edits, `win32compat`
    > shims, regress-test adaptations, `version.rc`. Those files do **not**
    > appear in `ConflictedFiles` on the real branch, so a per-file copy of only
    > the conflicted set silently drops them. You **must** reconcile the full
    > tree against the scratch tip.

    **Recommended (whole-tree copy)** — guarantees the real branch's tree exactly
    matches the validated scratch tip in one shot:
    ```pwsh
    # After the merge reports conflicts (do NOT abort):
    git checkout scratch-merge-v<VERSION>-<YYYYMMDD> -- .
    git add -A
    ```

    **If you instead copied files individually, run a reconciling diff** and copy
    over anything that still differs from the scratch tip:
    ```pwsh
    # List every path where the real branch differs from the scratch tip.
    # This surfaces the auto-merged-but-edited files a conflict-only copy missed.
    # MCP Tool: mcp_openssh-server_Invoke_Git
    # Operation="Diff", Range="scratch-merge-v<VERSION>-<YYYYMMDD>", NameOnly=true
    #
    # For each unexpected path, copy it from scratch and stage it:
    #   git checkout scratch-merge-v<VERSION>-<YYYYMMDD> -- <path>
    ```
    The only differences that should remain after reconciling are the build-fix
    commits you intend to replay separately in step 15. Before completing the
    merge, run `mcp_openssh-server_Test_MergeConflictMarkers` to confirm no
    markers survived the copy.

15. **Complete the merge and apply build fixes:**
    ```pwsh
    # MCP Tool: mcp_openssh-server_Invoke_Git
    # Operation="MergeContinue"
    ```
    If you used the per-file copy in step 14, replay the build-fix commits made on the scratch branch (cherry-pick or re-apply) as separate commits after the merge commit. If you used the whole-tree copy, the build fixes are already included in the merge commit's tree.

16. **Final build and validation** on the real branch.

---

## Build Phase

**📖 Detailed Instructions:** [Build Instructions](../build.instructions.md)

7. **Initial build attempt:**
   Use the Start-OpenSSHBuild MCP tool:
   - **MCP Tool Name**: `mcp_openssh-server_Start_OpenSSHBuild`
   - **Parameters**: `Configuration="Release"`, `Architecture="x64"`

8. **Resolve compilation errors (iterative process):**

   **Common Areas to Check:**
   - **config.h.vs updates:** New preprocessor definitions
   - **Function signatures:** Windows equivalents for Unix functions
   - **Build system changes:** Makefile vs Visual Studio projects
   - **New dependencies:** Windows compatibility verification

9. **Update Visual Studio projects:**
   - Check Makefile for added/removed binaries
   - Create/update .vcxproj files as needed
   - Update Win32-OpenSSH.sln solution file
   - Ensure Windows-applicable binaries only

10. **Commit build fixes:**
    ```pwsh
    # Use a terminal command: the MCPServerPS wrapper mangles embedded
    # newlines in Invoke-Git's Message parameter, so the conventional
    # header + body commit format must be expressed as repeated -m flags.
    git commit -m "Fix compilation errors for <VERSION>" `
               -m "Changes:" `
               -m "- Updated config.h.vs with <new definitions>" `
               -m "- Added Windows equivalent for <function>" `
               -m "- Updated project files for <binary changes>"
    ```

---

## Testing Phase

**📖 Detailed Instructions:** [Testing Instructions](../testing.instructions.md)

11. **Basic functionality test:**
    ```pwsh
    # Set up SSH service (see testing.instructions.md)
    ssh.exe <username>@localhost
    ```

12. **Troubleshoot connection issues:**
    - Enable verbose logging
    - Check service configuration
    - Use debugger if necessary
    - Verify certificate/key handling

13. **Commit any test fixes:**
    ```pwsh
    # Use a terminal command (multi-line Messages break the MCP wrapper):
    git commit -m "Fix runtime issues for <VERSION>" `
               -m "Issues resolved:" `
               -m "- <specific problem and solution>"
    ```

---

## Submission Phase

### Creating the Pull Request
14. **Push to fork:**
    ```pwsh
    # MCP Tool: mcp_openssh-server_Invoke_Git
    # Operation="Push", Remote="origin", Branch="merge-v<VERSION>-<DATE>"
    ```

15. **Generate PR review artifacts (conflict-resolution summary + merge-commit diff view):**
    The merge commit touches 300+ files, so reviewers cannot easily find the
    actual conflict resolutions inside it. Produce two artifacts to attach to the
    PR (see [PR #871](https://github.com/PowerShell/openssh-portable/pull/871) for
    an example). These are review aids — **do not commit them to the branch**;
    attach them to the PR.

    - **Conflict-resolution summary** (`V<VERSION>_Merge_Conflict_Resolutions.md`):
      a per-file *what / why / how* write-up of every resolved conflict plus any
      cleanly auto-merged upstream change that still needed a Windows follow-up
      (build fixes, `config.h.vs`, `.vcxproj`, `win32compat` shims, regress-test
      adaptations, `version.h`/`version.rc`). Structure it with the PR-summary
      guidance in the [resolve-merge-conflict skill](../../skills/resolve-merge-conflict/SKILL.md).

    - **Merge-commit diff view** (`V<VERSION>-Merge_Commit_Diff_Viewer.html`):
      a rendered diff of ONLY the conflict resolutions, produced from the single
      merge commit with `--remerge-diff` (which shows how the merge *resolved*
      conflicts, not every upstream file change):
      ```pwsh
      # <merge-commit> = the single merge commit created on the real branch
      git show --remerge-diff <merge-commit> > V<VERSION>-Merge_Commit_Diff.diff
      npx diff2html-cli -i file -s side -F V<VERSION>-Merge_Commit_Diff_Viewer.html -- V<VERSION>-Merge_Commit_Diff.diff
      ```

16. **Create Pull Request:**
    - Target: `PowerShell/openssh-portable:<branch>` (typically the branch you started from, e.g., latestw_all)
    - Title: `Merge upstream OpenSSH <VERSION>`
    - Include comprehensive description of changes and resolutions
    - Attach the two review artifacts from step 15

17. **Normalize upstream workflow triggers for Windows fork:**
    - Ensure merged upstream workflow files under `.github/workflows/*.yml` are dispatch-only in this fork.
    - Keep `workflow_dispatch` enabled and disable automatic triggers (`push`, `pull_request`, `schedule`) unless explicitly required for this fork.
    - Preserve trigger blocks as commented context where practical so future re-syncs are straightforward.

18. **Address CI/test failures:**
    - Monitor automated tests
    - Fix any Windows-specific test failures
    - Ensure all checks pass

19. **Request review:**
    - Tag appropriate PowerShell team reviewers
    - Provide context for complex conflict resolutions

---

## Success Criteria

**The merge is complete when:**
- [ ] All merge conflicts resolved with documented reasoning
- [ ] Solution builds successfully on Windows
- [ ] Basic SSH connection test passes
- [ ] All CI tests pass
- [ ] Upstream workflow triggers normalized to dispatch-only for this fork
- [ ] Conflict-resolution summary and merge-commit diff view generated and attached to the PR
- [ ] PR approved and ready for merge

---

## AI Agent Resources

AI agents should utilize these additional resources:

- **[Reference Analysis](./research.instructions.md)** - Intelligence gathering protocols
- **[Merge Details](./merge-details.instructions.md)** - Comprehensive merge process, conflict resolution, and automation algorithms
- **[Testing Instructions](../testing.instructions.md)** - Detailed validation procedures

**For AI Agents:**
1. **Start with this overview** - Follow the phases and track progress commit-by-commit
2. **Follow decision trees** - Refer to AI agent instructions for algorithmic guidance
3. **Document everything** - Maintain detailed commit messages and resolution rationale
4. **Use automated testing** - Leverage provided test scripts for validation
5. **Escalate when needed** - If complexity exceeds capabilities, document and request human intervention

**Success Criteria Check:**
The merge process is successful when an AI agent can complete all phases independently and produce a Pull Request that meets all quality standards without human intervention.

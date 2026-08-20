---
name: merge-upstream
description: Assist with merging upstream OpenSSH commits into the PowerShell fork.
tools:
  ['vscode', 'execute', 'read', 'edit', 'search', 'web', 'agent', 'openssh-server/*', 'todo']
---
# OpenSSH Upstream Merge Agent

## Agent Purpose
This agent assists with merging upstream OpenSSH commits into the PowerShell fork (PowerShell/openssh-portable). It handles the complete workflow from environment verification through pull request submission.

**Note:** This agent has access to specialized MCP (Model Context Protocol) tools that automate commit analysis and CI status checking. When available, use the MCP tools instead of running scripts manually.

## Agent Capabilities

### Core Functions
- **Environment verification and setup**
- **Commit group analysis** using Get-CommitGroups MCP tool
- **Two-phase merge**: (1) incremental work on a scratch branch (batched merges, conflict resolution, build fixes, validation); (2) create the real merge branch from the same starting point, perform a single merge of the final upstream target, and resolve any conflicts by copying the already-resolved files from the scratch branch.
- **Windows-specific build system updates**
- **Compilation and testing**
- **Documentation and PR preparation**

### Key Tools Available

1. **Get-CommitGroups MCP Tool** - Groups commits by CI presence or success
   - **Access**: Available via MCP server
   - **MCP Tool Name**: `mcp_openssh-server_Get_CommitGroups`
   - **Parameters**:
     - `GitHubTag` (string, optional): GitHub tag to start from (e.g., "V_10_0_P2")
     - `StartCommit` (string, optional): Commit SHA to start from
     - `EndCommit` (string, optional): Commit SHA to end at (default: HEAD - most recent upstream commit)
     - `FirstChunkOnly` (boolean, optional): Stop after finding first chunk
     - `GroupByCIPresence` (boolean, optional): Group by CI presence instead of CI success
   - **Required Usage**: Always pass `-FirstChunkOnly`. The value of `-GroupByCIPresence` is determined by the user-supplied **CI grouping mode** (see Phase 0):
     - `presence` → `GroupByCIPresence=true` (batches end at any commit with CI runs)
     - `success`  → `GroupByCIPresence=false` (batches end only at commits with successful CI)
   - **If the user has not specified a mode, ask before invoking the tool.** Do not assume a default.
   - **Usage**: Use the MCP tool function directly - it handles all GitHub API calls
   - **If tool unavailable**: ERROR - This tool is required for the merge workflow

2. **Start-OpenSSHBuild MCP Tool** - Build automation
    - **MCP Tool Name**: `mcp_openssh-server_Start_OpenSSHBuild`
    - **Parameters**:
       - `Configuration` (string, optional): Build configuration - "Debug" or "Release" (default: "Release")
       - `Architecture` (string, optional): Target architecture - "x64", "x86", "ARM", "ARM64". **Defaults to the host machine's architecture** (auto-detected). If you pass an architecture that does not match the host, the tool throws unless `-AllowArchMismatch` is also passed. Do NOT hard-code `x64`.
       - `AllowArchMismatch` (switch, optional): Permit building for a non-host architecture (e.g. cross-compiling x64 on an ARM64 host).
       - `Clean` (boolean, optional): Perform clean build (default: false)
    - **If tool unavailable**: ERROR - This tool is required for the merge workflow

3. **Test-OpenSSHFunctionality MCP Tool** - Functional testing
   - **MCP Tool Name**: `mcp_openssh-server_Test_OpenSSHFunctionality`
   - **Parameters**:
     - `Configuration` (string, optional): Build configuration - "Debug" or "Release" (default: "Release")
     - `Architecture` (string, optional): Target architecture. **Defaults to the host architecture**; mismatches are blocked unless `-AllowArchMismatch` is passed. Use the same architecture you built with.
     - `SkipFirewall` (boolean, optional): Skip firewall configuration (default: false)
     - `NoCleanup` (boolean, optional): Skip cleanup for debugging (default: false)
   - **If tool unavailable**: ERROR - This tool is required for the merge workflow

4. **Get-ConflictContext MCP Tool** - Three-way conflict context for high-complexity conflicts
   - **MCP Tool Name**: `mcp_openssh-server_Get_ConflictContext`
   - **When to use**: ONLY when `assess_conflict_complexity()` returns `HIGH_COMPLEXITY`
   - **Parameters**:
     - `FilePath` (string, required): Path to the conflicted file relative to the repository root
     - `CommitHash` (string, required): The upstream commit SHA being cherry-picked that caused the conflict
     - `ContextLines` (integer, optional): Lines of context above/below each hunk match (default: 40)
     - `MaxTotalLines` (integer, optional): Maximum total lines across all three versions and all hunks (default: 150 — ~50 per version). Increase if broader context is needed.
   - **What it returns**: For each hunk in the upstream diff — excerpts from three versions:
     - `UpstreamBefore`: The file as it existed in upstream *before* this commit
     - `UpstreamAfter`: The file in upstream *after* this commit
     - `OurFork`: The corresponding region in our fork (located by content-anchor matching, not line numbers)
   - **Budget**: `max(10, floor(MaxTotalLines / 3 / hunkCount))` lines per version per hunk; a warning is added to `Message` if the 10-line minimum floor is applied
   - **If tool unavailable**: Fall back to reading the conflicted file directly and using `Invoke_Git Operation="Show"` and `Operation="Diff"` to gather context manually

5. **Git** - Version control operations
   - Merge: `Invoke-Git Operation="Merge" CommitHash="<ref>"` (uses `--no-ff`)
   - MergeContinue / MergeAbort for conflict flow
   - Checkout from another branch: `git checkout <branch> -- <path>` (used to copy resolved files from scratch → merge branch)
   - Cherry-pick operations remain available for other use cases
   - Status: `git status`
   - Remotes: `origin`, `upstream-pwsh`, `upstream`
   - **Do NOT enable `rerere.enabled`.** The two-phase merge workflow does not rely on rerere; resolutions are copied wholesale from the scratch branch in Phase 6. If `rerere.enabled` is set in the local repo, disable it (`git config --local rerere.enabled false; git config --local rerere.autoupdate false`) so cached resolutions cannot silently influence batch merges.

6. **vcpkg dependency management** - Vendored library installation and updates
   - **Install tool**: `.\.github\tools\Install-VcpkgDependencies.ps1` (also exposed via MCP as `mcp_openssh-server_Install_VcpkgDependencies` when registered).
     - When to use: build fails because `contrib/win32/openssh/vcpkg_installed/<triplet>-custom/` is missing (e.g., on a fresh clone or after `vcpkg.json` changes).
     - First-time setup: run with `-Bootstrap`. Multi-arch parity with CI: `-Architecture x64,x86,ARM,ARM64`.
     - Default `-Architecture` matches `Start-OpenSSHBuild` (the host architecture). Install the triplet(s) for the architecture(s) you will build.
   - **Update skill**: [.github/skills/update-vcpkg-port/SKILL.md](../skills/update-vcpkg-port/SKILL.md).
     - When to use: an upstream merge bumps a vendored dependency (libressl, libfido2, libcbor, zlib), or upstream OpenSSH starts requiring a newer minimum.
     - The skill orchestrates `Update-VcpkgPort.ps1`, walks the patch-rejection decision tree, validates with the install tool and a build, and produces a commit message.
   - **Reference**: [vcpkg.instructions.md](../instructions/vcpkg.instructions.md) for layout, custom triplets, and overlay-port rationale.

7. **Get-RemainingCommitCount MCP Tool** - Merge progress tracking
   - **MCP Tool Name**: `mcp_openssh-server_Get_RemainingCommitCount`
   - **Parameters**: `StartRef` (required) — ref to count from; `EndRef` (optional, default `HEAD`) — end tag/commit.
   - **When to use**: at the start of each batch (and when reporting progress) to tell the user how many upstream commits remain between the current position and the end tag/HEAD.

8. **Test-MergeConflictMarkers MCP Tool** - Leftover conflict-marker guard
   - **MCP Tool Name**: `mcp_openssh-server_Test_MergeConflictMarkers`
   - **Parameters**: `IncludeAll` (switch) to also scan `.github/instructions|agents|prompts|skills` (excluded by default because those docs contain illustrative markers); `FailOnDivider` (switch) to also flag bare `=======`.
   - **When to use**: after resolving each batch's conflicts and **before** committing/continuing the merge — verifies no `<<<<<<<`/`=======`/`>>>>>>>` markers or unmerged paths remain. Run again on the real branch after copying files from scratch.

9. **Sync-VersionResource MCP Tool** - version.rc ↔ version.h sync
   - **MCP Tool Name**: `mcp_openssh-server_Sync_VersionResource`
   - **Parameters**: `DryRun` (switch) to preview.
   - **When to use**: whenever the merge changes `version.h` (nearly every merge). After resolving `version.h`, run this to rewrite `contrib/win32/openssh/version.rc` numbers to match. See [Pattern 7 in merge-details](../instructions/merge/merge-details.instructions.md).

### Conflict-resolution subagent and skills

- **conflict-review agent** ([conflict-review.agent.md](./conflict-review.agent.md)) — after resolving a batch's conflicts (and running `Test-MergeConflictMarkers`), **delegate the resolved diff to this review-only subagent** for a second pass before continuing the merge. It audits for leftover markers, prefer-upstream bias, balanced Windows guards, silently auto-merged changes needing Windows follow-up, regress-test adaptation, and version sync, then returns APPROVE or CHANGES-REQUIRED. Address CHANGES-REQUIRED items before proceeding.
- **resolve-merge-conflict skill** ([resolve-merge-conflict/SKILL.md](../skills/resolve-merge-conflict/SKILL.md)) — read when resolving conflicts; encodes the prefer-upstream-and-adapt procedure, strategy preference order, silent auto-merge hunting, regress/version sync, and how to summarize resolutions for the PR.
- **merge-retrospective skill** ([merge-retrospective/SKILL.md](../skills/merge-retrospective/SKILL.md)) — run after the merge PR lands to feed new conflict-resolution patterns back into the instructions/skills/agents/tools.

## Workflow Phases

### Phase 0: Research and Planning
**Objective:** Understand the merge scope, requirements, and context

**Steps:**
1. **Confirm user inputs** required for the workflow:
   - **Start ref** (tag or commit) — REQUIRED.
   - **End ref** (commit) — OPTIONAL (defaults to HEAD).
   - **CI grouping mode** — REQUIRED. Ask the user to choose:
     - `presence` (recommended): batches end at any commit with CI runs (passing or failing). Smaller batches, more frequent checkpoints.
     - `success`: batches end only at commits with successful CI. Larger batches, fewer checkpoints.
   - Record the choice; it will be passed as `GroupByCIPresence` to every `Get-CommitGroups` call in Phases 2 and 5.
   - If any required input is missing, ask the user before proceeding.

2. **Read all merge instructions** from `.github/instructions/merge/` folder:
   - `merge-process-overview.instructions.md` - Primary merge workflow and process overview
   - `research.instructions.md` - Research methodology and analysis requirements
   - `merge-details.instructions.md` - Detailed conflict resolution strategies and patterns

2. **Analyze upstream changes:**
   - Review release notes for target version
   - Identify breaking changes and new features
   - Note security fixes and critical updates
   - Assess Windows-specific impact

3. **Review historical context:**
   - Examine previous merge PRs for patterns
   - Identify recurring conflict areas
   - Note Windows-specific workarounds from past merges
   - Document lessons learned from previous merges

**Success Criteria:**
- All merge instructions read and understood
- Upstream changes analyzed and documented
- Ready to proceed with environment setup

### Phase 1: Pre-Merge Setup
**Objective:** Verify environment and establish baseline

**Steps:**
1. **Run prerequisite verification via MCP tool:**
   - **MCP Tool Name**: `mcp_openssh-server_Test_MergePrerequisites`
   - **Parameters**:
     - `TargetVersion` (string, required): Upstream version/tag to start from (e.g., "V_10_0_P2")

   This single tool verifies:
   - Git, PowerShell, Visual Studio are available
   - Repository remotes are configured (origin, upstream, upstream-pwsh)
   - Target version/tag exists in upstream
   - Working directory is clean (no uncommitted changes)
   - Baseline build passes from current branch
   - First commit batch is identified

2. **Proceed only if tool reports success:**
   - Tool must return `Success: true`
   - Tool must display "ALL PREREQUISITES MET"
   - If tool fails, fix reported issues before continuing

3. **Establish baseline warning count:**
   - **MCP Tool Name**: `mcp_openssh-server_Test_OpenSSHBuild`
   - **Parameters**: `Configuration="Release"` (Architecture defaults to the host; pass it explicitly only when it matches the host)
   - Parse and document the current warning count and categories
   - This baseline will be used to detect new warnings introduced during merge
   - Store baseline for comparison after each build

4. **Create the scratch branch only:**
   ```pwsh
   # Create the scratch branch — ALL work (merging, conflict resolution,
   # build fixes, validation) happens here. The real merge branch will be
   # created in Phase 6, after all batches are complete.
   # MCP Tool: mcp_openssh-server_Invoke_Git
   # Operation="CreateBranch", Branch="scratch-merge-v<VERSION>-<YYYYMMDD>"
   ```

   **Important:** Record the exact starting commit (the tip of the branch you started from). Phase 6 needs it to create the real merge branch from the same point.

**Success Criteria:**
- Prerequisite tool reports all checks passed
- Baseline warning count established and documented
- Scratch branch created from the chosen starting point
- Starting commit recorded for later use in Phase 6
- Currently on the scratch branch
- Ready to begin Phase 2 (scratch-branch incremental merge)

### Phase 2: Scratch Branch — Incremental Merge
**Objective:** Merge commits in batches on the scratch branch, resolving conflicts directly. All conflict resolutions, build fixes, and validation work live on the scratch branch — nothing is recorded for later replay.

**Steps:**
1. **Get first commit batch** using Get-CommitGroups MCP tool:
   - **MCP Tool Name**: `mcp_openssh-server_Get_CommitGroups`
   - **Parameters** (set `GroupByCIPresence` from the user's Phase 0 CI grouping mode — `true` for `presence`, `false` for `success`):
     - For first batch: `GitHubTag="V_10_0_P2"`, `EndCommit="<target_end_commit>"`, `FirstChunkOnly=true`, `GroupByCIPresence=<user_choice>`
     - For subsequent batches: `StartCommit="<previous_end_commit>"`, `EndCommit="<target_end_commit>"`, `FirstChunkOnly=true`, `GroupByCIPresence=<user_choice>`
   - **Note**: If `EndCommit` is not specified, the tool will merge up to the most recent upstream commit (HEAD)

   **The tool returns structured data:**
   ```json
   {
     "ChunkNumber": 1,
     "StartCommit": "609fe2c",
     "EndCommit": "6fb728d",
     "StartCommitFull": "609fe2cae2459d721ac11d23cd27b8a94397ef3c",
     "EndCommitFull": "6fb728df50c1afd338cb0223a84ce24579577eff",
     "CommitCount": 12,
     "StartMessage": "upstream: rework the text for -3 to make it clearer",
     "EndMessage": "Run all tests on Cygwin again."
   }
   ```

2. **Display batch information** for verification.

3. **Merge the batch endpoint:**
   ```pwsh
   # Merge all commits up to the batch endpoint
   # MCP Tool: mcp_openssh-server_Invoke_Git
   # Operation="Merge", CommitHash=$result.EndCommitFull
   ```
   This brings in all commits from the previous merge point through `EndCommitFull` in a single merge. The `--no-ff` flag ensures a merge commit is always created.

4. **If conflicts occur, resolve each one directly:**
   - Read the [resolve-merge-conflict skill](../skills/resolve-merge-conflict/SKILL.md) and follow it.
   - For each conflicted file reported in the merge result's `ConflictedFiles`:
     a. Resolve the conflict in place following the **prefer-upstream-and-adapt** principle and Windows preservation patterns (see [merge-details.instructions.md](../instructions/merge/merge-details.instructions.md)).
     b. Stage the resolved file: `Invoke-Git Operation="Add" Path="<file>"`
   - The resolved files on the scratch branch are the source of truth that will be copied to the real merge branch in Phase 6. No resolution log or rerere recording is needed.

5. **Verify no conflict markers remain, then complete the merge:**
   ```pwsh
   # MCP Tool: mcp_openssh-server_Test_MergeConflictMarkers
   # (must report no markers and no unmerged paths before continuing)

   # MCP Tool: mcp_openssh-server_Invoke_Git
   # Operation="MergeContinue"
   ```

6. **Hunt for silently auto-merged changes needing Windows work:**
   Even when there were no conflicts, upstream changes can merge cleanly yet
   require Windows follow-up (ssh-agent, `config.h.vs`, `.vcxproj`, new POSIX
   calls). Diff the batch range (`NameOnly=true`) and check those areas — see
   [Pattern 6 in merge-details](../instructions/merge/merge-details.instructions.md).
   If `version.h` changed, run `mcp_openssh-server_Sync_VersionResource` to update
   `version.rc`.

7. **Delegate the resolved batch to the conflict-review subagent:**
   Hand the batch's resolved diff to the [conflict-review agent](./conflict-review.agent.md)
   for a review-only second pass. Address any CHANGES-REQUIRED items it returns
   before proceeding to the build.

**Conflict Resolution Patterns:**
- **Prefer upstream:** Take the upstream change and adapt for Windows; do not keep old fork behavior just to minimize diff.
- **Windows-specific code:** Preserve with `#ifdef WINDOWS`
- **Removed/Unix-only features:** Exclude with `#ifndef WINDOWS` (wrap, never delete upstream code)
- **Build system changes:** Update `.vcxproj` / `.sln` files (use `\r\n` line endings)
- **Configuration:** Add new defines to `contrib/win32/openssh/config.h.vs`

### Phase 3: Build and Validation
**Objective:** Build successfully and validate if CI was successful

**Build/validation gating rule:** Build and validation are only required for batches whose merged commit range touches at least one C source or header file (`*.c` or `*.h`, including under `contrib/win32/**`). For batches that only modify non-compiled files (e.g., `*.md`, `*.0`/`*.5` man pages, `regress/*.sh`, `.github/**`, `Makefile.in` text-only changes that do not affect VS projects), skip the build and validation steps and proceed directly to Phase 4 (Summary and Approval), noting in the summary that build was skipped because no compiled sources changed.

**Detecting code impact:** Before Step 1, list the files changed by the batch:
```pwsh
# MCP Tool: mcp_openssh-server_Invoke_Git
# Operation="Diff", Range="<previous_batch_end>..<current_batch_end>", NameOnly=true
```
If any returned path matches `*.c` or `*.h`, perform the build/validation steps below. Otherwise, record "no compiled sources changed" and skip to Phase 4.

**Steps (when code impact detected):**
1. **Build the merged code:**
   - **MCP Tool Name**: `mcp_openssh-server_Start_OpenSSHBuild`
   - **Parameters**: `Configuration="Release"` (Architecture defaults to the host machine's architecture — do not hard-code `x64`)

2. **If build fails, fix compilation errors:**
   - Document all compilation errors from build output
   - Fix source code issues (add Windows compatibility defines, update function signatures, add platform guards)
   - Update Visual Studio project files (add/remove source files, create projects for new binaries)
   - Rebuild until successful
   - Commit build fixes with detailed description

3. **Run the functionality smoke test (mandatory after every successful build):**
   - **MCP Tool Name**: `mcp_openssh-server_Test_OpenSSHFunctionality`
   - **Parameters**: (use defaults — Release, host architecture)

   This test installs service, creates test user, validates SSH connectivity.
   If tests fail, fix issues and commit fixes.
   **Do not proceed** to next batch until the smoke test passes.

4. **Full CI suite is NOT run per-batch by default.**
   Run `mcp_openssh-server_Invoke_OpenSSHTests` with `TestSuite="All"` ONLY when:
   - The user explicitly requests it for a batch, OR
   - Before transitioning to the real merge branch (Phase 6), OR
   - Before creating the PR.

   When a full-suite run is requested and any sub-suite fails, re-run only the failing
   suite (`TestSuite="Unit"`, `TestSuite="Bash"`, or `TestSuite="E2E"`). For a single
   failing bash case, use `TestSuite="Bash"` with `BashTestFilePath="<absolute-path>"`.

**Common Build Fixes:**
- Missing source files in .vcxproj files
- Removed files still referenced in projects
- Missing function implementations (add to win32compat)

**Success Criteria:**
- Clean build with no errors
- All expected binaries generated
- `Test-OpenSSHFunctionality` smoke test passes
- Full CI suite (if explicitly requested) passes

### Phase 4: Summary and Approval
**Objective:** Summarize changes and get approval before proceeding

**MANDATORY:** Before proceeding to the next commit batch, provide summary and wait for user approval.

**Steps:**
1. **Generate batch summary:**
   ```markdown
   ## Batch Completion Summary

   **Batch:** [StartCommit]..[EndCommit] (<count> commits)
   **End Commit CI Status:** <success/failure/no_ci/has_ci>

   ### Changes in this Batch:
   - <List key changes from commit messages>
   - <Note any significant upstream features>
   - <Mention security fixes if any>

   ### Conflicts Resolved:
   - <file1>: <resolution strategy>
   - <file2>: <resolution strategy>

   ### Build Status:
   - Build: ✅ Success / ❌ Failed
   - Build fixes applied: <Yes/No - describe if yes>

   ### Validation Status:
   - Smoke test (`Test-OpenSSHFunctionality`): ✅ Passed / ⏭️ Skipped (no build) / ❌ Failed
   - Full CI suite: ⏭️ Not run (default) / ✅ Passed / ❌ Failed
   - Test fixes applied: <describe if any>

   ### Next Steps:
   - Next batch will start from commit: <EndCommitFull>
   - Estimated remaining batches: <if known>

   **Ready to proceed to next batch?**
   ```

2. **Wait for user response:**
   - User responds "yes" / "continue" / "proceed" → Continue to Phase 5
   - User responds "no" / "stop" / "wait" → Pause and await further instructions
   - User provides feedback → Address concerns and re-summarize

**Success Criteria:**
- Summary provided with all required information
- User approval received to proceed

### Phase 5: Scratch Branch Iteration
**Objective:** Process remaining commit batches on the scratch branch until all upstream commits are merged.

**Steps:**
1. **Return to Phase 2** with `-StartCommit` set to previous batch's end commit and `-EndCommit` set to target end commit
2. **Repeat Phases 2-4** for each batch:
   - Get next batch with Get-CommitGroups (passing both StartCommit and EndCommit)
   - Merge batch endpoint (`Invoke-Git Merge`)
   - Resolve conflicts directly (no resolution log)
   - Build (only if the batch touches `*.c` or `*.h` — see Phase 3 gating rule)
   - Validate (only if build was performed and the batch ends with successful CI)
   - Summarize and get approval
3. **Continue** until the target end commit is reached (or HEAD if no end commit was specified)
4. **Sync the scratch branch with its base branch (re-fetched):**
   PRs may have merged into the base branch (e.g. `latestw_all`) since work
   started. Bring the scratch branch up to date so the real branch (created from
   the refreshed base in Phase 6) matches:
   ```pwsh
   # Re-fetch the base branch
   # MCP Tool: mcp_openssh-server_Invoke_Git  →  Operation="Fetch", Remote="<base-remote>"
   # Merge the refreshed base tip into the scratch branch and resolve any conflicts
   # MCP Tool: mcp_openssh-server_Invoke_Git  →  Operation="Merge", CommitHash="<base-remote>/<base-branch>"
   ```
   Re-run `Test-MergeConflictMarkers`, rebuild, and re-run the smoke test if this
   sync touched compiled sources. Record the refreshed base tip for Phase 6.
5. **Final scratch-branch validation:**
   - **MCP Tool Name**: `mcp_openssh-server_Test_OpenSSHFunctionality`
   - **Parameters**: (use defaults — Release, host architecture)

**Success Criteria:**
- All commit batches processed on scratch branch
- Build remains stable after each batch
- All successful CI checkpoints validated
- Scratch branch contains the fully merged, conflict-resolved, building, and tested state
- Ready to proceed to real-branch single merge

### Phase 6: Real Branch — Single Merge with Copy-from-Scratch Resolution
**Objective:** Produce clean history on the real merge branch with a single merge commit preserving all upstream SHAs. Conflict resolutions are copied wholesale from the scratch branch — no rerere replay, no resolution log.

**Steps:**
1. **Create the real merge branch** from the refreshed base tip (recorded in Phase 5's base-sync step), so the single merge below yields a tree matching the scratch branch:
   ```pwsh
   # Re-fetch the base branch if you have not just done so, then check out its tip
   # MCP Tool: mcp_openssh-server_Invoke_Git
   # Operation="Checkout", Target="<base-remote>/<base-branch>"   # e.g. upstream-pwsh/latestw_all

   # Then create the real merge branch from there
   # MCP Tool: mcp_openssh-server_Invoke_Git
   # Operation="CreateBranch", Branch="merge-v<VERSION>-<YYYYMMDD>"
   # Example: Branch="merge-v10.0P2-20260109"
   ```
   > If the base branch has NOT advanced since Phase 1, this is equivalent to the original starting commit. If it HAS advanced (PRs merged in the meantime), creating from the refreshed base tip is required — the scratch branch was synced to it in Phase 5, so both branches share the same base.

2. **Perform a single merge** of the final upstream target:
   ```pwsh
   # MCP Tool: mcp_openssh-server_Invoke_Git
   # Operation="Merge", CommitHash="<final-upstream-commit-or-tag>"
   ```
   This creates one merge commit covering all upstream commits in the range.

3. **Resolve conflicts by copying from the scratch branch — and account for silently auto-merged files:**

   > ⚠️ **Do not copy only the conflicted files.** Git auto-merges files that had
   > no textual conflict, but some of those were hand-edited on the scratch branch
   > (build fixes, `config.h.vs`, `.vcxproj`, `win32compat`, `version.rc`,
   > regress-test adaptations). Copying only `ConflictedFiles` silently drops those
   > edits. Use the whole-tree copy below (recommended), or reconcile with a diff.

   **Recommended — whole-tree copy** (guarantees the real branch tree matches scratch):
   ```pwsh
   # After `git merge` reports conflicts (do NOT abort):
   git checkout scratch-merge-v<VERSION>-<YYYYMMDD> -- .
   # MCP Tool: mcp_openssh-server_Invoke_Git  →  Operation="Add", Path="."
   ```

   **Alternative — per-file copy + reconciling diff** (if you want a smaller, explicit change set):
   ```pwsh
   # Copy each conflicted file:
   git checkout scratch-merge-v<VERSION>-<YYYYMMDD> -- <file>
   ```
   Then find files that differ between the real branch and scratch (i.e. auto-merged
   files that were edited on scratch) and copy those too:
   ```pwsh
   # MCP Tool: mcp_openssh-server_Invoke_Git
   # Operation="Diff", Range="scratch-merge-v<VERSION>-<YYYYMMDD>", NameOnly=true
   ```
   Copy every path this reports, then stage.

4. **Verify the tree matches scratch and no markers remain:**
   ```pwsh
   # MCP Tool: mcp_openssh-server_Invoke_Git
   # Operation="Diff", Range="scratch-merge-v<VERSION>-<YYYYMMDD>", NameOnly=true
   # (should be empty after the whole-tree copy)

   # MCP Tool: mcp_openssh-server_Test_MergeConflictMarkers
   ```

5. **Complete the merge:**
   ```pwsh
   # MCP Tool: mcp_openssh-server_Invoke_Git
   # Operation="MergeContinue"
   ```

6. **Apply build fixes** as separate commits after the merge commit (only if you used the per-file copy in step 3 and did not bring over the build-fix changes):
   - Cherry-pick or re-apply the build-fix commits made on the scratch branch.
   - **CRITICAL: Restore paths.targets before committing:**
     ```pwsh
     # MCP Tool: mcp_openssh-server_Invoke_Git
     # Operation="Checkout", Target=".\contrib\win32\openssh\paths.targets"
     ```

7. **Build and validate on the real branch:**
   - Build: `mcp_openssh-server_Start_OpenSSHBuild` (Release, host architecture)
   - Check warnings: `mcp_openssh-server_Test_OpenSSHBuild`
   - Validate: `mcp_openssh-server_Test_OpenSSHFunctionality`

8. **Clean up scratch branch:**
   ```pwsh
   # The scratch branch is no longer needed once the real branch is verified
   # MCP Tool: mcp_openssh-server_Invoke_Git
   # Operation="Checkout", Target="merge-v<VERSION>-<YYYYMMDD>"
   # Then delete scratch: git branch -D scratch-merge-v<VERSION>-<YYYYMMDD>
   ```

**Success Criteria:**
- Real branch has exactly one merge commit (plus any replayed build-fix commits)
- All upstream commits appear in the DAG with original SHAs
- `git log --first-parent` shows a clean merge history
- Real branch's tree matches the scratch branch's tip (modulo intentional differences)
- Build succeeds and functionality tests pass
- Scratch branch deleted

### Phase 7: Documentation and PR
**Objective:** Document changes and submit for review

**Steps:**
1. Review all merge commits for clarity
2. Document major conflict resolutions — use the PR-summary guidance in the [resolve-merge-conflict skill](../skills/resolve-merge-conflict/SKILL.md) to structure the description
3. Note any Windows-specific changes
4. Normalize merged upstream `.github/workflows/*.yml` triggers to dispatch-only for this fork (keep `workflow_dispatch`, disable `push`/`pull_request`/`schedule`)
5. Push branch: `git push origin merge-v<VERSION>-<DATE>`
6. **Generate PR review artifacts** (attach to the PR; do NOT commit them). The merge commit touches 300+ files, so reviewers need a focused view of just the conflict resolutions — see [PR #871](https://github.com/PowerShell/openssh-portable/pull/871) for an example:
   - **Conflict-resolution summary** `V<VERSION>_Merge_Conflict_Resolutions.md` — a per-file *what / why / how* write-up of every resolved conflict plus any cleanly auto-merged upstream change that still needed a Windows follow-up (build fixes, `config.h.vs`, `.vcxproj`, `win32compat` shims, regress-test adaptations, `version.h`/`version.rc`). Structure it with the [resolve-merge-conflict skill](../skills/resolve-merge-conflict/SKILL.md) PR-summary guidance.
   - **Merge-commit diff view** `V<VERSION>-Merge_Commit_Diff_Viewer.html` — a rendered diff of ONLY the conflict resolutions, from the single merge commit via `--remerge-diff`:
     ```pwsh
     git show --remerge-diff <merge-commit> > V<VERSION>-Merge_Commit_Diff.diff
     npx diff2html-cli -i file -s side -F V<VERSION>-Merge_Commit_Diff_Viewer.html -- V<VERSION>-Merge_Commit_Diff.diff
     ```
7. Create PR with comprehensive description, attaching the two review artifacts from step 6
8. Add labels and request reviewers

**PR Description Template:**
```markdown
## Merge OpenSSH <VERSION>

This PR merges upstream OpenSSH commits from <START> through <END>.

### Commit Groups
- Batch 1: <start> to <end> (<count> commits)
- Batch 2: <start> to <end> (<count> commits)
...

### Major Changes
- [List significant upstream changes]

### Windows-Specific Resolutions
- [List Windows compatibility fixes]
- [List build system updates]

### Testing
- [x] Builds successfully (host architecture)
- [x] Service starts and runs
- [x] SSH connections work
- [x] Basic operations verified

### Known Issues
- [List any known limitations or issues]
```

**Success Criteria:**
- PR created with complete description
- All CI checks passing
- Reviewers assigned

### Phase 8: Post-Merge Retrospective (after the PR lands)
**Objective:** Capture new conflict-resolution patterns and improve the tooling.

Once the merge PR is **merged**, run the [merge-retrospective skill](../skills/merge-retrospective/SKILL.md).
It reviews the conflicts and Windows follow-ups from this merge and feeds any new
or recurring patterns back into the merge instructions, skills, the conflict-review
agent's checklist, and the tools — so the next merge is smoother. This step is
run separately from the merge itself and can be triggered by the user after merge.

## Decision Points

### When to Use Commit Groups
- **High complexity merge:** >100 commits, significant changes
- **Medium complexity merge:** 50-100 commits, moderate changes
- **Low complexity merge:** <50 commits, minor changes → single merge OK

### Conflict Resolution Strategy
**Always preserve:**
- Windows-specific functionality in `#ifdef WINDOWS` blocks
- Security fixes from upstream
- Build system integrity

**Accept upstream for:**
- Removed deprecated features (e.g., DSA)
- Algorithm updates
- API modernization

**Combine when:**
- Both sides add different functionality
- Windows needs additional compatibility code
- Upstream changes affect Windows-specific code

## Key Files to Monitor

### Frequently Modified
- `config.h` / `config.h.vs` - Configuration defines
- `*.vcxproj` - Visual Studio project files
- `contrib/win32/win32compat/*` - Windows compatibility layer

### Conflict Hotspots
- Authentication code (`auth*.c`)
- Platform-specific code (`platform*.c`)

## Recovery Procedures

### Abort Merge
```bash
git merge --abort
git clean -fd
git reset --hard
```

### Abort Cherry-Pick (if used outside merge workflow)
```bash
git cherry-pick --abort
git clean -fd
git reset --hard
```

### Restart Scratch Branch
```bash
# Delete the scratch branch and recreate from the original starting commit
git branch -D scratch-merge-v<VERSION>-<DATE>
git checkout <starting_commit_recorded_in_phase_1>
git checkout -b scratch-merge-v<VERSION>-<DATE>
```

### Restart from Checkpoint
```bash
git checkout scratch-merge-v<VERSION>-<DATE>
git log --oneline -5  # Verify last successful state
# Continue from there (or recreate scratch branch from the starting commit)
```

### Build Failure Recovery
1. Check build log: `contrib\win32\openssh\OpenSSHRelease<arch>.log` (e.g. `OpenSSHReleasearm64.log` on an ARM64 host)
2. Search for "error C" or "error LNK"
3. Fix errors in order (compilation before linking)
4. Commit fixes separately for clarity

## Best Practices

### Commit Organization
- One logical fix per commit
- Clear commit messages explaining Windows-specific changes
- Reference upstream commit SHAs when applicable

### Testing Between Batches
- Build after each batch that touches `*.c` or `*.h` files (skip for documentation-only / regress-script-only batches)
- Quick smoke test (service start, simple connection)
- Full test only after all batches complete

### Documentation
- Comment complex conflict resolutions in code
- Note Windows-specific workarounds
- Link to upstream issues/PRs when relevant

## Success Metrics
- ✅ All commits from target range merged
- ✅ Clean build with no warnings
- ✅ All tests passing
- ✅ SSH service functional
- ✅ PR approved and merged
- ✅ No regressions reported in first 48 hours

## Reference Links

### Repository Links
- [Upstream OpenSSH](https://github.com/openssh/openssh-portable)
- [PowerShell Fork](https://github.com/PowerShell/openssh-portable)

### Instruction Documents (Phase 0 Required Reading)
- [Merge Process Overview](../instructions/merge/merge-process-overview.instructions.md)
- [Research Instructions](../instructions/merge/research.instructions.md)
- [Merge Details Instructions](../instructions/merge/merge-details.instructions.md)

### Additional Instructions
- [Build Instructions](../instructions/build.instructions.md)
- [Setup Instructions](../instructions/setup.instructions.md)
- [Testing Instructions](../instructions/testing.instructions.md)

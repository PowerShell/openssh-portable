---
name: resolve-merge-conflict
description: |
  WORKFLOW SKILL — Resolve a merge conflict (or a batch of them) when merging
  upstream OpenSSH into this Windows fork, applying the fork's Windows-compat
  conventions, and summarize the resolutions for the pull request. USE FOR:
  deciding how to resolve a specific conflicted file, choosing between
  take-upstream / #ifdef WINDOWS / #ifndef WINDOWS, catching upstream changes
  that merged cleanly but still need Windows follow-up, syncing version.h /
  version.rc, and writing the per-file "what/why/how" resolution notes that go
  into the PR description. DO NOT USE FOR: the overall multi-batch merge
  orchestration (that's the merge-upstream agent) or vcpkg dependency bumps
  (use the update-vcpkg-port skill).
---

# Resolve Merge Conflict Skill

## Purpose

Give a consistent, correct procedure for resolving upstream→fork merge
conflicts on Windows, and for turning those resolutions into clear PR
documentation. This is the detailed "how do I resolve *this* file" companion to
the `merge-upstream` agent's batch orchestration.

## When to Use

- You hit conflicts during a batch merge on the scratch branch and need to
  decide how to resolve each file.
- You want to double-check a resolution follows fork conventions before staging.
- You are assembling the conflict-resolution section of the PR description.

## Core Principle: Prefer Upstream, Adapt for Windows

**Default to taking the upstream change and adding Windows adjustments around
it — do not keep the fork's old behavior just because it was there.** Upstream
owns the protocol/logic direction; the fork's job is to make that work on
Windows, ideally via the `win32compat` layer and, where unavoidable, via
`#ifdef WINDOWS` guards.

Anti-pattern to avoid: forcing upstream's relocated logic back to where the fork
used to have it. Example: OpenSSH split pre-auth / KEX work between
`sshd-session` and `sshd-auth`. The correct resolution **follows upstream's new
placement** and adds Windows-specific handling there; it does **not** drag the
work back into `sshd-session` for Windows just to minimize change. Fighting
upstream's structure creates state-ordering bugs (banner/KEX/post-auth failures)
and recurring future conflicts.

## Resolution Strategies (in order of preference)

1. **Take upstream verbatim.** Security fixes, bug fixes, algorithm/API changes,
   removed deprecated features (e.g. DSA). No Windows divergence needed.

2. **Take upstream + `win32compat`.** Upstream calls a POSIX API; provide/extend
   a `w32_*` shim in `contrib/win32/win32compat/` so the upstream call site
   stays unchanged. Prefer this over inline `#ifdef`.

3. **Take upstream + `#ifdef WINDOWS`.** Both platforms need different code at
   the same site. Keep upstream's code in the `#else` branch verbatim:
   ```c
   #ifdef WINDOWS
       /* Windows implementation */
   #else
       /* upstream code, unchanged */
   #endif /* WINDOWS */
   ```

4. **Exclude on Windows with `#ifndef WINDOWS`.** Upstream code genuinely does
   not apply to Windows (Unix-only feature). Wrap it, don't delete it:
   ```c
   #ifndef WINDOWS
       setup_unix_only_feature();
   #endif /* !WINDOWS */
   ```

**Never** delete upstream additions — removal guarantees the conflict returns on
every future merge.

## Step-by-Step

1. **Enumerate the conflicts.** From the merge result's `ConflictedFiles`, or
   `git status`.

2. **For each file, get three-way context.** For high-complexity files use
   `mcp_openssh-server_Get_ConflictContext` (FilePath + the batch endpoint
   CommitHash). It anchors by content, not line numbers, so it handles the
   fork's line drift. Otherwise read the file and use
   `Invoke-Git Operation="Show"` / `Operation="Diff"`.

3. **Pick a strategy** from the list above. Preserve upstream intent; add the
   minimal Windows adaptation.

4. **Resolve in place and stage:** edit the file, then
   `Invoke-Git Operation="Add" Path="<file>"`.

5. **Verify no markers remain:** `mcp_openssh-server_Test_MergeConflictMarkers`.
   Any `<<<<<<<` / `=======` / `>>>>>>>` / `|||||||` left is a hard stop.

6. **Hunt for silent, clean-merged changes that still need Windows work.** Git
   only flags textual conflicts. Upstream changes can merge cleanly yet require
   follow-up. After each batch, scan the diff (`Invoke-Git Operation="Diff"
   Range="<prev>..<cur>" NameOnly=true`) and check:
   - **ssh-agent:** changes to `ssh-agent.c` / agent protocol are **not** auto-
     reflected in the separate Windows agent under
     `contrib/win32/win32compat/ssh-agent/`. Port relevant logic by hand or
     record a TODO.
   - **config.h.vs:** new feature `#define`s upstream added to `config.h` /
     detected by autoconf must be added to
     `contrib/win32/openssh/config.h.vs` if Windows should have them.
   - **Build system:** new source files in `Makefile.in` must be added to the
     right `.vcxproj` (and solution) with `\r\n` line endings; removed files
     must be dropped from the projects.
   - **New POSIX usage:** fork/exec/signal/pipe/socket-option calls need a
     `w32_*` equivalent in `win32compat`.

7. **Regress tests.** For any touched `regress/*.sh` that already contains
   `if [ "$os" == "windows" ]` blocks, apply the same Windows adaptation to any
   **new** upstream test case in that file (commonly wrapping `diff` with
   `diff --strip-trailing-cr`). Git won't flag these because the existing
   Windows blocks are untouched.

8. **version.h / version.rc.** If `version.h` conflicted, keep the Windows
   fields (`SSH_WINDOWS_VERSION`, `SSH_WINDOWS_BANNER`) and take upstream's
   `SSH_PORTABLE` / OpenBSD version tag. Then sync the resource file:
   `mcp_openssh-server_Sync_VersionResource` (numbers follow version.h;
   descriptive text and the patch-in-ProductVersion-text convention are
   preserved automatically).

9. **Optional second opinion.** Hand the batch to the `conflict-review` agent
   for an independent audit before completing the merge.

## Summarizing Resolutions for the Pull Request

Keep a running note **per conflicted file** as you resolve it; these become the
PR's "Windows-Specific Resolutions" section. For each file capture:

- **What** the upstream change was (one line).
- **Why** a Windows adaptation was or wasn't needed.
- **How** it was resolved (which strategy: took-upstream / win32compat /
  `#ifdef WINDOWS` / `#ifndef WINDOWS` / manual rewrite).

Example lines:

```markdown
### Windows-Specific Resolutions
- `serverloop.c`: Took upstream's channel-handling refactor; wrapped the
  Windows event-based wait in `#ifdef WINDOWS`, upstream select() path kept in `#else`.
- `sshd-auth.c`: Followed upstream's move of the banner exchange into sshd-auth;
  added Windows post-auth message-ordering handling here (not in sshd-session).
- `auth2.c`: Accepted upstream security fix verbatim; no Windows change needed.
- `regress/cfgparse.sh`: New upstream MaxStartups case wrapped with
  `diff --strip-trailing-cr` to match existing Windows blocks.
- `version.h` / `version.rc`: Kept Windows banner fields; synced FILEVERSION /
  ProductVersion to the new upstream version.
```

Also note in the PR:
- **Silent follow-ups performed** (config.h.vs additions, .vcxproj updates,
  win32compat shims, ssh-agent ports).
- **Deferred TODOs** for anything flagged but not ported (e.g. complex ssh-agent
  changes needing Windows-team review).

## Related Assets

- [merge-upstream agent](../../agents/merge-upstream.agent.md) — batch orchestration.
- [conflict-review agent](../../agents/conflict-review.agent.md) — independent audit of resolutions.
- [merge-details.instructions.md](../../instructions/merge/merge-details.instructions.md) — full pattern library.
- Tools: `Get-ConflictContext`, `Test-MergeConflictMarkers`, `Sync-VersionResource`,
  `Get-RemainingCommitCount`.

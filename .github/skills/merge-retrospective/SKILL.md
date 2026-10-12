---
name: merge-retrospective
description: |
  WORKFLOW SKILL — Run a retrospective AFTER an upstream-merge PR has been
  merged, and feed what was learned back into the merge tooling. USE FOR:
  reviewing a completed merge (the merge commit, build/test fixes, and any
  post-review changes), extracting new or recurring conflict-resolution
  patterns, Windows follow-ups, and gotchas, then updating the relevant
  instructions, skills, agents, and tools under .github/ so the next merge is
  smoother. DO NOT USE FOR: performing a merge (use the merge-upstream agent) or
  resolving individual conflicts mid-merge (use the resolve-merge-conflict
  skill).
---

# Merge Retrospective Skill

## Purpose

Close the loop on an upstream merge. Once a merge PR is merged, mine it for
lessons and update the merge tooling so recurring problems become documented
patterns (or automated checks) instead of being rediscovered every cycle.

## When to Use

- Immediately after an upstream-merge PR is merged into the fork's Windows
  branch (e.g. `latestw_all`).
- Periodically, to reconcile several recent merges' lessons at once.

## Inputs

- The merged PR number / URL and its merge commit.
- The upstream version range that was merged (start..end tag or SHA).
- Optionally, notes the merge agent kept during the run (conflict resolutions,
  build fixes, deferred TODOs, reviewer feedback).

## Procedure

### 1. Gather the evidence

- The merge commit and its follow-up commits:
  `git log --first-parent <base>..<mergeHead>` and
  `git show <mergeHead>`.
- Build/test-fix commits made after the merge commit (these reveal what the
  batch merges missed).
- PR review threads: what reviewers flagged, especially anything Windows-
  specific or anything the agent got wrong.
- Any deferred TODOs recorded during the merge (e.g. un-ported ssh-agent
  changes).

### 2. Extract patterns

Sort findings into buckets:

- **New conflict-resolution pattern** — a file/area resolved in a non-obvious
  way that will recur (e.g. a new split-daemon state-ordering rule, a new
  `#ifdef WINDOWS` idiom, a new `win32compat` shim pattern).
- **Silent auto-merge follow-up** — an upstream change that merged cleanly but
  needed manual Windows work (config.h.vs define, .vcxproj source add, ssh-agent
  port, new `w32_*` shim). Note how it was detected so detection can be
  documented/automated.
- **Regress-test adaptation** — a new upstream test that needed Windows tweaks
  (e.g. `diff --strip-trailing-cr`).
- **Build/environment gotcha** — anything about SDK, arch, vcpkg, paths.targets,
  warnings baseline.
- **Tooling gap** — a manual step that a tool/agent/skill could have caught or
  automated.

### 3. Update the tooling

For each pattern, make the smallest change that will help next time:

| Finding type | Where to update |
|---|---|
| New conflict pattern / Windows idiom | [merge-details.instructions.md](../../instructions/merge/merge-details.instructions.md) (add a numbered Pattern) and, if it's a resolver decision, the [resolve-merge-conflict skill](../resolve-merge-conflict/SKILL.md) |
| New silent-follow-up class | resolve-merge-conflict skill checklist + [conflict-review agent](../../agents/conflict-review.agent.md) checklist |
| Regress-test adaptation nuance | merge-details.instructions.md (Pattern 5 family) |
| Build/env gotcha | [build.instructions.md](../../instructions/build.instructions.md) or [testing.instructions.md](../../instructions/testing.instructions.md) |
| Recurring manual step | propose/extend a tool under [.github/tools/](../../tools/); register it in [.github/README.md](../../README.md) |
| Workflow/phase change | [merge-upstream agent](../../agents/merge-upstream.agent.md) and [merge-process-overview.instructions.md](../../instructions/merge/merge-process-overview.instructions.md) |

Keep edits concrete: cite the real file/area from this merge as the example, the
way existing patterns in merge-details do (e.g. "Real example: the OpenSSH 10.3
merge…"). Add the specific upstream version so the example is traceable.

### 4. Record what was NOT changed

If a finding was a one-off (not expected to recur), note it in the PR/retro
summary but do **not** bloat the instructions with it. The goal is durable,
recurring patterns.

### 5. Produce a retro summary

```markdown
## Merge Retrospective — OpenSSH <version> (PR #<n>)

### New/updated patterns
- <pattern> → documented in <file>

### Tooling changes
- <tool/agent/skill> updated/created: <what and why>

### Deferred / follow-up
- <TODO> (owner: <who/team>)

### One-offs (not documented)
- <thing that won't recur>
```

## Guardrails

- Only edit `.github/` tooling docs and scripts here — do **not** touch product
  source in a retrospective.
- Validate any tool you add/modify runs (parse-check + a smoke invocation)
  before finishing, following the conventions of the existing tools.
- Cross-link new assets in [.github/README.md](../../README.md).

## Related Assets

- [merge-upstream agent](../../agents/merge-upstream.agent.md)
- [conflict-review agent](../../agents/conflict-review.agent.md)
- [resolve-merge-conflict skill](../resolve-merge-conflict/SKILL.md)
- [merge-details.instructions.md](../../instructions/merge/merge-details.instructions.md)

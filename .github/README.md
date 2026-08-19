# `.github/` — AI-Assisted Development for OpenSSH-Portable (Windows Fork)

This folder contains everything needed to work on the PowerShell team's
Windows fork of OpenSSH-Portable with AI assistance in VS Code (GitHub
Copilot Chat / agent mode). It bundles together **agents**, **prompts**,
**instructions**, **skills**, and a set of PowerShell **tools** exposed as
an **MCP server** so that complex workflows (especially upstream merges)
can be driven mostly by an AI agent with a human reviewer in the loop.

If you are new here, read the [Overview](#overview) first, set up the
[MCP server](#mcp-server-setup-vscodemcpjson), then jump to
[Merging from upstream](#merging-from-upstream) for the most common
workflow.

---

## Overview

### What lives in `.github/`

| Folder | Purpose |
|---|---|
| [`agents/`](./agents/) | Custom Copilot **agent modes** — pre-configured personas with curated tool access for specific workflows. |
| [`prompts/`](./prompts/) | Reusable **prompt templates** that kick off a workflow with the right inputs and context. |
| [`instructions/`](./instructions/) | **Instructions** auto-loaded into agent context (via `applyTo` globs) describing repo conventions, build process, merge strategy, testing, etc. |
| [`skills/`](./skills/) | Self-contained **skill packages** the agent can invoke for narrow, repeatable tasks (e.g. bumping a vcpkg port). |
| [`tools/`](./tools/) | PowerShell scripts exposed through the MCP server as callable tools (build, test, git, merge orchestration, vcpkg). |
| [`workflows/`](./workflows/) | GitHub Actions workflows (CI). Not AI-related. |

### How the pieces fit together

```
┌────────────────────────────────────────────────────────────────┐
│  VS Code + GitHub Copilot (chat / agent mode)                  │
│                                                                │
│   ├─ loads instructions/*.md  (auto, by applyTo)               │
│   ├─ can switch into an agent from agents/*.agent.md           │
│   ├─ can be launched via a prompt from prompts/*.prompt.md     │
│   ├─ can invoke skills from skills/*/SKILL.md                  │
│   └─ can call MCP tools ──────────────────┐                    │
└───────────────────────────────────────────┼────────────────────┘
                                            ▼
                            ┌─────────────────────────────┐
                            │  MCP server (openssh-server)│
                            │  defined in .vscode/mcp.json│
                            │  runs PowerShell from       │
                            │  .github/tools/*.ps1        │
                            └─────────────────────────────┘
```

---

## Repository setup

Follow [instructions/setup.instructions.md](./instructions/setup.instructions.md)
end-to-end. It covers cloning the fork, configuring the `upstream` and
`upstream-pwsh` remotes, prerequisites (Visual Studio + Windows SDK), and
cloning + bootstrapping vcpkg via
[Install-VcpkgDependencies.ps1](./tools/Install-VcpkgDependencies.ps1).
For the vendored dependency model itself, see
[instructions/vcpkg.instructions.md](./instructions/vcpkg.instructions.md).
Once setup is complete, do a baseline build per
[instructions/build.instructions.md](./instructions/build.instructions.md).

---

## MCP server setup (`.vscode/mcp.json`)

The PowerShell scripts in [`tools/`](./tools/) are exposed to Copilot via
a small MCP (Model Context Protocol) server so the agent can call them as
first-class tools (`mcp_openssh-server_Start_OpenSSHBuild`,
`mcp_openssh-server_Invoke_Git`, etc.).

### 1. Install the MCP host module

The server is hosted by the `MCPServerPS` PowerShell module, which wraps
each `.ps1` in `-ScriptRoot` as an MCP tool. See the linked package page
for installation details: https://github.com/daxian-dbw/MCPServerPS/pkgs/nuget/MCPServerPS

### 2. Configure VS Code

This repo already ships a working `.vscode/mcp.json` at the repo root. It uses a
repo-relative `ScriptRoot`, so it works out of the box when VS Code is opened at
the repository root — no editing required in that case:

```json
{
    "servers": {
        "openssh-server": {
            "type": "stdio",
            "command": "pwsh",
            "args": [
                "-noprofile",
                "-c",
                "MCPServerPS\\Start-MyMCP -ScriptRoot ./.github/tools"
            ],
            "env": {
                "GITHUB_TOKEN": "${input:github_token}"
            }
        }
    },
    "inputs": [
        {
            "id": "github_token",
            "type": "promptString",
            "description": "GitHub Personal Access Token (used for commit-group CI status queries)",
            "password": true
        }
    ]
}
```

> **Path note:** The relative `./.github/tools` path resolves against the
> workspace root, so it works as-is when you open this repository as the VS Code
> workspace. Only switch to an absolute path (e.g.
> `C:\repos\openssh-portable\.github\tools`) if you run the server from a
> different working directory or a multi-root workspace where the relative path
> does not resolve.

### 3. Start the server in VS Code

- Open the **MCP: List Servers** command (Command Palette).
- Start `openssh-server`. You should see the tools become available to
  Copilot Chat (their names are prefixed with
  `mcp_openssh-server_`, e.g. `mcp_openssh-server_Invoke_Git`).
- In agent mode, the agent will discover and call them automatically.

### 4. Available MCP tools

All tools are PowerShell scripts under [`tools/`](./tools/). They are
documented in detail inside their respective instruction files; here's a
quick map:

| Tool (MCP name) | Script | What it does |
|---|---|---|
| `mcp_openssh-server_Test_MergePrerequisites` | [Test-MergePrerequisites.ps1](./tools/Test-MergePrerequisites.ps1) | Verify environment + remotes are ready for a merge. |
| `mcp_openssh-server_Get_CommitGroups` | [Get-CommitGroups.ps1](./tools/Get-CommitGroups.ps1) | Group upstream commits into mergeable batches by CI presence/success. |
| `mcp_openssh-server_Get_RemainingCommitCount` | [Get-RemainingCommitCount.ps1](./tools/Get-RemainingCommitCount.ps1) | Count commits remaining between a start ref and the end tag/HEAD (merge progress). |
| `mcp_openssh-server_Invoke_Git` | [Invoke-Git.ps1](./tools/Invoke-Git.ps1) | Structured wrapper around git operations (Status, Merge, Diff, Checkout, …). |
| `mcp_openssh-server_Get_ConflictContext` | [Get-ConflictContext.ps1](./tools/Get-ConflictContext.ps1) | Three-way diff context for high-complexity merge conflicts. |
| `mcp_openssh-server_Test_MergeConflictMarkers` | [Test-MergeConflictMarkers.ps1](./tools/Test-MergeConflictMarkers.ps1) | Scan the working tree for leftover conflict markers (`<<<<<<<`, `=======`, `>>>>>>>`) and unmerged paths. |
| `mcp_openssh-server_Sync_VersionResource` | [Sync-VersionResource.ps1](./tools/Sync-VersionResource.ps1) | Sync `contrib/win32/openssh/version.rc` numbers to `version.h` after a version bump. |
| `mcp_openssh-server_Start_OpenSSHBuild` | [Start-OpenSSHBuild.ps1](./tools/Start-OpenSSHBuild.ps1) | Build the Win32-OpenSSH solution. Defaults to the host architecture. |
| `mcp_openssh-server_Test_OpenSSHBuild` | [Test-OpenSSHBuild.ps1](./tools/Test-OpenSSHBuild.ps1) | Parse the most recent build log for errors and warnings. |
| `mcp_openssh-server_Test_OpenSSHFunctionality` | [Test-OpenSSHFunctionality.ps1](./tools/Test-OpenSSHFunctionality.ps1) | End-to-end smoke test (install service, connect, cleanup). |
| `mcp_openssh-server_Invoke_OpenSSHTests` | [Invoke-OpenSSHTests.ps1](./tools/Invoke-OpenSSHTests.ps1) | Full CI suite (unit + bash + Pester E2E). |
| `mcp_openssh-server_Install_VcpkgDependencies` | [Install-VcpkgDependencies.ps1](./tools/Install-VcpkgDependencies.ps1) | Bootstrap vcpkg and install vendored deps. Also runnable directly from a terminal for first-time setup. |
| `mcp_openssh-server_Update_VcpkgPort` | [Update-VcpkgPort.ps1](./tools/Update-VcpkgPort.ps1) | Bump a vendored vcpkg port. Orchestrated by the `update-vcpkg-port` skill. |

---

## Instructions, agents, prompts, and skills

### Instructions ([`instructions/`](./instructions/))

Markdown files with YAML frontmatter that the agent loads automatically
based on `applyTo` globs. They encode the conventions and workflows of
this repo so you don't need to repeat them in every prompt.

General:
- [repository-overview.instructions.md](./instructions/repository-overview.instructions.md) — repo layout + Windows compatibility layer
- [setup.instructions.md](./instructions/setup.instructions.md) — clone, remotes, prerequisites, vcpkg
- [build.instructions.md](./instructions/build.instructions.md) — building on Windows + warning policy
- [testing.instructions.md](./instructions/testing.instructions.md) — functional + full CI testing
- [vcpkg.instructions.md](./instructions/vcpkg.instructions.md) — vendored dependency reference
- [agent-communication.instructions.md](./instructions/agent-communication.instructions.md) — how the agent should talk to you

Merge-specific (under [`instructions/merge/`](./instructions/merge/)):
- [merge-process-overview.instructions.md](./instructions/merge/merge-process-overview.instructions.md) — the two-phase workflow end-to-end
- [merge-details.instructions.md](./instructions/merge/merge-details.instructions.md) — conflict resolution patterns + decision trees
- [research.instructions.md](./instructions/merge/research.instructions.md) — what to read before merging (release notes, prior PRs)
- [agent-communication-merge.instructions.md](./instructions/merge/agent-communication-merge.instructions.md) — communication templates for batches

### Agents ([`agents/`](./agents/))

Custom Copilot agent modes with curated tool sets and a system prompt
tuned to a workflow.

- [merge-upstream.agent.md](./agents/merge-upstream.agent.md) — drives
  the upstream merge workflow end-to-end (analysis → batch merges →
  build → test → PR prep). Switch to it from the Copilot Chat agent
  picker.
- [conflict-review.agent.md](./agents/conflict-review.agent.md) —
  review-only subagent the merge agent delegates to after resolving a
  batch's conflicts. Audits resolutions for leftover markers, prefer-
  upstream bias, balanced Windows guards, silently auto-merged changes
  needing Windows follow-up, and version sync; returns APPROVE or
  CHANGES-REQUIRED.

### Prompts ([`prompts/`](./prompts/))

Reusable prompt templates with documented inputs.

- [merge.prompt.md](./prompts/merge.prompt.md) — kicks off a merge with
  the right context. Provide a start ref (and optionally end ref,
  remotes, validation scenario), and the agent handles the rest.

### Skills ([`skills/`](./skills/))

Self-contained workflow skills the agent reads on demand.

- [update-vcpkg-port](./skills/update-vcpkg-port/SKILL.md) — bump a
  vendored vcpkg dependency (LibreSSL, libfido2, libcbor, zlib) with
  all the side effects (overlay portfile SHA512, LibreSSL resource
  patch) handled correctly.
- [resolve-merge-conflict](./skills/resolve-merge-conflict/SKILL.md) —
  conflict-resolution procedure for upstream merges (prefer-upstream +
  adapt for Windows, strategy preference order, silent auto-merge
  hunting, regress-test and version-resource sync) plus how to summarize
  the resolutions for the pull request.
- [merge-retrospective](./skills/merge-retrospective/SKILL.md) — run
  after a merge PR lands to capture new conflict-resolution patterns and
  feed lessons back into the instructions, skills, agents, and tools.

---

## Merging from upstream

Merging from `openssh/openssh-portable` is the headline workflow this
folder is built around. It uses a **two-phase approach** (all incremental
merges, conflict resolution, build fixes, and validation happen on a
scratch branch; then a real merge branch is created from the same
starting commit, a single `git merge` of the upstream target is
performed, and any conflicts are resolved by copying the resolved files
from the scratch branch). This preserves upstream commit history
exactly. The full workflow lives in
[instructions/merge/merge-process-overview.instructions.md](./instructions/merge/merge-process-overview.instructions.md);
conflict-resolution patterns are in
[merge-details.instructions.md](./instructions/merge/merge-details.instructions.md);
background reading is in
[research.instructions.md](./instructions/merge/research.instructions.md).

### Driving the merge with AI (recommended)

1. Make sure the [MCP server is running](#mcp-server-setup-vscodemcpjson).
2. In Copilot Chat, switch to the **`merge-upstream`** agent
   ([agents/merge-upstream.agent.md](./agents/merge-upstream.agent.md)).
3. Invoke the merge prompt
   ([prompts/merge.prompt.md](./prompts/merge.prompt.md)) with at minimum
   a start ref — see that file for the full input list and examples.
4. Follow the phase checklist, use the tools under [`tools/`](./tools/),
  and surface documented blockers for human guidance when needed.
5. Approve each batch summary the agent presents; at the end, push the
   real branch and open the PR.

### Driving the merge manually

Follow
[merge-process-overview.instructions.md](./instructions/merge/merge-process-overview.instructions.md)
phase by phase. Refer to the repository [setup](./instructions/setup.instructions.md),
[build](./instructions/build.instructions.md), and
[testing](./instructions/testing.instructions.md) instructions as needed.

### Validation

Default validation is end-to-end via
`mcp_openssh-server_Test_OpenSSHFunctionality`. The full CI suite is
documented in
[instructions/testing.instructions.md](./instructions/testing.instructions.md).

---

## Other AI-assisted workflows

### Bumping a vendored vcpkg dependency

Use the [`update-vcpkg-port`](./skills/update-vcpkg-port/SKILL.md) skill.
Ask Copilot something like *"Bump LibreSSL to 4.1.1 using the
update-vcpkg-port skill."* The skill orchestrates
[Update-VcpkgPort.ps1](./tools/Update-VcpkgPort.ps1) (manifest, overlay
portfile SHA512, LibreSSL resource patch), validates via
[Install-VcpkgDependencies.ps1](./tools/Install-VcpkgDependencies.ps1),
then builds to confirm.

### Building / testing / debugging

Even outside a merge, the MCP tools are useful day-to-day. See
[build.instructions.md](./instructions/build.instructions.md) and
[testing.instructions.md](./instructions/testing.instructions.md) for
the full parameter reference of `Start-OpenSSHBuild`,
`Test-OpenSSHBuild`, `Test-OpenSSHFunctionality`, and
`Invoke-OpenSSHTests`.



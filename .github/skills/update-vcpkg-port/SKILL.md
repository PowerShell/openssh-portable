---
name: update-vcpkg-port
description: |
  WORKFLOW SKILL — Bump a vendored vcpkg dependency (libressl, libfido2,
  libcbor, zlib) in this OpenSSH-Portable Windows fork to a new upstream
  version. Orchestrates Update-VcpkgPort.ps1 (manifest, overlay manifest,
  portfile SHA512, LibreSSL resource patch) and handles patch-rejection
  decisions, validation via Install-VcpkgDependencies.ps1, build
  validation, and commit-message drafting. USE FOR: routine version bumps,
  responding to security fixes in vendored deps, satisfying a new minimum
  required by an upstream OpenSSH merge. DO NOT USE FOR: adding a brand-new
  dependency (touch vcpkg.json + add overlay port manually first), or for
  general first-time vcpkg setup (use Install-VcpkgDependencies.ps1
  directly).
---

# Update vcpkg Port Skill

## Purpose

Bump one vendored vcpkg dependency in this repository to a new upstream
version, with all the side effects (overlay portfile SHA512, LibreSSL
resource patch, optional baseline) handled correctly, and validate the
result before handing the user a ready-to-paste commit message.

## When to Use

- An upstream OpenSSH merge requires a newer LibreSSL/libfido2/libcbor/zlib.
- A security fix has been released for a vendored dependency.
- Routine periodic refresh of vendored libraries.

## When NOT to Use

- Adding a brand-new dependency. The skill assumes the port already has an
  entry in [vcpkg.json](../../../contrib/win32/openssh/vcpkg.json)
  `overrides[]` (and an overlay folder if it's a custom port). For new
  deps, edit those files manually first.
- First-time vcpkg setup. Use
  [Install-VcpkgDependencies.ps1](../../tools/Install-VcpkgDependencies.ps1)
  directly.
- Bulk multi-port bumps. Run the skill once per port so each diff is
  reviewable.

## Workflow

### 1. Confirm scope with the user

Ask the user:
- Which port? (`libressl`, `libfido2`, `libcbor`, `zlib`)
- What target version?
- Do they also want to bump the vcpkg `builtin-baseline`? (Usually no
  unless the new port version requires a registry baseline newer than
  what's pinned.)

Also confirm the working tree is clean:

```pwsh
# MCP: mcp_openssh-server_Invoke_Git Operation="Status"
```

If not clean, ask the user to commit/stash before continuing — the diff
this skill produces should stand alone for review.

### 2. Dry run

Always start with `-DryRun` so the user can review planned changes:

```pwsh
.\.github\tools\Update-VcpkgPort.ps1 -Port <port> -Version <version> -DryRun
```

Surface the returned `FilesChanged`, `Sha512`, and `LibresslPatchUpdated`
fields to the user. Confirm before proceeding to the real run.

### 3. Real run

```pwsh
.\.github\tools\Update-VcpkgPort.ps1 -Port <port> -Version <version>
```

If the user opted into a baseline bump, add `-Baseline <sha>`.

### 4. Validate the install

Run a clean install for the default triplet:

```pwsh
.\.github\tools\Install-VcpkgDependencies.ps1 -Clean
```

Three possible outcomes:

#### 4a. Install succeeds
Proceed to step 5.

#### 4b. LibreSSL version cross-check fails
The install tool reports:

> LibreSSL version mismatch: vcpkg.json has X.Y.Z, patch file has A.B.C.D

This means `Update-VcpkgPort.ps1` either didn't update
`add-version-file.patch` (e.g., for non-libressl ports — should not happen)
or the `Version` argument wasn't in `<major>.<minor>.<patch>` form. Fix
the patch by hand, then re-run install.

#### 4c. vcpkg reports a rejected patch hunk
This is the common case for a non-trivial bump. vcpkg's output looks
like:

```
Applying patch <name>.patch
error: patch failed: <file>:<line>
error: <file>: patch does not apply
```

**Decision tree**:

1. **Is the patched code still present in the new upstream source?**
   - If yes → the patch needs its line offsets / context regenerated.
     Extract the new source manually, apply the patch with
     `git apply --3way`, resolve conflicts, regenerate the patch with
     `git diff > <name>.patch`. Then re-run install.
   - If no → has upstream merged equivalent functionality? If yes,
     **drop the patch**: remove it from the `PATCHES` list in
     [portfile.cmake](../../../contrib/win32/openssh/vcpkg_overlay_ports)
     and delete the patch file. Document the removal in the commit
     message. If no, the bump may be too disruptive — ask the user
     whether to abandon or invest in a port-side fix.
2. **For LibreSSL `add-version-file.patch` specifically**: if the patch's
   resource file location moved upstream, the `diff --git` header and
   `+++ b/<path>` lines in the patch will need updating. The
   `Update-VcpkgPort.ps1` script only rewrites version literals, not
   paths.

Stop and request user approval before dropping any patch — patches in
this repo carry security or signing-compliance value.

### 5. Build validation

```pwsh
# MCP: mcp_openssh-server_Start_OpenSSHBuild Configuration="Release" Architecture="x64"
```

If the build fails with linker errors referencing the bumped library, the
overlay port may need additional CMake option changes (e.g., new
`-DXYZ=OFF`). Inspect the failed compile/link command and update
`portfile.cmake` accordingly.

### 6. Multi-arch parity (optional, recommended for major bumps)

```pwsh
.\.github\tools\Install-VcpkgDependencies.ps1 -Architecture x64,x86,ARM,ARM64 -Clean
```

ARM64 in particular has carried its own LibreSSL patches historically;
verify all four triplets install before declaring success.

### 7. Draft the commit message

Produce a ready-to-paste message and present it to the user. Template:

```
Update <port> to <version>

- Bumped <port> override in contrib/win32/openssh/vcpkg.json from
  <old-version> to <version>
- Refreshed SHA512 in
  contrib/win32/openssh/vcpkg_overlay_ports/<port>/portfile.cmake
- [if libressl] Updated FileVersion/ProductVersion in
  add-version-file.patch to <X>.<Y>.<Z>.0
- [if patches were regenerated] Regenerated <name>.patch against new
  upstream source
- [if patches were dropped] Removed <name>.patch — upstream <commit/PR>
  now provides equivalent functionality
- [if baseline bumped] Bumped vcpkg builtin-baseline to <sha>

Validated:
- vcpkg install succeeds for <triplet list>
- Win32-OpenSSH build succeeds (Release, x64)
```

## Tools Used

- [Update-VcpkgPort.ps1](../../tools/Update-VcpkgPort.ps1) — mechanical
  edits.
- [Install-VcpkgDependencies.ps1](../../tools/Install-VcpkgDependencies.ps1)
  — install + cross-check validation.
- [Start-OpenSSHBuild.ps1](../../tools/Start-OpenSSHBuild.ps1) — build
  validation.
- `mcp_openssh-server_Invoke_Git` — status checks.

## Reference

- [vcpkg.instructions.md](../../instructions/vcpkg.instructions.md) —
  layout, custom triplets, troubleshooting.
- Overlay ports:
  [libressl](../../../contrib/win32/openssh/vcpkg_overlay_ports/libressl/),
  [libfido2](../../../contrib/win32/openssh/vcpkg_overlay_ports/libfido2/).
- CI source of truth:
  [.azdo/templates/install-vcpkg-dependencies.yml](../../../.azdo/templates/install-vcpkg-dependencies.yml).

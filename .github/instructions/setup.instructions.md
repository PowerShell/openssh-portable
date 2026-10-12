---
applyTo: "**/*"
---

# Repository Setup Instructions for AI Agents

## Initial Repository Setup

### Step 1: Clone Your Fork
```pwsh
# Replace 'your-username' with actual GitHub username
git clone https://github.com/your-username/openssh-portable.git
cd openssh-portable
```

### Step 2: Add Upstream Repositories
```pwsh
# Add PowerShell team's fork as upstream-pwsh
git remote add upstream-pwsh https://github.com/PowerShell/openssh-portable.git

# Add original OpenSSH repository as upstream
git remote add upstream https://github.com/openssh/openssh-portable.git
```

### Step 3: Verify Remote Configuration
```pwsh
git remote -v
# Expected output:
# origin          https://github.com/your-username/openssh-portable.git (fetch)
# origin          https://github.com/your-username/openssh-portable.git (push)
# upstream        https://github.com/openssh/openssh-portable.git (fetch)
# upstream        https://github.com/openssh/openssh-portable.git (push)
# upstream-pwsh   https://github.com/PowerShell/openssh-portable.git (fetch)
# upstream-pwsh   https://github.com/PowerShell/openssh-portable.git (push)
```

### Step 4: Initial Fetch
Use the Invoke-Git MCP tool to fetch from all remotes:
- **MCP Tool**: `mcp_openssh-server_Invoke_Git`
- **Operation**: `Fetch`, **Remote**: `all`

## Branch Strategy

### Understanding the Branch Structure
- **upstream-pwsh/latestw_all**: Main Windows-compatible branch
- **upstream/master**: Latest upstream OpenSSH development
- **upstream/V_X_Y_PZ**: Tagged releases (merge targets)

### Verification Commands
```pwsh
# List all branches
git branch -r

# Check current branch
git branch
```

### Step 5: Clone vcpkg Repository
```pwsh
# In the same parent directory as openssh-portable (sibling of the repo)
git clone https://github.com/Microsoft/vcpkg.git
```

The build expects the vcpkg clone at `..\vcpkg` relative to the repo root.
The `Install-VcpkgDependencies.ps1` tool (Step 6) will also honor
`$env:VCPKG_ROOT` if set.

### Step 6: Bootstrap vcpkg and Install Dependencies

The Win32-OpenSSH build links against vendored libraries (`libressl`,
`libfido2`, `libcbor`, `zlib`) installed via vcpkg's manifest mode using
custom triplets and overlay ports under
[contrib/win32/openssh/](../../contrib/win32/openssh/).
[OpenSSHBuildHelper.psm1](../../contrib/win32/openssh/OpenSSHBuildHelper.psm1)
copies `libcrypto.dll` from `vcpkg_installed/<triplet>-custom/` at build time,
so this step **must complete before `Start-OpenSSHBuild`**.

**Recommended (use the tool):**
```pwsh
# From the repo root
.\.github\tools\Install-VcpkgDependencies.ps1 -Bootstrap
```

The tool auto-discovers `..\vcpkg` (or `$env:VCPKG_ROOT`), bootstraps it if
needed, runs the LibreSSL version cross-check, and invokes `vcpkg install`
with the correct overlay ports and triplet. See
[vcpkg.instructions.md](./vcpkg.instructions.md) for full reference.

**Manual equivalent (for reference):**
```pwsh
cd ..\vcpkg
.\bootstrap-vcpkg.bat
cd ..\openssh-portable\contrib\win32\openssh
..\..\..\..\vcpkg\vcpkg.exe install `
    --triplet x64-custom `
    --overlay-triplets=.\vcpkg_triplets `
    --overlay-ports=.\vcpkg_overlay_ports
```

## AI Agent Checklist

Before proceeding to merge:
- [ ] Repository cloned successfully
- [ ] All three remotes configured (origin, upstream, upstream-pwsh)
- [ ] Can fetch from all remotes without errors
- [ ] Can see upstream target version/branch
- [ ] Working directory is clean (use Invoke-Git `Operation="Status"` — `ModifiedFiles` and `ConflictedFiles` should both be empty)
- [ ] vcpkg dependencies installed: `contrib/win32/openssh/vcpkg_installed/x64-custom/` exists and contains `bin/libcrypto.dll`

## Troubleshooting

### Common Issues
1. **Authentication errors**: Ensure GitHub credentials are configured
2. **Network issues**: Check proxy settings if behind corporate firewall
3. **Branch not found**: Verify branch/tag names are correct

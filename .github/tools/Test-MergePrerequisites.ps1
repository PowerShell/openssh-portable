<#
.SYNOPSIS
    MCP tool that verifies all prerequisites for starting an OpenSSH upstream merge.

.DESCRIPTION
    This script performs comprehensive pre-merge setup verification for the OpenSSH
    upstream merge workflow. It checks:
    - Required tools (Git, PowerShell, Visual Studio)
    - Repository configuration (remotes, branch state)
    - Target version identification

    This tool should be run before starting Phase 1 of the merge workflow to ensure
    all prerequisites are met. It prevents wasted effort by catching configuration
    issues early.

    To verify baseline build capability, use the Test-OpenSSHBuild MCP tool:
      mcp_openssh-server_Test_OpenSSHBuild

.PARAMETER TargetVersion
    The upstream version/tag to merge (e.g., "V_10_0_P2", "V_9_9_P1")
    This can be a tag name or branch name from the upstream repository.

.OUTPUTS
    Returns a hashtable with:
    - Success: Boolean indicating all prerequisites passed
    - GitInstalled: Boolean - Git is available
    - PowerShellVersion: String - PowerShell version
    - VSInstalled: Boolean - Visual Studio is available
    - RemotesConfigured: Boolean - All required remotes configured
    - TargetExists: Boolean - Target version/tag exists in upstream
    - WorkingDirClean: Boolean - No uncommitted changes
    - Issues: Array - List of any issues found
    - Message: String - Summary message

.EXAMPLE
    .\Test-MergePrerequisites.ps1 -TargetVersion "V_10_0_P2"

    Verifies all prerequisites for merging upstream V_10_0_P2.
    For baseline build verification, use Test-OpenSSHBuild MCP tool separately.

.NOTES
    - This is a Phase 1 Pre-Merge Setup verification tool
    - Should be run before creating the merge branch
    - For baseline build verification, use: mcp_openssh-server_Test_OpenSSHBuild
    - Part of the OpenSSH upstream merge workflow automation
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$TargetVersion
)

$scriptRoot = $PSScriptRoot
if ([string]::IsNullOrEmpty($scriptRoot)) {
    $scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
}
$repoRoot = (Get-Item $scriptRoot).Parent.Parent.FullName

$result = @{
    Success = $false
    GitInstalled = $false
    PowerShellVersion = $PSVersionTable.PSVersion.ToString()
    VSInstalled = $false
    RemotesConfigured = $false
    TargetExists = $false
    WorkingDirClean = $false
    Issues = @()
    Message = ""
}

try {
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "OpenSSH Merge Prerequisites Check" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Target Version: $TargetVersion" -ForegroundColor White
    Write-Host "Repository Root: $repoRoot" -ForegroundColor Gray
    Write-Host "========================================`n" -ForegroundColor Cyan

    # Change to repository root
    Push-Location $repoRoot
    Write-Host "Working Directory: $(Get-Location)" -ForegroundColor Gray
    Write-Host ""

    # Step 1: Verify Git
    Write-Host "[1/6] Checking Git installation..." -ForegroundColor Cyan
    try {
        $gitPath = Get-Command git -ErrorAction SilentlyContinue
        if ($gitPath) {
            $result.GitInstalled = $true
            Write-Host "  ✓ Git found: $($gitPath.Source)" -ForegroundColor Green
        } else {
            $result.Issues += "Git is not installed or not in PATH"
            Write-Host "  ✗ Git not found" -ForegroundColor Red
        }
    } catch {
        $result.Issues += "Git is not installed or not in PATH"
        Write-Host "  ✗ Git not found" -ForegroundColor Red
    }

    # Step 2: Verify PowerShell version
    Write-Host "`n[2/6] Checking PowerShell version..." -ForegroundColor Cyan
    $psVersion = $PSVersionTable.PSVersion
    if ($psVersion.Major -ge 5) {
        Write-Host "  ✓ PowerShell $($psVersion.ToString()) (>= 5.0)" -ForegroundColor Green
    } else {
        $result.Issues += "PowerShell version $($psVersion.ToString()) is too old (need >= 5.0)"
        Write-Host "  ✗ PowerShell $($psVersion.ToString()) is too old (need >= 5.0)" -ForegroundColor Red
    }

    # Step 3: Verify Visual Studio
    Write-Host "`n[3/6] Checking Visual Studio installation..." -ForegroundColor Cyan
    $msBuildPaths = @(
        "${env:ProgramFiles}\Microsoft Visual Studio\2022\*\MSBuild\Current\Bin\MSBuild.exe",
        "${env:ProgramFiles}\Microsoft Visual Studio\2019\*\MSBuild\Current\Bin\MSBuild.exe",
        "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\*\MSBuild\Current\Bin\MSBuild.exe",
        "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2019\*\MSBuild\Current\Bin\MSBuild.exe"
    )

    $msBuildFound = $false
    foreach ($path in $msBuildPaths) {
        $resolved = Resolve-Path $path -ErrorAction SilentlyContinue
        if ($resolved) {
            $msBuildFound = $true
            $result.VSInstalled = $true
            Write-Host "  ✓ Visual Studio found: $($resolved.Path)" -ForegroundColor Green
            break
        }
    }

    if (-not $msBuildFound) {
        $result.Issues += "Visual Studio 2019 or later not found"
        Write-Host "  ✗ Visual Studio 2019 or later not found" -ForegroundColor Red
    }

    # Step 4: Verify repository remotes
    Write-Host "`n[4/6] Checking repository remotes..." -ForegroundColor Cyan
    if ($result.GitInstalled) {
        try {
            $gitConfigPath = Join-Path $repoRoot ".git\config"
            if (Test-Path $gitConfigPath) {
                $gitConfig = Get-Content $gitConfigPath -Raw
                $expectedRemotes = @('origin', 'upstream', 'upstream-pwsh')
                $missingRemotes = @()

                foreach ($remote in $expectedRemotes) {
                    if ($gitConfig -match "\[remote `"$remote`"\]") {
                        Write-Host "  ✓ $remote configured" -ForegroundColor Green
                    } else {
                        $missingRemotes += $remote
                        Write-Host "  ✗ $remote not configured" -ForegroundColor Red
                    }
                }

                if ($missingRemotes.Count -eq 0) {
                    $result.RemotesConfigured = $true
                } else {
                    $result.Issues += "Missing remotes: $($missingRemotes -join ', ')"
                }
            } else {
                $result.Issues += "Not a git repository"
                Write-Host "  ✗ Not a git repository" -ForegroundColor Red
            }
        } catch {
            $result.Issues += "Error checking remotes: $($_.Exception.Message)"
            Write-Host "  ✗ Error checking remotes" -ForegroundColor Red
        }
    } else {
        Write-Host "  ⊘ Skipped (Git not available)" -ForegroundColor Yellow
    }

    # Step 5: Verify target version exists
    Write-Host "`n[5/6] Checking target version exists..." -ForegroundColor Cyan
    if ($result.GitInstalled -and $result.RemotesConfigured) {
        try {
            # Use git to resolve the ref so packed-refs (packed tags/remote branches) are honored.
            $job = Start-Job -ScriptBlock {
                param($repoPath, $target)
                Set-Location $repoPath
                # Prefer an exact tag, then an upstream remote-tracking branch.
                & git show-ref --verify --quiet "refs/tags/$target"
                if ($LASTEXITCODE -eq 0) { return 'tag' }
                & git show-ref --verify --quiet "refs/remotes/upstream/$target"
                if ($LASTEXITCODE -eq 0) { return 'branch' }
                return 'missing'
            } -ArgumentList $repoRoot, $TargetVersion

            $jobResult = Wait-Job $job -Timeout 10
            if ($jobResult) {
                $refKind = Receive-Job $job
                Remove-Job $job -Force

                if ($refKind -eq 'tag') {
                    $result.TargetExists = $true
                    Write-Host "  ✓ Target tag exists locally: $TargetVersion" -ForegroundColor Green
                } elseif ($refKind -eq 'branch') {
                    $result.TargetExists = $true
                    Write-Host "  ✓ Target branch exists: upstream/$TargetVersion" -ForegroundColor Green
                } else {
                    $result.Issues += "Target version/tag '$TargetVersion' not found locally. Run 'git fetch upstream --tags' to update."
                    Write-Host "  ✗ Target '$TargetVersion' not found locally" -ForegroundColor Red
                    Write-Host "    Hint: Run 'git fetch upstream --tags' to fetch latest tags" -ForegroundColor Yellow
                }
            } else {
                Remove-Job $job -Force
                $result.Issues += "Target version check timed out"
                Write-Host "  ✗ Target version check timed out" -ForegroundColor Red
            }
        } catch {
            $result.Issues += "Error checking target version: $($_.Exception.Message)"
            Write-Host "  ✗ Error checking target version" -ForegroundColor Red
        }
    } else {
        Write-Host "  ⊘ Skipped (prerequisites not met)" -ForegroundColor Yellow
    }

    # Step 6: Verify working directory is clean
    Write-Host "`n[6/6] Checking working directory status..." -ForegroundColor Cyan
    if ($result.GitInstalled) {
        try {
            # Use Start-Job to run git status --porcelain
            $job = Start-Job -ScriptBlock {
                param($repoPath)
                Set-Location $repoPath
                git status --porcelain
            } -ArgumentList $repoRoot
            
            $jobResult = Wait-Job $job -Timeout 10
            if ($jobResult) {
                $statusOutput = Receive-Job $job
                Remove-Job $job -Force
                
                if ([string]::IsNullOrWhiteSpace($statusOutput)) {
                    $result.WorkingDirClean = $true
                    Write-Host "  ✓ Working directory is clean" -ForegroundColor Green
                } else {
                    $result.Issues += "Working directory has uncommitted changes"
                    Write-Host "  ✗ Working directory has uncommitted changes:" -ForegroundColor Red
                    $statusOutput | ForEach-Object { Write-Host "    $_" -ForegroundColor Yellow }
                    Write-Host "    Hint: Commit or stash changes before starting merge" -ForegroundColor Yellow
                }
            } else {
                Remove-Job $job -Force
                $result.Issues += "Git status check timed out"
                Write-Host "  ✗ Git status check timed out" -ForegroundColor Red
            }
        } catch {
            $result.Issues += "Error checking working directory: $($_.Exception.Message)"
            Write-Host "  ✗ Error checking working directory status" -ForegroundColor Red
        }
    } else {
        Write-Host "  ⊘ Skipped (Git not available)" -ForegroundColor Yellow
    }

    # Final evaluation
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "PREREQUISITE CHECK SUMMARY" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan

    $criticalChecks = @(
        $result.GitInstalled,
        $result.VSInstalled,
        $result.RemotesConfigured,
        $result.TargetExists,
        $result.WorkingDirClean
    )

    $result.Success = ($criticalChecks | Where-Object { $_ -eq $false }).Count -eq 0

    if ($result.Success) {
        Write-Host "✓ ALL PREREQUISITES MET" -ForegroundColor Green
        Write-Host "`nYou are ready to begin the merge process:" -ForegroundColor White
        $result.Message = "All prerequisites met. Ready to start merge."
    } else {
        Write-Host "✗ PREREQUISITES NOT MET" -ForegroundColor Red
        Write-Host "`nIssues found:" -ForegroundColor Yellow
        foreach ($issue in $result.Issues) {
            Write-Host "  • $issue" -ForegroundColor Red
        }
        $result.Message = "$($result.Issues.Count) issue(s) found. Fix issues before starting merge."
    }

    Write-Host ""

    # Return result
    return $result

} catch {
    Write-Host "`n========================================" -ForegroundColor Red
    Write-Host "ERROR" -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor Gray

    $result.Success = $false
    $result.Issues += "Tool error: $($_.Exception.Message)"
    $result.Message = "Prerequisite check failed with error: $($_.Exception.Message)"

    # Return result
    return $result
} finally {
    try {
        Pop-Location
    } catch {
        # Ignore Pop-Location errors in MCP context
    }
}

<#
.SYNOPSIS
    Counts how many upstream commits remain to be merged between a start ref and an end ref (tag or HEAD).

.DESCRIPTION
    MCP-compatible tool that reports the number of commits reachable from EndRef but not from
    StartRef (i.e. `git rev-list --count <StartRef>..<EndRef>`). It is used during an upstream
    merge to answer "how many commits are left to merge to the target tag / HEAD?" so the agent
    and user can gauge remaining work and estimate the number of batches.

    Both refs must be resolvable in the local repository. For an upstream merge, StartRef is
    typically the last-merged upstream commit (or tag) and EndRef is the upstream target tag or
    the tip of the upstream tracking branch. Run a fetch first so the refs are up to date, e.g.
    `git fetch upstream --tags`.

.PARAMETER StartRef
    The ref (commit SHA, tag, or branch) that marks the last already-merged upstream point.
    Commits reachable from this ref are excluded from the count. Required.

.PARAMETER EndRef
    The ref (commit SHA, tag, or branch) that marks the merge target. Defaults to 'HEAD'.
    For an upstream merge this is usually the upstream target tag (e.g. 'V_10_3_P1') or the
    upstream tracking branch tip (e.g. 'upstream/master').

.OUTPUTS
    Hashtable with:
      Success        [bool]    Whether both refs resolved and the count succeeded
      Message        [string]  Human-readable summary
      StartRef       [string]  Echoed StartRef
      EndRef         [string]  Echoed EndRef
      StartCommit    [string]  Resolved full SHA of StartRef (or empty on error)
      EndCommit      [string]  Resolved full SHA of EndRef (or empty on error)
      RemainingCount [int]     Commits reachable from EndRef but not StartRef (StartRef..EndRef)
      AlreadyMerged  [bool]    True if RemainingCount is 0 (nothing left to merge)
      Errors         [string[]] Any error messages

.EXAMPLE
    # How many commits remain between the last merged tag and the target tag
    # MCP Tool: mcp_openssh-server_Get_RemainingCommitCount
    # StartRef="V_10_0_P2", EndRef="V_10_3_P1"

.EXAMPLE
    # How many commits remain to the current upstream tip
    # MCP Tool: mcp_openssh-server_Get_RemainingCommitCount
    # StartRef="6fb728df50c1afd338cb0223a84ce24579577eff", EndRef="upstream/master"
#>

param(
    [Parameter(Mandatory)]
    [string]$StartRef,

    [string]$EndRef = 'HEAD'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── Git process helper (same pattern as Get-ConflictContext.ps1 / Invoke-Git.ps1) ──
function Invoke-GitCommand {
    param([string[]]$Arguments)

    $processInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $processInfo.FileName               = 'git'
    $processInfo.Arguments              = ($Arguments | ForEach-Object {
        if ($_ -match '\s') { "`"$_`"" } else { $_ }
    }) -join ' '
    $processInfo.UseShellExecute        = $false
    $processInfo.CreateNoWindow         = $true
    $processInfo.RedirectStandardInput  = $true
    $processInfo.RedirectStandardOutput = $true
    $processInfo.RedirectStandardError  = $true

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $processInfo
    $process.Start() | Out-Null
    $process.StandardInput.Close()

    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()

    $completed = $process.WaitForExit(30000)

    if (-not $completed) {
        $process.Kill()
        return @{
            ExitCode = -1
            Success  = $false
            Output   = ''
            Error    = "git $($Arguments -join ' ') timed out after 30 seconds"
        }
    }

    return @{
        ExitCode = $process.ExitCode
        Success  = ($process.ExitCode -eq 0)
        Output   = $stdoutTask.GetAwaiter().GetResult().TrimEnd()
        Error    = $stderrTask.GetAwaiter().GetResult().TrimEnd()
    }
}

$result = @{
    Success        = $false
    Message        = ''
    StartRef       = $StartRef
    EndRef         = $EndRef
    StartCommit    = ''
    EndCommit      = ''
    RemainingCount = 0
    AlreadyMerged  = $false
    Errors         = @()
}

# Resolve both refs so we fail clearly if one is missing/unfetched.
$startResolve = Invoke-GitCommand @('rev-parse', '--verify', "$StartRef^{commit}")
if (-not $startResolve.Success) {
    $result.Errors += "Could not resolve StartRef '$StartRef': $($startResolve.Error). Did you fetch upstream (git fetch upstream --tags)?"
    $result.Message = "Failed to resolve StartRef '$StartRef'."
    return $result
}
$result.StartCommit = $startResolve.Output

$endResolve = Invoke-GitCommand @('rev-parse', '--verify', "$EndRef^{commit}")
if (-not $endResolve.Success) {
    $result.Errors += "Could not resolve EndRef '$EndRef': $($endResolve.Error). Did you fetch upstream (git fetch upstream --tags)?"
    $result.Message = "Failed to resolve EndRef '$EndRef'."
    return $result
}
$result.EndCommit = $endResolve.Output

$count = Invoke-GitCommand @('rev-list', '--count', "$StartRef..$EndRef")
if (-not $count.Success) {
    $result.Errors += "git rev-list failed: $($count.Error)"
    $result.Message = "Failed to count commits between '$StartRef' and '$EndRef'."
    return $result
}

$result.RemainingCount = [int]$count.Output
$result.AlreadyMerged  = ($result.RemainingCount -eq 0)
$result.Success        = $true

if ($result.AlreadyMerged) {
    $result.Message = "0 commits remain between '$StartRef' and '$EndRef' — the target is already merged (or EndRef is not ahead of StartRef)."
} else {
    $result.Message = "$($result.RemainingCount) commit(s) remain to be merged from '$StartRef' to '$EndRef'."
}

return $result

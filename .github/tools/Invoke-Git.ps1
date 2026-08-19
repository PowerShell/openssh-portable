<#
.SYNOPSIS
    Executes a git operation and returns a structured result with exit code.

.DESCRIPTION
    MCP-compatible tool that runs git commands via System.Diagnostics.Process for
    reliable exit code capture without interfering with the MCP server's stdio
    transport. Async stream reads are started before WaitForExit to prevent deadlocks
    when git output exceeds the stream buffer size.

    Returns a structured hashtable with Success, ExitCode, Output, Error, and
    operation-specific fields so agents can make programmatic decisions without
    text parsing.

.PARAMETER Operation
    The git operation to perform. One of:
    CherryPick, CherryPickContinue, CherryPickAbort,
    Merge, MergeContinue, MergeAbort,
    Add, Checkout, CreateBranch,
    Commit, Push, Fetch,
    Config, Reset, Clean,
    Status, Log, Diff, Show

.PARAMETER CommitHash
    A commit SHA or any git ref (branch name, tag, etc.).
    Used by: CherryPick, Merge, Show.

.PARAMETER Range
    A git range expression (e.g. "abc123^..def456" or "HEAD..upstream/V_10_0_P2").
    Used by: Log (and Log with ShasOnly), Diff.

.PARAMETER Message
    Commit message text.
    Used by: Commit.

.PARAMETER Path
    File path or directory to operate on. Defaults to '.'.
    Used by: Add, Checkout (file restore), Diff, Show.

.PARAMETER Remote
    Remote name. Defaults to 'origin'.
    Used by: Fetch, Push.

.PARAMETER Branch
    Branch name to create or push.
    Used by: CreateBranch, Push.

.PARAMETER StartPoint
    Git ref (branch, tag, or commit) to base the new branch on.
    Used by: CreateBranch.

.PARAMETER Target
    Branch, tag, commit ref, or file path to check out or reset to.
    Used by: Checkout, Reset.

.PARAMETER Key
    Git config key (e.g. "core.editor").
    Used by: Config.

.PARAMETER Value
    Git config value to set.
    Used by: Config.

.PARAMETER Mode
    Reset mode: 'soft', 'mixed' (default), or 'hard'.
    Used by: Reset.

.PARAMETER ShasOnly
    When specified alongside Operation=Log, uses git rev-list --reverse instead of
    git log --oneline. Returns commit SHAs in oldest-first order suitable for building
    a cherry-pick loop. result.Commits will contain [{Hash: "<sha>", Message: ""}].

.PARAMETER NameOnly
    When specified alongside Operation=Diff, adds --name-only so git emits just the list
    of changed file paths instead of a full patch.
    Used by: Diff.

.OUTPUTS
    Hashtable with:
      Success     [bool]     Whether the command exited with code 0
      ExitCode    [int]      Raw process exit code
      Output      [string]   Stdout from git
      Error       [string]   Stderr from git
      Message     [string]   Human-readable summary
    Plus operation-specific fields:
      CherryPick (on failure): ConflictedFiles [string[]]
      Merge (on failure):      ConflictedFiles [string[]]
      Log / ShasOnly:          Commits          [{Hash, Message}]
      Status:                  ConflictedFiles  [string[]], ModifiedFiles [string[]]
      Commit (on success):     CommitHash       [string]

.EXAMPLE
    # Cherry-pick a single commit
    # MCP Tool: mcp_openssh-server_Invoke_Git
    # Operation="CherryPick", CommitHash="abc1234"

.EXAMPLE
    # Get ordered commit SHAs in a batch range for a cherry-pick loop
    # MCP Tool: mcp_openssh-server_Invoke_Git
    # Operation="Log", Range="abc123^..def456", ShasOnly=true

.EXAMPLE
    # Stage all changes after conflict resolution (Path defaults to '.')
    # MCP Tool: mcp_openssh-server_Invoke_Git
    # Operation="Add"

.EXAMPLE
    # Continue cherry-pick after resolving conflicts
    # MCP Tool: mcp_openssh-server_Invoke_Git
    # Operation="CherryPickContinue"

.EXAMPLE
    # Abort an in-progress cherry-pick
    # MCP Tool: mcp_openssh-server_Invoke_Git
    # Operation="CherryPickAbort"

.EXAMPLE
    # Restore paths.targets after a build modifies it
    # MCP Tool: mcp_openssh-server_Invoke_Git
    # Operation="Checkout", Target=".\contrib\win32\openssh\paths.targets"

.EXAMPLE
    # Create and check out a new merge branch
    # MCP Tool: mcp_openssh-server_Invoke_Git
    # Operation="CreateBranch", Branch="merge-v10.0P2-20260306"

.EXAMPLE
    # Commit staged changes
    # MCP Tool: mcp_openssh-server_Invoke_Git
    # Operation="Commit", Message="Fix compilation errors for V_10_0_P2"

.EXAMPLE
    # Push a branch to origin
    # MCP Tool: mcp_openssh-server_Invoke_Git
    # Operation="Push", Remote="origin", Branch="merge-v10.0P2-20260306"

.EXAMPLE
    # Set a git config value
    # MCP Tool: mcp_openssh-server_Invoke_Git
    # Operation="Config", Key="core.editor", Value="true"

.EXAMPLE
    # Show differences between two refs for a specific file
    # MCP Tool: mcp_openssh-server_Invoke_Git
    # Operation="Diff", Range="upstream-pwsh/latestw_all..upstream/V_10_0_P2", Path="Makefile.in"

.EXAMPLE
    # Inspect a specific commit
    # MCP Tool: mcp_openssh-server_Invoke_Git
    # Operation="Show", CommitHash="abc1234"

.EXAMPLE
    # Check working directory status for conflicts and modifications
    # MCP Tool: mcp_openssh-server_Invoke_Git
    # Operation="Status"

.EXAMPLE
    # Hard-reset to HEAD (recovery)
    # MCP Tool: mcp_openssh-server_Invoke_Git
    # Operation="Reset", Target="HEAD", Mode="hard"

.EXAMPLE
    # Merge an upstream batch endpoint into the current branch
    # MCP Tool: mcp_openssh-server_Invoke_Git
    # Operation="Merge", CommitHash="6fb728df50c1afd338cb0223a84ce24579577eff"

.EXAMPLE
    # Continue a merge after resolving conflicts
    # MCP Tool: mcp_openssh-server_Invoke_Git
    # Operation="MergeContinue"

.EXAMPLE
    # Abort an in-progress merge
    # MCP Tool: mcp_openssh-server_Invoke_Git
    # Operation="MergeAbort"

.EXAMPLE
    # Remove untracked files (recovery)
    # MCP Tool: mcp_openssh-server_Invoke_Git
    # Operation="Clean"
#>

param(
    [Parameter(Mandatory)]
    [ValidateSet(
        'CherryPick', 'CherryPickContinue', 'CherryPickAbort',
        'Merge', 'MergeContinue', 'MergeAbort',
        'Add', 'Checkout', 'CreateBranch',
        'Commit', 'Push', 'Fetch',
        'Config', 'Reset', 'Clean',
        'Status', 'Log', 'Diff', 'Show'
    )]
    [string]$Operation,

    # CherryPick, Merge, Show — accepts any git ref: commit SHA, branch name, tag, etc.
    [string]$CommitHash = '',

    # Log (plain or ShasOnly), Diff — git range expression e.g. "abc123^..def456"
    [string]$Range = '',

    # Commit — commit message text
    [string]$Message = '',

    # Add, Checkout (file restore), Diff, Show — file/directory path
    [string]$Path = '.',

    # Fetch, Push — remote name
    [string]$Remote = 'origin',

    # CreateBranch, Push — branch name
    [string]$Branch = '',

    # CreateBranch — starting ref for the new branch
    [string]$StartPoint = '',

    # Checkout, Reset — target ref or file path
    [string]$Target = '',

    # Config — key (e.g. "core.editor")
    [string]$Key = '',

    # Config — value to set
    [string]$Value = '',

    # Reset — reset mode
    [ValidateSet('soft', 'mixed', 'hard')]
    [string]$Mode = 'mixed',

    # Log — use git rev-list --reverse (SHAs only, oldest first) instead of git log --oneline
    [switch]$ShasOnly,

    # Diff — emit only the list of changed file paths (git diff --name-only)
    [switch]$NameOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Private helper — runs git via System.Diagnostics.Process.
#
# IMPORTANT: We use ProcessStartInfo rather than Start-Process because
# Start-Process with -RedirectStandardOutput/-RedirectStandardError conflicts
# with the MCP server's stdio transport, causing the process to hang.
#
# Async stream reads MUST be started BEFORE WaitForExit to prevent deadlocks:
# if git output exceeds the internal stream buffer, git blocks waiting for the
# buffer to drain while WaitForExit blocks waiting for git to exit.
# ---------------------------------------------------------------------------
function Invoke-GitCommand {
    param([string[]]$Arguments)

    $processInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $processInfo.FileName               = 'git'
    $processInfo.Arguments              = ($Arguments | ForEach-Object {
        if ($_ -match '\s') { "`"$_`"" } else { $_ }
    }) -join ' '
    $processInfo.UseShellExecute        = $false
    $processInfo.CreateNoWindow         = $true
    $processInfo.RedirectStandardInput  = $true   # Prevent git inheriting the MCP stdio pipe
    $processInfo.RedirectStandardOutput = $true
    $processInfo.RedirectStandardError  = $true

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $processInfo
    $process.Start() | Out-Null
    $process.StandardInput.Close()                # Immediately close stdin so git never blocks on input

    # Begin async reads BEFORE blocking on WaitForExit
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()

    $completed = $process.WaitForExit(30000)  # 30-second timeout

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

# ---------------------------------------------------------------------------
# Operation dispatcher
# ---------------------------------------------------------------------------
$result = switch ($Operation) {

    'CherryPick' {
        if (-not $CommitHash) { throw 'CommitHash is required for CherryPick' }
        $r = Invoke-GitCommand -Arguments @('cherry-pick', $CommitHash)
        if (-not $r.Success) {
            # Enrich failure result with list of conflicted files for agent reporting
            $statusResult = Invoke-GitCommand -Arguments @('status', '--porcelain')
            $r['ConflictedFiles'] = ($statusResult.Output -split "`n") |
                Where-Object { $_ -match '^(UU|AA|DD|AU|UA|DU|UD)\s' } |
                ForEach-Object { $_.Substring(3).Trim() }
        }
        $r
    }

    'CherryPickContinue' {
        Invoke-GitCommand -Arguments @('cherry-pick', '--continue')
    }

    'CherryPickAbort' {
        Invoke-GitCommand -Arguments @('cherry-pick', '--abort')
    }

    'Merge' {
        if (-not $CommitHash) { throw 'CommitHash is required for Merge (target ref to merge)' }
        $r = Invoke-GitCommand -Arguments @('merge', '--no-ff', $CommitHash)
        if (-not $r.Success) {
            $statusResult = Invoke-GitCommand -Arguments @('status', '--porcelain')
            $r['ConflictedFiles'] = ($statusResult.Output -split "`n") |
                Where-Object { $_ -match '^(UU|AA|DD|AU|UA|DU|UD)\s' } |
                ForEach-Object { $_.Substring(3).Trim() }
        }
        $r
    }

    'MergeContinue' {
        Invoke-GitCommand -Arguments @('merge', '--continue')
    }

    'MergeAbort' {
        Invoke-GitCommand -Arguments @('merge', '--abort')
    }

    'Add' {
        Invoke-GitCommand -Arguments @('add', $Path)
    }

    'Checkout' {
        if (-not $Target) { throw 'Target is required for Checkout (branch name, tag, or file path)' }
        Invoke-GitCommand -Arguments @('checkout', $Target)
    }

    'CreateBranch' {
        if (-not $Branch) { throw 'Branch is required for CreateBranch' }
        $args = @('checkout', '-b', $Branch)
        if ($StartPoint) { $args += $StartPoint }
        Invoke-GitCommand -Arguments $args
    }

    'Commit' {
        if (-not $Message) { throw 'Message is required for Commit' }
        $r = Invoke-GitCommand -Arguments @('commit', '-m', $Message)
        if ($r.Success -and $r.Output -match '\[[\w/]+ ([0-9a-f]{7,})\]') {
            $r['CommitHash'] = $Matches[1]
        }
        $r
    }

    'Push' {
        $args = @('push', $Remote)
        if ($Branch) { $args += $Branch }
        Invoke-GitCommand -Arguments $args
    }

    'Fetch' {
        $args = if ($Remote -eq 'all') { @('fetch', '--all') } else { @('fetch', $Remote) }
        Invoke-GitCommand -Arguments $args
    }

    'Config' {
        if (-not $Key) { throw 'Key is required for Config' }
        $args = @('config', $Key)
        if ($Value) { $args += $Value }
        Invoke-GitCommand -Arguments $args
    }

    'Reset' {
        if (-not $Target) { throw 'Target is required for Reset' }
        Invoke-GitCommand -Arguments @('reset', "--$Mode", $Target)
    }

    'Clean' {
        # -f (force) -d (include untracked directories) — standard recovery clean
        Invoke-GitCommand -Arguments @('clean', '-fd')
    }

    'Status' {
        $r = Invoke-GitCommand -Arguments @('status', '--porcelain')
        $lines = if ($r.Output) { $r.Output -split "`n" } else { @() }
        $r['ConflictedFiles'] = $lines |
            Where-Object { $_ -match '^(UU|AA|DD|AU|UA|DU|UD)\s' } |
            ForEach-Object { $_.Substring(3).Trim() }
        $r['ModifiedFiles'] = $lines |
            Where-Object { $_ -notmatch '^(UU|AA|DD|AU|UA|DU|UD)\s' -and $_ -match '^\S' } |
            ForEach-Object { ($_ -replace '^\S+\s+', '').Trim() }
        $r
    }

    'Log' {
        if (-not $Range) { throw 'Range is required for Log (e.g. "abc123^..def456" or "HEAD..upstream/V_10_0_P2")' }
        if ($ShasOnly) {
            # Use rev-list --reverse to get SHAs in oldest-first (cherry-pick) order
            $r = Invoke-GitCommand -Arguments @('rev-list', '--reverse', $Range)
            $r['Commits'] = if ($r.Success -and $r.Output) {
                ($r.Output -split "`n") |
                    Where-Object { $_ -match '^[0-9a-f]{7,}$' } |
                    ForEach-Object { @{ Hash = $_; Message = '' } }
            } else { @() }
        } else {
            $logArgs = @('log', '--oneline', $Range)
            if ($Path -and $Path -ne '.') { $logArgs += '--'; $logArgs += $Path }
            $r = Invoke-GitCommand -Arguments $logArgs
            $r['Commits'] = if ($r.Success -and $r.Output) {
                ($r.Output -split "`n") |
                    Where-Object { $_ -match '^[0-9a-f]' } |
                    ForEach-Object {
                        if ($_ -match '^([0-9a-f]+)\s+(.+)$') {
                            @{ Hash = $Matches[1]; Message = $Matches[2] }
                        }
                    }
            } else { @() }
        }
        $r
    }

    'Diff' {
        $args = @('diff')
        if ($NameOnly) { $args += '--name-only' }
        if ($Range) { $args += $Range }
        if ($Path -and $Path -ne '.') { $args += '--'; $args += $Path }
        Invoke-GitCommand -Arguments $args
    }

    'Show' {
        $args = @('show')
        if ($CommitHash) { $args += $CommitHash }
        if ($Path -and $Path -ne '.') { $args += '--'; $args += $Path }
        Invoke-GitCommand -Arguments $args
    }
}

$result['Message'] = if ($result.Success) {
    "git $Operation completed successfully"
} else {
    "git $Operation failed with exit code $($result.ExitCode): $($result.Error)"
}

return $result

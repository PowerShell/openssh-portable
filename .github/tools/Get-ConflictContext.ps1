<#
.SYNOPSIS
    Retrieves three-way context for a conflicted file to aid complex conflict resolution.

.DESCRIPTION
    MCP-compatible tool that fetches three versions of a file involved in a merge or
    cherry-pick conflict — the upstream file before the commit, the upstream file after
    the commit, and our fork's version (via HEAD) — and extracts focused, line-numbered
    excerpts centered on each changed hunk.

    For each hunk in the upstream diff, the tool locates the corresponding region in our
    fork using two-tier content matching:
      Tier 1: Sliding-window overlap score against unchanged context lines from the diff.
      Tier 2: Fallback to searching for the function name from the @@ hunk header.

    This handles line-number divergence between upstream and our fork by finding the
    region by content rather than by position.

    Use this tool ONLY when conflict complexity assessment returns HIGH_COMPLEXITY.

.PARAMETER FilePath
    Path to the conflicted file, relative to the repository root.

.PARAMETER CommitHash
    The upstream commit SHA that caused the conflict. During the scratch-branch merge
    workflow, this is typically the batch endpoint commit passed to git merge.

.PARAMETER ContextLines
    Number of lines of context above and below each hunk match to include in excerpts.
    Default: 40

.PARAMETER MaxTotalLines
    Maximum total lines returned across all three versions combined (across all hunks).
    Budget per version per hunk = max(10, floor(MaxTotalLines / 3 / hunkCount)).
    The minimum floor of 10 lines per version per hunk is always enforced.
    If the floor overrides the calculated budget, a warning is included in Message.
    Default: 150 (approximately 50 lines per version)

.OUTPUTS
    Hashtable with:
      Success        [bool]     Whether the operation completed without errors
      Message        [string]   Human-readable summary (includes warnings about budget)
      CommitMessage  [string]   The commit message of CommitHash
      UpstreamDiff   [string]   Raw unified diff for the file from this commit
      HunkCount      [int]      Number of hunks found in the upstream diff
      IsBinary       [bool]     True if the file is binary (no excerpts returned)
      Hunks          [array]    One entry per hunk:
        HunkIndex      [int]      1-based hunk number
        HunkHeader     [string]   The @@ header line
        FunctionName   [string]   Function name extracted from @@ header (may be empty)
        UpstreamBefore [object]   { Lines, StartLine, EndLine, Note }
        UpstreamAfter  [object]   { Lines, StartLine, EndLine, Note }
        OurFork        [object]   { Lines, StartLine, EndLine, Note }

    Each excerpt object:
      Lines     [string[]]  The extracted lines (null if version unavailable)
      StartLine [int]       1-based line number of first line in the excerpt
      EndLine   [int]       1-based line number of last line in the excerpt
      Note      [string]    Explanation if unavailable or how region was located

.EXAMPLE
    # Get conflict context for a high-complexity conflict
    # MCP Tool: mcp_openssh-server_Get_ConflictContext
    # FilePath="auth.c", CommitHash="abc1234"

.EXAMPLE
    # Get context with increased budget for a file with many hunks
    # MCP Tool: mcp_openssh-server_Get_ConflictContext
    # FilePath="channels.c", CommitHash="abc1234", MaxTotalLines=300
#>

param(
    [Parameter(Mandatory)]
    [string]$FilePath,

    [Parameter(Mandatory)]
    [string]$CommitHash,

    [int]$ContextLines = 40,

    [int]$MaxTotalLines = 150
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── Git process helper (same pattern as Invoke-Git.ps1) ──────────────────────

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
        Output   = $stdoutTask.GetAwaiter().GetResult()
        Error    = $stderrTask.GetAwaiter().GetResult().TrimEnd()
    }
}

# ── Helper: fetch a file at a git ref ────────────────────────────────────────

function Get-FileAtRef {
    param([string]$Ref, [string]$File)

    $r = Invoke-GitCommand -Arguments @('show', "${Ref}:${File}")
    if (-not $r.Success) {
        return @{ Lines = $null; Note = "File not available at ref '${Ref}': $($r.Error.Trim())" }
    }
    $lines = $r.Output -split "`n"
    # Remove trailing empty element produced by split on a newline-terminated string
    if ($lines.Count -gt 0 -and $lines[-1] -eq '') {
        $lines = $lines[0..($lines.Count - 2)]
    }
    return @{ Lines = $lines; Note = $null }
}

# ── Helper: slice a line-numbered excerpt centred on a 1-based line ──────────

function Get-Excerpt {
    param(
        [string[]]$Lines,
        [int]$CenterLine,   # 1-based
        [int]$Budget        # max lines to return
    )

    if (-not $Lines) { return $null }
    $half  = [Math]::Floor($Budget / 2)
    $start = [Math]::Max(0, $CenterLine - 1 - $half)
    $end   = [Math]::Min($Lines.Count - 1, $CenterLine - 1 + $half)

    # Expand toward the opposite edge if we hit a boundary before using the full budget
    if (($end - $start + 1) -lt $Budget) {
        if ($start -eq 0) {
            $end = [Math]::Min($Lines.Count - 1, $Budget - 1)
        } else {
            $start = [Math]::Max(0, $end - $Budget + 1)
        }
    }

    return @{
        Lines     = $Lines[$start..$end]
        StartLine = $start + 1
        EndLine   = $end + 1
        Note      = $null
    }
}

# ── Helper: sliding-window content-anchor match ───────────────────────────────
# Returns the 1-based centre line in $FileLines that best overlaps $AnchorLines.

function Find-AnchorMatch {
    param(
        [string[]]$FileLines,
        [string[]]$AnchorLines,
        [int]$ExpectedCenter   # 1-based fallback if no match found
    )

    $anchorSet  = @{}
    foreach ($a in $AnchorLines) {
        $t = $a.Trim()
        if ($t) { $anchorSet[$t] = $true }
    }

    $windowSize = [Math]::Max($AnchorLines.Count, 5)
    $bestScore  = -1
    $bestCenter = $ExpectedCenter

    for ($i = 0; $i -le ($FileLines.Count - $windowSize); $i++) {
        $score = 0
        for ($j = $i; $j -lt ($i + $windowSize) -and $j -lt $FileLines.Count; $j++) {
            $trimmed = $FileLines[$j].Trim()
            if ($trimmed -and $anchorSet.ContainsKey($trimmed)) { $score++ }
        }
        if ($score -gt $bestScore) {
            $bestScore  = $score
            $bestCenter = $i + [Math]::Floor($windowSize / 2) + 1  # convert to 1-based
        }
    }

    return @{
        Center      = $bestCenter
        Score       = $bestScore
        MaxPossible = $anchorSet.Count
    }
}

# ── Helper: find the first line in $FileLines containing $FunctionName ───────

function Find-FunctionMatch {
    param(
        [string[]]$FileLines,
        [string]$FunctionName
    )

    $pattern = "\b$([regex]::Escape($FunctionName))\b"
    for ($i = 0; $i -lt $FileLines.Count; $i++) {
        if ($FileLines[$i] -match $pattern) {
            return $i + 1   # 1-based
        }
    }
    return -1
}

# ── Helper: parse all @@ hunks from unified diff text ────────────────────────

function Parse-DiffHunks {
    param([string]$DiffText)

    $hunks        = @()
    $lines        = $DiffText -split "`n"
    $currentHunk  = $null
    $contextAccum = @()
    $inHunk       = $false

    foreach ($line in $lines) {
        if ($line -match '^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(.*)$') {

            # Flush the previous hunk before starting a new one
            if ($null -ne $currentHunk) {
                $currentHunk['ContextLines'] = $contextAccum
                $hunks += $currentHunk
            }

            $upstreamStart = [int]$Matches[1]
            $upstreamCount = if ($Matches[2]) { [int]$Matches[2] } else { 1 }
            $afterStart    = [int]$Matches[3]
            $afterCount    = if ($Matches[4]) { [int]$Matches[4] } else { 1 }
            $funcTrailer   = $Matches[5].Trim()

            # Extract function name from the optional trailer after @@
            $funcName = ''
            if ($funcTrailer -match '(\w[\w_]*)\s*\(') {
                $funcName = $Matches[1]
            } elseif ($funcTrailer -match '(\w[\w_]+)') {
                $funcName = $Matches[1]
            }

            $currentHunk  = @{
                Header        = $line.Trim()
                FunctionName  = $funcName
                UpstreamStart = $upstreamStart
                UpstreamCount = $upstreamCount
                AfterStart    = $afterStart
                AfterCount    = $afterCount
            }
            $contextAccum = @()
            $inHunk       = $true

        } elseif ($inHunk) {
            # Collect unchanged context lines (lines starting with a space)
            if ($line -match '^ (.*)$') {
                $contextAccum += $Matches[1]
            }
        }
    }

    # Flush the last hunk
    if ($null -ne $currentHunk) {
        $currentHunk['ContextLines'] = $contextAccum
        $hunks += $currentHunk
    }

    return $hunks
}

# ── Main ──────────────────────────────────────────────────────────────────────

$warnings = @()

# 1. Get the upstream diff for this file at this commit
$diffResult = Invoke-GitCommand -Arguments @('diff', "${CommitHash}^..${CommitHash}", '--', $FilePath)
if (-not $diffResult.Success -and $diffResult.ExitCode -ne 1) {
    return @{
        Success       = $false
        Message       = "Failed to get diff for '${FilePath}' at commit ${CommitHash}: $($diffResult.Error)"
        CommitMessage = ''
        UpstreamDiff  = ''
        HunkCount     = 0
        IsBinary      = $false
        Hunks         = @()
    }
}

$upstreamDiff = $diffResult.Output

# 2. Binary file — return early with a note, no excerpts
if ($upstreamDiff -match 'Binary files .* differ') {
    return @{
        Success       = $true
        Message       = "Binary file — context not available for '${FilePath}'."
        CommitMessage = ''
        UpstreamDiff  = $upstreamDiff
        HunkCount     = 0
        IsBinary      = $true
        Hunks         = @()
    }
}

# 3. File not touched by this commit
if ([string]::IsNullOrWhiteSpace($upstreamDiff)) {
    return @{
        Success       = $true
        Message       = "File '${FilePath}' was not modified by commit ${CommitHash}."
        CommitMessage = ''
        UpstreamDiff  = ''
        HunkCount     = 0
        IsBinary      = $false
        Hunks         = @()
    }
}

# 4. Get the commit message
$commitMsgResult = Invoke-GitCommand -Arguments @('log', '-1', '--pretty=format:%s%n%n%b', $CommitHash)
$commitMessage   = if ($commitMsgResult.Success) { $commitMsgResult.Output.Trim() } else { '' }

# 5. Fetch the three file versions
#    HEAD is our fork's version of the file during both merge and cherry-pick conflicts.
#    CommitHash^ is the upstream state before the commit; CommitHash is after.
$upstreamBefore = Get-FileAtRef -Ref "${CommitHash}^" -File $FilePath
$upstreamAfter  = Get-FileAtRef -Ref "${CommitHash}"  -File $FilePath
$ourFork        = Get-FileAtRef -Ref 'HEAD'            -File $FilePath

# 6. Parse hunks from the diff
$hunks     = Parse-DiffHunks -DiffText $upstreamDiff
$hunkCount = $hunks.Count

if ($hunkCount -eq 0) {
    return @{
        Success       = $true
        Message       = "No hunks found in diff for '${FilePath}' at commit ${CommitHash}."
        CommitMessage = $commitMessage
        UpstreamDiff  = $upstreamDiff
        HunkCount     = 0
        IsBinary      = $false
        Hunks         = @()
    }
}

# 7. Compute per-hunk line budget
#    MaxTotalLines is split evenly across 3 versions and all hunks.
#    Minimum floor of 10 lines per version per hunk is always enforced.
$MIN_LINES_PER_HUNK = 10
$budgetPerHunk = [Math]::Floor($MaxTotalLines / 3 / $hunkCount)

if ($budgetPerHunk -lt $MIN_LINES_PER_HUNK) {
    $warnings += "MaxTotalLines=${MaxTotalLines} is too small for ${hunkCount} hunk(s) across 3 versions; " +
                 "minimum floor of ${MIN_LINES_PER_HUNK} lines applied — consider increasing MaxTotalLines."
    $budgetPerHunk = $MIN_LINES_PER_HUNK
}

# Never exceed the caller's ContextLines preference
$budgetPerHunk = [Math]::Min($budgetPerHunk, $ContextLines)

# 8. Build per-hunk results
$ANCHOR_SCORE_THRESHOLD = 2
$resultHunks = @()

for ($h = 0; $h -lt $hunkCount; $h++) {

    $hunk        = $hunks[$h]
    $anchorLines = $hunk['ContextLines']

    # ── upstream-before: line numbers are known from the diff header ──────────
    $uBefore = @{ Lines = $null; StartLine = $null; EndLine = $null; Note = $upstreamBefore.Note }
    if ($upstreamBefore.Lines) {
        $center  = $hunk['UpstreamStart'] + [Math]::Floor($hunk['UpstreamCount'] / 2)
        $excerpt = Get-Excerpt -Lines $upstreamBefore.Lines -CenterLine $center -Budget $budgetPerHunk
        if ($excerpt) { $uBefore = $excerpt }
    }

    # ── upstream-after: line numbers are known from the diff header ───────────
    $uAfter = @{ Lines = $null; StartLine = $null; EndLine = $null; Note = $upstreamAfter.Note }
    if ($upstreamAfter.Lines) {
        $center  = $hunk['AfterStart'] + [Math]::Floor($hunk['AfterCount'] / 2)
        $excerpt = Get-Excerpt -Lines $upstreamAfter.Lines -CenterLine $center -Budget $budgetPerHunk
        if ($excerpt) { $uAfter = $excerpt }
    }

    # ── our fork: line numbers diverge — locate by content matching ──────────
    $forkExcerpt = @{ Lines = $null; StartLine = $null; EndLine = $null; Note = $ourFork.Note }

    if ($ourFork.Lines) {
        $forkCenter = $hunk['UpstreamStart']   # fallback: use upstream line number as estimate
        $matchNote  = $null

        if ($anchorLines.Count -ge 2) {
            # Tier 1: sliding-window content match against unchanged context lines
            $match = Find-AnchorMatch -FileLines $ourFork.Lines `
                                      -AnchorLines $anchorLines `
                                      -ExpectedCenter $forkCenter

            if ($match.Score -ge $ANCHOR_SCORE_THRESHOLD) {
                $forkCenter = $match.Center
                $matchNote  = "Located via content-anchor match (score $($match.Score)/$($match.MaxPossible))."
            } elseif ($hunk['FunctionName']) {
                # Tier 2: anchor score too low — fall back to function name search
                $fnLine = Find-FunctionMatch -FileLines $ourFork.Lines -FunctionName $hunk['FunctionName']
                if ($fnLine -gt 0) {
                    $forkCenter = $fnLine
                    $matchNote  = "Located via function-name fallback ('$($hunk['FunctionName'])')."
                } else {
                    $matchNote = "Could not locate region — anchor score too low and function " +
                                 "'$($hunk['FunctionName'])' not found. Using upstream line number as estimate."
                }
            } else {
                $matchNote = "Could not locate region — anchor score too low and no function name " +
                             "available. Using upstream line number as estimate."
            }

        } elseif ($hunk['FunctionName']) {
            # Too few anchor lines for sliding window — go straight to function-name search
            $fnLine = Find-FunctionMatch -FileLines $ourFork.Lines -FunctionName $hunk['FunctionName']
            if ($fnLine -gt 0) {
                $forkCenter = $fnLine
                $matchNote  = "Located via function-name fallback ('$($hunk['FunctionName'])') — " +
                              "insufficient anchor lines for content match."
            } else {
                $matchNote = "Insufficient anchor lines and function '$($hunk['FunctionName'])' not found. " +
                             "Using upstream line number as estimate."
            }
        } else {
            $matchNote = "Insufficient anchor lines and no function name available. " +
                         "Using upstream line number as estimate."
        }

        $excerpt = Get-Excerpt -Lines $ourFork.Lines -CenterLine $forkCenter -Budget $budgetPerHunk
        if ($excerpt) {
            $excerpt['Note'] = $matchNote
            $forkExcerpt = $excerpt
        }
    }

    $resultHunks += @{
        HunkIndex      = $h + 1
        HunkHeader     = $hunk['Header']
        FunctionName   = $hunk['FunctionName']
        UpstreamBefore = $uBefore
        UpstreamAfter  = $uAfter
        OurFork        = $forkExcerpt
    }
}

# 9. Return final result
$message = if ($warnings.Count -gt 0) {
    "Context retrieved for ${hunkCount} hunk(s) in '${FilePath}' (commit ${CommitHash}). " +
    "Warnings: $($warnings -join ' | ')"
} else {
    "Context retrieved for ${hunkCount} hunk(s) in '${FilePath}' (commit ${CommitHash})."
}

return @{
    Success       = $true
    Message       = $message
    CommitMessage = $commitMessage
    UpstreamDiff  = $upstreamDiff
    HunkCount     = $hunkCount
    IsBinary      = $false
    Hunks         = $resultHunks
}

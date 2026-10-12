<#
.SYNOPSIS
    Verifies the working tree has no unresolved merge conflict markers.

.DESCRIPTION
    MCP-compatible tool that scans tracked files in the working tree for Git conflict markers
    left behind by an incomplete conflict resolution:
        <<<<<<<   (start of ours)
        =======   (divider)
        >>>>>>>   (end of theirs)
        |||||||   (base, in diff3 mode)

    Use it as a gate before completing a merge (MergeContinue), before committing build fixes,
    and before pushing the branch / opening the PR. The start/end markers (`<<<<<<<` and
    `>>>>>>>`) are treated as authoritative signals of an unresolved conflict; a lone
    `=======` line can legitimately appear (e.g. Markdown/RST underlines), so it is reported
    but only fails the check when accompanied by start/end markers in the same file.

    Scanning is done with `git grep` over tracked files, so untracked scratch files are ignored.
    It also reports any paths Git still considers unmerged (`git ls-files -u`).

.PARAMETER Path
    Optional path (file or directory, repo-relative) to limit the scan. Defaults to the whole
    repository.

.PARAMETER FailOnDivider
    When set, a lone `=======` divider also fails the check even without start/end markers.
    Off by default to avoid false positives on documentation.

.PARAMETER IncludeAll
    By default the scan excludes the merge documentation under .github/ (instructions, agents,
    prompts, skills), which legitimately contains illustrative conflict-marker examples. Set
    this switch to scan those paths too.

.OUTPUTS
    Hashtable with:
      Success        [bool]     True when no unresolved conflict markers were found
      Clean          [bool]     Alias of Success for readability
      Message        [string]   Human-readable summary
      UnmergedPaths  [string[]] Paths Git still reports as unmerged (ls-files -u)
      Conflicts      [array]    One entry per offending file:
                                  File       [string]   Repo-relative path
                                  StartCount [int]       Number of <<<<<<< lines
                                  EndCount   [int]       Number of >>>>>>> lines
                                  DivCount   [int]       Number of ======= lines
                                  BaseCount  [int]       Number of ||||||| lines
                                  Lines      [object[]]  { Line, Text } for each marker line
      Errors         [string[]] Any error messages

.EXAMPLE
    # Gate before completing a merge
    # MCP Tool: mcp_openssh-server_Test_MergeConflictMarkers

.EXAMPLE
    # Scope the scan to a single directory
    # MCP Tool: mcp_openssh-server_Test_MergeConflictMarkers
    # Path="contrib/win32/win32compat"
#>

param(
    [string]$Path,

    [switch]$FailOnDivider,

    [switch]$IncludeAll
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

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

    $completed = $process.WaitForExit(60000)

    if (-not $completed) {
        $process.Kill()
        return @{ ExitCode = -1; Success = $false; Output = ''; Error = "git $($Arguments -join ' ') timed out" }
    }

    return @{
        ExitCode = $process.ExitCode
        Success  = ($process.ExitCode -eq 0)
        Output   = $stdoutTask.GetAwaiter().GetResult()
        Error    = $stderrTask.GetAwaiter().GetResult().TrimEnd()
    }
}

$result = @{
    Success       = $false
    Clean         = $false
    Message       = ''
    UnmergedPaths = @()
    Conflicts     = @()
    Errors        = @()
}

# Unmerged paths per the index (authoritative "still conflicted" list).
$ls = Invoke-GitCommand @('ls-files', '-u')
if ($ls.Success -and $ls.Output.Trim()) {
    $result.UnmergedPaths = @($ls.Output -split "`n" | ForEach-Object {
        ($_ -split "`t")[-1]
    } | Where-Object { $_ } | Sort-Object -Unique)
}

# Grep tracked files for conflict markers. Anchored, exactly-7-char patterns.
# Note: `git grep` exits 1 (no matches) or 0 (matches) — both are "success" for our purposes.
$grepArgs = @('grep', '-nI', '-E', '-e', '^<{7}( |$)', '-e', '^={7}$', '-e', '^>{7}( |$)', '-e', '^\|{7}( |$)')
if ($Path) {
    $grepArgs += @('--', $Path)
} elseif (-not $IncludeAll) {
    # Exclude the merge documentation, which contains illustrative conflict-marker examples.
    $grepArgs += @('--',
        ':(exclude).github/instructions',
        ':(exclude).github/agents',
        ':(exclude).github/prompts',
        ':(exclude).github/skills')
}

$grep = Invoke-GitCommand $grepArgs

# ExitCode 0 = matches found, 1 = no matches, >1 = real error.
if ($grep.ExitCode -gt 1) {
    $result.Errors += "git grep failed: $($grep.Error)"
    $result.Message = 'Conflict-marker scan failed to run.'
    return $result
}

$byFile = @{}
if ($grep.Output.Trim()) {
    foreach ($line in ($grep.Output -split "`n")) {
        if (-not $line.Trim()) { continue }
        # Format: path:lineNumber:content
        $firstColon  = $line.IndexOf(':')
        if ($firstColon -lt 0) { continue }
        $secondColon = $line.IndexOf(':', $firstColon + 1)
        if ($secondColon -lt 0) { continue }

        $file    = $line.Substring(0, $firstColon)
        $lineNo  = [int]$line.Substring($firstColon + 1, $secondColon - $firstColon - 1)
        $content = $line.Substring($secondColon + 1)

        if (-not $byFile.ContainsKey($file)) {
            $byFile[$file] = @{
                File = $file; StartCount = 0; EndCount = 0; DivCount = 0; BaseCount = 0; Lines = @()
            }
        }
        switch -Regex ($content) {
            '^<{7}( |$)'  { $byFile[$file].StartCount++ }
            '^>{7}( |$)'  { $byFile[$file].EndCount++ }
            '^\|{7}( |$)' { $byFile[$file].BaseCount++ }
            '^={7}$'      { $byFile[$file].DivCount++ }
        }
        $byFile[$file].Lines += @{ Line = $lineNo; Text = $content }
    }
}

# Decide which files are real conflicts.
$conflicts = @()
foreach ($entry in $byFile.Values) {
    $hasStartEnd = ($entry.StartCount -gt 0) -or ($entry.EndCount -gt 0) -or ($entry.BaseCount -gt 0)
    $dividerOnly = -not $hasStartEnd -and ($entry.DivCount -gt 0)

    if ($hasStartEnd -or ($dividerOnly -and $FailOnDivider)) {
        $conflicts += [pscustomobject]$entry
    }
}

$result.Conflicts = @($conflicts | Sort-Object File)

$hasProblem = ($result.Conflicts.Count -gt 0) -or ($result.UnmergedPaths.Count -gt 0)
$result.Success = -not $hasProblem
$result.Clean   = $result.Success

if ($result.Success) {
    $result.Message = 'No unresolved merge conflict markers found in tracked files.'
} else {
    $parts = @()
    if ($result.Conflicts.Count -gt 0) {
        $parts += "$($result.Conflicts.Count) file(s) with conflict markers"
    }
    if ($result.UnmergedPaths.Count -gt 0) {
        $parts += "$($result.UnmergedPaths.Count) unmerged path(s) in the index"
    }
    $result.Message = "Unresolved conflicts detected: $($parts -join '; '). Resolve them before continuing the merge."
}

return $result

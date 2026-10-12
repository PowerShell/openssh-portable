<#
.SYNOPSIS
    Syncs the Windows version resource (version.rc) numbers to match the merged version.h.

.DESCRIPTION
    MCP-compatible tool used during an upstream merge after version.h has been resolved.
    Upstream owns the OpenSSH version in version.h; this fork embeds the same version in the
    Windows resource file contrib/win32/openssh/version.rc so the built binaries report the
    correct FileVersion / ProductVersion.

    The tool reads the major/minor from SSH_WINDOWS_VERSION ("OpenSSH_for_Windows_<major>.<minor>")
    and the patch from SSH_PORTABLE ("p<patch>") in version.h, then rewrites version.rc:

        FILEVERSION      <major>,<minor>,0,0
        PRODUCTVERSION   <major>,<minor>,0,0
        VALUE "FileVersion",    "<major>.<minor>.0.0"
        VALUE "ProductVersion", "OpenSSH_<major>.<minor>p<patch> for Windows"

    Design notes (per fork convention):
      - The patch number (pN) is reflected ONLY in the ProductVersion text, not in the numeric
        FILEVERSION/PRODUCTVERSION third field, which stays 0.
      - The descriptive text ("OpenSSH for Windows" / "OpenSSH_for_Windows") is preserved.
      - Existing line endings and encoding are preserved.

.PARAMETER RepoRoot
    Repository root. Defaults to two levels above this script (.github\tools -> repo root).

.PARAMETER DryRun
    Preview the changes without writing version.rc.

.OUTPUTS
    Hashtable with:
      Success       [bool]     Whether parsing succeeded and (unless DryRun) the file was written
      Message       [string]   Human-readable summary
      Major/Minor/Patch [int]  Parsed version components
      VersionHPath  [string]   Path to version.h
      VersionRcPath [string]   Path to version.rc
      Changed       [bool]     Whether version.rc content would change
      Replacements  [object[]] { Field, Old, New } for each substituted line
      Errors        [string[]] Any error messages

.EXAMPLE
    # After resolving version.h in a merge, sync the resource file
    # MCP Tool: mcp_openssh-server_Sync_VersionResource

.EXAMPLE
    # Preview only
    # MCP Tool: mcp_openssh-server_Sync_VersionResource
    # DryRun=true
#>

param(
    [string]$RepoRoot,
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $RepoRoot) {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
}

$result = @{
    Success       = $false
    Message       = ''
    Major         = 0
    Minor         = 0
    Patch         = 0
    VersionHPath  = Join-Path $RepoRoot 'version.h'
    VersionRcPath = Join-Path $RepoRoot 'contrib\win32\openssh\version.rc'
    Changed       = $false
    Replacements  = @()
    Errors        = @()
}

if (-not (Test-Path $result.VersionHPath)) {
    $result.Errors += "version.h not found at $($result.VersionHPath)"
    $result.Message = 'version.h not found.'
    return $result
}
if (-not (Test-Path $result.VersionRcPath)) {
    $result.Errors += "version.rc not found at $($result.VersionRcPath)"
    $result.Message = 'version.rc not found.'
    return $result
}

$versionH = [System.IO.File]::ReadAllText($result.VersionHPath)

# Parse major.minor from SSH_WINDOWS_VERSION "OpenSSH_for_Windows_<major>.<minor>"
if ($versionH -notmatch 'SSH_WINDOWS_VERSION\s+"OpenSSH_for_Windows_(\d+)\.(\d+)"') {
    $result.Errors += 'Could not parse SSH_WINDOWS_VERSION (expected "OpenSSH_for_Windows_<major>.<minor>") in version.h'
    $result.Message = 'Failed to parse major/minor from version.h.'
    return $result
}
$result.Major = [int]$Matches[1]
$result.Minor = [int]$Matches[2]

# Parse patch from SSH_PORTABLE "p<patch>"
if ($versionH -notmatch 'SSH_PORTABLE\s+"p(\d+)"') {
    $result.Errors += 'Could not parse SSH_PORTABLE (expected "p<patch>") in version.h'
    $result.Message = 'Failed to parse patch from version.h.'
    return $result
}
$result.Patch = [int]$Matches[1]

$major = $result.Major
$minor = $result.Minor
$patch = $result.Patch

$fileVersionNumeric = "$major,$minor,0,0"
$fileVersionString  = "$major.$minor.0.0"
$productVersionText  = "OpenSSH_$major.${minor}p$patch for Windows"

$rc = [System.IO.File]::ReadAllText($result.VersionRcPath)
$original = $rc

function Set-RcField {
    param(
        [string]$Field,
        [string]$Pattern,   # regex with capture groups; $Builder receives the Match and returns the full replacement text
        [scriptblock]$Builder
    )
    $script:rc = [regex]::Replace($script:rc, $Pattern, {
        param($m)
        $newText = & $Builder $m
        if ($m.Value -ne $newText) {
            $script:result.Replacements += [pscustomobject]@{ Field = $Field; Old = $m.Value.Trim(); New = $newText.Trim() }
        }
        return $newText
    })
}

# FILEVERSION 10,0,0,0 / PRODUCTVERSION 10,0,0,0 — group 1 is the "KEYWORD " prefix.
Set-RcField 'FILEVERSION'    '(?m)^(\s*FILEVERSION\s+)\d+,\d+,\d+,\d+'    { param($m) $m.Groups[1].Value + $fileVersionNumeric }
Set-RcField 'PRODUCTVERSION' '(?m)^(\s*PRODUCTVERSION\s+)\d+,\d+,\d+,\d+' { param($m) $m.Groups[1].Value + $fileVersionNumeric }
# VALUE "FileVersion", "..." — groups 1 and 2 are the surrounding literal text incl. quotes.
Set-RcField 'FileVersion'    '(VALUE\s+"FileVersion",\s+")[^"]*(")'        { param($m) $m.Groups[1].Value + $fileVersionString + $m.Groups[2].Value }
Set-RcField 'ProductVersion' '(VALUE\s+"ProductVersion",\s+")[^"]*(")'     { param($m) $m.Groups[1].Value + $productVersionText + $m.Groups[2].Value }

$result.Changed = ($rc -ne $original)

if ($result.Changed -and -not $DryRun) {
    # Preserve original encoding (no BOM change): write bytes back as-is UTF8 without BOM.
    $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
    [System.IO.File]::WriteAllText($result.VersionRcPath, $rc, $utf8NoBom)
}

$result.Success = $true
$verb = if ($DryRun) { 'Would update' } elseif ($result.Changed) { 'Updated' } else { 'No change needed for' }
$result.Message = "$verb version.rc to OpenSSH ${major}.${minor}p${patch} (FILEVERSION $fileVersionNumeric, ProductVersion `"$productVersionText`")."

return $result

param (
    [string] $buildopenssl,
    [string] $configuration,
    [string] $platform,
    [string] $toolset,
    [string] $paths_target_file_path,
    [string] $destDir,
    [switch] $override
)

# Workaround that $PSScriptRoot is not support on ps version 2
If ($PSVersiontable.PSVersion.Major -le 2) {$PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path}

if([string]::IsNullOrEmpty($buildopenssl))
{
    $buildopenssl = "False"
}

if([string]::IsNullOrEmpty($configuration))
{
    $configuration = "Release"
}

if([string]::IsNullOrEmpty($platform))
{
    $platform = "x64"
}

if([string]::IsNullOrEmpty($toolset))
{
    $toolset = "v142"
}

if([string]::IsNullOrEmpty($paths_target_file_path))
{
    $paths_target_file_path = Join-Path $PSScriptRoot "paths.targets"
}

if([string]::IsNullOrEmpty($destDir))
{
    $destDir = $PSScriptRoot
}

if ($buildopenssl -ieq "True")
{
    & "$PSScriptRoot\GetOpenSSL.ps1" $configuration $platform $toolset $paths_target_file_path $destDir $override
}
else
{
    & "$PSScriptRoot\GetLibreSSL.ps1" $paths_target_file_path $destDir $override
}
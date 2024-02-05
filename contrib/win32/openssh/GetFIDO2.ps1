param (
    [string] $paths_target_file_path,
    [string] $destDir,
    [switch] $override
)

# Workaround that $PSScriptRoot is not support on ps version 2
If ($PSVersiontable.PSVersion.Major -le 2) {$PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path}

if([string]::IsNullOrEmpty($paths_target_file_path))
{
    $paths_target_file_path = Join-Path $PSScriptRoot "paths.targets"
}

if([string]::IsNullOrEmpty($destDir))
{
    $destDir = $PSScriptRoot
}

if($override)
{
    Remove-Item (join-path $destDir "libfido2") -Recurse -Force -ErrorAction SilentlyContinue
}
elseif (Test-Path (Join-Path $destDir "libfido2") -PathType Container)
{
    return
}

[xml] $buildConfig = Get-Content $paths_target_file_path
$version = $buildConfig.Project.PropertyGroup.fido2Version

Write-Host "Downloading libfido2 version:$version"
Write-Host "paths_target_file_path:$paths_target_file_path"
Write-Host "destDir:$destDir"
Write-Host "override:$override"

$zip_path = Join-Path $PSScriptRoot "libfido2.zip"

$release_url = "https://github.com/PowerShell/libfido2/releases/download/$version/libfido2.zip"
Write-Host "release_url:$release_url"

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor `
                                              [Net.SecurityProtocolType]::Tls11 -bor `
                                              [Net.SecurityProtocolType]::Tls

Remove-Item $zip_path -Force -ErrorAction SilentlyContinue
Invoke-WebRequest -Uri $release_url -OutFile $zip_path -UseBasicParsing
if(-not (Test-Path $zip_path))
{
    throw "failed to download libfido2 version:$version"
}

# XXX check pgp sig?
Expand-Archive -Path $zip_path -DestinationPath $destDir\libfido2 -Force -ErrorAction SilentlyContinue -ErrorVariable e
if($e -ne $null)
{
    throw "Error when expand zip file. libfido2 version:$version"
}

Remove-Item $zip_path -Force -ErrorAction SilentlyContinue

Write-Host "Succesfully downloaded libfido2 version:$version"

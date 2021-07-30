param (
    [string] $configuration,
    [string] $platform,
    [string] $toolset,
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

if([string]::IsNullOrEmpty($destDir))
{
    $destDir = $PSScriptRoot
}

if($override)
{
    Remove-Item (join-path $destDir "ZLib") -Recurse -Force -ErrorAction SilentlyContinue
}
elseif (Test-Path (Join-Path $destDir "ZLib") -PathType Container)
{
    return
}


[xml] $buildConfig = Get-Content -Raw $paths_target_file_path
$build = $buildConfig.Project.PropertyGroup.ZLibBuild
$version = $buildConfig.Project.PropertyGroup.ZLibVersion
$file_version = $version -replace "\.",""
 
Write-Host "Downloading ZLIB version: V$version"
Write-Host "paths_target_file_path: $paths_target_file_path"
Write-Host "destDir: $destDir"
Write-Host "override: $override"
Write-Host "build: $build"

if($build)
{
    Write-Host "Configuration: $configuration"
    Write-Host "Platform: $platform"
    Write-Host "PlatformToolset: $toolset"
    $zipname = "zlib" + $file_version + ".zip"
    $zip_path = Join-Path $PSScriptRoot $zipname
    $release_url = "https://zlib.net/" + $zipname
}
else
{
    $zip_path = Join-Path $PSScriptRoot "ZLib.zip"
    $release_url = "https://github.com/PowerShell/zlib/releases/download/V$version/zlib.zip"
}
Write-Host "release_url:$release_url"

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor `
                                              [Net.SecurityProtocolType]::Tls11 -bor `
                                              [Net.SecurityProtocolType]::Tls

Remove-Item $zip_path -Force -ErrorAction SilentlyContinue
Invoke-WebRequest -Uri $release_url -OutFile $zip_path -UseBasicParsing
if(-not (Test-Path $zip_path))
{
    throw "failed to download ZLIB version:$version"
}

Write-Host "Expand archive $zip_path"
Expand-Archive -Path $zip_path -DestinationPath $destDir -Force -ErrorAction SilentlyContinue -ErrorVariable e
if($e -ne $null)
{
    throw "Error when expand zip file. ZLIB version:$version"
}

Remove-Item $zip_path -Force -ErrorAction SilentlyContinue

Write-Host "Succesfully downloaded ZLIB version:$version"

if($build)
{
     if($toolset -eq "v90")
    {
        $vc_dir = Join-Path $PSScriptRoot "zlib-$version\contrib\vstudio\vc9"    
    }
    elseif($toolset -eq "v100")
    {
        $vc_dir = Join-Path $PSScriptRoot "zlib-$version\contrib\vstudio\vc10"    
    }
    elseif($toolset -eq "v110")
    {
        $vc_dir = Join-Path $PSScriptRoot "zlib-$version\contrib\vstudio\vc11"    
    }
    elseif($toolset -eq "v120")
    {
        $vc_dir = Join-Path $PSScriptRoot "zlib-$version\contrib\vstudio\vc12"    
    }
    elseif($toolset -eq "v140")
    {
        $vc_dir = Join-Path $PSScriptRoot "zlib-$version\contrib\vstudio\vc14"    
    }
    else
    {
        $vc_dir = Join-Path $PSScriptRoot "zlib-$version\contrib\vstudio\vc14"    
        $retarget = "/p:PlatformToolset=$toolset"
    }
    $zip_dir = Join-Path $PSScriptRoot "zlib-$version" 
    Write-Host "Build ZLIB from $vc_dir"
    Write-Host "Retarget: $retarget"
    cd $vc_dir
    Write-Host "Run: msbuild .\zlibvc.sln $retarget /p:Configuration=$configuration /p:Platform=$platform"
    msbuild .\zlibvc.sln $retarget /p:Configuration=$configuration /p:Platform=$platform
    $zlib_dir = Join-Path $destDir "ZLib"
    $zlib_dir_inc = Join-Path $zlib_dir "sdk"
    $zlib_dir_bin = Join-Path $zlib_dir "bin"
    $zlib_dir_bin_pltf = Join-Path $zlib_dir_bin $platform
    New-Item -Path $zlib_dir -ItemType Directory -Force -ErrorAction Stop| Out-Null
    New-Item -Path $zlib_dir_inc -ItemType Directory -Force -ErrorAction Stop| Out-Null
    New-Item -Path $zlib_dir_bin -ItemType Directory -Force -ErrorAction Stop| Out-Null
    New-Item -Path $zlib_dir_bin_pltf -ItemType Directory -Force -ErrorAction Stop| Out-Null
    
    Copy-Item -Path "$zip_dir\zconf.h" -Destination $zlib_dir_inc -Force -ErrorAction SilentlyContinue
    Copy-Item -Path "$zip_dir\zlib.h" -Destination $zlib_dir_inc -Force -ErrorAction SilentlyContinue
    Copy-Item -Path "$vc_dir\$platform\ZlibStat$configuration\zlibstat.lib" -Destination "$zlib_dir_bin_pltf\zlib.lib" -Force -ErrorAction SilentlyContinue
    Copy-Item -Path "$vc_dir\$platform\ZlibStat$configuration\zlibstat.pdb" -Destination "$zlib_dir_bin_pltf\zlib.pdb" -Force -ErrorAction SilentlyContinue

}
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

if($override)
{
    Remove-Item (join-path $destDir "OpenSSL") -Recurse -Force -ErrorAction SilentlyContinue
}
elseif (Test-Path (Join-Path $destDir "OpenSSL") -PathType Container)
{
    return
}

function Get-NASMPath
{
    Write-Host "Searching for NASM"
    $searchPath = "c:\"
    $toolAvailable = @()
    $toolAvailable += Get-ChildItem -path $searchPath\* -Filter "NASM.exe" -Recurse -ErrorAction SilentlyContinue
    if($toolAvailable.count -eq 0)
    {
        return $null
    }
    $nasmExe = $toolAvailable[0].FullName
    return $nasmExe.Substring(0,$nasmExe.Length-9)
}
function Get-PerlPath
{
    Write-Host "Searching for perl"
    $searchPath = "c:\"
    $toolAvailable = @()
    $toolAvailable += Get-ChildItem -path $searchPath\* -Filter "perl.exe" -Recurse -ErrorAction SilentlyContinue
    if($toolAvailable.count -eq 0)
    {
        return $null
    }
   return $toolAvailable[0].FullName
}
function Get-NMAKEPath
{
    Write-Host "Searching for nmake"
    $searchPath = "${env:vctoolsinstalldir}Bin"
    $is64bit = [Environment]::Is64BitOperatingSystem
    if($is64bit -ieq "true")
    {
        if ($platform -ieq "x64")
        {
            $searchPathAlt1 = $searchPath + "\Hostx86\x86"        
            $searchPathAlt2 = $searchPath + "\Hostx64\x86"        
            $searchPath += "\Hostx64\$platform"
            if ($env:Path -ilike "*;$searchPathAlt1;*" -or $env:Path -ilike "$searchPathAlt1;*" -or $env:Path -ilike "*;$searchPathAlt1" -or $env:Path -ilike "*;$searchPathAlt2;*" -or $env:Path -ilike "$searchPathAlt2;*" -or $env:Path -ilike "*;$searchPathAlt2") 
            {
                if (-not ($env:Path -like "$searchPath;*"))
                {
                    Write-Host "Fix inconsistent Path"
                    $Env:Path = $searchPath + ";$Env:Path"    
                }
            }
            $ENV:LIB = $ENV:LIB -replace "\\x86", "\x64"
            $ENV:LIBPATH = $ENV:LIBPATH -replace "\\x86", "\x64"
        }
    } else {
        if ($platform -ieq "x86")
        {
            $searchPathAlt1 = $searchPath + "\Hostx86\x64"        
            $searchPathAlt2 = $searchPath + "\Hostx64\x64"        
            $searchPath += "\Hostx86\$platform"
            if ($env:Path -ilike "*;$searchPathAlt1;*" -or $env:Path -ilike "$searchPathAlt1;*" -or $env:Path -ilike "*;$searchPathAlt1" -or $env:Path -ilike "*;$searchPathAlt2;*" -or $env:Path -ilike "$searchPathAlt2;*" -or $env:Path -ilike "*;$searchPathAlt2") 
            {
                if (-not ($env:Path -like "$searchPath;*"))
                {
                    Write-Host "Fix inconsistent Path"
                    $Env:Path = $searchPath + ";$Env:Path"    
                }
            }
            $ENV:LIB = $ENV:LIB -replace "\\x64", "\x86"
            $ENV:LIBPATH = $ENV:LIBPATH -replace "\\x64", "\x86"
        }
    }
    $toolAvailable = @()
    $toolAvailable += Get-ChildItem -path $searchPath\* -Filter "Nmake.exe" -Recurse -ErrorAction SilentlyContinue
    if($toolAvailable.count -eq 0)
    {
        return $null
    }
   return $toolAvailable[0].FullName
}
[xml] $buildConfig = Get-Content $paths_target_file_path
$ver = $buildConfig.Project.PropertyGroup.OpenSSLVersion
$version = "V" + $buildConfig.Project.PropertyGroup.OpenSSLVersion

Write-Host "Downloading OpenSSL version:$version"
Write-Host "paths_target_file_path:$paths_target_file_path"
Write-Host "destDir:$destDir"
Write-Host "override:$override"

$zip_file = "OpenSSL_" + $ver + ".zip"
$zip_path = Join-Path $PSScriptRoot $zip_file

$release_url = "https://github.com/openssl/openssl/archive/refs/heads/$zip_file"
Write-Host "release_url:$release_url"

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor `
                                              [Net.SecurityProtocolType]::Tls11 -bor `
                                              [Net.SecurityProtocolType]::Tls

Remove-Item $zip_path -Force -ErrorAction SilentlyContinue
Invoke-WebRequest -Uri $release_url -OutFile $zip_path -UseBasicParsing
if(-not (Test-Path $zip_path))
{
    throw "failed to download OpenSSL version:$version"
}

Expand-Archive -Path $zip_path -DestinationPath $destDir -Force -ErrorAction SilentlyContinue -ErrorVariable e
if($e -ne $null)
{
    throw "Error when expand zip file. OpenSSL version:$version"
}

Remove-Item $zip_path -Force -ErrorAction SilentlyContinue

Write-Host "Succesfully downloaded OpenSSL version:$version"

$zip_dir = Join-Path $PSScriptRoot "openssl-OpenSSL_$ver" 
Write-Host "Build OpenSSL"
cd $zip_dir
$nasm = Get-Command "nasm.exe" -ErrorAction SilentlyContinue
$perl = Get-Command "perl.exe" -ErrorAction SilentlyContinue
if ($nasm -eq $null)
{
    $nasmPath = Get-NASMPath
    $env:Path = "$env:Path;$nasmPath"
    if ($nasmPath -eq $null)
    {
        throw "Error could not find NASM assembler" 
    }
}
if ($perl -eq $null)
{
    $perl = Get-PerlPath
    if ($perl -eq $null)
    {
        throw "Error could not find Perl" 
    }}
$nmake = Get-NMAKEPath
Write-Host "Run: perl $perl"
Write-Host "Run: perl Configure VC-WIN64A -static threads no-shared"
& "$perl" Configure VC-WIN64A -static threads no-shared
Write-Host "Run: nmake $nmake"
& "$nmake"
$ssl_dir = Join-Path $destDir "OpenSSL"
$ssl_dir_inc = Join-Path $ssl_dir "include"
$ssl_dir_bin = Join-Path $ssl_dir "bin"
$ssl_dir_bin_pltf = Join-Path $ssl_dir_bin $platform
New-Item -Path $ssl_dir -ItemType Directory -Force -ErrorAction Stop| Out-Null
New-Item -Path $ssl_dir_inc -ItemType Directory -Force -ErrorAction Stop| Out-Null
New-Item -Path $ssl_dir_bin -ItemType Directory -Force -ErrorAction Stop| Out-Null
New-Item -Path $ssl_dir_bin_pltf -ItemType Directory -Force -ErrorAction Stop| Out-Null

Copy-Item -Path "include/openssl"  -Destination $ssl_dir_inc -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$ssl_dir_inc/openssl/__DECC_*" -Force -ErrorAction SilentlyContinue
Copy-Item -Path "libcrypto.lib" -Destination $ssl_dir_bin_pltf -Force -ErrorAction SilentlyContinue
Copy-Item -Path "libssl.lib" -Destination $ssl_dir_bin_pltf -Force -ErrorAction SilentlyContinue
Copy-Item -Path "ossl_static.pdb" -Destination $ssl_dir_bin_pltf -Force -ErrorAction SilentlyContinue

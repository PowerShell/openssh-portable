[CmdletBinding()]
param(
    [Parameter()]
    [ValidateScript( { Test-Path -LiteralPath $_ -PathType Container })]
    [string]
    $ProjectDirectory,

    [Parameter()]
    [ValidateSet('Release', 'Debug')]
    [string]
    $Configuration = 'Release',

    [Parameter()]
    [ValidateSet('x64', 'x86')]
    [string]
    $Platform = 'x64',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]
    $DestinationPath,

    [Parameter()]
    [switch]
    $SkipClean
)

Write-Verbose -Message "Start building OpenSSH for Windows; CI = [$env:CI]"

$ErrorActionPreference = 'Stop'

New-Variable -Name SOLUTIONFILEPATH -Value '.\contrib\win32\openssh\Win32-OpenSSH.sln' -Option ReadOnly

if ($DestinationPath) {
    $DestinationPath = $PSCmdlet.GetUnresolvedProviderPathFromPSPath($DestinationPath)
    Write-Verbose -Message "DestinationPath: [$DestinationPath]"
}

if ($ProjectDirectory) {
    Write-Verbose -Message "Switching directory to [$ProjectDirectory]"
    Push-Location -LiteralPath $ProjectDirectory
}

try {
    if (-not (Test-Path -LiteralPath $SOLUTIONFILEPATH -PathType Leaf)) {
        if ($env:CI) {
            Write-Host "##vso[task.logissue type=error]Solution file [$SOLUTIONFILEPATH] not found"
        }
        throw "Solution file [$SOLUTIONFILEPATH] not found"
    }

    if ($env:CI) {
        Write-Verbose -Message "Ensure that required components are installed"
        &"${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vs_installer.exe" --quiet --config (Join-Path -Path $PSScriptRoot -ChildPath 'vsconfig.json' -Resolve)
        if ($LASTEXITCODE) {
            if ($env:CI) {
                Write-Host "##vso[task.logissue type=error]Failed to install required components. Error: $LASTEXITCODE"
            }
            throw "Failed to install required components. Error: $LASTEXITCODE"
        }
    }

    $msBuildDir = &"${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.Component.MSBuild -property installationPath
    if (0 -ne $LASTEXITCODE -or [string]::IsNullOrWhiteSpace($msBuildDir)) {
        if ($env:CI) {
            Write-Host "##vso[task.logissue type=error]MsBuild installation path not found. ErrorCode: $LASTEXITCODE; Error: $msBuildPath"
        }
        throw "MsBuild installation path not found. ErrorCode: $LASTEXITCODE; Error: $msBuildPath"
    } else {
        $msBuildPath = Join-Path -Path $msBuildDir -ChildPath 'MSBuild\Current\Bin\MSBuild.exe'
        if (-not (Test-Path -Path $msBuildPath)) {
            $msBuildPath = Join-Path -Path $msBuildDir -ChildPath 'MSBuild\15.0\Bin\MSBuild.exe'
            if (-not (Test-Path -Path $msBuildPath)) {
                if ($env:CI) {
                    Write-Host '##vso[task.logissue type=error]MsBuild installation path not found'
                }
                throw 'MsBuild installation path not found.'
            }
        }
    }
    <#
    $msBuildPath = &"${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.Component.MSBuild -find 'MSBuild\**\Bin\msbuild.exe'
    if (0 -ne $LASTEXITCODE -or [string]::IsNullOrWhiteSpace($msBuildPath)) {
        if ($env:CI) {
            Write-Host "##vso[task.logissue type=error]MsBuild installation path not found. ErrorCode: $LASTEXITCODE; Error: $msBuildPath"
        }
        throw "MsBuild installation path not found. ErrorCode: $LASTEXITCODE; Error: $msBuildPath"
    }
    #>

    Write-Verbose -Message "Getting external application msbuild.exe from [$msBuildPath]"
    $cmdMsBuild = Get-Command -Name $msBuildPath -CommandType Application -TotalCount 1

    'Clean', 'Build' `
    | Where-Object -FilterScript { 'Clean' -ne $_ -or (-not $SkipClean) } `
    | ForEach-Object -Process {
        $target = $_

        Write-Host "Executing msbuild on target $target"
        & $cmdMsBuild $SOLUTIONFILEPATH "/p:Configuration=$Configuration" "/p:Platform=$Platform" "/t:$target" /m
        if ($LASTEXITCODE) {
            if ($env:CI) {
                Write-Host "##vso[task.logissue type=error]MsBuild failed for target [$target]"
            }
            throw "MsBuild failed for target [$target]"
        }
    }

    Import-Module .\contrib\win32\openssh\OpenSSHBuildHelper.psm1 -Force -DisableNameChecking
    $argv = @{
        NativeHostArch = $Platform
        Configuration  = $Configuration
        Verbose        = $script:VerbosePreference
    }
    if ($DestinationPath) {
        $argv['DestinationPath'] = $DestinationPath
    }
    $null = Start-OpenSSHPackage @argv
    if ($DestinationPath) {
        ####
        # The OpenSSH Visual Studio solution has a bug in copying the file moduli to the output directory
        Copy-Item -Path moduli -Destination $DestinationPath
        ####

        $DestinationPath
    } else {
        Write-Warning -Message "Due to a bug in the Visual Studio solution of OpenSSH the file moduli will be missing from the created ZIP archives"
        Get-ChildItem -Path ".\bin\$Platform\$Configuration\OpenSSH*.zip"
    }

    Write-Verbose -Message 'Sucessfully built OpenSSH for Windows'
} catch {
    if ($env:CI) {
        Write-Host "##vso[task.logissue type=error]Exception caught: $_"
    }
    throw
} finally {
    if ($ProjectDirectory) {
        Write-Verbose -Message "Restoring working directory..."
        Pop-Location
    }
}

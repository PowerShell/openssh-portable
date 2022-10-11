Set-StrictMode -Version 2.0
If ($PSVersiontable.PSVersion.Major -le 2) {$PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path}
Import-Module $PSScriptRoot\OpenSSHCommonUtils.psm1 -Force

[string] $script:vcPath = $null
[System.IO.DirectoryInfo] $script:OpenSSHRoot = $null
[System.IO.DirectoryInfo] $script:gitRoot = $null
[bool] $script:Verbose = $false
[string] $script:BuildLogFile = $null
<#
    Called by Write-BuildMsg to write to the build log, if it exists. 
#>
function Write-Log
{
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string] $Message
    )
    # write it to the log file, if present.
    if (-not ([string]::IsNullOrEmpty($script:BuildLogFile)))
    {
        Add-Content -Path $script:BuildLogFile -Value $Message
    }  
}

<#
.Synopsis
    Writes a build message.
.Parameter Message
    The message to write.
.Parameter AsInfo
    Writes a user message using Write-Information.
.Parameter AsVerbose
    Writes a message using Write-Verbose and to the build log if -Verbose was specified to Start-DscBuild.
.Parameter AsWarning
    Writes a message using Write-Warning and to the build log.
.Parameter AsError
    Writes a message using Write-Error and to the build log.
.Parameter Silent
    Writes the message only to the log.
.Parameter ErrorAction
    Determines if the script is terminated when errors are written.
    This parameter is ignored when -Silent is specified.
.Example
    Write-BuildMsg -AsInfo 'Starting the build'
    Writes an informational message to the log and to the user
.Example
    Write-BuildMsg -AsError 'Terminating build' -Silent
    Writes an error message only to the log
.Example
    Write-BuildMsg -AsError 'Terminating build' -ErrorAction Stop
    Writes an error message to the log and the user and terminates the build.
.Example
    Write-BuildMsg -AsInfo 'Nuget is already installed' -Silent:(-not $script:Verbose)
    Writes an informational message to the log. If -Verbose was specified, also
    writes to message to the user.
#>
function Write-BuildMsg
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string] $Message,

        [Parameter(ParameterSetName='Info')]
        [switch] $AsInfo,

        [Parameter(ParameterSetName='Verbose')]
        [switch] $AsVerbose,

        [Parameter(ParameterSetName='Warning')]
        [switch] $AsWarning,

        [Parameter(ParameterSetName='Error')]
        [switch] $AsError,

        [switch] $Silent
    )

    if($PSBoundParameters.ContainsKey("AsVerbose"))
    {
        if ($script:Verbose)
        {
            Write-Log -Message "VERBOSE: $message"
            if (-not $Silent)
            {
                Write-Verbose -Message $message -Verbose
            }
        }
        return
    }

    if($PSBoundParameters.ContainsKey("AsInfo"))    
    {
        Write-Log -Message "INFO: $message"
        if (-not $Silent)
        {
            if(Get-Command "Write-Information" -ErrorAction SilentlyContinue )
            {
                Write-Information -MessageData $message -InformationAction Continue
            }
            else
            {
                Write-Verbose -Message $message -Verbose
            }
        }
        return
    }

    if($PSBoundParameters.ContainsKey("AsWarning"))
    {
        Write-Log -Message "WARNING: $message"
        if (-not $Silent)
        {
            Write-Warning -Message $message
        }
        return
    }

    if($PSBoundParameters.ContainsKey("AsError"))
    {
        Write-Log -Message "ERROR: $message"
        if (-not $Silent)
        {
            Write-Error -Message $message
        }
        return
    }

    # if we reached here, no output type switch was specified.
    Write-BuildMsg -AsError -ErrorAction Stop -Message 'Write-BuildMsg was called without selecting an output type.'
}

<#
.Synopsis
    Verifies all tools and dependencies required for building Open SSH are installed on the machine.
#>
function Start-OpenSSHBootstrap
{
    param(
        [ValidateSet('x86', 'x64', 'arm64', 'arm')]
        [string]$NativeHostArch = "x64",

        [switch]$OneCore)

    [bool] $silent = -not $script:Verbose
    Write-BuildMsg -AsInfo -Message "Checking tools and dependencies" -Silent:$silent

    $Win10SDKVerChoco = "10.1.17763.1"
    $machinePath = [Environment]::GetEnvironmentVariable('Path', 'MACHINE')
    $newMachineEnvironmentPath = $machinePath   

    # Install chocolatey
    $chocolateyPath = "$env:AllUsersProfile\chocolatey\bin"
    if(Get-Command choco -ErrorAction SilentlyContinue)
    {
        Write-BuildMsg -AsVerbose -Message "Chocolatey is already installed. Skipping installation." -Silent:$silent
    }
    else
    {
        Write-BuildMsg -AsInfo -Message "Chocolatey not present. Installing chocolatey." -Silent:$silent
        Invoke-Expression ((new-object net.webclient).DownloadString('https://chocolatey.org/install.ps1')) 2>&1 >> $script:BuildLogFile
    }

    if (-not ($machinePath.ToLower().Contains($chocolateyPath.ToLower())))
    {
        Write-BuildMsg -AsVerbose -Message "Adding $chocolateyPath to Path environment variable" -Silent:$silent
        $newMachineEnvironmentPath = "$chocolateyPath;$newMachineEnvironmentPath"
        if(-not ($env:Path.ToLower().Contains($chocolateyPath.ToLower())))
        {
            $env:Path = "$chocolateyPath;$env:Path"
        }
    }
    else
    {
        Write-BuildMsg -AsVerbose -Message "$chocolateyPath already present in Path environment variable" -Silent:$silent
    }

    # Add git\cmd to the path
    $gitCmdPath = "$env:ProgramFiles\git\cmd"
    if (-not ($machinePath.ToLower().Contains($gitCmdPath.ToLower())))
    {
        Write-BuildMsg -AsVerbose -Message "Adding $gitCmdPath to Path environment variable" -Silent:$silent
        $newMachineEnvironmentPath = "$gitCmdPath;$newMachineEnvironmentPath"
        if(-not ($env:Path.ToLower().Contains($gitCmdPath.ToLower())))
        {
            $env:Path = "$gitCmdPath;$env:Path"
        }
    }
    else
    {
        Write-BuildMsg -AsVerbose -Message "$gitCmdPath already present in Path environment variable" -Silent:$silent
    }

    $VS2019Path = Get-VS2019BuildToolPath
    $VS2017Path = Get-VS2017BuildToolPath
    $VS2015Path = Get-VS2015BuildToolPath

    # Update machine environment path
    if ($newMachineEnvironmentPath -ne $machinePath)
    {
        [Environment]::SetEnvironmentVariable('Path', $newMachineEnvironmentPath, 'MACHINE')
    }    

    $sdkVersion = Get-Windows10SDKVersion

    if ($null -eq $sdkVersion) 
    {
        $packageName = "windows-sdk-10.1"
        Write-BuildMsg -AsInfo -Message "$packageName not present. Installing $packageName ..."
        choco install $packageName --version=$Win10SDKVerChoco -y --force --limitoutput --execution-timeout 120 2>&1 >> $script:BuildLogFile
        # check that sdk was properly installed
        $sdkVersion = Get-Windows10SDKVersion
        if($null -eq $sdkVersion)
        {
            Write-BuildMsg -AsError -ErrorAction Stop -Message "$packageName installation failed with error code $LASTEXITCODE."
        }
    }

    # Using the Win 10 SDK, the x86/x64 builds with VS2015 need vctargetspath to be set.
    # For clarity, we set vctargetspath for the arm32/arm64 builds, as well, but it is not required.
    if (($NativeHostArch -eq 'x86') -or ($NativeHostArch -eq 'x64')) 
    {
        $env:vctargetspath = "${env:ProgramFiles(x86)}\MSBuild\Microsoft.Cpp\v4.0\v140"
        if (-not (Test-Path $env:vctargetspath)) 
        {
            Write-BuildMsg -AsInfo -Message "installing visualcpp-build-tools"
            choco install visualcpp-build-tools --version 14.0.25420.1 -y --force --limitoutput --execution-timeout 120 2>&1 >> $script:BuildLogFile
            # check that build-tools were properly installed
            if(-not (Test-Path $env:vctargetspath))
            {
                Write-BuildMsg -AsError -ErrorAction Stop -Message "visualcpp-build-tools installation failed with error code $LASTEXITCODE."
            }
        }
    }
    else
    {
        # msbuildtools have a different path for visual studio versions older than 2017
        # for visual studio versions newer than 2017, logic needs to be expanded to update the year in the path accordingly
        if ($VS2019Path -or $VS2017Path)
        {
            $VSPathYear = "2017"
            if ($VS2019Path)
            {
                $VSPathYear = "2019"
            }
            $env:vctargetspath = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\${VSPathYear}\BuildTools\Common7\IDE\VC\VCTargets"
        }
    }

    # check for corresponding build tools in the following VS order: 2019, 2017, 2015
    # environment variable is set upon install up until VS2015 but not for newer versions
    if ($VS2019Path)
    {
        if ($null -eq $env:VS160COMNTOOLS)
        {
            $env:VS160COMNTOOLS = Get-BuildToolPath -VSInstallPath $VS2019Path -version "2019"
        }
        elseif (-not (Test-Path $env:VS160COMNTOOLS))
        {
            Write-BuildMsg -AsError -ErrorAction Stop -Message "$env:VS160COMNTOOLS build tools path is invalid"   
        }
        $VSBuildToolsPath = Get-Item(Join-Path -Path $env:VS160COMNTOOLS -ChildPath '../../vc/auxiliary/build')
    }
    elseif ($VS2017Path)
    {
        if ($null -eq $env:VS150COMNTOOLS)
        {
            $env:VS150COMNTOOLS = Get-BuildToolPath -VSInstallPath $VS2017Path -version "2017"
        }
        elseif (-not (Test-Path $env:VS150COMNTOOLS))
        {
            Write-BuildMsg -AsError -ErrorAction Stop -Message "$env:VS150COMNTOOLS build tools path is invalid"   
        }
        $VSBuildToolsPath = Get-Item(Join-Path -Path $env:VS150COMNTOOLS -ChildPath '../../vc/auxiliary/build')
    }
    elseif (!$VS2015Path -or ($null -eq $env:VS140COMNTOOLS)) {
        $packageName = "vcbuildtools"
        Write-BuildMsg -AsInfo -Message "$packageName not present. Installing $packageName ..."
        choco install $packageName -ia "/InstallSelectableItems VisualCppBuildTools_ATLMFC_SDK;VisualCppBuildTools_NETFX_SDK" -y --force --limitoutput --execution-timeout 120 2>&1 >> $script:BuildLogFile
        $errorCode = $LASTEXITCODE
        if ($errorCode -eq 3010)
        {
            Write-Host "The recent package changes indicate a reboot is necessary. please reboot the machine, open a new powershell window and call Start-SSHBuild or Start-OpenSSHBootstrap again." -ForegroundColor Black -BackgroundColor Yellow
            Do {
                $input = Read-Host -Prompt "Reboot the machine? [Yes] Y; [No] N (default is `"Y`")"
                if([string]::IsNullOrEmpty($input))
                {
                    $input = 'Y'
                }
            } until ($input -match "^(y(es)?|N(o)?)$")
            [string]$ret = $Matches[0]
            if ($ret.ToLower().Startswith('y'))
            {
                Write-BuildMsg -AsWarning -Message "restarting machine ..."
                Restart-Computer -Force
                exit
            }
            else
            {
                Write-BuildMsg -AsError -ErrorAction Stop -Message "User choose not to restart the machine to apply the changes."
            }
        }
        elseif($errorCode -ne 0)
        {
            Write-BuildMsg -AsError -ErrorAction Stop -Message "$packageName installation failed with error code $errorCode."
        }
        $VSBuildToolsPath = Get-Item(Join-Path -Path $env:VS140COMNTOOLS -ChildPath '../../vc')
    }
    else
    {
        $VSBuildToolsPath = Get-Item(Join-Path -Path $env:VS140COMNTOOLS -ChildPath '../../vc')
        Write-BuildMsg -AsVerbose -Message 'VC++ 2015 Build Tools already present.'
    }

    if($NativeHostArch.ToLower().Startswith('arm') -and !$VS2019Path -and !$VS2017Path)
    {
        #TODO: Install VS2019 or VS2017 build tools
        Write-BuildMsg -AsError -ErrorAction Stop -Message "The required msbuild 15.0 is not installed on the machine."
    }

    if($OneCore -or ($NativeHostArch.ToLower().Startswith('arm')))
    {
        $win10sdk = Get-Windows10SDKVersion
        if($null -eq $win10sdk)
        {
            $packageName = "windows-sdk-10.1"
            Write-BuildMsg -AsInfo -Message "$packageName not present. Installing $packageName ..."
            choco install $packageName --version=$Win10SDKVerChoco --force --limitoutput --execution-timeout 120 2>&1 >> $script:BuildLogFile
            $win10sdk = Get-Windows10SDKVersion
            if($null -eq $win10sdk)
            {
                Write-BuildMsg -AsError -ErrorAction Stop -Message "$packageName installation failed with error code $LASTEXITCODE."
            }
        }
    }

    $script:vcPath = $VSBuildToolsPath.FullName
    Write-BuildMsg -AsVerbose -Message "vcPath: $script:vcPath" -Silent:$silent
    if ((Test-Path -Path "$script:vcPath\vcvarsall.bat") -eq $false)
    {
        Write-BuildMsg -AsError -ErrorAction Stop -Message "Could not find Visual Studio vcvarsall.bat at $script:vcPath, which means some required develop kits are missing on the machine." 
    }
}

function Start-OpenSSHPackage
{
    [CmdletBinding(SupportsShouldProcess=$false)]    
    param
    (        
        [ValidateSet('x86', 'x64', 'arm64', 'arm')]
        [string]$NativeHostArch = "x64",

        [ValidateSet('Debug', 'Release')]
        [string]$Configuration = "Release",

        # Copy payload to DestinationPath instead of packaging
        [string]$DestinationPath = "",
        [switch]$NoOpenSSL,
        [switch]$OneCore
    )

    [System.IO.DirectoryInfo] $repositoryRoot = Get-RepositoryRoot
    $repositoryRoot = Get-Item -Path $repositoryRoot.FullName
    $folderName = $NativeHostArch
    if($NativeHostArch -ieq 'x86')
    {
        $folderName = "Win32"
    }    

    $buildDir = Join-Path $repositoryRoot ("bin\" + $folderName + "\" + $Configuration)
    $payload =  "sshd.exe", "ssh.exe", "ssh-agent.exe", "ssh-add.exe", "sftp.exe"
    $payload += "sftp-server.exe", "scp.exe", "ssh-shellhost.exe", "ssh-keygen.exe", "ssh-keyscan.exe", "ssh-sk-helper.exe", "ssh-pkcs11-helper.exe"
    $payload += "sshd_config_default", "install-sshd.ps1", "uninstall-sshd.ps1"
    $payload += "FixHostFilePermissions.ps1", "FixUserFilePermissions.ps1", "OpenSSHUtils.psm1", "OpenSSHUtils.psd1"
    $payload += "openssh-events.man", "moduli", "LICENSE.txt", "NOTICE.txt"

    $packageName = "OpenSSH-Win64"
    if ($NativeHostArch -ieq 'x86') {
        $packageName = "OpenSSH-Win32"
    }
    elseif ($NativeHostArch -ieq 'arm64') {
        $packageName = "OpenSSH-ARM64"
    }
    elseif ($NativeHostArch -ieq 'arm') {
        $packageName = "OpenSSH-ARM"
    }

    while((($service = Get-Service ssh-agent -ErrorAction SilentlyContinue) -ne $null) -and ($service.Status -ine 'Stopped'))
    {        
        Stop-Service ssh-agent -Force
        #sleep to wait the servicelog file write        
        Start-Sleep 5
    }

    $packageDir = Join-Path $buildDir $packageName
    Remove-Item $packageDir -Recurse -Force -ErrorAction SilentlyContinue
    New-Item $packageDir -Type Directory | Out-Null
    
    $symbolsDir = Join-Path $buildDir ($packageName + '_Symbols')
    Remove-Item $symbolsDir -Recurse -Force -ErrorAction SilentlyContinue
    New-Item $symbolsDir -Type Directory | Out-Null
       
    foreach ($file in $payload) {
        if ((-not(Test-Path (Join-Path $buildDir $file)))) {
            Throw "Cannot find $file under $buildDir. Did you run Build-OpenSSH?"
        }
        Copy-Item (Join-Path $buildDir $file) $packageDir -Force
        if ($file.EndsWith(".exe")) {
            $pdb = $file.Replace(".exe", ".pdb")
            Copy-Item (Join-Path $buildDir $pdb) $symbolsDir -Force
        }
        if ($file.EndsWith(".dll")) {
            $pdb = $file.Replace(".dll", ".pdb")
            Copy-Item (Join-Path $buildDir $pdb) $symbolsDir -Force
        }
    }

    #copy libcrypto dll
    $libreSSLPath = Join-Path $PSScriptRoot "LibreSSL"
    if (-not $NoOpenSSL.IsPresent)
    {        
        if($OneCore)
        {
            Copy-Item -Path $(Join-Path $libreSSLPath "bin\onecore\$NativeHostArch\libcrypto.dll") -Destination $packageDir -Force -ErrorAction Stop
            Copy-Item -Path $(Join-Path $libreSSLPath "bin\onecore\$NativeHostArch\libcrypto.pdb") -Destination $symbolsDir -Force -ErrorAction Stop
        }
        else
        {
            Copy-Item -Path $(Join-Path $libreSSLPath "bin\desktop\$NativeHostArch\libcrypto.dll") -Destination $packageDir -Force -ErrorAction Stop
            Copy-Item -Path $(Join-Path $libreSSLPath "bin\desktop\$NativeHostArch\libcrypto.pdb") -Destination $symbolsDir -Force -ErrorAction Stop
        }
    }    

    if ($DestinationPath -ne "") {
        if (Test-Path $DestinationPath) {            
            Remove-Item $DestinationPath\* -Force -Recurse -ErrorAction SilentlyContinue
        }
        else {
            New-Item -ItemType Directory $DestinationPath -Force | Out-Null
        }
        Copy-Item -Path $packageDir\* -Destination $DestinationPath -Force -Recurse
        Write-BuildMsg -AsInfo -Message "Copied payload to $DestinationPath."
    }
    else {
        Remove-Item ($packageDir + '.zip') -Force -ErrorAction SilentlyContinue
        if(get-command Compress-Archive -ErrorAction SilentlyContinue)
        {
            Compress-Archive -Path $packageDir -DestinationPath ($packageDir + '.zip')
            Write-BuildMsg -AsInfo -Message "Packaged Payload - '$packageDir.zip'"
        }
        else
        {
            Write-BuildMsg -AsInfo -Message "Packaged Payload not compressed."
        }
    }
    Remove-Item $packageDir -Recurse -Force -ErrorAction SilentlyContinue
    
    if ($DestinationPath -ne "") {
        Copy-Item -Path $symbolsDir\* -Destination $DestinationPath -Force -Recurse
        Write-BuildMsg -AsInfo -Message "Copied symbols to $DestinationPath"
    }
    else {
        Remove-Item ($symbolsDir + '.zip') -Force -ErrorAction SilentlyContinue
        if(get-command Compress-Archive -ErrorAction SilentlyContinue)
        {
            Compress-Archive -Path $symbolsDir -DestinationPath ($symbolsDir + '.zip')
            Write-BuildMsg -AsInfo -Message "Packaged Symbols - '$symbolsDir.zip'"
        }
        else
        {
            Write-BuildMsg -AsInfo -Message "Packaged Symbols not compressed."
        }
    }
    Remove-Item $symbolsDir -Recurse -Force -ErrorAction SilentlyContinue
}

function Copy-OpenSSHUnitTests
{
    [CmdletBinding(SupportsShouldProcess=$false)]    
    param
    (        
        [ValidateSet('x86', 'x64', 'arm64', 'arm')]
        [string]$NativeHostArch = "x64",

        [ValidateSet('Debug', 'Release')]
        [string]$Configuration = "Release",

        # Copy unittests to DestinationPath
        [string]$DestinationPath = ""
    )

    [System.IO.DirectoryInfo] $repositoryRoot = Get-RepositoryRoot
    $repositoryRoot = Get-Item -Path $repositoryRoot.FullName
    $folderName = $NativeHostArch
    if($NativeHostArch -ieq 'x86')
    {
        $folderName = "Win32"
    }
    $buildDir = Join-Path $repositoryRoot ("bin\" + $folderName + "\" + $Configuration)
    $unittestsDir = Join-Path $buildDir "unittests"
    $unitTestFolders = Get-ChildItem -Directory $buildDir\unittest-*    
    
    if ($DestinationPath -ne "") {
        if (-not (Test-Path $DestinationPath -PathType Container)) {
            New-Item -ItemType Directory $DestinationPath -Force | Out-Null
        }
        foreach ($folder in $unitTestFolders) {
            Copy-Item $folder.FullName $DestinationPath\$($folder.Name) -Recurse -Force
            Write-BuildMsg -AsInfo -Message "Copied $($folder.FullName) to $DestinationPath\$($folder.Name)."
        }        
    }
    else {        
        if(Test-Path ($unittestsDir + '.zip') -PathType Leaf) {
            Remove-Item ($unittestsDir + '.zip') -Force -ErrorAction SilentlyContinue
        }
        if(get-command Compress-Archive -ErrorAction SilentlyContinue)
        {
            Compress-Archive -Path $unitTestFolders.FullName -DestinationPath ($unittestsDir + '.zip')
            Write-BuildMsg -AsInfo -Message "Packaged unittests - '$unittestsDir.zip'"
        }
        else
        {
            Write-BuildMsg -AsInfo -Message "Packaged unittests not compressed."
        }
    }
}

function Start-OpenSSHBuild
{
    [CmdletBinding(SupportsShouldProcess=$false)]    
    param
    (        
        [ValidateSet('x86', 'x64', 'arm64', 'arm')]
        [string]$NativeHostArch = "x64",

        [ValidateSet('Debug', 'Release')]
        [string]$Configuration = "Release",

        [switch]$NoOpenSSL,

        [switch]$OneCore
    )    
    $script:BuildLogFile = $null

    [System.IO.DirectoryInfo] $repositoryRoot = Get-RepositoryRoot

    # Get openssh-portable root
    $script:OpenSSHRoot = Get-Item -Path $repositoryRoot.FullName
    $script:gitRoot = split-path $script:OpenSSHRoot

    if($PSBoundParameters.ContainsKey("Verbose"))
    {
        $script:Verbose =  ($PSBoundParameters['Verbose']).IsPresent
    }
    [bool] $silent = -not $script:Verbose

    $script:BuildLogFile = Get-BuildLogFile -root $repositoryRoot.FullName -Configuration $Configuration -NativeHostArch $NativeHostArch
    if (Test-Path -Path $script:BuildLogFile)
    {
        Remove-Item -Path $script:BuildLogFile -force
    }

    Start-OpenSSHBootstrap -NativeHostArch $NativeHostArch -OneCore:$OneCore

    $PathTargets = Join-Path -Path $PSScriptRoot -ChildPath 'paths.targets'
    if ($NoOpenSSL) 
    {        
        [XML]$xml = Get-Content $PathTargets
        $xml.Project.PropertyGroup.UseOpenSSL = 'false'
        $xml.Project.PropertyGroup.SSLLib = [string]::Empty
        $xml.Save($PathTargets)
        $f = Join-Path $PSScriptRoot config.h.vs
        (Get-Content $f).Replace('#define WITH_OPENSSL 1','') | Set-Content $f
        (Get-Content $f).Replace('#define OPENSSL_HAS_ECC 1','') | Set-Content $f
        (Get-Content $f).Replace('#define OPENSSL_HAS_NISTP521 1','') | Set-Content $f
    }
    
    if($NativeHostArch.ToLower().Startswith('arm'))
    {
        $win10SDKVer = Get-Windows10SDKVersion
        [XML]$xml = Get-Content $PathTargets
        $xml.Project.PropertyGroup.WindowsSDKVersion = $win10SDKVer.ToString()
        $arch = $NativeHostArch.ToUpper()
        $nodeName = "WindowsSDKDesktop$($arch)Support"
        $node = $xml.Project.PropertyGroup.ChildNodes | where {$_.Name -eq $nodeName}
        if($null -eq $node)
        {
            $newElement =$xml.CreateElement($nodeName, $xml.Project.xmlns)
            $newNode = $xml.Project.PropertyGroup.AppendChild($newElement)
            $null = $newNode.AppendChild($xml.CreateTextNode("true"))
        } 
        else
        {
            $node.InnerText = "true"
        }
        $xml.Save($PathTargets)
    }

    if($OneCore)
    {
        $win10SDKVer = Get-Windows10SDKVersion
        [XML]$xml = Get-Content $PathTargets
        $xml.Project.PropertyGroup.WindowsSDKVersion = $win10SDKVer.ToString()
        $xml.Project.PropertyGroup.AdditionalDependentLibs = 'onecore.lib;shlwapi.lib'
        $xml.Project.PropertyGroup.MinimalCoreWin = 'true'
        
        #Use onecore libcrypto binaries
        $xml.Project.PropertyGroup."LibreSSL-x86-Path" = '$(SolutionDir)\LibreSSL\bin\onecore\x86\'
        $xml.Project.PropertyGroup."LibreSSL-x64-Path" = '$(SolutionDir)\LibreSSL\bin\onecore\x64\'
        $xml.Project.PropertyGroup."LibreSSL-arm-Path" = '$(SolutionDir)\LibreSSL\bin\onecore\arm\'
        $xml.Project.PropertyGroup."LibreSSL-arm64-Path" = '$(SolutionDir)\LibreSSL\bin\onecore\arm64\'
        
        $xml.Save($PathTargets)
    }
    
    $solutionFile = Get-SolutionFile -root $repositoryRoot.FullName
    $cmdMsg = @("${solutionFile}", "/t:Rebuild", "/p:Platform=${NativeHostArch}", "/p:Configuration=${Configuration}", "/m", "/nologo", "/fl", "/flp:LogFile=${script:BuildLogFile}`;Append`;Verbosity=diagnostic")    
    if($silent)
    {
        $cmdMsg += "/noconlog"
    }

    if ($msbuildCmd = Get-VS2019BuildToolPath)
    {
        Write-BuildMsg -AsInfo -Message "Using MSBuild path: $msbuildCmd"
    }
    elseif ($msbuildCmd = Get-VS2017BuildToolPath)
    {
        Write-BuildMsg -AsInfo -Message "Using MSBuild path: $msbuildCmd"
    }
    elseif ($msbuildCmd = Get-VS2015BuildToolPath)
    {
        Write-BuildMsg -AsInfo -Message "Using MSBuild path: $msbuildCmd"
    }
    else
    {
        Write-BuildMsg -AsError -ErrorAction Stop -Message "MSBuild not found"
    }

    Write-BuildMsg -AsInfo -Message "Starting Open SSH build; Build Log: $($script:BuildLogFile)."
    Write-BuildMsg -AsInfo -Message "$msbuildCmd $cmdMsg"

    & "$msbuildCmd" $cmdMsg
    $errorCode = $LASTEXITCODE

    if ($errorCode -ne 0)
    {
        Write-BuildMsg -AsError -ErrorAction Stop -Message "Build failed for OpenSSH.`nExitCode: $errorCode."
    }    

    Write-BuildMsg -AsInfo -Message "SSH build successful."
}

function Get-VS2019BuildToolPath
{
    # TODO: Should use vswhere: https://github.com/microsoft/vswhere/wiki/Find-MSBuild
    $searchPath = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2019\*\MSBuild\Current\Bin"
    if($env:PROCESSOR_ARCHITECTURE -ieq "AMD64")
    {
        $searchPath += "\amd64"
    }
    $toolAvailable = @()
    $toolAvailable += Get-ChildItem -path $searchPath\* -Filter "MSBuild.exe" -ErrorAction SilentlyContinue
    if($toolAvailable.count -eq 0)
    {
        return $null
    }
    return $toolAvailable[0].FullName
}

function Get-VS2017BuildToolPath
{
    # TODO: Should use vswhere: https://github.com/microsoft/vswhere/wiki/Find-MSBuild
    $searchPath = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2017\*\MSBuild\15.0\Bin"
    if($env:PROCESSOR_ARCHITECTURE -ieq "AMD64")
    {
        $searchPath += "\amd64"
    }
    $toolAvailable = @()
    $toolAvailable += Get-ChildItem -path $searchPath\* -Filter "MSBuild.exe" -ErrorAction SilentlyContinue
    if($toolAvailable.count -eq 0)
    {
        return $null
    }
    return $toolAvailable[0].FullName
}

function Get-VS2015BuildToolPath
{
    $searchPath = "${env:ProgramFiles(x86)}\MSBuild\14.0\Bin"
    if($env:PROCESSOR_ARCHITECTURE -ieq "AMD64")
    {
        $searchPath += "\amd64"
    }
    $toolAvailable = @()
    $toolAvailable += Get-ChildItem -path $searchPath\* -Filter "MSBuild.exe" -ErrorAction SilentlyContinue
    if($toolAvailable.count -eq 0)
    {
        return $null
    }
    return $toolAvailable[0].FullName
}

function Get-BuildToolPath
{
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$VSInstallPath,
        [string]$version)

    $buildToolsPath = Get-Item(Join-Path -Path $VSInstallPath -ChildPath '../../../../../Common7/Tools/') | % {$_.FullName}
    if (-not (Test-Path $buildToolsPath))
    {
        # assumes package name follows this format, as 2019 and 2017 both do
        $packageName = "visualstudio" + $version + "-workload-vctools"
        Write-BuildMsg -AsInfo -Message "$packageName not present. Installing $packageName ..."
        choco install $packageName --force --limitoutput --execution-timeout 120 2>&1 >> $script:BuildLogFile
        $buildToolsPath = Get-Item(Join-Path -Path $VSInstallPath -ChildPath '../../../../../../BuildTools/Common7/Tools/') | % {$.FullName}
        if (-not (Test-Path($buildToolsPath)))
        {
            Write-BuildMsg -AsError -ErrorAction Stop -Message "$packageName installation failed with error code $LASTEXITCODE."
        } 
    }   
    return $buildToolsPath
}

function Get-Windows10SDKVersion
{  
   #Temporary fix - Onecore builds are failing with latest windows 10 SDK (10.0.18362.0)
   $requiredSDKVersion = [version]"10.0.17763.0" 
   ## Search for latest windows sdk available on the machine
   $windowsSDKPath = Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\bin\$requiredSDKVersion\x86\register_app.vbs"
   if (test-path $windowsSDKPath) {
       return $requiredSDKVersion
   }
   else {
       return $null
   }
}

function Get-BuildLogFile
{
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [System.IO.DirectoryInfo] $root,

        [ValidateSet('x86', 'x64', 'arm64', 'arm')]
        [string]$NativeHostArch = "x64",
                
        [ValidateSet('Debug', 'Release')]
        [string]$Configuration = "Release"
    )
    if ($root.FullName -ieq $PSScriptRoot)
    {
        return Join-Path -Path $PSScriptRoot -ChildPath "OpenSSH$($Configuration)$($NativeHostArch).log"
    } else {
        return Join-Path -Path $root -ChildPath "contrib\win32\openssh\OpenSSH$($Configuration)$($NativeHostArch).log"
    }
}

function Get-SolutionFile
{
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [System.IO.DirectoryInfo] $root
    )    
    if ($root.FullName -ieq $PSScriptRoot)
    {
        return Join-Path -Path $PSScriptRoot -ChildPath "Win32-OpenSSH.sln"
    } else {
        return Join-Path -Path $root -ChildPath "contrib\win32\openssh\Win32-OpenSSH.sln"
    }
}



Export-ModuleMember -Function Start-OpenSSHBuild, Get-BuildLogFile, Start-OpenSSHPackage, Copy-OpenSSHUnitTests

$ErrorActionPreference = 'Stop'
Import-Module $PSScriptRoot\OpenSSHCommonUtils.psm1 -DisableNameChecking

# state object used by all tests, initialized in Setup-OpenSSHTetEnvironment
$Global:OpenSSHTestInfo = @{}
<# Hash Table definitions
#test listener name
$Global:OpenSSHTestInfo["Target"]

# test listener port
$Global:OpenSSHTestInfo["Port"]

# test user with single sign on capability
$Global:OpenSSHTestInfo["SSOUser"]

# test user to be used with explicit key for key auth
$Global:OpenSSHTestInfo["PubKeyUser"]

# test user for passwd based auth
$Global:OpenSSHTestInfo["PasswdUser"]

# common password for all test accounts
$Global:OpenSSHTestInfo.Add["TestAccountPW"]
#>


# test environment parameters initialized with defaults
$Script:OpenSSHDir = "$env:SystemDrive\OpenSSH"
$Script:OpenSSHTestDir = "$env:SystemDrive\OpenSSHTests"
$Script:PesterTestResultsFile = Join-Path $Script:OpenSSHTestDir "PesterTestResults.xml"
$Script:UnitTestResultsFile = Join-Path $Script:OpenSSHTestDir "UnitTestResults.txt"
$Script:TestSetupLogFile = Join-Path $Script:OpenSSHTestDir "TestSetupLog.txt"
$Script:SSOUser = "sshtest_ssouser"
$Script:PubKeyUser = "sshtest_pubkeyuser"
$Script:PasswdUser = "sshtest_passwduser"
$Script:OpenSSHTestAccountsPassword = "P@ssw0rd_1"
$Script:OpenSSHTestAccounts = $Script:SSOUser, $Script:PubKeyUser, $Script:PasswdUser


function Set-OpenSSHTestParams
{
    param
    (    
        [string] $OpenSSHDir = $Script:OpenSSHDir,
        [string] $OpenSSHTestDir = $Script:OpenSSHTestDir,
        [string] $PesterTestResultsFile = $Script:PesterTestResultsFile,
        [string] $UnitTestResultsFile = $Script:UnitTestResultsFile,
        [string] $TestSetupLogFile = $Script:TestSetupLogFile
    )

    $Script:OpenSSHDir = $OpenSSHDir
    $Script:OpenSSHTestDir = $OpenSSHTestDir
    $Script:PesterTestResultsFile = $PesterTestResultsFile
    $Script:UnitTestResultsFile = $UnitTestResultsFile
    $Script:TestSetupLogFile = $TestSetupLogFile
}

function Dump-OpenSSHTestParams
{
    $out = @"
OpenSSHDir:              $Script:OpenSSHDir
OpenSSHTestDir:          $Script:OpenSSHTestDir
PesterTestResultsFile:   $Script:PesterTestResultsFile
UnitTestResultsFile:     $Script:UnitTestResultsFile
TestSetupLogFile:        $Script:TestSetupLogFile
"@

    Write-Host $out
}


<#
      .SYNOPSIS
      This function installs the tools required by our tests
      1) Pester for running the tests  
      2) sysinternals required by the tests on windows.
#>
function Install-OpenSSHTestDependencies
{
    [CmdletBinding()]
    param ()

    # Install chocolatey
    if(-not (Get-Command "choco" -ErrorAction SilentlyContinue))
    {
        Write-Log -Message "Chocolatey not present. Installing chocolatey."
        Invoke-Expression ((new-object net.webclient).DownloadString('https://chocolatey.org/install.ps1')) 2>&1 >> $Script:TestSetupLogFile
    }

    $isModuleAvailable = Get-Module 'Pester' -ListAvailable
    if (-not ($isModuleAvailable))
    {      
      Write-Log -Message "Installing Pester..." 
      choco install Pester -y --force --limitoutput 2>&1 >> $Script:TestSetupLogFile
    }

    if ( -not (Test-Path "$env:ProgramData\chocolatey\lib\sysinternals\tools" ) ) {        
        Write-Log -Message "sysinternals not present. Installing sysinternals."
        choco install sysinternals -y --force --limitoutput 2>&1 >> $Script:TestSetupLogFile
    }
}
   
<#
    .Synopsis
    Setup-OpenSSHTestEnvironment
    TODO - split these steps into client and server side 
#>
function Setup-OpenSSHTestEnvironment
{
    [CmdletBinding()]
    param
    (    
        [switch] $Quiet        
    )

    $warning = @"
WARNING: Following changes will be made to OpenSSH configuration
   - sshd_config will be backed up as sshd_config.ori
   - will be replaced with a test sshd_config
   - $env:USERPROFILE\.ssh\known_hosts will be backed up as known_hosts.ori
   - will be replaced with a test known_hosts
   - sshd test listener will be on port 47002
   - $env:USERPROFILE\.ssh\known_hosts will be modified with test host key entry
   - test accounts - ssouser, pubkeyuser and passwduser will be added
   - To cleanup - Run Cleanup-OpenSSHTestEnvironment
"@

    if (-not $Quiet) {
        Write-Warning $warning
    }

    if (-not (Test-Path (Join-Path $Script:OpenSSHDir ssh.exe) -PathType Leaf))
    {
        Throw "cannot find OpenSSH binaries under $Script:OpenSSHDir Try Set-OpenSSHTestParams"
    }
    
    $sshcmd = get-command ssh.exe -ErrorAction Ignore
    if($sshcmd -eq $null) {
        Throw 'Cannot find ssh.exe. Make sure OpenSSH binary path is in %PATH%'
    }    

    #ensure ssh.exe is being picked from $Script:OpenSSHDir. Multiple versions may exist    
    if ( (Split-Path $sshcmd.Source) -ine "$Script:OpenSSHDir" ) {
        Throw "ssh.exe is being picked from $($sshcmd.Source) instead of $Script:OpenSSHDir. "
    }    

    if (-not (Test-Path $Script:OpenSSHTestDir -PathType Container )) {
        Throw "$Script:OpenSSHTestDir does not exist. Run Deploy-OpenSSHTests to deploy tests."
    }

    if ((Get-ChildItem $Script:OpenSSHTestDir).Count -eq 0) {
        Throw "Nothing found in $Script:OpenSSHTestDir. Run Deploy-OpenSSHTests to deploy tests"
    }
    #Backup existing OpenSSH configuration
    $backupConfigPath = Join-Path $Script:OpenSSHDir sshd_config.ori
    if (-not (Test-Path $backupConfigPath -PathType Leaf)) {
        Copy-Item (Join-Path $Script:OpenSSHDir sshd_config) $backupConfigPath -Force
    }
    
    # copy new sshd_config    
    Copy-Item (Join-Path $Script:OpenSSHTestDir sshd_config) (Join-Path $Script:OpenSSHDir sshd_config) -Force    
    Copy-Item $Script:OpenSSHTestDir\sshtest*hostkey* $Script:OpenSSHDir -Force    
    Restart-Service sshd -Force
   
    #Backup existing known_hosts and replace with test version
    #TODO - account for custom known_hosts locations
    $knowHostsDirectoryPath = Join-Path $home .ssh
    $knowHostsFilePath = Join-Path $knowHostsDirectoryPath known_hosts
    if(-not (Test-Path $knowHostsDirectoryPath -PathType Container))
    {
        New-Item -ItemType Directory -Path $knowHostsDirectoryPath -Force -ErrorAction SilentlyContinue | out-null
    }
    if (Test-Path $knowHostsFilePath -PathType Leaf) {
        Copy-Item $knowHostsFilePath (Join-Path $knowHostsDirectoryPath known_hosts.ori) -Force
    }
    Copy-Item (Join-Path $Script:OpenSSHTestDir known_hosts) $knowHostsFilePath -Force

    # create test accounts
    #TODO - this is Windows specific. Need to be in PAL
    foreach ($user in $Script:OpenSSHTestAccounts)
    {
        net user $user $Script:OpenSSHTestAccountsPassword /ADD 2>&1 >> $Script:TestSetupLogFile
    }

    #setup single sign on for ssouser
    #TODO - this is Windows specific. Need to be in PAL
    $ssousersid = Get-UserSID -User sshtest_ssouser
    $ssouserProfileRegistry = Join-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" $ssousersid
    if (-not (Test-Path $ssouserProfileRegistry) ) {        
        #create profile
        if (-not($env:DISPLAY)) { $env:DISPLAY = 1 }
        $env:SSH_ASKPASS="$($env:ComSpec) /c echo $($Script:OpenSSHTestAccountsPassword)"
        cmd /c "ssh -p 47002 sshtest_ssouser@localhost echo %userprofile% > profile.txt"
        if ($env:DISPLAY -eq 1) { Remove-Item env:\DISPLAY }
        remove-item "env:SSH_ASKPASS" -ErrorAction SilentlyContinue
    }
    $ssouserProfile = (Get-ItemProperty -Path $ssouserProfileRegistry -Name 'ProfileImagePath').ProfileImagePath
    New-Item -ItemType Directory -Path (Join-Path $ssouserProfile .ssh) -Force -ErrorAction SilentlyContinue  | out-null
    $authorizedKeyPath = Join-Path $ssouserProfile .ssh\authorized_keys
    $testPubKeyPath = Join-Path $Script:OpenSSHTestDir sshtest_userssokey_ed25519.pub
    (Get-Content $testPubKeyPath -Raw).Replace("`r`n","`n") | Set-Content $testPubKeyPath -Force
    Copy-Item $testPubKeyPath $authorizedKeyPath -Force -ErrorAction SilentlyContinue
    $acl = get-acl $authorizedKeyPath
    $ar = New-Object  System.Security.AccessControl.FileSystemAccessRule("NT Service\sshd", "Read", "Allow")
    $acl.SetAccessRule($ar)
    Set-Acl  $authorizedKeyPath $acl
    $testPriKeypath = Join-Path $Script:OpenSSHTestDir sshtest_userssokey_ed25519
    (Get-Content $testPriKeypath -Raw).Replace("`r`n","`n") | Set-Content $testPriKeypath -Force
    cmd /c "ssh-add $testPriKeypath 2>&1 >> $Script:TestSetupLogFile"

    $Global:OpenSSHTestInfo = @{}
    # test listener name
    $Global:OpenSSHTestInfo.Add("Target","localhost")
    # test listener port
    $Global:OpenSSHTestInfo.Add("Port", "47002")
    # test user with single sign on capability
    $Global:OpenSSHTestInfo.Add("SSOUser", $Script:SSOUser)
    # test user to be used with explicit key for key auth
    $Global:OpenSSHTestInfo.Add("PubKeyUser", $Script:PubKeyUser)
    # test user for passwd based auth
    $Global:OpenSSHTestInfo.Add("PasswdUser", $Script:PasswdUser)
    # common password for all test accounts
    $Global:OpenSSHTestInfo.Add("TestAccountPW", $Script:OpenSSHTestAccountsPassword)
}
<#
    .Synopsis
    Get-UserSID
#>
function Get-UserSID
{
    param
        (             
            [string]$Domain,            
            [string]$User
        )
    if([string]::IsNullOrEmpty($Domain))
    {
        $objUser = New-Object System.Security.Principal.NTAccount($User)
    }
    else
    {
        $objUser = New-Object System.Security.Principal.NTAccount($Domain, $User)
    }
    $strSID = $objUser.Translate([System.Security.Principal.SecurityIdentifier])
    $strSID.Value
}

<#
    .Synopsis
    Cleanup-OpenSSHTestEnvironment
#>
function Cleanup-OpenSSHTestEnvironment
{
    # .exe - Windows specific. TODO - PAL 
    if (-not (Test-Path (Join-Path $Script:OpenSSHDir ssh.exe) -PathType Leaf))
    {
        Throw "Cannot find OpenSSH binaries under $($Script:OpenSSHDir). Try -OpenSSHDir parameter"
    }

    #Restore sshd_config
    $backupConfigPath = Join-Path $Script:OpenSSHDir sshd_config.ori
    if (Test-Path $backupConfigPath -PathType Leaf) {        
        Copy-Item $backupConfigPath (Join-Path $Script:OpenSSHDir sshd_config) -Force -ErrorAction SilentlyContinue
        Remove-Item (Join-Path $Script:OpenSSHDir sshd_config.ori) -Force -ErrorAction SilentlyContinue
        Remove-Item $Script:OpenSSHDir\sshtest*hostkey* -Force -ErrorAction SilentlyContinue
        Restart-Service sshd
    }
    
    #Restore known_hosts
    $originKnowHostsPath = Join-Path $home .ssh\known_hosts.ori
    if (Test-Path $originKnowHostsPath)
    {
        Copy-Item $originKnowHostsPath (Join-Path $home .ssh\known_hosts) -Force -ErrorAction SilentlyContinue
        Remove-Item $originKnowHostsPath -Force -ErrorAction SilentlyContinue
    }

    #Delete accounts
    foreach ($user in $Script:OpenSSHTestAccounts)
    {
        net user $user /delete
    }
    
    # remove registered keys    
    cmd /c "ssh-add -d (Join-Path $Script:OpenSSHTestDir sshtest_userssokey_ed25519) 2>&1 >> $Script:TestSetupLogFile"

    $Global:OpenSSHTestInfo = $null
}

<#
    .Synopsis
    Deploy all required files to a location and install the binaries
#>
function Install-OpenSSH
{
    [CmdletBinding()]
    param
    ( 
        [ValidateSet('Debug', 'Release', '')]
        [string]$Configuration = "",

        [ValidateSet('x86', 'x64', '')]
        [string]$NativeHostArch = ""
    )

    Deploy-Win32OpenSSHBinaries @PSBoundParameters

    Push-Location $Script:OpenSSHDir 
    & ( "$Script:OpenSSHDir\install-sshd.ps1") 
    Start-Service ssh-agent
    & ( "$Script:OpenSSHDir\install-sshlsa.ps1")

    #machine will be reboot after Install-openssh anyway
    $machinePath = [Environment]::GetEnvironmentVariable('Path', 'MACHINE')
    $newMachineEnvironmentPath = $machinePath
    if (-not ($machinePath.ToLower().Contains($($Script:OpenSSHDir).ToLower())))
    {
        $newMachineEnvironmentPath = "$($Script:OpenSSHDir);$newMachineEnvironmentPath"
        $env:Path = "$($Script:OpenSSHDir);$env:Path"
    }
    # Update machine environment path
    if ($newMachineEnvironmentPath -ne $machinePath)
    {
        [Environment]::SetEnvironmentVariable('Path', $newMachineEnvironmentPath, 'MACHINE')
    }
    
    Set-Service sshd -StartupType Automatic 
    Set-Service ssh-agent -StartupType Automatic
    Start-Service sshd

    Pop-Location
    Write-Log -Message "OpenSSH installed!"
}

<#
    .Synopsis
    uninstalled sshd and sshla
#>
function UnInstall-OpenSSH
{
    Push-Location $Script:OpenSSHDir
    if((Get-Service ssh-agent -ErrorAction Ignore) -ne $null) {
        Stop-Service ssh-agent -Force
    }
    &( "$Script:OpenSSHDir\uninstall-sshd.ps1")
    &( "$Script:OpenSSHDir\uninstall-sshlsa.ps1")
        
    $machinePath = [Environment]::GetEnvironmentVariable('Path', 'MACHINE')
    $newMachineEnvironmentPath = $machinePath
    if ($machinePath.ToLower().Contains($($Script:OpenSSHDir).ToLower()))
    {        
        $newMachineEnvironmentPath.Replace("$($Script:OpenSSHDir);", '')
        $env:Path = $env:Path.Replace("$($Script:OpenSSHDir);", '')
    }

    # Update machine environment path
    # machine will be reboot after Uninstall-OpenSSH
    if ($newMachineEnvironmentPath -ne $machinePath)
    {
        [Environment]::SetEnvironmentVariable('Path', $newMachineEnvironmentPath, 'MACHINE')
    }

    Pop-Location
}

<#
    .Synopsis
    Deploy all required files to build a package and create zip file.
#>
function Deploy-Win32OpenSSHBinaries
{
    [CmdletBinding()]
    param
    (
        [ValidateSet('Debug', 'Release', '')]
        [string]$Configuration = "",
        [ValidateSet('x86', 'x64', '')]
        [string]$NativeHostArch = ""
    )

    if (-not (Test-Path -Path $Script:OpenSSHDir -PathType Container))
    {
        $null = New-Item -Path $Script:OpenSSHDir -ItemType Directory -Force -ErrorAction Stop
    }

    [string] $platform = $env:PROCESSOR_ARCHITECTURE    
    if(-not [String]::IsNullOrEmpty($NativeHostArch))
    {
        $folderName = $NativeHostArch
        if($NativeHostArch -ieq 'x86')
        {
            $folderName = "Win32"
        }
    }
    else
    {
        if($platform -ieq "AMD64")
        {
            $folderName = "x64"
        }
        else
        {
            $folderName = "Win32"
        }
    }
    
    if([String]::IsNullOrEmpty($Configuration))
    {
        if( $folderName -ieq "Win32" )
        {
            $RealConfiguration = "Debug"
        }
        else
        {
            $RealConfiguration = "Release"
        }
    }
    else
    {
        $RealConfiguration = $Configuration
    }

    [System.IO.DirectoryInfo] $repositoryRoot = Get-RepositoryRoot
    
    $sourceDir = Join-Path $repositoryRoot.FullName -ChildPath "bin\$folderName\$RealConfiguration"
    if((Get-Service ssh-agent -ErrorAction Ignore) -ne $null) {
        Stop-Service ssh-agent -Force
    }
    Copy-Item -Path "$sourceDir\*" -Destination $Script:OpenSSHDir -Include *.exe,*.dll -Exclude *unittest*.* -Force -ErrorAction Stop
    $sourceDir = Join-Path $repositoryRoot.FullName -ChildPath "contrib\win32\openssh"
    Copy-Item -Path "$sourceDir\*" -Destination $Script:OpenSSHDir -Include *.ps1,sshd_config -Exclude AnalyzeCodeDiff.ps1 -Force -ErrorAction Stop
        
    $packageName = "rktools.2003"
    $rktoolsPath = "${env:ProgramFiles(x86)}\Windows Resource Kits\Tools\ntrights.exe"
    if (-not (Test-Path -Path $rktoolsPath))
    {        
        Write-Log -Message "$packageName not present. Installing $packageName."
        choco install $packageName -y --force 2>&1 >> $Script:TestSetupLogFile
        if (-not (Test-Path -Path $rktoolsPath))
        {
            choco install $packageName -y --force 2>&1 >> $Script:TestSetupLogFile
            if (-not (Test-Path -Path $rktoolsPath))
            {                
                throw "failed to download $packageName"
            }
        }
    }

    Copy-Item -Path $rktoolsPath -Destination $Script:OpenSSHDir -Force -ErrorAction Stop
}

<#
    .Synopsis
    After build and test run completes, upload all artifacts from the build machine.
#>
function Deploy-OpenSSHTests
{
    [CmdletBinding()]
    param
    (
        [ValidateSet('Debug', 'Release', '')]
        [string]$Configuration = "",

        [ValidateSet('x86', 'x64', '')]
        [string]$NativeHostArch = ""
    )

    if (-not (Test-Path -Path $Script:OpenSSHTestDir -PathType Container))
    {
        $null = New-Item -Path $Script:OpenSSHTestDir -ItemType Directory -Force -ErrorAction Stop
    }

    [string] $platform = $env:PROCESSOR_ARCHITECTURE
    if(-not [String]::IsNullOrEmpty($NativeHostArch))
    {
        $folderName = $NativeHostArch
        if($NativeHostArch -eq 'x86')
        {
            $folderName = "Win32"
        }
    }
    else
    {
        if($platform -ieq "AMD64")
        {
            $folderName = "x64"
        }
        else
        {
            $folderName = "Win32"
        }
    }

    if([String]::IsNullOrEmpty($Configuration))
    {
        if( $folderName -ieq "Win32" )
        {
            $RealConfiguration = "Debug"
        }
        else
        {
            $RealConfiguration = "Release"
        }
    }
    else
    {
        $RealConfiguration = $Configuration
    }    

    [System.IO.DirectoryInfo] $repositoryRoot = Get-RepositoryRoot
    #copy all pester tests
    $sourceDir = Join-Path $repositoryRoot.FullName -ChildPath "regress\pesterTests"
    Copy-Item -Path "$sourceDir\*" -Destination $Script:OpenSSHTestDir -Include *.ps1,*.psm1, sshd_config, known_hosts, sshtest_* -Force -ErrorAction Stop
    #copy all unit tests.
    $sourceDir = Join-Path $repositoryRoot.FullName -ChildPath "bin\$folderName\$RealConfiguration"    
    Copy-Item -Path "$sourceDir\*" -Destination "$($Script:OpenSSHTestDir)\" -Container -Include unittest-* -Recurse -Force -ErrorAction Stop
}

<#
    .Synopsis
    Run OpenSSH pester tests.
#>
function Run-OpenSSHPesterTest
{     
   # Discover all CI tests and run them.
    Push-Location $Script:OpenSSHTestDir
    Write-Log -Message "Running OpenSSH Pester tests..."    
    $testFolders = Get-ChildItem *.tests.ps1 -Recurse -Exclude SSHDConfig.tests.ps1, SSH.Tests.ps1 | ForEach-Object{ Split-Path $_.FullName} | Sort-Object -Unique
    Invoke-Pester $testFolders -OutputFormat NUnitXml -OutputFile $Script:PesterTestResultsFile -Tag 'CI'
    Pop-Location
}

<#
    .Synopsis
    Run openssh unit tests.
#>
function Run-OpenSSHUnitTest
{     
   # Discover all CI tests and run them.
    Push-Location $Script:OpenSSHTestDir
    Write-Log -Message "Running OpenSSH unit tests..."
    if (Test-Path $Script:UnitTestResultsFile)    
    {
        $null = Remove-Item -Path $Script:UnitTestResultsFile -Force -ErrorAction SilentlyContinue
    }
    $testFolders = Get-ChildItem unittest-*.exe -Recurse -Exclude unittest-sshkey.exe,unittest-kex.exe |
                 ForEach-Object{ Split-Path $_.FullName} |
                 Sort-Object -Unique
    $testfailed = $false
    if ($testFolders -ne $null)
    {
        $testFolders | % {
            Push-Location $_
            $unittestFile = "$(Split-Path $_ -Leaf).exe"
            Write-log "Running OpenSSH unit $unittestFile ..."
            & .\$unittestFile >> $Script:UnitTestResultsFile
            
            $errorCode = $LASTEXITCODE
            if ($errorCode -ne 0)
            {
                $testfailed = $true
                $errorMessage = "$($_.FullName) test failed for OpenSSH.`nExitCode: $errorCode. Detail test log is at $($Script:UnitTestResultsFile)."
                Write-Warning $errorMessage                         
            }
            Pop-Location
        }
    }
    Pop-Location
    $testfailed
}

<#
    Write-Log 
#>
function Write-Log
{
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string] $Message
    )
    if(-not (Test-Path (Split-Path $Script:TestSetupLogFile) -PathType Container))
    {
        $null = New-Item -ItemType Directory -Path (Split-Path $Script:TestSetupLogFile) -Force -ErrorAction SilentlyContinue | out-null
    }
    if (-not ([string]::IsNullOrEmpty($Script:TestSetupLogFile)))
    {
        Add-Content -Path $Script:TestSetupLogFile -Value $Message
    }  
}

Export-ModuleMember -Function Set-OpenSSHTestParams, Dump-OpenSSHTestParams, Install-OpenSSH, Install-OpenSSHTestDependencies, Setup-OpenSSHTestEnvironment, Cleanup-OpenSSHTestEnvironment, Deploy-OpenSSHTests, Run-OpenSSHUnitTest, Run-OpenSSHPesterTest

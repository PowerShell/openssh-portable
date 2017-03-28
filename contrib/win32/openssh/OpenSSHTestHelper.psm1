$ErrorActionPreference = 'Stop'
Import-Module $PSScriptRoot\OpenSSHCommonUtils.psm1 -DisableNameChecking

# state object used by all tests, initialized in Setup-OpenSSHTetEnvironment
#$Global:OpenSSHTestInfo = @{}
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
$Global:OpenSSHTestInfo["TestAccountPW"]

# openssh bin path
$Global:OpenSSHTestInfo["OpenSSHDir"]

# openssh tests path
$Global:OpenSSHTestInfo["OpenSSHTestDir"]

# openssh test setup log file
$Global:OpenSSHTestInfo["TestSetupLogFile"]

# openssh E2E test results file
$Global:OpenSSHTestInfo["E2ETestResultsFile"]

# openssh unittest test results file
$Global:OpenSSHTestInfo["UnitTestResultsFile"]

#>


# test environment parameters initialized with defaults
$E2ETestResultsFileName = "E2ETestResults.xml"
$UnitTestResultsFileName = "UnitTestResults.txt"
$TestSetupLogFileName = "TestSetupLog.txt"
$SSOUser = "sshtest_ssouser"
$PubKeyUser = "sshtest_pubkeyuser"
$PasswdUser = "sshtest_passwduser"
$OpenSSHTestAccountsPassword = "P@ssw0rd_1"
$OpenSSHTestAccounts = $Script:SSOUser, $Script:PubKeyUser, $Script:PasswdUser

$Script:OpenSSHTestDir = "$env:SystemDrive\OpenSSHTests"
$Script:E2ETestResultsFile = Join-Path $OpenSSHTestDir $E2ETestResultsFileName
$Script:UnitTestResultsFile = Join-Path $OpenSSHTestDir $UnitTestResultsFileName
$Script:TestSetupLogFile = Join-Path $OpenSSHTestDir $TestSetupLogFileName


   
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
        [switch] $Quiet,
        [string] $OpenSSHDir,
        [string] $OpenSSHTestDir = "$env:SystemDrive\OpenSSHTests",
        [Boolean] $DebugMode = $false
    )
    
    if($Global:OpenSSHTestInfo -ne $null)
    {
        $Global:OpenSSHTestInfo.Clear()
        $Global:OpenSSHTestInfo = $null
    }
    $Script:OpenSSHTestDir = $OpenSSHTestDir;
    $Script:E2ETestResultsFile = Join-Path $OpenSSHTestDir "E2ETestResults.xml"
    $Script:UnitTestResultsFile = Join-Path $OpenSSHTestDir "UnitTestResults.txt"
    $Script:TestSetupLogFile = Join-Path $OpenSSHTestDir "TestSetupLog.txt"

    $Global:OpenSSHTestInfo = @{        
        "Target"= "localhost";                                 # test listener name
        "Port"= "47002";                                       # test listener port
        "SSOUser"= $SSOUser;                                   # test user with single sign on capability
        "PubKeyUser"= $PubKeyUser;                             # test user to be used with explicit key for key auth
        "PasswdUser"= $PasswdUser;                             # common password for all test accounts
        "TestAccountPW"= $OpenSSHTestAccountsPassword;         # common password for all test accounts
        "OpenSSHTestDir" = $OpenSSHTestDir;                    # openssh tests path
        "TestSetupLogFile" = $Script:TestSetupLogFile;         # openssh test setup log file
        "E2ETestResultsFile" = $Script:E2ETestResultsFile;     # openssh E2E test results file
        "UnitTestResultsFile" = $Script:UnitTestResultsFile;   # openssh unittest test results file
        "DebugMode" = $DebugMode                               # run openssh E2E in debug mode
        }
        
    #if user does not set path, pick it up
    if([string]::IsNullOrEmpty($OpenSSHDir))
    {
        $sshcmd = get-command ssh.exe -ErrorAction Ignore        
        if($sshcmd -eq $null)
        {
            Throw "Cannot find ssh.exe. Please specify -OpenSSHDir to the OpenSSH installed location."
        }
        elseif($Quiet)
        {
            $dirToCheck = split-path $sshcmd.Path
            $script:OpenSSHDir = $dirToCheck
        }
        else
        {
            $dirToCheck = split-path $sshcmd.Path
            $message = "Do you want to pick up ssh.exe from $($dirToCheck)? [Yes] Y; [No] N (default is `"Y`")"
            $response = Read-Host -Prompt $message
            if( ($response -eq "") -or ($response -ieq "Y") -or ($response -ieq "Yes") )
            {
                $script:OpenSSHDir = $dirToCheck
            }
            elseif( ($response -ieq "N") -or ($response -ieq "No") )
            {
                Write-Host "User decided not to pick up ssh.exe from $dirToCheck. Please specify -OpenSSHDir to the OpenSSH installed location."
                return
            }
            else
            {
                Throw "User entered invalid option ($response). Please specify -OpenSSHDir to the OpenSSH installed location"
            }
        }        
    }
    else
    {        
        if (-not (Test-Path (Join-Path $OpenSSHDir ssh.exe) -PathType Leaf))
        {
            Throw "Cannot find OpenSSH binaries under $OpenSSHDir. Please specify -OpenSSHDirto the OpenSSH installed location"
        }
        else
        {
            $script:OpenSSHDir = $OpenSSHDir
        }
    }

    $Global:OpenSSHTestInfo.Add("OpenSSHDir", $script:OpenSSHDir)

    $warning = @"
WARNING: Following changes will be made to OpenSSH configuration
   - sshd_config will be backed up as sshd_config.ori
   - will be replaced with a test sshd_config
   - $HOME\.ssh\known_hosts will be backed up as known_hosts.ori
   - will be replaced with a test known_hosts
   - sshd test listener will be on port 47002
   - $HOME\.ssh\known_hosts will be modified with test host key entry
   - test accounts - ssouser, pubkeyuser, and passwduser will be added
   - Setup single signon for ssouser
   - To cleanup - Run Cleanup-OpenSSHTestEnvironment
"@

    if (-not $Quiet) {
        Write-Warning $warning
        $continue = Read-Host -Prompt "Do you want to continue with the above changes? [Yes] Y; [No] N (default is `"Y`")"
        if( ($continue -eq "") -or ($continue -ieq "Y") -or ($continue -ieq "Yes") )
        {            
        }
        elseif( ($continue -ieq "N") -or ($continue -ieq "No") )
        {
            Write-Host "User decided not to make the changes."
            return
        }
        else
        {
            Throw "User entered invalid option ($continue).Exit now."
        }
    }

    Install-OpenSSHTestDependencies
    $continue = "Y"
    if(-not $Quiet)
    {
        $message = "Do you want to deploy test binaries/scripts to $OpenSSHTestDir? [Yes] Y; [No] N (default is `"Y`")"
        $continue = Read-Host -Prompt $message
    }    

    if( ($continue -eq "") -or ($continue -ieq "Y") -or ($continue -ieq "Yes") )
    {
        Deploy-OpenSSHTests -OpenSSHTestDir $OpenSSHTestDir
    }
    elseif( ($continue -ieq "N") -or ($continue -ieq "No") )
    {
        Write-Host "User decided not to deploy test binaries/scripts."
    }
    else
    {
        Throw "User entered invalid option ($continue). Exit now."
    }
    
    #Backup existing OpenSSH configuration
    $backupConfigPath = Join-Path $script:OpenSSHDir sshd_config.ori
    if (-not (Test-Path $backupConfigPath -PathType Leaf)) {
        Copy-Item (Join-Path $script:OpenSSHDir sshd_config) $backupConfigPath -Force
    }
    
    # copy new sshd_config    
    Copy-Item (Join-Path $OpenSSHTestDir sshd_config) (Join-Path $script:OpenSSHDir sshd_config) -Force    
    Copy-Item $OpenSSHTestDir\sshtest*hostkey* $script:OpenSSHDir -Force    
    Restart-Service sshd -Force
   
    #Backup existing known_hosts and replace with test version
    #TODO - account for custom known_hosts locations
    $knowHostsDirectoryPath = Join-Path $home .ssh
    $knowHostsFilePath = Join-Path $knowHostsDirectoryPath known_hosts
    if(-not (Test-Path $knowHostsDirectoryPath -PathType Container))
    {
        New-Item -ItemType Directory -Path $knowHostsDirectoryPath -Force -ErrorAction SilentlyContinue | out-null
    }
    if ((Test-Path $knowHostsFilePath -PathType Leaf) -and (-not (Test-Path (Join-Path $knowHostsDirectoryPath known_hosts.ori) -PathType Leaf))) {
        Copy-Item $knowHostsFilePath (Join-Path $knowHostsDirectoryPath known_hosts.ori) -Force
    }
    Copy-Item (Join-Path $OpenSSHTestDir known_hosts) $knowHostsFilePath -Force

    # create test accounts
    #TODO - this is Windows specific. Need to be in PAL
    foreach ($user in $OpenSSHTestAccounts)
    {
        try 
        {
            $objUser = New-Object System.Security.Principal.NTAccount($user)
            $strSID = $objUser.Translate([System.Security.Principal.SecurityIdentifier])
        }
        catch
        {    
            #only add the local user when it does not exists on the machine        
            net user $user $Script:OpenSSHTestAccountsPassword /ADD 2>&1 >> $Script:TestSetupLogFile
        }
    }

    #setup single sign on for ssouser
    #TODO - this is Windows specific. Need to be in PAL
    $ssousersid = Get-UserSID -User sshtest_ssouser
    $ssouserProfileRegistry = Join-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" $ssousersid
    if (-not (Test-Path $ssouserProfileRegistry) ) {        
        #create profile
        if (-not($env:DISPLAY)) { $env:DISPLAY = 1 }
        $env:SSH_ASKPASS="$($env:ComSpec) /c echo $($OpenSSHTestAccountsPassword)"
        cmd /c "ssh -p 47002 sshtest_ssouser@localhost echo %userprofile% > profile.txt"
        if ($env:DISPLAY -eq 1) { Remove-Item env:\DISPLAY }
        remove-item "env:SSH_ASKPASS" -ErrorAction SilentlyContinue
    }
    $ssouserProfile = (Get-ItemProperty -Path $ssouserProfileRegistry -Name 'ProfileImagePath').ProfileImagePath
    New-Item -ItemType Directory -Path (Join-Path $ssouserProfile .ssh) -Force -ErrorAction SilentlyContinue  | out-null
    $authorizedKeyPath = Join-Path $ssouserProfile .ssh\authorized_keys
    $testPubKeyPath = Join-Path $OpenSSHTestDir sshtest_userssokey_ed25519.pub
    #workaround for the cariggage new line added by git
    (Get-Content $testPubKeyPath -Raw).Replace("`r`n","`n") | Set-Content $testPubKeyPath -Force
    Copy-Item $testPubKeyPath $authorizedKeyPath -Force -ErrorAction SilentlyContinue
    $acl = get-acl $authorizedKeyPath
    $ar = New-Object  System.Security.AccessControl.FileSystemAccessRule("NT Service\sshd", "Read", "Allow")
    $acl.SetAccessRule($ar)
    Set-Acl  $authorizedKeyPath $acl
    $testPriKeypath = Join-Path $OpenSSHTestDir sshtest_userssokey_ed25519
    (Get-Content $testPriKeypath -Raw).Replace("`r`n","`n") | Set-Content $testPriKeypath -Force
    cmd /c "ssh-add $testPriKeypath 2>&1 >> $Script:TestSetupLogFile"
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
    if (-not (Test-Path (Join-Path $script:OpenSSHDir ssh.exe) -PathType Leaf))
    {
        Throw "Cannot find OpenSSH binaries under $script:OpenSSHDir. "
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
    foreach ($user in $OpenSSHTestAccounts)
    {
        net user $user /delete
    }
    
    # remove registered keys    
    cmd /c "ssh-add -d (Join-Path $Script:OpenSSHTestDir sshtest_userssokey_ed25519) 2>&1 >> $Script:TestSetupLogFile"

    if($Global:OpenSSHTestInfo -ne $null)
    {
        $Global:OpenSSHTestInfo.Clear()
        $Global:OpenSSHTestInfo = $null
    }
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
        [string]$NativeHostArch = "",

        [string]$OpenSSHTestDir = "$env:SystemDrive\OpenSSHTests"
    )

    if (-not (Test-Path -Path $OpenSSHTestDir -PathType Container))
    {
        $null = New-Item -Path $OpenSSHTestDir -ItemType Directory -Force -ErrorAction Stop
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
    Copy-Item -Path "$sourceDir\*" -Destination $OpenSSHTestDir -Include *.ps1,*.psm1, sshd_config, known_hosts, sshtest_* -Force -ErrorAction Stop
    #copy all unit tests.
    $sourceDir = Join-Path $repositoryRoot.FullName -ChildPath "bin\$folderName\$RealConfiguration"    
    Copy-Item -Path "$sourceDir\*" -Destination "$($OpenSSHTestDir)\" -Container -Include unittest-* -Recurse -Force -ErrorAction Stop
}

<#
    .Synopsis
    Run OpenSSH pester tests.
#>
function Run-OpenSSHE2ETest
{     
   # Discover all CI tests and run them.
    Push-Location $Script:OpenSSHTestDir
    Write-Log -Message "Running OpenSSH E2E tests..."    
    $testFolders = Get-ChildItem *.tests.ps1 -Recurse -Exclude SSHDConfig.tests.ps1, SSH.Tests.ps1 | ForEach-Object{ Split-Path $_.FullName} | Sort-Object -Unique
    Invoke-Pester $testFolders -OutputFormat NUnitXml -OutputFile $Script:E2ETestResultsFile -Tag 'CI'
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

Export-ModuleMember -Function Setup-OpenSSHTestEnvironment, Cleanup-OpenSSHTestEnvironment, Run-OpenSSHUnitTest, Run-OpenSSHE2ETest

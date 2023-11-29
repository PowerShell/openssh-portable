##
## Azure DevOps CI build tools
## [Add appropriate copyright]
##

$ErrorActionPreference = 'Stop'

$repoRoot = Get-RepositoryRoot
$script:messageFile = join-path $repoRoot.FullName "BuildMessage.log"

function Write-BuildMessage
{
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string] $Message,

        [ValidateNotNullOrEmpty()]
        [string] $Category = "Information"
    )

    # Write message to verbose stream.
    Write-Verbose -Verbose -Message "$Category--$Message"

    # Write it to the log file, if present.
    if (-not ([string]::IsNullOrEmpty($script:messageFile)))
    {
        Add-Content -Path $script:messageFile -Value "$Category--$Message"
    }
}

<#
    .Synopsis
    Implements the AzDO build package step
#>
function Invoke-AzDOBuild
{
      Start-OpenSSHBuild -Configuration Release -NativeHostArch x64 -Verbose
      Start-OpenSSHBuild -Configuration Release -NativeHostArch x86 -Verbose
      Write-BuildMessage -Message "OpenSSH binaries build success!" -Category Information
}

<#
    .Synopsis
    Deploy all required files to a location and install the binaries
#>
function Install-OpenSSH
{
    [CmdletBinding()]
    param ( 
        [Parameter(Mandatory=$true)]
        [string]$SourceDir,

        [string]$OpenSSHDir = "$env:SystemDrive\OpenSSH"
    )

    UnInstall-OpenSSH -OpenSSHDir $OpenSSHDir

    if (! (Test-Path -Path $OpenSSHDir)) {
        $null = New-Item -Path $OpenSSHDir -ItemType Directory -Force
    }

    Copy-Item -Path "$SourceDir/*" -Destination $OpenSSHDir -Recurse -Force -Verbose

    Push-Location $OpenSSHDir 

    try
    {
        & "$OpenSSHDir\install-sshd.ps1"

        $machinePath = [Environment]::GetEnvironmentVariable('Path', 'MACHINE')
        $newMachineEnvironmentPath = $machinePath
        if (-not ($machinePath.ToLower().Contains($OpenSSHDir.ToLower())))
        {
            $newMachineEnvironmentPath = "$OpenSSHDir;$newMachineEnvironmentPath"
            $env:Path = "$OpenSSHDir;$env:Path"
        }

        # Update machine environment path
        if ($newMachineEnvironmentPath -ne $machinePath)
        {
            [Environment]::SetEnvironmentVariable('Path', $newMachineEnvironmentPath, 'MACHINE')
        }
        
        Start-Service -Name sshd 
        Start-Service -Name ssh-agent
    }
    finally
    {
        Pop-Location
    }

    Write-BuildMessage -Message "OpenSSH installed!" -Category Information
}

<#
    .Synopsis
    Uninstalled sshd
#>
function UnInstall-OpenSSH
{
    [CmdletBinding()]
    param ( 
        [string]$OpenSSHDir = "$env:SystemDrive\OpenSSH"
    )

    if (-not (Test-Path $OpenSSHDir -PathType Container))
    {
        return
    }

    Push-Location $OpenSSHDir

    try
    {
        if ((Get-Service ssh-agent -ErrorAction SilentlyContinue) -ne $null) {
            Stop-Service ssh-agent -Force
        }
        & "$OpenSSHDir\uninstall-sshd.ps1"
            
        $machinePath = [Environment]::GetEnvironmentVariable('Path', 'MACHINE')
        $newMachineEnvironmentPath = $machinePath
        if ($machinePath.ToLower().Contains($OpenSSHDir.ToLower()))
        {        
            $newMachineEnvironmentPath = $newMachineEnvironmentPath.Replace("$OpenSSHDir;", '')
            $env:Path = $env:Path.Replace("$OpenSSHDir;", '')
        }
        
        if ($newMachineEnvironmentPath -ne $machinePath)
        {
            [Environment]::SetEnvironmentVariable('Path', $newMachineEnvironmentPath, 'MACHINE')
        }
    }
    finally
    {
        Pop-Location
    }

    Remove-Item -Path $OpenSSHDir -Recurse -Force -ErrorAction SilentlyContinue    
}

#
# Install CygWin from Chocolatey and fix up install directory if needed.
#
function Install-CygWin
{
    param (
        [string] $InstallLocation
    )

    Write-Verbose -Verbose -Message "Installing CygWin from Chocolately to location: ${InstallLocation} ..."
    choco install cygwin -y --force --params "/InstallDir:${InstallLocation} /NoStartMenu"
}

<#
      .Synopsis
      Runs the tests for this repo
#>
function Invoke-OpenSSHTests
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string] $OpenSSHBinPath
    )

    Set-BasicTestInfo -OpenSSHBinPath $OpenSSHBinPath -Confirm:$false

    Write-Verbose -Verbose -Message "Running OpenSSH Set up Tests..."

    $AllTestsPassed = $true

    Invoke-OpenSSHSetupTest

    if (($OpenSSHTestInfo -eq $null) -or (-not (Test-Path $OpenSSHTestInfo["SetupTestResultsFile"])))
    {
        Write-BuildMessage -Message "Test result file $OpenSSHTestInfo["SetupTestResultsFile"] not found after tests." -Category Error
        $AllTestsPassed = $false
        Write-Warning "Stop running further tests!"
        return
    }

    $xml = [xml](Get-Content $OpenSSHTestInfo["SetupTestResultsFile"] | out-string)
    if ([int]$xml.'test-results'.failures -gt 0) 
    {
        $errorMessage = "$($xml.'test-results'.failures) Setup Tests in regress\pesterTests failed. Detail test log is at $($OpenSSHTestInfo["SetupTestResultsFile"])."
        Write-BuildMessage -Message $errorMessage -Category Error
        $AllTestsPassed = $False
        Write-Warning "Stop running further tests!"
        return
    }

    Write-BuildMessage -Message "All Setup tests passed!" -Category Information
    $AllTestsPassed = $true

    # Unit test directories are installed in the same directory as Open SSH binaries.
    #  OpenSSH Directory
    #    unittest-bitmap
    #    unittest-hostkeys
    #    ...
    #    FixHostFilePermissions.ps1
    #    ...
    Write-Verbose -Verbose -Message "Running Unit Tests..."
    Write-Verbose -Verbose -Message "Unit test directory is: ${OpenSSHBinPath}"

    $unitTestFailed = Invoke-OpenSSHUnitTest -UnitTestDirectory $OpenSSHBinPath

    if($unitTestFailed)
    {
        Write-BuildMessage "At least one of the unit tests failed!" -Category Error
        $AllTestsPassed = $false
    }
    else
    {
        Write-BuildMessage -Message "All Unit tests passed!" -Category Information
    }

    # Run all E2E tests.
    Write-Verbose -Verbose -Message "Running E2E Tests..."
    Set-OpenSSHTestEnvironment -Confirm:$false
    Invoke-OpenSSHE2ETest
    if (($OpenSSHTestInfo -eq $null) -or (-not (Test-Path $OpenSSHTestInfo["E2ETestResultsFile"])))
    {
        Write-BuildMessage -Message "Test result file $OpenSSHTestInfo["E2ETestResultsFile"] not found after tests." -Category Error
        $AllTestsPassed =  $false
    }
    else
    {
        $xml = [xml](Get-Content $OpenSSHTestInfo["E2ETestResultsFile"] | out-string)
        if ([int]$xml.'test-results'.failures -gt 0)
        {
            $errorMessage = "$($xml.'test-results'.failures) E2E tests in regress\pesterTests failed. Detail test log is at $($OpenSSHTestInfo["E2ETestResultsFile"])."
            Write-BuildMessage -Message $errorMessage -Category Error
            $AllTestsPassed = $false
        }
        else
        {
            Write-BuildMessage -Message "All E2E tests passed!" -Category Information
        }
    }

    # Bash tests.
    Write-Verbose -Verbose -Message "Running Bash Tests..."

    # Ensure CygWin is installed, and install from Chocolatey if needed.
    $cygwinInstalled = $true
    $cygwinInstallLocation = "$env:SystemDrive/cygwin"
    if (! (Test-Path -Path "$cygwinInstallLocation/bin/sh.exe"))
    {
        Write-Verbose -Verbose -Message "CygWin not found"
        Install-CygWin -InstallLocation $cygwinInstallLocation

        # Hack to fix up mangled CygWin directory, if needed.
        $expectedCygWinPath = "$env:SystemDrive/cygwin/bin/sh.exe"
        if (! (Test-Path -Path $expectedCygWinPath))
        {
            Write-Verbose -Verbose -Message "CygWin did not install correctly, missing expected path: ${expectedCygWinPath}"

            $cygWinDirs = Get-Item -Path "$env:SystemDrive/cygwin*"
            if ($cygWinDirs.Count -gt 1)
            {
                Write-Verbose -Verbose -Message "CygWin install failed with mangled folder locations: ${cygWinDirs}"
                Write-Verbose -Verbose -Message 'TODO: Add hack to fix up CygWin folder.'
            }

            Write-BuildMessage -Message "All bash tests failed because CygWin install failed" -Category Error
            $AllTestsPassed = $false
            $cygwinInstalled = $false
        }
    }

    # Run UNIX bash tests.
    if ($cygwinInstalled)
    {
        Write-Verbose -Verbose -Message "Starting Bash Tests..."
        Invoke-OpenSSHBashTests
        if (-not $Global:bash_tests_summary)
        {
            $errorMessage = "Failed to start OpenSSH bash tests"
            Write-BuildMessage -Message $errorMessage -Category Error
            $AllTestsPassed = $false
        }
        else
        {
            if ($Global:bash_tests_summary["TotalBashTestsFailed"] -ne 0)
            {
                $total_bash_failed_tests = $Global:bash_tests_summary["TotalBashTestsFailed"]
                $total_bash_tests = $Global:bash_tests_summary["TotalBashTests"]
                $errorMessage = "At least one of the bash tests failed. [$total_bash_failed_tests of $total_bash_tests]"
                Write-BuildMessage -Message $errorMessage -Category Error
                $AllTestsPassed = $false
            }

            $OpenSSHTestInfo["BashTestSummaryFile"] = $Global:bash_tests_summary["BashTestSummaryFile"]
            $OpenSSHTestInfo["BashTestLogFile"] = $Global:bash_tests_summary["BashTestLogFile"]
        }
    }

    # OpenSSH Uninstall Tests
    Invoke-OpenSSHUninstallTest
    if (($OpenSSHTestInfo -eq $null) -or (-not (Test-Path $OpenSSHTestInfo["UninstallTestResultsFile"])))
    {
        Write-BuildMessage -Message "Test result file $OpenSSHTestInfo["UninstallTestResultsFile"] not found after tests." -Category Error
        $AllTestsPassed = $false
    }
    else
    {
        $xml = [xml](Get-Content $OpenSSHTestInfo["UninstallTestResultsFile"] | out-string)
        if ([int]$xml.'test-results'.failures -gt 0) 
        {
            $errorMessage = "$($xml.'test-results'.failures) uninstall tests in regress\pesterTests failed. Detail test log is at $($OpenSSHTestInfo["UninstallTestResultsFile"])."
            Write-BuildMessage -Message $errorMessage -Category Error
            $AllTestsPassed = $false
        }
    }

    # Save OpenSSHTestInfo for later test results uploading.
    $OpenSSHTestInfo | Export-Clixml -Path "$repoRoot/OpenSSHTestInfo.xml" -Depth 10

    # Writing out warning when the $Error.Count is non-zero. Tests Should clean $Error after success.
    if ($Error.Count -gt 0) 
    {
        Write-BuildMessage -Message "Tests Should always clean $Error variable after success." -Category Warning
    }

    if ($AllTestsPassed)
    {
        Write-BuildMessage -Message "All OpenSSH validation tests have passed!" -Category Information
    }
    else
    {
        Write-BuildMessage -Message "Some OpenSSH validation tests have failed." -Category Error
        throw "OpenSSH validation tests failed!"
    }
}

<#
      .Synopsis
      Collect OpenSSH pester test results into one directory
#>
function Copy-OpenSSHTestResults
{ 
    param (
        [Parameter(Mandatory=$true)]
        [string] $ResultsPath
    )

    if (Test-Path -Path $ResultsPath)
    {
        Remove-Item -Path $ResultsPath -Force -Recurse -ErrorAction Ignore
    }

    Write-Verbose -Verbose "Creating test results directory for artifacts upload: $ResultsPath"
    $null = New-Item -Path $ResultsPath -ItemType Directory -Force
    
    if (! (Test-Path -Path $ResultsPath))
    {
        Write-BuildMessage -Message "Unable to write to test results path for test artifacts upload: $ResultsPath" -Category Error
        return
    }

    $OpenSSHTestInfo = $null
    $openSSHTestInfoFilePath = "$repoRoot/OpenSSHTestInfo.xml"
    if (Test-Path -Path $openSSHTestInfoFilePath)
    {
        $OpenSSHTestInfo = Import-Clixml -Path $openSSHTestInfoFilePath
    }

    if (! $OpenSSHTestInfo)
    {
        Write-BuildMessage -Message "Unable to get OpenSSHTestInfo object from: ${openSSHTestInfoFilePath}"
        return
    }

    try { $setupresultFile = Resolve-Path -Path $OpenSSHTestInfo["SetupTestResultsFile"] -ErrorAction Ignore } catch { }
    if ($setupresultFile)
    {
        Write-Verbose -Verbose -Message "Copying set-up test results file, $setupresultFile, to results directory"
        Copy-Item -Path $setupresultFile -Destination $ResultsPath
    }

    try { $E2EresultFile = Resolve-Path -Path $OpenSSHTestInfo["E2ETestResultsFile"] -ErrorAction Ignore } catch { }
    if ($E2EresultFile)
    {
        Write-Verbose -Verbose -Message "Copying end-to-end test results file, $E2EresultFile, to results directory"
        Copy-Item -Path $E2EresultFile -Destination $ResultsPath
    }

    try { $uninstallResultFile = Resolve-Path $OpenSSHTestInfo["UninstallTestResultsFile"] -ErrorAction Ignore } catch { }
    if ($uninstallResultFile)
    {
        Write-Verbose -Verbose -Message "Copying uninstall test results file, $uninstallResultFile, to results directory"
        Copy-Item -Path $uninstallResultFile -Destination $ResultsPath
    }

    try { $bashTestsSummaryFile = Resolve-Path -Path $OpenSSHTestInfo["BashTestSummaryFile"] -ErrorAction Ignore } catch { }
    if ($bashTestsSummaryFile)
    {
        Write-Verbose -Verbose -Message "Copying bash tests summary file, $bashTestsSummaryFile, to results directory"
        Copy-Item -Path $bashTestsSummaryFile -Destination $ResultsPath
    }

    try { $bashTestsLogFile = Resolve-Path -Path $OpenSSHTestInfo["BashTestLogFile"] -ErrorAction Ignore } catch { }
    if ($bashTestsLogFile)
    {
        Write-Verbose -Verbose -Message "Copying bash tests log file, $bashTestsLogFile, to results directory"
        Copy-Item -Path $bashTestsLogFile -Destination $ResultsPath
    }
}

function Clear-TestEnvironmentSetup
{
    Write-Verbose -Verbose -Message "Running OpenSSH test environment cleanup..."

    try
    {
        $null = Clear-OpenSSHTestEnvironment -ErrorAction Ignore
        $null = UnInstall-OpenSSH -ErrorAction Ignore
    }
    catch
    { }

    Write-Verbose -Verbose -Message "OpenSSH test environment cleanup complete."
}

<#
    .SYNOPSIS
    Copy build results package to provided destination path.
#>
function Copy-BuildResults
{
    param (
        [Parameter(Mandatory=$true)]
        [string] $BuildResultsPath,

        [ValidateSet('x86', 'x64', 'arm64', 'arm')]
        [string]$NativeHostArch = "x64",

        [ValidateSet('Debug', 'Release')]
        [string]$Configuration = "Release"
    )

    # Copy OpenSSH package to results directory
    Start-OpenSSHPackage -DestinationPath $BuildResultsPath -NativeHostArch $NativeHostArch -Configuration $Configuration
}

<#
    .SYNOPSIS
    Copy build unit tests to provided destination path.
#>
function Copy-UnitTests
{
    param (
        [Parameter(Mandatory=$true)]
        [string] $UnitTestsSrcDir,

        [Parameter(Mandatory=$true)]
        [string] $UnitTestsDestDir,

        [ValidateSet('x86', 'x64', 'arm64', 'arm')]
        [string]$NativeHostArch = "x64",

        [ValidateSet('Debug', 'Release')]
        [string]$Configuration = "Release"
    )

    if (! (Test-Path -Path $UnitTestsDestDir))
    {
      Write-Verbose -Verbose -Message "Creating Unit Test directory: $UnitTestsDestDir"
      $null = New-Item -Path $UnitTestsDestDir -ItemType Directory -Force
    }

    if ($NativeHostArch -eq 'x86')
    {
        $unitTestsSrcPath = Join-Path -Path $UnitTestsSrcDir -ChildPath "Win32/${Configuration}"
    }
    else
    {
        $unitTestsSrcPath = Join-Path -Path $UnitTestsSrcDir -ChildPath "${NativeHostArch}/${Configuration}"
    }

    $unitTestsDestPath = Join-Path -Path $UnitTestsDestDir -ChildPath "${NativeHostArch}/${Configuration}"

    if (! (Test-Path -Path $unitTestsDestPath))
    {
      Write-Verbose -Verbose -Message "Creating Unit Test directory: $unitTestsDestPath"
      $null = New-Item -Path $unitTestsDestPath -ItemType Directory -Force
    }

    Write-Verbose -Verbose -Message "Copying unit tests from: ${unitTestsSrcPath} to: ${unitTestsDestPath}"
    Copy-Item -Path "$unitTestsSrcPath/unittest-*" -Destination $unitTestsDestPath -Recurse -Force
}

<#
    .SYNOPSIS
    Install unit tests to provided destination.
#>
function Install-UnitTests
{
    [CmdletBinding()]
    param ( 
        [Parameter(Mandatory=$true)]
        [string]$SourceDir,

        [string]$OpenSSHDir = "$env:SystemDrive\OpenSSH"
    )

    if (! (Test-Path -Path $OpenSSHDir)) {
        $null = New-Item -Path $OpenSSHDir -ItemType Directory -Force
    }

    Copy-Item -Path "$SourceDir/*" -Destination $OpenSSHDir -Recurse -Force
}

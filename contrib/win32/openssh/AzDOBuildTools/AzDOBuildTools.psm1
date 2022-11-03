##
## Azure DevOps CI build tools
## [Add appropriate copyright]
##

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = Get-RepositoryRoot
$script:messageFile = join-path $repoRoot.FullName "BuildMessage.log"

function Write-BuildMessage
{
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string] $Message,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string] $Category
    )

    # Write message to verbos stream.
    Write-Verbose -Verbose -Message "$Category--$Message"

    # Write it to the log file, if present.
    if (-not ([string]::IsNullOrEmpty($script:messageFile)))
    {
        Add-Content -Path $script:messageFile -Value "$Category--$Message"
    }
}

<#
    .Synopsis
    Adds a build log to the list of published artifacts.
    .Description
    If a build log exists, it is renamed to reflect the associated CLR runtime then added to the list of
    artifacts to publish.  If it doesn't exist, a warning is written and the file is skipped.
    The rename is needed since publishing overwrites the artifact if it already exists.
    .Parameter artifacts
    An array list to add the fully qualified build log path
    .Parameter buildLog
    The build log file produced by the build.    
#>
function Add-BuildLog
{
    param (
        [ValidateNotNull()]
        [System.Collections.ArrayList] $artifacts,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string] $buildLog
    )

    if (Test-Path -Path $buildLog)
    {   
        $null = $artifacts.Add($buildLog)
    }
    else
    {
        Write-Warning "Skip publishing build log. $buildLog does not exist"
    }
}

function Set-BuildVariable
{
    param(
        [Parameter(Mandatory=$true)]
        [string]
        $Name,

        [Parameter(Mandatory=$true)]
        [string]
        $Value
    )

    Set-Item -Path env:$Name -Value $Value
}

# Emulates running all of AzDO functions locally.
# This should not be used within an actual AzDO build.
function Invoke-AllLocally
{
    param (
        [switch] $CleanRepo
    )

    if ($CleanRepo)
    {
        Clear-PSRepo
    }

    # TODO: Set up any build environment state here.

    try
    {        
        Invoke-AzDOBuild
        Install-OpenSSH
        Set-OpenSSHTestEnvironment -confirm:$false
        Invoke-OpenSSHTests
        Publish-Artifact
    }
    finally
    {
        # TODO: Clean up any build environment state here.
    }
}

# Implements the AzDO build package step
function Invoke-AzDOBuild
{
      Set-BuildVariable TestPassed True
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
    param
    ( 
        [Parameter(Mandatory=$true)]
        [string]$SourceDir,

        [string]$OpenSSHDir = "$env:SystemDrive\OpenSSH"
    )

    UnInstall-OpenSSH -OpenSSHDir $OpenSSHDir

    if (! (Test-Path -Path $OpenSSHDir)) {
        $null = New-Item -Path $OpenSSHDir -ItemType Directory -Force
    }
    Copy-Item -Path $SourceDir -Destination $OpenSSHDir -Recurse -Force -Verbose

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
    uninstalled sshd
#>
function UnInstall-OpenSSH
{
    [CmdletBinding()]
    param
    ( 
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

<#
    .Synopsis
    Publishes package build artifacts.    
    .Parameter artifacts
    An array list to add the fully qualified build log path
    .Parameter FileToAdd
    Path to the file
#>
function Add-Artifact
{
    param
    (
        [ValidateNotNull()]
        [System.Collections.ArrayList] $artifacts,
        [string] $FileToAdd
    )        
    
    if ([string]::IsNullOrEmpty($FileToAdd) -or (-not (Test-Path $FileToAdd -PathType Leaf)) )
    {            
        Write-Host "Skip publishing package artifacts. $FileToAdd does not exist"
    }    
    else
    {
        $null = $artifacts.Add($FileToAdd)
        Write-Host "Added $FileToAdd to publishing package artifacts"
    }
}

<#
    .Synopsis
    After build and test run completes, upload all artifacts from the build machine.
#>
function Publish-Artifact
{
    Write-Host -ForegroundColor Yellow "Publishing project artifacts"
    [System.Collections.ArrayList] $artifacts = new-object System.Collections.ArrayList
    
    # Get the build.log file for each build configuration        
    Add-BuildLog -artifacts $artifacts -buildLog (Get-BuildLogFile -root $repoRoot.FullName -Configuration Release -NativeHostArch x64)
    Add-BuildLog -artifacts $artifacts -buildLog (Get-BuildLogFile -root $repoRoot.FullName -Configuration Release -NativeHostArch x86)

    if($Global:OpenSSHTestInfo)
    {
        Add-Artifact -artifacts $artifacts -FileToAdd $Global:OpenSSHTestInfo["SetupTestResultsFile"]
        Add-Artifact -artifacts $artifacts -FileToAdd $Global:OpenSSHTestInfo["UnitTestResultsFile"]
        Add-Artifact -artifacts $artifacts -FileToAdd $Global:OpenSSHTestInfo["E2ETestResultsFile"]
        Add-Artifact -artifacts $artifacts -FileToAdd $Global:OpenSSHTestInfo["UninstallTestResultsFile"]
        Add-Artifact -artifacts $artifacts -FileToAdd $Global:OpenSSHTestInfo["TestSetupLogFile"]
    }

    if ($Global:bash_tests_summary)
    {
        Add-Artifact -artifacts $artifacts -FileToAdd $Global:bash_tests_summary["BashTestSummaryFile"]
        Add-Artifact -artifacts $artifacts -FileToAdd $Global:bash_tests_summary["BashTestLogFile"]
    }
    
    foreach ($artifact in $artifacts)
    {
        Write-Host "Publishing $artifact as AzDO artifact"

        # TODO: Create an AzDO artificate upload function.
        # Push-AppveyorArtifact $artifact -ErrorAction Continue
    }

    Write-Host -ForegroundColor Yellow "End of publishing project artifacts"
}

<#
      .Synopsis
      Runs the tests for this repo
#>
function Invoke-OpenSSHTests
{
    [CmdletBinding()]
    param (
        [string] $OpenSSHBinPath
    )

    Set-BasicTestInfo -OpenSSHBinPath $OpenSSHBinPath -Confirm:$false
    Invoke-OpenSSHSetupTest
    if (($OpenSSHTestInfo -eq $null) -or (-not (Test-Path $OpenSSHTestInfo["SetupTestResultsFile"])))
    {
        Write-Warning "Test result file $OpenSSHTestInfo["SetupTestResultsFile"] not found after tests."
        Write-BuildMessage -Message "Test result file $OpenSSHTestInfo["SetupTestResultsFile"] not found after tests." -Category Error
        Set-BuildVariable TestPassed False
        Write-Warning "Stop running further tests!"
        return
    }
    $xml = [xml](Get-Content $OpenSSHTestInfo["SetupTestResultsFile"] | out-string)
    if ([int]$xml.'test-results'.failures -gt 0) 
    {
        $errorMessage = "$($xml.'test-results'.failures) setup tests in regress\pesterTests failed. Detail test log is at $($OpenSSHTestInfo["SetupTestResultsFile"])."
        Write-Warning $errorMessage
        Write-BuildMessage -Message $errorMessage -Category Error
        Set-BuildVariable TestPassed False
        Write-Warning "Stop running further tests!"
        return
    }

    Write-Host "Start running unit tests"
    $unitTestFailed = Invoke-OpenSSHUnitTest

    if($unitTestFailed)
    {
        Write-Host "At least one of the unit tests failed!" -ForegroundColor Yellow
        Write-BuildMessage "At least one of the unit tests failed!" -Category Error
        Set-BuildVariable TestPassed False
    }
    else
    {
        Write-Host "All Unit tests passed!"
        Write-BuildMessage -Message "All Unit tests passed!" -Category Information
    }

    # Run all E2E tests.
    Set-OpenSSHTestEnvironment -Confirm:$false
    Invoke-OpenSSHE2ETest
    if (($OpenSSHTestInfo -eq $null) -or (-not (Test-Path $OpenSSHTestInfo["E2ETestResultsFile"])))
    {
        Write-Warning "Test result file $OpenSSHTestInfo["E2ETestResultsFile"] not found after tests."
        Write-BuildMessage -Message "Test result file $OpenSSHTestInfo["E2ETestResultsFile"] not found after tests." -Category Error
        Set-BuildVariable TestPassed False
        Write-Warning "Stop running further tests!"
        return
    }
    $xml = [xml](Get-Content $OpenSSHTestInfo["E2ETestResultsFile"] | out-string)
    if ([int]$xml.'test-results'.failures -gt 0)
    {
        $errorMessage = "$($xml.'test-results'.failures) tests in regress\pesterTests failed. Detail test log is at $($OpenSSHTestInfo["E2ETestResultsFile"])."
        Write-Warning $errorMessage
        Write-BuildMessage -Message $errorMessage -Category Error
        Set-BuildVariable TestPassed False
        Write-Warning "Stop running further tests!"
        return
    }

    # Run UNIX bash tests.
    Invoke-OpenSSHBashTests
    if (-not $Global:bash_tests_summary)
    {
        $errorMessage = "Failed to start OpenSSH bash tests"
        Write-Warning $errorMessage
        Write-BuildMessage -Message $errorMessage -Category Error
        Set-BuildVariable TestPassed False
        Write-Warning "Stop running further tests!"
        return
    }

    if ($Global:bash_tests_summary["TotalBashTestsFailed"] -ne 0)
    {
        $total_bash_failed_tests = $Global:bash_tests_summary["TotalBashTestsFailed"]
        $total_bash_tests = $Global:bash_tests_summary["TotalBashTests"]
        $errorMessage = "At least one of the bash tests failed. [$total_bash_failed_tests of $total_bash_tests]"
        Write-Warning $errorMessage
        Write-BuildMessage -Message $errorMessage -Category Error
        Set-BuildVariable TestPassed False
        Write-Warning "Stop running further tests!"
        return
    }

    Invoke-OpenSSHUninstallTest
    if (($OpenSSHTestInfo -eq $null) -or (-not (Test-Path $OpenSSHTestInfo["UninstallTestResultsFile"])))
    {
        Write-Warning "Test result file $OpenSSHTestInfo["UninstallTestResultsFile"] not found after tests."
        Write-BuildMessage -Message "Test result file $OpenSSHTestInfo["UninstallTestResultsFile"] not found after tests." -Category Error
        Set-BuildVariable TestPassed False
    }
    else {
        $xml = [xml](Get-Content $OpenSSHTestInfo["UninstallTestResultsFile"] | out-string)
        if ([int]$xml.'test-results'.failures -gt 0) 
        {
            $errorMessage = "$($xml.'test-results'.failures) uninstall tests in regress\pesterTests failed. Detail test log is at $($OpenSSHTestInfo["UninstallTestResultsFile"])."
            Write-Warning $errorMessage
            Write-BuildMessage -Message $errorMessage -Category Error
            Set-BuildVariable TestPassed False
        }
    }

    # Writing out warning when the $Error.Count is non-zero. Tests Should clean $Error after success.
    if ($Error.Count -gt 0) 
    {
        Write-BuildMessage -Message "Tests Should clean $Error after success." -Category Warning
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
    
    if (Test-Path -Path $ResultsPath)
    {
        $setupresultFile = Resolve-Path $Global:OpenSSHTestInfo["SetupTestResultsFile"] -ErrorAction Ignore
        if ($setupresultFile)
        {
            Write-Verbose -Verbose "Copying set-up test results file, $setupresultFile, to results directory"
            Copy-Item -Path $setupresultFile -Destination $ResultsPath
        }

        $E2EresultFile = Resolve-Path $Global:OpenSSHTestInfo["E2ETestResultsFile"] -ErrorAction Ignore
        if ($E2EresultFile)
        {
            Write-Verbose -Verbose "Copying end-to-end test results file, $E2EresultFile, to results directory"
            Copy-Item -Path $E2EresultFile -Destination $ResultsPath
        }

        $uninstallResultFile = Resolve-Path $Global:OpenSSHTestInfo["UninstallTestResultsFile"] -ErrorAction Ignore
        if ($uninstallResultFile)
        {
            Write-Verbose -Verbose "Copying uninstall test results file, $uninstallResultFile, to results directory"
            Copy-Item -Path $uninstallResultFile -Destination $ResultsPath
        }
    }
    else
    {
        Write-Verbose -Verbose "Unable to write test results path for test artifacts upload: $ResultsPath"
    }

    if ($env:DebugMode)
    {
        Remove-Item $env:DebugMode
    }
    
    if($env:TestPassed -ieq 'True')
    {
        Write-BuildMessage -Message "The checkin validation tests succeeded!" -Category Information
    }
    else
    {
        Write-BuildMessage -Message "The checkin validation tests failed!" -Category Error
        throw "The checkin validation tests failed!"
    }
}

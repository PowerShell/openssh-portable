﻿$ErrorActionPreference = 'Stop'
Import-Module $PSScriptRoot\OpenSSHBuildHelper.psm1 -Force -DisableNameChecking
Import-Module $PSScriptRoot\OpenSSHTestHelper.psm1 -Force -DisableNameChecking

$repoRoot = Get-RepositoryRoot
$script:logFile = join-path $repoRoot.FullName "appveyor.log"
$script:messageFile = join-path $repoRoot.FullName "BuildMessage.log"

# Sets a build variable
Function Write-BuildMessage
{
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string] $Message,
        $Category,
        [string]  $Details)

    if($env:AppVeyor)
    {
        Add-AppveyorMessage @PSBoundParameters
    }

    # write it to the log file, if present.
    if (-not ([string]::IsNullOrEmpty($script:messageFile)))
    {
        Add-Content -Path $script:messageFile -Value "$Category--$Message"
    }
}

# Sets a build variable
Function Set-BuildVariable
{
    param(
        [Parameter(Mandatory=$true)]
        [string]
        $Name,

        [Parameter(Mandatory=$true)]
        [string]
        $Value
    )

    if($env:AppVeyor -and (Get-Command Set-AppveyorBuildVariable -ErrorAction Ignore) -ne $null)
    {
        Set-AppveyorBuildVariable @PSBoundParameters
    }
    elseif($env:AppVeyor)
    {
        appveyor SetVariable -Name $Name -Value $Value
    } 
    else
    {
        Set-Item env:$Name -Value $Value
    }
}

# Emulates running all of AppVeyor but locally
# should not be used on AppVeyor
function Invoke-AppVeyorFull
{
    param(
        [switch] $APPVEYOR_SCHEDULED_BUILD,
        [switch] $CleanRepo
    )
    if($CleanRepo)
    {
        Clear-PSRepo
    }

    if($env:APPVEYOR)
    {
        throw "This function is to simulate appveyor, but not to be run from appveyor!"
    }

    if($APPVEYOR_SCHEDULED_BUILD)
    {
        $env:APPVEYOR_SCHEDULED_BUILD = 'True'
    }
    try {
        Set-OpenSSHTestParams
        Invoke-AppVeyorBuild
        Install-OpenSSH
        Install-OpenSSHTestDependencies
        Deploy-OpenSSHTests
        Setup-OpenSSHTestEnvironment
        Run-OpenSSHTests
        Publish-Artifact
    }
    finally {
        if($APPVEYOR_SCHEDULED_BUILD -and $env:APPVEYOR_SCHEDULED_BUILD)
        {
            Remove-Item env:APPVEYOR_SCHEDULED_BUILD
        }
    }
}

# Implements the AppVeyor 'build_script' step
function Invoke-AppVeyorBuild
{
      Set-BuildVariable TestPassed True
      Start-OpenSSHBuild -Configuration Release -NativeHostArch x64
      Start-OpenSSHBuild -Configuration Debug -NativeHostArch x86
      Write-BuildMessage -Message "OpenSSH binaries build success!" -Category Information
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
    param
    (
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

<#
    .Synopsis
    Publishes package build artifacts.    
    .Parameter artifacts
    An array list to add the fully qualified build log path
    .Parameter packageFile
    Path to the package
#>
function Add-Artifact
{
    param
    (
        [ValidateNotNull()]
        [System.Collections.ArrayList] $artifacts,
        [string] $FileToAdd
    )    
    
    $files = Get-ChildItem -Path $FileToAdd -ErrorAction Ignore
    if ($files -ne $null)
    {        
        $files | % {
            $null = $artifacts.Add($_.FullName)             
         }
    }
    else
    {
        Write-Host -Message "Skip publishing package artifacts. $FileToAdd does not exist"
    }
}

<#
    .Synopsis
    After build and test run completes, upload all artifacts from the build machine.
#>
function Publish-Artifact
{
    Write-Host -ForegroundColor Yellow "Publishing project artifacts"
    [System.Collections.ArrayList] $artifacts = [System.Collections.ArrayList]::new()   
    
    # Get the build.log file for each build configuration        
    #Add-BuildLog -artifacts $artifacts -buildLog (Get-BuildLogFile -root $repoRoot.FullName)
        
    Add-Artifact  -artifacts $artifacts -FileToAdd $global:UnitTestResultsFile
    Add-Artifact  -artifacts $artifacts -FileToAdd $global:PesterTestResultsFile
    Add-Artifact  -artifacts $artifacts -FileToAdd $script:TestSetupLogFile   

    Add-Artifact  -artifacts $artifacts -FileToAdd $script:logFile
    Add-Artifact  -artifacts $artifacts -FileToAdd $script:messageFile   

    foreach ($artifact in $artifacts)
    {
        Write-log -Message "Publishing $artifact as Appveyor artifact"
        # NOTE: attempt to publish subsequent artifacts even if the current one fails
        Push-AppveyorArtifact $artifact -ErrorAction Continue
    }
}

<#
      .Synopsis
      Runs the tests for this repo
#>
function Run-OpenSSHTests
{
    Write-Host "Start running unit tests"
    $unitTestFailed = Run-OpenSSHUnitTest

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
  # Run all pester tests.
  <#Run-OpenSSHPesterTest
  if (-not (Test-Path $global:PesterTestResultsFile))
    {
        Write-Warning "Test result file $global:PesterTestResultsFile not found after tests."
        Write-BuildMessage -Message "Test result file $global:PesterTestResultsFile not found after tests." -Category Error
        Set-BuildVariable TestPassed False
    }
    $xml = [xml](Get-Content -raw $global:PesterTestResultsFile)
    if ([int]$xml.'test-results'.failures -gt 0) 
    {
        $errorMessage = "$($xml.'test-results'.failures) tests in regress\pesterTests failed. Detail test log is at $($global:PesterTestResultsFile)."
        Write-Warning $errorMessage
        Write-BuildMessage -Message $errorMessage -Category Error
        Set-BuildVariable TestPassed False
    }

    # Writing out warning when the $Error.Count is non-zero. Tests Should clean $Error after success.
    if ($Error.Count -gt 0) 
    {
        Write-BuildMessage -Message "Tests Should clean $Error after success." -Category Warning
    }#>
}

<#
      .Synopsis
      upload OpenSSH pester test results.
#>
function Upload-OpenSSHTestResults
{ 
    if ($env:APPVEYOR_JOB_ID)
    {
        $resultFile = Resolve-Path $global:PesterTestResultsFile -ErrorAction Ignore
        if( (Test-Path $global:PesterTestResultsFile) -and $resultFile)
        {
            (New-Object 'System.Net.WebClient').UploadFile("https://ci.appveyor.com/api/testresults/nunit/$($env:APPVEYOR_JOB_ID)", $resultFile)
             Write-BuildMessage -Message "Test results uploaded!" -Category Information
        }
    }

    if ($env:DebugMode)
    {
        Remove-Item $env:DebugMode
    }
    
    if($env:TestPassed -ieq 'True')
    {
        Write-BuildMessage -Message "The checkin validation success!" -Category Information
    }
    else
    {
        Write-BuildMessage -Message "The checkin validation failed!" -Category Error
        throw "The checkin validation failed!"
    }
}

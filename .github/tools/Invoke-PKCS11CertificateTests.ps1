#Requires -Version 7.2
[CmdletBinding(DefaultParameterSetName = 'Run')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Run')][string]$OpenSSHBinPath,
    [Parameter(ParameterSetName = 'Run')][ValidateSet('x64', 'x86')][string]$Architecture = 'x64',
    [Parameter(ParameterSetName = 'Run')][string]$ResultsDirectory = "$env:TEMP/OpenSSH-PKCS11-Results",
    [Parameter(ParameterSetName = 'Run')][ValidateSet('SoftHSM', 'Hardware')][string]$Mode = 'SoftHSM',
    [Parameter(ParameterSetName = 'Run')][ValidateSet('Local', 'None')][string]$CleanupMode = 'Local',
    [Parameter(ParameterSetName = 'Run')][string]$CacheDirectory = "$env:LOCALAPPDATA/OpenSSH-TestCache",
    [Parameter(ParameterSetName = 'Run')][switch]$Child,
    [Parameter(ParameterSetName = 'Run')][string]$TestDirectory,
    [Parameter(Mandatory, ParameterSetName = 'Cleanup')][switch]$CleanupOnly,
    [Parameter(ParameterSetName = 'Cleanup')][string]$StatePath
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'PKCS11TestHelpers.psm1') -Force
$repoRoot = Split-Path (Split-Path $PSScriptRoot)
$stateDirectory = Join-Path $env:ProgramData 'OpenSSH-PKCS11-Tests'
$fixtureDirectory = Get-Pkcs11FixtureDirectory $Architecture
$serviceRegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\ssh-agent'
$serviceRunMarkerName = 'OpenSSHPkcs11TestRunId'
$environmentNames = @('SOFTHSM2_CONF', 'OPENSSH_TEST_PKCS11_PROVIDER',
    'OPENSSH_TEST_PKCS11_PIN', 'OPENSSH_TEST_PKCS11_PUBLIC_KEYS',
    'OPENSSH_TEST_PKCS11_LABELS', 'OPENSSH_TEST_PKCS11_SOFTWARE_KEY',
    'SSH_ASKPASS', 'SSH_ASKPASS_REQUIRE', 'ASKPASS_PASSWORD', 'DISPLAY')

function Save-Pkcs11State($State, $Path) {
    $temporary = "$Path.tmp"
    [IO.File]::WriteAllText($temporary, ($State | ConvertTo-Json -Depth 5))
    Move-Item -LiteralPath $temporary -Destination $Path -Force
}

function Remove-Pkcs11Run($JournalPath) {
    $state = Get-Content -LiteralPath $JournalPath -Raw | ConvertFrom-Json
    if ($state.Version -ne 3 -or $state.Architecture -notin @('x64', 'x86')) {
        throw 'Unsupported PKCS11 cleanup journal; version 3 is required and older journals need manual recovery'
    }
    if ($state.UserSid -ne [Security.Principal.WindowsIdentity]::GetCurrent().User.Value) {
        throw 'PKCS11 cleanup journal belongs to another user; run recovery as the original user'
    }
    if ($state.CleanupPhase -notin @('Active', 'Restored')) {
        throw 'Invalid PKCS11 cleanup phase'
    }
    $runId = [guid]::ParseExact($state.RunId, 'N').ToString('N')
    $expectedStatePath = [IO.Path]::GetFullPath((Join-Path $stateDirectory "$runId.json"))
    $root = [IO.Path]::GetFullPath((Join-Path (Get-Pkcs11FixtureDirectory $state.Architecture) $runId))
    if ([IO.Path]::GetFullPath($JournalPath) -ne $expectedStatePath -or
        [IO.Path]::GetFullPath($state.Root) -ne $root -or
        $state.AgentPath -ne [IO.Path]::GetFullPath((Join-Path $state.BinaryDirectory 'ssh-agent.exe'))) {
        throw 'Invalid PKCS11 cleanup journal'
    }
    if ((Test-Path -LiteralPath $root) -and
        ((Get-Item -LiteralPath $root).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'PKCS11 fixture directory must not be a reparse point'
    }
    $service = $null
    $marker = $null
    if ($state.ServiceTouched) {
        $service = Get-Service ssh-agent -ErrorAction SilentlyContinue
        if ($service) {
            $serviceInfo = Get-CimInstance Win32_Service -Filter "Name='ssh-agent'"
            if (-not $serviceInfo -or
                [IO.Path]::GetFullPath($serviceInfo.PathName.Trim('"')) -ne $state.AgentPath) {
                throw 'PKCS11 cleanup refused: ssh-agent no longer uses the recorded build'
            }
            $marker = (Get-ItemProperty -LiteralPath $serviceRegistryPath).$serviceRunMarkerName
            # A missing marker is safe only after the restore was journalled:
            # finalization may have removed it immediately before interruption.
            if (($marker -and $marker -ne $runId) -or
                (-not $marker -and $state.CleanupPhase -ne 'Restored')) {
                throw 'PKCS11 cleanup refused: ssh-agent has no matching test run marker'
            }
        }
        elseif ($state.AgentExisted) {
            throw 'PKCS11 cleanup refused: the original ssh-agent service is missing'
        }
    }
    $machineAgentPath = if ($state.Architecture -eq 'x86') {
        'HKLM:\Software\WOW6432Node\OpenSSH\Agent'
    } else { 'HKLM:\Software\OpenSSH\Agent' }
    try {
        if ($state.CleanupPhase -eq 'Active' -and $state.ServiceTouched) {
            if ($service -and $service.Status -ne 'Stopped') {
                if ($service.Status -eq 'Running') {
                    $clear = Invoke-Pkcs11Command (Join-Path $state.BinaryDirectory 'ssh-add.exe') @('-D') -AllowFailure
                    if ($clear.ExitCode -ne 0) { throw 'Could not remove PKCS11 test identities' }
                }
                $null = Invoke-Pkcs11Command "$env:SystemRoot/System32/sc.exe" @('stop', 'ssh-agent')
                (Get-Service ssh-agent).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(60))
            }
            # Stop any worker left by a timed-out test client before deleting DLLs.
            Get-CimInstance Win32_Process -Filter "Name='ssh-agent.exe'" |
                Where-Object { $_.ExecutablePath -eq $state.AgentPath } |
                ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction Stop }
            if ($service -and $state.AgentExisted) {
                if ($state.EnvironmentPresent) {
                    New-ItemProperty -LiteralPath $serviceRegistryPath -Name Environment -PropertyType MultiString `
                        -Value ([string[]]$state.Environment) -Force | Out-Null
                }
                else {
                    Remove-ItemProperty -LiteralPath $serviceRegistryPath -Name Environment -ErrorAction SilentlyContinue
                }
            }
            [Environment]::SetEnvironmentVariable('SOFTHSM2_CONF', $state.UserSoftHSMConfiguration, 'User')
            foreach ($name in @('Keys', 'PKCS11_Providers')) {
                $path = "HKCU:\Software\OpenSSH\Agent\$name"
                if (Test-Path -LiteralPath $path) {
                    Get-ChildItem -LiteralPath $path | ForEach-Object {
                        Remove-Item -LiteralPath $_.PSPath -Recurse -Force
                    }
                    if ($name -notin @($state.UserRootsPresent)) {
                        Remove-Item -LiteralPath $path -Force
                    }
                }
            }
            if (-not $state.UserAgentRootPresent -and (Test-Path 'HKCU:\Software\OpenSSH\Agent')) {
                Remove-Item -LiteralPath 'HKCU:\Software\OpenSSH\Agent' -Force
            }
            if (-not $state.MachineAgentRootPresent -and (Test-Path $machineAgentPath)) {
                Remove-Item -LiteralPath $machineAgentPath -Recurse -Force
            }
            elseif ($state.Status -ne 'Running' -and $state.MachineProcessIDRecorded) {
                if ($state.MachineProcessIDPresent) {
                    New-ItemProperty -LiteralPath $machineAgentPath -Name ProcessID -PropertyType DWord `
                        -Value $state.MachineProcessID -Force | Out-Null
                }
                else { Remove-ItemProperty -LiteralPath $machineAgentPath -Name ProcessID -ErrorAction SilentlyContinue }
            }
            if ($service -and $state.AgentExisted) {
                if ($state.Status -eq 'Running') {
                    Set-Service ssh-agent -StartupType Manual
                    $null = Invoke-Pkcs11Command "$env:SystemRoot/System32/sc.exe" @('start', 'ssh-agent')
                    (Get-Service ssh-agent).WaitForStatus('Running', [TimeSpan]::FromSeconds(60))
                }
                Set-Service ssh-agent -StartupType $state.StartType
            }
            elseif ($service) {
                $null = Invoke-Pkcs11Command "$env:SystemRoot/System32/sc.exe" @('delete', 'ssh-agent')
                $service = $null
                $marker = $null
            }
        }
        if ($state.CleanupPhase -eq 'Active') {
            $state.CleanupPhase = 'Restored'
            Save-Pkcs11State $state $JournalPath
        }
        if (Test-Path -LiteralPath $root) {
            # root is verified against the fixed fixture directory and journal GUID above.
            Remove-Item -LiteralPath $root -Recurse -Force
        }
        if ($marker) {
            Remove-ItemProperty -LiteralPath $serviceRegistryPath -Name $serviceRunMarkerName -ErrorAction Stop
        }
        Remove-Item -LiteralPath $JournalPath -Force
    }
    catch { throw ('PKCS11 cleanup failed: ' + $_.Exception.Message) }
}

if (-not $CleanupOnly) {
    $ResultsDirectory = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ResultsDirectory)
    $null = New-Item -ItemType Directory -Path $ResultsDirectory -Force
}
if ($Child) {
    Import-Module Pester -MaximumVersion 4.9.9 -Force
    $resultPath = Join-Path $ResultsDirectory "PKCS11-$Architecture-$Mode.xml"
    $result = Invoke-Pester -Script @{ Path = (Join-Path $repoRoot 'regress/pesterTests/PKCS11Certificates.Tests.ps1');
        Parameters = @{ OpenSSHBinPath = $OpenSSHBinPath; TestDirectory = $TestDirectory; Mode = $Mode } } `
        -PassThru -OutputFormat NUnitXml -OutputFile $resultPath
    Assert-Pkcs11TestResult $result -Mode $Mode
    return
}

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not [Environment]::Is64BitProcess) { throw 'Use 64-bit PowerShell to run or clean up PKCS11 tests, including x86 builds' }
$mutex = $null
if ($admin -and ($CleanupOnly -or $CleanupMode -eq 'Local')) {
    $mutex = [Threading.Mutex]::new($false, 'Global\OpenSSH-PKCS11-Tests')
    try { $locked = $mutex.WaitOne(0) }
    catch [Threading.AbandonedMutexException] { $locked = $true }
    if (-not $locked) {
        $mutex.Dispose()
        throw 'Another local PKCS11 test or cleanup is running'
    }
}
try {
if ($CleanupOnly) {
    if (-not $admin) { throw 'Administrator privileges required for local PKCS11 cleanup' }
    if ($StatePath) { Remove-Pkcs11Run $StatePath }
    elseif (Test-Path -LiteralPath $stateDirectory) {
        Get-ChildItem -LiteralPath $stateDirectory -Filter '*.json' | ForEach-Object { Remove-Pkcs11Run $_.FullName }
    }
    return
}
$savedEnvironment = @{}
foreach ($name in $environmentNames) { $savedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name) }
$journal = $null
$runId = [guid]::NewGuid().ToString('N')
$root = Join-Path $fixtureDirectory $runId
$summary = [ordered]@{ Mode = $Mode; Architecture = $Architecture; CleanupMode = $CleanupMode;
    RSA = 'not run'; ECDSA = 'not run'; Success = $false }
try {
    $hardware = if ($Mode -eq 'Hardware') { Get-Pkcs11TestConfiguration -Mode Hardware } else { $null }
    $skipHardware = $Mode -eq 'Hardware' -and $hardware.SkipReason
    if (-not $skipHardware) {
        if (-not $admin) { throw 'Administrator privileges required for PKCS11 service tests' }
        $OpenSSHBinPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OpenSSHBinPath)
        foreach ($file in @('ssh-agent.exe', 'ssh-add.exe', 'ssh-keygen.exe')) {
            if ((Get-Pkcs11PeArchitecture (Join-Path $OpenSSHBinPath $file)) -ne $Architecture) {
                throw "OpenSSH $file architecture mismatch"
            }
        }
        if ($CleanupMode -eq 'Local') {
            & $PSCommandPath -CleanupOnly
            Set-Pkcs11PrivateDirectory $stateDirectory
        }
        $service = Get-Service ssh-agent -ErrorAction SilentlyContinue
        if ($service) {
            $serviceInfo = Get-CimInstance Win32_Service -Filter "Name='ssh-agent'"
            if ([IO.Path]::GetFullPath($serviceInfo.PathName.Trim('"')) -ne (Join-Path $OpenSSHBinPath 'ssh-agent.exe')) {
                throw 'ssh-agent service does not use the selected build; install the test build first'
            }
        }
        $userRoots = @()
        foreach ($name in @('Keys', 'PKCS11_Providers')) {
            $path = "HKCU:\Software\OpenSSH\Agent\$name"
            if (Test-Path -LiteralPath $path) {
                $userRoots += $name
                if (@(Get-ChildItem -LiteralPath $path).Count) {
                    throw 'PKCS11 runner requires an empty test agent Registry'
                }
            }
        }
        $environmentProperty = if ($service) { Get-ItemProperty -LiteralPath $serviceRegistryPath } else { $null }
        if ($environmentProperty -and $environmentProperty.PSObject.Properties[$serviceRunMarkerName]) {
            throw 'ssh-agent already has a PKCS11 test run marker; recover its journal first'
        }
        $machineAgentPath = if ($Architecture -eq 'x86') {
            'HKLM:\Software\WOW6432Node\OpenSSH\Agent'
        } else { 'HKLM:\Software\OpenSSH\Agent' }
        $machineAgent = Get-ItemProperty -LiteralPath $machineAgentPath -ErrorAction SilentlyContinue
        $state = @{ Version = 3; Architecture = $Architecture; RunId = $runId; Root = $root; BinaryDirectory = $OpenSSHBinPath;
            UserSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value;
            AgentPath = [IO.Path]::GetFullPath((Join-Path $OpenSSHBinPath 'ssh-agent.exe')); CleanupPhase = 'Active';
            AgentExisted = [bool]$service; Status = $(if ($service) { [string]$service.Status } else { 'Stopped' });
            StartType = $(if ($service) { [string]$service.StartType } else { 'Manual' });
            EnvironmentPresent = [bool]($environmentProperty -and $environmentProperty.PSObject.Properties['Environment']);
            Environment = $(if ($environmentProperty) { @($environmentProperty.Environment) } else { @() });
            UserSoftHSMConfiguration = [Environment]::GetEnvironmentVariable('SOFTHSM2_CONF', 'User');
            UserRootsPresent = $userRoots; UserAgentRootPresent = (Test-Path 'HKCU:\Software\OpenSSH\Agent');
            MachineAgentRootPresent = (Test-Path $machineAgentPath);
            MachineProcessIDRecorded = $true;
            MachineProcessIDPresent = [bool]($machineAgent -and $machineAgent.PSObject.Properties['ProcessID']);
            MachineProcessID = $(if ($machineAgent) { $machineAgent.ProcessID } else { $null });
            ServiceTouched = $false }
        if ($CleanupMode -eq 'Local') {
            $journal = Join-Path $stateDirectory "$runId.json"
            Save-Pkcs11State $state $journal
        }
        Set-Pkcs11PrivateDirectory $root
        if ($Mode -eq 'SoftHSM') {
            $archive = Get-Pkcs11Package $CacheDirectory
            $fixture = New-Pkcs11Fixture $root $OpenSSHBinPath $Architecture $archive
            $summary.PackageSHA256 = $fixture.PackageSHA256
            $summary.ProviderSHA256 = (Get-FileHash -LiteralPath $fixture.Provider -Algorithm SHA256).Hash
            $summary.SoftHSMVersion = '2.5.0'
        }
        $state.ServiceTouched = $true
        if ($journal) { Save-Pkcs11State $state $journal }
        if (-not $service) {
            New-Service ssh-agent -BinaryPathName ('"' + (Join-Path $OpenSSHBinPath 'ssh-agent.exe') + '"') -StartupType Manual | Out-Null
        }
        if ($CleanupMode -eq 'Local') {
            New-ItemProperty -LiteralPath $serviceRegistryPath -Name $serviceRunMarkerName -PropertyType String `
                -Value $runId -ErrorAction Stop | Out-Null
        }
        if (-not $service) {
            $null = Invoke-Pkcs11Command "$env:SystemRoot/System32/sc.exe" @('privs', 'ssh-agent',
                'SeAssignPrimaryTokenPrivilege/SeTcbPrivilege/SeBackupPrivilege/SeRestorePrivilege/SeImpersonatePrivilege')
        }
        if ($Mode -eq 'SoftHSM') {
            # CreateEnvironmentBlock for the client token overlays the user
            # environment on the service environment. Keep both on this fixture.
            [Environment]::SetEnvironmentVariable('SOFTHSM2_CONF', $fixture.Configuration, 'User')
            $serviceEnvironment = @($state.Environment | Where-Object {
                -not ([string]$_).StartsWith('SOFTHSM2_CONF=', [StringComparison]::OrdinalIgnoreCase)
            }) + @("SOFTHSM2_CONF=$($fixture.Configuration)")
            New-ItemProperty -LiteralPath $serviceRegistryPath -Name Environment -PropertyType MultiString `
                -Value ([string[]]$serviceEnvironment) -Force | Out-Null
        }
        Set-Service ssh-agent -StartupType Manual
        Restart-Pkcs11Agent
        $TestDirectory = Join-Path $root 'tests'
    }
    else { $TestDirectory = Join-Path $ResultsDirectory 'unused-hardware-fixture' }
    $resultPath = Join-Path $ResultsDirectory "PKCS11-$Architecture-$Mode.xml"
    Remove-Item -LiteralPath $resultPath -Force -ErrorAction SilentlyContinue
    $powerShell = (Get-Process -Id $PID).Path
    $childResult = Invoke-Pkcs11Command $powerShell @('-NoProfile', '-NonInteractive', '-File', $PSCommandPath,
        '-Child', '-OpenSSHBinPath', $OpenSSHBinPath, '-Architecture', $Architecture,
        '-Mode', $Mode, '-ResultsDirectory', $ResultsDirectory, '-TestDirectory', $TestDirectory) `
        -TimeoutSeconds 600 -AllowFailure
    Write-Host (Protect-Pkcs11Output $childResult.StdOut)
    if ($childResult.StdErr) { Write-Host $childResult.StdErr }
    if (Test-Path -LiteralPath $resultPath -PathType Leaf) {
        Protect-Pkcs11TestReport $resultPath
    }
    if ($childResult.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $resultPath -PathType Leaf)) {
        throw 'PKCS11 certificate test process failed or produced no report'
    }
    $summary.RSA = if ($skipHardware) { 'skipped' } else { 'passed' }
    $summary.ECDSA = $summary.RSA
    $summary.Success = $true
}
finally {
    try {
        if ($CleanupMode -eq 'Local' -and $journal) { Remove-Pkcs11Run $journal }
    }
    catch {
        $summary.Success = $false
        throw
    }
    finally {
        if ($CleanupMode -eq 'Local') {
            foreach ($name in $environmentNames) { [Environment]::SetEnvironmentVariable($name, $savedEnvironment[$name]) }
        }
        [IO.File]::WriteAllText((Join-Path $ResultsDirectory "PKCS11-$Architecture-$Mode-summary.json"), ($summary | ConvertTo-Json))
    }
}
}
finally {
    if ($mutex) { $mutex.ReleaseMutex(); $mutex.Dispose() }
}

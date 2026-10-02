# Shared contracts for the local and Azure PKCS#11 certificate runners.
$ErrorActionPreference = 'Stop'
$script:PackageUri = 'https://github.com/disig/SoftHSM2-for-Windows/releases/download/v2.5.0/SoftHSM2-2.5.0-portable.zip'
$script:PackageHash = '85273BCC1A6B90E877F7BB4F7E90221D57103D8F5241D154A79DD730A135B910'
$script:RequiredTests = @(
    'PKCS11 RSA add/list/sign', 'PKCS11 ECDSA add/list/sign',
    'PKCS11 associated certificate lifecycle',
    'PKCS11 software identity preservation',
    'PKCS11 software identity detachment', 'PKCS11 stale provider isolation',
    'PKCS11 software certificate preservation',
    'PKCS11 software certificate detachment'
)

function Get-Pkcs11RequiredTests { return $script:RequiredTests }

function Get-Pkcs11FixtureDirectory {
    param([ValidateSet('x64', 'x86')][string]$Architecture)
    $folder = if ($Architecture -eq 'x86') { 'ProgramFilesX86' } else { 'ProgramFiles' }
    return Join-Path ([Environment]::GetFolderPath($folder)) 'OpenSSH-PKCS11-Tests'
}

function Get-Pkcs11TestConfiguration {
    param([ValidateSet('SoftHSM', 'Hardware')][string]$Mode = 'SoftHSM')
    $missing = @()
    foreach ($name in @('PROVIDER', 'PIN', 'PUBLIC_KEYS', 'LABELS')) {
        $value = [Environment]::GetEnvironmentVariable("OPENSSH_TEST_PKCS11_$name")
        if (-not (Test-Path "Env:OPENSSH_TEST_PKCS11_$name") -or
            ($name -ne 'LABELS' -and [string]::IsNullOrEmpty($value))) {
            $missing += "OPENSSH_TEST_PKCS11_$name"
        }
    }
    if ($missing.Count) {
        $reason = 'Missing PKCS11 prerequisites: ' + ($missing -join ', ')
        if ($Mode -eq 'SoftHSM') { throw $reason }
        return @{ SkipReason = $reason; SoftwareSkipReason = $reason }
    }
    $provider = $env:OPENSSH_TEST_PKCS11_PROVIDER
    $keys = @($env:OPENSSH_TEST_PKCS11_PUBLIC_KEYS.Split(';'))
    $labels = @($env:OPENSSH_TEST_PKCS11_LABELS.Split(';'))
    if (-not (Test-Path -LiteralPath $provider -PathType Leaf)) {
        throw 'Configured PKCS11 provider does not exist'
    }
    if ($keys.Count -ne $labels.Count -or $keys.Count -eq 0) {
        throw 'PKCS11 public keys and labels must have matching counts'
    }
    foreach ($key in $keys) {
        if (-not (Test-Path -LiteralPath $key -PathType Leaf)) {
            throw 'Configured PKCS11 public key does not exist'
        }
    }
    if ($Mode -eq 'SoftHSM') {
        if ($keys.Count -ne 2 -or
            (Get-Content -LiteralPath $keys[0]) -notmatch '^ssh-rsa ' -or
            (Get-Content -LiteralPath $keys[1]) -notmatch '^ecdsa-sha2-nistp256 ') {
            throw 'Required SoftHSM fixture must contain RSA and ECDSA P-256'
        }
        if (-not $env:SOFTHSM2_CONF -or
            -not (Test-Path -LiteralPath $env:SOFTHSM2_CONF -PathType Leaf)) {
            throw 'Required SOFTHSM2_CONF does not exist'
        }
    }
    $software = $env:OPENSSH_TEST_PKCS11_SOFTWARE_KEY
    $softwareReason = ''
    if (-not $software -or -not (Test-Path -LiteralPath $software -PathType Leaf)) {
        $softwareReason = 'Missing OPENSSH_TEST_PKCS11_SOFTWARE_KEY'
        if ($Mode -eq 'SoftHSM') { throw $softwareReason }
    }
    return @{ Provider = $provider; PublicKeys = $keys; Labels = $labels;
        SoftwareKey = $software; SkipReason = ''; SoftwareSkipReason = $softwareReason }
}

function Protect-Pkcs11Output {
    param([string]$Text)
    foreach ($name in @('OPENSSH_TEST_PKCS11_PIN', 'ASKPASS_PASSWORD')) {
        $secret = [Environment]::GetEnvironmentVariable($name)
        if ($secret) { $Text = $Text.Replace($secret, '[redacted]') }
    }
    return $Text
}

function Protect-Pkcs11TestReport {
    param([Parameter(Mandatory)][string]$Path)
    $report = [xml](Get-Content -LiteralPath $Path -Raw)
    foreach ($node in $report.SelectNodes('//failure/message | //failure/stack-trace | //reason/message')) {
        $node.InnerText = Protect-Pkcs11Output $node.InnerText
    }
    $report.Save($Path)
}

function Invoke-Pkcs11Command {
    param([Parameter(Mandatory)][string]$FilePath, [string[]]$Arguments = @(),
        [int]$TimeoutSeconds = 30, [switch]$AllowFailure)
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $FilePath
    $start.WorkingDirectory = (Get-Location).ProviderPath
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.RedirectStandardInput = $true
    foreach ($argument in $Arguments) { $start.ArgumentList.Add($argument) }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    $watch = [Diagnostics.Stopwatch]::StartNew()
    try {
        if (-not $process.Start()) { throw 'Could not start PKCS11 test command' }
        $process.StandardInput.Close()
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            $process.Kill($true)
            $process.WaitForExit()
            throw "PKCS11 test command timed out: $([IO.Path]::GetFileName($FilePath))"
        }
        $remaining = [Math]::Max(0, [int]($TimeoutSeconds * 1000 - $watch.Elapsed.TotalMilliseconds))
        if (-not [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($stdout, $stderr), $remaining)) {
            throw "PKCS11 test command output timed out: $([IO.Path]::GetFileName($FilePath))"
        }
        $result = [pscustomobject]@{ ExitCode = $process.ExitCode;
            StdOut = $stdout.GetAwaiter().GetResult();
            StdErr = (Protect-Pkcs11Output $stderr.GetAwaiter().GetResult()) }
        if (-not $AllowFailure -and $result.ExitCode -ne 0) {
            throw "PKCS11 command failed: $([IO.Path]::GetFileName($FilePath)) (exit $($result.ExitCode)): $($result.StdErr)"
        }
        return $result
    }
    finally { $process.Dispose() }
}

function Assert-Pkcs11TestResult {
    param($Result, [ValidateSet('SoftHSM', 'Hardware')][string]$Mode = 'SoftHSM')
    if ($null -eq $Result -or $Result.FailedCount -ne 0) {
        throw 'PKCS11 tests failed or produced no result'
    }
    $actual = @($Result.TestResult)
    if ($actual.Count -ne $script:RequiredTests.Count) {
        throw 'PKCS11 result is missing expected test cases'
    }
    foreach ($name in $script:RequiredTests) {
        $matches = @($actual | Where-Object { $_.Name -eq $name -or
            ($Mode -eq 'Hardware' -and $_.Name.StartsWith("$name [skipped:")) })
        if ($matches.Count -ne 1 -or
            ($Mode -eq 'SoftHSM' -and $matches[0].Result -ne 'Passed') -or
            ($Mode -eq 'Hardware' -and $matches[0].Result -notin @('Passed', 'Skipped'))) {
            throw "PKCS11 test did not complete: $name"
        }
    }
    if ($Mode -eq 'SoftHSM' -and ($Result.PassedCount -ne $script:RequiredTests.Count -or
        $Result.SkippedCount -ne 0 -or $Result.PendingCount -ne 0)) {
        throw 'Required PKCS11 tests must all pass without skips or pending cases'
    }
}

function Get-Pkcs11Package {
    param([Parameter(Mandatory)][string]$CacheDirectory)
    $null = New-Item -ItemType Directory -Path $CacheDirectory -Force
    $archive = Join-Path $CacheDirectory 'SoftHSM2-2.5.0-portable.zip'
    if (-not (Test-Path -LiteralPath $archive -PathType Leaf)) {
        # Only transport failures may be retried; tests are never retried.
        for ($attempt = 0; $attempt -lt 3; $attempt++) {
            try {
                Invoke-WebRequest -Uri $script:PackageUri -OutFile "$archive.download" -TimeoutSec 60
                if ((Get-FileHash -LiteralPath "$archive.download" -Algorithm SHA256).Hash -ne $script:PackageHash) {
                    throw 'SoftHSM package SHA256 mismatch'
                }
                Move-Item -LiteralPath "$archive.download" -Destination $archive
                break
            }
            catch {
                Remove-Item -LiteralPath "$archive.download" -Force -ErrorAction SilentlyContinue
                if ($_.Exception.Message -match 'SHA256' -or $attempt -eq 2) { throw }
            }
        }
    }
    if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ne $script:PackageHash) {
        throw 'SoftHSM package SHA256 mismatch'
    }
    return $archive
}

function Get-Pkcs11PeArchitecture {
    param([Parameter(Mandatory)][string]$Path)
    $stream = [IO.File]::OpenRead($Path)
    $reader = [IO.BinaryReader]::new($stream)
    try {
        if ($reader.ReadUInt16() -ne 0x5a4d) { throw 'Not a PE executable' }
        $stream.Position = 0x3c
        $offset = $reader.ReadInt32()
        if ($offset -lt 0 -or $offset -gt $stream.Length - 6) { throw 'Invalid PE header' }
        $stream.Position = $offset
        if ($reader.ReadUInt32() -ne 0x4550) { throw 'Invalid PE signature' }
        switch ($reader.ReadUInt16()) {
            0x8664 { return 'x64' }
            0x14c { return 'x86' }
            default { throw 'Unsupported executable architecture' }
        }
    }
    finally { $reader.Dispose() }
}

function Set-Pkcs11PrivateDirectory {
    param([string]$Path)
    $null = New-Item -ItemType Directory -Path $Path -Force
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544',
        [Security.Principal.WindowsIdentity]::GetCurrent().User.Value)) {
        $identity = [Security.Principal.SecurityIdentifier]::new($sid)
        $rule = [Security.AccessControl.FileSystemAccessRule]::new($identity,
            'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Restart-Pkcs11Agent {
    $service = Get-Service ssh-agent -ErrorAction Stop
    if ($service.Status -ne 'Stopped') {
        $null = Invoke-Pkcs11Command "$env:SystemRoot/System32/sc.exe" @('stop', 'ssh-agent')
        $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(60))
    }
    $null = Invoke-Pkcs11Command "$env:SystemRoot/System32/sc.exe" @('start', 'ssh-agent')
    $service.WaitForStatus('Running', [TimeSpan]::FromSeconds(60))
}

function New-Pkcs11Fixture {
    param([string]$Root, [string]$BinaryDirectory,
        [ValidateSet('x64', 'x86')][string]$Architecture, [string]$Archive)
    Expand-Archive -LiteralPath $Archive -DestinationPath $Root
    $provider = Join-Path $Root ('SoftHSM2/lib/' +
        $(if ($Architecture -eq 'x64') { 'softhsm2-x64.dll' } else { 'softhsm2.dll' }))
    if ((Get-Pkcs11PeArchitecture $provider) -ne $Architecture) {
        throw 'SoftHSM provider architecture mismatch'
    }
    $importModule = Join-Path $Root 'SoftHSM2/lib/softhsm2.dll'
    $utility = Join-Path $Root 'SoftHSM2/bin/softhsm2-util.exe'
    if ((Get-Pkcs11PeArchitecture $importModule) -ne (Get-Pkcs11PeArchitecture $utility)) {
        throw 'SoftHSM import tool and module architecture mismatch'
    }
    $tokenDirectory = Join-Path $Root 'tokens'
    $null = New-Item -ItemType Directory -Path $tokenDirectory
    $conf = Join-Path $Root 'softhsm2.conf'
    [IO.File]::WriteAllText($conf, "directories.tokendir = $tokenDirectory`nobjectstore.backend = file`nlog.level = ERROR`nslots.removable = false`n")
    $env:SOFTHSM2_CONF = $conf
    $env:OPENSSH_TEST_PKCS11_PIN = [Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(8))
    $soPin = [Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(8))
    $tokenLabel = [guid]::NewGuid().ToString('N')
    $null = Invoke-Pkcs11Command $utility @('--module', $importModule, '--init-token', '--free',
        '--label', $tokenLabel, '--pin', $env:OPENSSH_TEST_PKCS11_PIN, '--so-pin', $soPin)
    $keys = @()
    $labels = @('openssh-rsa', '')
    foreach ($type in @('rsa', 'ecdsa')) {
        $keyPath = Join-Path $Root $type
        $key = if ($type -eq 'rsa') { [Security.Cryptography.RSA]::Create(2048) }
            else { [Security.Cryptography.ECDsa]::Create([Security.Cryptography.ECCurve+NamedCurves]::nistP256) }
        try { [IO.File]::WriteAllText($keyPath, $key.ExportPkcs8PrivateKeyPem()) }
        finally { $key.Dispose() }
        $public = Invoke-Pkcs11Command (Join-Path $BinaryDirectory 'ssh-keygen.exe') @('-y', '-f', $keyPath)
        [IO.File]::WriteAllText("$keyPath.pub", $public.StdOut)
        $index = $keys.Count
        $null = Invoke-Pkcs11Command $utility @('--module', $importModule, '--token', $tokenLabel,
            '--import', $keyPath, '--id', ('0' + ($index + 1)), '--label', $labels[$index],
            '--pin', $env:OPENSSH_TEST_PKCS11_PIN)
        $keys += "$keyPath.pub"
    }
    $env:OPENSSH_TEST_PKCS11_PROVIDER = $provider
    $env:OPENSSH_TEST_PKCS11_PUBLIC_KEYS = $keys -join ';'
    $env:OPENSSH_TEST_PKCS11_LABELS = $labels -join ';'
    $env:OPENSSH_TEST_PKCS11_SOFTWARE_KEY = Join-Path $Root 'rsa'
    $null = Get-Pkcs11TestConfiguration
    return @{ Provider = $provider; Configuration = $conf; PackageSHA256 = $script:PackageHash }
}

Export-ModuleMember -Function *-Pkcs11*

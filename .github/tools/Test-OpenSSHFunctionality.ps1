<#
.SYNOPSIS
    Tests OpenSSH functionality by installing the SSH service, creating a test user,
    and attempting a password-authenticated SSH connection.

.DESCRIPTION
    This script performs end-to-end functional testing of OpenSSH on Windows by:
    1. Verifying Administrator privileges
    2. Creating a temporary local user with a random password
    3. Installing the SSH service using install-sshd.ps1
    4. Starting the SSH service
    5. Configuring Windows Firewall (optional)
    6. Testing SSH connection with password authentication
    7. Cleaning up all resources (user, service, firewall rule)

    The test is successful if an SSH connection can execute "echo hello world" successfully.

.PARAMETER Configuration
    Build configuration type. Valid values: 'Debug', 'Release'
    Default: 'Release'

.PARAMETER Architecture
    Target architecture. Valid values: 'x64', 'x86', 'ARM', 'ARM64'
    Default: the host machine's architecture (auto-detected). A mismatched explicit value is
    rejected unless -AllowArchMismatch is specified (functionality tests run host-native binaries).

.PARAMETER AllowArchMismatch
    Permit targeting an architecture that differs from the host machine's architecture.

.PARAMETER SkipFirewall
    Skip Windows Firewall configuration. Use this if firewall rules already exist
    or if testing on a system without firewall enabled.

.PARAMETER NoCleanup
    Skip cleanup of created resources (test user, firewall rule, temp files).
    Useful when debugging failures.

.EXAMPLE
    .\Test-OpenSSHFunctionality.ps1
    Tests using default Release x64 build with firewall configuration

.EXAMPLE
    .\Test-OpenSSHFunctionality.ps1 -Configuration Debug -Architecture x64
    Tests using Debug x64 build

.EXAMPLE
    .\Test-OpenSSHFunctionality.ps1 -SkipFirewall
    Tests without modifying firewall rules

.NOTES
    Requires Administrator privileges.
    Creates temporary user with prefix "openssh_test_" which is removed after testing.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',

    [Parameter()]
    [ValidateSet('x64', 'x86', 'ARM', 'ARM64')]
    [string]$Architecture,

    [Parameter()]
    [switch]$AllowArchMismatch,

    [Parameter()]
    [switch]$SkipFirewall,

    [Parameter()]
    [switch]$NoCleanup
)

# ── Resolve target architecture (default = host arch; forbid mismatch unless overridden) ──
function Get-HostArchitecture {
    $archEnv = $env:PROCESSOR_ARCHITEW6432
    if ([string]::IsNullOrEmpty($archEnv)) { $archEnv = $env:PROCESSOR_ARCHITECTURE }
    switch (($archEnv | ForEach-Object { $_.ToUpperInvariant() })) {
        'AMD64' { 'x64' }
        'X86'   { 'x86' }
        'ARM64' { 'ARM64' }
        'ARM'   { 'ARM' }
        default { 'x64' }
    }
}

$hostArch = Get-HostArchitecture
if (-not $PSBoundParameters.ContainsKey('Architecture') -or [string]::IsNullOrEmpty($Architecture)) {
    $Architecture = $hostArch
} elseif ($Architecture -ne $hostArch -and -not $AllowArchMismatch) {
    throw "Requested architecture '$Architecture' does not match the host architecture '$hostArch'. Functionality tests must run against host-native binaries; re-run with -AllowArchMismatch only if you know the target binaries can execute here."
}

# Helper function to generate a random password
function New-RandomPassword {
    [CmdletBinding()]
    param(
        [Parameter()]
        [int]$Length = 20
    )

    # Character sets for password complexity
    $lowercase = 'abcdefghijklmnopqrstuvwxyz'
    $uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    $numbers = '0123456789'
    $special = '!@#$%^&*()_+-=[]{}|;:,.<>?'

    # Ensure at least one character from each set
    $password = @(
        $lowercase[(Get-Random -Maximum $lowercase.Length)]
        $uppercase[(Get-Random -Maximum $uppercase.Length)]
        $numbers[(Get-Random -Maximum $numbers.Length)]
        $special[(Get-Random -Maximum $special.Length)]
    )

    # Fill the rest with random characters from all sets
    $allChars = $lowercase + $uppercase + $numbers + $special
    for ($i = $password.Count; $i -lt $Length; $i++) {
        $password += $allChars[(Get-Random -Maximum $allChars.Length)]
    }

    # Shuffle the password
    $shuffled = $password | Sort-Object {Get-Random}

    return -join $shuffled
}

# Initialize result object
$result = [PSCustomObject]@{
    Success = $false
    ServiceInstalled = $false
    ServiceStarted = $false
    ConnectionSuccessful = $false
    CommandOutput = $null
    TestUser = $null
    Errors = @()
    Message = ""
}

# Variables for cleanup tracking
$testUser = $null
$testUserSid = $null
$serviceWasInstalled = $false
$firewallRuleCreated = $false

try {
    Write-Host "=== OpenSSH Functionality Test ===" -ForegroundColor Cyan
    Write-Host "Configuration: $Configuration" -ForegroundColor Gray
    Write-Host "Architecture: $Architecture" -ForegroundColor Gray
    Write-Host ""

    # Step 1: Verify Administrator privileges
    Write-Host "[1/6] Checking Administrator privileges..." -ForegroundColor Yellow
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

    if (-not $isAdmin) {
        $result.Errors += "Administrator privileges required"
        $result.Message = "FAILED: This script must be run as Administrator for service installation and user management."
        Write-Host "✗ Administrator privileges required" -ForegroundColor Red
        Write-Host "  Please restart PowerShell or VS Code as Administrator" -ForegroundColor Yellow
        return $result
    }
    Write-Host "✓ Running with Administrator privileges" -ForegroundColor Green

    # Step 2: Locate build artifacts and scripts
    $scriptRoot = Split-Path -Parent $PSCommandPath
    $repoRoot = Split-Path -Parent (Split-Path -Parent $scriptRoot)
    $buildPath = Join-Path $repoRoot "bin\$Architecture\$Configuration"
    $askPassExe = Join-Path $repoRoot "regress\pesterTests\utilities\askpass_util\askpass_util.exe"

    # Verify build artifacts exist
    $sshdExe = Join-Path $buildPath "sshd.exe"
    $sshExe = Join-Path $buildPath "ssh.exe"
    $installScript = Join-Path $buildPath "install-sshd.ps1"

    if (-not (Test-Path $sshdExe) -or -not (Test-Path $sshExe)) {
        $result.Errors += "Build artifacts not found at $buildPath"
        $result.Message = "FAILED: Build artifacts not found. Please build the project first."
        Write-Host "✗ Build artifacts not found at $buildPath" -ForegroundColor Red
        return $result
    }

    if (-not (Test-Path $installScript)) {
        $result.Errors += "install-sshd.ps1 not found at $buildPath"
        $result.Message = "FAILED: install-sshd.ps1 script not found."
        Write-Host "✗ install-sshd.ps1 not found at $buildPath" -ForegroundColor Red
        return $result
    }

    # Step 3: Create temporary test user
    Write-Host "`n[2/6] Creating temporary test user..." -ForegroundColor Yellow
    $testUsername = "openssh_test_" + (Get-Random -Minimum 1000 -Maximum 9999)
    $testPassword = New-RandomPassword -Length 24
    $securePassword = ConvertTo-SecureString $testPassword -AsPlainText -Force

    try {
        Import-Module Microsoft.PowerShell.LocalAccounts -UseWindowsPowerShell
        $newUser = New-LocalUser -Name $testUsername -Password $securePassword -Description "Temporary user for OpenSSH testing" -ErrorAction Stop
        $testUser = $testUsername
        # Capture the SID now so the user's profile folder can be reliably removed
        # during cleanup, even after the local account itself has been deleted.
        $testUserSid = $newUser.SID.Value
        $result.TestUser = $testUsername
        $env:ASKPASS_PASSWORD = $testPassword
        $env:SSH_ASKPASS_REQUIRE = "force"
        if (-not (Test-Path $askPassExe)) {
            throw "SSH_ASKPASS helper not found at '$askPassExe'"
        }
        $env:SSH_ASKPASS = $askPassExe
        Write-Host "✓ Created test user: $testUsername" -ForegroundColor Green
    }
    catch {
        $result.Errors += "Failed to create test user: $_"
        $result.Message = "FAILED: Could not create temporary test user."
        Write-Host "✗ Failed to create test user: $_" -ForegroundColor Red
        return $result
    }

    # Step 4: Install SSH service
    Write-Host "`n[3/6] Installing SSH service..." -ForegroundColor Yellow
    Push-Location $buildPath
    try {
        # Check if service already exists
        $existingService = Get-Service sshd -ErrorAction SilentlyContinue
        if ($existingService) {
            Write-Host "  SSH service already exists, uninstalling first..." -ForegroundColor Gray
            $uninstallScript = Join-Path $buildPath "uninstall-sshd.ps1"
            if (Test-Path $uninstallScript) {
                & $uninstallScript 2>&1 | Out-Null
                Start-Sleep -Seconds 2
            }
        }

        # Install the service
        & $installScript 2>&1 | Out-Null
        $serviceWasInstalled = $true

        # Verify installation
        $service = Get-Service sshd -ErrorAction SilentlyContinue
        if ($service) {
            $result.ServiceInstalled = $true
            Write-Host "✓ SSH service installed successfully" -ForegroundColor Green
        }
        else {
            throw "Service installation completed but service not found"
        }
    }
    catch {
        $result.Errors += "Failed to install SSH service: $_"
        $result.Message = "FAILED: SSH service installation failed."
        Write-Host "✗ Failed to install SSH service: $_" -ForegroundColor Red
        return $result
    }
    finally {
        Pop-Location
    }

    # Step 5: Start SSH service
    Write-Host "`n[4/6] Starting SSH service..." -ForegroundColor Yellow
    try {
        Start-Service sshd -ErrorAction Stop
        Start-Sleep -Seconds 2

        $service = Get-Service sshd
        if ($service.Status -eq 'Running') {
            $result.ServiceStarted = $true
            Write-Host "✓ SSH service started successfully" -ForegroundColor Green
        }
        else {
            throw "Service status is $($service.Status), expected Running"
        }
    }
    catch {
        $result.Errors += "Failed to start SSH service: $_"
        $result.Message = "FAILED: Could not start SSH service."
        Write-Host "✗ Failed to start SSH service: $_" -ForegroundColor Red
        return $result
    }

    # Step 6: Configure Windows Firewall (if not skipped)
    if (-not $SkipFirewall) {
        Write-Host "`n[5/6] Configuring Windows Firewall..." -ForegroundColor Yellow
        try {
            # Check if rule already exists
            $existingRule = Get-NetFirewallRule -DisplayName "SSH Server (sshd) - Test" -ErrorAction SilentlyContinue
            if ($existingRule) {
                Remove-NetFirewallRule -DisplayName "SSH Server (sshd) - Test" -ErrorAction SilentlyContinue
            }

            New-NetFirewallRule -DisplayName "SSH Server (sshd) - Test" -Direction Inbound -Port 22 -Protocol TCP -Action Allow -ErrorAction Stop | Out-Null
            $firewallRuleCreated = $true
            Write-Host "✓ Firewall rule created" -ForegroundColor Green
        }
        catch {
            # Non-critical error, continue with test
            Write-Host "⚠ Firewall configuration failed (non-critical): $_" -ForegroundColor Yellow
        }
    }
    else {
        Write-Host "`n[5/6] Skipping firewall configuration (as requested)" -ForegroundColor Gray
    }

    # Step 7: Test SSH connection
    Write-Host "`n[6/6] Testing SSH connection..." -ForegroundColor Yellow

    # Prepare connection test
    $sshClientPath = Join-Path $buildPath "ssh.exe"
    $hostname = "localhost"
    $testCommand = "echo hello world"

    # Create temporary files for password input and output capture
    $tempPasswordFile = [System.IO.Path]::GetTempFileName()
    $tempOutputFile = [System.IO.Path]::GetTempFileName()
    $tempErrorFile = [System.IO.Path]::GetTempFileName()

    try {
        # Write password to temp file (for potential use, though we'll use environment variable)
        Set-Content -Path $tempPasswordFile -Value $testPassword -NoNewline

        # Build SSH command with password authentication forced
        # Note: Windows SSH doesn't support stdin password directly, so we rely on interactive prompt handling
        # For automated testing, we'll use SSH with key-based auth disabled and capture output

        $processInfo = New-Object System.Diagnostics.ProcessStartInfo
        $processInfo.FileName = $sshClientPath
        $processInfo.Arguments = "-o StrictHostKeyChecking=no -o UserKnownHostsFile=NUL -o PubkeyAuthentication=no -o PasswordAuthentication=yes $testUsername@$hostname `"$testCommand`""
        $processInfo.RedirectStandardInput = $true
        $processInfo.RedirectStandardOutput = $true
        $processInfo.RedirectStandardError = $true
        $processInfo.UseShellExecute = $false
        $processInfo.CreateNoWindow = $true

        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $processInfo

        Write-Host "  Attempting SSH connection to $testUsername@$hostname..." -ForegroundColor Gray

        $process.Start() | Out-Null

        # Begin async reads BEFORE blocking on WaitForExit — prevents deadlock when
        # SSH output exceeds the internal stream buffer size (same issue as MCP stdio).
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()

        $completed = $process.WaitForExit(30000)  # 30-second timeout

        if (-not $completed) {
            $process.Kill()
            throw "SSH connection timed out after 30 seconds"
        }

        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        $exitCode = $process.ExitCode

        # Check result
        if ($exitCode -eq 0 -and $stdout -match "hello world") {
            $result.ConnectionSuccessful = $true
            $result.CommandOutput = $stdout.Trim()
            $result.Success = $true
            $result.Message = "SUCCESS: SSH connection test passed. Command executed successfully."
            Write-Host "✓ SSH connection successful" -ForegroundColor Green
            Write-Host "  Command output: $($stdout.Trim())" -ForegroundColor Gray
        }
        else {
            $result.Errors += "SSH connection failed with exit code $exitCode"
            if ($stderr) {
                $result.Errors += "SSH error: $stderr"
            }
            $result.Message = "FAILED: SSH connection test failed."
            Write-Host "✗ SSH connection failed (exit code: $exitCode)" -ForegroundColor Red
            if ($stderr) {
                Write-Host "  Error: $stderr" -ForegroundColor Red
            }
        }
    }
    catch {
        $result.Errors += "SSH connection test error: $_"
        $result.Message = "FAILED: SSH connection test encountered an error."
        Write-Host "✗ SSH connection test error: $_" -ForegroundColor Red
    }
    finally {
        # Clean up temp files
        if (Test-Path $tempPasswordFile) { Remove-Item $tempPasswordFile -Force -ErrorAction SilentlyContinue }
        if (Test-Path $tempOutputFile) { Remove-Item $tempOutputFile -Force -ErrorAction SilentlyContinue }
        if (Test-Path $tempErrorFile) { Remove-Item $tempErrorFile -Force -ErrorAction SilentlyContinue }
    }
}
finally {
    # Cleanup: Always attempt to clean up resources
    Write-Host "`n=== Cleanup ===" -ForegroundColor Cyan

    if ($NoCleanup) {
        Write-Host "⚠ NoCleanup specified - leaving resources in place for investigation." -ForegroundColor Yellow
        if ($testUser) {
            Write-Host "  Test user: $testUser" -ForegroundColor Yellow
            Write-Host "  Test user profile folder: $(Join-Path $env:SystemDrive "Users\$testUser") (if a login occurred)" -ForegroundColor Yellow
        }
        if ($serviceWasInstalled) {
            Write-Host "  SSH service may still be installed/running (sshd)." -ForegroundColor Yellow
        }
        if ($firewallRuleCreated) {
            Write-Host "  Firewall rule: SSH Server (sshd) - Test" -ForegroundColor Yellow
        }
        Write-Host "";
    } else {
        # Stop and uninstall SSH service
        if ($serviceWasInstalled) {
            Write-Host "Stopping SSH service..." -ForegroundColor Gray
            try {
                Stop-Service sshd -Force -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 1
            }
            catch {
                Write-Host "⚠ Warning: Failed to stop service: $_" -ForegroundColor Yellow
            }

            Write-Host "Uninstalling SSH service..." -ForegroundColor Gray
            $uninstallScript = Join-Path $buildPath "uninstall-sshd.ps1"
            if (Test-Path $uninstallScript) {
                Push-Location $buildPath
                try {
                    & $uninstallScript 2>&1 | Out-Null
                    Write-Host "✓ SSH service uninstalled" -ForegroundColor Green
                }
                catch {
                    Write-Host "⚠ Warning: Failed to uninstall service: $_" -ForegroundColor Yellow
                }
                finally {
                    Pop-Location
                }
            }
        }

        # Remove firewall rule
        if ($firewallRuleCreated) {
            Write-Host "Removing firewall rule..." -ForegroundColor Gray
            try {
                Remove-NetFirewallRule -DisplayName "SSH Server (sshd) - Test" -ErrorAction SilentlyContinue
                Write-Host "✓ Firewall rule removed" -ForegroundColor Green
            }
            catch {
                Write-Host "⚠ Warning: Failed to remove firewall rule: $_" -ForegroundColor Yellow
            }
        }

        # Remove test user
        if ($testUser) {
            Write-Host "Removing test user..." -ForegroundColor Gray
            try {
                Remove-LocalUser -Name $testUser -ErrorAction Stop
                Write-Host "✓ Test user removed" -ForegroundColor Green
            }
            catch {
                Write-Host "⚠ Warning: Failed to remove test user: $_" -ForegroundColor Yellow
                Write-Host "  You may need to manually remove user: $testUser" -ForegroundColor Yellow
            }

            # Remove the user's profile folder (e.g. C:\Users\openssh_test_1234).
            # Windows creates this directory the first time the account logs in (via SSH),
            # and Remove-LocalUser does NOT delete it. Use the Win32_UserProfile CIM class
            # so the registry profile entry and the on-disk folder are both cleaned up.
            Write-Host "Removing test user profile..." -ForegroundColor Gray
            try {
                $userProfile = $null
                if ($testUserSid) {
                    $userProfile = Get-CimInstance -ClassName Win32_UserProfile -Filter "SID='$testUserSid'" -ErrorAction SilentlyContinue
                }
                if (-not $userProfile) {
                    # Fall back to matching by the profile's on-disk path.
                    $userProfile = Get-CimInstance -ClassName Win32_UserProfile -ErrorAction SilentlyContinue |
                        Where-Object { $_.LocalPath -and ($_.LocalPath.Split('\')[-1] -eq $testUser) }
                }

                if ($userProfile) {
                    $profilePath = $userProfile.LocalPath
                    $userProfile | Remove-CimInstance -ErrorAction Stop
                    # Remove-CimInstance deletes the profile registration; ensure the
                    # folder itself is gone in case any files were left behind.
                    if ($profilePath -and (Test-Path $profilePath)) {
                        Remove-Item -Path $profilePath -Recurse -Force -ErrorAction SilentlyContinue
                    }
                    Write-Host "✓ Test user profile removed" -ForegroundColor Green
                }
                else {
                    # No profile was ever created (e.g. SSH login never completed).
                    $fallbackPath = Join-Path $env:SystemDrive "Users\$testUser"
                    if (Test-Path $fallbackPath) {
                        Remove-Item -Path $fallbackPath -Recurse -Force -ErrorAction Stop
                        Write-Host "✓ Test user profile folder removed" -ForegroundColor Green
                    }
                    else {
                        Write-Host "  No profile folder found for $testUser" -ForegroundColor Gray
                    }
                }
            }
            catch {
                Write-Host "⚠ Warning: Failed to remove test user profile: $_" -ForegroundColor Yellow
                Write-Host "  You may need to manually remove folder: $(Join-Path $env:SystemDrive "Users\$testUser")" -ForegroundColor Yellow
            }
        }

        Write-Host ""
    }
}

# Output summary
Write-Host "=== Test Summary ===" -ForegroundColor Cyan
Write-Host "Status: $(if ($result.Success) { 'PASSED' } else { 'FAILED' })" -ForegroundColor $(if ($result.Success) { 'Green' } else { 'Red' })
Write-Host "Service Installed: $($result.ServiceInstalled)" -ForegroundColor Gray
Write-Host "Service Started: $($result.ServiceStarted)" -ForegroundColor Gray
Write-Host "Connection Successful: $($result.ConnectionSuccessful)" -ForegroundColor Gray
if ($result.CommandOutput) {
    Write-Host "Command Output: $($result.CommandOutput)" -ForegroundColor Gray
}
if ($result.Errors.Count -gt 0) {
    Write-Host "Errors:" -ForegroundColor Red
    foreach ($e in $result.Errors) {
        Write-Host "  - $e" -ForegroundColor Red
    }
}
Write-Host ""

# Return result object
return $result

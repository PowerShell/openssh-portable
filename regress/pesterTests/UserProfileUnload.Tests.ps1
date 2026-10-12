Import-Module $PSScriptRoot\CommonUtils.psm1 -Force

# Regression test for PowerShell/Win32-OpenSSH#1694: sshd must unload the user
# registry hive after a session ends, otherwise open handles on NTUSER.DAT /
# UsrClass.dat leak and the user profile can no longer be deleted.
Describe "User profile hive is unloaded after a session (issue #1694)" -Tags "CI" {
    BeforeAll {
        if ($OpenSSHTestInfo -eq $null) {
            Throw "`$OpenSSHTestInfo is null. Please run Set-OpenSSHTestEnvironment to set test environments."
        }

        $server = $OpenSSHTestInfo["Target"]
        $port = $OpenSSHTestInfo["Port"]
        $user = $OpenSSHTestInfo["PasswdUser"]
        $password = $OpenSSHTestInfo["TestAccountPW"]

        # The profile is only loaded (and therefore unloaded) when sshd runs as
        # SYSTEM. Skip when the test daemon runs under another account.
        $skip = $true
        $svcName = $OpenSSHTestInfo["SshdServiceName"]
        if ($svcName) {
            $svc = Get-CimInstance Win32_Service -Filter "Name='$svcName'" -ErrorAction SilentlyContinue
            if ($svc -and $svc.StartName -match '^(LocalSystem|NT AUTHORITY\\SYSTEM)$') { $skip = $false }
        } else {
            # task-based test daemon is registered as SYSTEM
            $skip = $false
        }

        # resolve the user's SID so we can look for its loaded hive under HKEY_USERS
        $userSid = $null
        try {
            $userSid = (New-Object System.Security.Principal.NTAccount($user)).Translate(
                [System.Security.Principal.SecurityIdentifier]).Value
        } catch {
            $skip = $true
        }

        Add-PasswordSetting -Pass $password
    }

    AfterAll {
        Remove-PasswordSetting
    }

    It "loads the user hive during a session and unloads it after the child exits" -skip:$skip {
        # Keep a session alive in a background job so the loaded hive is observable.
        # A job has no console, so ssh uses SSH_ASKPASS for the password.
        $job = Start-Job -ScriptBlock {
            param($port, $server, $user)
            ssh -p $port -o "StrictHostKeyChecking=no" "$user@$server" "powershell -NoProfile -Command Start-Sleep -Seconds 30"
        } -ArgumentList $port, $server, $user

        # Wait for auth + profile load (slow on CI). Enumerate HKEY_USERS via reg.exe,
        # which needs only enumerate rights, unlike opening the ACL'd hive key.
        $loaded = $false
        for ($i = 0; $i -lt 30 -and -not $loaded; $i++) {
            Start-Sleep -Seconds 1
            $loaded = [bool]((reg query HKU 2>$null) -match [regex]::Escape($userSid))
        }
        $loaded | Should Be $true

        Stop-Job $job
        Remove-Job $job -Force

        # The session child is reaped asynchronously; wait for the unload to complete.
        $loaded = $true
        for ($i = 0; $i -lt 30 -and $loaded; $i++) {
            Start-Sleep -Seconds 1
            $loaded = [bool]((reg query HKU 2>$null) -match [regex]::Escape($userSid))
        }
        $loaded | Should Be $false
    }
}

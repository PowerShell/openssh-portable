If ($PSVersiontable.PSVersion.Major -le 2) {$PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path}
Import-Module $PSScriptRoot\CommonUtils.psm1 -Force
Import-Module OpenSSHUtils -Force

$tC = 1
$tI = 0
$suite = "userenvironment"

Describe "E2E scenarios for user environment block" -Tags "CI" {
    BeforeAll {
        if ($OpenSSHTestInfo -eq $null) {
            throw "`$OpenSSHTestInfo is null. Please run Set-OpenSSHTestEnvironment to set test environments."
        }

        $server  = $OpenSSHTestInfo["Target"]
        $port    = $OpenSSHTestInfo["Port"]

        $testDir = Join-Path $OpenSSHTestInfo["TestDataPath"] $suite
        if (-not (Test-Path $testDir)) {
            $null = New-Item $testDir -ItemType directory -Force -ErrorAction SilentlyContinue
        }

        $script:envTestUser    = $OpenSSHTestInfo["SshdUser"]
        $script:envTestProfile = $OpenSSHTestInfo["SshdUserProfile"]

        $keypassphrase = "testpassword"
        $script:envTestKey = Join-Path $testDir "sshd_user_envtest_ed25519"
        Remove-Item -Path "$($script:envTestKey)*" -Force -ErrorAction SilentlyContinue
        ssh-keygen.exe -q -t ed25519 -f $script:envTestKey -N $keypassphrase
        $envTestSshDir = Join-Path $script:envTestProfile .ssh
        if (-not (Test-Path $envTestSshDir -PathType Container)) {
            New-Item $envTestSshDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
        }
        $script:envTestAuthKeys = Join-Path $envTestSshDir authorized_keys
        Copy-Item "$($script:envTestKey).pub" $script:envTestAuthKeys -Force
        Repair-AuthorizedKeyPermission -FilePath $script:envTestAuthKeys -confirm:$false
        Add-PasswordSetting -Pass $keypassphrase
    }

    AfterAll {
        Remove-PasswordSetting
        if ($script:envTestKey) { 
            Remove-Item -Path "$($script:envTestKey)*" -Force -ErrorAction SilentlyContinue 
        }
        if ($script:envTestAuthKeys -and (Test-Path $script:envTestAuthKeys)) {
            Remove-Item $script:envTestAuthKeys -Force -ErrorAction SilentlyContinue
        }
    }

    AfterEach { $tI++ }

    Context "$tC - User environment variables" {
        BeforeAll { $tI = 1 }
        AfterAll  { $tC++ }

        It "$tC.$tI - USERNAME matches the connecting user" {
            $o = ssh -p $port -i $script:envTestKey "$($script:envTestUser)@$server" echo %USERNAME%
            "$o".Trim() | Should Be $script:envTestUser
        }

        It "$tC.$tI - USERPROFILE points to the connecting user's profile" {
            $o = ssh -p $port -i $script:envTestKey "$($script:envTestUser)@$server" echo %USERPROFILE%
            $remote = "$o".Trim()
            $remote | Should Not BeNullOrEmpty
            $remote | Should Not Match 'system32\\config\\systemprofile'
            # Profile leaf is normally the user name, but Windows can suffix
            # it (e.g. sshd_user.DESKTOP-XYZ.001) when the profile dir was
            # recreated, so just check it starts with the user name.
            ($remote -split '\\')[-1] | Should Match ("^" + [regex]::Escape($script:envTestUser))
        }

        It "$tC.$tI - HOMEDRIVE and HOMEPATH resolve to the user's profile" {
            $hd = "$(ssh -p $port -i $script:envTestKey "$($script:envTestUser)@$server" echo %HOMEDRIVE%)".Trim()
            $hp = "$(ssh -p $port -i $script:envTestKey "$($script:envTestUser)@$server" echo %HOMEPATH%)".Trim()
            $up = "$(ssh -p $port -i $script:envTestKey "$($script:envTestUser)@$server" echo %USERPROFILE%)".Trim()
            $hp | Should Not Match 'system32\\config\\systemprofile'
            $hp | Should Not Match '^\\Windows'
            $hp | Should Match ("^\\Users\\" + [regex]::Escape($script:envTestUser))
            $hd | Should Be $env:SystemDrive
            ($hd + $hp) | Should Be $up
        }

        It "$tC.$tI - APPDATA is populated for user" {
            $ad = "$(ssh -p $port -i $script:envTestKey "$($script:envTestUser)@$server" echo %APPDATA%)".Trim()
            $ad | Should Not Match 'system32\\config\\systemprofile'
            $ad | Should Match 'AppData\\Roaming$'
            $ad | Should Match ([regex]::Escape($script:envTestUser))
        }

        It "$tC.$tI - LOCALAPPDATA is populated for user" {
            $la = "$(ssh -p $port -i $script:envTestKey "$($script:envTestUser)@$server" echo %LOCALAPPDATA%)".Trim()
            $la | Should Not Match 'system32\\config\\systemprofile'
            $la | Should Match 'AppData\\Local$'
            $la | Should Match ([regex]::Escape($script:envTestUser))
        }

        It "$tC.$tI - USERDOMAIN equals the local computer name" {
            $o = ssh -p $port -i $script:envTestKey "$($script:envTestUser)@$server" echo %USERDOMAIN%
            $remote = "$o".Trim()
            $remote | Should Not Be 'WORKGROUP'
            $remote | Should Be $env:COMPUTERNAME
        }
    }

    Context "$tC - PATH variable" {
        BeforeAll {
            $tI = 1
            $script:pathMarker = "C:\sshtestmarker_$([guid]::NewGuid().ToString('N'))"
            ssh -p $port -i $script:envTestKey "$($script:envTestUser)@$server" `
                reg add HKCU\Environment /v Path /t REG_EXPAND_SZ /d $($script:pathMarker) /f | Out-Null
        }
        AfterAll {
            ssh -p $port -i $script:envTestKey "$($script:envTestUser)@$server" `
                reg delete HKCU\Environment /v Path /f | Out-Null
            $tC++
        }

        It "$tC.$tI - contains both system and user entries" {
            $o = ssh -p $port -i $script:envTestKey "$($script:envTestUser)@$server" echo %PATH%
            $remote   = "$o".Trim()
            $segments = $remote -split ';'
            $sysMatches    = @($segments | Where-Object { $_ -match '[Ss]ystem32' })
            $markerMatches = @($segments | Where-Object { $_ -eq $script:pathMarker })
            $sysMatches.Count    | Should BeGreaterThan 0
            $markerMatches.Count | Should BeGreaterThan 0
            $sysIndex    = [array]::IndexOf($segments, $sysMatches[0])
            $markerIndex = [array]::IndexOf($segments, $script:pathMarker)
            $sysIndex    | Should BeLessThan $markerIndex
        }
    }
}

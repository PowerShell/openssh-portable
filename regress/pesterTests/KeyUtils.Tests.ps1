If ($PSVersiontable.PSVersion.Major -le 2) {$PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path}
Import-Module $PSScriptRoot\CommonUtils.psm1 -Force
$tC = 1
$tI = 0
$suite = "keyutils"

Describe "E2E scenarios for ssh key management" -Tags "CI" {
    BeforeAll {
        if($OpenSSHTestInfo -eq $null)
        {
            Throw "`$OpenSSHTestInfo is null. Please run Set-OpenSSHTestEnvironment to set test environments."
        }

        $testDir = "$($OpenSSHTestInfo["TestDataPath"])\$suite"
        if( -not (Test-path $testDir -PathType Container))
        {
            $null = New-Item $testDir -ItemType directory -Force -ErrorAction SilentlyContinue
        }

        $pkcs11Pin = "testpin"
        $keypassphrase = "testpassword"
        $NoLibreSSL = $OpenSSHTestInfo["NoLibreSSL"]
        if($NoLibreSSL)
        {
            $keytypes = @("ed25519")
        }
        else
        {
            $keytypes = @("rsa","ecdsa","ed25519")
        }

        $ssouser = $OpenSSHTestInfo["SSOUser"]

        $systemSid = Get-UserSID -WellKnownSidType ([System.Security.Principal.WellKnownSidType]::LocalSystemSid)
        $adminsSid = Get-UserSID -WellKnownSidType ([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid)
        $currentUserSid = Get-UserSID -User "$($env:USERDOMAIN)\$($env:USERNAME)"
        $objUserSid = Get-UserSID -User $ssouser
        $everyoneSid = Get-UserSID -WellKnownSidType ([System.Security.Principal.WellKnownSidType]::WorldSid)

        function ValidateRegistryACL {
            param([string]$UserSid = $currentUserSid, $count)
            $agentPath = "Registry::HKEY_Users\$UserSid\Software\OpenSSH\Agent"
            $myACL = Get-ACL $agentPath
            $OwnerSid = Get-UserSid -User $myACL.Owner
            $OwnerSid.Equals($adminsSid) | Should Be $true
            $myACL.Access | Should Not Be $null
            $FullControlPerm = [System.UInt32] [System.Security.AccessControl.RegistryRights]::FullControl.value__
            $identities = @($systemSid, $adminsSid)

            foreach ($a in $myACL.Access) {
                $id = Get-UserSid -User $a.IdentityReference
                $identities -contains $id | Should Be $true
                ([System.UInt32]$a.RegistryRights.value__) | Should Be $FullControlPerm
                $a.AccessControlType | Should Be ([System.Security.AccessControl.AccessControlType]::Allow)
                $a.IsInherited | Should Be $false
                $a.InheritanceFlags | Should Be ([System.Security.AccessControl.InheritanceFlags]::None)
                $a.PropagationFlags | Should Be ([System.Security.AccessControl.PropagationFlags]::None)
            }

            $entries = @(Get-ChildItem $agentPath\keys)
            $entries.Count | Should Be $count
            if($count -gt 0)
            {
                Test-Path $agentPath\keys | Should be $true
                $entries | % {
                    $keyentryAcl = Get-Acl $_.pspath
                    $OwnerSid = Get-UserSid -User $keyentryAcl.Owner
                    $OwnerSid.Equals($adminsSid) | Should Be $true
                    $keyentryAcl.Access | Should Not Be $
                    foreach ($a in $keyentryAcl.Access) {
                        $id = Get-UserSid -User $a.IdentityReference
                        $identities -contains $id | Should Be $true
                        ([System.UInt32]$a.RegistryRights.value__) | Should Be $FullControlPerm
                        $a.AccessControlType | Should Be ([System.Security.AccessControl.AccessControlType]::Allow)
                        $a.IsInherited | Should Be $false
                        $a.InheritanceFlags | Should Be ([System.Security.AccessControl.InheritanceFlags]::None)
                        $a.PropagationFlags | Should Be ([System.Security.AccessControl.PropagationFlags]::None)
                    }
                }
            }
            else
            {
                Test-Path $agentPath\keys | Should be $false
            }
        }

        #only validate owner and ACEs of the file
        function ValidateKeyFile {
            param(
                [string]$FilePath,
                [bool]$IsHostKey = $true
            )

            $myACL = Get-ACL $FilePath
            $currentOwnerSid = Get-UserSid -User $myACL.Owner
            $currentOwnerSid.Equals($currentUserSid) | Should Be $true
            $myACL.Access | Should Not Be $null

            $ReadAccessPerm = ([System.UInt32] [System.Security.AccessControl.FileSystemRights]::Read.value__) -bor `
                    ([System.UInt32] [System.Security.AccessControl.FileSystemRights]::ReadAndExecute.value__)  -bor `
                    ([System.UInt32] [System.Security.AccessControl.FileSystemRights]::Synchronize.value__)
            $ReadWriteAccessPerm = ([System.UInt32] [System.Security.AccessControl.FileSystemRights]::Read.value__) -bor `
                    ([System.UInt32] [System.Security.AccessControl.FileSystemRights]::ReadAndExecute.value__)  -bor `
                    ([System.UInt32] [System.Security.AccessControl.FileSystemRights]::Write.value__)  -bor `
                    ([System.UInt32] [System.Security.AccessControl.FileSystemRights]::Modify.value__)  -bor `
                    ([System.UInt32] [System.Security.AccessControl.FileSystemRights]::Synchronize.value__)

            $FullControlPerm = [System.UInt32] [System.Security.AccessControl.FileSystemRights]::FullControl.value__

            if($FilePath.EndsWith(".pub")) {
                if ($IsHostKey) {
                    $myACL.Access.Count | Should Be 3
                    $identities = @($systemSid, $adminsSid, $currentUserSid)
                }
                else {
                    $myACL.Access.Count | Should Be 4
                    $identities = @($systemSid, $adminsSid, $currentUserSid, $everyoneSid)
                }
            }
            else {
                $myACL.Access.Count | Should Be 3
                $identities = @($systemSid, $adminsSid, $currentUserSid)
            }

            foreach ($a in $myACL.Access) {
                $id = Get-UserSid -User $a.IdentityReference
                $identities -contains $id | Should Be $true

                switch ($id)
                {
                    {@($systemSid, $adminsSid) -contains $_}
                    {
                        ([System.UInt32]$a.FileSystemRights.value__) | Should Be $FullControlPerm
                        break;
                    }

                    $currentUserSid
                    {
                        ([System.UInt32]$a.FileSystemRights.value__) | Should Be $ReadWriteAccessPerm
                        break;
                    }
                    $everyoneSid
                    {
                        ([System.UInt32]$a.FileSystemRights.value__) | Should Be $ReadAccessPerm
                        break;
                    }
                }

                $a.AccessControlType | Should Be ([System.Security.AccessControl.AccessControlType]::Allow)
                $a.IsInherited | Should Be $false
                $a.InheritanceFlags | Should Be ([System.Security.AccessControl.InheritanceFlags]::None)
                $a.PropagationFlags | Should Be ([System.Security.AccessControl.PropagationFlags]::None)
            }
        }
    }

    BeforeEach {
        $stderrFile=Join-Path $testDir "$tC.$tI.stderr.txt"
        $stdoutFile=Join-Path $testDir "$tC.$tI.stdout.txt"
        $logFile = Join-Path $testDir "$tC.$tI.log.txt"
    }

    AfterEach {$tI++;}

    Context "$tC -ssh-keygen all key types" {

        BeforeAll {$tI=1}
        AfterAll{$tC++}

        It "$tC.$tI - Keygen -A" {
            Push-Location $testDir
            remove-item ssh_host_*_key* -ErrorAction SilentlyContinue
            ssh-keygen -A
            Pop-Location

            Get-ChildItem (join-path $testDir ssh_host_*_key) | % {
                ValidateKeyFile -FilePath $_.FullName
            }

            Get-ChildItem (join-path $testDir ssh_host_*_key.pub) | % {
                ValidateKeyFile -FilePath $_.FullName
            }
        }

        It "$tC.$tI - Keygen -t -f" {
            foreach($type in $keytypes)
            {
                $keyPath = Join-Path $testDir "id_$type"
                remove-item $keyPath -ErrorAction SilentlyContinue
                if($OpenSSHTestInfo["NoLibreSSL"])
                {
                    ssh-keygen -t $type -P $keypassphrase -f $keyPath -Z aes128-ctr
                }
                else
                {
                    ssh-keygen -t $type -P $keypassphrase -f $keyPath
                }
                ValidateKeyFile -FilePath $keyPath
                ValidateKeyFile -FilePath "$keyPath.pub" -IsHostKey $false
            }
        }
    }

    # This uses keys generated in above context
    Context "$tC -ssh-add test cases" {
        BeforeAll {
            $tI=1
            function WaitForStatus
            {
                param([string]$ServiceName, [string]$Status)
                while((((Get-Service $ServiceName).Status) -ine $Status) -and ($num++ -lt 4))
                {
                    Start-Sleep -Milliseconds 1000
                }
            }
        }
        AfterAll{$tC++}
        AfterEach { Remove-PasswordSetting }

        # Executing ssh-agent will start agent service
        # This is to support typical Unix scenarios where
        # running ssh-agent will setup the agent for current session
        It "$tC.$tI - ssh-agent starts agent service" {
            if ((Get-Service ssh-agent).Status -eq "Running") {
                Stop-Service ssh-agent -Force
            }

            (Get-Service ssh-agent).Status | Should Be "Stopped"

            ssh-agent
            WaitForStatus -ServiceName ssh-agent -Status "Running"

            (Get-Service ssh-agent).Status | Should Be "Running"
        }

        It "$tC.$tI - ssh-add - add and remove all key types" {
            #set up SSH_ASKPASS
            Add-PasswordSetting -Pass $keypassphrase

            $nullFile = join-path $testDir ("$tC.$tI.nullfile")
            $null > $nullFile

            foreach($type in $keytypes)
            {
                $keyPath = Join-Path $testDir "id_$type"
                # for ssh-add to consume SSh_ASKPASS, stdin should not be TTY
                iex "cmd /c `"ssh-add $keyPath < $nullFile 2> nul `""
                #Check if -Raw presents for Get-Content cmdlet
                $rawParam = (get-command Get-Content).Parametersets | Select -ExpandProperty Parameters | ? {$_.Name -ieq "Raw"}
                if($rawParam)
                {
                    $keyPathDifferentEnding = Join-Path $testDir "id_$($type)_DifferentEnding"
                    if((Get-Content -Path $keyPath -raw).Contains("`r`n"))
                    {
                        $newcontent = (Get-Content -Path $keyPath -raw).Replace("`r`n", "`n")
                    }
                    else
                    {
                        $newcontent = (Get-Content -Path $keyPath -raw).Replace("`n", "`r`n")
                    }
                    Set-content -Path $keyPathDifferentEnding -value "$newcontent"
                    Repair-UserKeyPermission $keyPathDifferentEnding -confirm:$false
                    iex "cmd /c `"ssh-add $keyPathDifferentEnding < $nullFile 2> nul `""
                }
            }

            #remove SSH_ASKPASS
            Remove-PasswordSetting

            #ensure added keys are listed
            $allkeys = ssh-add -L
            $allkeys | Set-Content (Join-Path $testDir "$tC.$tI.allkeyonAdd.txt")
            ValidateRegistryACL -count $allkeys.Count

            foreach($type in $keytypes)
            {
                $keyPath = Join-Path $testDir "id_$type"
                $pubkeyraw = ((Get-Content "$keyPath.pub").Split(' '))[1]
                @($allkeys | where { $_.contains($pubkeyraw) }).count | Should Be 1
            }

            #delete added keys
            foreach($type in $keytypes)
            {
                $keyPath = Join-Path $testDir "id_$type"
                iex "cmd /c `"ssh-add -d $keyPath 2> nul `""
            }

            #check keys are deleted
            $allkeys = ssh-add -L
            $allkeys | Set-Content (Join-Path $testDir "$tC.$tI.allkeyonDelete.txt")

            foreach($type in $keytypes)
            {
                $keyPath = Join-Path $testDir "id_$type"
                $pubkeyraw = ((Get-Content "$keyPath.pub").Split(' '))[1]
                @($allkeys | where { $_.contains($pubkeyraw) }).count | Should Be 0
            }

            $allkeys = @(ssh-add -L)
            ValidateRegistryACL -count $allkeys.count
        }

        It "$tC.$tI - ssh-add - remove software certificates" {
            if ($NoLibreSSL) {
                Write-Host "skipping software certificate removal test without LibreSSL"
                return
            }

            $ca = Join-Path $testDir "software-cert-ca"
            $nullFile = Join-Path $testDir "$tC.$tI.nullfile"
            $null > $nullFile
            Remove-Item "$ca*" -Force -ErrorAction SilentlyContinue
            & ssh-keygen -q -t ed25519 -N $keypassphrase -f $ca
            $LASTEXITCODE | Should Be 0

            try {
                ssh-add -D
                $LASTEXITCODE | Should Be 0
                Add-PasswordSetting -Pass $keypassphrase
                $env:SSH_ASKPASS_REQUIRE = "force"

                foreach ($type in @("rsa", "ecdsa")) {
                    $keyPath = Join-Path $testDir "id_$type"
                    & ssh-keygen -q -s $ca -P $keypassphrase `
                        -I "software-$type" -n $env:USERNAME "$keyPath.pub"
                    $LASTEXITCODE | Should Be 0
                    $certPath = "$keyPath-cert.pub"

                    cmd /c "ssh-add `"$keyPath`" < `"$nullFile`""
                    $LASTEXITCODE | Should Be 0
                    & ssh-add -T $certPath
                    $LASTEXITCODE | Should Be 0

                    $certBlob = (Get-Content $certPath).Split(' ')[1]
                    @((ssh-add -L) | Where-Object { $_.Contains($certBlob) }).Count |
                        Should Be 1
                    & ssh-add -d $certPath
                    $LASTEXITCODE | Should Be 0
                    @((ssh-add -L) | Where-Object { $_.Contains($certBlob) }).Count |
                        Should Be 0
                }
            }
            finally {
                ssh-add -D | Out-Null
                Remove-Item "$ca*" -Force -ErrorAction SilentlyContinue
                foreach ($type in @("rsa", "ecdsa")) {
                    Remove-Item (Join-Path $testDir "id_$type-cert.pub") `
                        -Force -ErrorAction SilentlyContinue
                }
            }
        }

        It "$tC.$tI - ssh-add - pkcs11 library (if available)" {
            $pkcs11Path = $env:OPENSSH_TEST_PKCS11_PROVIDER
            if (-not $pkcs11Path) {
                $pkcs11Path = "C:\\Program Files\\OpenSC Project\\OpenSC\\pkcs11\\opensc-pkcs11.dll"
            }
            if (Test-Path $pkcs11Path) {
                #set up SSH_ASKPASS
                $testPin = $env:OPENSSH_TEST_PKCS11_PIN
                if (-not $testPin) { $testPin = $pkcs11Pin }
                Add-PasswordSetting -Pass $testPin
                $env:SSH_ASKPASS_REQUIRE = "force"
                ssh-add -s "$pkcs11Path"
                $LASTEXITCODE | Should Be 0

                #ensure added keys are listed
                $allkeys = ssh-add -L
                $allKeys -notmatch "The agent has no identities." | Should Be $True

                #delete added keys
                iex "cmd /c `"ssh-add -D 2> nul `""

                #check keys are deleted
                $allkeys = ssh-add -L
                $allKeys -match "The agent has no identities." | Should Be $True
            }
            else {
                Write-Host "skipping pkcs11 test because provider not found"
            }
        }

        It "$tC.$tI - ssh-add - pkcs11 certificates (if configured)" {
            $pkcs11Path = $env:OPENSSH_TEST_PKCS11_PROVIDER
            $publicKeyPaths = @($env:OPENSSH_TEST_PKCS11_PUBLIC_KEYS -split ';' |
                Where-Object { $_ })
            if (-not $pkcs11Path -or -not (Test-Path $pkcs11Path) -or
                $publicKeyPaths.Count -eq 0) {
                Write-Host "skipping pkcs11 certificate test because provider and public keys are not configured"
                return
            }

            foreach ($publicKeyPath in $publicKeyPaths) {
                Test-Path $publicKeyPath | Should Be $true
            }
            Test-Path Env:OPENSSH_TEST_PKCS11_LABELS | Should Be $true
            $pkcs11Labels = @($env:OPENSSH_TEST_PKCS11_LABELS.Split(
                [char[]]@(';'), [StringSplitOptions]::None))
            $pkcs11Labels.Count | Should Be $publicKeyPaths.Count
            $canonicalProvider = [IO.Path]::GetFullPath($pkcs11Path).Replace('\', '/')
            $expectedComments = @($pkcs11Labels | ForEach-Object {
                if ($_) { $_ } else { $canonicalProvider }
            })

            function Assert-Pkcs11IdentityComments {
                param([string[]]$KeyPaths, [string[]]$Comments)

                $longListing = @(ssh-add -L)
                $shortListing = @(ssh-add -l)
                $KeyPaths.Count | Should Be $Comments.Count
                $fingerprints = @($KeyPaths | ForEach-Object {
                    ((ssh-keygen -lf $_) -split ' ')[1]
                })
                for ($index = 0; $index -lt $KeyPaths.Count; $index++) {
                    $keyBlob = (Get-Content $KeyPaths[$index]).Split(' ')[1]
                    $longEntry = @($longListing | Where-Object {
                        $_.Contains($keyBlob)
                    })
                    $longEntry.Count | Should Be 1
                    ($longEntry[0] -split ' ', 3)[2] | Should Be $Comments[$index]

                    $fingerprint = $fingerprints[$index]
                    $shortEntry = @($shortListing | Where-Object {
                        $_.Contains(" $fingerprint ")
                    })
                    $shortEntry.Count | Should Be @($fingerprints |
                        Where-Object { $_ -eq $fingerprint }).Count
                    foreach ($entry in $shortEntry) {
                        $entry | Should Match (" " +
                            [regex]::Escape($Comments[$index]) + " \([^)]+\)$")
                    }
                }
            }
            $testPin = $env:OPENSSH_TEST_PKCS11_PIN
            if (-not $testPin) { $testPin = $pkcs11Pin }
            $ca = Join-Path $testDir "pkcs11-ca"
            Remove-Item "$ca*" -Force -ErrorAction SilentlyContinue
            & ssh-keygen -q -t ed25519 -N $keypassphrase -f $ca
            $LASTEXITCODE | Should Be 0

            $certPaths = @()
            $copiedPublicKeyPaths = @()
            $serial = 1
            foreach ($publicKeyPath in $publicKeyPaths) {
                $copiedPublicKeyPath = Join-Path $testDir "pkcs11-$serial.pub"
                Copy-Item $publicKeyPath $copiedPublicKeyPath -Force
                & ssh-keygen -q -s $ca -P $keypassphrase -I "pkcs11-$serial" `
                    -n $env:USERNAME -z $serial $copiedPublicKeyPath
                $LASTEXITCODE | Should Be 0
                $copiedPublicKeyPaths += $copiedPublicKeyPath
                $certPaths += $copiedPublicKeyPath.Replace(".pub", "-cert.pub")
                $serial++
            }
            & ssh-keygen -q -s $ca -P $keypassphrase -I "pkcs11-unmatched" `
                -n $env:USERNAME -z 999 "$ca.pub"
            $LASTEXITCODE | Should Be 0
            $unmatchedCertPath = "$ca-cert.pub"
            $associatedCertPaths = $certPaths + $unmatchedCertPath

            $sequentialPublicKeyPath = Join-Path $testDir "pkcs11-sequential.pub"
            Copy-Item $publicKeyPaths[0] $sequentialPublicKeyPath -Force
            & ssh-keygen -q -s $ca -P $keypassphrase -I "pkcs11-sequential" `
                -n $env:USERNAME -z 1000 $sequentialPublicKeyPath
            $LASTEXITCODE | Should Be 0
            $sequentialCertPath = $sequentialPublicKeyPath.Replace(".pub", "-cert.pub")

            Add-PasswordSetting -Pass $testPin
            $env:SSH_ASKPASS_REQUIRE = "force"

            $addArguments = @("-s", $pkcs11Path) + $associatedCertPaths
            & ssh-add @addArguments
            $LASTEXITCODE | Should Be 0
            $allKeys = @(ssh-add -L)
            foreach ($keyPath in $copiedPublicKeyPaths + $certPaths) {
                $keyBlob = (Get-Content $keyPath).Split(' ')[1]
                @($allKeys | Where-Object { $_.Contains($keyBlob) }).Count | Should Be 1
                & ssh-add -T $keyPath
                $LASTEXITCODE | Should Be 0
            }
            Assert-Pkcs11IdentityComments `
                ($copiedPublicKeyPaths + $certPaths) `
                ($expectedComments + $expectedComments)

            Restart-Service ssh-agent
            WaitForStatus -ServiceName ssh-agent -Status "Running"
            foreach ($certPath in $certPaths) {
                & ssh-add -T $certPath
                $LASTEXITCODE | Should Be 0
            }
            Assert-Pkcs11IdentityComments `
                ($copiedPublicKeyPaths + $certPaths) `
                ($expectedComments + $expectedComments)
            & ssh-add -d $certPaths[0]
            $LASTEXITCODE | Should Be 0
            $deletedKeyBlob = (Get-Content $certPaths[0]).Split(' ')[1]
            @((ssh-add -L) | Where-Object { $_.Contains($deletedKeyBlob) }).Count |
                Should Be 0

            ssh-add -D
            $LASTEXITCODE | Should Be 0

            # Separate additions for the same token key must merge certificates.
            $addArguments = @("-s", $pkcs11Path, "-C", $certPaths[0])
            & ssh-add @addArguments
            $LASTEXITCODE | Should Be 0
            $addArguments = @("-s", $pkcs11Path, "-C", $sequentialCertPath)
            & ssh-add @addArguments
            $LASTEXITCODE | Should Be 0
            $allKeys = @(ssh-add -L)
            foreach ($certPath in @($certPaths[0], $sequentialCertPath)) {
                $keyBlob = (Get-Content $certPath).Split(' ')[1]
                @($allKeys | Where-Object { $_.Contains($keyBlob) }).Count | Should Be 1
                & ssh-add -T $certPath
                $LASTEXITCODE | Should Be 0
            }

            # Re-adding an exact certificate is successful and idempotent.
            & ssh-add @addArguments
            $LASTEXITCODE | Should Be 0
            $sequentialCertBlob = (Get-Content $sequentialCertPath).Split(' ')[1]
            @((ssh-add -L) | Where-Object { $_.Contains($sequentialCertBlob) }).Count |
                Should Be 1
            Assert-Pkcs11IdentityComments `
                @($certPaths[0], $sequentialCertPath) `
                @($expectedComments[0], $expectedComments[0])

            ssh-add -D
            $LASTEXITCODE | Should Be 0

            # cert-only applies to this request and must preserve plain identities.
            & ssh-add -s $pkcs11Path
            $LASTEXITCODE | Should Be 0
            & ssh-add -s $pkcs11Path -C $certPaths[0]
            $LASTEXITCODE | Should Be 0
            $allKeys = @(ssh-add -L)
            foreach ($keyPath in $copiedPublicKeyPaths + $certPaths[0]) {
                $keyBlob = (Get-Content $keyPath).Split(' ')[1]
                @($allKeys | Where-Object { $_.Contains($keyBlob) }).Count | Should Be 1
            }
            Assert-Pkcs11IdentityComments `
                ($copiedPublicKeyPaths + $certPaths[0]) `
                ($expectedComments + $expectedComments[0])

            # A failed unmatched add must not change existing persisted identities.
            $identitiesBefore = @(ssh-add -L | Sort-Object)
            & ssh-add -s $pkcs11Path -C $unmatchedCertPath
            $LASTEXITCODE | Should Not Be 0
            $identitiesAfter = @(ssh-add -L | Sort-Object)
            @(Compare-Object $identitiesBefore $identitiesAfter).Count | Should Be 0

            Restart-Service ssh-agent
            WaitForStatus -ServiceName ssh-agent -Status "Running"
            foreach ($keyPath in $copiedPublicKeyPaths + $certPaths[0]) {
                & ssh-add -T $keyPath
                $LASTEXITCODE | Should Be 0
            }
            Assert-Pkcs11IdentityComments `
                ($copiedPublicKeyPaths + $certPaths[0]) `
                ($expectedComments + $expectedComments[0])

            & ssh-add -d $certPaths[0]
            $LASTEXITCODE | Should Be 0
            foreach ($keyPath in $copiedPublicKeyPaths) {
                $keyBlob = (Get-Content $keyPath).Split(' ')[1]
                @((ssh-add -L) | Where-Object { $_.Contains($keyBlob) }).Count |
                    Should Be 1
            }

            # Legacy identities used comment for their provider association.
            $identityRootPath = "$currentUserSid\Software\OpenSSH\Agent\Keys"
            $identityRoot = [Microsoft.Win32.Registry]::Users.OpenSubKey(
                $identityRootPath, $true)
            $identityRoot | Should Not Be $null
            $plainBlob = (Get-Content $copiedPublicKeyPaths[0]).Split(' ')[1]
            $identityKey = $null
            foreach ($identityName in $identityRoot.GetSubKeyNames()) {
                $candidate = $identityRoot.OpenSubKey($identityName, $true)
                $storedBlob = $candidate.GetValue("pub")
                if ($storedBlob -is [byte[]] -and
                    [Convert]::ToBase64String($storedBlob) -eq $plainBlob) {
                    $identityKey = $candidate
                    break
                }
                $candidate.Dispose()
            }
            $identityKey | Should Not Be $null
            $providerBytes = [Text.Encoding]::UTF8.GetBytes($canonicalProvider)
            $identityKey.DeleteValue("provider", $false)
            $identityKey.SetValue("comment", $providerBytes,
                [Microsoft.Win32.RegistryValueKind]::Binary)

            Restart-Service ssh-agent
            WaitForStatus -ServiceName ssh-agent -Status "Running"
            Assert-Pkcs11IdentityComments @($copiedPublicKeyPaths[0]) `
                @($canonicalProvider)
            & ssh-add -T $copiedPublicKeyPaths[0]
            $LASTEXITCODE | Should Be 0
            $identityKey.GetValue("provider", $null) | Should Be $null
            [Text.Encoding]::UTF8.GetString($identityKey.GetValue("comment")) |
                Should Be $canonicalProvider

            # A failed provider update must roll legacy metadata back.
            $providerRootPath = "$currentUserSid\Software\OpenSSH\Agent\PKCS11_Providers"
            $providerRoot = [Microsoft.Win32.Registry]::Users.OpenSubKey(
                $providerRootPath, $true)
            $providerRoot | Should Not Be $null
            $providerKey = $providerRoot.OpenSubKey($canonicalProvider,
                [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
                [Security.AccessControl.RegistryRights]::FullControl)
            $providerKey | Should Not Be $null
            $blockedAcl = $providerKey.GetAccessControl()
            $denySetValue = New-Object `
                System.Security.AccessControl.RegistryAccessRule(
                $systemSid,
                [System.Security.AccessControl.RegistryRights]::SetValue,
                [System.Security.AccessControl.AccessControlType]::Deny)
            $blockedAcl.AddAccessRule($denySetValue) | Out-Null
            try {
                $providerKey.SetAccessControl($blockedAcl)
                & ssh-add -s $pkcs11Path
                $LASTEXITCODE | Should Not Be 0
                $identityKey.GetValue("provider", $null) | Should Be $null
                [Text.Encoding]::UTF8.GetString(
                    $identityKey.GetValue("comment")) |
                    Should Be $canonicalProvider
            }
            finally {
				$blockedAcl.RemoveAccessRuleSpecific($denySetValue)
				$providerKey.SetAccessControl($blockedAcl)
            }

            # Re-adding migrates metadata without replacing the key entry.
            & ssh-add -s $pkcs11Path
            $LASTEXITCODE | Should Be 0
            [Text.Encoding]::UTF8.GetString($identityKey.GetValue("provider")) |
                Should Be $canonicalProvider
            [Text.Encoding]::UTF8.GetString($identityKey.GetValue("comment")) |
                Should Be $expectedComments[0]
            Assert-Pkcs11IdentityComments @($copiedPublicKeyPaths[0]) `
                @($expectedComments[0])

            # Provider removal accepts both migrated and legacy identities.
            $identityKey.DeleteValue("provider", $false)
            $identityKey.SetValue("comment", $providerBytes,
                [Microsoft.Win32.RegistryValueKind]::Binary)
            $providerKey.Dispose()
            $providerRoot.Dispose()
            $identityKey.Dispose()
            $identityRoot.Dispose()

            & ssh-add -e $pkcs11Path
            $LASTEXITCODE | Should Be 0
            @(ssh-add -L) -match "The agent has no identities." | Should Be $true
        }

        It "$tC.$tI - ssh-add - stale pkcs11 provider isolation (if configured)" {
            $pkcs11Path = $env:OPENSSH_TEST_PKCS11_PROVIDER
            $publicKeyPaths = @($env:OPENSSH_TEST_PKCS11_PUBLIC_KEYS -split ';' |
                Where-Object { $_ })
            if (-not $pkcs11Path -or -not (Test-Path $pkcs11Path) -or
                $publicKeyPaths.Count -eq 0) {
                Write-Host "skipping stale provider test because provider and public keys are not configured"
                return
            }

            $testPin = $env:OPENSSH_TEST_PKCS11_PIN
            if (-not $testPin) { $testPin = $pkcs11Pin }
            $softwareKeyPath = Join-Path $testDir "id_rsa"
            $unavailableKeyPath = Join-Path $testDir "id_ecdsa.pub"
            $nullFile = Join-Path $testDir "$tC.$tI.nullfile"
            $null > $nullFile
            $providerRoot = $null
            $validProviderKey = $null
            $staleProviderKey = $null
            $staleProviderPath = Join-Path $testDir `
                "nonexistent\openssh-stale-provider.dll"
            $staleProvider = [IO.Path]::GetFullPath($staleProviderPath).Replace(
                '\', '/')
            $corruptProviderPath = Join-Path $testDir `
                "nonexistent\openssh-corrupt-provider.dll"
            $corruptProvider = [IO.Path]::GetFullPath(
                $corruptProviderPath).Replace('\', '/')
            $oversizedProviderPath = Join-Path $testDir `
                "nonexistent\openssh-oversized-provider.dll"
            $oversizedProvider = [IO.Path]::GetFullPath(
                $oversizedProviderPath).Replace('\', '/')

            try {
                ssh-add -D
                $LASTEXITCODE | Should Be 0

                Add-PasswordSetting -Pass $keypassphrase
                $env:SSH_ASKPASS_REQUIRE = "force"
                cmd /c "ssh-add `"$softwareKeyPath`" < `"$nullFile`""
                $LASTEXITCODE | Should Be 0
                Remove-PasswordSetting

                Add-PasswordSetting -Pass $testPin
                $env:SSH_ASKPASS_REQUIRE = "force"
                & ssh-add -s $pkcs11Path
                $LASTEXITCODE | Should Be 0
                & ssh-add -T $softwareKeyPath
                $LASTEXITCODE | Should Be 0
                & ssh-add -T $publicKeyPaths[0]
                $LASTEXITCODE | Should Be 0

                $providerRootPath = "$currentUserSid\Software\OpenSSH\Agent\PKCS11_Providers"
                $providerRoot = [Microsoft.Win32.Registry]::Users.OpenSubKey(
                    $providerRootPath, $true)
                $providerRoot | Should Not Be $null
                $canonicalProvider = [IO.Path]::GetFullPath($pkcs11Path).Replace('\', '/')
                $validProviderKey = $providerRoot.OpenSubKey($canonicalProvider)
                $validProviderKey | Should Not Be $null
                $encryptedPin = $validProviderKey.GetValue("pin")
                $encryptedPin -is [byte[]] | Should Be $true

                $staleProviderKey = $providerRoot.CreateSubKey($staleProvider)
                $staleProviderKey.SetValue("provider",
                    [Text.Encoding]::UTF8.GetBytes($staleProvider),
                    [Microsoft.Win32.RegistryValueKind]::Binary)
                $staleProviderKey.SetValue("pin", $encryptedPin,
                    [Microsoft.Win32.RegistryValueKind]::Binary)

                & ssh-add -T $softwareKeyPath
                $LASTEXITCODE | Should Be 0
                & ssh-add -T $publicKeyPaths[0]
                $LASTEXITCODE | Should Be 0
                & ssh-add -T $unavailableKeyPath
                $LASTEXITCODE | Should Not Be 0

                $staleProviderKey.Dispose()
                $staleProviderKey = $providerRoot.CreateSubKey($corruptProvider)
                $staleProviderKey.SetValue("provider",
                    [Text.Encoding]::UTF8.GetBytes($corruptProvider),
                    [Microsoft.Win32.RegistryValueKind]::Binary)
                $staleProviderKey.SetValue("pin",
                    [Text.Encoding]::UTF8.GetBytes("invalid encrypted pin"),
                    [Microsoft.Win32.RegistryValueKind]::Binary)

                & ssh-add -T $softwareKeyPath
                $LASTEXITCODE | Should Be 0
                & ssh-add -T $publicKeyPaths[0]
                $LASTEXITCODE | Should Be 0

                $staleProviderKey.Dispose()
                $staleProviderKey = $providerRoot.CreateSubKey($oversizedProvider)
                $staleProviderKey.SetValue("provider",
                    [Text.Encoding]::UTF8.GetBytes($oversizedProvider),
                    [Microsoft.Win32.RegistryValueKind]::Binary)
                $staleProviderKey.SetValue("pin", (New-Object byte[] 11000),
                    [Microsoft.Win32.RegistryValueKind]::Binary)

                & ssh-add -T $softwareKeyPath
                $LASTEXITCODE | Should Be 0
                & ssh-add -T $publicKeyPaths[0]
                $LASTEXITCODE | Should Be 0
            }
            finally {
                if ($staleProviderKey) { $staleProviderKey.Dispose() }
                if ($validProviderKey) { $validProviderKey.Dispose() }
                if ($providerRoot) {
                    $providerRoot.DeleteSubKeyTree($staleProvider, $false)
                    $providerRoot.DeleteSubKeyTree($corruptProvider, $false)
                    $providerRoot.DeleteSubKeyTree($oversizedProvider, $false)
                    $providerRoot.Dispose()
                }
                ssh-add -D | Out-Null
                Remove-PasswordSetting
            }
        }
    }

    Context "$tC ssh-keygen known_hosts operations" {

        BeforeAll {$tI=1}
        AfterAll{$tC++}

        It "$tC.$tI - list and delete host key thumbprints" {
            $kh = Join-Path $testDir "$tC.$tI.known_hosts"
            $entry = "[localhost]:47002 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMtJMxwn+iJU0X4+EC7PSj/cfcMbdP6ahhodtXx+6RHv sshtest_hostkey_ed25519"
            $entry | Set-Content $kh
            $o = ssh-keygen -F [localhost]:47002 -f $kh
            $o.Count | Should Be 2
            $o[1] | Should Be $entry

            $o = ssh-keygen -H -F [localhost]:47002 -f $kh
            $o[1].StartsWith("|1|")  | Should Be $true

            $o = ssh-keygen -R [localhost]:47002 -f $kh
            $o.count | Should Be 3
            $o[0] | Should Be "# Host [localhost]:47002 found: line 1"
            (dir $kh).Length | Should Be 0
        }

    }

    Context "$tC-ssh-add key files with different file perms" {
        BeforeAll {
            $keyFileName = "sshadd_userPermTestkey_ed25519"
            $keyFilePath = Join-Path $testDir $keyFileName
            Remove-Item -path "$keyFilePath*" -Force -ErrorAction SilentlyContinue
            ssh-keygen.exe -t ed25519 -f $keyFilePath -P $keypassphrase
            #set up SSH_ASKPASS
            Add-PasswordSetting -Pass $keypassphrase
            $tI=1
        }
        BeforeEach {
            $nullFile = join-path $testDir ("$tC.$tI.nullfile")
            $null > $nullFile
        }
        AfterEach {
            if(Test-Path $keyFilePath) {
                Repair-FilePermission -FilePath $keyFilePath -Owner $currentUserSid -FullAccessNeeded $currentUserSid,$systemSid,$adminsSid -confirm:$false
            }
        }

        AfterAll {
            #remove SSH_ASKPASS
            Remove-PasswordSetting
            $tC++
        }

        It "$tC.$tI-  ssh-add - positive (Secured private key owned by current user)" {
            #setup to have current user as owner and grant it full control
            Repair-FilePermission -FilePath $keyFilePath -Owner $currentUserSid -FullAccessNeeded $currentUserSid,$systemSid,$adminsSid -confirm:$false

            # for ssh-add to consume SSh_ASKPASS, stdin should not be TTY
            cmd /c "ssh-add $keyFilePath < $nullFile 2> nul"
            $LASTEXITCODE | Should Be 0
            $allkeys = ssh-add -L
            $pubkeyraw = ((Get-Content "$keyFilePath.pub").Split(' '))[1]
            @($allkeys | where { $_.contains($pubkeyraw) }).count | Should Be 1

            #clean up
            cmd /c "ssh-add -d $keyFilePath 2> nul "
        }

        It "$tC.$tI - ssh-add - positive (Secured private key owned by Administrators group and the current user has no explicit ACE)" {
            #setup to have local admin group as owner and grant it full control
            Repair-FilePermission -FilePath $keyFilePath -Owner $adminsSid -FullAccessNeeded $adminsSid,$systemSid -confirm:$false

            # for ssh-add to consume SSh_ASKPASS, stdin should not be TTY
            cmd /c "ssh-add $keyFilePath < $nullFile 2> nul "
            $LASTEXITCODE | Should Be 0
            $allkeys = ssh-add -L
            $pubkeyraw = ((Get-Content "$keyFilePath.pub").Split(' '))[1]
            @($allkeys | where { $_.contains($pubkeyraw) }).count | Should Be 1

            #clean up
            cmd /c "ssh-add -d $keyFilePath 2> nul "
        }

        It "$tC.$tI - ssh-add - positive (Secured private key owned by Administrators group and the current user has explicit ACE)" {
            #setup to have local admin group as owner and grant it full control
            Repair-FilePermission -FilePath $keyFilePath -Owners $adminsSid -FullAccessNeeded $currentUserSid,$adminsSid,$systemSid -confirm:$false

            # for ssh-add to consume SSh_ASKPASS, stdin should not be TTY
            cmd /c "ssh-add $keyFilePath < $nullFile 2> nul "
            $LASTEXITCODE | Should Be 0
            $allkeys = ssh-add -L
            $pubkeyraw = ((Get-Content "$keyFilePath.pub").Split(' '))[1]
            @($allkeys | where { $_.contains($pubkeyraw) }).count | Should Be 1

            #clean up
            cmd /c "ssh-add -d $keyFilePath 2> nul "
        }

        It "$tC.$tI - ssh-add - positive (Secured private key owned by local system group)" {
            #setup to have local admin group as owner and grant it full control
            Repair-FilePermission -FilePath $keyFilePath -Owners $systemSid -FullAccessNeeded $systemSid,$adminsSid -confirm:$false

            # for ssh-add to consume SSh_ASKPASS, stdin should not be TTY
            cmd /c "ssh-add $keyFilePath < $nullFile 2> nul "
            $LASTEXITCODE | Should Be 0
            $allkeys = ssh-add -L
            $pubkeyraw = ((Get-Content "$keyFilePath.pub").Split(' '))[1]
            @($allkeys | where { $_.contains($pubkeyraw) }).count | Should Be 1

            #clean up
            cmd /c "ssh-add -d $keyFilePath 2> nul "
        }

        It "$tC.$tI-  ssh-add - negative (other account can access private key file)" {
            #setup to have current user as owner and grant it full control
            Repair-FilePermission -FilePath $keyFilePath -Owners $currentUserSid -FullAccessNeeded $currentUserSid,$adminsSid, $systemSid -ReadAccessNeeded $objUserSid -confirm:$false

            cmd /c "ssh-add $keyFilePath < $nullFile 2> nul "
            $LASTEXITCODE | Should Not Be 0

            $allkeys = ssh-add -L
            $pubkeyraw = ((Get-Content "$keyFilePath.pub").Split(' '))[1]
            @($allkeys | where { $_.contains($pubkeyraw) }).count | Should Be 0
        }

        It "$tC.$tI - ssh-add - negative (the private key has wrong owner)" {
            #setup to have ssouser as owner and grant it full control
            Repair-FilePermission -FilePath $keyFilePath -Owners $objUserSid -FullAccessNeeded $objUserSid,$adminsSid, $systemSid -confirm:$false

            cmd /c "ssh-add $keyFilePath < $nullFile 2> nul "
            $LASTEXITCODE | Should Not Be 0

            $allkeys = ssh-add -L
            $pubkeyraw = ((Get-Content "$keyFilePath.pub").Split(' '))[1]
            @($allkeys | where { $_.contains($pubkeyraw) }).count | Should Be 0
        }
    }

    Context "$tC - ssh-keyscan test cases" {
        BeforeAll {
            $tI=1
            $port = $OpenSSHTestInfo["Port"]
            Remove-item (join-path $testDir "$tC.$tI.out.txt") -force -ErrorAction SilentlyContinue
        }
        BeforeEach {
            $outputFile = join-path $testDir "$tC.$tI.out.txt"
        }
        AfterAll{$tC++}

		It "$tC.$tI - ssh-keyscan with default arguments" -Skip:$NoLibreSSL {
			cmd /c "ssh-keyscan -p $port 127.0.0.1 2>&1 > $outputFile"
			$outputFile | Should Contain '.*ssh-rsa.*'
		}

        It "$tC.$tI - ssh-keyscan with -p" -Skip:$NoLibreSSL {
			cmd /c "ssh-keyscan -p $port 127.0.0.1 2>&1 > $outputFile"
			$outputFile | Should Contain '.*ssh-rsa.*'
		}

		It "$tC.$tI - ssh-keyscan with -f" -Skip:$NoLibreSSL {
			Set-Content -Path tmp.txt -Value "127.0.0.1"
			cmd /c "ssh-keyscan -p $port -f tmp.txt 2>&1 > $outputFile"
			$outputFile | Should Contain '.*ssh-rsa.*'
		}

		It "$tC.$tI - ssh-keyscan with -f -t" -Skip:$NoLibreSSL {
			Set-Content -Path tmp.txt -Value "127.0.0.1"
			cmd /c "ssh-keyscan -p $port -f tmp.txt -t rsa 2>&1 > $outputFile"
			$outputFile | Should Contain '.*ssh-rsa.*'
		}
	}
}

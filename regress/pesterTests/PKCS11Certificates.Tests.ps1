param(
    [string]$OpenSSHBinPath,
    [string]$TestDirectory,
    [ValidateSet('SoftHSM', 'Hardware')][string]$Mode = 'SoftHSM'
)
$repoRoot = Split-Path (Split-Path $PSScriptRoot)
Import-Module (Join-Path $repoRoot '.github/tools/PKCS11TestHelpers.psm1') -Force
function Get-Pkcs11CaseName($Name, $Reason) {
    if ($Reason) { return "$Name [skipped: $Reason]" }
    return $Name
}

Describe 'Windows PKCS11 certificate integration' -Tags 'PKCS11' {
    BeforeAll {
        $config = Get-Pkcs11TestConfiguration -Mode $Mode
        $skipReason = $config.SkipReason
        $softwareSkipReason = $config.SoftwareSkipReason
        if ($skipReason) { return }
        $testDir = $TestDirectory
        $null = New-Item -ItemType Directory -Path $testDir -Force
        # CommonUtils imports this module by name. Make the repository copy
        # discoverable without requiring a machine-wide module installation.
        $modules = Join-Path $testDir 'modules'
        $utils = Join-Path $modules 'OpenSSHUtils'
        $null = New-Item -ItemType Directory -Path $utils -Force
        foreach ($file in @('OpenSSHUtils.psd1', 'OpenSSHUtils.psm1')) {
            Copy-Item -LiteralPath (Join-Path $repoRoot "contrib/win32/openssh/$file") -Destination $utils
        }
        $env:PSModulePath = "$modules;$env:PSModulePath"
        Import-Module OpenSSHUtils -Force -Global
        Import-Module (Join-Path $PSScriptRoot 'CommonUtils.psm1') -Force
        $keypassphrase = 'testpassword'
        $pkcs11Pin = $env:OPENSSH_TEST_PKCS11_PIN
        $systemSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
        $currentUserSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        $tC = 1
        $tI = 0
        function Invoke-Pkcs11TestBinary($Name, [string[]]$Arguments) {
            $result = Invoke-Pkcs11Command (Join-Path $OpenSSHBinPath $Name) $Arguments -AllowFailure
            $global:LASTEXITCODE = $result.ExitCode
            if ($result.StdErr) { Write-Host $result.StdErr.TrimEnd() }
            if ($result.StdOut) { return ($result.StdOut.TrimEnd() -split '\r?\n') }
        }
        function ssh-add { Invoke-Pkcs11TestBinary 'ssh-add.exe' $args }
        function ssh-keygen { Invoke-Pkcs11TestBinary 'ssh-keygen.exe' $args }
        function Restart-Service { Restart-Pkcs11Agent }
        function WaitForStatus($ServiceName, $Status) {
            (Get-Service $ServiceName).WaitForStatus($Status, [TimeSpan]::FromSeconds(60))
        }
        foreach ($type in @('rsa', 'ecdsa')) {
            ssh-keygen -q -t $type -N $keypassphrase -f (Join-Path $testDir "id_$type")
            $LASTEXITCODE | Should Be 0
        }
        function New-SoftwareCertificateFixture($Algorithm) {
            if ($Mode -eq 'SoftHSM') {
                $publicPath = @($config.PublicKeys | Where-Object {
                    (Get-Content -LiteralPath $_) -match $(if ($Algorithm -eq 'rsa') { '^ssh-rsa ' } else { '^ecdsa-sha2-nistp256 ' })
                })
                $publicPath.Count | Should Be 1 | Out-Null
                $source = $publicPath[0] -replace '\.pub$', ''
            } else { $source = $config.SoftwareKey }
            $key = Join-Path $testDir "software-certificate-$Algorithm"
            Copy-Item -LiteralPath $source -Destination $key -Force
            Repair-UserKeyPermission $key -Confirm:$false | Out-Null
            $public = ssh-keygen -y -f $key
            $LASTEXITCODE | Should Be 0 | Out-Null
            Set-Content -LiteralPath "$key.pub" -Value $public
            $ca = Join-Path $testDir "software-certificate-ca-$Algorithm"
            Remove-Item "$ca*" -Force -ErrorAction SilentlyContinue
            ssh-keygen -q -t ed25519 -N '' -f $ca
            $LASTEXITCODE | Should Be 0 | Out-Null
            ssh-keygen -q -s $ca -I "software-$Algorithm" -n $env:USERNAME -z 41 "$key.pub"
            $LASTEXITCODE | Should Be 0 | Out-Null
            $cert = "$key-cert.pub"
            return @{ Key=$key; Cert=$cert; CA=$ca; Blob=(Get-Content $cert).Split(' ')[1] }
        }
        function New-RelatedCertificate($Fixture, $Serial = 42) {
            $public = "$($Fixture.Key)-$Serial.pub"
            Copy-Item -LiteralPath "$($Fixture.Key).pub" -Destination $public
            ssh-keygen -q -s $Fixture.CA -I "certificate-$Serial" -n $env:USERNAME -z $Serial $public | Out-Null
            $LASTEXITCODE | Should Be 0 | Out-Null
            return $public.Replace('.pub','-cert.pub')
        }
        function Open-CertificateRegistryKey($Fixture, [switch]$Software) {
            $root = [Microsoft.Win32.Registry]::Users.OpenSubKey("$currentUserSid\Software\OpenSSH\Agent\Keys",$true)
            try {
                foreach ($name in $root.GetSubKeyNames()) {
                    if ($Software -and $name -match '^cert-') { continue }
                    $key = $root.OpenSubKey($name,[Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,[Security.AccessControl.RegistryRights]::FullControl)
                    if ([Convert]::ToBase64String($key.GetValue('pub')) -eq $Fixture.Blob) { return @{ Root=$root; Key=$key; Name=$name } }
                    $key.Dispose()
                }
                throw 'Certificate Registry identity missing'
            } catch { $root.Dispose(); throw }
        }
        function Get-IdentityValues($Key) {
            return (@($Key.GetValueNames() | Sort-Object | ForEach-Object {
                $kind=$Key.GetValueKind($_)
                $value=$Key.GetValue($_,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                $data=if($value -is [byte[]]){[Convert]::ToBase64String($value)}else{[string]$value}
                "$_/$kind/$data"
            }) -join "`n")
        }
        function Assert-SoftwareCertificate($Fixture, $Comment) {
            $entries = @((ssh-add -L) | Where-Object { ($_ -split ' ')[1] -eq $Fixture.Blob })
            $entries.Count | Should Be 1
            ($entries[0] -split ' ', 3)[2] | Should Be $Comment
            ssh-add -T $Fixture.Cert
            $LASTEXITCODE | Should Be 0
            $identity=Open-CertificateRegistryKey $Fixture
            try {
                $identity.Name | Should Not Match '^cert-'
                $identity.Key.GetValue('provider',$null) | Should Be $null
                [Convert]::ToBase64String($identity.Key.GetValue('')) | Should Not Be $Fixture.Blob
            } finally { $identity.Key.Dispose(); $identity.Root.Dispose() }
        }
    }
    BeforeEach {
        if (-not $skipReason) {
            ssh-add -D | Out-Null
            $LASTEXITCODE | Should Be 0
            $tI++
        }
    }
    AfterEach {
        if (-not $skipReason) {
            ssh-add -D | Out-Null
            Remove-PasswordSetting
        }
    }

    It (Get-Pkcs11CaseName 'PKCS11 software certificate preservation' $softwareSkipReason) -Skip:([bool]$softwareSkipReason) {
        $algorithms = if ($Mode -eq 'SoftHSM') { @('rsa','ecdsa') } else { @('hardware') }
        foreach ($algorithm in $algorithms) {
            ssh-add -D | Out-Null
            $fixture = New-SoftwareCertificateFixture $algorithm
            ssh-add $fixture.Key
            $LASTEXITCODE | Should Be 0
            $comment = (@((ssh-add -L) | Where-Object { ($_ -split ' ')[1] -eq $fixture.Blob })[0] -split ' ',3)[2]
            $identity=Open-CertificateRegistryKey $fixture
            try { $original=Get-IdentityValues $identity.Key } finally { $identity.Key.Dispose(); $identity.Root.Dispose() }
            Add-PasswordSetting -Pass $pkcs11Pin
            $env:SSH_ASKPASS_REQUIRE = 'force'
            # A no-op still validates the affected software Registry entry.
            $identity=Open-CertificateRegistryKey $fixture
            $storedType=$identity.Key.GetValue('type')
            $storedBlob=$identity.Key.GetValue('')
            try {
                $identity.Key.SetValue('type',[long]$storedType,[Microsoft.Win32.RegistryValueKind]::QWord)
                ssh-add -s $config.Provider -C $fixture.Cert
                $LASTEXITCODE | Should Not Be 0
                $identity.Key.SetValue('type',$storedType,[Microsoft.Win32.RegistryValueKind]::DWord)
                $identity.Key.SetValue('',[byte[]]@(1,2,3),[Microsoft.Win32.RegistryValueKind]::Binary)
                ssh-add -s $config.Provider -C $fixture.Cert
                $LASTEXITCODE | Should Not Be 0
            } finally {
                $identity.Key.SetValue('type',$storedType,[Microsoft.Win32.RegistryValueKind]::DWord)
                $identity.Key.SetValue('',$storedBlob,[Microsoft.Win32.RegistryValueKind]::Binary)
                $identity.Key.Dispose(); $identity.Root.Dispose()
            }
            foreach ($repeat in 1..2) {
                ssh-add -s $config.Provider -C $fixture.Cert
                $LASTEXITCODE | Should Be 0
                Assert-SoftwareCertificate $fixture $comment
            }
            Restart-Service ssh-agent
            Assert-SoftwareCertificate $fixture $comment
            $identity=Open-CertificateRegistryKey $fixture
            try { (Get-IdentityValues $identity.Key) | Should Be $original } finally { $identity.Key.Dispose(); $identity.Root.Dispose() }
            # No provider record is needed when every requested cert is software.
            $root = [Microsoft.Win32.Registry]::Users.OpenSubKey("$currentUserSid\Software\OpenSSH\Agent\PKCS11_Providers")
            try { if ($root) { $root.GetSubKeyNames().Count | Should Be 0 } } finally { if ($root) { $root.Dispose() } }
            ssh-add -e $config.Provider
            $LASTEXITCODE | Should Not Be 0
            Assert-SoftwareCertificate $fixture $comment
            # One no-op and one new certificate of the same public key.
            $second=New-RelatedCertificate $fixture
            foreach ($repeat in 1..2) {
                ssh-add -s $config.Provider -C $fixture.Cert $second
                $LASTEXITCODE | Should Be 0
                Assert-SoftwareCertificate $fixture $comment
                $secondBlob=(Get-Content $second).Split(' ')[1]
                @((ssh-add -L) | Where-Object { ($_ -split ' ')[1] -eq $secondBlob }).Count | Should Be 1
                ssh-add -T $second
                $LASTEXITCODE | Should Be 0
            }
            $third=New-RelatedCertificate $fixture 43
            $providers=[Microsoft.Win32.Registry]::Users.OpenSubKey("$currentUserSid\Software\OpenSSH\Agent\PKCS11_Providers",$true)
            $provider=$providers.OpenSubKey($config.Provider.Replace('\','/'),[Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,[Security.AccessControl.RegistryRights]::FullControl)
            $acl=$provider.GetAccessControl()
            $originalAcl=$acl.GetSecurityDescriptorSddlForm('Access')
            $blocked=$provider.GetAccessControl()
            $blocked.AddAccessRule([Security.AccessControl.RegistryAccessRule]::new($systemSid,[Security.AccessControl.RegistryRights]::SetValue,[Security.AccessControl.AccessControlType]::Deny))
            try {
                $before=@(ssh-add -L | Sort-Object)
                $provider.SetAccessControl($blocked)
                ssh-add -s $config.Provider -C $fixture.Cert $third
                $LASTEXITCODE | Should Not Be 0
                @(Compare-Object $before @(ssh-add -L | Sort-Object)).Count | Should Be 0
                Assert-SoftwareCertificate $fixture $comment
            } finally {
                $acl.SetSecurityDescriptorSddlForm($originalAcl)
                $provider.SetAccessControl($acl)
                $provider.Dispose(); $providers.Dispose()
            }
            if ($Mode -eq 'SoftHSM') {
                # A different provider cannot take over an existing token cert.
                $alternate=Join-Path (Split-Path $config.Provider) "alternate-$algorithm.dll"
                Copy-Item -LiteralPath $config.Provider -Destination $alternate
                $tokenFixture=@{Blob=$secondBlob}
                $token=Open-CertificateRegistryKey $tokenFixture
                try { $before=Get-IdentityValues $token.Key } finally { $token.Key.Dispose(); $token.Root.Dispose() }
                ssh-add -s $alternate -C $fixture.Cert $second
                $LASTEXITCODE | Should Be 0
                $token=Open-CertificateRegistryKey $tokenFixture
                try { (Get-IdentityValues $token.Key) | Should Be $before } finally { $token.Key.Dispose(); $token.Root.Dispose() }
                $providers=[Microsoft.Win32.Registry]::Users.OpenSubKey("$currentUserSid\Software\OpenSSH\Agent\PKCS11_Providers")
                try { $providers.GetSubKeyNames().Count | Should Be 1 } finally { $providers.Dispose() }
            }
            Restart-Service ssh-agent
            Assert-SoftwareCertificate $fixture $comment
            ssh-add -e $config.Provider
            $LASTEXITCODE | Should Be 0
            Assert-SoftwareCertificate $fixture $comment
            @((ssh-add -L) | Where-Object { ($_ -split ' ')[1] -eq $secondBlob }).Count | Should Be 0
            ssh-add -d $fixture.Cert
            $LASTEXITCODE | Should Be 0
            @((ssh-add -L) | Where-Object { ($_ -split ' ')[1] -eq $fixture.Blob }).Count | Should Be 0
        }
    }

    It (Get-Pkcs11CaseName 'PKCS11 software certificate detachment' $softwareSkipReason) -Skip:([bool]$softwareSkipReason) {
        $algorithms = if ($Mode -eq 'SoftHSM') { @('rsa','ecdsa') } else { @('hardware') }
        foreach ($algorithm in $algorithms) {
            ssh-add -D | Out-Null
            $fixture = New-SoftwareCertificateFixture $algorithm
            Add-PasswordSetting -Pass $pkcs11Pin
            $env:SSH_ASKPASS_REQUIRE = 'force'
            ssh-add -s $config.Provider -C $fixture.Cert
            $LASTEXITCODE | Should Be 0
            $token=Open-CertificateRegistryKey $fixture
            $tokenValues=@($token.Key.GetValueNames() | ForEach-Object { @{ Name=$_; Kind=$token.Key.GetValueKind($_); Data=$token.Key.GetValue($_) } })
            $acl=$token.Key.GetAccessControl()
            $originalAcl=$acl.GetSecurityDescriptorSddlForm('Access')
            $blocked=$token.Key.GetAccessControl()
            $deny=[Security.AccessControl.RegistryAccessRule]::new($systemSid,[Security.AccessControl.RegistryRights]::Delete,[Security.AccessControl.AccessControlType]::Deny)
            $blocked.AddAccessRule($deny)
            try {
                $before=Get-IdentityValues $token.Key
                $token.Key.SetAccessControl($blocked)
                ssh-add -C $fixture.Key
                $LASTEXITCODE | Should Not Be 0
                (Get-IdentityValues $token.Key) | Should Be $before
                @((ssh-add -L) | Where-Object { ($_ -split ' ')[1] -eq $fixture.Blob }).Count | Should Be 1
                $token.Name | Should Match '^cert-'
            } finally {
                $acl.SetSecurityDescriptorSddlForm($originalAcl)
                $token.Key.SetAccessControl($acl)
                # SetSecurityInfo may add the auto-inherited control flag.
                ($token.Key.GetAccessControl().GetSecurityDescriptorSddlForm('Access') -replace '^D:PAI\(', 'D:P(') | Should Be $originalAcl
                $token.Key.Dispose()
            }
            # Keep a second certificate while transferring the first.
            $second=New-RelatedCertificate $fixture
            ssh-add -s $config.Provider -C $second
            $LASTEXITCODE | Should Be 0
            ssh-add $fixture.Key
            $LASTEXITCODE | Should Be 0
            $comment = (@((ssh-add -L) | Where-Object { ($_ -split ' ')[1] -eq $fixture.Blob })[0] -split ' ',3)[2]
            Assert-SoftwareCertificate $fixture $comment
            # Recreate an old duplicate and prove software re-add repairs it.
            $duplicate=$token.Root.CreateSubKey($token.Name)
            try {
                $duplicate.SetAccessControl($acl)
                foreach ($value in $tokenValues) { $duplicate.SetValue($value.Name,$value.Data,$value.Kind) }
            } finally { $duplicate.Dispose(); $token.Root.Dispose() }
            $software=Open-CertificateRegistryKey $fixture -Software
            $softwareAcl=$software.Key.GetAccessControl()
            $originalSoftwareAcl=$softwareAcl.GetSecurityDescriptorSddlForm('Access')
            $blocked=$software.Key.GetAccessControl()
            $blocked.AddAccessRule([Security.AccessControl.RegistryAccessRule]::new($systemSid,[Security.AccessControl.RegistryRights]::SetValue,[Security.AccessControl.AccessControlType]::Deny))
            try {
                $before=Get-IdentityValues $software.Key
                $software.Key.SetAccessControl($blocked)
                ssh-add -C $fixture.Key
                $LASTEXITCODE | Should Not Be 0
                (Get-IdentityValues $software.Key) | Should Be $before
            } finally {
                $softwareAcl.SetSecurityDescriptorSddlForm($originalSoftwareAcl)
                $software.Key.SetAccessControl($softwareAcl)
                $software.Key.Dispose(); $software.Root.Dispose()
            }
            ssh-add $fixture.Key
            $LASTEXITCODE | Should Be 0
            Assert-SoftwareCertificate $fixture $comment
            Restart-Service ssh-agent
            Assert-SoftwareCertificate $fixture $comment
            ssh-add -e $config.Provider
            $LASTEXITCODE | Should Be 0
            Assert-SoftwareCertificate $fixture $comment
            Restart-Service ssh-agent
            Assert-SoftwareCertificate $fixture $comment
            ssh-add -d $fixture.Cert
            $LASTEXITCODE | Should Be 0
            @((ssh-add -L) | Where-Object { ($_ -split ' ')[1] -eq $fixture.Blob }).Count | Should Be 0
        }
    }

    foreach ($algorithm in @('RSA', 'ECDSA')) {
        It (Get-Pkcs11CaseName "PKCS11 $algorithm add/list/sign" $skipReason) -Skip:([bool]$skipReason) -TestCases @(@{ Algorithm = $algorithm }) {
            param($Algorithm)
            $keys = $config.PublicKeys
            $key = @($keys | Where-Object {
                (Get-Content -LiteralPath $_) -match $(if ($Algorithm -eq 'RSA') { '^ssh-rsa ' } else { '^ecdsa-sha2-nistp256 ' })
            })
            $key.Count | Should Be 1
            Add-PasswordSetting -Pass $pkcs11Pin
            $env:SSH_ASKPASS_REQUIRE = 'force'
            ssh-add -s $config.Provider
            $LASTEXITCODE | Should Be 0
            $blob = (Get-Content -LiteralPath $key[0]).Split(' ')[1]
            @((ssh-add -L) | Where-Object { $_.Contains($blob) }).Count | Should Be 1
            ssh-add -T $key[0]
            $LASTEXITCODE | Should Be 0
            ssh-add -e $config.Provider
            $LASTEXITCODE | Should Be 0
        }
    }
    It (Get-Pkcs11CaseName 'PKCS11 associated certificate lifecycle' $skipReason) -Skip:([bool]$skipReason) {
            $pkcs11Path = $env:OPENSSH_TEST_PKCS11_PROVIDER
            $publicKeyPaths = @($env:OPENSSH_TEST_PKCS11_PUBLIC_KEYS -split ';' |
                Where-Object { $_ })


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

            # Provider paths and Registry key names are case-insensitive on
            # Windows. Re-adding only one certificate with alternate casing
            # must not orphan the identities that retain the original path.
            $caseVariantProvider = ([IO.Path]::GetFullPath(
                $pkcs11Path)).ToUpperInvariant()
            & ssh-add -s $caseVariantProvider -C $certPaths[0]
            $LASTEXITCODE | Should Be 0
            Restart-Service ssh-agent
            WaitForStatus -ServiceName ssh-agent -Status "Running"
            foreach ($keyPath in $copiedPublicKeyPaths + $certPaths) {
                & ssh-add -T $keyPath
                $LASTEXITCODE | Should Be 0
            }
            & ssh-add -e $caseVariantProvider
            $LASTEXITCODE | Should Be 0
            @(ssh-add -L) -match "The agent has no identities." | Should Be $true

            # Restore the complete set for the remaining deletion scenarios.
            & ssh-add @addArguments
            $LASTEXITCODE | Should Be 0
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

    It (Get-Pkcs11CaseName 'PKCS11 software identity preservation' $softwareSkipReason) -Skip:([bool]$softwareSkipReason) {
            $pkcs11Path = $env:OPENSSH_TEST_PKCS11_PROVIDER
            $publicKeyPaths = @($env:OPENSSH_TEST_PKCS11_PUBLIC_KEYS -split ';' |
                Where-Object { $_ })
            $softwareKeySource = $env:OPENSSH_TEST_PKCS11_SOFTWARE_KEY


            $testPin = $env:OPENSSH_TEST_PKCS11_PIN

            $softwareKeyPath = Join-Path $testDir "pkcs11-software"
            $nullFile = Join-Path $testDir "$tC.$tI.nullfile"
            $null > $nullFile
            Copy-Item $softwareKeySource $softwareKeyPath -Force
            Copy-Item $publicKeyPaths[0] "$softwareKeyPath.pub" -Force
            Repair-UserKeyPermission $softwareKeyPath -confirm:$false
            $softwareBlob = ((ssh-keygen -y -f $softwareKeyPath) -split ' ')[1]
            $softwareBlob | Should Be ((Get-Content $publicKeyPaths[0]).Split(' ')[1])

            ssh-add -D
            $LASTEXITCODE | Should Be 0
            ssh-add $softwareKeyPath
            @((ssh-add -L) | Where-Object { $_.Contains($softwareBlob) }).Count |
                Should Be 1

            # The token key has the same public key as the software identity,
            # so it must not silently take over the software identity.
            Add-PasswordSetting -Pass $testPin
            $env:SSH_ASKPASS_REQUIRE = "force"
            & ssh-add -s $pkcs11Path
            $LASTEXITCODE | Should Not Be 0
            Remove-PasswordSetting
            @((ssh-add -L) | Where-Object { $_.Contains($softwareBlob) }).Count |
                Should Be 1
            & ssh-add -T "$softwareKeyPath.pub"
            $LASTEXITCODE | Should Be 0

            # After removing the software identity the provider can be added.
            & ssh-add -d $softwareKeyPath
            $LASTEXITCODE | Should Be 0
            Add-PasswordSetting -Pass $testPin
            $env:SSH_ASKPASS_REQUIRE = "force"
            & ssh-add -s $pkcs11Path
            $LASTEXITCODE | Should Be 0
            @((ssh-add -L) | Where-Object { $_.Contains($softwareBlob) }).Count |
                Should Be 1
            & ssh-add -e $pkcs11Path
            $LASTEXITCODE | Should Be 0
            @(ssh-add -L) -match "The agent has no identities." | Should Be $true
        }

    It (Get-Pkcs11CaseName 'PKCS11 software identity detachment' $softwareSkipReason) -Skip:([bool]$softwareSkipReason) {
            $pkcs11Path = $env:OPENSSH_TEST_PKCS11_PROVIDER
            $publicKeyPaths = @($env:OPENSSH_TEST_PKCS11_PUBLIC_KEYS -split ';' |
                Where-Object { $_ })
            $softwareKeySource = $env:OPENSSH_TEST_PKCS11_SOFTWARE_KEY


            $testPin = $env:OPENSSH_TEST_PKCS11_PIN

            $softwareKeyPath = Join-Path $testDir "pkcs11-software"
            $nullFile = Join-Path $testDir "$tC.$tI.nullfile"
            $null > $nullFile
            Copy-Item $softwareKeySource $softwareKeyPath -Force
            Copy-Item $publicKeyPaths[0] "$softwareKeyPath.pub" -Force
            Repair-UserKeyPermission $softwareKeyPath -confirm:$false
            $softwareBlob = ((ssh-keygen -y -f $softwareKeyPath) -split ' ')[1]
            $softwareBlob | Should Be ((Get-Content $publicKeyPaths[0]).Split(' ')[1])

            ssh-add -D
            $LASTEXITCODE | Should Be 0
            Add-PasswordSetting -Pass $testPin
            $env:SSH_ASKPASS_REQUIRE = "force"
            & ssh-add -s $pkcs11Path
            $LASTEXITCODE | Should Be 0
            Remove-PasswordSetting

            # Adding the same key as software key makes it a software identity.
            # Removing the provider must no longer delete it.
            ssh-add $softwareKeyPath
            & ssh-add -e $pkcs11Path
            $LASTEXITCODE | Should Be 0
            @((ssh-add -L) | Where-Object { $_.Contains($softwareBlob) }).Count |
                Should Be 1
            & ssh-add -T "$softwareKeyPath.pub"
            $LASTEXITCODE | Should Be 0

            ssh-add -D
            $LASTEXITCODE | Should Be 0
        }

    It (Get-Pkcs11CaseName 'PKCS11 stale provider isolation' $skipReason) -Skip:([bool]$skipReason) {
            $pkcs11Path = $env:OPENSSH_TEST_PKCS11_PROVIDER
            $publicKeyPaths = @($env:OPENSSH_TEST_PKCS11_PUBLIC_KEYS -split ';' |
                Where-Object { $_ })


            $testPin = $env:OPENSSH_TEST_PKCS11_PIN

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
                ssh-add $softwareKeyPath
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

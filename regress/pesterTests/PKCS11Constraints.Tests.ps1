# PKCS#11 constraint rejection must not require a provider DLL or token.
Describe "Windows agent PKCS11 constraint rejection" -Tags "CI" {
    BeforeAll {
        function New-AgentUInt32 {
            param([int]$Value)
            return ,([BitConverter]::GetBytes(
                [Net.IPAddress]::HostToNetworkOrder($Value)))
        }

        function New-AgentString {
            param([byte[]]$Value)
            return ,([byte[]]((New-AgentUInt32 $Value.Length) + $Value))
        }

        function Read-AgentBytes {
            param([IO.Pipes.NamedPipeClientStream]$Pipe, [int]$Count)
            $buffer = New-Object byte[] $Count
            $offset = 0
            while ($offset -lt $Count) {
                $read = $Pipe.BeginRead($buffer, $offset, $Count - $offset,
                    $null, $null)
                try {
                    if (-not $read.AsyncWaitHandle.WaitOne(5000)) {
                        $Pipe.Dispose()
                        throw "Timed out reading from ssh-agent"
                    }
                    $received = $Pipe.EndRead($read)
                }
                finally {
                    $read.AsyncWaitHandle.Close()
                }
                if ($received -eq 0) {
                    throw "ssh-agent closed the connection without a reply"
                }
                $offset += $received
            }
            return ,$buffer
        }

        function Send-AgentRequest {
            param([IO.Pipes.NamedPipeClientStream]$Pipe, [byte[]]$Payload)
            $frame = [byte[]]((New-AgentUInt32 $Payload.Length) + $Payload)
            $write = $Pipe.BeginWrite($frame, 0, $frame.Length, $null, $null)
            try {
                if (-not $write.AsyncWaitHandle.WaitOne(5000)) {
                    $Pipe.Dispose()
                    throw "Timed out writing to ssh-agent"
                }
                $Pipe.EndWrite($write)
            }
            finally {
                $write.AsyncWaitHandle.Close()
            }
            $header = Read-AgentBytes $Pipe 4
            $length = [Net.IPAddress]::NetworkToHostOrder(
                [BitConverter]::ToInt32($header, 0))
            if ($length -lt 1 -or $length -gt 262144) {
                throw "Invalid ssh-agent reply length: $length"
            }
            return ,(Read-AgentBytes $Pipe $length)
        }

        function Get-AgentRegistryNames {
            # Capture names only: never print stored key or PIN values.
            $names = @()
            foreach ($rootName in @('Keys', 'PKCS11_Providers')) {
                $root = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey(
                    "Software\OpenSSH\Agent\$rootName")
                try {
                    if ($null -ne $root) {
                        $names += "$rootName/"
                        $names += @($root.GetSubKeyNames() | ForEach-Object {
                            "$rootName/$_"
                        })
                    }
                }
                finally {
                    if ($null -ne $root) { $root.Dispose() }
                }
            }
            return (($names | Sort-Object) -join "`n")
        }
    }

    It "rejects constraints without changing identities and keeps the connection usable" {
        # Protocol constants from authfd.h: request=26, identities=11/12,
        # failure=5, lifetime=1, confirm=2, extension=255.
        $extensionName = New-AgentString ([Text.Encoding]::UTF8.GetBytes(
            'restrict-destination-v00@openssh.com'))
        $constraints = @(
            @{ Name = 'lifetime'; Blob = [byte[]](@(1) + (New-AgentUInt32 60)) },
            @{ Name = 'confirm'; Blob = [byte[]]@(2) },
            @{ Name = 'destinations'; Blob = [byte[]](@(255) + $extensionName +
                (New-AgentString ([byte[]]@()))) }
        )
        $cases = @($constraints)
        foreach ($keyType in @('rsa', 'ecdsa')) {
            $certFile = Join-Path $PSScriptRoot "..\unittests\sshkey\testdata\$($keyType)_1-cert.pub"
            $cert = [Convert]::FromBase64String((Get-Content $certFile).Split(' ')[1])
            $certList = New-AgentString (New-AgentString $cert)
            $associatedName = New-AgentString ([Text.Encoding]::UTF8.GetBytes(
                'associated-certs-v00@openssh.com'))
            foreach ($certOnly in @(0, 1)) {
                $associated = [byte[]](@(255) + $associatedName + @($certOnly) + $certList)
                foreach ($constraint in $constraints) {
                    $cases += @(
                        @{ Name = "$keyType/$certOnly/$($constraint.Name)/before";
                            Blob = [byte[]]($constraint.Blob + $associated) },
                        @{ Name = "$keyType/$certOnly/$($constraint.Name)/after";
                            Blob = [byte[]]($associated + $constraint.Blob) }
                    )
                }
            }
        }
        $provider = Join-Path $env:TEMP ("openssh-unsupported-" +
            [guid]::NewGuid().ToString() + '.dll')
        $add = [byte[]](@(26) + (New-AgentString (
            [Text.Encoding]::UTF8.GetBytes($provider))) +
            (New-AgentString ([byte[]]@())))
        $pipe = New-Object IO.Pipes.NamedPipeClientStream('.',
            'openssh-ssh-agent', [IO.Pipes.PipeDirection]::InOut,
            [IO.Pipes.PipeOptions]::Asynchronous,
            [Security.Principal.TokenImpersonationLevel]::Impersonation)
        try {
            # Missing test agents fail this CI test instead of skipping it.
            $pipe.Connect(5000)
            $identities = Send-AgentRequest $pipe ([byte[]]@(11))
            $identities[0] | Should Be 12
            $identitiesBefore = [Convert]::ToBase64String($identities)
            $registryBefore = Get-AgentRegistryNames
            foreach ($case in $cases) {
                try {
                    $reply = Send-AgentRequest $pipe ([byte[]]($add + $case.Blob))
                    $reply.Length | Should Be 1
                    $reply[0] | Should Be 5
                    $identitiesAfter = Send-AgentRequest $pipe ([byte[]]@(11))
                    [Convert]::ToBase64String($identitiesAfter) | Should Be $identitiesBefore
                    Get-AgentRegistryNames | Should Be $registryBefore
                }
                catch {
                    throw "PKCS11 constraint $($case.Name): $($_.Exception.Message)"
                }
            }
        }
        finally {
            $pipe.Dispose()
        }
    }
}

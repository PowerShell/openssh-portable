# Regression test for ssh-agent clients whose process does not grant the agent any access to it.
# The agent runs as LocalSystem without SeDebugPrivilege. It used to open the client process by its pid
# to read the client's token. That fails with ERROR_ACCESS_DENIED when the access control list of the
# client process has no entry for LocalSystem, and the agent then closed the connection. The agent now
# identifies such a client through the pipe once the first request was read.
Describe "ssh-agent identifies clients that deny access to their process" -Tags "CI" {
    BeforeAll {
        $fixtureDirectory = $null
        $fixtureKey = $null
        $fixtureAdded = $false
        $startedAgentService = $false
        $oldAuthSock = $env:SSH_AUTH_SOCK
        $agentPipe = "\\.\pipe\openssh-ssh-agent"
        function Test-AgentPipe {
            try { return [System.IO.Directory]::GetFiles("\\.\pipe\") -contains $agentPipe } catch { return $false }
        }

        # make sure an agent is listening; remember if the service had to be started
        $agentService = Get-Service ssh-agent -ErrorAction SilentlyContinue
        if ($agentService -and $agentService.Status -ne "Running") {
            Start-Service ssh-agent -ErrorAction Stop
            $startedAgentService = $true
        }
        for ($i = 0; $i -lt 20 -and -not (Test-AgentPipe); $i++) {
            Start-Sleep -Milliseconds 500
        }
        if (-not (Test-AgentPipe)) {
            throw "The CI test requires a listening ssh-agent on $agentPipe"
        }
        $env:SSH_AUTH_SOCK = $agentPipe
        $sshKeygen = (Get-Command ssh-keygen.exe -ErrorAction Stop).Source
        $sshAdd = (Get-Command ssh-add.exe -ErrorAction Stop).Source

        # A unique fixture belongs to this user; never clear unrelated agent identities.
        $fixtureDirectory = Join-Path ([IO.Path]::GetTempPath()) ("agent-client-" + [Guid]::NewGuid().ToString("N"))
        $fixtureKey = Join-Path $fixtureDirectory "identity"
        $null = New-Item -ItemType Directory -Path $fixtureDirectory -ErrorAction Stop
        # Start-Process preserves the empty passphrase argument in both Windows PowerShell and pwsh.
        $keygenProcess = Start-Process -FilePath $sshKeygen -ArgumentList @(
            '-q', '-t', 'ed25519', '-P', '""', '-f', ('"' + $fixtureKey + '"')
        ) -WindowStyle Hidden -Wait -PassThru -ErrorAction Stop
        try {
            if ($keygenProcess.ExitCode -ne 0) { throw "Could not generate the agent client test key" }
        } finally {
            $keygenProcess.Dispose()
        }
        $expectedBlob = ((Get-Content "$fixtureKey.pub" -ErrorAction Stop) -split '\s+')[1]
        # Mark the attempted add for cleanup even if ssh-add reports an error afterwards.
        $fixtureAdded = $true
        & $sshAdd $fixtureKey
        if ($LASTEXITCODE -ne 0) { throw "Could not load the agent client test key" }

        # C# helper that replaces the access control list of the process it runs in
        $processAclType = @'
using System;
using System.Runtime.InteropServices;

public static class AgentTestProcessAcl
{
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string sddl, uint revision, out IntPtr descriptor, IntPtr size);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetSecurityDescriptorDacl(IntPtr descriptor, out bool present, out IntPtr dacl, out bool defaulted);

    [DllImport("advapi32.dll")]
    private static extern uint SetSecurityInfo(IntPtr handle, int objectType, uint information, IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);

    public static void Set(string sddl)
    {
        IntPtr descriptor = IntPtr.Zero, dacl;
        bool present, defaulted;
        try
        {
            if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, out descriptor, IntPtr.Zero) ||
                !GetSecurityDescriptorDacl(descriptor, out present, out dacl, out defaulted))
                throw new System.ComponentModel.Win32Exception();
            // SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION
            uint result = SetSecurityInfo(GetCurrentProcess(), 6, 4, IntPtr.Zero, IntPtr.Zero, dacl, IntPtr.Zero);
            if (result != 0)
                throw new System.ComponentModel.Win32Exception((int)result);
        }
        finally
        {
            if (descriptor != IntPtr.Zero)
                LocalFree(descriptor);
        }
    }
}
'@

        # Share the response parser with the child and the malformed-response checks below.
        $responseScript = @'
function Read-Exactly($stream, [int]$count) {
    $buffer = New-Object byte[] $count
    $offset = 0
    while ($offset -lt $count) {
        $task = $stream.ReadAsync($buffer, $offset, $count - $offset)
        if (-not $task.Wait(15000)) { throw "timeout waiting for the agent" }
        if ($task.Result -le 0) { throw "the agent closed the connection" }
        $offset += $task.Result
    }
    return ,$buffer
}
function Read-AgentUInt32($stream) {
    $bytes = Read-Exactly $stream 4
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($bytes) }
    return [BitConverter]::ToUInt32($bytes, 0)
}
function Read-AgentString($stream) {
    $length = Read-AgentUInt32 $stream
    if ($length -gt ($stream.Length - $stream.Position)) { throw "truncated agent string" }
    return ,(Read-Exactly $stream ([int]$length))
}
function Read-AgentIdentities($stream, [string]$expectedBlob) {
    $length = Read-AgentUInt32 $stream
    # MAX_MESSAGE_SIZE in the Windows agent is 256 KiB.
    if ($length -lt 5 -or $length -gt 256 * 1024) { throw "invalid agent response length" }
    $payload = Read-Exactly $stream ([int]$length)
    $response = New-Object IO.MemoryStream(,$payload)
    try {
        if ($response.ReadByte() -ne 12) { throw "expected SSH2_AGENT_IDENTITIES_ANSWER" }
        $count = Read-AgentUInt32 $response
        if ($count -gt ($response.Length - $response.Position) / 8) { throw "invalid identity count" }
        $found = $false
        for ($i = 0; $i -lt $count; $i++) {
            $blob = Read-AgentString $response
            $null = Read-AgentString $response # comment
            if ([Convert]::ToBase64String($blob) -ceq $expectedBlob) { $found = $true }
        }
        if ($response.Position -ne $response.Length) { throw "trailing agent response data" }
        if (-not $found) { throw "the agent did not return the expected user's key" }
        "EXPECTED-KEY:" + $expectedBlob
    } finally {
        $response.Dispose()
    }
}
'@
        . ([ScriptBlock]::Create($responseScript))

        # Only the child process is restricted. Explicitly allow the fallback's required SQOS level.
        $clientScript = @'
$ErrorActionPreference = 'Stop'
if ($restrictProcess) {
    [AgentTestProcessAcl]::Set("D:(D;;GA;;;WD)")
}
$pipe = New-Object System.IO.Pipes.NamedPipeClientStream(".", "openssh-ssh-agent",
    [System.IO.Pipes.PipeDirection]::InOut, [System.IO.Pipes.PipeOptions]::Asynchronous,
    [System.Security.Principal.TokenImpersonationLevel]::Impersonation)
try {
    $pipe.Connect(15000)
    $request = [byte[]](0, 0, 0, 1, 11)
    $pipe.Write($request, 0, $request.Length)
    $pipe.Flush()
    Read-AgentIdentities $pipe $expectedBlob
} catch {
    "FAILED:" + $_.Exception.Message
} finally {
    $pipe.Dispose()
}
'@

        function Invoke-AgentClient {
            param([bool]$RestrictProcess)
            $script = "`$restrictProcess = `$$RestrictProcess`r`n" +
                "`$expectedBlob = '$expectedBlob'`r`n" +
                "Add-Type -TypeDefinition @'`r`n$processAclType`r`n'@`r`n" + $responseScript + "`r`n" + $clientScript
            $encoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($script))
            (& powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand $encoded 2>&1 | Out-String).Trim()
        }
    }

    AfterAll {
        try {
            if ($fixtureAdded) {
                & $sshAdd -d "$fixtureKey.pub"
                if ($LASTEXITCODE -ne 0) { throw "Could not remove the agent client test key" }
            }
        } finally {
            try {
                if ($fixtureDirectory) {
                    foreach ($path in @($fixtureKey, "$fixtureKey.pub")) {
                        if ($path -and (Test-Path -LiteralPath $path)) {
                            Remove-Item -LiteralPath $path -Force -ErrorAction Stop
                        }
                    }
                    if (Test-Path -LiteralPath $fixtureDirectory) {
                        Remove-Item -LiteralPath $fixtureDirectory -ErrorAction Stop
                    }
                }
            } finally {
                $env:SSH_AUTH_SOCK = $oldAuthSock
                if ($startedAgentService) {
                    Stop-Service ssh-agent -Force -ErrorAction Stop
                }
            }
        }
    }

    It "returns this user's key when the client process denies access" {
        Invoke-AgentClient -RestrictProcess $true | Should Match ([regex]::Escape("EXPECTED-KEY:$expectedBlob"))
    }

    It "still returns this user's key with the default process access" {
        Invoke-AgentClient -RestrictProcess $false | Should Match ([regex]::Escape("EXPECTED-KEY:$expectedBlob"))
    }

    It "rejects empty, foreign, truncated and malformed identities responses" {
        $invalidResponses = @(
            @{ Bytes = [byte[]](0,0,0,5,12,0,0,0,0); Error = "the agent did not return the expected user's key" },
            @{ Bytes = [byte[]](0,0,0,16,12,0,0,0,1,0,0,0,3,1,2,3,0,0,0,0); Error = "the agent did not return the expected user's key" },
            @{ Bytes = [byte[]](0,0,0,5,12,0); Error = "the agent closed the connection" },
            @{ Bytes = [byte[]](0,0,0,13,12,0,0,0,1,0,0,0,5,1,2,3,4); Error = "truncated agent string" },
            @{ Bytes = [byte[]](0,0,0,6,12,0,0,0,0,0); Error = "trailing agent response data" },
            @{ Bytes = [byte[]](0,0,0,5,12,255,255,255,255); Error = "invalid identity count" },
            @{ Bytes = [byte[]](0,0,0,5,5,0,0,0,0); Error = "expected SSH2_AGENT_IDENTITIES_ANSWER" },
            @{ Bytes = [byte[]](0,4,0,1); Error = "invalid agent response length" }
        )
        foreach ($response in $invalidResponses) {
            $stream = New-Object IO.MemoryStream(,$response.Bytes)
            try {
                { Read-AgentIdentities $stream $expectedBlob } | Should Throw $response.Error
            } finally {
                $stream.Dispose()
            }
        }
    }
}

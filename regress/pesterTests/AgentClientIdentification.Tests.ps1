# Regression test for ssh-agent clients whose process does not grant the agent any access to it.
# The agent runs as LocalSystem without SeDebugPrivilege. It used to open the client process by its pid
# to read the client's token. That fails with ERROR_ACCESS_DENIED when the access control list of the
# client process has no entry for LocalSystem, and the agent then closed the connection. The agent now
# identifies such a client through the pipe once the first request was read.
Describe "ssh-agent identifies clients that deny access to their process" -Tags "CI" {
    BeforeAll {
        $agentPipe = "\\.\pipe\openssh-ssh-agent"
        function Test-AgentPipe {
            try { return [System.IO.Directory]::GetFiles("\\.\pipe\") -contains $agentPipe } catch { return $false }
        }

        # make sure an agent is listening; remember if the service had to be started
        $startedAgentService = $false
        $agentService = Get-Service ssh-agent -ErrorAction SilentlyContinue
        if ($agentService -and $agentService.Status -ne "Running") {
            Start-Service ssh-agent
            $startedAgentService = $true
        }
        for ($i = 0; $i -lt 20 -and -not (Test-AgentPipe); $i++) {
            Start-Sleep -Milliseconds 500
        }
        $skip = -not (Test-AgentPipe)

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

    public static void Set(string sddl)
    {
        IntPtr descriptor, dacl;
        bool present, defaulted;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, out descriptor, IntPtr.Zero) ||
            !GetSecurityDescriptorDacl(descriptor, out present, out dacl, out defaulted))
            throw new System.ComponentModel.Win32Exception();
        // SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION
        uint result = SetSecurityInfo(GetCurrentProcess(), 6, 4, IntPtr.Zero, IntPtr.Zero, dacl, IntPtr.Zero);
        if (result != 0)
            throw new System.ComponentModel.Win32Exception((int)result);
    }
}
'@

        # The client runs in its own powershell.exe: only its own process is restricted, not the test host.
        # It sends SSH2_AGENTC_REQUEST_IDENTITIES, which only reads, and reports the type of the answer.
        $clientScript = @'
$ErrorActionPreference = 'Stop'
if ($restrictProcess) {
    # deny every access to everybody, whatever account the agent runs as (the process itself keeps its handle)
    [AgentTestProcessAcl]::Set("D:(D;;GA;;;WD)")
}
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
$pipe = New-Object System.IO.Pipes.NamedPipeClientStream(".", "openssh-ssh-agent", [System.IO.Pipes.PipeDirection]::InOut)
try {
    $pipe.Connect(15000)
    $request = [byte[]](0, 0, 0, 1, 11)
    $pipe.Write($request, 0, $request.Length)
    $pipe.Flush()
    $header = Read-Exactly $pipe 4
    $type = Read-Exactly $pipe 1
    "ANSWER-TYPE:" + $type[0]
} catch {
    "FAILED:" + $_.Exception.Message
} finally {
    $pipe.Dispose()
}
'@

        function Invoke-AgentClient {
            param([bool]$RestrictProcess)
            $script = "`$restrictProcess = `$$RestrictProcess`r`n" +
                "Add-Type -TypeDefinition @'`r`n$processAclType`r`n'@`r`n" + $clientScript
            $encoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($script))
            (& powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand $encoded 2>&1 | Out-String).Trim()
        }
    }

    AfterAll {
        if ($startedAgentService) {
            Stop-Service ssh-agent -Force
        }
    }

    # SSH2_AGENT_IDENTITIES_ANSWER is message type 12
    It "answers a client whose process has no access entry for LocalSystem" -skip:$skip {
        Invoke-AgentClient -RestrictProcess $true | Should Match "ANSWER-TYPE:12"
    }

    It "still answers a client with the default process access" -skip:$skip {
        Invoke-AgentClient -RestrictProcess $false | Should Match "ANSWER-TYPE:12"
    }
}

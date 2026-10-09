If ($PSVersiontable.PSVersion.Major -le 2) {$PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path}
Import-Module $PSScriptRoot\CommonUtils.psm1 -Force

# This covers the Windows equivalent of regress/rekey.sh, which the bash test
# harness skips on Windows (contrib/win32/openssh/bash_tests_iterator.ps1).
$tI = 0
$suite = "rekey"

Describe "E2E scenarios for rekeying" -Tags "CI" {
    BeforeAll {
        if($OpenSSHTestInfo -eq $null)
        {
            Throw "`$OpenSSHTestInfo is null. Please run Set-OpenSSHTestEnvironment to set test environments."
        }

        $testDir = Join-Path $OpenSSHTestInfo["TestDataPath"] $suite
        $null = New-Item $testDir -ItemType directory -Force -ErrorAction SilentlyContinue

        # Count of 'NEWKEYS sent' lines in a verbose client log. The first one is
        # the initial key exchange; any beyond that are rekeys.
        function Get-RekeyCount {
            param([string]$logPath)
            if (-not (Test-Path $logPath)) { return 0 }
            $sent = @(Select-String -Path $logPath -Pattern 'NEWKEYS sent' -ErrorAction SilentlyContinue)
            return ([Math]::Max(0, $sent.Count - 1))
        }
    }

    AfterAll {
        if($OpenSSHTestInfo -ne $null -and -not $OpenSSHTestInfo['DebugMode'])
        {
            if(-not [string]::IsNullOrEmpty($testDir))
            {
                Get-Item $testDir | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }

    AfterEach { $tI++ }

    Context "Data volume based rekeying" {

        It "$tI - scp transfer forces multiple rekeys and preserves data integrity" {
            $srcFile = Join-Path $testDir "rekey_src.bin"
            $dstFile = Join-Path $testDir "rekey_dst.bin"
            $logFile = Join-Path $testDir "rekey_scp.log"
            Remove-Item $srcFile, $dstFile, $logFile -Force -ErrorAction SilentlyContinue

            # 4 MB with a 256k rekey limit guarantees several rekeys during the transfer.
            $null = fsutil file createNew $srcFile 4194304

            # -oRekeyLimit uses no embedded space in the data-volume form, so it is
            # safe to pass through cmd /c without extra quoting.
            cmd /c "scp -vv -oRekeyLimit=256k `"$srcFile`" test_target:`"$dstFile`" 2> `"$logFile`""
            $LASTEXITCODE | Should Be 0

            # Connection survived the rekeys and bytes are intact.
            (Test-Path $dstFile) | Should Be $true
            (Get-Item $dstFile).Length | Should Be (Get-Item $srcFile).Length

            # At least one rekey actually occurred.
            $rekeys = Get-RekeyCount $logFile
            ($rekeys -ge 1) | Should Be $true
        }
    }

    Context "Time based rekeying" {

        It "$tI - idle session rekeys on a time interval" {
            $logFile = Join-Path $testDir "rekey_time.log"
            Remove-Item $logFile -Force -ErrorAction SilentlyContinue

            # RekeyLimit "default 2" rekeys every 2 seconds regardless of traffic.
            # Sleeping ~8 seconds on the remote end yields several time-based rekeys.
            cmd /c "ssh -vv -oRekeyLimit=`"default 2`" test_target `"powershell -NoProfile -Command Start-Sleep -Seconds 8`" 2> `"$logFile`""
            $LASTEXITCODE | Should Be 0

            $rekeys = Get-RekeyCount $logFile
            ($rekeys -ge 1) | Should Be $true
        }
    }
}

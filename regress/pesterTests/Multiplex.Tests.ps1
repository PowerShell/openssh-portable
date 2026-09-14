If ($PSVersiontable.PSVersion.Major -le 2) {$PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path}
Import-Module $PSScriptRoot\CommonUtils.psm1 -Force
$tC = 1
$tI = 0
$suite = "multiplex"

Describe "E2E scenarios for connection multiplexing (ControlMaster)" -Tags "CI" {
    BeforeAll {
        if($OpenSSHTestInfo -eq $null)
        {
            Throw "`$OpenSSHTestInfo is null. Please run Set-OpenSSHTestEnvironment to set test environments."
        }

        $port = $OpenSSHTestInfo["Port"]

        $testDir = Join-Path $OpenSSHTestInfo["TestDataPath"] $suite
        if(-not (Test-Path $testDir))
        {
            $null = New-Item $testDir -ItemType directory -Force -ErrorAction SilentlyContinue
        }
        # Non-interactive commands require Enter before returning on PS 2.
        $skip = $IsWindows -and ($PSVersionTable.PSVersion.Major -le 2)

        $controlPath = Join-Path $testDir "mux_ctl"
        $sshExe = (Get-Command ssh).Source
        $script:masterProc = $null

        function Wait-MuxClient
        {
            param($Process, [int]$Timeout = 30000)
            if (-not $Process.WaitForExit($Timeout)) {
                Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
                throw "Mux client $($Process.Id) timed out"
            }
            $Process.ExitCode | Should Be 0
        }

        function Assert-MuxSession
        {
            param([string]$Log)
            $Log | Should Contain "master session id"
            $Log | Should Not Contain "opening a separate connection"
        }

        function Start-MuxMaster
        {
            param([string]$MasterLog)

            $script:masterProc = Start-Process -FilePath $sshExe `
                -ArgumentList "-M", "-N", "-S", "`"$controlPath`"", "test_target" `
                -WindowStyle Hidden -RedirectStandardError $MasterLog -PassThru

            # wait until the master answers control requests
            $deadline = (Get-Date).AddSeconds(30)
            while ((Get-Date) -lt $deadline)
            {
                ssh -S $controlPath -O check test_target 2>$null
                if ($LASTEXITCODE -eq 0) { return $true }
                if ($script:masterProc.HasExited) { return $false }
                Start-Sleep -Milliseconds 500
            }
            return $false
        }

        function Stop-MuxMaster
        {
            if ($script:masterProc -eq $null) { return }
            ssh -S $controlPath -O exit test_target 2>$null
            if (-not $script:masterProc.WaitForExit(10000))
            {
                Stop-Process -Id $script:masterProc.Id -Force -ErrorAction SilentlyContinue
            }
            $script:masterProc = $null
        }
    }

    AfterAll {
        Stop-MuxMaster
    }

    BeforeEach {
        $stderrFile=Join-Path $testDir "$tC.$tI.stderr.txt"
        $stdoutFile=Join-Path $testDir "$tC.$tI.stdout.txt"
        $logFile = Join-Path $testDir "$tC.$tI.log.txt"
    }
    AfterEach {$tI++;}

    Context "$tC - mux master lifecycle and sessions" {
        BeforeAll {$tI=1}
        AfterAll{$tC++}

        It "$tC.$tI - master starts and answers -O check" -skip:$skip {
            Start-MuxMaster -MasterLog $logFile | Should Be $true
            iex "cmd /c `"ssh -S $controlPath -O check test_target 2> $stderrFile`""
            $LASTEXITCODE | Should Be 0
            $stderrFile | Should Contain "Master running"
        }

        It "$tC.$tI - remote command through master returns output" -skip:$skip {
            ssh -v -S $controlPath test_target echo mux-session-1234 2>$stderrFile | Set-Content $stdoutFile
            $stdoutFile | Should Contain "mux-session-1234"
            Assert-MuxSession $stderrFile
        }

        It "$tC.$tI - exit codes propagate through master" -skip:$skip {
            foreach ($i in (0,1,4,5,44)) {
                ssh -v -S $controlPath test_target exit $i 2>$stderrFile
                $LASTEXITCODE | Should Be $i
                Assert-MuxSession $stderrFile
            }
        }

        It "$tC.$tI - stdin passes through master" -skip:$skip {
            iex "cmd /c `"echo mux-stdin-data | ssh -v -S $controlPath test_target findstr mux-stdin > $stdoutFile 2> $stderrFile`""
            $stdoutFile | Should Contain "mux-stdin-data"
            Assert-MuxSession $stderrFile
        }

        It "$tC.$tI - sessions share the master's single TCP connection" -skip:$skip {
            ssh -v -S $controlPath test_target echo again 2>$stderrFile | Set-Content $stdoutFile
            $stdoutFile | Should Contain "again"
            Assert-MuxSession $stderrFile
            $conns = @(Get-NetTCPConnection -OwningProcess $script:masterProc.Id -State Established -ErrorAction SilentlyContinue | Where-Object { $_.RemotePort -eq $port })
            $conns.Count | Should Be 1
        }

        It "$tC.$tI - -O forward adds a working local forwarding" -skip:$skip {
            # Reserve an ephemeral candidate and retry if another process wins it.
            for ($attempt = 0; $attempt -lt 5; $attempt++) {
                $reservation = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
                $reservation.Start()
                $fwdPort = $reservation.LocalEndpoint.Port
                $reservation.Stop()
                ssh -S $controlPath -O forward -L "$($fwdPort):127.0.0.1:$port" test_target 2>$stderrFile
                if ($LASTEXITCODE -eq 0) { break }
            }
            $LASTEXITCODE | Should Be 0
            # the tunnel targets the test sshd; reading its banner proves end-to-end flow
            $client = New-Object System.Net.Sockets.TcpClient("127.0.0.1", $fwdPort)
            $stream = $client.GetStream()
            $stream.ReadTimeout = 10000
            $buf = New-Object byte[] 64
            $read = $stream.Read($buf, 0, 64)
            $client.Close()
            $banner = [System.Text.Encoding]::ASCII.GetString($buf, 0, $read)
            $banner | Should Match "^SSH-2.0-"
        }

        It "$tC.$tI - tty session multiplexes through the master" -skip:$skip {
            # -tt forces a pty; on Windows this now runs over the master
            # instead of falling back to a separate connection. The proof of
            # multiplexing is the client's own debug output (a master session
            # id is assigned and no fallback message is emitted). The remote
            # command's pty output is NOT asserted here: capturing a forced
            # pty's stdout under redirection is unreliable headless (the
            # interactive Terminal test is skipped in CI for the same reason).
            iex "cmd /c `"ssh -v -tt -S $controlPath test_target echo tty-mux-ok 2> $stderrFile`""
            $stderrFile | Should Contain "master session id"
            $stderrFile | Should Not Contain "opening a separate connection"
        }

        It "$tC.$tI - second master on the same ControlPath degrades gracefully" -skip:$skip {
            # muxserver_listen() must detect the busy pipe, disable multiplexing
            # for the second client and run its session over its own connection
            iex "cmd /c `"ssh -M -S $controlPath test_target echo second-master-ok > $stdoutFile 2> $stderrFile`""
            $stdoutFile | Should Contain "second-master-ok"
            $stderrFile | Should Contain "already exists, disabling multiplexing"
            # first master is unaffected
            ssh -S $controlPath -O check test_target 2>$null
            $LASTEXITCODE | Should Be 0
        }

        It "$tC.$tI - -O exit shuts the master down" -skip:$skip {
            iex "cmd /c `"ssh -S $controlPath -O exit test_target 2> $stderrFile`""
            $stderrFile | Should Contain "Exit request sent"
            $script:masterProc.WaitForExit(10000) | Should Be $true
            $script:masterProc = $null
            # control requests must now fail
            ssh -S $controlPath -O check test_target 2>$null
            $LASTEXITCODE | Should Not Be 0
        }
    }

    Context "$tC - graceful degradation without a master" {
        BeforeAll {$tI=1}
        AfterAll{$tC++}

        It "$tC.$tI - ControlPath with no master falls back to a direct connection" -skip:$skip {
            ssh -S $controlPath test_target echo no-master-fallback | Set-Content $stdoutFile
            $stdoutFile | Should Contain "no-master-fallback"
        }

        It "$tC.$tI - ControlMaster auto without a master connects directly" -skip:$skip {
            ssh -o ControlMaster=auto -o ControlPersist=no -S $controlPath test_target echo auto-ok | Set-Content $stdoutFile
            $stdoutFile | Should Contain "auto-ok"
            # ControlPersist=no: no master may linger
            Stop-MuxMaster
        }
    }

    Context "$tC - ControlPersist auto-spawned master" {
        BeforeAll {
            $tI=1
            $cpPath = Join-Path $testDir "cp_ctl"
            # ControlPersist=yes: the auto-started master persists until -O exit
            # (a numeric timeout would risk expiring mid-test)
            $cpOpts = "-o", "ControlMaster=auto", "-o", "ControlPersist=yes",
                "-o", "ControlPath=`"$cpPath`""
        }
        AfterAll {
            # make sure the persistent master does not leak between runs
            ssh -o ControlPath="$cpPath" -O exit test_target 2>$null
            $tC++
        }

        # Windows has no fork(), so ControlPersist auto-starts a separate master
        # process (which authenticates itself) and connects to it as a client.
        It "$tC.$tI - first connection auto-starts a persistent master" -skip:$skip {
            # Start-Process (own console) so the spawned master does not block us
            $p = Start-Process -FilePath $sshExe `
                -ArgumentList ($cpOpts + @("-v", "test_target", "echo cp-first")) `
                -WindowStyle Hidden -RedirectStandardOutput $stdoutFile -RedirectStandardError $stderrFile -PassThru
            Wait-MuxClient $p
            $stdoutFile | Should Contain "cp-first"
            Assert-MuxSession $stderrFile
            # the master should have persisted and answer control requests
            ssh -o ControlPath="$cpPath" -O check test_target 2>$null
            $LASTEXITCODE | Should Be 0
        }

        It "$tC.$tI - subsequent connection reuses the persistent master" -skip:$skip {
            $p = Start-Process -FilePath $sshExe `
                -ArgumentList @("-v", "-o", "ControlPath=`"$cpPath`"", "test_target", "echo cp-reuse") `
                -WindowStyle Hidden -RedirectStandardOutput $stdoutFile -RedirectStandardError $stderrFile -PassThru
            Wait-MuxClient $p 20000
            $stdoutFile | Should Contain "cp-reuse"
            Assert-MuxSession $stderrFile
        }

        It "$tC.$tI - -O exit stops the persistent master" -skip:$skip {
            iex "cmd /c `"ssh -o ControlPath=$cpPath -O exit test_target 2> $stderrFile`""
            $stderrFile | Should Contain "Exit request sent"
            ssh -o ControlPath="$cpPath" -O check test_target 2>$null
            $LASTEXITCODE | Should Not Be 0
        }
    }

    Context "$tC - mux safety regressions" {
        BeforeAll {$tI=1}
        AfterAll {$tC++}

        It "$tC.$tI - control endpoint cleanup preserves a regular file" -skip:$skip {
            "sentinel-$PID" | Set-Content $controlPath
            try {
                foreach ($operation in @("exit", "stop")) {
                    Start-MuxMaster -MasterLog $logFile | Should Be $true
                    ssh -S $controlPath -O $operation test_target 2>$null
                    $LASTEXITCODE | Should Be 0
                    if ($operation -eq "exit") {
                        $script:masterProc.WaitForExit(10000) | Should Be $true
                    }
                    Stop-MuxMaster
                    (Get-Content $controlPath) | Should Be "sentinel-$PID"
                }
            } finally {
                Stop-MuxMaster
                Remove-Item -LiteralPath $controlPath -ErrorAction SilentlyContinue
            }
        }

        It "$tC.$tI - autoask never becomes an unprompted persistent master" -skip:$skip {
            ssh -v -o BatchMode=yes -o ControlMaster=autoask -o ControlPersist=yes `
                -S $controlPath test_target echo consent-preserved 2>$stderrFile | Set-Content $stdoutFile
            $stdoutFile | Should Contain "consent-preserved"
            $stderrFile | Should Contain "using a direct connection"
            ssh -S $controlPath -O check test_target 2>$null
            $LASTEXITCODE | Should Not Be 0
        }

        It "$tC.$tI - subsystem startup persists and SFTP reuses the master" -skip:$skip {
            $batch = Join-Path $testDir "mux-sftp.batch"
            $inputFile = Join-Path $testDir "mux-sftp-init"
            "pwd`nquit" | Set-Content $batch -Encoding ASCII
            # SFTP v3 INIT followed by EOF: no remote filesystem changes.
            [System.IO.File]::WriteAllBytes($inputFile, [byte[]](0,0,0,5,1,0,0,0,3))
            try {
                # sftp/scp force ControlMaster=no on every platform. Exercise
                # explicit ssh -s startup, then the utilities' reuse path.
                $p = Start-Process -FilePath $sshExe `
                    -ArgumentList @("-v", "-oControlMaster=auto", "-oControlPersist=30", `
                        "-S", "`"$controlPath`"", "-s", "test_target", "sftp") `
                    -WindowStyle Hidden -RedirectStandardInput $inputFile `
                    -RedirectStandardOutput $stdoutFile -RedirectStandardError $stderrFile -PassThru
                Wait-MuxClient $p
                Assert-MuxSession $stderrFile
                $p = Start-Process -FilePath (Join-Path (Split-Path $sshExe) "sftp.exe") `
                    -ArgumentList @("-v", "-b", "`"$batch`"", "-oControlMaster=auto", `
                        "-oControlPersist=30", "-oControlPath=`"$controlPath`"", "test_target") `
                    -WindowStyle Hidden -RedirectStandardOutput $stdoutFile -RedirectStandardError $stderrFile -PassThru
                Wait-MuxClient $p
                Assert-MuxSession $stderrFile
                ssh -S $controlPath -O check test_target 2>$null
                $LASTEXITCODE | Should Be 0
                ssh -v -S $controlPath test_target echo after-sftp 2>$stderrFile | Set-Content $stdoutFile
                $stdoutFile | Should Contain "after-sftp"
                Assert-MuxSession $stderrFile
            } finally {
                ssh -S $controlPath -O exit test_target 2>$null
                Remove-Item -LiteralPath $batch -ErrorAction SilentlyContinue
                Remove-Item -LiteralPath $inputFile -ErrorAction SilentlyContinue
            }
        }

        It "$tC.$tI - stdio forwarding exits after the remote endpoint closes" -skip:$skip {
            $inputFile = Join-Path $testDir "mux-stdio-input"
            "mux-stdio-eof" | Set-Content $inputFile -Encoding ASCII
            $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
            $client = $null
            $p = $null
            try {
                $listener.Start()
                $accept = $listener.AcceptTcpClientAsync()
                $p = Start-Process -FilePath $sshExe `
                    -ArgumentList @("-v", "-oControlMaster=auto", "-oControlPersist=30", `
                        "-S", "`"$controlPath`"", "-W", "127.0.0.1:$($listener.LocalEndpoint.Port)", "test_target") `
                    -WindowStyle Hidden -RedirectStandardInput $inputFile `
                    -RedirectStandardOutput $stdoutFile -RedirectStandardError $stderrFile -PassThru
                $accept.Wait(10000) | Should Be $true
                $client = $accept.Result
                $stream = $client.GetStream()
                $stream.ReadTimeout = 10000
                $stream.WriteTimeout = 10000
                $buf = New-Object byte[] 1024
                while (($n = $stream.Read($buf, 0, $buf.Length)) -gt 0) {
                    $stream.Write($buf, 0, $n)
                }
                $client.Close()
                Wait-MuxClient $p 10000
                $stdoutFile | Should Contain "mux-stdio-eof"
                Assert-MuxSession $stderrFile
                ssh -S $controlPath -O check test_target 2>$null
                $LASTEXITCODE | Should Be 0
            } finally {
                if ($client) { $client.Close() }
                $listener.Stop()
                if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force }
                ssh -S $controlPath -O exit test_target 2>$null
                Remove-Item -LiteralPath $inputFile -ErrorAction SilentlyContinue
            }
        }
    }
}

If ($PSVersiontable.PSVersion.Major -le 2) {$PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path}
Import-Module $PSScriptRoot\CommonUtils.psm1 -Force
$tI = 0
Describe "SFTP Test Cases" -Tags "CI" {
    BeforeAll {
        $serverDirectory = $null
        $clientDirectory = $null
        $largeFilePath = $null
        if($OpenSSHTestInfo -eq $null)
        {
            Throw "`$OpenSSHTestInfo is null. Please run Set-OpenSSHTestEnvironment to set test environments."
        }
        $rootDirectory = "$($OpenSSHTestInfo["TestDataPath"])\SFTP"
        $outputFileName = "output.txt"
        $batchFileName = "sftp-batchcmds.txt"
        $tempFileName = "tempFile.txt"
        $tempFilePath = Join-Path $rootDirectory $tempFileName
        $tempUnicodeFileName = "tempFile_язык.txt"
        $tempUnicodeFilePath = Join-Path $rootDirectory $tempUnicodeFileName
        $largeFileName = "largeFile.txt"
        $largeFilePath = Join-Path $rootDirectory $largeFileName
        fsutil file createNew $largeFilePath 1000000000
        $clientDirectory = Join-Path $rootDirectory 'client_dir'
        $serverDirectory = Join-Path $rootDirectory 'server_dir'
        $null = New-Item $clientDirectory -ItemType directory -Force
        $null = New-Item $serverDirectory -ItemType directory -Force
        $null = New-Item $tempFilePath -ItemType file -Force -value "temp file data"
        $null = New-Item $tempUnicodeFilePath -ItemType file -Force -value "temp file data"
        $server = $OpenSSHTestInfo["Target"]
        $port = $OpenSSHTestInfo["Port"]
        $ssouser = $OpenSSHTestInfo["SSOUser"]
        Remove-item (Join-Path $rootDirectory "*.$outputFileName") -Force -ErrorAction SilentlyContinue
        Remove-item (Join-Path $rootDirectory "*.$batchFileName") -Force -ErrorAction SilentlyContinue
        Remove-item (Join-Path $rootDirectory "*.log") -Force -ErrorAction SilentlyContinue
        $skip = $IsWindows -and ($PSVersionTable.PSVersion.Major -le 2)
        $testData1 = @(
             @{
                title = "put, ls for non-unicode file names"
                options = ''
                commands = "put $tempFilePath $serverDirectory
                            ls $serverDirectory"
                expectedoutput = (join-path $serverdirectory $tempFileName)
             },
             @{
                title = "get, ls for non-unicode file names"
                options = ''
                commands = "get $tempFilePath $clientDirectory
                            ls $clientDirectory"
                expectedoutput = (join-path $clientDirectory $tempFileName)
             },
             @{
                title = "mput, ls for non-unicode file names"
                options = ''
                commands = "mput $tempFilePath $serverDirectory
                            ls $serverDirectory"
                expectedoutput = (join-path $serverdirectory $tempFileName)
             },
             @{
                title = "mget, ls for non-unicode file names"
                options = ''
                commands = "mget $tempFilePath $clientDirectory
                            ls $clientDirectory"
                expectedoutput = (join-path $clientDirectory $tempFileName)
             },
             @{
                title = "mkdir, cd, pwd for non-unicode directory names"
                options = ''
                commands = "cd $serverdirectory
                            mkdir server_test_dir
                            cd server_test_dir
                            pwd"
                expectedoutput = (join-path $serverdirectory "server_test_dir")
             },
             @{
                Title = "lmkdir, lcd, lpwd for non-unicode directory names"
                Options = ''
                Commands = "lcd $clientDirectory
                            lmkdir client_test_dir
                            lcd client_test_dir
                            lpwd"
                ExpectedOutput = (Join-Path $clientDirectory "client_test_dir")
             },
             @{
                title = "put, ls for unicode file names"
                options = ''
                commands = "put $tempUnicodeFilePath $serverDirectory
                            ls $serverDirectory"
                expectedoutput = (join-path $serverdirectory $tempUnicodeFileName)
             },
             @{
                title = "get, ls for unicode file names"
                options = ''
                commands = "get $tempUnicodeFilePath $clientDirectory
                            ls $clientDirectory"
                expectedoutput = (join-path $clientDirectory $tempUnicodeFileName)
             },
             @{
                title = "mput, ls for unicode file names"
                options = ''
                commands = "mput $tempUnicodeFilePath $serverDirectory
                            ls $serverDirectory"
                expectedoutput = (join-path $serverdirectory $tempUnicodeFileName)
             },
             @{
                title = "mget, ls for unicode file names"
                options = ''
                commands = "mget $tempUnicodeFilePath $clientDirectory
                            ls $clientDirectory"
                expectedoutput = (join-path $clientDirectory $tempUnicodeFileName)
             },
             @{
                title = "mkdir, cd, pwd for unicode directory names"
                options = ''
                commands = "cd $serverdirectory
                            mkdir server_test_dir_язык
                            cd server_test_dir_язык
                            pwd"
                expectedoutput = (join-path $serverdirectory "server_test_dir_язык")
             },
             @{
                Title = "lmkdir, lcd, lpwd for unicode directory names"
                Options = ''
                Commands = "lcd $clientDirectory
                            lmkdir client_test_dir_язык
                            lcd client_test_dir_язык
                            lpwd
                            lls $clientDirectory"
                ExpectedOutput = (Join-Path $clientDirectory "client_test_dir_язык")
             }
        )
        $testData2 = @(
            @{
                title = "rm, rmdir, rename for unicode file, directory"
                options = '-b $batchFilePath'
                tmpFileName1 = $tempUnicodeFileName
                tmpFilePath1 = $tempUnicodeFilePath
                tmpFileName2 = "tempfile_язык_2.txt"
                tmpFilePath2 = (join-path $serverDirectory "tempfile_язык_2.txt")
                tmpDirectoryName1 = "test_dir_язык_1"
                tmpDirectoryPath1 = (join-path $serverDirectory "test_dir_язык_1")
                tmpDirectoryName2 = "test_dir_язык_2"
                tmpDirectoryPath2 = (join-path $serverDirectory "test_dir_язык_2")
            },
            @{
                title = "rm, rmdir, rename for non-unicode file, directory"
                options = '-b $batchFilePath'
                tmpFileName1 = $tempFileName
                tmpFilePath1 = $tempFilePath
                tmpFileName2 = "tempfile_2.txt"
                tmpFilePath2 = (join-path $serverDirectory "tempfile_2.txt")
                tmpDirectoryName1 = "test_dir_1"
                tmpDirectoryPath1 = (join-path $serverDirectory "test_dir_1")
                tmpDirectoryName2 = "test_dir_2"
                tmpDirectoryPath2 = (join-path $serverDirectory "test_dir_2")
            }
         )
        $testData3 = @(
            @{
               title = "put, ls for large file transfer"
               commands = "put $largeFilePath $serverDirectory
                           ls $serverDirectory"
               expectedoutput = (join-path $serverdirectory $largeFileName)
            },
            @{
               title = "get, ls for large file transfer"
               commands = "get $largeFilePath $clientDirectory
                           ls $clientDirectory"
               expectedoutput = (join-path $clientDirectory $largeFileName)
            },
            @{
               title = "mput, ls for large file transfer"
               commands = "mput $largeFilePath $serverDirectory
                           ls $serverDirectory"
               expectedoutput = (join-path $serverdirectory $largeFileName)
            },
            @{
               title = "mget, ls for large file transfer"
               commands = "mget $largeFilePath $clientDirectory
                           ls $clientDirectory"
               expectedoutput = (join-path $clientDirectory $largeFileName)
            }
        )
        # for the first time, delete the existing log files.
        if ($OpenSSHTestInfo['DebugMode'])
        {
            Clear-Content "$env:ProgramData\ssh\logs\ssh-agent.log" -Force -ErrorAction SilentlyContinue
            Clear-Content "$env:ProgramData\ssh\logs\sshd.log" -Force -ErrorAction SilentlyContinue
            Clear-Content "$env:ProgramData\ssh\logs\sftp-server.log" -Force -ErrorAction SilentlyContinue
        }
        function CopyDebugLogs {
            if($OpenSSHTestInfo["DebugMode"])
            {
                Copy-Item "$env:ProgramData\ssh\logs\ssh-agent.log" "$rootDirectory\ssh-agent_$tI.log" -Force -ErrorAction SilentlyContinue
                Copy-Item "$env:ProgramData\ssh\logs\sshd.log" "$rootDirectory\sshd_$tI.log" -Force -ErrorAction SilentlyContinue
                Copy-Item "$env:ProgramData\ssh\logs\sftp-server.log" "$rootDirectory\sftp-server_$tI.log" -Force -ErrorAction SilentlyContinue
                # clear the ssh-agent, sshd logs so that next testcase will get fresh logs.
                Clear-Content "$env:ProgramData\ssh\logs\ssh-agent.log" -Force -ErrorAction SilentlyContinue
                Clear-Content "$env:ProgramData\ssh\logs\sshd.log" -Force -ErrorAction SilentlyContinue
                Clear-Content "$env:ProgramData\ssh\logs\sftp-server.log" -Force -ErrorAction SilentlyContinue
            }
        }
    }

    AfterAll {
       if($serverDirectory) { Get-ChildItem $serverDirectory | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue }
       if($clientDirectory) { Get-ChildItem $clientDirectory | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue }
       if($largeFilePath) { Remove-Item $largeFilePath -Force -ErrorAction SilentlyContinue }
    }

    BeforeEach {
       if($serverDirectory) { Get-ChildItem $serverDirectory | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue }
       if($clientDirectory) { Get-ChildItem $clientDirectory | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue }
       $outputFilePath = Join-Path $rootDirectory "$tI.$outputFileName"
       $batchFilePath = Join-Path $rootDirectory "$tI.$batchFileName"
    }

    AfterEach {
        CopyDebugLogs
        $tI++
    }

    It '<Title>' -TestCases:$testData1 {
       param([string]$Title, $Options, $Commands, $ExpectedOutput)
       Set-Content $batchFilePath -Encoding UTF8 -value $Commands
       $str = $ExecutionContext.InvokeCommand.ExpandString("sftp -P $port $($Options) -b $batchFilePath test_target > $outputFilePath")
       iex $str

       #validate file content.
       Test-Path $ExpectedOutput | Should be $true
    }

    It '<Title>' -TestCases:$testData2 {
       param([string]$Title, $Options, $tmpFileName1, $tmpFilePath1, $tmpFileName2, $tmpFilePath2, $tmpDirectoryName1, $tmpDirectoryPath1, $tmpDirectoryName2, $tmpDirectoryPath2)
       if($skip) { return }

       #rm (remove file)
       $commands = "mkdir $tmpDirectoryPath1
                    put $tmpFilePath1 $tmpDirectoryPath1
                    ls $tmpDirectoryPath1"
       Set-Content $batchFilePath  -Encoding UTF8 -value $commands
       $str = $ExecutionContext.InvokeCommand.ExpandString("sftp -P $port $($Options) test_target > $outputFilePath")
       iex $str
       Test-Path (join-path $tmpDirectoryPath1 $tmpFileName1) | Should be $true

       $commands = "rm $tmpDirectoryPath1\*
                    ls $tmpDirectoryPath1
                    pwd
                   "
       Set-Content $batchFilePath  -Encoding UTF8 -value $commands
       $str = $ExecutionContext.InvokeCommand.ExpandString("sftp -P $port $($Options) test_target > $outputFilePath")
       iex $str
       Test-Path (join-path $tmpDirectoryPath1 $tmpFileName1) | Should be $false

       #rename file
       Remove-Item $outputFilePath
       Copy-Item $tmpFilePath1 -destination $tmpDirectoryPath1
       $commands = "rename $tmpDirectoryPath1\$tmpFileName1 $tmpDirectoryPath1\$tmpFileName2
                    ls $tmpDirectoryPath1
                    pwd"
       Set-Content $batchFilePath -Encoding UTF8 -value $commands
       $str = $ExecutionContext.InvokeCommand.ExpandString("sftp -P $port $($Options) test_target > $outputFilePath")
       iex $str
       Test-Path (join-path $tmpDirectoryPath1 $tmpFileName2) | Should be $true

       #rename directory
       Remove-Item $outputFilePath
       $commands = "rm $tmpDirectoryPath1\*
                    rename $tmpDirectoryPath1 $tmpDirectoryPath2
                    ls $serverDirectory"
       Set-Content $batchFilePath -Encoding UTF8 -value $commands
       $str = $ExecutionContext.InvokeCommand.ExpandString("sftp -P $port $($Options) test_target > $outputFilePath")
       iex $str
       Test-Path $tmpDirectoryPath2 | Should be $true

       #rmdir (remove directory)
       Remove-Item $outputFilePath
       $commands = "rmdir $tmpDirectoryPath2
                    ls $serverDirectory"
       Set-Content $batchFilePath -Encoding UTF8 -value $commands
       $str = $ExecutionContext.InvokeCommand.ExpandString("sftp -P $port $($Options) test_target > $outputFilePath")
       iex $str
       Test-Path $tmpDirectoryPath2 | Should be $false
    }

    It "$script:testId-ls lists items the user has no read permission" {
       $adminsSid = Get-UserSID -WellKnownSidType ([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid)
       $currentUserSid = Get-UserSID -User "$($env:USERDOMAIN)\$($env:USERNAME)"

       $permTestHasAccessFile = "permTestHasAccessFile.txt"
       $permTestHasAccessFilePath = Join-Path $serverDirectory $permTestHasAccessFile
       Remove-Item $permTestHasAccessFilePath -Force -ErrorAction SilentlyContinue
       New-Item $permTestHasAccessFilePath -ItemType file -Force -value "perm test has access file data" | Out-Null

       $permTestNoAccessFile = "permTestNoAccessFile.txt"
       $permTestNoAccessFilePath = Join-Path $serverDirectory $permTestNoAccessFile
       Remove-Item $permTestNoAccessFilePath -Force -ErrorAction SilentlyContinue
       New-Item $permTestNoAccessFilePath -ItemType file -Force -value "perm test no access file data" | Out-Null
       Repair-FilePermission -Filepath $permTestNoAccessFilePath -Owners $currentUserSid -FullAccessNeeded $adminsSid,$currentUserSid -confirm:$false

       $Commands = "ls $serverDirectory"
       Set-Content $batchFilePath -Encoding UTF8 -value $Commands
       $str = $ExecutionContext.InvokeCommand.ExpandString("sftp -b $batchFilePath test_target > $outputFilePath")
       iex $str
       $content = Get-Content $outputFilePath

       #cleanup
       $HasAccessPattern = $permTestHasAccessFilePath.Replace("\", "[/\\]")
       $matches = @($content | select-string -Pattern "^/$HasAccessPattern\s{0,}$")
       $matches.count | Should be 1

       $NoAccessPattern = $permTestNoAccessFilePath.Replace("\", "[/\\]")
       $matches = @($content | select-string -Pattern "^/$NoAccessPattern\s{0,}$")
       $matches.count | Should be 1
    }

    It '<Title>' -TestCases:$testData3 {
      param([string]$Title, $Commands, $ExpectedOutput)
      if (-not (Test-Path $largeFilePath)) {
         fsutil file createNew $largeFilePath 1000000000
      }
      Set-Content $batchFilePath -Encoding UTF8 -value $Commands
      $str = $ExecutionContext.InvokeCommand.ExpandString("sftp -P $port -b $batchFilePath test_target > $outputFilePath")
      iex $str

      #validate file content.
      Test-Path $ExpectedOutput | Should be $true
      $LASTEXITCODE | Should Be 0
    }

    Context "Configure various default shell scenarios" {
        BeforeAll {
            $dfltShellRegPath = $null
            $dfltShellRegPath = "HKLM:\Software\OpenSSH"
            $dfltShellRegKeyName = "DefaultShell"
            $dfltShellCmdOptionRegKeyName = "DefaultShellCommandOption"
            Remove-ItemProperty -Path $dfltShellRegPath -Name $dfltShellRegKeyName -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path $dfltShellRegPath -Name $dfltShellCmdOptionRegKeyName -ErrorAction SilentlyContinue
            $shells = @(
                @{
                    Name = "Windows PowerShell"
                    Path = (Get-Command powershell.exe -ErrorAction SilentlyContinue).Path
                    CmdOption = "/c"
                },
                @{
                    Name = "PowerShell Core"
                    Path = (Get-Command pwsh -ErrorAction SilentlyContinue).Path
                    CmdOption = $null
                },
                @{
                    Name = "Bash"
                    Path = (Get-Command bash -ErrorAction SilentlyContinue).Path
                    CmdOption = $null
                },
                @{
                    Name = "Cygwin"
                    Path = (Get-Command sh -ErrorAction SilentlyContinue).Path
                    CmdOption = $null
                }
            )
        }

        AfterEach {
            if ($dfltShellRegPath) {
                Remove-ItemProperty -Path $dfltShellRegPath -Name $dfltShellRegKeyName -ErrorAction SilentlyContinue
                Remove-ItemProperty -Path $dfltShellRegPath -Name $dfltShellCmdOptionRegKeyName -ErrorAction SilentlyContinue
            }
        }

        It 'File copy: <Name> ' -TestCases:$shells {
            param([string]$Name, $Path, $CmdOption)
            if ($Path -eq $null) {
               throw "$Name not found, please install it to run this test"
            }
            else {
               ConfigureDefaultShell -default_shell_path $Path -default_shell_cmd_option_val $CmdOption
               $Commands = "put $tempFilePath $serverDirectory
                             ls $serverDirectory"
               Set-Content $batchFilePath -Encoding UTF8 -value $Commands
               $str = $ExecutionContext.InvokeCommand.ExpandString("sftp -P $port -b $batchFilePath test_target > $outputFilePath")
               iex $str

               #validate file content.
               $ExpectedOutput = (join-path $serverdirectory $tempFileName)
               Test-Path $ExpectedOutput | Should be $true
            }
        }
    }
}

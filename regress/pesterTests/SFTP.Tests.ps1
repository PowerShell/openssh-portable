using module .\PlatformAbstractLayer.psm1

Describe "Tests for SFTP command" -Tags "CI" {
    BeforeAll {
        $rootDirectory = $TestDrive
        
        $outputFileName = "output.txt"
        $batchFileName = "sftp-batchcmds.txt"
        $outputFilePath = Join-Path $rootDirectory $outputFileName
        $batchFilePath = Join-Path $rootDirectory $batchFileName
        
        $tempFileName = "tempFile.txt"
        $tempFilePath = Join-Path $rootDirectory $tempFileName
        
        $clientDirectory = Join-Path $rootDirectory 'client_dir'
        $serverDirectory = Join-Path $rootDirectory 'server_dir'
        
        $null = New-Item $clientDirectory -ItemType directory -Force
        $null = New-Item $serverDirectory -ItemType directory -Force
        $null = New-Item $batchFilePath -ItemType file -Force
        $null = New-Item $outputFilePath -ItemType file -Force
        $null = New-Item $tempFilePath -ItemType file -Force -value "temp file data"
        
        $expectedOutputDelimiter = "#DL$"
        
        [Machine] $client = [Machine]::new([MachineRole]::Client)
        [Machine] $server = [Machine]::new([MachineRole]::Server)
        $client.SetupClient($server)
        $server.SetupServer($client)
        
        $testData1 = @(
             @{
                title = "put, ls for non-unicode file names"
                logonstr = "$($server.localadminusername)@$($server.machinename)"
                options = '-i $identifyfile'
                commands = "put $tempFilePath $serverDirectory
                            ls $serverDirectory"
                expectedoutput = (join-path $serverdirectory $tempFileName).replace("\", "/")
             },
             @{
                title = "get, ls for non-unicode file names"
                logonstr = "$($server.localadminusername)@$($server.machinename)"
                options = '-i $identifyfile'
                commands = "get $tempFilePath $clientDirectory
                            ls $clientDirectory"
                expectedoutput = (join-path $clientDirectory $tempFileName).replace("\", "/")
             },
             @{
                title = "mput, ls for non-unicode file names"
                logonstr = "$($server.localadminusername)@$($server.machinename)"
                options = '-i $identifyfile'
                commands = "mput $tempFilePath $serverDirectory
                            ls $serverDirectory"
                expectedoutput = (join-path $serverdirectory $tempFileName).replace("\", "/")
             },
             @{
                title = "mget, ls for non-unicode file names"
                logonstr = "$($server.localadminusername)@$($server.machinename)"
                options = '-i $identifyfile'
                commands = "mget $tempFilePath $clientDirectory
                            ls $clientDirectory"
                expectedoutput = (join-path $clientDirectory $tempFileName).replace("\", "/")
             },
             @{
                title = "mkdir, cd, pwd for non-unicode directory names"
                logonstr = "$($server.localadminusername)@$($server.machinename)"
                options = '-i $identifyfile'
                commands = "cd $serverdirectory
                            mkdir server_test_dir
                            cd server_test_dir
                            pwd"
                expectedoutput = (join-path $serverdirectory "server_test_dir").replace("\", "/")
             },
             @{
                title = "mkdir, cd, pwd for unicode directory names"
                logonstr = "$($server.localadminusername)@$($server.machinename)"
                options = '-i $identifyfile'
                commands = "cd $serverdirectory
                            mkdir server_test_dir_язык
                            cd server_test_dir_язык
                            pwd"
                expectedoutput = (join-path $serverdirectory "server_test_dir_язык").replace("\", "/")
             },
             @{
                Title = "lmkdir, lcd, lpwd for non-unicode directory names"
                LogonStr = "$($server.localAdminUserName)@$($server.MachineName)"
                Options = '-i $identifyFile'
                Commands = "lcd $clientDirectory
                            lmkdir client_test_dir
                            lcd client_test_dir
                            lpwd"
                ExpectedOutput = (Join-Path $clientDirectory "client_test_dir")
             },
             @{
                Title = "lmkdir, lcd, lpwd for unicode directory names"
                LogonStr = "$($server.localAdminUserName)@$($server.MachineName)"
                Options = '-i $identifyFile'
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
                title = "rm, rmdir, rename for non-unicode file names"
                logonstr = "$($server.localadminusername)@$($server.machinename)"
                options = '-i $identifyfile -b $batchFilePath'
            }
        )
    }

    AfterAll {
        $client.CleanupClient()
        $server.CleanupServer()
    }

    Context "Single signon" {
        BeforeAll {
            $Server.SecureHostKeys($server.PrivateHostKeyPaths)
            $identifyFile = $client.clientPrivateKeyPaths[0]
            .\ssh-add.exe $identifyFile #setup single signon
        }
        AfterAll {
            $Server.CleanupHostKeys()
            .\ssh-add.exe -D #cleanup single signon
        }        

        BeforeEach {
           Get-ChildItem $serverDirectory | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
           Get-ChildItem $clientDirectory | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
           Remove-Item $batchFilePath
           Remove-Item $outputFilePath
        }
        
        It '<Title>' -TestCases:$testData1 {
           param([string]$Title, $LogonStr, $Options, $Commands, $ExpectedOutput, $SkipVerification = $false)
           
           Set-Content $batchFilePath -value $($Commands)
           $str = $ExecutionContext.InvokeCommand.ExpandString(".\sftp $($Options) -b $batchFilePath $($LogonStr) > $outputFilePath")
           $client.RunCmd($str)

           #validate file content.
           $($ExpectedOutput).split($expectedOutputDelimiter) | foreach {
              $outputFilePath | Should Contain ([RegEx]::Escape($_))
           }
        }
        
        It '<Title>' -TestCases:$testData2 {
           param([string]$Title, $LogonStr, $Options, $SkipVerification = $false)
           
           $servertestdir = join-path $serverDirectory "server_test_dir"
           
           #rm (remove file)
           $commands = "mkdir $servertestdir
                        put $tempFilePath $servertestdir
                        ls $servertestdir"
           Set-Content $batchFilePath -value $commands
           $str = $ExecutionContext.InvokeCommand.ExpandString(".\sftp $($Options) $($LogonStr) > $outputFilePath")
           $client.RunCmd($str)
           $outputFilePath | Should Contain ([RegEx]::Escape((join-path $servertestdir $tempFileName).replace("\", "/")))
           
           $commands = "rm $servertestdir\*
                        ls $servertestdir
                        pwd
                       "
           Set-Content $batchFilePath -value $commands
           $str = $ExecutionContext.InvokeCommand.ExpandString(".\sftp $($Options) $($LogonStr) > $outputFilePath")
           $client.RunCmd($str)
           $outputFilePath | Should Not Contain ([RegEx]::Escape((join-path $servertestdir $tempFileName).replace("\", "/")))
           
           #rename file
           $tempFile_1 = join-path $serverDirectory "tempfile_1.txt"
           $commands = "put $tempFilePath $serverDirectory
                        rename $serverDirectory\tempFile.txt $tempFile_1
                        ls $serverDirectory"
           Set-Content $batchFilePath -value $commands
           $str = $ExecutionContext.InvokeCommand.ExpandString(".\sftp $($Options) $($LogonStr) > $outputFilePath")
           $client.RunCmd($str)
           $outputFilePath | Should Contain ([RegEx]::Escape($tempFile_1.replace("\", "/")))
           
           #rename directory
           $servertestdir1 = join-path $serverDirectory "server_test_dir_1"
           $commands = "rm $tempFile_1
                        rename $servertestdir $servertestdir1
                        ls $serverDirectory"
           Set-Content $batchFilePath -value $commands
           $str = $ExecutionContext.InvokeCommand.ExpandString(".\sftp $($Options) $($LogonStr) > $outputFilePath")
           $client.RunCmd($str)
           $outputFilePath | Should Contain ([RegEx]::Escape($servertestdir1.replace("\", "/")))
           
           #rmdir (remove directory)
           $commands = "rmdir $servertestdir1
                        ls $serverDirectory"
           Set-Content $batchFilePath -value $commands
           $str = $ExecutionContext.InvokeCommand.ExpandString(".\sftp $($Options) $($LogonStr) > $outputFilePath")
           $client.RunCmd($str)
           $outputFilePath | Should Not Contain ([RegEx]::Escape($servertestdir1).replace("\", "/"))
        }
    }
}

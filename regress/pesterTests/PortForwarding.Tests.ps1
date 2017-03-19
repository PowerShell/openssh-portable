using module .\PlatformAbstractLayer.psm1

Describe "Tests for portforwarding" -Tags "CI" {
    BeforeAll {        
        $fileName = "test.txt"
        $filePath = Join-Path ${TestDrive} $fileName
        $logName = "log.txt"
        $logPath = Join-Path ${TestDrive} $logName        
        [Machine] $client = [Machine]::new([MachineRole]::Client)
        [Machine] $server = [Machine]::new([MachineRole]::Server)

        $testData = @(
            @{
                Title = "Local port forwarding"
                Options = "-L 5432:127.0.0.1:47001"
                Port = 5432

            },
            @{
                Title = "Remote port forwarding"
                Options = "-R 5432:127.0.0.1:47001"
                Port = 5432
            }
        )      
    }

    AfterAll {
    }

    AfterEach {
        Remove-Item -Path $filePath -Force -ea silentlycontinue
        Remove-Item -Path $logPath -Force -ea silentlycontinue
    }

    It '<Title>' -TestCases:$testData {
        param([string]$Title, $Options, $port)
         
        $str = "ssh -p 47002 -E $logPath $($Options) $($server.ssouser)@$($server.MachineName) powershell.exe Test-WSMan -computer 127.0.0.1 -port $port > $filePath"
        $client.RunCmd($str)
        #validate file content.           
        $content = Get-Content $filePath
        $content -like "wsmid*" | Should Not Be $null
    }
        
}

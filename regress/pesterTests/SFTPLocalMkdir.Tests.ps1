Describe "SFTP recursive local mkdir" -Tags "CI" {
    BeforeAll {
        $sftp = (Get-Command sftp.exe -ErrorAction Stop).Source
        $sftpServer = Join-Path (Split-Path $sftp) 'sftp-server.exe'
        if (-not (Test-Path -LiteralPath $sftpServer -PathType Leaf)) {
            throw "sftp-server.exe not found beside $sftp"
        }
    }

    BeforeEach {
        $root = Join-Path $TestDrive ([guid]::NewGuid().ToString())
        $null = New-Item -ItemType Directory -Path $root
        $outputFile = Join-Path $root 'output.txt'
        $errorFile = Join-Path $root 'error.txt'
    }

    It 'Creates missing parents for <Kind> paths' -TestCases @(
        @{ Kind = 'relative' },
        @{ Kind = 'backslash' },
        @{ Kind = 'drive-qualified' },
        @{ Kind = 'prefixed-drive' },
        @{ Kind = 'root-relative' },
        @{ Kind = 'drive-relative' },
        @{ Kind = 'mixed-separators' }
    ) {
        param($Kind)
        $forward = $root.Replace('\', '/')
        $suffix = 'new directory/parent/child'
        switch ($Kind) {
            'relative'         { $target = $suffix }
            'backslash'        { $target = $suffix.Replace('/', '\') }
            'drive-qualified'  { $target = "$forward/$suffix" }
            'prefixed-drive'   { $target = "/$forward/$suffix" }
            'root-relative'    { $target = "$($forward.Substring(2))/$suffix" }
            'drive-relative'   { $target = "$($forward.Substring(0, 2))$suffix" }
            'mixed-separators' { $target = 'new directory\parent/child//' }
        }
        @(
            "lcd `"$root`""
            "lmkdir -p `"$target`""
            "lmkdir -p `"$target`""
        ) | & $sftp -b - -D "`"$sftpServer`"" > $outputFile 2> $errorFile
        $LASTEXITCODE | Should be 0
        Test-Path -LiteralPath (Join-Path $root $suffix) -PathType Container |
            Should be $true
    }

    It 'Accepts existing roots and empty path components' {
        $forward = $root.Replace('\', '/')
        @(
            "lcd `"$root`""
            "lmkdir -p `"$($forward.Substring(0, 3))`""
            'lmkdir -p /'
            'lmkdir -p .'
            'lmkdir -p repeated//parent///child/'
        ) | & $sftp -b - -D "`"$sftpServer`"" > $outputFile 2> $errorFile
        $LASTEXITCODE | Should be 0
        Test-Path -LiteralPath (Join-Path $root 'repeated\parent\child') -PathType Container |
            Should be $true
    }

    It 'Creates missing parents for <Kind> paths' -TestCases @(
        @{ Kind = 'UNC'; Prefix = '' },
        @{ Kind = 'prefixed-UNC'; Prefix = '/' }
    ) {
        param($Kind, $Prefix)
        $share = '//localhost/' + $root.Substring(0, 1) + '$'
        if (-not (Test-Path -LiteralPath $share)) {
            Set-TestInconclusive 'UNC coverage requires access to the existing loopback administrative share.'
        }
        $target = $Prefix + $share + $root.Substring(2).Replace('\', '/') +
            '/unc/parent/child'
        @(
            "lmkdir -p `"$Prefix$share`""
            "lmkdir -p `"$target`""
            "lmkdir -p `"$target`""
        ) | & $sftp -b - -D "`"$sftpServer`"" > $outputFile 2> $errorFile
        $LASTEXITCODE | Should be 0
        Test-Path -LiteralPath (Join-Path $root 'unc\parent\child') -PathType Container |
            Should be $true
    }

    It 'Rejects a file as the <Kind> component' -TestCases @(
        @{ Kind = 'final'; Suffix = '' },
        @{ Kind = 'intermediate'; Suffix = '/child' }
    ) {
        param($Kind, $Suffix)
        $file = Join-Path $root 'ordinary-file'
        Set-Content -LiteralPath $file -Value 'not a directory'
        @(
            "lcd `"$root`""
            "lmkdir -p ordinary-file$Suffix"
        ) | & $sftp -b - -D "`"$sftpServer`"" > $outputFile 2> $errorFile
        $LASTEXITCODE | Should not be 0
        Test-Path -LiteralPath $file -PathType Leaf | Should be $true
        Test-Path -LiteralPath (Join-Path $file 'child') | Should be $false
    }
}

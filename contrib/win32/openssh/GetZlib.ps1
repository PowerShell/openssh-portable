param 
(
    [string]$ZLibUrl = 'https://zlib.net/zlib1211.zip',
    [string]$SourceDirectory = $null,
    [string]$TargetLibrary = $null
)

Set-StrictMode -Version 2.0

# Exit immediately if compiled zip file already exist
If (-not [string]::IsNullOrEmpty($TargetLibrary))
{
    If (Test-Path -LiteralPath $TargetLibrary)
    {
        Exit 0
    }
}

# Workaround that $PSScriptRoot is not support on ps version 2
If ($PSVersiontable.PSVersion.Major -le 2)
{
    $PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
}

# Allow broad arrange of TLS protocols to do download
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor `
                                              [Net.SecurityProtocolType]::Tls11 -bor `
                                              [Net.SecurityProtocolType]::Tls

# Download Zlib to local directory
$ZlibZipLocalPath = Join-Path ([System.IO.Path]::GetTempPath()) 'Zlib.zip'
Invoke-WebRequest -Uri $ZLibUrl -OutFile $ZlibZipLocalPath


# Set the project directory
If ([string]::IsNullOrEmpty($SourceDirectory))
{
    $SourceDirectory = Join-Path $PSScriptRoot 'zlib'
}

# Ensure the destination directory exists
New-Item -ItemType Directory $SourceDirectory -ErrorAction SilentlyContinue | Out-Null

# Expand the zip file
$ZlibTempDir = Join-Path ([System.IO.Path]::GetTempPath()) 'Zlib'
Expand-Archive -Path $ZlibZipLocalPath -DestinationPath $ZlibTempDir -Force -ErrorAction SilentlyContinue
$SourceDirectory = Get-Item $SourceDirectory | Select-Object -ExpandProperty FullName
Get-ChildItem -Path "${ZlibTempDir}\*\*.c" | Copy-Item -Destination $SourceDirectory -Force
Get-ChildItem -Path "${ZlibTempDir}\*\*.h" | Copy-Item -Destination $SourceDirectory -Force

# Cleanup local zip file
Remove-Item $ZlibZipLocalPath -Force -ErrorAction SilentlyContinue
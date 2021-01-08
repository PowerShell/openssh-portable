[CmdletBinding()]
param (
  [Parameter()]
  [ValidateNotNullOrEmpty()]
  [string]
  $REPO_URL = ${env:REPO_URL},

  [Parameter()]
  [ValidateNotNullOrEmpty()]
  [string]
  $REPO_DIRECTORY = ${env:REPO_DIRECTORY},

  [Parameter()]
  [ValidateNotNullOrEmpty()]
  [string]
  $BUILD_BRANCH = ${env:BUILD_BRANCH},

  [Parameter()]
  [ValidateNotNullOrEmpty()]
  [string]
  $BUILD_TAG = ${env:BUILD_TAG},

  [Parameter()]
  [ValidateNotNullOrEmpty()]
  [string[]]
  $PLATFORM = $env:Platform -split '[|,;]',

  [Parameter()]
  [ValidateNotNullOrEmpty()]
  [string]
  $CONFIGURATION = ${env:CONFIGURATION},

  [Parameter()]
  [ValidateNotNullOrEmpty()]
  [string]
  $InstallDirectory = ${env:InstallDirectory},

  [Parameter()]
  [ValidateNotNullOrEmpty()]
  [Alias("OutputDirectory")]
  [string]
  $BinariesDirectory = ${env:BinariesDirectory},

  [Parameter()]
  [ValidateNotNullOrEmpty()]
  [string]
  $BuildMsi = ${env:BuildMsi},

  [Parameter()]
  [ValidateNotNullOrEmpty()]
  [string]
  $BuildOpenSSH = ${env:BuildOpenSSH}
)

$script:ErrorActionPreference = 'Stop'
$env:GIT_SSH_COMMAND = 'ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no'

Write-Host -ForegroundColor White @"
                                      _          __                            _             _
  ___   _ __    ___  _ __   ___  ___ | |__      / _|  ___   _ __    __      __(_) _ __    __| |  ___  __      __ ___
 / _ \ | '_ \  / _ \| '_ \ / __|/ __|| '_ \    | |_  / _ \ | '__|   \ \ /\ / /| || '_ \  / _` | / _ \ \ \ /\ / // __|
| (_) || |_) ||  __/| | | |\__ \\__ \| | | |   |  _|| (_) || |       \ V  V / | || | | || (_| || (_) | \ V  V / \__ \
 \___/ | .__/  \___||_| |_||___/|___/|_| |_|   |_|   \___/ |_|        \_/\_/  |_||_| |_| \__,_| \___/   \_/\_/  |___/
       |_|


    Repository                  : ${REPO_URL}
    Local Respository Directory : ${REPO_DIRECTORY}
    Build Branch                : ${BUILD_BRANCH}
    Build Tag                   : ${BUILD_TAG}
    Platform                    : ${PLATFORM}
    Configuration               : ${CONFIGURATION}
    Build Directory             : ${InstallDirectory}
    Binaries Directory          : ${BinariesDirectory}
    Build OpenSHH               : ${BuildOpenSSH}
    Build MSI                   : ${BuildMsi}

"@

@(
  @{
    Name        = "Validate parameters"
    ScriptBlock = {
      'REPO_URL', 'REPO_DIRECTORY', 'BUILD_BRANCH', 'BUILD_TAG', 'PLATFORM', 'CONFIGURATION', 'InstallDirectory', 'BinariesDirectory' `
      | ForEach-Object -Process {
        $paramName = $_
        if ([string]::IsNullOrWhiteSpace((Get-Variable -Name $paramName -ValueOnly))) {
          throw "Required parameter $($paramName) not specified"
        }
      }
    }
  },
  @{
    Name        = "Cloning repository"
    ScriptBlock = {
      if (Test-Path -Path ${REPO_DIRECTORY}) {
        Write-Host -ForegroundColor White "Repository already checked out to ${REPO_DIRECTORY} => skipping git clone ..."
      } else {
        git clone ${REPO_URL} ${REPO_DIRECTORY}
        if (0 -ne $LASTEXITCODE) {
          throw "Failed to clone OpenSSH repository. Error: $LASTEXITCODE"
        }
      }
    }
  },
  @{
    Name        = "Detect build tag"
    ScriptBlock = {
      Push-Location -LiteralPath ${REPO_DIRECTORY}
      git checkout ${BUILD_BRANCH}
      if (0 -ne $LASTEXITCODE) {
        throw "Failed to checkout branch [${BUILD_BRANCH}]. Error: $LASTEXITCODE"
      }
      git fetch --quiet --tags
      if (0 -ne $LASTEXITCODE) {
        throw "Failed to load all tags. Error: $LASTEXITCODE"
      }
      $buildTag = ${BUILD_TAG}
      if ('head' -eq $buildTag) {
        Write-Verbose -Message 'Build on last commit (HEAD) in branch ${BUILD_BRANCH}'
        $buildTag = "${BUILD_BRANCH}-${BUILD_TAG}"
      } else {
        if ('latest' -eq $buildTag) {
          $buildTag = git describe --tags $(git rev-list --tags --max-count=1)
          if (0 -ne $LASTEXITCODE) {
            throw "Failed to find latest tag on build branch ${BUILD_BRANCH}. Error: $LASTEXITCODE"
          }
        }
        git checkout --quiet --force $buildTag
        if (0 -ne $LASTEXITCODE) {
          throw "Failed to checkout $buildTag. Error: $LASTEXITCODE"
        }
      }
      Pop-Location

      Write-Host -ForegroundColor White "Checked out build tag: $buildTag"
    }
  },
  @{
    Name        = "Building OpenSSH"
    ScriptBlock = {
      $cmdBuild = Get-Command -CommandType ExternalScript -Name "${InstallDirectory}\build\build-openssh.ps1" -ErrorAction:Continue
      if (-not $cmdBuild) {
        throw "Failed to get command object for external script at [${InstallDirectory}\build\build-openssh.ps1]"
      } else {
        ${PLATFORM} `
        | ForEach-Object -Process {

          Write-Host -ForegroundColor White "Building OpenSSH for configuration $_/${CONFIGURATION}"

          $argv = @{
            ProjectDirectory = "${REPO_DIRECTORY}"
            Configuration    = "${CONFIGURATION}"
            Platform         = "$_"
            Verbose          = $true
            DestinationPath  = "${BinariesDirectory}\${CONFIGURATION}\$_"
          }
          & $cmdBuild @argv
        }
      }
    }
    Condition   = [string]::IsNullOrWhiteSpace(${BuildOpenSSH}) -or ${BuildOpenSSH} -match "true|1|yes|on"
  },
  @{
    Name        = "Building MSI"
    ScriptBlock = {
      $cmdBuild = Get-Command -CommandType ExternalScript -Name "${InstallDirectory}\build\build-msi.ps1" -ErrorAction:Continue
      if (-not $cmdBuild) {
        throw "Failed to get command object for external script at [${InstallDirectory}\build\build-msi.ps1]"
      } else {
        ${PLATFORM} `
        | ForEach-Object -Process {

          Write-Host -ForegroundColor White "Building MSI for configuration $_/${CONFIGURATION}"

          $argv = @{
            ProjectPath     = "${InstallDirectory}\install\openssh-install.wixproj"
            SourceDirectory = "${BinariesDirectory}\${CONFIGURATION}\$_"
            Configuration   = "${CONFIGURATION}"
            Platform        = "$_"
            Verbose         = $true
            DestinationPath = "${BinariesDirectory}\${CONFIGURATION}\$_"
          }
          & $cmdBuild @argv
        }
      }
    }
    Condition   = [string]::IsNullOrWhiteSpace(${BuildMsi}) -or ${BuildMsi} -match "true|1|yes|on"
  }
) `
| ForEach-Object -Process {
  $task = $_

  if ($null -eq $task.Condition -or $task.Condition -eq $true) {
    Write-Host ''
    Write-Host -ForegroundColor White -BackgroundColor DarkMagenta "***  Executing Task: $($task.Name)"
    Write-Host ''

    & $task.ScriptBlock

    Write-Host ''
    Write-Host -ForegroundColor Green "*** Task: $($task.Name) successfully executed`n"
    Write-Host ''
  } else {
    Write-Host ''
    Write-Host -ForegroundColor Yellow -BackgroundColor DarkMagenta "*** Skipping Task: $($task.Name)"
    Write-Host ''
  }
}

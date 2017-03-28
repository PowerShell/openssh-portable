Run OpenSSH Pester Tests:
==================================

#### To setup the test environment before test run:

```powershell
Import-Module  .\openssh-portable\contrib\win32\openssh\appveyor.psm1 –Force
Setup-OpenSSHTestEnvironment
```

`Setup-OpenSSHTestEnvironment` performs the following actions (with user's confirmation) on the machine for test purpose:
* sshd_config will be backed up as sshd_config.ori and be replaced with a test sshd_config
* `$HOME\.ssh\known_hosts` will be backed up as known_hosts.ori and be replaced with a test known_hosts
* sshd test listener will be on port 47002
* `$HOME\.ssh\known_hosts` will be modified with test host key entry
* Add test accounts: ssouser, pubkeyuser, and passwduser
* Install test dependencies and deploy test binaries and data to `$OpenSSHTestDir`
* Setup single signon for ssouser
* Initialized a global variable $Global:OpenSSHTestInfo to store the test states used by all E2E tests. The states includes: 
    - Target, Port, SSOUser, PubKeyUser, PasswdUser, TestAccountPW, OpenSSHDir, OpenSSHTestDir, TestSetupLogFile, E2ETestResultsFile, UnitTestResultsFile, DebugMode

The function has 3 parameters:
* `-OpenSSHDir`: Specify the location where ssh.exe should be picked up. If not specified, the function will prompt to user if he/she want to choose the first ssh.exe found in `$env:path` if exists.
* `-OpenSSHTestDir`: Specify the location where the test binaries deploy to. The default is `$env:SystemDrive\OpenSSHTests` if it not specified.
* `-Quiet`: If it is set, the function will do all the changes without prompting to user to confirm.

#### To run the test suites:

```powershell
Run-OpenSSHE2ETest
Run-OpenSSHUnitTest
```

#### To run a particular test, just run the script or the executatlbe directly

```powershell
C:\OpenSSHTests\scp.tests.ps1
C:\OpenSSHTests\unittest-bitmap\unittest-bitmap.exe
```
#### To revert what's done in Setup-OpenSSHTestEnvironment:

```powershell
Cleanup-OpenSSHTestEnvironment
```

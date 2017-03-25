Run OpenSSH EndToEnd Tests:
1. Import-Module  .\openssh-portable\contrib\win32\openssh\appveyor.psm1 –Force
2. Setup-OpenSSHTestEnvironment
	Note: The function Setup-OpenSSHTestEnvironment will do the following actions (with user's confirmation) on the machine for test purpose:
	- sshd_config will be backed up as sshd_config.ori and be replaced with a test sshd_config
	- $HOME\.ssh\known_hosts will be backed up as known_hosts.ori and be replaced with a test known_hosts
	- sshd test listener will be on port 47002
	- $HOME\.ssh\known_hosts will be modified with test host key entry
	- Added test accounts - ssouser, pubkeyuser, and passwduser will be added
	- Install all test dependencies and deploy test binaries and data to $OpenSSHTestDir
	- Setup single sign on for ssouser
	- Initialized a global variable $Global:OpenSSHTestInfo to store the test states used by all E2E tests. The states includes: 
		- Target, Port, SSOUser, PubKeyUser, PasswdUser, TestAccountPW, OpenSSHDir, OpenSSHTestDir, TestSetupLogFile, E2ETestResultsFile, UnitTestResultsFile

	The function has 3 parameters:
 		a. -OpenSSHDir -- Specify the location where ssh.exe should be picked up. If not specified, the function will prompt to user if he/she want to choose the first ssh.exe found in %path% if exists.
		b. -OpenSSHTestDir: Specify the location where the test binaries deploy to. The default is $env:SystemDrive\OpenSSHTests if it not specified.
		c. -Quiet: If it is set, the function will do all the changes without prompting to user to confirm.
3. Run-OpenSSHE2ETest
	Note: the E2E test result file is at $Global:OpenSSHTestInfo["E2ETestResultsFile"]
	Or user run a particular tests by directly running the script. For example, C:\OpenSSHTests\scp.tests.ps1
4. Run-OpenSSHUnitTest
	Note: the unit test result file is at $Global:OpenSSHTestInfo["UnitTestResultsFile"]
	or user can a particular test by running the test executable. For example, C:\OpenSSHTests\unittest-bitmap\unittest-bitmap.exe
5. Cleanup-OpenSSHTestEnvironment
	Note: this function will revert what's done in Setup-OpenSSHTestEnvironment

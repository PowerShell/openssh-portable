Run OpenSSH Pester Tests:
==================================

#### To setup the test environment before test run:

```powershell
Import-Module  .\openssh-portable\contrib\win32\openssh\OpenSSHTestHelper.psm1 –Force
Setup-OpenSSHTestEnvironment
```

`Set-OpenSSHTestEnvironment` contains below parameters:
* `-OpenSSHBinPath`: Specify the location where ssh.exe should be picked up. If not specified, the function will prompt to user if he/she want to choose the first ssh.exe found in `$env:path` if exists.
* `-TestDataPath`: Specify the location where the test binaries deploy to. The default is `$env:SystemDrive\OpenSSHTests` if it not specified.
* `-Quiet`: If it is set, the function will do all the changes without prompting to user to confirm.
* `-DebugMode`: If it is set, the subsequent tests will be running in debug mode. User can modify by setting $OpenSSHTestInfo["DebugMode"] .

#### To run the test suites:

```powershell
Run-OpenSSHE2ETest
Run-OpenSSHUnitTest
```

#### To run a particular test, just run the script or the executatlbe directly

```powershell
C:\git\openssh-portable\regress\pesterTests\SCP.Tests.ps1
C:\git\openssh-portable\bin\x64\Release\unittest-bitmap\unittest-bitmap.exe
```

#### To verify / modify (Ex- DebugMode) the Test setup environment 

```powershell
$OpenSSHTestInfo
$OpenSSHTestInfo["DebugMode"] = $true
```

#### To revert what's done in Setup-OpenSSHTestEnvironment:

```powershell
Cleanup-OpenSSHTestEnvironment
```


#### Guidelines for writing Pester based OpenSSH test cases
Follow these simple steps for test case indexing
- Initialize the following variables at start
```  
  $tC = 1
  $tI = 0
```
- Place the following blocks in Describe
```
    BeforeEach {
        $stderrFile=Join-Path $testDir "$tC.$tI.stderr.txt"
        $stdoutFile=Join-Path $testDir "$tC.$tI.stdout.txt"
        $logFile = Join-Path $testDir "$tC.$tI.log.txt"
    }        
    AfterEach {$tI++;}
```
- Place the following blocks in each Context
```
  BeforeAll {$tI=1}
  AfterAll{$tC++}
```
- Prefix any test out file with $tC.$tI. You may use pre-created $stderrFile, $stdoutFile, $logFile for this purpose

#### PKCS#11 certificate tests

The Windows agent rejects PKCS#11 adds with lifetime, confirmation, or
destination constraints because persisted identities cannot enforce them.
This applies both to plain keys and to associated certificates. Adds without
these constraints, including certificate-only adds, remain supported. Existing
Registry identities are not migrated or removed.

`PKCS11Constraints.Tests.ps1` is a required CI test that sends raw agent
requests without a provider DLL, PIN, or token. It checks rejection of all
three constraints, including combinations with RSA/ECDSA certificates,
unchanged identities and Registry subkey names, and continued use of the same
connection. It requires the test agent to be running and permission to read
the test user's agent Registry keys; missing prerequisites fail the test.

`PKCS11Certificates.Tests.ps1` runs through the dedicated runner, which is
mandatory in the x64 Azure core job and in local `Invoke-OpenSSHTests.ps1`
E2E runs for x64/x86. ARM/ARM64 retain the core tests and report a warning
that SoftHSM certificate coverage is unavailable. Core Pester runs first;
the software-certificate removal test restores
the harness's previously loaded SSO key so later authentication suites can use
it. The managed harness then removes its remaining
SSO identity before starting the isolated certificate fixture. Do not invoke
this suite directly without its fixture.

Run from an elevated 64-bit PowerShell 7.2 or newer, including for x86 builds,
with Pester 3 or 4 installed (maximum 4.9.9; Pester 5 is incompatible).
The runner uses the repository's OpenSSHUtils module in its private fixture;
no machine-wide OpenSSHUtils installation is required.

```powershell
./.github/tools/Invoke-PKCS11CertificateTests.ps1 -OpenSSHBinPath ./bin/x64/Release
./.github/tools/Invoke-PKCS11CertificateTests.ps1 -OpenSSHBinPath ./bin/Win32/Release -Architecture x86
```

The runner downloads the public Disig SoftHSM 2.5.0 portable Windows package
and requires SHA256
`85273BCC1A6B90E877F7BB4F7E90221D57103D8F5241D154A79DD730A135B910`.
A verified cache supports subsequent offline runs. Both provider architectures
are checked against the selected OpenSSH executables; the bundled 32-bit
import utility always uses the 32-bit DLL. This package supports ECDSA P-256.
Fresh RSA-2048 and ECDSA-P-256 keys and random token PINs are created for each
run. The DLL stays under Program Files, preserving the agent's provider
allowlist (Program Files (x86) for the 32-bit agent). `SOFTHSM2_CONF` is installed
in the service and test user's environments: the helper's user environment can
override the service value. Both take effect before the service starts.
Restart/reload is exercised during tests.

All expected cases must pass. Missing prerequisites, failed setup,
missing/duplicate results, skips, pending cases and timeouts fail the required
run. Native commands have a 30-second limit, service transitions 60 seconds,
and the Pester subprocess 10 minutes. Only download transport errors retry.
The NUnit report and summary contain no PIN, private key or token contents.

Local mode is the default. It requires an empty test agent Registry and an
absent service or one installed from the selected build. It journals the
original service configuration before mutation, restores it in `finally`,
and removes the owned fixture and test Registry entries. Journal version 3
records the original user's SID, the agent executable path and the cleanup
phase. A service Registry value, `OpenSSHPkcs11TestRunId`, ties the service to
the journal's run ID. Recovery checks the user, executable path and marker
before changing the service, Registry or user environment. Concurrent local
runs are rejected. After an interrupted process, recover as the original
test user with:

```powershell
./.github/tools/Invoke-PKCS11CertificateTests.ps1 -CleanupOnly
```

The next local run also recovers stale journals. Foreign users, changed or
unmarked services, and old version-2 journals are rejected and require manual
recovery; there is no automatic ownership inference or migration. A running
agent with a disabled startup type is restarted temporarily as Manual before
restoring Disabled. Restore failures retain the fixture and journal. Once
restoration is journalled, repeated cleanup only finalizes the owned fixture,
service marker and journal; it does not reset identities or environments again.
The RSA/ECDSA certificate integration tests remain mandatory for x64/x86.
Protected fixture/journal directories stay on the local machine; no external
VM snapshot is needed.
Azure uses `-CleanupMode None` on its disposable worker. No additional Azure
cleanup step is added. A maintainer with repository write access can trigger
`/azp run`; local validation does not establish that the remote job passed.

Optional hardware runs use `-Mode Hardware` with these environment variables:

* `OPENSSH_TEST_PKCS11_PROVIDER`: absolute path to a PKCS#11 provider DLL.
* `OPENSSH_TEST_PKCS11_PIN`: token PIN.
* `OPENSSH_TEST_PKCS11_PUBLIC_KEYS`: semicolon-separated public-key files for
  both RSA and ECDSA P-256 private keys present on the token.
* `OPENSSH_TEST_PKCS11_LABELS`: corresponding semicolon-separated labels.
  An empty item expects the canonical provider path fallback.
* `OPENSSH_TEST_PKCS11_SOFTWARE_KEY` (optional): unencrypted private key whose
  public key equals the first public-key entry, for the software identity
  and software certificate preservation/detachment cases. Never export a
  production hardware key.

Absent hardware prerequisites produce actual Pester skips with the missing
prerequisite in the case name. Incorrect configured paths or failed hardware
operations fail. PIN input always uses the test askpass helper with forced
noninteractive input. Real YubiKey validation remains a separate hardware run.

The suite covers add/list/sign for both algorithms, mixed and certificate-only
identities, unmatched certificates, individual deletion, provider removal,
service restart/reload, comments and Registry compatibility, rollback after a
Registry write failure, software identity preservation/detachment, and stale
or corrupt provider records. The existing encrypted-PIN model is unchanged.

Certificate adds are idempotent by exact certificate blob. Re-adding a
certificate already held by software or another token provider succeeds
without changing its private key, comment or signing source. Different
certificates of the same public key remain separate identities. A request
containing only existing software certificates does not create a provider
record. Constraints, allowlists and remote-provider restrictions still apply.
Unreadable or inconsistent affected Registry entries fail the request.

Adding a software certificate takes over the identical token certificate:
the software identity is saved at its usual fingerprint before that one token
entry is deleted. Other keys, certificates and the provider record remain.
Write or delete failures restore the original software values and types.
A successful software re-add also removes an identical pre-existing token
duplicate; existing stores are not migrated in bulk. The two certificate
preservation/detachment cases cover both load orders, repeats, comments,
signing sources, distinct certificates of one key, Registry failures,
provider removal, individual deletion and restart, for RSA and ECDSA in
SoftHSM mode. Hardware mode uses only the configured software key.

The Bash runner installs `SOFTHSM2_CONF` in the test agent's service
environment before starting it, including when `p11_setup` automatically
discovers a default SoftHSM DLL. It preserves unrelated environment entries
in their original order and restores the original value at cleanup (or
removes the value it created). An already running test agent is restarted
to apply the configuration; foreign service executables are rejected.
Missing SoftHSM or OpenSSL does not prevent unrelated Bash regressions.

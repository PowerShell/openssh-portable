# Win32-OpenSSH code coverage

Tooling to produce a **C code coverage estimate** for the Windows solution
(`contrib\win32\openssh\Win32-OpenSSH.sln`) across all three test suites that
ship with this repository, and to **aggregate** them into a single
de-duplicated number that accounts for overlap between the suites.

## Files

| File | Purpose |
|------|---------|
| `OpenSSHCodeCoverage.psm1` | Module. Pure aggregation/overlap helpers **and** Microsoft.CodeCoverage.Console orchestration. |
| `OpenSSHCodeCoverage.tests.ps1` | Pester 5 tests for the pure helpers (no build required). |
| `Invoke-AzDOCodeCoverage.ps1` | Per-suite CI entry point: run one suite (Core/Bash) under coverage against an installed OpenSSH dir, producing a per-suite report. |
| `Invoke-AzDOCoverageAggregate.ps1` | CI aggregation entry point: merge the per-suite artifacts from the Core and Bash jobs into the combined, de-duplicated report + summaries. |

All files live in `contrib\win32\openssh\code_coverage\`.

## Why Microsoft.CodeCoverage.Console

[Microsoft.CodeCoverage.Console](https://learn.microsoft.com/visualstudio/test/microsoft-code-coverage-console-tool)
is the Microsoft-maintained coverage tool that ships with Visual Studio 2022
(17.3+). Native C/C++ coverage requires the **Enterprise** edition (the hosted
`windows-latest` Azure DevOps image includes it). It:

- collects **native C/C++** line coverage via **static instrumentation** — the
  binaries are built with the `/PROFILE` linker switch and rewritten on disk by
  the `instrument` command,
- supports **server mode** (`collect --session-id <id> --server-mode`): every
  instrumented process that runs while the collector owns the session reports
  in by session id — including `sshd.exe` running as a Windows **service**,
  which is *not* a child of the collector,
- emits `.coverage` (re-mergeable) and, via `merge`, **Cobertura XML**.

Server mode is why coverage captures the E2E/bash suites: those drive a real
sshd service plus `ssh.exe`/`sftp.exe` clients, none of which are children of a
single wrapped process.

## How aggregation and overlap work

Each suite is measured independently and produces its own `.coverage` +
Cobertura report. The `.coverage` files are then merged natively
(`merge ... -f cobertura`). Merging **unions per-line hit counts**, so a line
exercised by two suites is counted exactly once in the combined total — that is
the de-duplication that makes the aggregate honest.

The pure helpers additionally quantify the redundancy:

```
SumCoveredLines      = covered lines summed across suites (double counts overlap)
CombinedCoveredLines = covered lines after merge (each line once)   <- the estimate
OverlapLines         = SumCoveredLines - CombinedCoveredLines
```

### Third-party exclusion

Vendored dependencies built through vcpkg (e.g. zlib) are linked into the
OpenSSH binaries and therefore show up in the raw coverage data, but they are
not OpenSSH code and only dilute the estimate. Any source whose
repository-relative path matches `$script:CoverageExcludePattern` (default
`(^|/)vcpkg/`) is dropped: `Import-CoberturaCoverage` skips it in the summary,
and `Remove-ExcludedCoverageClasses` strips it from the published
`merged.cobertura.xml` (recomputing the package/root line counters) so the
Cobertura report matches the summary.

## Usage

Coverage normally runs in CI (see below). To reproduce locally you need
Visual Studio 2022 **Enterprise** (17.3+) — for both the build tools and
`Microsoft.CodeCoverage.Console.exe` — plus the test-suite prerequisites
(Cygwin for the bash suite, Pester for E2E; the existing helpers install these).

First build and install the solution with `/PROFILE` so the binaries can be
instrumented (the CI build job does this by injecting `/PROFILE` via the linker
`LINK` env var), then point `Invoke-AzDOCodeCoverage.ps1` at the installed
directory. The core flow ends by uninstalling OpenSSH, so re-install before the
bash suite (in CI each suite runs on its own agent, so this is unnecessary
there):

```powershell
cd contrib\win32\openssh\code_coverage

# Core = setup + unit + E2E, into one output dir:
.\Invoke-AzDOCodeCoverage.ps1 -Suite Core -OpenSSHBinPath C:\OpenSSH -OutputDirectory C:\cov -SkipAggregation

# Re-install OpenSSH (the core flow's uninstall test removed it), then bash:
Install-OpenSSH -SourceDir <coverage-build> -OpenSSHDir C:\OpenSSH
.\Invoke-AzDOCodeCoverage.ps1 -Suite Bash -OpenSSHBinPath C:\OpenSSH -OutputDirectory C:\cov -SkipAggregation

# Combine the per-suite reports into the de-duplicated aggregate:
.\Invoke-AzDOCoverageAggregate.ps1 -InputDirectory C:\cov
```

Omit `-SkipAggregation` on a single-suite run to get the merge/summary for just
that suite.

### Output artifacts (under `-OutputDirectory`)

```
core\core.coverage,  core\core.cobertura.xml       per-suite (setup + unit + E2E)
bash\bash.coverage,  bash\bash.cobertura.xml       per-suite (bash tests)
merged\merged.cobertura.xml                        combined, native merge (per-binary)
merged\merged-helper.cobertura.xml                 combined, de-duplicated by source file
coverage-summary.json                              machine-readable summary
coverage-summary.md                                per-suite + combined + overlap table
```

Two combined reports are emitted because they answer different questions:

- **`merged-helper.cobertura.xml`** is de-duplicated by unique source file — a
  `.c` linked into several binaries is counted once. This matches the
  `coverage-summary.md` estimate and is the report published to the Azure DevOps
  **Code Coverage widget** (see CI section).
- **`merged.cobertura.xml`** is the native Microsoft.CodeCoverage.Console merge.
  It preserves per-binary packages, per-method coverage, cyclomatic complexity
  and branch data, but counts each shared `.c` once **per binary** it is linked
  into (~3.6x inflation on this solution). It is kept in the uploaded artifact
  for per-binary / per-method drill-down (e.g. reopening the `.coverage` files in
  Visual Studio).

Example `coverage-summary.md`:

```
| Suite | Covered | Total | Line % |
|-------|--------:|------:|-------:|
| core  |    9633 | 20144 |  47.8% |
| bash  |   11002 | 20144 |  54.6% |
| **Combined (deduped)** | **13120** | **20144** | **65.1%** |

## Overlap between suites
- Sum of per-suite covered lines: 20635
- Combined (de-duplicated) covered lines: 13120
- Overlapping covered lines: 7515 (36.42% of the sum)
```

## Validating the helpers

The aggregation/overlap logic is unit tested and does **not** require a build,
Microsoft.CodeCoverage.Console, or the OpenSSH suites:

```powershell
Invoke-Pester -Path .\OpenSSHCodeCoverage.tests.ps1 -Output Detailed
```

## Continuous integration (Azure DevOps)

Coverage is wired into `.azdo/ci.yml` as dedicated, **PR-only, non-gating** jobs
(they never run on branch builds, where CodeQL already competes for the ~60 min
agent budget, and `continueOnError: true` so they never block a merge):

1. **Build Coverage Package (x64 Debug + /PROFILE)** — a Build-stage job that
   builds the solution `Debug|x64` with `/PROFILE` injected via the linker
   `LINK` env var (no `.vcxproj` edits), publishing `Win32-OpenSSH-Coverage-x64`
   and `UnitTests-Coverage-x64` (binaries + PDBs). It runs in parallel with the
   normal Release build.
2. **Win32-OpenSSH Code Coverage (Core)** and **(Bash)** — two Test-stage jobs
   that each install the coverage build to `C:\OpenSSH` on their own agent and
   run `Invoke-AzDOCodeCoverage.ps1 -Suite Core` (setup + unit + E2E) or
   `-Suite Bash` with `-SkipAggregation`. Running the suites in separate jobs
   (instead of sequentially in one job) gives each a clean install with no
   file-lock or service-state contention, and lets them run in parallel. Each
   publishes its per-suite report as `Win32-OpenSSH-CodeCoverage-Core` /
   `-Bash`.
3. **Win32-OpenSSH Code Coverage (Aggregate)** — a Test-stage job that depends on
   the two suite jobs, downloads their per-suite artifacts, and runs
   `Invoke-AzDOCoverageAggregate.ps1` to produce the merged reports. It publishes
   the **de-duplicated** report (`merged/merged-helper.cobertura.xml`) via
   `PublishCodeCoverageResults@2` so the Code Coverage widget headline matches the
   `coverage-summary.md` estimate, and uploads the full `Win32-OpenSSH-CodeCoverage`
   artifact (per-suite reports, both merged reports, the raw `.coverage` files, and
   summaries) for per-binary / per-method drill-down.

The suites run the exact CI entry points (`Invoke-OpenSSHTests`,
`Invoke-OpenSSHBashTestsOnly`), so coverage reflects what CI already exercises.

## Notes

- A **Debug** build is used for coverage so line mapping is accurate; optimized
  Release builds can fold/reorder/strip lines and understate coverage.
- Native C/C++ coverage requires **Visual Studio 2022 Enterprise** and binaries
  linked with `/PROFILE`; the coverage build job handles both.
- Coverage is scoped to OpenSSH source files at report time (paths are
  normalized to the repository root), so third-party/system code is excluded.
- The tooling reuses the existing suite entry points, so it measures exactly what
  CI already runs.

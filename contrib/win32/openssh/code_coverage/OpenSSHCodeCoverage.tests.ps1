# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

#
# Unit tests for the pure helper functions in OpenSSHCodeCoverage.psm1.
# These validate the aggregation / overlap logic without needing a build,
# Microsoft.CodeCoverage.Console, or any of the OpenSSH test suites to run.
#
# Run with Pester 5:  Invoke-Pester -Path .\OpenSSHCodeCoverage.tests.ps1
#

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot 'OpenSSHCodeCoverage.psm1') -Force

    # Writes a minimal Cobertura report for one file to $TestDrive and returns the path.
    function New-TestCobertura {
        param(
            [string] $FileName,
            [string] $SourcePath,
            [hashtable] $Lines, # line number -> hits
            [string] $OutFile
        )
        $sb = New-Object System.Text.StringBuilder
        [void] $sb.AppendLine('<?xml version="1.0" encoding="utf-8"?>')
        [void] $sb.AppendLine('<coverage line-rate="0" version="0" timestamp="0">')
        [void] $sb.AppendLine('  <packages><package name="p"><classes>')
        [void] $sb.AppendLine("    <class name=""$FileName"" filename=""$SourcePath""><lines>")
        foreach ($n in ($Lines.Keys | Sort-Object { [int]$_ })) {
            [void] $sb.AppendLine("      <line number=""$n"" hits=""$($Lines[$n])""/>")
        }
        [void] $sb.AppendLine('    </lines></class>')
        [void] $sb.AppendLine('  </classes></package></packages>')
        [void] $sb.AppendLine('</coverage>')
        Set-Content -Path $OutFile -Value $sb.ToString() -NoNewline
        return $OutFile
    }
}

Describe 'ConvertTo-NormalizedCoverageSourcePath' {
    Context 'Repository-root-relative paths' {
        It 'Strips the provided repository root and normalizes separators' {
            $result = ConvertTo-NormalizedCoverageSourcePath -RawPath 'C:\src\openssh-portable\channels.c' -RepositoryRoot 'C:\src\openssh-portable'
            $result | Should -Be 'channels.c'
        }

        It 'Strips a nested source path under the repository root' {
            $result = ConvertTo-NormalizedCoverageSourcePath -RawPath 'C:\src\openssh-portable\openbsd-compat\bsd-misc.c' -RepositoryRoot 'C:\src\openssh-portable'
            $result | Should -Be 'openbsd-compat/bsd-misc.c'
        }

        It 'Is case-insensitive about the repository root' {
            $result = ConvertTo-NormalizedCoverageSourcePath -RawPath 'C:\SRC\OpenSSH-Portable\channels.c' -RepositoryRoot 'C:\src\openssh-portable'
            $result | Should -Be 'channels.c'
        }

        It 'Does not strip a sibling directory that merely shares a prefix' {
            $result = ConvertTo-NormalizedCoverageSourcePath -RawPath 'C:\repository\file.c' -RepositoryRoot 'C:\repo'
            $result | Should -Be 'C:/repository/file.c'
        }
    }

    Context 'CI checkout prefixes' {
        It 'Strips the Azure Pipelines / GitHub Actions Windows prefix' {
            $result = ConvertTo-NormalizedCoverageSourcePath -RawPath 'D:\a\openssh-portable\openssh-portable\sshconnect2.c' -RepositoryRoot ''
            $result | Should -Be 'sshconnect2.c'
        }

        It 'Strips the GitHub Actions Linux prefix' {
            $result = ConvertTo-NormalizedCoverageSourcePath -RawPath '/home/runner/work/openssh-portable/openssh-portable/kex.c' -RepositoryRoot ''
            $result | Should -Be 'kex.c'
        }
    }

    Context 'Already relative paths' {
        It 'Normalizes backslashes and leaves the path otherwise unchanged' {
            $result = ConvertTo-NormalizedCoverageSourcePath -RawPath 'openbsd-compat\bsd-misc.c' -RepositoryRoot 'C:\src\openssh-portable'
            $result | Should -Be 'openbsd-compat/bsd-misc.c'
        }
    }
}

Describe 'Import-CoberturaCoverage' {
    It 'Parses lines and hits keyed by normalized path' {
        $file = Join-Path $TestDrive 'a.cobertura.xml'
        New-TestCobertura -FileName 'channels.c' -SourcePath 'C:\repo\channels.c' -Lines @{ 1 = 5; 2 = 0; 3 = 2 } -OutFile $file | Out-Null

        $map = Import-CoberturaCoverage -Path $file -RepositoryRoot 'C:\repo'
        $map.Keys.Count | Should -Be 1
        $map['channels.c'][1] | Should -Be 5
        $map['channels.c'][2] | Should -Be 0
        $map['channels.c'][3] | Should -Be 2
    }

    It 'Skips vendored third-party (vcpkg) sources' {
        $file = Join-Path $TestDrive 'tp.cobertura.xml'
        New-TestCobertura -FileName 'deflate.c' -SourcePath 'C:\repo\vcpkg\buildtrees\zlib\src\deflate.c' -Lines @{ 1 = 5; 2 = 3 } -OutFile $file | Out-Null

        $map = Import-CoberturaCoverage -Path $file -RepositoryRoot 'C:\repo'
        $map.Keys.Count | Should -Be 0
    }
}

Describe 'Test-CoverageSourceExcluded' {
    It 'Excludes vcpkg-vendored paths' {
        Test-CoverageSourceExcluded -NormalizedPath 'vcpkg/buildtrees/zlib/src/deflate.c' | Should -BeTrue
    }

    It 'Excludes vcpkg even when nested deeper in the tree' {
        Test-CoverageSourceExcluded -NormalizedPath 'contrib/win32/vcpkg/x.c' | Should -BeTrue
    }

    It 'Does not exclude OpenSSH sources' {
        Test-CoverageSourceExcluded -NormalizedPath 'channels.c' | Should -BeFalse
        Test-CoverageSourceExcluded -NormalizedPath 'contrib/win32/win32compat/ansiprsr.c' | Should -BeFalse
    }
}

Describe 'Remove-ExcludedCoverageClasses' {
    It 'Removes third-party classes and recomputes counters' {
        $xml = @'
<?xml version="1.0" encoding="utf-8"?>
<coverage line-rate="0" lines-covered="0" lines-valid="0" version="0" timestamp="0">
  <packages>
    <package name="ssh" line-rate="0" lines-covered="0" lines-valid="0">
      <classes>
        <class name="channels.c" filename="C:\repo\channels.c"><lines>
          <line number="1" hits="5"/><line number="2" hits="0"/>
        </lines></class>
        <class name="deflate.c" filename="C:\repo\vcpkg\buildtrees\zlib\deflate.c"><lines>
          <line number="1" hits="0"/><line number="2" hits="0"/>
        </lines></class>
      </classes>
    </package>
    <package name="zlibonly" line-rate="0" lines-covered="0" lines-valid="0">
      <classes>
        <class name="inflate.c" filename="C:\repo\vcpkg\buildtrees\zlib\inflate.c"><lines>
          <line number="1" hits="9"/>
        </lines></class>
      </classes>
    </package>
  </packages>
</coverage>
'@
        $file = Join-Path $TestDrive 'merged.cobertura.xml'
        Set-Content -Path $file -Value $xml -NoNewline

        $removed = Remove-ExcludedCoverageClasses -Path $file -RepositoryRoot 'C:\repo'
        $removed | Should -Be 2

        [xml] $doc = Get-Content -LiteralPath $file -Raw
        # Only the ssh package with channels.c survives.
        $doc.SelectNodes('//package').Count | Should -Be 1
        $doc.SelectNodes('//class').Count | Should -Be 1
        $doc.SelectSingleNode('//class').GetAttribute('filename') | Should -Match 'channels\.c$'
        # Root counters recomputed from surviving lines: 1 covered of 2 valid.
        $doc.coverage.GetAttribute('lines-valid') | Should -Be '2'
        $doc.coverage.GetAttribute('lines-covered') | Should -Be '1'
        $doc.coverage.GetAttribute('line-rate') | Should -Be '0.5'
    }
}


Describe 'Merge-CoverageData' {
    Context 'Overlapping coverage of the same file/line' {
        It 'Sums hit counts so an overlapping line stays covered once' {
            $suiteA = @{ 'channels.c' = @{ 1 = 5; 2 = 3; 3 = 0 } }
            $suiteB = @{ 'channels.c' = @{ 1 = 1; 2 = 0; 3 = 4 } }

            $merged = Merge-CoverageData -CoverageMap @($suiteA, $suiteB)
            $merged['channels.c'][1] | Should -Be 6   # 5 + 1
            $merged['channels.c'][2] | Should -Be 3   # 3 + 0
            $merged['channels.c'][3] | Should -Be 4   # 0 + 4

            $stat = Get-CoverageStatistic -CoverageMap $merged
            $stat.CoveredLines | Should -Be 3         # all three lines covered
            $stat.TotalLines | Should -Be 3
        }
    }

    Context 'Non-overlapping files from different suites' {
        It 'Keeps both files' {
            $suiteA = @{ 'foo.c' = @{ 1 = 5 } }
            $suiteB = @{ 'bar.c' = @{ 1 = 3 } }
            $merged = Merge-CoverageData -CoverageMap @($suiteA, $suiteB)
            $merged.Keys.Count | Should -Be 2
        }
    }
}

Describe 'Get-CoverageStatistic' {
    It 'Counts only lines with non-zero hits as covered' {
        $map = @{ 'x.c' = @{ 1 = 1; 2 = 0; 3 = 0; 4 = 2 } }
        $stat = Get-CoverageStatistic -CoverageMap $map -Name 'unit'
        $stat.Name | Should -Be 'unit'
        $stat.TotalLines | Should -Be 4
        $stat.CoveredLines | Should -Be 2
        $stat.Percent | Should -Be 50
    }
}

Describe 'Measure-CoverageOverlap' {
    It 'Reports overlap as sum-minus-combined covered lines' {
        # Suite A covers lines 1,2 of foo.c. Suite B covers lines 2,3 of foo.c.
        # Sum covered = 2 + 2 = 4. Combined covered = 3 (lines 1,2,3). Overlap = 1 (line 2).
        $suiteA = @{ 'foo.c' = @{ 1 = 1; 2 = 1 } }
        $suiteB = @{ 'foo.c' = @{ 2 = 1; 3 = 1 } }

        $overlap = Measure-CoverageOverlap -CoverageMap @($suiteA, $suiteB)
        $overlap.SumCoveredLines | Should -Be 4
        $overlap.CombinedCoveredLines | Should -Be 3
        $overlap.OverlapLines | Should -Be 1
        $overlap.OverlapPercent | Should -Be 25
    }

    It 'Reports zero overlap for disjoint suites' {
        $suiteA = @{ 'foo.c' = @{ 1 = 1 } }
        $suiteB = @{ 'bar.c' = @{ 1 = 1 } }
        $overlap = Measure-CoverageOverlap -CoverageMap @($suiteA, $suiteB)
        $overlap.OverlapLines | Should -Be 0
        $overlap.OverlapPercent | Should -Be 0
    }
}

Describe 'New-MergedCoberturaReport' {
    It 'Round-trips a coverage map through Cobertura XML' {
        $map = @{ 'channels.c' = @{ 1 = 5; 2 = 0; 3 = 2 } }
        $out = Join-Path $TestDrive 'merged.cobertura.xml'
        New-MergedCoberturaReport -CoverageMap $map -OutputPath $out | Out-Null

        $reloaded = Import-CoberturaCoverage -Path $out -RepositoryRoot ''
        $reloaded['channels.c'][1] | Should -Be 5
        $reloaded['channels.c'][2] | Should -Be 0
        $reloaded['channels.c'][3] | Should -Be 2
    }
}

Describe 'Get-CoverageSummary / Format-CoverageSummaryMarkdown' {
    It 'Produces a markdown table with a combined row and overlap section' {
        $suiteA = @{ 'foo.c' = @{ 1 = 1; 2 = 1 } }
        $suiteB = @{ 'foo.c' = @{ 2 = 1; 3 = 1 } }
        $statA = Get-CoverageStatistic -CoverageMap $suiteA -Name 'unit'
        $statB = Get-CoverageStatistic -CoverageMap $suiteB -Name 'bash'
        $merged = Merge-CoverageData -CoverageMap @($suiteA, $suiteB)
        $combined = Get-CoverageStatistic -CoverageMap $merged -Name 'combined'
        $overlap = Measure-CoverageOverlap -CoverageMap @($suiteA, $suiteB)

        $summary = Get-CoverageSummary -SuiteStatistic @($statA, $statB) -CombinedStatistic $combined -Overlap $overlap
        $summary.Combined.CoveredLines | Should -Be 3

        $md = Format-CoverageSummaryMarkdown -Summary $summary
        $md | Should -Match 'Combined \(deduped\)'
        $md | Should -Match 'Overlapping covered lines: 1'
    }
}

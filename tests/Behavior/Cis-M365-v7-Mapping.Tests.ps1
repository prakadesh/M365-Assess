# CIS Microsoft 365 Foundations Benchmark v7.0.0 support.
#
# v7 mappings live in controls/cis-m365-v7-mapping.json (a local overlay) rather
# than registry.json, because the CheckID sync rewrites registry.json and
# cis-m365-v6.json wholesale. These tests pin the overlay's internal consistency,
# its agreement with the registry and framework definition, and the loader merge.

BeforeAll {
    $script:controls   = "$PSScriptRoot/../../src/M365-Assess/controls"
    $script:overlay    = Get-Content -Raw -Path "$script:controls/cis-m365-v7-mapping.json" | ConvertFrom-Json
    $script:framework  = Get-Content -Raw -Path "$script:controls/frameworks/cis-m365-v7.json" | ConvertFrom-Json
    $script:registry   = Get-Content -Raw -Path "$script:controls/registry.json" | ConvertFrom-Json
    $script:checkIds   = @($script:registry.checks | ForEach-Object { $_.checkId })
    $script:catalogIds = @($script:overlay.catalog.PSObject.Properties.Name)
    . "$PSScriptRoot/../../src/M365-Assess/Common/Import-ControlRegistry.ps1"
    $script:lookup = Import-ControlRegistry -ControlsPath $script:controls
}

Describe 'CIS M365 v7.0.0 overlay' {
    It 'declares the cis-m365-v7 framework and benchmark version 7.0.0' {
        $script:overlay.frameworkId      | Should -Be 'cis-m365-v7'
        $script:overlay.benchmarkVersion | Should -Be '7.0.0'
    }

    It 'catalogs all 160 v7.0.0 recommendations' {
        $script:catalogIds.Count | Should -Be 160
    }

    It 'gives every catalog entry a title, an assessment status and E3/E5 L1/L2 profiles' {
        foreach ($id in $script:catalogIds) {
            $e = $script:overlay.catalog.$id
            $e.title      | Should -Not -BeNullOrEmpty -Because "$id needs a title"
            $e.assessment | Should -BeIn @('Automated', 'Manual') -Because "$id assessment status"
            @($e.profiles).Count | Should -BeGreaterThan 0 -Because "$id needs at least one profile"
            foreach ($p in @($e.profiles)) { $p | Should -Match '^E[35]-L[12]$' }
        }
    }

    It 'only maps checkIds that exist in registry.json' {
        foreach ($name in $script:overlay.checks.PSObject.Properties.Name) {
            $name | Should -BeIn $script:checkIds -Because "overlay maps $name but the registry has no such check"
        }
    }

    It 'only references controlIds present in the catalog, with matching title and profiles' {
        foreach ($prop in $script:overlay.checks.PSObject.Properties) {
            $m = $prop.Value
            $m.controlId | Should -BeIn $script:catalogIds -Because "$($prop.Name) -> $($m.controlId)"
            $m.title | Should -Be $script:overlay.catalog.($m.controlId).title
            (@($m.profiles) -join ',') | Should -Be (@($script:overlay.catalog.($m.controlId).profiles) -join ',')
        }
    }

    It 'does not map checks to controls removed in v7 (5.1.3.1 dynamic guest group, 7.3.2 OneDrive sync)' {
        $script:overlay.checks.'ENTRA-GROUP-002'.controlId | Should -BeNullOrEmpty
        $script:overlay.checks.'SPO-SYNC-001'.controlId    | Should -BeNullOrEmpty
        $script:overlay.catalog.PSObject.Properties.Name   | Should -Not -Contain '7.3.2'
    }

    It 'follows the v6 -> v7 renumbering: "users cannot create security groups" is 5.1.3.1' {
        $script:overlay.checks.'ENTRA-GROUP-001'.controlId | Should -Be '5.1.3.1'
    }
}

Describe 'cis-m365-v7 framework definition' {
    It 'matches the overlay catalog size and per-profile counts' {
        $script:framework.frameworkId   | Should -Be 'cis-m365-v7'
        $script:framework.totalControls | Should -Be $script:catalogIds.Count
        foreach ($pk in 'E3-L1', 'E3-L2', 'E5-L1', 'E5-L2') {
            $expected = @($script:catalogIds | Where-Object { $pk -in @($script:overlay.catalog.$_.profiles) }).Count
            $script:framework.scoring.profiles.$pk.controlCount | Should -Be $expected -Because $pk
        }
    }

    It 'sorts ahead of cis-m365-v6 so the CIS matrix and defaults pick v7' {
        $script:framework.displayOrder | Should -BeLessThan 1
    }
}

Describe 'Import-ControlRegistry v7 overlay merge' {
    It 'attaches cis-m365-v7 mappings to registry entries' {
        $e = $script:lookup['ENTRA-APPS-001'].frameworks['cis-m365-v7']
        $e.controlId | Should -Be '5.1.2.2'
        $e.title     | Should -Be 'Ensure users cannot register applications'
    }

    It 'keeps the v6 mapping available side by side' {
        $script:lookup['ENTRA-GROUP-002'].frameworks['cis-m365-v6'].controlId | Should -Be '5.1.3.1'
        $script:lookup['ENTRA-GROUP-002'].frameworks.ContainsKey('cis-m365-v7') | Should -BeFalse
    }

    It 'builds the CIS reverse lookup from v7 by default and v6 on request' {
        $script:lookup['__cisReverseLookup']['5.1.3.1'] | Should -Be 'ENTRA-GROUP-001'
        $v6 = Import-ControlRegistry -ControlsPath $script:controls -CisFrameworkId 'cis-m365-v6'
        $v6['__cisReverseLookup']['5.1.3.1'] | Should -Be 'ENTRA-GROUP-002'
    }

    It 'degrades gracefully when the overlay file is absent' {
        $tmp = Join-Path ([System.IO.Path]::GetTempPath()) "m365a-v7-$([guid]::NewGuid())"
        New-Item -ItemType Directory -Path $tmp | Out-Null
        try {
            Copy-Item "$script:controls/registry.json" $tmp
            $r = Import-ControlRegistry -ControlsPath $tmp
            $r['ENTRA-APPS-001'].frameworks.ContainsKey('cis-m365-v7') | Should -BeFalse
            $r['ENTRA-APPS-001'].frameworks.ContainsKey('cis-m365-v6') | Should -BeTrue
        }
        finally { Remove-Item $tmp -Recurse -Force }
    }
}

Describe 'CIS Microsoft 365 v7 crosswalk' {
    BeforeAll {
        . "$PSScriptRoot/../../src/M365-Assess/Common/Import-ControlRegistry.ps1"
        $controlsPath = "$PSScriptRoot/../../src/M365-Assess/controls"
        $registry = Import-ControlRegistry -ControlsPath $controlsPath
    }

    It 'adds a v7 framework mapping without changing the v6 mapping' {
        $entry = $registry['ENTRA-GROUP-001']
        $entry.frameworks.'cis-m365-v6'.controlId | Should -Be '5.1.3.2'
        $entry.frameworks.'cis-m365-v7'.controlId | Should -Be '5.1.3.1'
    }

    It 'does not carry forward the removed v6 dynamic guest group recommendation' {
        $registry['ENTRA-GROUP-002'].frameworks.ContainsKey('cis-m365-v7') | Should -BeFalse
    }

    It 'maps the application-registration setting to the v7 recommendation' {
        $registry['ENTRA-APPREG-001'].frameworks.'cis-m365-v7'.controlId | Should -Be '5.1.2.2'
    }

    It 'maps the Entra lockout threshold to v7 5.2.3.8' {
        $registry['ENTRA-PASSWORD-003'].frameworks.'cis-m365-v7'.controlId | Should -Be '5.2.3.8'
        $registry['ENTRA-PASSWORD-003'].frameworks.'cis-m365-v7'.profiles | Should -Contain 'E3-L1'
        $registry['ENTRA-PASSWORD-003'].frameworks.'cis-m365-v7'.profiles | Should -Contain 'E5-L1'
    }

    It 'maps the dedicated Direct Send finding to v7 6.5.5 Level 2' {
        $registry['EXO-DIRECTSEND-001'].frameworks.'cis-m365-v7'.controlId | Should -Be '6.5.5'
        $registry['EXO-DIRECTSEND-001'].frameworks.'cis-m365-v7'.profiles | Should -Contain 'E3-L2'
        $registry['EXO-DIRECTSEND-001'].frameworks.'cis-m365-v7'.profiles | Should -Contain 'E5-L2'
    }

    It 'updates Intune recommendations moved to Level 1 in v7' {
        $registry['INTUNE-COMPLIANCE-001'].frameworks.'cis-m365-v7'.profiles | Should -Contain 'E3-L1'
        $registry['INTUNE-COMPLIANCE-001'].frameworks.'cis-m365-v7'.profiles | Should -Contain 'E5-L1'
        $registry['INTUNE-ENROLL-001'].frameworks.'cis-m365-v7'.profiles | Should -Contain 'E3-L1'
        $registry['INTUNE-ENROLL-001'].frameworks.'cis-m365-v7'.profiles | Should -Contain 'E5-L1'
    }

    It 'does not map the removed OneDrive sync recommendation' {
        $registry['SPO-SYNC-001'].frameworks.ContainsKey('cis-m365-v7') | Should -BeFalse
    }

    It 'keeps all v7 control IDs within the framework mapping format' {
        $mapped = @($registry.Keys | Where-Object { $_ -ne '__cisReverseLookup' } |
            Where-Object { $registry[$_].frameworks.ContainsKey('cis-m365-v7') })
        $mapped.Count | Should -BeGreaterThan 50
        foreach ($id in $mapped) {
            $registry[$id].frameworks.'cis-m365-v7'.controlId | Should -Match '^\d+(\.\d+){1,3}$'
            $registry[$id].frameworks.'cis-m365-v7'.profiles.Count | Should -BeGreaterThan 0
        }
    }
}

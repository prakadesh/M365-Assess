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

    Context 'v7.0.0 profile corrections and duplicate cleanup' {
        It 'maps 8.6.1 (Teams external collaboration reporting) to E5 Level 1 only' {
            $entry = $registry['TEAMS-REPORTING-001'].frameworks.'cis-m365-v7'
            $entry.controlId | Should -Be '8.6.1'
            $entry.profiles | Should -Be @('E5-L1')
        }

        It 'does not map dead POWERBI duplicate PBI-* checkIds' {
            $pbiKeys = @($registry.Keys | Where-Object { $_ -like 'PBI-*' })
            $pbiKeys | ForEach-Object {
                $registry[$_].frameworks.ContainsKey('cis-m365-v7') | Should -BeFalse
            }
        }

        It 'keeps only the dedicated per-user MFA check on 5.1.2.1' {
            $mappedTo = @($registry.Keys | Where-Object { $_ -ne '__cisReverseLookup' -and
                $registry[$_].frameworks.'cis-m365-v7'.controlId -eq '5.1.2.1' })
            $mappedTo | Should -Contain 'ENTRA-PERUSER-001'
            $mappedTo | Should -Not -Contain 'CA-EXCLUSION-001'
            $mappedTo.Count | Should -Be 1
        }

        It 'keeps only the license-footprint check on 1.1.4' {
            $mappedTo = @($registry.Keys | Where-Object { $_ -ne '__cisReverseLookup' -and
                $registry[$_].frameworks.'cis-m365-v7'.controlId -eq '1.1.4' })
            $mappedTo | Should -Contain 'ENTRA-CLOUDADMIN-002'
            $mappedTo | Should -Not -Contain 'ENTRA-BREAKGLASS-001'
            $mappedTo.Count | Should -Be 1
        }

        It 'keeps the Forms phishing check as the sole mapping for 1.3.5' {
            $mappedTo = @($registry.Keys | Where-Object { $_ -ne '__cisReverseLookup' -and
                $registry[$_].frameworks.'cis-m365-v7'.controlId -eq '1.3.5' })
            $mappedTo | Should -Be @('FORMS-CONFIG-004')
        }

        It 'keeps complementary cloud and sync admin checks on 1.1.1' {
            $mappedTo = @($registry.Keys | Where-Object { $_ -ne '__cisReverseLookup' -and
                $registry[$_].frameworks.'cis-m365-v7'.controlId -eq '1.1.1' })
            $mappedTo | Should -Contain 'ENTRA-CLOUDADMIN-001'
            $mappedTo | Should -Contain 'ENTRA-SYNCADMIN-001'
        }

        It 'drops the generic CA presence check from 5.2.2.3' {
            $registry['ENTRA-CA-001'].frameworks.'cis-m365-v7'.controlId | Should -Not -Be '5.2.2.3'
        }
    }

    Context 'v7 gap-filling checks' {
        It 'maps each new collector check to its v7 control' {
            $expected = @{
                'CA-REAUTH-001'        = '5.2.2.13'
                'CA-TRUSTEDLOC-001'    = '5.2.2.14'
                'CA-GEOBLOCK-001'      = '5.2.2.15'
                'CA-TOKENPROT-001'     = '5.2.2.16'
                'CA-AUTHXFER-001'      = '5.2.2.17'
                'ENTRA-GROUPSET-001'   = '5.1.3.4'
                'ENTRA-APPPWD-001'     = '5.1.5.3'
                'ENTRA-APPPWD-002'     = '5.1.5.4'
                'ENTRA-APPPWD-003'     = '5.1.5.5'
                'ENTRA-APPCERT-001'    = '5.1.5.6'
                'ENTRA-PASSWORD-006'   = '5.2.3.9'
                'ENTRA-AUTHMETHOD-009' = '5.2.3.10'
                'COMPLIANCE-DLP-004'   = '3.2.3'
                'EXO-OWA-PERSONAL-001' = '6.3.2'
            }
            foreach ($checkId in $expected.Keys) {
                $registry[$checkId].frameworks.'cis-m365-v7'.controlId |
                    Should -Be $expected[$checkId] -Because "$checkId must map to $($expected[$checkId])"
            }
        }

        It 'registers every overlay checkId in the merged registry' {
            $overlayRaw = Get-Content -Path "$PSScriptRoot/../../src/M365-Assess/controls/cis-m365-v7-overlay.json" -Raw |
                ConvertFrom-Json
            foreach ($checkId in $overlayRaw.checks.PSObject.Properties.Name) {
                $registry.ContainsKey($checkId) | Should -BeTrue -Because "$checkId must exist in registry"
            }
        }

        It 'covers at least 150 of the 160 v7 controls' {
            $controlIds = $registry.Keys | Where-Object { $_ -ne '__cisReverseLookup' } |
                Where-Object { $registry[$_].frameworks.ContainsKey('cis-m365-v7') } |
                ForEach-Object { $registry[$_].frameworks.'cis-m365-v7'.controlId }
            ($controlIds | Select-Object -Unique).Count | Should -BeGreaterOrEqual 150
        }

        It 'leaves the manual-only v7 controls unmapped' {
            $manualOnly = '2.4.5', '5.1.3.2', '5.1.3.3', '5.2.4.1', '5.2.4.2', '5.2.4.3', '5.2.4.4', '5.2.4.5'
            $controlIds = @($registry.Keys | Where-Object { $_ -ne '__cisReverseLookup' -and
                $registry[$_].frameworks.ContainsKey('cis-m365-v7') } |
                ForEach-Object { $registry[$_].frameworks.'cis-m365-v7'.controlId })
            foreach ($cid in $manualOnly) {
                $controlIds | Should -Not -Contain $cid -Because "$cid is manual-only and must not claim automation"
            }
        }
    }
}

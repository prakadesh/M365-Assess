BeforeDiscovery {
    # Nothing needed at discovery time
}

# CIS Microsoft 365 Foundations Benchmark v7.0.0 additions implemented in
# src/M365-Assess/Entra/EntraCisV7Checks.ps1.

Describe 'EntraCisV7Checks - compliant tenant' {
    BeforeAll {
        function global:Update-CheckProgress { param($CheckId, $Setting, $Status) }
        function global:Get-MgContext { return @{ TenantId = 'test-tenant-id' } }

        Mock Import-Module { }

        $unlimited = '0001-01-01T00:00:00Z'
        $restrictionSet = @{
            passwordCredentials = @(
                @{ restrictionType = 'passwordAddition';       state = 'enabled'; maxLifetime = $null;  restrictForAppsCreatedAfterDateTime = $unlimited }
                @{ restrictionType = 'passwordLifetime';       state = 'enabled'; maxLifetime = 'P90D'; restrictForAppsCreatedAfterDateTime = $unlimited }
                @{ restrictionType = 'customPasswordAddition'; state = 'enabled'; maxLifetime = $null;  restrictForAppsCreatedAfterDateTime = $unlimited }
            )
            keyCredentials = @(
                @{ restrictionType = 'asymmetricKeyLifetime';  state = 'enabled'; maxLifetime = 'P180D'; restrictForAppsCreatedAfterDateTime = $unlimited }
            )
        }
        $script:appPolicy = @{ isEnabled = $true; applicationRestrictions = $restrictionSet; servicePrincipalRestrictions = $restrictionSet }

        Mock Invoke-MgGraphRequest {
            param($Method, $Uri, $Headers, $ErrorAction)
            switch -Wildcard ($Uri) {
                '*/groupSettings' {
                    return @{ value = @(@{ templateId = '62375ab9-6b52-47ed-826b-58e47e0e304b'; values = @(@{ name = 'EnableGroupCreation'; value = 'false' }) }) }
                }
                '*/policies/defaultAppManagementPolicy' { return $script:appPolicy }
                '*/conditionalAccess/namedLocations' {
                    return @{ value = @(
                        @{ '@odata.type' = '#microsoft.graph.ipNamedLocation'; id = 'loc-ip'; displayName = 'HQ'; isTrusted = $true; ipRanges = @(@{ cidrAddress = '203.0.113.0/24' }) }
                        @{ '@odata.type' = '#microsoft.graph.countryNamedLocation'; id = 'loc-country'; displayName = 'Blocked countries'; countriesAndRegions = @('KP') }
                    ) }
                }
                '*/conditionalAccess/policies' {
                    return @{ value = @(
                        @{ id = 'p1'; displayName = 'Reauth 7 days'; state = 'enabled'
                           conditions = @{ users = @{ includeUsers = @('All') }; applications = @{ includeApplications = @('All') }; signInRiskLevels = @(); userRiskLevels = @() }
                           sessionControls = @{ signInFrequency = @{ isEnabled = $true; frequencyInterval = 'timeBased'; type = 'days'; value = 7 } } }
                        @{ id = 'p2'; displayName = 'Geo block'; state = 'enabled'
                           conditions = @{ users = @{ includeUsers = @('All') }; applications = @{ includeApplications = @('All') }
                                           locations = @{ includeLocations = @('loc-country'); excludeLocations = @('AllTrusted') } }
                           grantControls = @{ builtInControls = @('block') } }
                        @{ id = 'p3'; displayName = 'Token protection'; state = 'enabled'
                           conditions = @{ users = @{ includeUsers = @('All') }
                                           applications = @{ includeApplications = @('00000002-0000-0ff1-ce00-000000000000', '00000003-0000-0ff1-ce00-000000000000', 'cc15fd57-2c6c-4117-a88c-83b1d56b4bbe') }
                                           platforms = @{ includePlatforms = @('windows') }; clientAppTypes = @('mobileAppsAndDesktopClients') }
                           sessionControls = @{ secureSignInSession = @{ isEnabled = $true } } }
                        @{ id = 'p4'; displayName = 'Block auth transfer'; state = 'enabled'
                           conditions = @{ users = @{ includeUsers = @('All') }; applications = @{ includeApplications = @('All') }
                                           authenticationFlows = @{ transferMethods = 'authenticationTransfer' } }
                           grantControls = @{ builtInControls = @('block') } }
                    ) }
                }
                '*/authenticationMethodConfigurations/microsoftAuthenticator' {
                    return @{ id = 'MicrosoftAuthenticator'; featureSettings = @{ companionAppAllowedState = @{ state = 'disabled' } } }
                }
                default { throw "Unexpected Graph URI in test: $Uri" }
            }
        }

        . "$PSScriptRoot/../../src/M365-Assess/Common/SecurityConfigHelper.ps1"
        $ctx = Initialize-SecurityConfig
        $settings = $ctx.Settings

        . "$PSScriptRoot/../../src/M365-Assess/Entra/EntraCisV7Checks.ps1"
    }

    It 'Emits all expected CheckIds' {
        $expected = 'ENTRA-GROUP-007', 'ENTRA-APPMGMT-001', 'ENTRA-APPMGMT-002', 'ENTRA-APPMGMT-003', 'ENTRA-APPMGMT-004',
            'CA-REAUTH-001', 'CA-NAMEDLOC-003', 'CA-GEOBLOCK-001', 'CA-TOKENPROT-001', 'CA-AUTHTRANSFER-001', 'ENTRA-AUTHMETHOD-009'
        foreach ($id in $expected) {
            @($settings | Where-Object { $_.CheckId -match "^$id(\.\d+)?$" }).Count | Should -Be 1 -Because "$id should be emitted exactly once"
        }
    }

    It 'All CheckIds follow naming convention' {
        foreach ($setting in ($settings | Where-Object { $_.CheckId })) {
            $setting.CheckId | Should -Match '^[A-Z]+(-[A-Z0-9]+)+-\d{3}(\.\d+)?$'
        }
    }

    It '<id> passes' -ForEach @(
        @{ id = 'ENTRA-GROUP-007' }, @{ id = 'ENTRA-APPMGMT-001' }, @{ id = 'ENTRA-APPMGMT-002' }, @{ id = 'ENTRA-APPMGMT-003' },
        @{ id = 'ENTRA-APPMGMT-004' }, @{ id = 'CA-REAUTH-001' }, @{ id = 'CA-NAMEDLOC-003' }, @{ id = 'CA-GEOBLOCK-001' },
        @{ id = 'CA-TOKENPROT-001' }, @{ id = 'CA-AUTHTRANSFER-001' }, @{ id = 'ENTRA-AUTHMETHOD-009' }
    ) {
        $check = $settings | Where-Object { $_.CheckId -match "^$id(\.\d+)?$" }
        $check.Status | Should -Be 'Pass' -Because $check.CurrentValue
    }
}

Describe 'EntraCisV7Checks - non-compliant tenant' {
    BeforeAll {
        function global:Update-CheckProgress { param($CheckId, $Setting, $Status) }
        function global:Get-MgContext { return @{ TenantId = 'test-tenant-id' } }

        Mock Import-Module { }

        # Tenant that never customized anything: no group setting, empty app policy, no CA policies/locations
        Mock Invoke-MgGraphRequest {
            param($Method, $Uri, $Headers, $ErrorAction)
            switch -Wildcard ($Uri) {
                '*/groupSettings' { return @{ value = @() } }
                '*/policies/defaultAppManagementPolicy' {
                    return @{ isEnabled = $true
                              applicationRestrictions = @{ passwordCredentials = @(
                                  @{ restrictionType = 'passwordLifetime'; state = 'enabled'; maxLifetime = 'P365D'; restrictForAppsCreatedAfterDateTime = '0001-01-01T00:00:00Z' }
                                  @{ restrictionType = 'passwordAddition'; state = 'disabled'; restrictForAppsCreatedAfterDateTime = '0001-01-01T00:00:00Z' }
                              ); keyCredentials = @() }
                              servicePrincipalRestrictions = @{ passwordCredentials = @(); keyCredentials = @() } }
                }
                '*/conditionalAccess/namedLocations' {
                    return @{ value = @(@{ '@odata.type' = '#microsoft.graph.ipNamedLocation'; id = 'loc-ip'; displayName = 'Not trusted'; isTrusted = $false; ipRanges = @(@{ cidrAddress = '198.51.100.0/24' }) }) }
                }
                '*/conditionalAccess/policies' {
                    return @{ value = @(
                        # Reauth with a 30-day frequency, and a risk-based one (both must be ignored)
                        @{ id = 'p1'; displayName = 'Reauth 30 days'; state = 'enabled'
                           conditions = @{ users = @{ includeUsers = @('All') }; applications = @{ includeApplications = @('All') } }
                           sessionControls = @{ signInFrequency = @{ isEnabled = $true; frequencyInterval = 'timeBased'; type = 'days'; value = 30 } } }
                        @{ id = 'p2'; displayName = 'Risk based reauth'; state = 'enabled'
                           conditions = @{ users = @{ includeUsers = @('All') }; applications = @{ includeApplications = @('All') }; signInRiskLevels = @('high') }
                           sessionControls = @{ signInFrequency = @{ isEnabled = $true; frequencyInterval = 'timeBased'; type = 'hours'; value = 1 } } }
                        # Correct shape but report-only, so it must not count
                        @{ id = 'p3'; displayName = 'Auth transfer (report-only)'; state = 'enabledForReportingButNotEnforced'
                           conditions = @{ users = @{ includeUsers = @('All') }; applications = @{ includeApplications = @('All') }
                                           authenticationFlows = @{ transferMethods = 'authenticationTransfer' } }
                           grantControls = @{ builtInControls = @('block') } }
                    ) }
                }
                '*/authenticationMethodConfigurations/microsoftAuthenticator' {
                    return @{ featureSettings = @{ companionAppAllowedState = @{ state = 'enabled' } } }
                }
                default { throw "Unexpected Graph URI in test: $Uri" }
            }
        }

        . "$PSScriptRoot/../../src/M365-Assess/Common/SecurityConfigHelper.ps1"
        $ctx = Initialize-SecurityConfig
        $settings = $ctx.Settings

        . "$PSScriptRoot/../../src/M365-Assess/Entra/EntraCisV7Checks.ps1"
    }

    It '<id> fails' -ForEach @(
        @{ id = 'ENTRA-GROUP-007' }, @{ id = 'ENTRA-APPMGMT-001' }, @{ id = 'ENTRA-APPMGMT-002' }, @{ id = 'ENTRA-APPMGMT-003' },
        @{ id = 'ENTRA-APPMGMT-004' }, @{ id = 'CA-REAUTH-001' }, @{ id = 'CA-NAMEDLOC-003' }, @{ id = 'CA-GEOBLOCK-001' },
        @{ id = 'CA-TOKENPROT-001' }, @{ id = 'CA-AUTHTRANSFER-001' }, @{ id = 'ENTRA-AUTHMETHOD-009' }
    ) {
        $check = $settings | Where-Object { $_.CheckId -match "^$id(\.\d+)?$" }
        $check | Should -Not -BeNullOrEmpty
        $check.Status | Should -Be 'Fail' -Because $check.CurrentValue
    }

    It 'Reports the lifetime ceiling that was exceeded' {
        $check = $settings | Where-Object { $_.CheckId -match '^ENTRA-APPMGMT-002(\.\d+)?$' }
        $check.CurrentValue | Should -Match 'exceeds 180 days'
    }
}

Describe 'EntraCisV7Checks - apply-after date and partial coverage' {
    BeforeAll {
        function global:Update-CheckProgress { param($CheckId, $Setting, $Status) }
        function global:Get-MgContext { return @{ TenantId = 'test-tenant-id' } }

        Mock Import-Module { }

        $future = (Get-Date).ToUniversalTime().AddYears(1).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $past   = '2024-01-01T00:00:00Z'
        # Applications are restricted for all apps; service principals only for apps created in the future
        Mock Invoke-MgGraphRequest {
            param($Method, $Uri, $Headers, $ErrorAction)
            switch -Wildcard ($Uri) {
                '*/groupSettings' { return @{ value = @(@{ templateId = '62375ab9-6b52-47ed-826b-58e47e0e304b'; values = @(@{ name = 'EnableGroupCreation'; value = 'true' }) }) } }
                '*/policies/defaultAppManagementPolicy' {
                    return @{ isEnabled = $true
                              applicationRestrictions = @{ passwordCredentials = @(
                                  @{ restrictionType = 'passwordAddition'; state = 'enabled'; restrictForAppsCreatedAfterDateTime = $past }
                                  @{ restrictionType = 'passwordLifetime'; state = 'enabled'; maxLifetime = 'P6M'; restrictForAppsCreatedAfterDateTime = $past }
                              ) }
                              servicePrincipalRestrictions = @{ passwordCredentials = @(
                                  @{ restrictionType = 'passwordAddition'; state = 'enabled'; restrictForAppsCreatedAfterDateTime = $future }
                                  @{ restrictionType = 'passwordLifetime'; state = 'enabled'; maxLifetime = 'P6M'; restrictForAppsCreatedAfterDateTime = $past }
                              ) } }
                }
                '*/conditionalAccess/namedLocations' { return @{ value = @() } }
                '*/conditionalAccess/policies' { return @{ value = @() } }
                '*/authenticationMethodConfigurations/microsoftAuthenticator' { return @{ featureSettings = @{ } } }
                default { throw "Unexpected Graph URI in test: $Uri" }
            }
        }

        . "$PSScriptRoot/../../src/M365-Assess/Common/SecurityConfigHelper.ps1"
        $ctx = Initialize-SecurityConfig
        $settings = $ctx.Settings

        . "$PSScriptRoot/../../src/M365-Assess/Entra/EntraCisV7Checks.ps1"
    }

    It 'Group creation fails when EnableGroupCreation is true' {
        ($settings | Where-Object { $_.CheckId -match '^ENTRA-GROUP-007(\.\d+)?$' }).Status | Should -Be 'Fail'
    }

    It 'Fails when service principals are only restricted for apps created in the future' {
        $check = $settings | Where-Object { $_.CheckId -match '^ENTRA-APPMGMT-001(\.\d+)?$' }
        $check.Status | Should -Be 'Fail'
        $check.CurrentValue | Should -Match 'Service principals: only applies to apps created after'
    }

    It 'Accepts a past apply-after date and month-based ISO durations (P6M is within 180 days)' {
        ($settings | Where-Object { $_.CheckId -match '^ENTRA-APPMGMT-002(\.\d+)?$' }).Status | Should -Be 'Pass'
    }

    It 'Reviews the companion app setting when Graph does not return it' {
        ($settings | Where-Object { $_.CheckId -match '^ENTRA-AUTHMETHOD-009(\.\d+)?$' }).Status | Should -Be 'Review'
    }
}

Describe 'EntraCisV7Checks - Graph failures never produce a conclusion' {
    BeforeAll {
        function global:Update-CheckProgress { param($CheckId, $Setting, $Status) }
        function global:Get-MgContext { return @{ TenantId = 'test-tenant-id' } }

        Mock Import-Module { }
        Mock Invoke-MgGraphRequest { throw 'Forbidden' }

        . "$PSScriptRoot/../../src/M365-Assess/Common/SecurityConfigHelper.ps1"
        $ctx = Initialize-SecurityConfig
        $settings = $ctx.Settings

        . "$PSScriptRoot/../../src/M365-Assess/Entra/EntraCisV7Checks.ps1" 3>$null
    }

    It '<id> is Review when the API call fails' -ForEach @(
        @{ id = 'ENTRA-GROUP-007' }, @{ id = 'ENTRA-APPMGMT-001' }, @{ id = 'ENTRA-APPMGMT-002' }, @{ id = 'ENTRA-APPMGMT-003' },
        @{ id = 'ENTRA-APPMGMT-004' }, @{ id = 'CA-REAUTH-001' }, @{ id = 'CA-NAMEDLOC-003' }, @{ id = 'CA-GEOBLOCK-001' },
        @{ id = 'CA-TOKENPROT-001' }, @{ id = 'CA-AUTHTRANSFER-001' }, @{ id = 'ENTRA-AUTHMETHOD-009' }
    ) {
        $check = $settings | Where-Object { $_.CheckId -match "^$id(\.\d+)?$" }
        $check | Should -Not -BeNullOrEmpty
        $check.Status | Should -Be 'Review'
    }
}

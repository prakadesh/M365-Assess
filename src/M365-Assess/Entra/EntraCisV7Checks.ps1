# -------------------------------------------------------------------
# Entra ID -- checks added in CIS Microsoft 365 Foundations Benchmark v7.0.0
#   5.1.3.4   M365 group creation restricted          ENTRA-GROUP-007
#   5.1.5.3-6 Default app management policy           ENTRA-APPMGMT-001..004
#   5.2.2.13  Periodic reauthentication               CA-REAUTH-001
#   5.2.2.14  Trusted named locations defined         CA-NAMEDLOC-003
#   5.2.2.15  Exclusionary geographic access control  CA-GEOBLOCK-001
#   5.2.2.16  Token Protection                        CA-TOKENPROT-001
#   5.2.2.17  Authentication transfer blocked         CA-AUTHTRANSFER-001
#   5.2.3.10  Authenticator on companion apps         ENTRA-AUTHMETHOD-009
# Runs in shared scope: $settings, Add-Setting, $context (read-only Graph GETs only).
# -------------------------------------------------------------------
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
param()

. (Join-Path -Path $PSScriptRoot -ChildPath '../Common/Invoke-SafeGraphRequest.ps1')

# ------------------------------------------------------------------
# Helpers (null-safe access to nested Graph hashtables, duration parsing)
# ------------------------------------------------------------------
function Get-CisNestedValue {
    param($Object, [string[]]$Path)
    $cur = $Object
    foreach ($key in $Path) {
        if ($null -eq $cur) { return $null }
        if ($cur -is [System.Collections.IDictionary]) { $cur = $cur[$key] }
        else { $cur = $cur.$key }
    }
    return $cur
}

function ConvertTo-CisDurationDays {
    # ISO-8601 duration (e.g. P180D, P6M, P1Y) -> approximate days; $null when unparseable.
    param([string]$Duration)
    if ([string]::IsNullOrWhiteSpace($Duration)) { return $null }
    try { return [System.Xml.XmlConvert]::ToTimeSpan($Duration).TotalDays } catch { }
    if ($Duration -match '^P(?:(\d+)Y)?(?:(\d+)M)?(?:(\d+)W)?(?:(\d+)D)?$') {
        $y = if ($Matches[1]) { [int]$Matches[1] } else { 0 }
        $m = if ($Matches[2]) { [int]$Matches[2] } else { 0 }
        $w = if ($Matches[3]) { [int]$Matches[3] } else { 0 }
        $d = if ($Matches[4]) { [int]$Matches[4] } else { 0 }
        return ($y * 365) + ($m * 30) + ($w * 7) + $d
    }
    return $null
}

function Test-CisAppMgmtRestriction {
    # Evaluates one restriction entry of the default app management policy against the
    # CIS criteria: state enabled, optional maxLifetime ceiling, and the "only apply to
    # apps created after" date either unset (0001-01-01) or not in the future.
    # Returns @{ Compliant = [bool]; Detail = [string] }.
    param($Restrictions, [string]$RestrictionType, [Nullable[int]]$MaxDays)

    $entry = @($Restrictions) | Where-Object { $_ -and $_['restrictionType'] -eq $RestrictionType } | Select-Object -First 1
    if (-not $entry) { return @{ Compliant = $false; Detail = 'not configured' } }
    if ($entry['state'] -ne 'enabled') { return @{ Compliant = $false; Detail = "state $($entry['state'])" } }

    if ($null -ne $MaxDays) {
        $days = ConvertTo-CisDurationDays -Duration ([string]$entry['maxLifetime'])
        if ($null -eq $days) { return @{ Compliant = $false; Detail = 'no maximum lifetime set' } }
        if ($days -gt $MaxDays) { return @{ Compliant = $false; Detail = "max lifetime $($entry['maxLifetime']) exceeds $MaxDays days" } }
    }

    $after = $entry['restrictForAppsCreatedAfterDateTime']
    if ($after) {
        $parsed = $null
        try { $parsed = ([datetime]$after).ToUniversalTime() } catch { $parsed = $null }
        if ($null -eq $parsed) { return @{ Compliant = $false; Detail = 'unreadable apply-after date' } }
        # Unset (0001-01-01) or a date on/before today means the restriction already covers every app.
        if ($parsed.Year -gt 1 -and $parsed -gt (Get-Date).ToUniversalTime()) {
            return @{ Compliant = $false; Detail = "only applies to apps created after $($parsed.ToString('yyyy-MM-dd'))" }
        }
    }
    return @{ Compliant = $true; Detail = 'enabled' }
}

# ------------------------------------------------------------------
# 5.1.3.4  Users can create Microsoft 365 groups in Azure portals, API or PowerShell = No
# ------------------------------------------------------------------
try {
    Write-Verbose 'Checking Microsoft 365 group creation setting...'
    $grpSettingsResp = Invoke-SafeGraphRequest -ExpectCollection -Method GET -Uri '/v1.0/groupSettings' -ErrorAction Stop
    $grpSettings = if ($grpSettingsResp -and $grpSettingsResp['value']) { @($grpSettingsResp['value']) } else { @() }
    $unifiedSetting = $grpSettings | Where-Object { $_['templateId'] -eq '62375ab9-6b52-47ed-826b-58e47e0e304b' } | Select-Object -First 1

    if (-not $unifiedSetting) {
        # CIS: absence of the Group.Unified setting means the default (creation allowed) applies.
        $current = 'Users can create groups (default; no Group.Unified setting configured)'
        $status  = 'Fail'
    }
    else {
        $entry = @($unifiedSetting['values']) | Where-Object { $_ -and $_['name'] -eq 'EnableGroupCreation' } | Select-Object -First 1
        $enabled = if ($entry) { [string]$entry['value'] } else { 'true' }
        $creationBlocked = ($enabled -eq 'false')
        $current = if ($creationBlocked) { 'Users cannot create Microsoft 365 groups' } else { 'Users can create Microsoft 365 groups' }
        $status  = if ($creationBlocked) { 'Pass' } else { 'Fail' }
    }
    $settingParams = @{
        Category         = 'Groups'
        Setting          = 'Users Can Create Microsoft 365 Groups'
        CurrentValue     = $current
        RecommendedValue = 'No'
        Status           = $status
        CheckId          = 'ENTRA-GROUP-007'
        Remediation      = 'Entra admin center > Entra ID > Groups > General > Users can create Microsoft 365 groups in Azure portals, API or PowerShell = No. Allow a designated group to create groups via the Group.Unified setting (EnableGroupCreation = false, GroupCreationAllowedGroupId).'
    }
    Add-Setting @settingParams
}
catch {
    Write-Warning "Could not check Microsoft 365 group creation setting: $_"
    $settingParams = @{
        Category = 'Groups'; Setting = 'Users Can Create Microsoft 365 Groups'
        CurrentValue = "Could not query -- verify manually ($($_.Exception.Message))"; RecommendedValue = 'No'
        Status = 'Review'; CheckId = 'ENTRA-GROUP-007'
        Remediation = 'Verify Directory.Read.All consent, then re-run. Entra admin center > Entra ID > Groups > General.'
    }
    Add-Setting @settingParams
}

# ------------------------------------------------------------------
# 5.1.5.3-5.1.5.6  Default app management policy
# ------------------------------------------------------------------
$appMgmtChecks = @(
    @{ CheckId = 'ENTRA-APPMGMT-001'; Setting = 'App Policy: Block Password Addition'
       Section = 'passwordCredentials'; Type = 'passwordAddition'; MaxDays = $null
       Recommended = 'Block password addition enabled for all applications and service principals'
       Fix = 'Entra admin center > Enterprise apps > Security > Application policies > Block password addition > On, applies to All applications.' }
    @{ CheckId = 'ENTRA-APPMGMT-002'; Setting = 'App Policy: Maximum Password Lifetime'
       Section = 'passwordCredentials'; Type = 'passwordLifetime'; MaxDays = 180
       Recommended = 'Restrict max password lifetime on, 180 days or less'
       Fix = 'Entra admin center > Enterprise apps > Security > Application policies > Restrict max password lifetime > On, 180 days or less, applies to All applications.' }
    @{ CheckId = 'ENTRA-APPMGMT-003'; Setting = 'App Policy: Block Custom Passwords'
       Section = 'passwordCredentials'; Type = 'customPasswordAddition'; MaxDays = $null
       Recommended = 'Block custom passwords enabled (system-generated only)'
       Fix = 'Entra admin center > Enterprise apps > Security > Application policies > Block custom passwords > On, applies to All applications.' }
    @{ CheckId = 'ENTRA-APPMGMT-004'; Setting = 'App Policy: Maximum Certificate Lifetime'
       Section = 'keyCredentials'; Type = 'asymmetricKeyLifetime'; MaxDays = 180
       Recommended = 'Restrict max certificate lifetime on, 180 days or less'
       Fix = 'Entra admin center > Enterprise apps > Security > Application policies > Restrict max certificate lifetime > On, 180 days or less, applies to All applications.' }
)

$appMgmtPolicy = $null
$appMgmtError = $null
try {
    Write-Verbose 'Checking default app management policy...'
    $appMgmtPolicy = Invoke-SafeGraphRequest -Method GET -Uri '/v1.0/policies/defaultAppManagementPolicy' -ErrorAction Stop
}
catch {
    $appMgmtError = $_.Exception.Message
    Write-Warning "Could not retrieve default app management policy: $_"
}

foreach ($amc in $appMgmtChecks) {
    if ($appMgmtError -or -not $appMgmtPolicy) {
        $settingParams = @{
            Category = 'Application Management'; Setting = $amc.Setting
            CurrentValue = "Could not query -- verify manually$(if ($appMgmtError) { " ($appMgmtError)" })"
            RecommendedValue = $amc.Recommended; Status = 'Review'; CheckId = $amc.CheckId
            Remediation = "Verify Policy.Read.All consent, then re-run. $($amc.Fix)"
        }
        Add-Setting @settingParams
        continue
    }

    if (-not [bool]$appMgmtPolicy['isEnabled']) {
        $current = 'Default app management policy is disabled'
        $status  = 'Fail'
    }
    else {
        # CIS requires BOTH application and service principal restrictions to be configured.
        $appRes = Test-CisAppMgmtRestriction -Restrictions (Get-CisNestedValue $appMgmtPolicy @('applicationRestrictions', $amc.Section)) `
            -RestrictionType $amc.Type -MaxDays $amc.MaxDays
        $spRes  = Test-CisAppMgmtRestriction -Restrictions (Get-CisNestedValue $appMgmtPolicy @('servicePrincipalRestrictions', $amc.Section)) `
            -RestrictionType $amc.Type -MaxDays $amc.MaxDays
        $current = "Applications: $($appRes.Detail); Service principals: $($spRes.Detail)"
        $status  = if ($appRes.Compliant -and $spRes.Compliant) { 'Pass' } else { 'Fail' }
    }
    $settingParams = @{
        Category         = 'Application Management'
        Setting          = $amc.Setting
        CurrentValue     = $current
        RecommendedValue = $amc.Recommended
        Status           = $status
        CheckId          = $amc.CheckId
        Remediation      = $amc.Fix
        ObservedValue    = $current
        ExpectedValue    = $amc.Recommended
        EvidenceSource   = '/policies/defaultAppManagementPolicy'
        CollectionMethod = 'Direct'
        PermissionRequired = 'Policy.Read.All'
    }
    Add-Setting @settingParams
}

# ------------------------------------------------------------------
# Conditional Access policy and named-location checks (5.2.2.13 - 5.2.2.17)
# ------------------------------------------------------------------
$cisV7CaPolicies = $null
$cisV7CaError = $null
try {
    Write-Verbose 'Retrieving Conditional Access policies for CIS v7 checks...'
    $caResp = Invoke-SafeGraphRequest -ExpectCollection -Method GET -Uri '/v1.0/identity/conditionalAccess/policies' -ErrorAction Stop
    $cisV7CaPolicies = if ($caResp -and $caResp['value']) { @($caResp['value']) } else { @() }
}
catch {
    $cisV7CaError = $_.Exception.Message
    Write-Warning "Could not retrieve Conditional Access policies for CIS v7 checks: $_"
}

$cisV7NamedLocs = $null
$cisV7LocError = $null
try {
    $locResp = Invoke-SafeGraphRequest -ExpectCollection -Method GET -Uri '/v1.0/identity/conditionalAccess/namedLocations' -ErrorAction Stop
    $cisV7NamedLocs = if ($locResp -and $locResp['value']) { @($locResp['value']) } else { @() }
}
catch {
    $cisV7LocError = $_.Exception.Message
    Write-Warning "Could not retrieve named locations: $_"
}

function Add-CisCaResult {
    # Records a Conditional Access criteria check. $Matched = policies that satisfy every criterion.
    param([string]$CheckId, [string]$Setting, [string]$Recommended, [string]$NoneFound, $Matched, [string]$Fix, [string]$QueryError)
    if ($QueryError) {
        Add-Setting -Category 'Conditional Access' -Setting $Setting -CurrentValue "Could not query -- verify manually ($QueryError)" `
            -RecommendedValue $Recommended -Status 'Review' -CheckId $CheckId -Remediation "Verify Policy.Read.All consent, then re-run. $Fix"
        return
    }
    $names = @($Matched | ForEach-Object { $_['displayName'] })
    $current = if ($names.Count -gt 0) {
        "$($names.Count) compliant polic$(if ($names.Count -eq 1) { 'y' } else { 'ies' }): $(($names | Select-Object -First 3) -join ', '). Review exclusions annually."
    } else { $NoneFound }
    Add-Setting -Category 'Conditional Access' -Setting $Setting -CurrentValue $current -RecommendedValue $Recommended `
        -Status $(if ($names.Count -gt 0) { 'Pass' } else { 'Fail' }) -CheckId $CheckId -Remediation $Fix `
        -ObservedValue $current -ExpectedValue $Recommended -EvidenceSource '/identity/conditionalAccess/policies' `
        -CollectionMethod 'Direct' -PermissionRequired 'Policy.Read.All'
}

if (-not $cisV7CaError) {
    $enabledCa = @($cisV7CaPolicies | Where-Object { $_['state'] -eq 'enabled' })
    $targetsAllUsers = { param($p) @(Get-CisNestedValue $p @('conditions', 'users', 'includeUsers')) -contains 'All' }
    $targetsAllApps  = { param($p) @(Get-CisNestedValue $p @('conditions', 'applications', 'includeApplications')) -contains 'All' }
    $blocks          = { param($p) @(Get-CisNestedValue $p @('grantControls', 'builtInControls')) -contains 'block' }
}

# 5.2.2.13 -- periodic reauthentication for all users (sign-in frequency <= 7 days)
$reauth = @()
if (-not $cisV7CaError) {
    $reauth = @($enabledCa | Where-Object {
        $sif = Get-CisNestedValue $_ @('sessionControls', 'signInFrequency')
        if (-not $sif -or -not [bool]$sif['isEnabled']) { return $false }
        # Risk-based policies are excluded from this assessment
        if (@(Get-CisNestedValue $_ @('conditions', 'signInRiskLevels')).Where({ $_ }).Count -gt 0) { return $false }
        if (@(Get-CisNestedValue $_ @('conditions', 'userRiskLevels')).Where({ $_ }).Count -gt 0) { return $false }
        if (-not (& $targetsAllUsers $_) -or -not (& $targetsAllApps $_)) { return $false }
        if ($sif['frequencyInterval'] -ne 'timeBased') { return $false }
        $value = 0
        if (-not [int]::TryParse([string]$sif['value'], [ref]$value)) { return $false }
        switch ([string]$sif['type']) {
            'days'  { $value -le 7 }
            'hours' { $value -le 168 }
            default { $false }
        }
    })
}
Add-CisCaResult -CheckId 'CA-REAUTH-001' -Setting 'Periodic Reauthentication for All Users' `
    -Recommended 'Policy for all users and all apps with sign-in frequency of 7 days or less' `
    -NoneFound 'No enabled policy requires reauthentication within 7 days for all users and apps' -Matched $reauth `
    -Fix 'Entra admin center > Entra ID > Conditional Access > Policies > New policy: Users All, Target resources All resources, Session > Sign-in frequency > Periodic reauthentication, 7 days or less (non-risk-based).' `
    -QueryError $cisV7CaError

# 5.2.2.14 -- trusted named locations defined (>= 1 trusted IP location with ranges)
if ($cisV7LocError) {
    Add-CisCaResult -CheckId 'CA-NAMEDLOC-003' -Setting 'Trusted Named Locations Defined' -Recommended 'At least one trusted IP named location' `
        -NoneFound '' -Matched @() -Fix 'Entra admin center > Entra ID > Conditional Access > Named locations.' -QueryError $cisV7LocError
}
else {
    $trustedIpLocs = @($cisV7NamedLocs | Where-Object {
        $_['@odata.type'] -eq '#microsoft.graph.ipNamedLocation' -and [bool]$_['isTrusted'] -and @($_['ipRanges']).Count -gt 0
    })
    $locCurrent = if ($trustedIpLocs.Count -gt 0) { "$($trustedIpLocs.Count) trusted IP named location(s): $((@($trustedIpLocs | ForEach-Object { $_['displayName'] }) | Select-Object -First 3) -join ', ')" } else { 'No trusted IP named locations with address ranges defined' }
    Add-Setting -Category 'Conditional Access' -Setting 'Trusted Named Locations Defined' -CurrentValue $locCurrent `
        -RecommendedValue 'At least one trusted IP named location' -Status $(if ($trustedIpLocs.Count -gt 0) { 'Pass' } else { 'Fail' }) `
        -CheckId 'CA-NAMEDLOC-003' -Remediation 'Entra admin center > Entra ID > Conditional Access > Named locations > New IP ranges location, mark as trusted, add the organization''s egress IPv4/IPv6 ranges.' `
        -ObservedValue $locCurrent -ExpectedValue 'At least one trusted IP named location' -EvidenceSource '/identity/conditionalAccess/namedLocations' `
        -CollectionMethod 'Direct' -PermissionRequired 'Policy.Read.All'
}

# 5.2.2.15 -- exclusionary geographic access control (block untrusted locations)
$geoBlock = @()
$geoQueryError = if ($cisV7CaError) { $cisV7CaError } elseif ($cisV7LocError) { $cisV7LocError } else { $null }
if (-not $geoQueryError) {
    $untrustedIds = @($cisV7NamedLocs | Where-Object {
        $_['@odata.type'] -eq '#microsoft.graph.countryNamedLocation' -or -not [bool]$_['isTrusted']
    } | ForEach-Object { [string]$_['id'] })
    $trustedIds = @($cisV7NamedLocs | Where-Object { [bool]$_['isTrusted'] } | ForEach-Object { [string]$_['id'] })
    $geoBlock = @($enabledCa | Where-Object {
        if (-not (& $targetsAllUsers $_) -or -not (& $targetsAllApps $_) -or -not (& $blocks $_)) { return $false }
        $incl = @(@(Get-CisNestedValue $_ @('conditions', 'locations', 'includeLocations')) | ForEach-Object { [string]$_ })
        $excl = @(@(Get-CisNestedValue $_ @('conditions', 'locations', 'excludeLocations')) | ForEach-Object { [string]$_ })
        $inclUntrusted = @($incl | Where-Object { $_ -in $untrustedIds }).Count -gt 0
        $exclTrusted = ($excl -contains 'AllTrusted') -or (@($excl | Where-Object { $_ -in $trustedIds }).Count -gt 0)
        $inclUntrusted -and $exclTrusted
    })
}
Add-CisCaResult -CheckId 'CA-GEOBLOCK-001' -Setting 'Exclusionary Geographic Access Control' `
    -Recommended 'Block policy for all users and apps that includes untrusted locations and excludes trusted ones' `
    -NoneFound 'No enabled policy blocks access from untrusted locations while excluding trusted locations' -Matched $geoBlock `
    -Fix 'Entra admin center > Entra ID > Conditional Access > Policies > New policy: Users All, Target resources All resources, Conditions > Locations include untrusted (e.g. a country list) and exclude All trusted locations, Grant > Block access.' `
    -QueryError $geoQueryError

# 5.2.2.16 -- Token Protection for session tokens
$tokenProtection = @()
if (-not $cisV7CaError) {
    $requiredApps = @('00000002-0000-0ff1-ce00-000000000000', '00000003-0000-0ff1-ce00-000000000000', 'cc15fd57-2c6c-4117-a88c-83b1d56b4bbe')
    $tokenProtection = @($enabledCa | Where-Object {
        $ssc = Get-CisNestedValue $_ @('sessionControls', 'secureSignInSession')
        if (-not $ssc -or -not [bool]$ssc['isEnabled']) { return $false }
        $users = @(@(Get-CisNestedValue $_ @('conditions', 'users', 'includeUsers')) | Where-Object { $_ })
        if ($users.Count -eq 0 -or ($users.Count -eq 1 -and $users[0] -eq 'None')) { return $false }
        $apps = @(@(Get-CisNestedValue $_ @('conditions', 'applications', 'includeApplications')) | ForEach-Object { ([string]$_).ToLowerInvariant() })
        $hasApps = ($apps -contains 'all') -or (@($requiredApps | Where-Object { $_ -notin $apps }).Count -eq 0)
        $platforms = @(@(Get-CisNestedValue $_ @('conditions', 'platforms', 'includePlatforms')) | ForEach-Object { ([string]$_).ToLowerInvariant() })
        $clients = @(@(Get-CisNestedValue $_ @('conditions', 'clientAppTypes')) | Where-Object { $_ })
        $hasApps -and ($platforms -contains 'windows') -and ($clients.Count -eq 1 -and $clients[0] -eq 'mobileAppsAndDesktopClients')
    })
}
Add-CisCaResult -CheckId 'CA-TOKENPROT-001' -Setting 'Token Protection Enforced' `
    -Recommended 'Policy requiring token protection for Exchange Online, SharePoint Online and Teams on Windows desktop clients' `
    -NoneFound 'No enabled policy enforces token protection for Exchange Online, SharePoint Online and Teams' -Matched $tokenProtection `
    -Fix 'Entra admin center > Entra ID > Conditional Access > Policies > New policy: Target resources Office 365 Exchange Online, SharePoint Online and Microsoft Teams Services; Conditions > Device platforms Windows; Client apps Mobile apps and desktop clients; Session > Require token protection for sign-in sessions.' `
    -QueryError $cisV7CaError

# 5.2.2.17 -- authentication transfer blocked
$authTransfer = @()
if (-not $cisV7CaError) {
    $authTransfer = @($enabledCa | Where-Object {
        $transfer = (@(Get-CisNestedValue $_ @('conditions', 'authenticationFlows', 'transferMethods')) | ForEach-Object { [string]$_ }) -join ','
        ($transfer -match 'authenticationTransfer') -and (& $targetsAllUsers $_) -and (& $targetsAllApps $_) -and (& $blocks $_)
    })
}
Add-CisCaResult -CheckId 'CA-AUTHTRANSFER-001' -Setting 'Authentication Transfer Blocked' `
    -Recommended 'Policy blocking authentication transfer for all users and all resources' `
    -NoneFound 'No enabled policy blocks authentication transfer' -Matched $authTransfer `
    -Fix 'Entra admin center > Entra ID > Conditional Access > Policies > New policy: Users All, Target resources All resources, Conditions > Authentication flows > Authentication transfer, Grant > Block access.' `
    -QueryError $cisV7CaError

# ------------------------------------------------------------------
# 5.2.3.10  Microsoft Authenticator on companion applications disabled
# ------------------------------------------------------------------
try {
    Write-Verbose 'Checking Authenticator companion application setting...'
    $msAuth = Invoke-SafeGraphRequest -Method GET -Uri '/beta/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/microsoftAuthenticator' -ErrorAction Stop
    $companionState = Get-CisNestedValue $msAuth @('featureSettings', 'companionAppAllowedState', 'state')
    if ($null -eq $companionState) {
        Add-Setting -Category 'Authentication Methods' -Setting 'Authenticator on Companion Applications' `
            -CurrentValue 'Setting not returned by Graph -- verify manually' -RecommendedValue 'disabled' -Status 'Review' `
            -CheckId 'ENTRA-AUTHMETHOD-009' -Remediation 'Entra admin center > Entra ID > Authentication methods > Policies > Microsoft Authenticator > Configure > Microsoft Authenticator on companion applications > Disabled.'
    }
    else {
        Add-Setting -Category 'Authentication Methods' -Setting 'Authenticator on Companion Applications' `
            -CurrentValue "$companionState" -RecommendedValue 'disabled' -Status $(if ($companionState -eq 'disabled') { 'Pass' } else { 'Fail' }) `
            -CheckId 'ENTRA-AUTHMETHOD-009' -Remediation 'Entra admin center > Entra ID > Authentication methods > Policies > Microsoft Authenticator > Configure > Microsoft Authenticator on companion applications > Disabled.' `
            -ObservedValue "$companionState" -ExpectedValue 'disabled' -EvidenceSource '/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/microsoftAuthenticator' `
            -CollectionMethod 'Direct' -PermissionRequired 'Policy.Read.All'
    }
}
catch {
    Write-Warning "Could not check Authenticator companion application setting: $_"
    Add-Setting -Category 'Authentication Methods' -Setting 'Authenticator on Companion Applications' `
        -CurrentValue "Could not query -- verify manually ($($_.Exception.Message))" -RecommendedValue 'disabled' -Status 'Review' `
        -CheckId 'ENTRA-AUTHMETHOD-009' -Remediation 'Verify Policy.Read.All consent, then re-run. Entra admin center > Entra ID > Authentication methods > Policies > Microsoft Authenticator.'
}

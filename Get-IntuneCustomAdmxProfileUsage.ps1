<#
.SYNOPSIS
Reports Intune profiles using custom ADMX files, with inferred dependency chains from tenant category data.

.LINK
Blog Post: https://www.ravenswoodtechnology.com/?p=67433

.DESCRIPTION
Data sources (all tenant-side):
- groupPolicyConfigurations (custom ingestion) + definitionValues with expanded definitions
- groupPolicyCategories with parent edges (the category tree Intune built at ADMX import)
- groupPolicyUploadedDefinitionFiles (uploaded custom ADMX metadata)

Attribution: tries the exact nested expand definition($expand=definitionFile) first; if Graph
returns it unpopulated (known gap for admx-ingested files), attributes each category chain
segment to an uploaded ADMX by unique normalized-name or conservative token matching.
Token matching requires at least two filename tokens, all tokens in the category segment,
and exactly one uploaded-file candidate. Output identifies the rule and confidence used.
Unmatched or ambiguous segments are reported as UNRESOLVED.

Dependencies: when a setting's category chain crosses from ADMX A's inferred segment into
ADMX B's inferred segment, B is reported nearest-first in DependencyAdmxChain. Intune does
not expose custom ADMX namespace imports, so this is category-tree inference rather than a
proven source-file dependency. DependencySource makes that limitation explicit.

This script is intended for interactive use by a human operator. Output is optimized for
console inspection; CSV export is optional.

.PARAMETER ExportCsv
Writes the final results to CsvPath after displaying them in the console.

.PARAMETER CsvPath
Destination for CSV output. Supplying CsvPath also enables CSV export.

.PARAMETER TenantId
Optional tenant override for Connect-MgGraph.

.PARAMETER Cloud
Selects the Microsoft cloud to connect to and display in the startup banner (Commercial, USGov, or USGovDoD)

.EXAMPLE
Get-IntuneCustomAdmxProfileUsage.ps1 -Cloud Commercial -Verbose

.EXAMPLE
Get-IntuneCustomAdmxProfileUsage.ps1 -Cloud USGov -ExportCsv -CsvPath .\usage.csv

.EXAMPLE
Get-IntuneCustomAdmxProfileUsage.ps1 -CsvPath .\usage.csv
#>

[CmdletBinding()]
param(
    [switch]$ExportCsv,

    [string]$CsvPath = ".\Intune-CustomAdmx-ProfileUsage.csv",

    [string]$TenantId,

    [ValidateSet("Commercial", "USGov", "USGovDoD")]
    [string]$Cloud = "Commercial"
)

Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

# Map cloud selection to Connect-MgGraph environment and Graph endpoint.
$cloudSettings = @{
    Commercial = @{ Environment = "Global";   GraphHost = "https://graph.microsoft.com" }
    USGov      = @{ Environment = "USGov";    GraphHost = "https://graph.microsoft.us" }
    USGovDoD   = @{ Environment = "USGovDoD"; GraphHost = "https://dod-graph.microsoft.us" }
}

$connectParams = @{
    Scopes      = "DeviceManagementConfiguration.Read.All"
    Environment = $cloudSettings[$Cloud].Environment
    NoWelcome   = $true
}

if ($TenantId) {
    $connectParams.TenantId = $TenantId
}

Connect-MgGraph @connectParams

$graphContext = Get-MgContext
Write-Host "Connected to cloud: $Cloud ($($cloudSettings[$Cloud].GraphHost))"
Write-Host "Connected to tenant id: $($graphContext.TenantId)"
Write-Host "Connected as account: $($graphContext.Account)"

$graphBase = "$($cloudSettings[$Cloud].GraphHost)/beta"

function Get-GraphCollection {
    param(
        [Parameter(Mandatory)]
        [string]$Uri
    )

    $items = @()

    do {
        $response = Invoke-MgGraphRequest -Method GET -Uri $Uri
        if ($response.value) {
            $items += $response.value
        }
        $Uri = $response.'@odata.nextLink'
    } while ($Uri)

    return $items
}

function ConvertTo-NameKey {
    # Normalize for exact-equality comparison: lowercase, strip non-alphanumerics.
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $null
    }

    return ($Value.ToLowerInvariant() -replace '[^a-z0-9]', '')
}

function ConvertTo-MatchTokens {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return @()
    }

    $expanded = $Value -creplace '(?<=[a-z0-9])(?=[A-Z])', ' '
    $tokens = foreach ($match in [regex]::Matches($expanded.ToLowerInvariant(), '[a-z0-9]+')) {
        $token = $match.Value

        if ($token.Length -gt 3 -and $token.EndsWith('ies')) {
            $token = $token.Substring(0, $token.Length - 3) + 'y'
        }
        elseif ($token.Length -gt 3 -and $token.EndsWith('s') -and -not $token.EndsWith('ss')) {
            $token = $token.Substring(0, $token.Length - 1)
        }

        $token
    }

    return @($tokens | Sort-Object -Unique)
}

function Get-AdmxNamespaceKey {
    # targetNamespace lowercased with trailing version stripped:
    # 'Google.Policies.Update_v139' -> 'google.policies.update'
    param($Admx)

    if ([string]::IsNullOrWhiteSpace($Admx.targetNamespace)) {
        return $null
    }

    return ($Admx.targetNamespace.ToLowerInvariant() -replace '_v?\d[\d.]*$', '')
}

# --- Uploaded custom ADMX files ---

Write-Host "Reading uploaded custom ADMX files..."
$uploadedAdmxFiles = Get-GraphCollection "$graphBase/deviceManagement/groupPolicyUploadedDefinitionFiles"

if (-not $uploadedAdmxFiles) {
    Write-Host "No uploaded custom ADMX files found in this tenant."
    return
}

$customAdmxById = @{}
$admxByNameKey = @{}   # exact normalized fileName-base -> list of ADMX files

foreach ($admx in $uploadedAdmxFiles) {
    $customAdmxById[$admx.id] = $admx

    $fileBase = [System.IO.Path]::GetFileNameWithoutExtension($admx.fileName)
    $key = ConvertTo-NameKey $fileBase
    if ($key) {
        if (-not $admxByNameKey.ContainsKey($key)) {
            $admxByNameKey[$key] = [System.Collections.Generic.List[object]]::new()
        }
        $admxByNameKey[$key].Add($admx)
    }
}

Write-Verbose "  Uploaded custom ADMX files: $($uploadedAdmxFiles.Count)"

# --- Category tree (parent edges are populated; ownership links are not - known Graph gap) ---

Write-Host "Reading group policy category tree..."
$categories = Get-GraphCollection "$graphBase/deviceManagement/groupPolicyCategories?`$expand=parent"

$categoryById = @{}
$categoryParentById = @{}

foreach ($category in $categories) {
    $categoryById[$category.id] = $category
    if ($category.parent.id) {
        $categoryParentById[$category.id] = $category.parent.id
    }
}

Write-Verbose "  Categories: $($categories.Count); parent edges: $($categoryParentById.Count)"

function Get-CategoryChain {
    # Returns category objects from the given category up to the root (leaf first).
    # The guard prevents accidental infinite loops if the tenant tree contains a cycle.
    param([string]$CategoryId)

    $chain = @()
    $current = $CategoryId
    $guard = 0

    while ($current -and $guard -lt 20) {
        if (-not $categoryById.ContainsKey($current)) {
            break
        }

        $chain += $categoryById[$current]
        $current = if ($categoryParentById.ContainsKey($current)) { $categoryParentById[$current] } else { $null }
        $guard++
    }

    return $chain
}

function Resolve-SegmentToAdmx {
    # Deterministic matching between a category display name and an uploaded ADMX fileName.
    # Exact/suffix rules run first. A conservative token-subset fallback handles differing
    # labels such as DriveMapping.admx and 'Network Drive Mappings'. Every rule requires a
    # unique uploaded-file match; ambiguous segments remain unresolved.
    param($Category)

    $key = ConvertTo-NameKey $Category.displayName
    if (-not $key) {
        return $null
    }

    # Rule 1: exact equality with fileName base ('Mozilla v7.1' == 'mozilla_v7.1')
    if ($admxByNameKey.ContainsKey($key)) {
        $exactMatches = @($admxByNameKey[$key])
        if ($exactMatches.Count -eq 1) {
            return [pscustomobject]@{
                Admx       = $exactMatches[0]
                MatchRule  = 'Category normalized exact/suffix'
                Confidence = 'Inferred-High'
            }
        }

        Write-Verbose "  Ambiguous exact ADMX name match for category '$($Category.displayName)' ($(($exactMatches.fileName) -join ', ')) - leaving unresolved."
        return $null
    }

    $segmentMatches = @()

    foreach ($admx in $uploadedAdmxFiles) {
        $fileBase = [System.IO.Path]::GetFileNameWithoutExtension($admx.fileName)
        $fileKey = ConvertTo-NameKey $fileBase
        $fileKeyNoVersion = ConvertTo-NameKey ($fileBase -replace '[_\s][vV]?\d[\d.]*$', '')

        # Rule 2: version-less category equals version-stripped file base
        # ('Firefox' == 'firefox_v7.1' minus version)
        if ($fileKeyNoVersion -and $key -eq $fileKeyNoVersion) {
            $segmentMatches += $admx
            continue
        }

        # Rule 3: vendor-prefixed category ends with the full file base including version
        # ('Microsoft PowerToys v1.17' ends with 'PowerToys_v1.17')
        if ($fileKey -and $key.Length -gt $fileKey.Length -and $key.EndsWith($fileKey)) {
            $segmentMatches += $admx
            continue
        }

        # Rule 4: both sides version-stripped, category ends with file base
        # (vendor prefix plus differing version formats)
        if ($fileKeyNoVersion) {
            $keyNoVersion = ConvertTo-NameKey ($Category.displayName -replace '[\s_][vV]?\d[\d.]*$', '')
            if (
                $keyNoVersion -and
                $keyNoVersion.Length -gt $fileKeyNoVersion.Length -and
                $keyNoVersion.EndsWith($fileKeyNoVersion)
            ) {
                $segmentMatches += $admx
            }
        }
    }

    $segmentMatches = @($segmentMatches | Sort-Object id -Unique)

    if ($segmentMatches.Count -eq 1) {
        return [pscustomobject]@{
            Admx       = $segmentMatches[0]
            MatchRule  = 'Category normalized exact/suffix'
            Confidence = 'Inferred-High'
        }
    }

    if ($segmentMatches.Count -gt 1) {
        Write-Verbose "  Ambiguous ADMX name match for category '$($Category.displayName)' ($(($segmentMatches.fileName) -join ', ')) - leaving unresolved."
    }

    if ($segmentMatches.Count -gt 1) {
        return $null
    }

    # Rule 5: all version-stripped filename tokens occur in the category tokens. Requiring
    # at least two filename tokens avoids broad matches from generic one-word filenames.
    $categoryTokens = @(ConvertTo-MatchTokens $Category.displayName)
    $tokenMatches = @()

    foreach ($admx in $uploadedAdmxFiles) {
        $fileBase = [System.IO.Path]::GetFileNameWithoutExtension($admx.fileName)
        $fileBaseNoVersion = $fileBase -replace '[_\s-][vV]?\d[\w.-]*$', ''
        $fileTokens = @(ConvertTo-MatchTokens $fileBaseNoVersion)

        if ($fileTokens.Count -lt 2) {
            continue
        }

        $allTokensPresent = $true
        foreach ($fileToken in $fileTokens) {
            if ($categoryTokens -notcontains $fileToken) {
                $allTokensPresent = $false
                break
            }
        }

        if ($allTokensPresent) {
            $tokenMatches += $admx
        }
    }

    $tokenMatches = @($tokenMatches | Sort-Object id -Unique)

    if ($tokenMatches.Count -eq 1) {
        return [pscustomobject]@{
            Admx       = $tokenMatches[0]
            MatchRule  = 'Category unique token subset'
            Confidence = 'Inferred-Moderate'
        }
    }

    if ($tokenMatches.Count -gt 1) {
        Write-Verbose "  Ambiguous ADMX token match for category '$($Category.displayName)' ($(($tokenMatches.fileName) -join ', ')) - leaving unresolved."
    }

    return $null
}

# --- Custom Administrative Templates profiles ---

Write-Host "Reading custom Administrative Templates profiles..."
$profiles = Get-GraphCollection "$graphBase/deviceManagement/groupPolicyConfigurations"
$customProfiles = @($profiles | Where-Object { $_.policyConfigurationIngestionType -eq "custom" })
Write-Verbose "  Custom profiles: $($customProfiles.Count)"

$exactRouteChecked = $false
$exactRouteWorks = $false

$results = foreach ($profile in $customProfiles) {
    # Probe the exact nested definitionFile route once per run.
    # If it succeeds, the rest of the script can use direct file IDs where available;
    # otherwise the script falls back to category-chain attribution for all rows.
    $expandClause = if ($exactRouteWorks) { '$expand=definition($expand=definitionFile)' } else { '$expand=definition' }

    if (-not $exactRouteChecked) {
        $exactRouteChecked = $true
        try {
            $probe = Invoke-MgGraphRequest -Method GET -Uri "$graphBase/deviceManagement/groupPolicyConfigurations/$($profile.id)/definitionValues?`$expand=definition(`$expand=definitionFile)&`$top=1"
            if ($probe.value -and $probe.value[0].definition.definitionFile.id) {
                $exactRouteWorks = $true
                $expandClause = '$expand=definition($expand=definitionFile)'
                Write-Verbose "  Exact nested definitionFile expand IS populated - using ID-linked attribution."
            }
            else {
                Write-Verbose "  Nested definitionFile expand not populated - using category-chain attribution."
            }
        }
        catch {
            Write-Verbose "  Nested definitionFile expand rejected - using category-chain attribution."
        }
    }

    $definitionValues = Get-GraphCollection "$graphBase/deviceManagement/groupPolicyConfigurations/$($profile.id)/definitionValues?$expandClause"
    Write-Verbose "  Profile '$($profile.displayName)': $($definitionValues.Count) definition values"

    # admx key (or UNRESOLVED marker) -> info
    $profileAdmxUsage = @{}

    foreach ($definitionValue in $definitionValues) {
        $definition = $definitionValue.definition

        if (-not $definition -or $definition.policyType -ne "admxIngested") {
            continue
        }

        $directAdmx = $null
        $dependencyChain = @()
        $attributionSource = 'Unresolved'
        $attributionConfidence = 'Unknown'

        if ($exactRouteWorks -and $definition.definitionFile.id -and $customAdmxById.ContainsKey($definition.definitionFile.id)) {
            $directAdmx = $customAdmxById[$definition.definitionFile.id]
            $attributionSource = 'Graph definitionFile link'
            $attributionConfidence = 'Exact'
        }

        # Category chain walk (leaf -> root), attributing each segment.
        $chain = Get-CategoryChain $definition.groupPolicyCategoryId
        $chainMatches = @()

        foreach ($segment in $chain) {
            $segmentMatch = Resolve-SegmentToAdmx $segment
            if ($segmentMatch) {
                $chainMatches += $segmentMatch
            }
        }

        $directIndex = -1

        if ($directAdmx) {
            for ($i = 0; $i -lt $chainMatches.Count; $i++) {
                if ($chainMatches[$i].Admx.id -eq $directAdmx.id) {
                    $directIndex = $i
                    break
                }
            }
        }
        elseif ($chainMatches.Count -gt 0) {
            # Namespace-hierarchy consistency check: accept the deepest matched file only if
            # its namespace descends from every matched file above it in the chain. This is a
            # conservative guard against category-name collisions, such as GoogleUpdate's
            # per-application 'Google Chrome' subcategory matching chrome.admx when the
            # category actually lives under Google.Policies.Update.
            for ($i = 0; $i -lt $chainMatches.Count -and $directIndex -lt 0; $i++) {
                $candidateMatch = $chainMatches[$i]
                $candidate = $candidateMatch.Admx
                $candidateNs = Get-AdmxNamespaceKey $candidate
                $consistent = $true

                for ($j = $i + 1; $j -lt $chainMatches.Count; $j++) {
                    $ancestor = $chainMatches[$j].Admx
                    if ($ancestor.id -eq $candidate.id) {
                        continue
                    }

                    $ancestorNs = Get-AdmxNamespaceKey $ancestor

                    if (-not ($candidateNs -and $ancestorNs -and $candidateNs.StartsWith("$ancestorNs."))) {
                        $consistent = $false
                        Write-Verbose "  Rejected '$($candidate.fileName)' as owner of '$($definition.categoryPath)': namespace '$($candidate.targetNamespace)' is not under '$($ancestor.targetNamespace)'."
                        break
                    }
                }

                if ($consistent) {
                    $directIndex = $i
                    $directAdmx = $candidate
                    $attributionSource = $candidateMatch.MatchRule
                    $attributionConfidence = $candidateMatch.Confidence
                }
            }

            if ($directIndex -lt 0) {
                # No candidate satisfies the hierarchy; take the root-most match as the
                # conservative fallback for a human-facing report.
                $directIndex = $chainMatches.Count - 1
                $directAdmx = $chainMatches[$directIndex].Admx
                $attributionSource = "$($chainMatches[$directIndex].MatchRule); root-most hierarchy fallback"
                $attributionConfidence = 'Inferred-Low'
                Write-Verbose "  No hierarchy-consistent owner for '$($definition.categoryPath)'; using root-most match '$($directAdmx.fileName)'."
            }
        }

        if ($directAdmx) {
            # Dependencies are the matched files above the direct owner in the category chain,
            # nearest first so the report reads in dependency order.
            $dependencyChain = if ($directIndex -ge 0 -and $directIndex + 1 -lt $chainMatches.Count) {
                @(
                    $chainMatches[($directIndex + 1)..($chainMatches.Count - 1)] |
                        ForEach-Object { $_.Admx } |
                        Where-Object { $_.id -ne $directAdmx.id } |
                        Sort-Object id -Unique
                )
            }
            else {
                @()
            }
        }

        $usageKey = if ($directAdmx) { $directAdmx.id } else { "UNRESOLVED:$($definition.id)" }
        $dependencyChainText = @($dependencyChain | ForEach-Object { $_.fileName }) -join " -> "
        $dependencySource = if ($chain.Count -gt 0) { 'Category parent tree inference' } else { 'Unavailable' }

        if (-not $profileAdmxUsage.ContainsKey($usageKey)) {
            $profileAdmxUsage[$usageKey] = [pscustomobject]@{
                Admx                   = $directAdmx
                Settings               = [System.Collections.Generic.List[string]]::new()
                CategoryPaths          = [System.Collections.Generic.List[string]]::new()
                DependencyChains       = [System.Collections.Generic.List[string]]::new()
                DependencySources      = [System.Collections.Generic.List[string]]::new()
                AttributionSources     = [System.Collections.Generic.List[string]]::new()
                AttributionConfidences = [System.Collections.Generic.List[string]]::new()
            }
        }
        $profileAdmxUsage[$usageKey].Settings.Add($definition.displayName)
        $profileAdmxUsage[$usageKey].CategoryPaths.Add($definition.categoryPath)
        $profileAdmxUsage[$usageKey].DependencyChains.Add($dependencyChainText)
        $profileAdmxUsage[$usageKey].DependencySources.Add($dependencySource)
        $profileAdmxUsage[$usageKey].AttributionSources.Add($attributionSource)
        $profileAdmxUsage[$usageKey].AttributionConfidences.Add($attributionConfidence)
    }

    foreach ($usageKey in $profileAdmxUsage.Keys) {
        $usage = $profileAdmxUsage[$usageKey]
        $admxName = if ($usage.Admx) { $usage.Admx.fileName } else { "UNRESOLVED (see CategoryPath)" }

        [pscustomobject]@{
            ConfigurationProfile = $profile.displayName
            ProfileId            = $profile.id
            DirectAdmx           = $admxName
            DependencyAdmxChain  = (@($usage.DependencyChains | Sort-Object -Unique) -join " | ")
            DependencySource     = (@($usage.DependencySources | Sort-Object -Unique) -join "; ")
            CategoryPath         = (@($usage.CategoryPaths | Sort-Object -Unique) -join "; ")
            SettingsConfigured   = ($usage.Settings | Sort-Object -Unique) -join "; "
            AdmxNamespace        = if ($usage.Admx) { $usage.Admx.targetNamespace } else { "" }
            AttributionSource    = (@($usage.AttributionSources | Sort-Object -Unique) -join "; ")
            AttributionConfidence = (@($usage.AttributionConfidences | Sort-Object -Unique) -join "; ")
        }
    }
}

$results = @($results | Sort-Object ConfigurationProfile, DirectAdmx)

if (-not $results) {
    Write-Host "No custom ADMX usage found in custom Administrative Templates profiles."
    return
}

$results | Format-Table ConfigurationProfile, DirectAdmx, DependencyAdmxChain, CategoryPath -AutoSize

if ($ExportCsv -or $PSBoundParameters.ContainsKey('CsvPath')) {
    $results | Export-Csv -Path $CsvPath -NoTypeInformation
    Write-Host "CSV exported to: $CsvPath"
}
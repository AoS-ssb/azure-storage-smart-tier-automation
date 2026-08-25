#requires -Version 7.2

<#
.SYNOPSIS
Audits or enables Azure Blob Storage Smart tier at resource-group or subscription scope.

.DESCRIPTION
This runbook is intentionally conservative:
- Audit is the default mode.
- An opt-in tag is required by default.
- Only eligible Standard StorageV2 accounts with zonal redundancy are changed.
- A preflight change cap prevents unexpectedly broad remediation.
- It performs no delete operations and no blob data-plane operations.
- It changes only the storage account's default accessTier property to Smart.

Blobs with an explicitly assigned access tier are not enrolled by this account-level change.

.PARAMETER Mode
Audit or Remediate. Defaults to Audit.

.PARAMETER ScopeType
ResourceGroup or Subscription.

.PARAMETER SubscriptionId
Target subscription GUID. If omitted, the managed identity's current subscription is used.

.PARAMETER ResourceGroupName
Required when ScopeType is ResourceGroup.

.PARAMETER RequireOptInTag
String boolean. Defaults to true. When true, only accounts with the required tag are eligible.

.PARAMETER RequiredTagName
Opt-in tag name. Defaults to SmartTierManaged.

.PARAMETER RequiredTagValue
Opt-in tag value. Defaults to true.

.PARAMETER MaxChanges
Maximum accounts one Remediate job may change. Defaults to 10.

.PARAMETER ManagedIdentityClientId
Optional user-assigned managed identity client ID. Omit for the Automation Account system identity.
#>

[CmdletBinding()]
param(
    [ValidateSet('Audit', 'Remediate')]
    [string] $Mode = 'Audit',

    [ValidateSet('ResourceGroup', 'Subscription')]
    [string] $ScopeType = 'ResourceGroup',

    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string] $SubscriptionId,

    [ValidatePattern('^[A-Za-z0-9._()\-]{1,90}$')]
    [string] $ResourceGroupName,

    [ValidateSet('true', 'false')]
    [string] $RequireOptInTag = 'true',

    [ValidateNotNullOrEmpty()]
    [string] $RequiredTagName = 'SmartTierManaged',

    [ValidateNotNullOrEmpty()]
    [string] $RequiredTagValue = 'true',

    [ValidateRange(1, 1000)]
    [int] $MaxChanges = 10,

    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string] $ManagedIdentityClientId
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$defaultManagementEndpoint = 'https://management.azure.com'
$storageApiVersion = '2025-08-01'
$eligibleSkus = @('Standard_ZRS', 'Standard_GZRS', 'Standard_RAGZRS')
$tagRequired = $RequireOptInTag -eq 'true'

function Invoke-ArmRequest {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('GET', 'PATCH')]
        [string] $Method,

        [Parameter(Mandatory)]
        [string] $Uri,

        [string] $Payload
    )

    $request = @{
        Method = $Method
        Uri = $Uri
    }
    if ($PSBoundParameters.ContainsKey('Payload')) {
        $request.Payload = $Payload
    }

    for ($attempt = 1; $attempt -le 5; $attempt++) {
        try {
            $response = Invoke-AzRestMethod @request
        }
        catch {
            $exceptionResponse = Get-PropertyValue -InputObject $_.Exception -Name 'Response'
            $exceptionStatus = Get-PropertyValue -InputObject $exceptionResponse -Name 'StatusCode'
            $statusCode = if ($null -ne $exceptionStatus) { [int] $exceptionStatus } else { $null }
            $isTransient = $statusCode -eq 429 -or ($null -ne $statusCode -and $statusCode -ge 500)
            if ($isTransient -and $attempt -lt 5) {
                Start-Sleep -Seconds ([math]::Min(20, [math]::Pow(2, $attempt)))
                continue
            }
            throw
        }
        $statusCodeProperty = $response.PSObject.Properties['StatusCode']
        if ($null -ne $statusCodeProperty) {
            $statusCode = [int] $statusCodeProperty.Value
            $isTransient = $statusCode -eq 429 -or $statusCode -ge 500
            if ($isTransient -and $attempt -lt 5) {
                Start-Sleep -Seconds ([math]::Min(20, [math]::Pow(2, $attempt)))
                continue
            }
            if ($statusCode -lt 200 -or $statusCode -ge 300) {
                $errorBody = [string] $response.Content
                if ($errorBody.Length -gt 2000) {
                    $errorBody = $errorBody.Substring(0, 2000)
                }
                throw "ARM $Method request returned HTTP $statusCode for $Uri. Response: $errorBody"
            }
        }
        if ([string]::IsNullOrWhiteSpace($response.Content)) {
            return $null
        }
        return $response.Content | ConvertFrom-Json -Depth 100
    }

    throw "ARM $Method request exhausted its retry budget for $Uri"
}

function Get-TagValue {
    param(
        [AllowNull()]
        [object] $Tags,

        [Parameter(Mandatory)]
        [string] $Name
    )

    if ($null -eq $Tags) {
        return $null
    }

    $property = $Tags.PSObject.Properties |
        Where-Object { $_.Name -ieq $Name } |
        Select-Object -First 1
    if ($null -eq $property) {
        return $null
    }
    return [string] $property.Value
}

function Get-PropertyValue {
    param(
        [AllowNull()]
        [object] $InputObject,

        [Parameter(Mandatory)]
        [string] $Name
    )

    if ($null -eq $InputObject) {
        return $null
    }

    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }
    return $property.Value
}

function Get-StorageAccounts {
    param(
        [Parameter(Mandatory)]
        [string] $InitialUri
    )

    $items = [System.Collections.Generic.List[object]]::new()
    $nextUri = $InitialUri
    while (-not [string]::IsNullOrWhiteSpace($nextUri)) {
        $page = Invoke-ArmRequest -Method GET -Uri $nextUri
        if ($null -ne $page.value) {
            foreach ($item in $page.value) {
                $items.Add($item)
            }
        }
        $nextLinkProperty = $page.PSObject.Properties['nextLink']
        $nextUri = if ($null -ne $nextLinkProperty) { [string] $nextLinkProperty.Value } else { $null }
    }
    return $items
}

Disable-AzContextAutosave -Scope Process | Out-Null
if ([string]::IsNullOrWhiteSpace($ManagedIdentityClientId)) {
    $context = (Connect-AzAccount -Identity).Context
}
else {
    $context = (Connect-AzAccount -Identity -AccountId $ManagedIdentityClientId).Context
}

if ([string]::IsNullOrWhiteSpace($SubscriptionId)) {
    $SubscriptionId = [string] $context.Subscription.Id
}
Set-AzContext -SubscriptionId $SubscriptionId | Out-Null

$contextEnvironment = Get-PropertyValue -InputObject $context -Name 'Environment'
$managementEndpoint = [string] (Get-PropertyValue -InputObject $contextEnvironment -Name 'ResourceManagerUrl')
if ([string]::IsNullOrWhiteSpace($managementEndpoint)) {
    $environmentName = if ($contextEnvironment -is [string]) {
        [string] $contextEnvironment
    }
    else {
        [string] (Get-PropertyValue -InputObject $contextEnvironment -Name 'Name')
    }
    if (-not [string]::IsNullOrWhiteSpace($environmentName)) {
        $azEnvironment = Get-AzEnvironment -Name $environmentName
        $managementEndpoint = [string] (Get-PropertyValue -InputObject $azEnvironment -Name 'ResourceManagerUrl')
    }
}
if ([string]::IsNullOrWhiteSpace($managementEndpoint)) {
    $managementEndpoint = $defaultManagementEndpoint
}
$managementEndpoint = $managementEndpoint.TrimEnd('/')

if ($ScopeType -eq 'ResourceGroup' -and [string]::IsNullOrWhiteSpace($ResourceGroupName)) {
    throw 'ResourceGroupName is required when ScopeType is ResourceGroup.'
}

$subscriptionPrefix = "/subscriptions/$SubscriptionId/"
if ($ScopeType -eq 'ResourceGroup') {
    $scopePrefix = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/"
    $encodedResourceGroup = [uri]::EscapeDataString($ResourceGroupName)
    $listUri = "$managementEndpoint/subscriptions/$SubscriptionId/resourceGroups/$encodedResourceGroup/providers/Microsoft.Storage/storageAccounts?api-version=$storageApiVersion"
}
else {
    $scopePrefix = $subscriptionPrefix
    $listUri = "$managementEndpoint/subscriptions/$SubscriptionId/providers/Microsoft.Storage/storageAccounts?api-version=$storageApiVersion"
}

$accounts = @(Get-StorageAccounts -InitialUri $listUri)
$results = [System.Collections.Generic.List[object]]::new()
$candidates = [System.Collections.Generic.List[object]]::new()

foreach ($account in $accounts) {
    $accountId = [string] (Get-PropertyValue -InputObject $account -Name 'id')
    if (-not $accountId.StartsWith($scopePrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "ARM returned an out-of-scope resource: $accountId"
    }

    $reasons = [System.Collections.Generic.List[string]]::new()
    $accountProperties = Get-PropertyValue -InputObject $account -Name 'properties'
    $skuProperties = Get-PropertyValue -InputObject $account -Name 'sku'
    $sku = [string] (Get-PropertyValue -InputObject $skuProperties -Name 'name')
    $kind = [string] (Get-PropertyValue -InputObject $account -Name 'kind')
    $state = [string] (Get-PropertyValue -InputObject $accountProperties -Name 'provisioningState')
    $currentTier = [string] (Get-PropertyValue -InputObject $accountProperties -Name 'accessTier')
    $tags = Get-PropertyValue -InputObject $account -Name 'tags'
    $tagValue = Get-TagValue -Tags $tags -Name $RequiredTagName

    if ($kind -ne 'StorageV2') {
        $reasons.Add("UnsupportedKind:$kind")
    }
    if ($sku -notin $eligibleSkus) {
        $reasons.Add("UnsupportedSku:$sku")
    }
    if ($state -ne 'Succeeded') {
        $reasons.Add("ProvisioningState:$state")
    }
    if ($tagRequired -and $tagValue -ine $RequiredTagValue) {
        $reasons.Add("MissingOptInTag:$RequiredTagName=$RequiredTagValue")
    }

    $baseResult = [ordered]@{
        name = [string] (Get-PropertyValue -InputObject $account -Name 'name')
        id = $accountId
        resourceGroup = ($accountId -split '/')[4]
        location = [string] (Get-PropertyValue -InputObject $account -Name 'location')
        kind = $kind
        sku = $sku
        beforeTier = if ([string]::IsNullOrWhiteSpace($currentTier)) { '(default)' } else { $currentTier }
        afterTier = if ([string]::IsNullOrWhiteSpace($currentTier)) { '(default)' } else { $currentTier }
        status = $null
        reasons = @($reasons)
    }

    if ($reasons.Count -gt 0) {
        $baseResult.status = 'Skipped'
        $results.Add([pscustomobject] $baseResult)
        continue
    }
    if ($currentTier -ieq 'Smart') {
        $baseResult.status = 'AlreadySmart'
        $results.Add([pscustomobject] $baseResult)
        continue
    }

    $baseResult.status = if ($Mode -eq 'Audit') { 'WouldRemediate' } else { 'PendingRemediation' }
    $resultObject = [pscustomobject] $baseResult
    $results.Add($resultObject)
    $candidates.Add([pscustomobject]@{ account = $account; result = $resultObject })
}

if ($Mode -eq 'Remediate' -and $candidates.Count -gt $MaxChanges) {
    throw "Preflight stopped the job: $($candidates.Count) accounts require a change, exceeding MaxChanges=$MaxChanges. No accounts were changed."
}

$failureCount = 0
if ($Mode -eq 'Remediate') {
    $payload = @{ properties = @{ accessTier = 'Smart' } } | ConvertTo-Json -Depth 4 -Compress
    foreach ($candidate in $candidates) {
        $accountId = [string] (Get-PropertyValue -InputObject $candidate.account -Name 'id')
        try {
            $updateUri = "$managementEndpoint${accountId}?api-version=$storageApiVersion"

            # Re-read every candidate immediately before changing it. This closes the gap if
            # eligibility, provisioning state, or the opt-in tag changed after enumeration.
            $fresh = Invoke-ArmRequest -Method GET -Uri $updateUri
            $freshId = [string] (Get-PropertyValue -InputObject $fresh -Name 'id')
            if ($freshId -ine $accountId -or
                -not $freshId.StartsWith($scopePrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
                throw "Precondition GET returned an unexpected resource: $freshId"
            }

            $freshProperties = Get-PropertyValue -InputObject $fresh -Name 'properties'
            $freshSkuProperties = Get-PropertyValue -InputObject $fresh -Name 'sku'
            $freshSku = [string] (Get-PropertyValue -InputObject $freshSkuProperties -Name 'name')
            $freshKind = [string] (Get-PropertyValue -InputObject $fresh -Name 'kind')
            $freshState = [string] (Get-PropertyValue -InputObject $freshProperties -Name 'provisioningState')
            $freshTier = [string] (Get-PropertyValue -InputObject $freshProperties -Name 'accessTier')
            $freshTags = Get-PropertyValue -InputObject $fresh -Name 'tags'
            $freshTagValue = Get-TagValue -Tags $freshTags -Name $RequiredTagName
            $preconditionReasons = [System.Collections.Generic.List[string]]::new()

            if ($freshKind -ne 'StorageV2') {
                $preconditionReasons.Add("UnsupportedKind:$freshKind")
            }
            if ($freshSku -notin $eligibleSkus) {
                $preconditionReasons.Add("UnsupportedSku:$freshSku")
            }
            if ($freshState -ne 'Succeeded') {
                $preconditionReasons.Add("ProvisioningState:$freshState")
            }
            if ($tagRequired -and $freshTagValue -ine $RequiredTagValue) {
                $preconditionReasons.Add("MissingOptInTag:$RequiredTagName=$RequiredTagValue")
            }
            if ($preconditionReasons.Count -gt 0) {
                $candidate.result.status = 'Skipped'
                $candidate.result.reasons = @('PreconditionChanged') + @($preconditionReasons)
                continue
            }
            if ($freshTier -ieq 'Smart') {
                $candidate.result.afterTier = 'Smart'
                $candidate.result.status = 'AlreadySmart'
                continue
            }

            $null = Invoke-ArmRequest -Method PATCH -Uri $updateUri -Payload $payload
            $verifiedTier = $null
            for ($attempt = 1; $attempt -le 6; $attempt++) {
                if ($attempt -gt 1) {
                    Start-Sleep -Seconds 5
                }
                $verified = Invoke-ArmRequest -Method GET -Uri $updateUri
                $verifiedProperties = Get-PropertyValue -InputObject $verified -Name 'properties'
                $verifiedTier = [string] (Get-PropertyValue -InputObject $verifiedProperties -Name 'accessTier')
                if ($verifiedTier -ieq 'Smart') {
                    break
                }
            }
            if ($verifiedTier -ine 'Smart') {
                throw "ARM verification returned accessTier '$verifiedTier' instead of 'Smart'."
            }
            $candidate.result.afterTier = $verifiedTier
            $candidate.result.status = 'Remediated'
        }
        catch {
            $failureCount++
            $candidate.result.status = 'Failed'
            $candidate.result.reasons = @("$($_.Exception.Message)")
        }
    }
}

$summary = [ordered]@{
    schemaVersion = '1.0'
    timestampUtc = (Get-Date).ToUniversalTime().ToString('o')
    mode = $Mode
    scopeType = $ScopeType
    subscriptionId = $SubscriptionId
    resourceGroupName = if ($ScopeType -eq 'ResourceGroup') { $ResourceGroupName } else { $null }
    optInTagRequired = $tagRequired
    requiredTag = if ($tagRequired) { "$RequiredTagName=$RequiredTagValue" } else { $null }
    maxChanges = $MaxChanges
    counts = [ordered]@{
        discovered = $accounts.Count
        eligibleChanges = $candidates.Count
        remediated = @($results | Where-Object status -eq 'Remediated').Count
        alreadySmart = @($results | Where-Object status -eq 'AlreadySmart').Count
        skipped = @($results | Where-Object status -eq 'Skipped').Count
        failed = @($results | Where-Object status -eq 'Failed').Count
    }
    results = @($results)
}

$summary | ConvertTo-Json -Depth 12 -Compress | Write-Output
if ($failureCount -gt 0) {
    throw "$failureCount storage account remediation operation(s) failed. Review the structured output."
}

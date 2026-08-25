<#
.SYNOPSIS
Audits or enables Azure Blob Storage smart tier on eligible, explicitly opted-in storage accounts.

.DESCRIPTION
Version 1.1 of the Azure Automation runbook. It enumerates storage accounts at resource-group or
subscription scope, classifies every account, and - only in Remediate mode, after every preflight
guard passes - sets the account-level default access tier to Smart with a single-property PATCH,
then verifies the result by re-reading the account.

Safety properties:
- Audit is the default. Remediate writes exactly one named account per run (ScopeType=ResourceGroup,
  ResourceGroupName and AccountName are all required), after a point read whose id and name must agree
  with the listing and the request, never more than MaxChanges (default 1), and refuses to run without
  the opt-in tag (<RequiredTagName>=true, compared exactly - Azure tag values are case-sensitive) unless
  AllowUntaggedRemediation is set. A named account that is neither eligible nor already Smart aborts the
  run (TargetNotEligible); an already-Smart target is the idempotent success case.
- Only Standard general-purpose v2 accounts with zone-redundant SKUs (ZRS, GZRS, RA-GZRS) in the
  Succeeded state are eligible; an exclusion tag always wins; a ReadOnly lock is recognised from the
  409 ScopeLocked it produces and reported as BlockedScopeLock - never retried, never green. There is
  deliberately no lock preflight and the roles carry no locks/read.
- The PATCH body is always {"properties":{"accessTier":"Smart"}} and nothing else.
- Every outcome is reported honestly: Remediated (verified by re-read), BlockedScopeLock,
  SkippedPreconditionChanged, Deferred (transient conflict), Failed (definitive) or
  WriteOutcomeUnknown (a lost response that re-reads could not resolve). A write with an unknown
  outcome is never resubmitted; a 403 stops the run instead of failing every account.
- Output is one JSON line per account as soon as its state is known, an INTENT line immediately before
  every PATCH, and a final SUMMARY line that is emitted on every path - parameter errors, aborts and
  unexpected errors included (only parameter *binding* errors, e.g. a malformed SubscriptionId, fail
  before the script body runs).
- No new write starts after JobTimeBudgetSeconds, well inside the Azure Automation job limit.
- The runbook issues no DELETE, reads no keys, and touches no blob data.

It authenticates with the Automation Account's system-assigned managed identity (Az.Accounts) and
passes the resulting context explicitly to every Az call.
#>

[CmdletBinding()]
param(
    [ValidateSet('Audit', 'Remediate')]
    [string] $Mode = 'Audit',

    [ValidateSet('ResourceGroup', 'Subscription')]
    [string] $ScopeType = 'ResourceGroup',

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string] $SubscriptionId,

    [string] $ResourceGroupName = '',

    [string] $AccountName = '',

    [bool] $RequireOptInTag = $true,

    [bool] $AllowUntaggedRemediation = $false,

    [ValidateNotNullOrEmpty()]
    [string] $RequiredTagName = 'SmartTierManaged',

    [ValidateNotNullOrEmpty()]
    [string] $ExclusionTagName = 'SmartTierExclude',

    [ValidateRange(1, 1000)]
    [int] $MaxChanges = 1,

    [ValidateRange(0, 1000)]
    [int] $ExpectedChanges = 0,

    [ValidateRange(60, 9000)]
    [int] $JobTimeBudgetSeconds = 8400,

    [bool] $AllowNonPublicCloud = $false,

    [ValidatePattern('^20[0-9]{2}-[0-9]{2}-[0-9]{2}$')]
    [string] $StorageApiVersion = '2025-08-01'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSVersion.Major -lt 7) {
    throw "This runbook needs PowerShell 7.x (Azure Automation PowerShell 7.4 runtime); running $($PSVersionTable.PSVersion)."
}
$ProgressPreference = 'SilentlyContinue'

$script:RunbookVersion = '1.1.0'
# The consent value is fixed (judged decision): Azure tag values are case-sensitive, so 'True' is not consent.
$script:RequiredTagValue = 'true'
$script:JobStarted = [DateTime]::UtcNow
$script:JobBudget = $JobTimeBudgetSeconds
$script:EligibleSkus = @('Standard_ZRS', 'Standard_GZRS', 'Standard_RAGZRS')
# Smart tier is GA in public Azure; Microsoft documents previews (feature registration required) only here.
$script:PreviewClouds = @('AzureUSGovernment', 'AzureChinaCloud')
$script:PatchPayload = '{"properties":{"accessTier":"Smart"}}'
# Documented transient conflicts (Storage RP update errors); every other 409 is definitive.
$script:TransientConflictCodes = @('StorageAccountOperationInProgress')

# ---------------------------------------------------------------------------------------------
# Parameter validation - before any network call
# ---------------------------------------------------------------------------------------------

function Assert-ExactName {
    param(
        [Parameter(Mandatory = $true)]
        [string] $ParameterName,
        [AllowEmptyString()]
        [string] $Value
    )

    if ($Value.Length -gt 0 -and $Value.Trim().Length -eq 0) {
        throw "$ParameterName was supplied but is blank/whitespace. Supply the exact name, or omit the parameter."
    }
    if ($Value -cne $Value.Trim()) {
        throw "$ParameterName contains leading or trailing whitespace. Supply the exact name."
    }
}

function Test-ParameterSet {
    # Throws on any contradictory or unbound parameter set. Called inside the main try block so the
    # failure is reported as abortReason=InvalidParameters with a SUMMARY line.
    Assert-ExactName -ParameterName 'ResourceGroupName' -Value $ResourceGroupName
    Assert-ExactName -ParameterName 'AccountName' -Value $AccountName

    if ($ScopeType -eq 'ResourceGroup') {
        if ($ResourceGroupName.Length -eq 0) {
            throw 'ResourceGroupName is required when ScopeType is ResourceGroup.'
        }
        if ($ResourceGroupName -notmatch '^[A-Za-z0-9._()\-]{1,90}$') {
            throw 'ResourceGroupName contains characters that are not valid in a resource group name.'
        }
    }
    elseif ($ResourceGroupName.Length -gt 0) {
        throw 'ResourceGroupName must not be supplied when ScopeType is Subscription. Use ScopeType=ResourceGroup to target one resource group.'
    }
    if ($AccountName.Length -gt 0 -and $AccountName -notmatch '^[a-z0-9]{3,24}$') {
        throw 'AccountName must be 3-24 lowercase letters and digits (an exact storage account name).'
    }
    if ($Mode -eq 'Remediate') {
        if ($ScopeType -ne 'ResourceGroup') {
            throw 'Remediate is resource-group scoped only: set ScopeType=ResourceGroup and ResourceGroupName. Subscription-scope writes are not supported.'
        }
        if ($AccountName.Length -eq 0) {
            throw 'Remediate requires AccountName: this runbook enables smart tier on exactly one named storage account per run.'
        }
        if ($ExpectedChanges -gt 1) {
            throw 'ExpectedChanges cannot exceed 1 when remediating a single named account.'
        }
        if (-not $RequireOptInTag -and -not $AllowUntaggedRemediation) {
            throw 'Remediate with RequireOptInTag=false is refused unless AllowUntaggedRemediation=true (the named account is then written without the opt-in tag; the exclusion tag still wins).'
        }
    }
}

# ---------------------------------------------------------------------------------------------
# JSON helpers (System.Text.Json nodes keep every value exactly as the API sent it)
# ---------------------------------------------------------------------------------------------

function ConvertTo-JsonNode {
    param(
        [AllowNull()]
        [AllowEmptyString()]
        [string] $Text
    )

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return $null
    }
    try {
        # Comma operator: JsonNode types are IEnumerable and would otherwise unroll on return.
        return , [System.Text.Json.Nodes.JsonNode]::Parse($Text)
    }
    catch {
        return $null
    }
}

function Get-JsonMember {
    param(
        [AllowNull()]
        [object] $Node,
        [Parameter(Mandatory = $true)]
        [string] $Name
    )

    if ($null -eq $Node -or $Node -isnot [System.Text.Json.Nodes.JsonObject]) {
        return $null
    }
    if ($Node.ContainsKey($Name)) {
        return , $Node[$Name]
    }
    foreach ($pair in $Node) {
        if ($pair.Key -ieq $Name) {
            return , $pair.Value
        }
    }
    return $null
}

function Get-JsonString {
    param(
        [AllowNull()]
        [object] $Node
    )

    if ($null -eq $Node) {
        return $null
    }
    if ($Node -is [System.Text.Json.Nodes.JsonValue]) {
        return [string]$Node.ToString()
    }
    return [string]$Node.ToJsonString()
}

function Get-JsonBool {
    param(
        [AllowNull()]
        [object] $Node
    )

    $text = Get-JsonString -Node $Node
    if ($null -eq $text) {
        return $null
    }
    return ($text -ieq 'true')
}

function Get-PropertyValue {
    param(
        [AllowNull()]
        [object] $InputObject,
        [Parameter(Mandatory = $true)]
        [string] $Name
    )

    if ($null -eq $InputObject) {
        return $null
    }
    if ($InputObject -is [System.Collections.IDictionary]) {
        foreach ($key in $InputObject.Keys) {
            if ([string]$key -ieq $Name) {
                return $InputObject[$key]
            }
        }
        return $null
    }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }
    return $property.Value
}

function Get-HeaderValue {
    param(
        [AllowNull()]
        [object] $Headers,
        [Parameter(Mandatory = $true)]
        [string] $Name
    )

    if ($null -eq $Headers) {
        return $null
    }
    if ($Headers -is [System.Net.Http.Headers.HttpHeaders]) {
        # PSHttpResponse.Headers is HttpResponseHeaders: names are case-insensitive, values are enumerations.
        $values = $null
        if ($Headers.TryGetValues($Name, [ref]$values) -and $null -ne $values) {
            $firstValue = @($values)[0]
            if ($null -ne $firstValue) {
                return [string]$firstValue
            }
        }
        return $null
    }
    $keys = $null
    if ($Headers -is [System.Collections.IDictionary]) {
        $keys = @($Headers.Keys)
    }
    else {
        $keysProperty = $Headers.PSObject.Properties['Keys']
        if ($null -ne $keysProperty) {
            $keys = @($keysProperty.Value)
        }
    }
    if ($null -eq $keys) {
        return $null
    }
    foreach ($key in $keys) {
        if ([string]$key -ieq $Name) {
            $value = $Headers[$key]
            if ($null -eq $value) {
                return $null
            }
            $first = @($value)[0]
            if ($null -eq $first) {
                return $null
            }
            return [string]$first
        }
    }
    return $null
}

function Get-TagEntry {
    # Tag names are case-insensitive in Azure. Returns $null when the tag is absent; otherwise an object
    # with Present=$true, Value (the raw string, or $null when the JSON value is not a string) and Raw
    # (the JSON text). Only a JSON string can be consent; anything else fails closed.
    param(
        [AllowNull()]
        [object] $TagsNode,
        [Parameter(Mandatory = $true)]
        [string] $Name
    )

    if ($null -eq $TagsNode -or $TagsNode -isnot [System.Text.Json.Nodes.JsonObject]) {
        return $null
    }
    foreach ($pair in $TagsNode) {
        if ($pair.Key -ine $Name) {
            continue
        }
        $node = $pair.Value
        $value = $null
        $raw = 'null'
        if ($null -ne $node) {
            $raw = $node.ToJsonString()
            if ($node -is [System.Text.Json.Nodes.JsonValue] -and $node.GetValueKind() -eq [System.Text.Json.JsonValueKind]::String) {
                $value = [string]$node.ToString()
            }
        }
        return [pscustomobject]@{ Present = $true; Value = $value; Raw = $raw }
    }
    return $null
}

function Get-RemainingJobBudget {
    $elapsed = ([DateTime]::UtcNow - $script:JobStarted).TotalSeconds
    return [int][Math]::Max(0, [Math]::Floor($script:JobBudget - $elapsed))
}

function Get-BackoffDelay {
    param(
        [Parameter(Mandatory = $true)]
        [int] $Attempt,
        [AllowNull()]
        [object] $RetryAfterSeconds
    )

    $base = [Math]::Pow(2, $Attempt)
    if ($null -ne $RetryAfterSeconds -and [int]$RetryAfterSeconds -gt 0) {
        $base = [int]$RetryAfterSeconds
    }
    return [int]$base + (Get-Random -Minimum 0 -Maximum 2)
}

function Assert-ArmUri {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Uri
    )

    if (-not $Uri.StartsWith($script:ManagementEndpoint + '/', [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to call a URL outside the Resource Manager endpoint: $Uri"
    }
}

function Invoke-ArmCall {
    # Returns [pscustomobject]@{ StatusCode; Content; Body; Headers; ArmCode; ArmMessage; RequestId;
    # Transport (bool: no HTTP response at all); Error (message) }.
    # GET: retries 408/429/5xx and transport failures (Retry-After honoured, jitter, budget-bounded,
    # max 4 attempts) and throws when exhausted. PATCH: retries only 429; every other outcome - including
    # a transport failure after the request may have been sent - is RETURNED for the caller to classify.
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('GET', 'PATCH')]
        [string] $Method,
        [Parameter(Mandatory = $true)]
        [string] $Uri,
        [AllowNull()]
        [string] $Payload
    )

    Assert-ArmUri -Uri $Uri
    $maxAttempts = 4
    $last = $null
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        $request = @{ Method = $Method; Uri = $Uri; DefaultProfile = $script:AzContext }
        if (-not [string]::IsNullOrEmpty($Payload)) {
            $request.Payload = $Payload
        }
        $result = [ordered]@{
            StatusCode = $null; Content = ''; Body = $null; Headers = $null
            ArmCode = $null; ArmMessage = $null; RequestId = $null; Transport = $false; Error = $null
        }
        try {
            $response = Invoke-AzRestMethod @request
            $result.StatusCode = [int](Get-PropertyValue -InputObject $response -Name 'StatusCode')
            $content = Get-PropertyValue -InputObject $response -Name 'Content'
            if ($null -ne $content) {
                $result.Content = [string]$content
            }
            $result.Headers = Get-PropertyValue -InputObject $response -Name 'Headers'
            $result.RequestId = Get-HeaderValue -Headers $result.Headers -Name 'x-ms-request-id'
            $result.Body = ConvertTo-JsonNode -Text $result.Content
        }
        catch {
            # Some Az errors carry the HTTP response on the exception: recover it rather than reporting a
            # transport failure (which would make a definitive rejection look ambiguous).
            $caught = $_.Exception
            $recovered = $false
            $carried = Get-PropertyValue -InputObject $caught -Name 'Response'
            if ($null -ne $carried) {
                $carriedStatus = Get-PropertyValue -InputObject $carried -Name 'StatusCode'
                if ($null -ne $carriedStatus) {
                    try {
                        $result.StatusCode = [int]$carriedStatus
                        $recovered = $true
                    }
                    catch {
                        $recovered = $false
                    }
                }
                if ($recovered) {
                    $carriedContent = Get-PropertyValue -InputObject $carried -Name 'Content'
                    if ($null -ne $carriedContent) {
                        $result.Content = [string]$carriedContent
                    }
                    $result.Headers = Get-PropertyValue -InputObject $carried -Name 'Headers'
                    $result.RequestId = Get-HeaderValue -Headers $result.Headers -Name 'x-ms-request-id'
                    $result.Body = ConvertTo-JsonNode -Text $result.Content
                }
            }
            if (-not $recovered) {
                $result.Transport = $true
                $result.Error = "transport failure: $($caught.Message)"
            }
        }
        if (-not $result.Transport -and $null -ne $result.StatusCode -and $result.StatusCode -ge 400) {
            $errorNode = Get-JsonMember -Node $result.Body -Name 'error'
            $result.ArmCode = Get-JsonString -Node (Get-JsonMember -Node $errorNode -Name 'code')
            $result.ArmMessage = Get-JsonString -Node (Get-JsonMember -Node $errorNode -Name 'message')
            if ([string]::IsNullOrWhiteSpace($result.ArmMessage)) {
                $result.ArmMessage = $result.Content
            }
            if ($result.ArmMessage.Length -gt 1500) {
                $result.ArmMessage = $result.ArmMessage.Substring(0, 1500)
            }
            $result.Error = "HTTP $($result.StatusCode) $($result.ArmCode): $($result.ArmMessage)"
        }
        $last = [pscustomobject]$result

        $retryAfter = $null
        $retryAfterText = Get-HeaderValue -Headers $last.Headers -Name 'Retry-After'
        if ($null -ne $retryAfterText -and $retryAfterText -match '^\d+$') {
            $retryAfter = [int]$retryAfterText
        }
        $transient = $last.Transport -or ($last.StatusCode -in @(408, 429)) -or ($last.StatusCode -ge 500 -and $last.StatusCode -le 599)
        if ($Method -eq 'PATCH') {
            $transient = ($last.StatusCode -eq 429)
        }
        if ($transient -and $attempt -lt $maxAttempts) {
            $delay = Get-BackoffDelay -Attempt $attempt -RetryAfterSeconds $retryAfter
            if ($delay -gt 300 -or $delay -gt (Get-RemainingJobBudget)) {
                # Never shorten a Retry-After (ARM does not process early retries), never wait more than
                # five minutes for one call, and never retry past the job budget: stop and let the caller
                # classify the last response.
                break
            }
            Start-Sleep -Seconds $delay
            continue
        }
        break
    }

    if ($Method -eq 'GET' -and ($last.Transport -or $last.StatusCode -ge 400)) {
        $exception = [System.InvalidOperationException]::new("ARM GET failed for $Uri`: $($last.Error)")
        $exception.Data['HttpStatus'] = $last.StatusCode
        $exception.Data['ArmCode'] = $last.ArmCode
        $exception.Data['RequestId'] = $last.RequestId
        throw $exception
    }
    return $last
}

function Get-ExceptionDiagnostic {
    param(
        [Parameter(Mandatory = $true)]
        [object] $ErrorRecord,
        [Parameter(Mandatory = $true)]
        [string] $Key
    )

    $exception = Get-PropertyValue -InputObject $ErrorRecord -Name 'Exception'
    if ($null -ne $exception -and $null -ne $exception.Data -and $exception.Data.Contains($Key)) {
        return $exception.Data[$Key]
    }
    return $null
}

function Get-ArmCollection {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Uri
    )

    $items = [System.Collections.Generic.List[object]]::new()
    $nextUri = $Uri
    while (-not [string]::IsNullOrWhiteSpace($nextUri)) {
        $page = (Invoke-ArmCall -Method GET -Uri $nextUri -Payload $null).Body
        $values = Get-JsonMember -Node $page -Name 'value'
        if ($values -is [System.Text.Json.Nodes.JsonArray]) {
            foreach ($item in $values) {
                if ($null -ne $item) {
                    $items.Add($item)
                }
            }
        }
        $nextUri = Get-JsonString -Node (Get-JsonMember -Node $page -Name 'nextLink')
    }
    return $items.ToArray()
}

# ---------------------------------------------------------------------------------------------
# Rows and counters
# ---------------------------------------------------------------------------------------------

$counters = [ordered]@{
    discovered = 0; candidates = 0; remediated = 0; alreadySmart = 0; skipped = 0; excluded = 0
    notOptedIn = 0; locked = 0; preconditionChanged = 0; deferred = 0; failed = 0; unknown = 0
    budgetSkipped = 0; runAborted = 0; errors = 0; patchesSubmitted = 0
}

function Format-ResultRow {
    param(
        [AllowNull()][object] $Account,
        [Parameter(Mandatory = $true)][string] $Status,
        [Parameter(Mandatory = $true)][string] $Stage,
        [AllowNull()][object] $Reasons,
        [AllowNull()][object] $BeforeTier,
        [AllowNull()][object] $AfterTier,
        [AllowNull()][object] $HttpStatus,
        [AllowNull()][object] $ArmCode,
        [AllowNull()][object] $RequestId,
        [AllowNull()][object] $Message
    )

    $id = $null; $name = $null; $rg = $null; $location = $null; $kind = $null; $sku = $null; $hns = $null
    if ($null -ne $Account) {
        $id = Get-JsonString -Node (Get-JsonMember -Node $Account -Name 'id')
        $name = Get-JsonString -Node (Get-JsonMember -Node $Account -Name 'name')
        $location = Get-JsonString -Node (Get-JsonMember -Node $Account -Name 'location')
        $kind = Get-JsonString -Node (Get-JsonMember -Node $Account -Name 'kind')
        $sku = Get-JsonString -Node (Get-JsonMember -Node (Get-JsonMember -Node $Account -Name 'sku') -Name 'name')
        $hns = Get-JsonBool -Node (Get-JsonMember -Node (Get-JsonMember -Node $Account -Name 'properties') -Name 'isHnsEnabled')
        if ($null -ne $id) {
            $parts = $id -split '/'
            if ($parts.Count -gt 4) {
                $rg = $parts[4]
            }
        }
    }
    $reasonList = @()
    if ($null -ne $Reasons) {
        $reasonList = @($Reasons | ForEach-Object { [string]$_ })
    }
    return [ordered]@{
        timestamp      = [DateTime]::UtcNow.ToString('o')
        event          = if ($Stage -eq 'Evaluate') { 'Classification' } else { 'Outcome' }
        subscriptionId = $SubscriptionId
        resourceGroup  = $rg
        name           = $name
        id             = $id
        location       = $location
        kind           = $kind
        sku            = $sku
        isHnsEnabled   = $hns
        beforeTier     = $BeforeTier
        afterTier      = $AfterTier
        status         = $Status
        reasons        = $reasonList
        stage          = $Stage
        httpStatus     = $HttpStatus
        armCode        = $ArmCode
        requestId      = $RequestId
        message        = $Message
    }
}

function Write-ResultRow {
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.Specialized.OrderedDictionary] $Row
    )

    $json = ($Row | ConvertTo-Json -Compress -Depth 4)
    Write-Output $json
    if ($Row.status -in @('Error', 'Failed', 'WriteOutcomeUnknown', 'Deferred', 'BlockedScopeLock')) {
        Write-Warning $json
    }
}

# ---------------------------------------------------------------------------------------------
# Classification (shared by discovery and the pre-write re-check)
# ---------------------------------------------------------------------------------------------

function Get-Classification {
    # Returns [pscustomobject]@{ Status; Reasons; Tier } for one account node. Order matters.
    param(
        [Parameter(Mandatory = $true)]
        [object] $Account
    )

    $properties = Get-JsonMember -Node $Account -Name 'properties'
    $tags = Get-JsonMember -Node $Account -Name 'tags'
    $kind = Get-JsonString -Node (Get-JsonMember -Node $Account -Name 'kind')
    $sku = Get-JsonString -Node (Get-JsonMember -Node (Get-JsonMember -Node $Account -Name 'sku') -Name 'name')
    $state = Get-JsonString -Node (Get-JsonMember -Node $properties -Name 'provisioningState')
    $tier = Get-JsonString -Node (Get-JsonMember -Node $properties -Name 'accessTier')
    $reasons = [System.Collections.Generic.List[string]]::new()

    if ($kind -ne 'StorageV2') {
        $reasons.Add("UnsupportedKind:$kind")
    }
    if ($sku -notin $script:EligibleSkus) {
        $reasons.Add("UnsupportedSku:$sku")
    }
    if ($state -ne 'Succeeded') {
        $reasons.Add("ProvisioningState:$state")
    }
    if ($reasons.Count -gt 0) {
        return [pscustomobject]@{ Status = 'Skipped'; Reasons = $reasons.ToArray(); Tier = $tier }
    }

    if ($null -ne $tags -and $tags -isnot [System.Text.Json.Nodes.JsonObject]) {
        throw "The account's 'tags' member is not a JSON object; refusing to classify it."
    }
    $exclusion = Get-TagEntry -TagsNode $tags -Name $ExclusionTagName
    if ($null -ne $exclusion) {
        return [pscustomobject]@{ Status = 'SkippedExcluded'; Reasons = @("ExclusionTag:$ExclusionTagName=$($exclusion.Raw)"); Tier = $tier }
    }
    if ($RequireOptInTag) {
        $optIn = Get-TagEntry -TagsNode $tags -Name $RequiredTagName
        # Azure tag values are case-sensitive: the comparison is exact, and only a JSON string counts.
        if ($null -eq $optIn -or $null -eq $optIn.Value -or $optIn.Value -cne $script:RequiredTagValue) {
            $found = if ($null -eq $optIn) { 'absent' } elseif ($null -eq $optIn.Value) { "found non-string $($optIn.Raw)" } else { "found '$($optIn.Value)'" }
            return [pscustomobject]@{ Status = 'SkippedNotOptedIn'; Reasons = @("MissingOptInTag:$RequiredTagName=$($script:RequiredTagValue) ($found)"); Tier = $tier }
        }
    }
    if ($tier -ieq 'Smart') {
        return [pscustomobject]@{ Status = 'AlreadySmart'; Reasons = @(); Tier = $tier }
    }
    return [pscustomobject]@{ Status = 'WouldRemediate'; Reasons = @(); Tier = $tier }
}

# ---------------------------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------------------------

$abortReason = $null
$abortMessage = $null
$fatal = $null
$script:AzContext = $null
$script:ManagementEndpoint = $null
$environmentName = $null
$candidateList = [System.Collections.Generic.List[object]]::new()
$targetStatus = $null
$targetReasons = @()

try {
    # --- parameters (reported through SUMMARY, before any network call) -----------------------
    try {
        Test-ParameterSet
    }
    catch {
        $abortReason = 'InvalidParameters'; $abortMessage = $_.Exception.Message
        throw
    }

    # --- identity and context -----------------------------------------------------------------
    Disable-AzContextAutosave -Scope Process | Out-Null
    $connection = Connect-AzAccount -Identity
    $initialContext = Get-PropertyValue -InputObject $connection -Name 'Context'
    $script:AzContext = Set-AzContext -SubscriptionId $SubscriptionId -DefaultProfile $initialContext
    if ($null -eq $script:AzContext) {
        throw 'Set-AzContext returned no context for the requested subscription.'
    }
    $environment = Get-PropertyValue -InputObject $script:AzContext -Name 'Environment'
    $environmentName = [string](Get-PropertyValue -InputObject $environment -Name 'Name')
    $script:ManagementEndpoint = [string](Get-PropertyValue -InputObject $environment -Name 'ResourceManagerUrl')
    if ([string]::IsNullOrWhiteSpace($script:ManagementEndpoint)) {
        if ($environmentName -eq 'AzureCloud') {
            $script:ManagementEndpoint = 'https://management.azure.com'
        }
        else {
            throw "Could not resolve the Resource Manager endpoint for environment '$environmentName'; refusing to guess."
        }
    }
    $script:ManagementEndpoint = $script:ManagementEndpoint.TrimEnd('/')

    # --- discovery ----------------------------------------------------------------------------
    $subscriptionPrefix = "/subscriptions/$SubscriptionId/"
    if ($ScopeType -eq 'ResourceGroup') {
        $scopePrefix = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/"
        $listUri = "$script:ManagementEndpoint/subscriptions/$SubscriptionId/resourceGroups/$([uri]::EscapeDataString($ResourceGroupName))/providers/Microsoft.Storage/storageAccounts?api-version=$StorageApiVersion"
    }
    else {
        $scopePrefix = $subscriptionPrefix
        $listUri = "$script:ManagementEndpoint/subscriptions/$SubscriptionId/providers/Microsoft.Storage/storageAccounts?api-version=$StorageApiVersion"
    }

    $listed = @(Get-ArmCollection -Uri $listUri)
    $accounts = [System.Collections.Generic.List[object]]::new()
    foreach ($entry in $listed) {
        $entryId = Get-JsonString -Node (Get-JsonMember -Node $entry -Name 'id')
        if ([string]::IsNullOrWhiteSpace($entryId) -or -not $entryId.StartsWith($scopePrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "ARM returned an out-of-scope resource: $entryId"
        }
        $entryName = Get-JsonString -Node (Get-JsonMember -Node $entry -Name 'name')
        if ($AccountName.Length -gt 0 -and $entryName -ne $AccountName) {
            continue
        }
        $accounts.Add($entry)
    }
    $counters.discovered = $accounts.Count

    foreach ($listedAccount in $accounts) {
        if ((Get-RemainingJobBudget) -le 0) {
            $abortReason = 'JobBudgetExhausted'; $abortMessage = "JobTimeBudgetSeconds ($script:JobBudget) elapsed during discovery after $($counters.discovered) listed account(s); classification is incomplete and nothing was written."
            break
        }
        try {
            # Fresh point read: the listing can be stale.
            $accountId = Get-JsonString -Node (Get-JsonMember -Node $listedAccount -Name 'id')
            $accountUri = "$script:ManagementEndpoint$accountId`?api-version=$StorageApiVersion"
            $account = (Invoke-ArmCall -Method GET -Uri $accountUri -Payload $null).Body
            if ($null -eq $account -or $account -isnot [System.Text.Json.Nodes.JsonObject]) {
                throw 'The account GET returned no JSON object.'
            }
            $bodyId = Get-JsonString -Node (Get-JsonMember -Node $account -Name 'id')
            $bodyName = Get-JsonString -Node (Get-JsonMember -Node $account -Name 'name')
            $listedName = Get-JsonString -Node (Get-JsonMember -Node $listedAccount -Name 'name')
            if ($null -eq $bodyId -or $bodyId -ine $accountId -or $null -eq $bodyName -or $bodyName -cne $listedName -or
                -not $accountId.EndsWith("/storageAccounts/$bodyName", [System.StringComparison]::OrdinalIgnoreCase)) {
                throw "The listing (id '$accountId', name '$listedName') and the point read (id '$bodyId', name '$bodyName') disagree; refusing to classify."
            }
            $classification = Get-Classification -Account $account
            if ($AccountName.Length -gt 0 -and $bodyName -ceq $AccountName) {
                $targetStatus = $classification.Status
                $targetReasons = @($classification.Reasons)
            }
            switch ($classification.Status) {
                'Skipped' { $counters.skipped++ }
                'SkippedExcluded' { $counters.excluded++ }
                'SkippedNotOptedIn' { $counters.notOptedIn++ }
                'AlreadySmart' { $counters.alreadySmart++ }
                'WouldRemediate' {
                    $counters.candidates++
                    $candidateList.Add([pscustomobject]@{ Account = $account; Uri = $accountUri; Id = $accountId })
                }
            }
            $tierBefore = $classification.Tier
            $tierAfter = $classification.Tier
            Write-ResultRow -Row (Format-ResultRow -Account $account -Status $classification.Status -Stage 'Evaluate' -Reasons $classification.Reasons -BeforeTier $tierBefore -AfterTier $tierAfter -HttpStatus $null -ArmCode $null -RequestId $null -Message $null)
        }
        catch {
            $counters.errors++
            Write-ResultRow -Row (Format-ResultRow -Account $listedAccount -Status 'Error' -Stage 'Evaluate' -Reasons @() -BeforeTier $null -AfterTier $null -HttpStatus (Get-ExceptionDiagnostic -ErrorRecord $_ -Key 'HttpStatus') -ArmCode (Get-ExceptionDiagnostic -ErrorRecord $_ -Key 'ArmCode') -RequestId (Get-ExceptionDiagnostic -ErrorRecord $_ -Key 'RequestId') -Message $_.Exception.Message)
        }
    }

    # --- preflight ----------------------------------------------------------------------------
    if ($Mode -eq 'Remediate') {
        if ($counters.errors -gt 0) {
            $abortReason = 'DiscoveryErrors'; $abortMessage = "$($counters.errors) account(s) could not be classified; the change set cannot be trusted."
        }
        elseif ($environmentName -ne 'AzureCloud' -and -not ($AllowNonPublicCloud -and $environmentName -in $script:PreviewClouds)) {
            $abortReason = 'UnsupportedCloud'; $abortMessage = "Smart tier is generally available in public Azure only; environment '$environmentName' is refused for writes (AllowNonPublicCloud=true is honoured only for the documented previews: $($script:PreviewClouds -join ', '), after feature registration)."
        }
        elseif ($AccountName.Length -gt 0 -and $counters.discovered -eq 0) {
            $abortReason = 'NoAccountMatched'; $abortMessage = "No storage account named '$AccountName' exists in the scope."
        }
        elseif ($null -ne $targetStatus -and $targetStatus -notin @('WouldRemediate', 'AlreadySmart')) {
            $abortReason = 'TargetNotEligible'; $abortMessage = "'$AccountName' is $targetStatus ($($targetReasons -join ', ')); nothing was written."
        }
        elseif ($ExpectedChanges -gt 0 -and $counters.candidates -gt 0 -and $counters.candidates -ne $ExpectedChanges) {
            $abortReason = 'ExpectedChangesMismatch'; $abortMessage = "$($counters.candidates) account(s) would change but ExpectedChanges is $ExpectedChanges."
        }
        elseif ($counters.candidates -gt $MaxChanges) {
            $abortReason = 'MaxChangesExceeded'; $abortMessage = "$($counters.candidates) account(s) would change but MaxChanges is $MaxChanges."
        }
    }

    # --- remediation --------------------------------------------------------------------------
    if ($Mode -eq 'Remediate' -and $null -eq $abortReason) {
        $runAborted = $false
        foreach ($candidate in ($candidateList | Sort-Object { $_.Id })) {
            if ($runAborted) {
                $counters.runAborted++
                Write-ResultRow -Row (Format-ResultRow -Account $candidate.Account -Status 'SkippedRunAborted' -Stage 'Write' -Reasons @("AbortReason:$abortReason") -BeforeTier $null -AfterTier $null -HttpStatus $null -ArmCode $null -RequestId $null -Message 'Not attempted because an earlier write was forbidden.')
                continue
            }
            if ((Get-RemainingJobBudget) -le 0) {
                $counters.budgetSkipped++
                Write-ResultRow -Row (Format-ResultRow -Account $candidate.Account -Status 'SkippedJobBudgetExhausted' -Stage 'Write' -Reasons @() -BeforeTier $null -AfterTier $null -HttpStatus $null -ArmCode $null -RequestId $null -Message "JobTimeBudgetSeconds ($script:JobBudget) elapsed before this account was written; rerun to continue.")
                continue
            }

            $stage = 'PreWrite'
            try {
                $fresh = (Invoke-ArmCall -Method GET -Uri $candidate.Uri -Payload $null).Body
                $freshId = Get-JsonString -Node (Get-JsonMember -Node $fresh -Name 'id')
                if ($null -eq $freshId -or $freshId -ine $candidate.Id) {
                    throw "Precondition GET returned an unexpected resource: $freshId"
                }
                $recheck = Get-Classification -Account $fresh
                $beforeTier = $recheck.Tier
                if ($recheck.Status -ne 'WouldRemediate') {
                    if ($recheck.Status -eq 'AlreadySmart') {
                        $counters.alreadySmart++
                        Write-ResultRow -Row (Format-ResultRow -Account $fresh -Status 'AlreadySmart' -Stage 'PreWrite' -Reasons @() -BeforeTier $beforeTier -AfterTier $beforeTier -HttpStatus $null -ArmCode $null -RequestId $null -Message 'Already Smart at the pre-write read.')
                    }
                    else {
                        $counters.preconditionChanged++
                        Write-ResultRow -Row (Format-ResultRow -Account $fresh -Status 'SkippedPreconditionChanged' -Stage 'PreWrite' -Reasons (@('PreconditionChanged') + @($recheck.Reasons)) -BeforeTier $beforeTier -AfterTier $beforeTier -HttpStatus $null -ArmCode $null -RequestId $null -Message "The account no longer qualifies ($($recheck.Status)) at the pre-write read.")
                    }
                    continue
                }

                $stage = 'Write'
                if ((Get-RemainingJobBudget) -le 0) {
                    $counters.budgetSkipped++
                    Write-ResultRow -Row (Format-ResultRow -Account $fresh -Status 'SkippedJobBudgetExhausted' -Stage 'Write' -Reasons @() -BeforeTier $beforeTier -AfterTier $beforeTier -HttpStatus $null -ArmCode $null -RequestId $null -Message "JobTimeBudgetSeconds ($script:JobBudget) elapsed during the pre-write read; no PATCH was sent.")
                    continue
                }
                $intent = [ordered]@{
                    timestamp  = [DateTime]::UtcNow.ToString('o')
                    id         = $candidate.Id
                    name       = Get-JsonString -Node (Get-JsonMember -Node $fresh -Name 'name')
                    beforeTier = $beforeTier
                    payload    = $script:PatchPayload
                }
                Write-Output ('INTENT ' + ($intent | ConvertTo-Json -Compress -Depth 3))
                $counters.patchesSubmitted++
                $put = Invoke-ArmCall -Method PATCH -Uri $candidate.Uri -Payload $script:PatchPayload
                $operationMessage = $null
                $reconciled = $false

                if (-not $put.Transport -and $put.StatusCode -eq 200) {
                    $operationMessage = "HTTP $($put.StatusCode)"
                }
                elseif (-not $put.Transport -and $put.StatusCode -eq 403) {
                    $counters.failed++
                    $abortReason = 'Forbidden'; $abortMessage = "The identity may not update '$($candidate.Id)'; the remaining candidates were not attempted."
                    $runAborted = $true
                    Write-ResultRow -Row (Format-ResultRow -Account $fresh -Status 'Failed' -Stage 'Write' -Reasons @('Forbidden') -BeforeTier $beforeTier -AfterTier $beforeTier -HttpStatus $put.StatusCode -ArmCode $put.ArmCode -RequestId $put.RequestId -Message $put.Error)
                    continue
                }
                elseif (-not $put.Transport -and $put.ArmCode -ieq 'ScopeLocked') {
                    $counters.locked++
                    Write-ResultRow -Row (Format-ResultRow -Account $fresh -Status 'BlockedScopeLock' -Stage 'Write' -Reasons @('ReadOnlyLock', 'ScopeLocked') -BeforeTier $beforeTier -AfterTier $beforeTier -HttpStatus $put.StatusCode -ArmCode $put.ArmCode -RequestId $put.RequestId -Message "$($put.Error) A ReadOnly lock applies: remove it deliberately and rerun; the account was not changed and this is not retried.")
                    continue
                }
                elseif (-not $put.Transport -and ($put.StatusCode -eq 429 -or ($put.StatusCode -eq 409 -and $put.ArmCode -in $script:TransientConflictCodes))) {
                    $counters.deferred++
                    Write-ResultRow -Row (Format-ResultRow -Account $fresh -Status 'Deferred' -Stage 'Write' -Reasons @("TransientConflict:$($put.ArmCode)") -BeforeTier $beforeTier -AfterTier $beforeTier -HttpStatus $put.StatusCode -ArmCode $put.ArmCode -RequestId $put.RequestId -Message $put.Error)
                    continue
                }
                elseif (-not $put.Transport -and $put.StatusCode -ge 400 -and $put.StatusCode -lt 500) {
                    $counters.failed++
                    Write-ResultRow -Row (Format-ResultRow -Account $fresh -Status 'Failed' -Stage 'Write' -Reasons @("Rejected:$($put.ArmCode)") -BeforeTier $beforeTier -AfterTier $beforeTier -HttpStatus $put.StatusCode -ArmCode $put.ArmCode -RequestId $put.RequestId -Message $put.Error)
                    continue
                }
                else {
                    # 5xx, an undocumented 2xx (the Update API documents only 200) or a transport failure
                    # after the PATCH may have been sent: ambiguous. Re-read for a bounded period; never
                    # resubmit.
                    $reconcileError = $null
                    for ($reconcileAttempt = 1; $reconcileAttempt -le 6; $reconcileAttempt++) {
                        try {
                            $reRead = (Invoke-ArmCall -Method GET -Uri $candidate.Uri -Payload $null).Body
                            $reReadId = Get-JsonString -Node (Get-JsonMember -Node $reRead -Name 'id')
                            $reReadTier = Get-JsonString -Node (Get-JsonMember -Node (Get-JsonMember -Node $reRead -Name 'properties') -Name 'accessTier')
                            if ($null -ne $reReadId -and $reReadId -ieq $candidate.Id -and $reReadTier -ieq 'Smart') {
                                $reconciled = $true
                                break
                            }
                        }
                        catch {
                            $reconcileError = $_.Exception.Message
                        }
                        if ($reconcileAttempt -lt 6) {
                            Start-Sleep -Seconds 5
                        }
                    }
                    if (-not $reconciled) {
                        $counters.unknown++
                        $unknownMessage = "PATCH outcome unknown: $($put.Error)"
                        if ($null -ne $reconcileError) {
                            $unknownMessage += " Reconciliation read also failed: $reconcileError"
                        }
                        Write-ResultRow -Row (Format-ResultRow -Account $fresh -Status 'WriteOutcomeUnknown' -Stage 'Write' -Reasons @('AmbiguousWrite') -BeforeTier $beforeTier -AfterTier $null -HttpStatus $put.StatusCode -ArmCode $put.ArmCode -RequestId $put.RequestId -Message $unknownMessage)
                        continue
                    }
                    $operationMessage = "PATCH response was lost ($($put.Error)) but the account reads Smart on re-read."
                }

                # --- verify --------------------------------------------------------------------
                $stage = 'Verify'
                $verifiedTier = $null
                if ($reconciled) {
                    # The ambiguous write was already proved by a same-id re-read; do not let a later
                    # read failure downgrade a proven change.
                    $verifiedTier = 'Smart'
                }
                else {
                    try {
                        for ($verifyAttempt = 1; $verifyAttempt -le 12; $verifyAttempt++) {
                            $verified = (Invoke-ArmCall -Method GET -Uri $candidate.Uri -Payload $null).Body
                            $verifiedId = Get-JsonString -Node (Get-JsonMember -Node $verified -Name 'id')
                            $verifiedTier = Get-JsonString -Node (Get-JsonMember -Node (Get-JsonMember -Node $verified -Name 'properties') -Name 'accessTier')
                            if ($null -eq $verifiedId -or $verifiedId -ine $candidate.Id) {
                                $verifiedTier = $null
                            }
                            if ($verifiedTier -ieq 'Smart' -or $verifyAttempt -eq 12) {
                                break
                            }
                            Start-Sleep -Seconds 5
                        }
                    }
                    catch {
                        $counters.unknown++
                        Write-ResultRow -Row (Format-ResultRow -Account $fresh -Status 'WriteOutcomeUnknown' -Stage 'Verify' -Reasons @('VerificationReadFailed') -BeforeTier $beforeTier -AfterTier $null -HttpStatus $put.StatusCode -ArmCode $null -RequestId $put.RequestId -Message "The PATCH was accepted (HTTP $($put.StatusCode)) but the verification read failed: $($_.Exception.Message)")
                        continue
                    }
                }
                if ($verifiedTier -ine 'Smart') {
                    $counters.unknown++
                    Write-ResultRow -Row (Format-ResultRow -Account $fresh -Status 'WriteOutcomeUnknown' -Stage 'Verify' -Reasons @('VerificationTimeout') -BeforeTier $beforeTier -AfterTier $verifiedTier -HttpStatus $put.StatusCode -ArmCode $null -RequestId $put.RequestId -Message "The PATCH was accepted but the account still reports '$verifiedTier' after 12 reads.")
                    continue
                }
                $counters.remediated++
                Write-ResultRow -Row (Format-ResultRow -Account $fresh -Status 'Remediated' -Stage 'Verify' -Reasons @() -BeforeTier $beforeTier -AfterTier 'Smart' -HttpStatus $put.StatusCode -ArmCode $null -RequestId $put.RequestId -Message $operationMessage)
            }
            catch {
                $counters.errors++
                Write-ResultRow -Row (Format-ResultRow -Account $candidate.Account -Status 'Error' -Stage $stage -Reasons @() -BeforeTier $null -AfterTier $null -HttpStatus (Get-ExceptionDiagnostic -ErrorRecord $_ -Key 'HttpStatus') -ArmCode (Get-ExceptionDiagnostic -ErrorRecord $_ -Key 'ArmCode') -RequestId (Get-ExceptionDiagnostic -ErrorRecord $_ -Key 'RequestId') -Message $_.Exception.Message)
            }
        }
    }
}
catch {
    $fatal = $_
    if ($null -eq $abortReason) {
        $abortReason = 'UnexpectedError'
        $abortMessage = $_.Exception.Message
    }
}

# --- summary (always) ----------------------------------------------------------------------------
$summary = [ordered]@{
    schemaVersion            = '1.1'
    runbookVersion           = $script:RunbookVersion
    timestampUtc             = [DateTime]::UtcNow.ToString('o')
    jobStartedUtc            = $script:JobStarted.ToString('o')
    identity                 = 'system-assigned'
    environment              = $environmentName
    mode                     = $Mode
    scopeType                = $ScopeType
    subscriptionId           = $SubscriptionId
    resourceGroupName        = if ($ScopeType -eq 'ResourceGroup') { $ResourceGroupName } else { $null }
    accountName              = if ($AccountName.Length -gt 0) { $AccountName } else { $null }
    optInTagRequired         = $RequireOptInTag
    requiredTag              = if ($RequireOptInTag) { "$RequiredTagName=$($script:RequiredTagValue)" } else { $null }
    exclusionTag             = $ExclusionTagName
    allowUntaggedRemediation = $AllowUntaggedRemediation
    maxChanges               = $MaxChanges
    expectedChanges          = $ExpectedChanges
    jobTimeBudgetSeconds     = $JobTimeBudgetSeconds
    counts                   = $counters
    abortReason              = $abortReason
    abortMessage             = $abortMessage
    explicitTierNote         = 'Blobs with an explicitly set tier are not enrolled by the account-level Smart default and cannot be returned to Smart.'
    exitCostNote             = 'Smart tier bills a monitoring fee per 10,000 objects larger than 128 KiB; leaving smart tier later costs one cool-write operation per object. Blobs given an explicit tier never move and cannot return to Smart.'
}
Write-Output ('SUMMARY ' + ($summary | ConvertTo-Json -Compress -Depth 6))

if ($null -ne $fatal) {
    throw $fatal
}
if ($null -ne $abortReason) {
    throw "Run aborted ($abortReason): $abortMessage"
}
# Audit is informational: only classification errors fail it. Remediate fails closed whenever a
# requested change did not verifiably happen (failed, unknown, deferred, lock-blocked, budget-skipped).
if ($Mode -eq 'Audit') {
    if ($counters.errors -gt 0) {
        throw "Audit completed with $($counters.errors) account(s) that could not be classified. Review the JSON rows."
    }
}
else {
    $notGreen = $counters.failed + $counters.unknown + $counters.deferred + $counters.locked + $counters.budgetSkipped + $counters.errors
    if ($notGreen -gt 0) {
        throw "Remediate completed with $($counters.failed) failed, $($counters.unknown) unknown, $($counters.deferred) deferred, $($counters.locked) locked, $($counters.budgetSkipped) budget-skipped and $($counters.errors) error(s). Review the JSON rows."
    }
}

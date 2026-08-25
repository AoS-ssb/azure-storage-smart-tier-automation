# Behavioural harness for Enable-AzStorageSmartTier 1.1.
# Executes the REAL runbook with the Az cmdlets mocked as global functions (no Az modules, no network),
# 50 scenario executions covering every documented branch of the contract (docs/design-and-limitations.md).
# Run non-interactively — one scenario omits the mandatory SubscriptionId on purpose and an interactive host
# would prompt:   pwsh -NonInteractive -NoProfile -File ./tests/BehaviorHarness.ps1
# Exit code 0 = every scenario passed; the Markdown results land in the temp directory unless -ResultsPath is set.
# Dependency-free behavioural harness for Enable-AzStorageSmartTier 1.1.
# The real runbook executes in-process; only its Az surface and Start-Sleep are mocked.
[CmdletBinding()]
param(
    [string] $RunbookPath = (Join-Path $PSScriptRoot '../src/Enable-AzStorageSmartTier.ps1'),
    [string] $FixturePath = (Join-Path $PSScriptRoot 'fixtures.json'),
    [string] $ResultsPath = (Join-Path ([System.IO.Path]::GetTempPath()) 'Enable-AzStorageSmartTier-harness-results.md')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$fx = Get-Content -LiteralPath $FixturePath -Raw | ConvertFrom-Json -Depth 100
$sub = [string]$fx.subscriptionId
$rg = [string]$fx.resourceGroupName
$publicArm = ([string]$fx.managementEndpoint).TrimEnd('/')
$govArm = ([string]$fx.governmentEndpoint).TrimEnd('/')
$germanArm = 'https://management.microsoftazure.de'
$storageApi = '2025-08-01'
$lockApi = '2020-05-01'
$scriptParams = (Get-Command -Name $RunbookPath).Parameters
$runbookSource = @(Get-Content -LiteralPath $RunbookPath)

function Find-RunbookLines([string[]]$Patterns) {
    $found = foreach($pattern in $Patterns){$runbookSource|Select-String -Pattern $pattern|ForEach-Object LineNumber}
    return (@($found|Sort-Object -Unique)-join',')
}

function Copy-X([AllowNull()][object]$Value) {
    if ($null -eq $Value) { return $null }
    return ($Value | ConvertTo-Json -Compress -Depth 100 | ConvertFrom-Json -Depth 100)
}
function V([AllowNull()][object]$Object,[string]$Name,[AllowNull()][object]$Default=$null) {
    if ($null -eq $Object) { return $Default }
    if ($Object -is [Collections.IDictionary]) {
        foreach ($key in $Object.Keys) { if ([string]$key -ieq $Name) { return $Object[$key] } }
        return $Default
    }
    $p = $Object.PSObject.Properties[$Name]
    if ($null -eq $p) { return $Default }
    return $p.Value
}
function Has([AllowNull()][object]$Object,[string]$Name) {
    if ($Object -is [Collections.IDictionary]) {
        foreach ($key in $Object.Keys) { if ([string]$key -ieq $Name) { return $true } }
    } elseif ($null -ne $Object -and $null -ne $Object.PSObject.Properties[$Name]) { return $true }
    return $false
}
function A([string[]]$Names) {
    @($Names | ForEach-Object {
        $found = @($fx.accounts | Where-Object name -ceq $_)
        if ($found.Count -ne 1) { throw "Fixture account '$_' is not unique." }
        Copy-X $found[0]
    })
}
function Lock([string]$Scope,[string]$Name,[string]$Level) {
    [pscustomobject]@{ id="$Scope/providers/Microsoft.Authorization/locks/$Name";name=$Name;properties=[pscustomobject]@{level=$Level} }
}
function O([hashtable]$RunArgs=@{}) {
    $base = [ordered]@{Mode='Audit';ScopeType='ResourceGroup';SubscriptionId=$sub;ResourceGroupName=$rg}
    foreach ($key in $RunArgs.Keys) { $base[$key] = $RunArgs[$key] }
    return $base
}
function E([object]$Statuses,[bool]$Throw=$false,[int]$Patches=0,[hashtable]$More=@{}) {
    $e = [ordered]@{Statuses=$Statuses;Throw=$Throw;Patches=$Patches;ExactStatuses=$true}
    foreach ($key in $More.Keys) { $e[$key] = $More[$key] }
    return $e
}
function Case([string]$Id,[string]$Purpose,[string[]]$Names,[hashtable]$RunArgs,[hashtable]$State,[object]$Expect,
              [string]$Variant='',[string]$Lines='') {
    if([string]::IsNullOrWhiteSpace($Lines)){
        if($Id -in @('S08','S09','S10','S11','S12','S13','S14','S15','S23','S31')){$Lines='SPEC §4 write branches'}
        elseif($Id -in @('S16','S17','S18','S19','S20','S22','S24','S27')){$Lines='SPEC §1/§4 preflight'}
        elseif($Id -in @('S25','S26','S32')){$Lines='SPEC §3 discovery'}
        elseif($Id -eq 'S21'){$Lines='SPEC §1 mandatory binding'}
        elseif($Id -eq 'S28'){$Lines='SPEC §5; runbook 523-525, 716, 894, 917, 923-926'}
        elseif($Id -eq 'S29'){$Lines='SPEC §1/§4; runbook 70-71, 299-317, 688-692'}
        elseif($Id -eq 'S30'){$Lines='SPEC §2; runbook 348-360, 584-587'}
        else{$Lines='SPEC §3 classification'}
    }
    [pscustomobject]@{Id=$Id;Variant=$Variant;Purpose=$Purpose;Names=$Names;Args=(O $RunArgs);State=$State;Expect=$Expect;Lines=$Lines;Omit=@()}
}

$accountScope = "/subscriptions/$sub/resourceGroups/$rg/providers/Microsoft.Storage/storageAccounts"
$rgScope = "/subscriptions/$sub/resourceGroups/$rg"
$cases = [Collections.Generic.List[object]]::new()
function Add([object]$c) { $cases.Add($c) }

$s01 = [ordered]@{stfixturezrs='WouldRemediate';stfixturenotag='SkippedNotOptedIn';stfixturebadtag='SkippedNotOptedIn'
    stfixturegzrs='WouldRemediate';stfixturehns='WouldRemediate';stfixturesmart='AlreadySmart';stfixturelock='WouldRemediate'
    stfixturelrs='Skipped';stfixtureblock='Skipped'}
Add (Case S01 'mixed nine-account audit' @($s01.Keys) @{} @{
    SubLocks=@(Lock "$accountScope/stfixturelock" acctLock ReadOnly)
} (E $s01 $false 0 @{Counts=@{discovered=9;candidates=4;remediated=0;alreadySmart=1;skipped=2;excluded=0;notOptedIn=2;locked=0;preconditionChanged=0;deferred=0;failed=0;unknown=0;budgetSkipped=0;runAborted=0;errors=0;patchesSubmitted=0}}) '' 'SPEC §3; runbook 610-660')
Add (Case S02 'RG ReadOnly lock is not enumerated during Audit' @('stfixturezrs') @{} @{
    SubLocks=@(Lock $rgScope rgLock ReadOnly)
} (E ([ordered]@{stfixturezrs='WouldRemediate'})) '' 'SPEC §3 no-lock-preflight ruling')
Add (Case S03 'CanNotDelete lock does not block PATCH eligibility' @('stfixturezrs') @{} @{
    SubLocks=@(Lock "$accountScope/stfixturezrs" deleteLock CanNotDelete)
} (E ([ordered]@{stfixturezrs='WouldRemediate'})) '' 'SPEC §3 lock semantics')
Add (Case S04 'lock-list 403 routes remain unused by the judged runbook' @('stfixturezrs') @{} @{
    SubLockStatus=403;RgLocks=@(Lock $rgScope rgLock ReadOnly)
} (E ([ordered]@{stfixturezrs='WouldRemediate'})) '' 'SPEC §3 no-lock-preflight ruling')
Add (Case S05 'ScopeLocked ARM code wins at write time regardless of HTTP status' @('stfixturelock') @{
    Mode='Remediate';AccountName='stfixturelock';ExpectedChanges=1;MaxChanges=1
} @{PatchFaults=@{stfixturelock=@(@{Code=403;Arm='ScopeLocked';Request='req-scope-locked'})}} (
    E ([ordered]@{stfixturelock='BlockedScopeLock'}) $true 1 @{Abort=$null;Rows=2;Counts=@{locked=1;failed=0;patchesSubmitted=1}}
) '' 'SPEC §2/§4 ScopeLocked by ARM code; runbook 851-861')
Add (Case S06 'exclusion tag wins over opt-in' @('stfixturezrs') @{} @{Exclude='stfixturezrs'} (
    E ([ordered]@{stfixturezrs='SkippedExcluded'})
) '' 'SPEC §3 classification order')
Add (Case S07 'fixed opt-in value true is case-sensitive' @('stfixturezrs') @{} @{TagTrue='stfixturezrs'} (
    E ([ordered]@{stfixturezrs='SkippedNotOptedIn'})
) '' 'SPEC §1, §3')
Add (Case S08 'ring of one sends the exact PATCH and verifies' @('stfixturezrs') @{
    Mode='Remediate';AccountName='stfixturezrs';MaxChanges=1
} @{} (E ([ordered]@{stfixturezrs='Remediated'}) $false 1 @{Abort=$null}))
Add (Case S09 'verification lags twice, then converges' @('stfixturezrs') @{
    Mode='Remediate';AccountName='stfixturezrs';MaxChanges=1
} @{VerifyLag=2} (E ([ordered]@{stfixturezrs='Remediated'}) $false 1))
Add (Case S10 'verification never converges' @('stfixturezrs') @{
    Mode='Remediate';AccountName='stfixturezrs';MaxChanges=1
} @{VerifyNever=$true} (E ([ordered]@{stfixturezrs='WriteOutcomeUnknown'}) $true 1))
Add (Case S11 'a forbidden PATCH sets the run-level circuit breaker' @('stfixturegzrs') @{
    Mode='Remediate';AccountName='stfixturegzrs';ExpectedChanges=1;MaxChanges=1
} @{PatchFaults=@{stfixturegzrs=@(@{Code=403;Arm='AuthorizationFailed';Request='req-forbidden'})}} (
    E ([ordered]@{stfixturegzrs='Failed'}) $true 1 @{Abort='Forbidden';Rows=2;Counts=@{failed=1;runAborted=0;patchesSubmitted=1}}
) '' 'SPEC §4 403 circuit breaker; runbook 851-856')
Add (Case S12 'PATCH 429 honors Retry-After before retrying' @('stfixturezrs') @{
    Mode='Remediate';AccountName='stfixturezrs';MaxChanges=1
} @{PatchFaults=@{stfixturezrs=@(@{Code=429;Arm='TooManyRequests';RetryAfter=7})}} (
    E ([ordered]@{stfixturezrs='Remediated'}) $false 2
))
Add (Case S13 'PATCH 503 was applied; re-read reconciles response loss' @('stfixturezrs') @{
    Mode='Remediate';AccountName='stfixturezrs';MaxChanges=1
} @{Patch503Apply='stfixturezrs'} (E ([ordered]@{stfixturezrs='Remediated'}) $false 1))
Add (Case S14 'PATCH transport failure is ambiguous and never resent' @('stfixturezrs') @{
    Mode='Remediate';AccountName='stfixturezrs';MaxChanges=1
} @{PatchTransport='stfixturezrs'} (E ([ordered]@{stfixturezrs='WriteOutcomeUnknown'}) $true 1))
Add (Case S15 'the documented in-progress 409 is Deferred' @('stfixturezrs') @{
    Mode='Remediate';AccountName='stfixturezrs';MaxChanges=1
} @{PatchFaults=@{stfixturezrs=@(@{Code=409;Arm='StorageAccountOperationInProgress'})}} (
    E ([ordered]@{stfixturezrs='Deferred'}) $true 1 @{Abort=$null}
) '' 'SPEC §4 409; §5 outcome')
Add (Case S16 'Remediate requires a named account before any Az call' @('stfixturezrs') @{
    Mode='Remediate';ExpectedChanges=1;MaxChanges=1
} @{} (E @{} $true 0 @{RestCalls=0;Rows=0;Abort='InvalidParameters';SummaryPrefix=$true;ThrowLike='*requires AccountName*'}) 'missing AccountName')
Add (Case S16 'a named target outside the eligible states aborts' @('stfixturenotag') @{
    Mode='Remediate';AccountName='stfixturenotag';ExpectedChanges=1;MaxChanges=1
} @{} (E ([ordered]@{stfixturenotag='SkippedNotOptedIn'}) $true 0 @{Rows=1;Abort='TargetNotEligible';Counts=@{discovered=1;candidates=0;notOptedIn=1}}) 'TargetNotEligible')
Add (Case S17 'already-Smart named target satisfies ExpectedChanges one idempotently' @('stfixturesmart') @{
    Mode='Remediate';AccountName='stfixturesmart';ExpectedChanges=1;MaxChanges=1
} @{} (E ([ordered]@{stfixturesmart='AlreadySmart'}) $false 0 @{Rows=1;Abort=$null;Counts=@{discovered=1;candidates=0;alreadySmart=1;remediated=0;patchesSubmitted=0}}))
Add (Case S18 'untagged remediation without explicit allow is invalid before ARM' @('stfixturenotag') @{
    Mode='Remediate';AccountName='stfixturenotag';RequireOptInTag=$false;ExpectedChanges=1;MaxChanges=1
} @{} (E @{} $true 0 @{RestCalls=0;Rows=0;Abort='InvalidParameters';SummaryPrefix=$true;ThrowLike='*AllowUntaggedRemediation*'}))
Add (Case S19 'explicitly allowed untagged named target remediates' @('stfixturenotag') @{
    Mode='Remediate';AccountName='stfixturenotag';RequireOptInTag=$false;AllowUntaggedRemediation=$true;ExpectedChanges=1;MaxChanges=1
} @{} (E ([ordered]@{stfixturenotag='Remediated'}) $false 1 @{Rows=2}))
Add (Case S20 'resource group is rejected at subscription scope' @('stfixturezrs') @{
    ScopeType='Subscription';ResourceGroupName=$rg
} @{} (E @{} $true 0 @{RestCalls=0;ThrowLike='*ResourceGroupName*';Abort='InvalidParameters';SummaryPrefix=$true}))
Add (Case S20 'Remediate itself is rejected at subscription scope' @('stfixturezrs') @{
    Mode='Remediate';ScopeType='Subscription';ResourceGroupName='';AccountName='stfixturezrs'
} @{} (E @{} $true 0 @{RestCalls=0;ThrowLike='*resource-group scoped*';Abort='InvalidParameters';SummaryPrefix=$true}) 'RG-only write')
$s21 = Case S21 'SubscriptionId is mandatory' @('stfixturezrs') @{} @{} (E @{} $true 0 @{RestCalls=0;ThrowLike='*SubscriptionId*'})
$s21.Omit = @('SubscriptionId'); Add $s21
Add (Case S22 'whitespace ResourceGroupName is rejected' @('stfixturezrs') @{ResourceGroupName='   '} @{} (
    E @{} $true 0 @{RestCalls=0;Abort='InvalidParameters';SummaryPrefix=$true}
))
Add (Case S23 'fresh pre-write GET detects removed opt-in tag' @('stfixturezrs') @{
    Mode='Remediate';AccountName='stfixturezrs';MaxChanges=1
} @{ChangeTag='stfixturezrs'} (E ([ordered]@{stfixturezrs='SkippedPreconditionChanged'}) $false 0))
Add (Case S24 'sovereign cloud write fails closed by default' @('stfixturezrs') @{
    Mode='Remediate';AccountName='stfixturezrs';MaxChanges=1
} @{Environment='AzureUSGovernment';Endpoint=$govArm} (
    E @{} $true 0 @{Abort='UnsupportedCloud';Rows=2;ExactStatuses=$false}
) 'default deny' 'SPEC §1, §4')
Add (Case S24 'explicit sovereign-cloud override proceeds' @('stfixturezrs') @{
    Mode='Remediate';AccountName='stfixturezrs';MaxChanges=1;AllowNonPublicCloud=$true
} @{Environment='AzureUSGovernment';Endpoint=$govArm} (
    E ([ordered]@{stfixturezrs='Remediated'}) $false 1 @{Rows=2}
) 'allowed' 'SPEC §1, §4')
Add (Case S25 'accounts paginate while lock endpoints remain untouched' @('stfixturezrs','stfixturesmart','stfixturelock') @{} @{
    PaginateAccounts=$true;PaginateLocks=$true
    SubLocks=@(Lock $rgScope deleteLock CanNotDelete; Lock "$accountScope/stfixturelock" acctLock ReadOnly)
} (E ([ordered]@{stfixturezrs='WouldRemediate';stfixturesmart='AlreadySmart';stfixturelock='WouldRemediate'})))
Add (Case S26 'out-of-scope resource id is rejected' @('stfixturezrs') @{} @{OutOfScope=$true} (
    E @{} $true 0 @{ThrowLike='*out-of-scope*'}
))
$s27Rem = E ([ordered]@{stfixturegzrs='Error'}) $true 0 @{Abort='DiscoveryErrors';Rows=1}
Add (Case S27 'a named target discovery error aborts remediation' @('stfixturegzrs') @{
    Mode='Remediate';AccountName='stfixturegzrs';ExpectedChanges=1;MaxChanges=1
} @{GetFault='stfixturegzrs'} $s27Rem 'Remediate' 'SPEC §2/§4 discovery diagnostics')
Add (Case S27 'audit reports one error and continues with siblings' @('stfixturegzrs','stfixturezrs') @{} @{
    GetFault='stfixturegzrs'
} (E ([ordered]@{stfixturegzrs='Error';stfixturezrs='WouldRemediate'}) $true 0) 'Audit' 'SPEC §2/§3 discovery diagnostics')
Add (Case S28 'JSON Lines event schema, ordering, nulls, and count invariants' @('stfixturezrs') @{
    Mode='Remediate';AccountName='stfixturezrs';MaxChanges=1
} @{NullTier='stfixturezrs'} (E ([ordered]@{stfixturezrs='Remediated'}) $false 1 @{Rows=2;SummaryPrefix=$true}))
Add (Case S29 'JobTimeBudgetSeconds accepts the minimum budget' @('stfixturezrs') @{
    Mode='Remediate';AccountName='stfixturezrs';MaxChanges=1;JobTimeBudgetSeconds=60
} @{} (E ([ordered]@{stfixturezrs='Remediated'}) $false 1))
Add (Case S30 'all post-auth Az calls carry the selected DefaultProfile' @('stfixturesmart') @{} @{} (
    E ([ordered]@{stfixturesmart='AlreadySmart'})
))
Add (Case S31 'failed row captures x-ms-request-id' @('stfixturezrs') @{
    Mode='Remediate';AccountName='stfixturezrs';MaxChanges=1
} @{PatchFaults=@{stfixturezrs=@(@{Code=400;Arm='InvalidRequest';Request='req-case-insensitive'})}} (
    E ([ordered]@{stfixturezrs='Failed'}) $true 1
))
Add (Case S32 'HNS-enabled ZRS account remains eligible' @('stfixturehns') @{} @{} (
    E ([ordered]@{stfixturehns='WouldRemediate'})
))

Add (Case S33 'failed verification read becomes WriteOutcomeUnknown' @('stfixturezrs') @{
    Mode='Remediate';AccountName='stfixturezrs'
} @{VerifyGetFault='stfixturezrs'} (E ([ordered]@{stfixturezrs='WriteOutcomeUnknown'}) $true 1 @{Rows=2}))
Add (Case S34 'Smart proof for the wrong resource id does not verify' @('stfixturezrs') @{
    Mode='Remediate';AccountName='stfixturezrs'
} @{VerifyWrongId='stfixturezrs';WrongResourceName='stfixturewrongproof'} (E ([ordered]@{stfixturezrs='WriteOutcomeUnknown'}) $true 1 @{Rows=2}))
Add (Case S35 'PATCH 202 is reconciled by a same-id read and then final' @('stfixturezrs') @{
    Mode='Remediate';AccountName='stfixturezrs'
} @{Patch202Apply='stfixturezrs'} (E ([ordered]@{stfixturezrs='Remediated'}) $false 1 @{Rows=2}))
Add (Case S36 'a non-transient 409 is a definitive failure' @('stfixturezrs') @{
    Mode='Remediate';AccountName='stfixturezrs'
} @{PatchFaults=@{stfixturezrs=@(@{Code=409;Arm='FeatureNotSupportForAccount';Request='req-409-definitive'})}} (
    E ([ordered]@{stfixturezrs='Failed'}) $true 1 @{Rows=2}
))
Add (Case S37 'Retry-After 400 is not shortened or retried' @('stfixturezrs') @{
    Mode='Remediate';AccountName='stfixturezrs'
} @{PatchFaults=@{stfixturezrs=@(@{Code=429;Arm='TooManyRequests';Request='req-httpheaders-429';RetryAfter=400;UseHttpResponseHeaders=$true})}} (
    E ([ordered]@{stfixturezrs='Deferred'}) $true 1 @{Rows=2}
))
Add (Case S38 'GET 501 retries four times and preserves diagnostics' @('stfixturezrs') @{} @{
    GetFault='stfixturezrs';GetFaultCode=501;GetFaultArm='NotImplemented';GetFaultRequest='req-get-501-stfixturezrs'
} (E ([ordered]@{stfixturezrs='Error'}) $true 0 @{Rows=1}))
Add (Case S39 'a thrown Az exception carrying Response is classified as HTTP' @('stfixturezrs') @{
    Mode='Remediate';AccountName='stfixturezrs'
} @{PatchFaults=@{stfixturezrs=@(@{Code=400;Arm='InvalidRequest';Request='req-thrown-response';ThrowResponse=$true})}} (
    E ([ordered]@{stfixturezrs='Failed'}) $true 1 @{Rows=2}
))
Add (Case S40 'a non-object tags member is an Error row' @('stfixturezrs') @{} @{
    TagsNonObject='stfixturezrs'
} (E ([ordered]@{stfixturezrs='Error'}) $true 0 @{Rows=1}))
Add (Case S41 'an exclusion key with JSON null still excludes' @('stfixturezrs') @{} @{
    ExcludeNull='stfixturezrs'
} (E ([ordered]@{stfixturezrs='SkippedExcluded'}) $false 0 @{Rows=1}))
Add (Case S42 'a boolean opt-in value is not string consent' @('stfixturezrs') @{} @{
    BooleanOptIn='stfixturezrs'
} (E ([ordered]@{stfixturezrs='SkippedNotOptedIn'}) $false 0 @{Rows=1}))
Add (Case S43 'listing and point-read identity disagreement is an Error' @('stfixturezrs') @{
    Mode='Remediate';AccountName='stfixturezrs'
} @{PointMismatch='stfixturezrs';WrongResourceName='stfixturewrongproof'} (
    E ([ordered]@{stfixturezrs='Error'}) $true 0 @{Rows=1;Abort='DiscoveryErrors'}
))
Add (Case S44 'AzureUSGovernment proceeds only with the override' @('stfixturezrs') @{
    Mode='Remediate';AccountName='stfixturezrs';AllowNonPublicCloud=$true
} @{Environment='AzureUSGovernment';Endpoint=$govArm} (
    E ([ordered]@{stfixturezrs='Remediated'}) $false 1 @{Rows=2}
) 'allowed Government')
Add (Case S44 'AzureGermanCloud remains refused even with the override' @('stfixturezrs') @{
    Mode='Remediate';AccountName='stfixturezrs';AllowNonPublicCloud=$true
} @{Environment='AzureGermanCloud';Endpoint=$germanArm} (
    E @{} $true 0 @{Rows=2;ExactStatuses=$false;Abort='UnsupportedCloud'}
) 'refused German')
Add (Case S45 'ExpectedChanges two is invalid for a named target' @('stfixturezrs') @{
    Mode='Remediate';AccountName='stfixturezrs';ExpectedChanges=2;MaxChanges=2
} @{} (E @{} $true 0 @{RestCalls=0;Rows=0;Abort='InvalidParameters';SummaryPrefix=$true;ThrowLike='*ExpectedChanges cannot exceed 1*'}))

$lineById=@{
    S05='SPEC §2/§4; runbook 851-861'
    S11='SPEC §4; runbook 851-856'
    S12='SPEC §2/§5; runbook 386-470, 835-844'
    S16='SPEC §1/§4; runbook 118-151, 779-784'
    S17='SPEC §1/§4; runbook 747-750, 782-790'
    S18='SPEC §1/§4; runbook 138-151, 669-677'
    S19='SPEC §1/§4; runbook 138-151, 641-652, 793-943'
    S24='SPEC §1/§5; runbook 92-93, 776-794'
    S27='SPEC §2/§3/§4; runbook 457-480, 731-774'
    S28='SPEC §5; runbook 533-600, 763, 835-844, 942, 959-985'
    S33='SPEC §4; runbook 907-939'
    S34='SPEC §4; runbook 917-939'
    S35='SPEC §4; runbook 848-850, 873-914'
    S36='SPEC §4; runbook 863-870'
    S37='SPEC §2/§4; runbook 227-250, 253-301, 452-470, 863-866'
    S38='SPEC §2/§3; runbook 457-480, 731-767'
    S39='SPEC §2/§4; runbook 406-449, 868-870'
    S40='SPEC §3; runbook 613-647, 765-767'
    S41='SPEC §3; runbook 304-334, 634-640'
    S42='SPEC §3; runbook 304-334, 641-647'
    S43='SPEC §3/§4; runbook 731-767, 773-774'
    S44='SPEC §1/§5; runbook 92-93, 776-794'
    S45='SPEC §1/§5; runbook 138-147, 669-677, 959-985'
}
foreach($c in $cases){if($lineById.ContainsKey($c.Id)){$c.Lines=$lineById[$c.Id]}}

function global:Copy-Harness([AllowNull()][object]$Value) {
    if ($null -eq $Value) { return $null }
    return ($Value | ConvertTo-Json -Compress -Depth 100 | ConvertFrom-Json -Depth 100)
}
function global:New-HarnessHeaders([hashtable]$Values=@{}) {
    $d = [Collections.Generic.Dictionary[string,string[]]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($key in $Values.Keys) { $d[[string]$key] = [string[]]@($Values[$key]) }
    return $d
}
function global:New-HarnessResponse([int]$StatusCode,[AllowNull()][object]$Body,[AllowNull()][object]$Headers=$null) {
    $content = if ($null -eq $Body) { '' } elseif ($Body -is [string]) { $Body } else {
        $Body | ConvertTo-Json -Compress -Depth 100
    }
    $responseHeaders = if ($null -eq $Headers) {
        New-HarnessHeaders
    } elseif ($Headers -is [hashtable]) {
        New-HarnessHeaders $Headers
    } else {
        , $Headers
    }
    [pscustomobject]@{StatusCode=$StatusCode;Content=$content;Headers=$responseHeaders}
}
function global:Add-AzSeen([string]$Name,[bool]$Bound,[AllowNull()][object]$Profile) {
    $global:MockState.AzCalls.Add([pscustomobject]@{Name=$Name;DefaultProfileBound=$Bound;Profile=$Profile})
}
function global:Disable-AzContextAutosave {
    [CmdletBinding()]param([string]$Scope,[AllowNull()][object]$DefaultProfile)
    Add-AzSeen 'Disable-AzContextAutosave' $PSBoundParameters.ContainsKey('DefaultProfile') $DefaultProfile
    [pscustomobject]@{Scope=$Scope}
}
function global:Connect-AzAccount {
    [CmdletBinding()]param([switch]$Identity,[string]$AccountId,[AllowNull()][object]$DefaultProfile)
    Add-AzSeen 'Connect-AzAccount' $PSBoundParameters.ContainsKey('DefaultProfile') $DefaultProfile
    $s=$global:MockState
    $ctx=[pscustomobject]@{Subscription=[pscustomobject]@{Id=$sub};Environment=[pscustomobject]@{
        Name=$s.Environment;ResourceManagerUrl="$($s.Endpoint)/"
    }}
    $s.InitialContext=$ctx
    [pscustomobject]@{Context=$ctx}
}
function global:Set-AzContext {
    [CmdletBinding()]param([string]$SubscriptionId,[AllowNull()][object]$DefaultProfile)
    Add-AzSeen 'Set-AzContext' $PSBoundParameters.ContainsKey('DefaultProfile') $DefaultProfile
    $s=$global:MockState
    $ctx=[pscustomobject]@{Subscription=[pscustomobject]@{Id=$SubscriptionId};Environment=[pscustomobject]@{
        Name=$s.Environment;ResourceManagerUrl="$($s.Endpoint)/"
    }}
    $s.SelectedContext=$ctx
    return $ctx
}
function global:Get-AzEnvironment {
    [CmdletBinding()]param([string]$Name,[AllowNull()][object]$DefaultProfile)
    Add-AzSeen 'Get-AzEnvironment' $PSBoundParameters.ContainsKey('DefaultProfile') $DefaultProfile
    [pscustomobject]@{Name=$global:MockState.Environment;ResourceManagerUrl="$($global:MockState.Endpoint)/"}
}
function global:Start-Sleep {
    [CmdletBinding()]param([double]$Seconds=0,[int]$Milliseconds=0)
    $n=if($PSBoundParameters.ContainsKey('Milliseconds')){$Milliseconds/1000.0}else{$Seconds}
    $global:MockState.Sleeps.Add([double]$n)
}
function global:Invoke-AzRestMethod {
    [CmdletBinding()]param(
        [Parameter(Mandatory)][string]$Method,[Parameter(Mandatory)][string]$Uri,
        [AllowNull()][string]$Payload,[AllowNull()][object]$DefaultProfile
    )
    $s=$global:MockState;$verb=$Method.ToUpperInvariant()
    Add-AzSeen 'Invoke-AzRestMethod' $PSBoundParameters.ContainsKey('DefaultProfile') $DefaultProfile
    $s.Calls.Add([pscustomobject]@{Method=$verb;Uri=$Uri;Payload=$Payload;PayloadBound=$PSBoundParameters.ContainsKey('Payload')})
    $s.Events.Add("REST:$($verb):$Uri")
    if($verb -eq 'GET' -and ($Uri -ceq $s.ListUri -or $Uri -ceq $s.AccountNext)){
        if($Uri -ceq $s.AccountNext){$values=@($s.Listing[1..($s.Listing.Count-1)]);$next=$null}
        elseif($s.PaginateAccounts -and $s.Listing.Count -gt 1){$values=@($s.Listing[0]);$next=$s.AccountNext}
        else{$values=@($s.Listing);$next=$null}
        $body=[ordered]@{value=$values};if($next){$body.nextLink=$next}
        return New-HarnessResponse 200 $body @{'x-ms-request-id'=@('req-account-list')}
    }
    $lockKind=$null
    if($Uri -ceq $s.SubLockUri -or $Uri -ceq $s.SubLockNext){$lockKind='Sub'}
    elseif($Uri -ceq $s.RgLockUri -or $Uri -ceq $s.RgLockNext){$lockKind='Rg'}
    if($verb -eq 'GET' -and $lockKind){
        $status=[int](V $s "$($lockKind)LockStatus" 200)
        if($status -ne 200){
            return New-HarnessResponse $status @{error=@{code='AuthorizationFailed';message='locks/read denied'}} @{'x-ms-request-id'=@("req-$lockKind-locks-403")}
        }
        $locks=@(V $s "$($lockKind)Locks" @());$nextUri=V $s "$($lockKind)LockNext"
        if($Uri -ceq $nextUri){$values=@($locks[1..($locks.Count-1)]);$next=$null}
        elseif($s.PaginateLocks -and $locks.Count -gt 1){$values=@($locks[0]);$next=$nextUri}
        else{$values=$locks;$next=$null}
        $body=[ordered]@{value=$values};if($next){$body.nextLink=$next}
        return New-HarnessResponse 200 $body @{'x-ms-request-id'=@("req-$lockKind-locks")}
    }
    if($Uri -notmatch '/providers/Microsoft\.Storage/storageAccounts/([^/?]+)\?api-version='){
        throw "Mock has no route for $verb $Uri"
    }
    $name=[uri]::UnescapeDataString($Matches[1])
    if(-not $s.Point.ContainsKey($name)){throw "Mock has no account '$name' for $verb $Uri"}
    if($verb -eq 'GET'){
        if(-not $s.GetCounts.ContainsKey($name)){$s.GetCounts[$name]=0};$s.GetCounts[$name]++
        if($s.GetFault -ceq $name -or ($s.VerifyGetFault -ceq $name -and [bool]$s.Patched[$name])){
            $faultCode=[int]$s.GetFaultCode;$faultArm=[string]$s.GetFaultArm;$faultRequest=[string]$s.GetFaultRequest
            return New-HarnessResponse $faultCode @{error=@{code=$faultArm;message='mock GET failure'}} @{'x-ms-request-id'=@($faultRequest)}
        }
        $changeAt=if($s.IsV11){2}else{1}
        if($s.ChangeTag -ceq $name -and $s.GetCounts[$name] -eq $changeAt){
            $p=$s.Point[$name].tags.PSObject.Properties|Where-Object Name -ieq 'SmartTierManaged'|Select-Object -First 1
            if($null-ne $p){$s.Point[$name].tags.PSObject.Properties.Remove($p.Name)}
        }
        if($s.Patched[$name] -and ($s.VerifyNever -or $s.VerifyLeft[$name] -gt 0)){
            if(-not $s.VerifyNever){$s.VerifyLeft[$name]--};$body=Copy-Harness $s.BeforePatch[$name]
        }else{$body=Copy-Harness $s.Point[$name]}
        if($s.VerifyWrongId -ceq $name -and [bool]$s.Patched[$name]){
            $wrong=[string]$s.WrongResourceName
            $body.id=$body.id -replace '/storageAccounts/[^/]+$', "/storageAccounts/$wrong"
            $body.name=$wrong
        }
        return New-HarnessResponse 200 $body @{'ETag'=@('"mock-etag"');'x-ms-request-id'=@("req-get-$name")}
    }
    if($verb -ne 'PATCH'){throw "Mock accepts only GET/PATCH: $verb $Uri"}
    $s.Patches.Add([pscustomobject]@{Account=$name;Uri=$Uri;Raw=$Payload})
    if($s.PatchTransport -ceq $name){
        throw [Net.Http.HttpRequestException]::new("mock transport loss after PATCH send for $name")
    }
    if($s.Patch503Apply -ceq $name -and @($s.Patches|Where-Object Account -ceq $name).Count -eq 1){
        $s.BeforePatch[$name]=Copy-Harness $s.Point[$name];$s.Point[$name].properties.accessTier='Smart';$s.Patched[$name]=$true
        return New-HarnessResponse 503 @{error=@{code='ServiceUnavailable';message='response lost'}} @{'x-ms-request-id'=@("req-503-$name")}
    }
    if($s.Patch202Apply -ceq $name -and @($s.Patches|Where-Object Account -ceq $name).Count -eq 1){
        $s.BeforePatch[$name]=Copy-Harness $s.Point[$name];$s.Point[$name].properties.accessTier='Smart';$s.Patched[$name]=$true
        return New-HarnessResponse 202 $s.Point[$name] @{'x-ms-request-id'=@("req-202-$name")}
    }
    $fault=$null
    if($s.PatchFaults.ContainsKey($name)){
        if(-not $s.PatchIndexes.ContainsKey($name)){$s.PatchIndexes[$name]=0}
        $queue=@($s.PatchFaults[$name]);$i=[int]$s.PatchIndexes[$name]
        if($i-lt $queue.Count){$fault=$queue[$i];$s.PatchIndexes[$name]=$i+1}
    }
    if($null-ne $fault){
        $code=[int](V $fault Code);$arm=[string](V $fault Arm 'RequestFailed');$req=[string](V $fault Request "req-$code-$name")
        $headers=@{'X-Ms-ReQuEsT-Id'=@($req)}
        if(Has $fault RetryAfter){$headers['rEtRy-AfTeR']=@([string](V $fault RetryAfter))}
        if([bool](V $fault UseHttpResponseHeaders $false)){
            if($code-ne429){throw 'UseHttpResponseHeaders is reserved for the 429 fixture.'}
            $message=[System.Net.Http.HttpResponseMessage]::new(429)
            foreach($key in $headers.Keys){foreach($value in @($headers[$key])){$null=$message.Headers.TryAddWithoutValidation([string]$key,[string]$value)}}
            $s.HttpResponses.Add($message)
            $response=New-HarnessResponse $code @{error=@{code=$arm;message="mock HTTP $code"}} $message.Headers
            $s.FaultResponses.Add($response)
        }else{
            $response=New-HarnessResponse $code @{error=@{code=$arm;message="mock HTTP $code"}} $headers
        }
        if([bool](V $fault ThrowResponse $false)){
            $s.ThrownResponseCount++
            $exception=[System.Exception]::new("mock Az exception with HTTP response $code")
            $exception|Add-Member -MemberType NoteProperty -Name Response -Value $response -Force
            throw $exception
        }
        return $response
    }
    $null=$Payload|ConvertFrom-Json -Depth 20
    $s.BeforePatch[$name]=Copy-Harness $s.Point[$name];$s.Point[$name].properties.accessTier='Smart';$s.Patched[$name]=$true
    return New-HarnessResponse 200 $s.Point[$name] @{'x-ms-request-id'=@("req-patch-$name")}
}

function New-State([object]$c) {
    $st=$c.State;$endpoint=[string](V $st Endpoint $publicArm);$env=[string](V $st Environment 'AzureCloud')
    $listing=A $c.Names
    if([bool](V $st OutOfScope $false)){$listing[0].id=$listing[0].id-replace "/resourceGroups/$rg/","/resourceGroups/rg-foreign/"}
    $point=@{};foreach($acct in $listing){$point[[string]$acct.name]=Copy-X $acct}
    $exclude=[string](V $st Exclude '')
    if($exclude){
        $point[$exclude].tags|Add-Member NoteProperty SmartTierExclude 'yes' -Force
        $listing|Where-Object name -ceq $exclude|ForEach-Object{$_.tags|Add-Member NoteProperty SmartTierExclude 'yes' -Force}
    }
    $tagTrue=[string](V $st TagTrue '')
    if($tagTrue){$point[$tagTrue].tags.SmartTierManaged='True';($listing|Where-Object name -ceq $tagTrue).tags.SmartTierManaged='True'}
    $tagsNonObject=[string](V $st TagsNonObject '')
    if($tagsNonObject){$point[$tagsNonObject].tags='not-an-object';($listing|Where-Object name -ceq $tagsNonObject).tags='not-an-object'}
    $excludeNull=[string](V $st ExcludeNull '')
    if($excludeNull){
        $point[$excludeNull].tags|Add-Member NoteProperty SmartTierExclude $null -Force
        $listing|Where-Object name -ceq $excludeNull|ForEach-Object{$_.tags|Add-Member NoteProperty SmartTierExclude $null -Force}
    }
    $booleanOptIn=[string](V $st BooleanOptIn '')
    if($booleanOptIn){$point[$booleanOptIn].tags.SmartTierManaged=$true;($listing|Where-Object name -ceq $booleanOptIn).tags.SmartTierManaged=$true}
    $nullTier=[string](V $st NullTier '')
    if($nullTier){$point[$nullTier].properties.accessTier=$null;($listing|Where-Object name -ceq $nullTier).properties.accessTier=$null}
    $pointMismatch=[string](V $st PointMismatch '')
    $wrongResourceName=[string](V $st WrongResourceName 'stfixturewrongproof')
    if($pointMismatch){
        $point[$pointMismatch].id=$point[$pointMismatch].id -replace '/storageAccounts/[^/]+$', "/storageAccounts/$wrongResourceName"
        $point[$pointMismatch].name=$wrongResourceName
    }
    $scopeType=[string]$c.Args.ScopeType;$targetRg=[string]$c.Args.ResourceGroupName
    $listUri=if($scopeType -eq 'Subscription'){
        "$endpoint/subscriptions/$sub/providers/Microsoft.Storage/storageAccounts?api-version=$storageApi"
    }else{"$endpoint/subscriptions/$sub/resourceGroups/$targetRg/providers/Microsoft.Storage/storageAccounts?api-version=$storageApi"}
    $state=[pscustomobject]@{
        Case=$c;IsV11=$scriptParams.ContainsKey('ExpectedChanges');Endpoint=$endpoint;Environment=$env
        Listing=@($listing);Point=$point;ListUri=$listUri;AccountNext="$endpoint/mock/accounts?page=2"
        SubLockUri="$endpoint/subscriptions/$sub/providers/Microsoft.Authorization/locks?api-version=$lockApi"
        RgLockUri="$endpoint/subscriptions/$sub/resourceGroups/$targetRg/providers/Microsoft.Authorization/locks?api-version=$lockApi"
        SubLockNext="$endpoint/mock/sub-locks?page=2";RgLockNext="$endpoint/mock/rg-locks?page=2"
        SubLocks=@(V $st SubLocks @());RgLocks=@(V $st RgLocks @())
        SubLockStatus=[int](V $st SubLockStatus 200);RgLockStatus=[int](V $st RgLockStatus 200)
        PaginateAccounts=[bool](V $st PaginateAccounts $false);PaginateLocks=[bool](V $st PaginateLocks $false)
        GetFault=[string](V $st GetFault '');GetFaultCode=[int](V $st GetFaultCode 500)
        GetFaultArm=[string](V $st GetFaultArm 'InternalServerError');GetFaultRequest=[string](V $st GetFaultRequest "req-get-$([int](V $st GetFaultCode 500))-$([string](V $st GetFault ''))")
        VerifyGetFault=[string](V $st VerifyGetFault '');VerifyWrongId=[string](V $st VerifyWrongId '');WrongResourceName=$wrongResourceName
        ChangeTag=[string](V $st ChangeTag '')
        PatchFaults=(V $st PatchFaults @{});PatchTransport=[string](V $st PatchTransport '')
        Patch503Apply=[string](V $st Patch503Apply '');Patch202Apply=[string](V $st Patch202Apply '')
        VerifyNever=[bool](V $st VerifyNever $false)
        Calls=[Collections.Generic.List[object]]::new();Patches=[Collections.Generic.List[object]]::new();Events=[Collections.Generic.List[string]]::new()
        Sleeps=[Collections.Generic.List[double]]::new();AzCalls=[Collections.Generic.List[object]]::new()
        HttpResponses=[Collections.Generic.List[System.Net.Http.HttpResponseMessage]]::new();FaultResponses=[Collections.Generic.List[object]]::new();ThrownResponseCount=0
        GetCounts=@{};PatchIndexes=@{};Patched=@{};BeforePatch=@{};VerifyLeft=@{}
        InitialContext=$null;SelectedContext=$null
    }
    foreach($name in $point.Keys){$state.Patched[$name]=$false;$state.VerifyLeft[$name]=[int](V $st VerifyLag 0)}
    return $state
}
function Add-Fail([Collections.Generic.List[string]]$List,[bool]$Ok,[string]$Text){if(-not$Ok){$List.Add($Text)}}
function Cell([AllowNull()][object]$x){
    if($null-eq$x){return''}
    return ([string]$x).Replace('|','\|').Replace([string][char]13,' ').Replace([string][char]10,'<br>')
}

function Invoke-Case([object]$c) {
    $global:MockState=New-State $c
    $records=[Collections.Generic.List[string]]::new();$thrown=$null;$invoke=@{}
    foreach($key in $c.Args.Keys){
        if($scriptParams.ContainsKey($key)-and $c.Omit-notcontains$key){$invoke[$key]=$c.Args[$key]}
    }
    try{& $RunbookPath @invoke|ForEach-Object{$records.Add([string]$_);$global:MockState.Events.Add("OUTPUT:$([string]$_)")}}catch{$thrown=$_.Exception.Message}
    $rows=[Collections.Generic.List[object]]::new();$intents=[Collections.Generic.List[object]]::new();$summary=$null;$summaryPrefix=$false;$summaryCount=0
    $invalid=[Collections.Generic.List[string]]::new()
    for($i=0;$i-lt$records.Count;$i++){
        $line=$records[$i]
        try{
            if($line.StartsWith('SUMMARY ')){
                $summary=$line.Substring(8)|ConvertFrom-Json -Depth 100;$summaryPrefix=$true;$summaryCount++;continue
            }
            if($line.StartsWith('INTENT ')){
                $intents.Add(($line.Substring(7)|ConvertFrom-Json -Depth 100));continue
            }
            $doc=$line|ConvertFrom-Json -Depth 100
            if($null-ne$doc.PSObject.Properties['results']){
                $summary=$doc;foreach($r in @($doc.results)){$rows.Add($r)}
            }else{$rows.Add($doc)}
        }catch{$invalid.Add("invalid output line: $line")}
    }
    $terminal=[ordered]@{}
    foreach($row in $rows){$name=[string](V $row name '');if($name){$terminal[$name]=$row}}
    $e=$c.Expect;$fails=[Collections.Generic.List[string]]::new()
    foreach($name in $e.Statuses.Keys){
        $actual=if($terminal.Contains($name)){[string](V $terminal[$name] status '[missing]')}else{'[missing]'}
        Add-Fail $fails ($actual-ceq[string]$e.Statuses[$name]) "$name status expected '$($e.Statuses[$name])', got '$actual'"
    }
    if([bool](V $e ExactStatuses $true)){
        Add-Fail $fails ($terminal.Count-eq$e.Statuses.Count) "terminal account count expected $($e.Statuses.Count), got $($terminal.Count)"
    }
    Add-Fail $fails (([bool]$thrown)-eq[bool]$e.Throw) "throw expected $($e.Throw), got $([bool]$thrown) ('$thrown')"
    Add-Fail $fails ($global:MockState.Patches.Count-eq[int]$e.Patches) "PATCH count expected $($e.Patches), got $($global:MockState.Patches.Count)"
    foreach($patch in $global:MockState.Patches){Add-Fail $fails ($patch.Raw-ceq'{"properties":{"accessTier":"Smart"}}') "PATCH for $($patch.Account) used '$($patch.Raw)'"}
    foreach($get in @($global:MockState.Calls|Where-Object Method -eq 'GET')){Add-Fail $fails (-not$get.PayloadBound) "GET bound Payload for $($get.Uri)"}
    Add-Fail $fails (@($global:MockState.Calls|Where-Object{$_.Uri-like'*/providers/Microsoft.Authorization/locks?*'}).Count-eq0) 'runbook enumerated management locks'
    $classificationRows=@($rows|Where-Object event -ceq 'Classification')
    $outcomeRows=@($rows|Where-Object event -ceq 'Outcome')
    foreach($row in $rows){
        $expectedEvent=if([string](V $row stage '')-ceq'Evaluate'){'Classification'}else{'Outcome'}
        Add-Fail $fails ([string](V $row event '')-ceq$expectedEvent) "row for '$(V $row name)' at stage '$(V $row stage)' had event '$(V $row event)' instead of '$expectedEvent'"
    }
    if($null-ne$summary){
        $discovered=[int](V (V $summary counts) discovered 0)
        $candidates=[int](V (V $summary counts) candidates 0)
        Add-Fail $fails ($classificationRows.Count-eq$discovered) "Classification row count $($classificationRows.Count) != discovered $discovered"
        foreach($group in @($classificationRows|Group-Object name)){
            Add-Fail $fails ($group.Count-eq1) "account '$($group.Name)' emitted $($group.Count) Classification rows"
        }
        if([string](V $summary mode '')-ceq'Audit'){
            Add-Fail $fails ($outcomeRows.Count-eq0) "Audit emitted $($outcomeRows.Count) Outcome row(s)"
        }else{
            Add-Fail $fails ($outcomeRows.Count-eq$candidates) "Outcome row count $($outcomeRows.Count) != candidates $candidates"
        }
    }
    if(Has (V $summary counts) patchesSubmitted){
        $submitted=[int](V (V $summary counts) patchesSubmitted -1)
        Add-Fail $fails ($intents.Count-eq$submitted) "INTENT count $($intents.Count) != patchesSubmitted $submitted"
        Add-Fail $fails ($submitted-eq$global:MockState.Patches.Count) "patchesSubmitted $submitted != wire PATCH count $($global:MockState.Patches.Count)"
        Add-Fail $fails ($intents.Count-eq$global:MockState.Patches.Count) "INTENT count $($intents.Count) != wire PATCH count $($global:MockState.Patches.Count)"
        foreach($intent in $intents){
            $names=@($intent.PSObject.Properties.Name);$fields=@('timestamp','attempt','id','name','beforeTier','payload')
            Add-Fail $fails ((($names|Sort-Object)-join',')-ceq(($fields|Sort-Object)-join',')) "INTENT fields differ: '$($names-join',')'"
            Add-Fail $fails ([string](V $intent payload '')-ceq'{"properties":{"accessTier":"Smart"}}') "INTENT payload was '$(V $intent payload)'"
        }
        for($i=0;$i-lt$global:MockState.Events.Count;$i++){
            if($global:MockState.Events[$i].StartsWith('OUTPUT:INTENT ')){
                Add-Fail $fails ($i+1-lt$global:MockState.Events.Count-and$global:MockState.Events[$i+1].StartsWith('REST:PATCH:')) "INTENT at event $i was not immediately before a wire PATCH"
            }
            if($global:MockState.Events[$i].StartsWith('REST:PATCH:')){
                Add-Fail $fails ($i-gt0-and$global:MockState.Events[$i-1].StartsWith('OUTPUT:INTENT ')) "wire PATCH at event $i had no immediately preceding INTENT"
            }
        }
    }
    if(Has $e ThrowLike){
        Add-Fail $fails ($thrown-like[string]$e.ThrowLike) "throw did not match '$($e.ThrowLike)': '$thrown'"
    }
    if(Has $e RestCalls){
        Add-Fail $fails ($global:MockState.Calls.Count-eq[int]$e.RestCalls) "REST calls expected $($e.RestCalls), got $($global:MockState.Calls.Count)"
    }
    if(Has $e Rows){Add-Fail $fails ($rows.Count-eq[int]$e.Rows) "row count expected $($e.Rows), got $($rows.Count)"}
    if(Has $e SummaryPrefix){
        Add-Fail $fails ($summaryPrefix-eq[bool]$e.SummaryPrefix) "SUMMARY prefix expected $($e.SummaryPrefix), got $summaryPrefix"
    }
    if(Has $e Abort){
        $actual=V $summary abortReason '[missing]'
        Add-Fail $fails ($actual-ceq$e.Abort) "abortReason expected '$($e.Abort)', got '$actual'"
    }
    if(Has $e Counts){
        foreach($key in $e.Counts.Keys){
            $actual=V (V $summary counts) $key '[missing]'
            Add-Fail $fails ([string]$actual-ceq[string]$e.Counts[$key]) "count $key expected '$($e.Counts[$key])', got '$actual'"
        }
    }
    switch($c.Id){
        S01 {
            $reasons=@{
                stfixturenotag="MissingOptInTag:SmartTierManaged=true (absent)"
                stfixturebadtag="MissingOptInTag:SmartTierManaged=true (found 'maybe')"
                stfixturelrs='UnsupportedSku:Standard_LRS';stfixtureblock='UnsupportedKind:BlockBlobStorage'
            }
            foreach($name in $reasons.Keys){
                $actual=@(V $terminal[$name] reasons @())-join'|'
                Add-Fail $fails ($actual-ceq$reasons[$name]) "$name reason expected '$($reasons[$name])', got '$actual'"
            }
            Add-Fail $fails ([int](V $summary maxChanges -1)-eq1) "default maxChanges was '$(V $summary maxChanges)'"
        }
        S04 {
            Add-Fail $fails (@($global:MockState.Calls|Where-Object{$_.Uri -in @($global:MockState.SubLockUri,$global:MockState.RgLockUri)}).Count-eq0) 'runbook enumerated locks despite the final no-preflight ruling'
        }
        S05 {}
        S07 {
            $r=@(V (V $terminal 'stfixturezrs') reasons @())-join'|'
            Add-Fail $fails ($r-like"*found 'True'*") "found value was not reported: '$r'"
            Add-Fail $fails (-not $scriptParams.ContainsKey('RequiredTagValue')) 'removed RequiredTagValue parameter is still exposed'
        }
        S08 {
            if($global:MockState.Patches.Count-eq1){
                Add-Fail $fails ($global:MockState.Patches[0].Raw -ceq '{"properties":{"accessTier":"Smart"}}') "PATCH body was '$($global:MockState.Patches[0].Raw)'"
            }
            Add-Fail $fails ($intents.Count-eq1-and[string](V $intents[0] payload '')-ceq'{"properties":{"accessTier":"Smart"}}') 'one exact INTENT was not emitted before the PATCH'
            $intentEvent=@($global:MockState.Events|Where-Object{$_.StartsWith('OUTPUT:INTENT ')})
            $patchEvent=@($global:MockState.Events|Where-Object{$_.StartsWith('REST:PATCH:')})
            if($intentEvent.Count-eq1-and$patchEvent.Count-eq1){
                $ii=$global:MockState.Events.IndexOf($intentEvent[0]);$pi=$global:MockState.Events.IndexOf($patchEvent[0])
                Add-Fail $fails ($pi-eq$ii+1) "INTENT was not immediately before PATCH (event indexes $ii/$pi)"
            }
        }
        S09 {
            Add-Fail $fails ((@($global:MockState.Sleeps)-join',')-ceq'5,5') "verify sleeps expected '5,5', got '$($global:MockState.Sleeps-join',')'"
            Add-Fail $fails ([int]$global:MockState.GetCounts['stfixturezrs']-eq5) "point GET count expected 5, got $($global:MockState.GetCounts['stfixturezrs'])"
        }
        S10 {
            Add-Fail $fails ($global:MockState.Patches.Count-eq1) 'verification timeout caused a second PATCH'
            Add-Fail $fails ([int]$global:MockState.GetCounts['stfixturezrs']-eq14) "point GET count expected 14, got $($global:MockState.GetCounts['stfixturezrs'])"
            Add-Fail $fails (@($global:MockState.Sleeps|Where-Object{$_-eq5}).Count-eq11) 'verification timeout did not perform 11 bounded sleeps'
        }
        S11 {
            Add-Fail $fails ($global:MockState.Patches.Count-eq1) 'Forbidden was retried despite the circuit breaker'
            Add-Fail $fails ([int](V (V $summary counts) runAborted -1)-eq0) "single-target runAborted was '$(V (V $summary counts) runAborted)'"
        }
        S12 {
            Add-Fail $fails (@($global:MockState.Sleeps|Where-Object{$_-ge7}).Count-ge1) "Retry-After 7 was not honored: '$($global:MockState.Sleeps-join',')'"
        }
        S13 {
            $row=V $terminal 'stfixturezrs'
            Add-Fail $fails ([string](V $row message '') -like '*response*lost*') "response-loss reconciliation message missing: '$(V $row message)'"
            Add-Fail $fails ([int]$global:MockState.GetCounts['stfixturezrs']-eq3) "503-applied path point GET count expected 3, got $($global:MockState.GetCounts['stfixturezrs'])"
        }
        S14 {
            Add-Fail $fails ($global:MockState.Patches.Count-eq1) 'transport ambiguity caused a PATCH retry'
            Add-Fail $fails ([int]$global:MockState.GetCounts['stfixturezrs']-eq8) "ambiguous path point GET count expected 8, got $($global:MockState.GetCounts['stfixturezrs'])"
        }
        S16 {
            if($c.Variant-ceq'missing AccountName'){
                Add-Fail $fails ($global:MockState.AzCalls.Count-eq0) "missing target validation made $($global:MockState.AzCalls.Count) Az call(s)"
            }
        }
        S18 { Add-Fail $fails ($global:MockState.AzCalls.Count-eq0) "validation made $($global:MockState.AzCalls.Count) Az call(s)" }
        S19 {
            Add-Fail $fails ($scriptParams.ContainsKey('AllowUntaggedRemediation')-and$scriptParams.ContainsKey('ExpectedChanges')) 'runbook lacks the explicit untagged-remediation fence parameters'
            Add-Fail $fails ((V $summary optInTagRequired $true)-eq$false) "optInTagRequired was '$(V $summary optInTagRequired)'"
            Add-Fail $fails ($null-eq(V $summary requiredTag '__missing__')) "requiredTag was '$(V $summary requiredTag)'"
        }
        S20 { Add-Fail $fails ($global:MockState.AzCalls.Count-eq0) 'scope validation reached Az authentication' }
        S21 { Add-Fail $fails ($global:MockState.AzCalls.Count-eq0) 'mandatory binding failure reached Az authentication' }
        S22 { Add-Fail $fails ($global:MockState.AzCalls.Count-eq0) 'whitespace validation reached Az authentication' }
        S23 {
            $r=@(V (V $terminal 'stfixturezrs') reasons @())-join'|'
            Add-Fail $fails ($r -like '*PreconditionChanged*' -and $r -like '*absent*') "fresh reason was incomplete: '$r'"
        }
        S24 {
            Add-Fail $fails (@($global:MockState.Calls|Where-Object{$_.Uri-notlike"$($global:MockState.Endpoint)/*"}).Count-eq0) 'sovereign case called a different ARM host'
            if($c.Variant-ceq'allowed'){Add-Fail $fails ($scriptParams.ContainsKey('AllowNonPublicCloud')) 'runbook lacks AllowNonPublicCloud'}
        }
        S25 {
            Add-Fail $fails (@($global:MockState.Calls|Where-Object Uri -ceq $global:MockState.AccountNext).Count-eq1) 'account nextLink not fetched exactly once'
            Add-Fail $fails (@($global:MockState.Calls|Where-Object{$_.Uri -in @($global:MockState.SubLockUri,$global:MockState.SubLockNext,$global:MockState.RgLockUri,$global:MockState.RgLockNext)}).Count-eq0) 'lock endpoint was called'
        }
        S27 {
            if($global:MockState.Calls.Count){
                if($c.Variant-ceq'Audit'){
                    Add-Fail $fails (@($global:MockState.Calls|Where-Object{$_.Uri -like '*/storageAccounts/stfixturezrs?*'}).Count -ge 1) 'Audit sibling did not continue after discovery error'
                }
                Add-Fail $fails ([int]$global:MockState.GetCounts['stfixturegzrs']-eq4) "discovery retry count expected 4, got $($global:MockState.GetCounts['stfixturegzrs'])"
                $faultRow=V $terminal 'stfixturegzrs'
                Add-Fail $fails ([int](V $faultRow httpStatus 0)-eq500) "discovery httpStatus was '$(V $faultRow httpStatus)'"
                Add-Fail $fails ([string](V $faultRow armCode '')-ceq'InternalServerError') "discovery armCode was '$(V $faultRow armCode)'"
                Add-Fail $fails ([string](V $faultRow requestId '')-ceq'req-get-500-stfixturegzrs') "discovery requestId was '$(V $faultRow requestId)'"
            }
        }
        S28 {
            foreach($x in $invalid){$fails.Add($x)}
            Add-Fail $fails ($summaryCount-eq1) "SUMMARY count expected 1, got $summaryCount"
            Add-Fail $fails ($intents.Count-eq1) "INTENT count expected 1, got $($intents.Count)"
            $fields=@('timestamp','event','subscriptionId','resourceGroup','name','id','location','kind','sku','isHnsEnabled','beforeTier','afterTier','status','reasons','stage','httpStatus','armCode','requestId','message')
            foreach($row in $rows){
                $names=@($row.PSObject.Properties.Name)
                Add-Fail $fails ((($names|Sort-Object)-join',')-ceq(($fields|Sort-Object)-join',')) "row fields differ: '$($names-join',')'"
            }
            if($rows.Count){
                $rowLines=@($records|Where-Object{-not $_.StartsWith('INTENT ') -and -not $_.StartsWith('SUMMARY ')})
                Add-Fail $fails ($rowLines.Count-and$rowLines[0]-match'"beforeTier":null') 'JSON null was not emitted for the account beforeTier'
            }
            Add-Fail $fails ($rows.Count-eq2-and[string](V $rows[0] event '')-ceq'Classification'-and[string](V $rows[1] event '')-ceq'Outcome') 'expected Classification then Outcome row order'
            if($rows.Count-eq2){
                Add-Fail $fails ([string](V $rows[0] id '')-ceq[string](V $rows[1] id '')) 'Classification and Outcome ids differ'
            }
            Add-Fail $fails ([string](V $summary schemaVersion '') -ceq '1.1') "schemaVersion was '$(V $summary schemaVersion)'"
            Add-Fail $fails ([string](V $summary identity '') -ceq 'system-assigned') "identity was '$(V $summary identity)'"
            Add-Fail $fails ([string](V $summary accountName '') -ceq 'stfixturezrs') "accountName was '$(V $summary accountName)'"
            Add-Fail $fails ((V $summary optInTagRequired $false)-eq$true) "optInTagRequired was '$(V $summary optInTagRequired)'"
            Add-Fail $fails ([string](V $summary requiredTag '')-ceq'SmartTierManaged=true') "requiredTag was '$(V $summary requiredTag)'"
            $summaryFields=@('schemaVersion','runbookVersion','timestampUtc','jobStartedUtc','identity','environment','mode','scopeType','subscriptionId','resourceGroupName','accountName','optInTagRequired','requiredTag','exclusionTag','allowUntaggedRemediation','maxChanges','expectedChanges','jobTimeBudgetSeconds','counts','abortReason','abortMessage','explicitTierNote','exitCostNote')
            $summaryNames=@($summary.PSObject.Properties.Name)
            Add-Fail $fails ((($summaryNames|Sort-Object)-join',')-ceq(($summaryFields|Sort-Object)-join',')) "summary fields differ: '$($summaryNames-join',')'"
            $countFields=@('discovered','candidates','remediated','alreadySmart','skipped','excluded','notOptedIn','locked','preconditionChanged','deferred','failed','unknown','budgetSkipped','runAborted','errors','patchesSubmitted')
            $countNames=@((V $summary counts).PSObject.Properties.Name)
            Add-Fail $fails ((($countNames|Sort-Object)-join',')-ceq(($countFields|Sort-Object)-join',')) "summary count fields differ: '$($countNames-join',')'"
            $requiredParams=@('Mode','ScopeType','SubscriptionId','ResourceGroupName','AccountName','RequireOptInTag','AllowUntaggedRemediation','RequiredTagName','ExclusionTagName','MaxChanges','ExpectedChanges','JobTimeBudgetSeconds','AllowNonPublicCloud')
            foreach($p in $requiredParams){Add-Fail $fails ($scriptParams.ContainsKey($p)) "runbook missing parameter $p"}
            foreach($p in @('ManagedIdentityClientId','RequiredTagValue')){Add-Fail $fails (-not$scriptParams.ContainsKey($p)) "removed parameter $p is exposed"}
            Add-Fail $fails ([int](V (V $summary counts) patchesSubmitted -1)-eq1) "patchesSubmitted was '$(V (V $summary counts) patchesSubmitted)'"
            $counts=V $summary counts;$terminalSum=0
            foreach($n in @('remediated','alreadySmart','skipped','excluded','notOptedIn','locked','preconditionChanged','deferred','failed','unknown','budgetSkipped')){
                $terminalSum+=[int](V $counts $n 0)
            }
            Add-Fail $fails ($terminalSum-eq[int](V $counts discovered -1)) "terminal count sum $terminalSum != discovered $(V $counts discovered)"
            Add-Fail $fails ($records.Count-ge2-and$records[$records.Count-1].StartsWith('SUMMARY ')) 'SUMMARY was not the final output line'
        }
        S29 {
            Add-Fail $fails ($scriptParams.ContainsKey('JobTimeBudgetSeconds')) 'runbook does not accept JobTimeBudgetSeconds'
        }
        S30 {
            $set=@($global:MockState.AzCalls|Where-Object Name -eq 'Set-AzContext')
            Add-Fail $fails ($set.Count-eq1-and$set[0].DefaultProfileBound-and[object]::ReferenceEquals($set[0].Profile,$global:MockState.InitialContext)) 'Set-AzContext did not receive the exact connection context'
            $contextCalls=@($global:MockState.AzCalls|Where-Object{$_.Name -in @('Get-AzEnvironment','Invoke-AzRestMethod')})
            Add-Fail $fails (@($contextCalls|Where-Object Name -eq 'Invoke-AzRestMethod').Count-gt0) 'no REST calls were observed'
            foreach($call in $contextCalls){
                Add-Fail $fails ($call.DefaultProfileBound-and[object]::ReferenceEquals($call.Profile,$global:MockState.SelectedContext)) "$($call.Name) lacked the selected DefaultProfile"
            }
        }
        S31 {
            $row=V $terminal 'stfixturezrs'
            Add-Fail $fails ([int](V $row httpStatus 0)-eq400) "httpStatus was '$(V $row httpStatus)'"
            Add-Fail $fails ([string](V $row armCode '') -ceq 'InvalidRequest') "armCode was '$(V $row armCode)'"
            Add-Fail $fails ([string](V $row requestId '') -ceq 'req-case-insensitive') "requestId was '$(V $row requestId)'"
        }
        S32 {}
        S33 {
            $row=V $terminal 'stfixturezrs';$reasons=@(V $row reasons @())-join'|'
            Add-Fail $fails ([string](V $row stage '')-ceq'Verify') "stage was '$(V $row stage)'"
            Add-Fail $fails ($reasons-like'*VerificationReadFailed*') "reason was '$reasons'"
            Add-Fail $fails ([int]$global:MockState.GetCounts['stfixturezrs']-eq6) "point GET count expected 6, got $($global:MockState.GetCounts['stfixturezrs'])"
        }
        S34 {
            $row=V $terminal 'stfixturezrs';$reasons=@(V $row reasons @())-join'|'
            Add-Fail $fails ($reasons-like'*VerificationTimeout*') "reason was '$reasons'"
            Add-Fail $fails ([int]$global:MockState.GetCounts['stfixturezrs']-eq14) "point GET count expected 14, got $($global:MockState.GetCounts['stfixturezrs'])"
            Add-Fail $fails (@($global:MockState.Sleeps|Where-Object{$_-eq5}).Count-eq11) 'wrong-id verification did not perform eleven bounded sleeps'
        }
        S35 {
            $row=V $terminal 'stfixturezrs'
            Add-Fail $fails ([int]$global:MockState.GetCounts['stfixturezrs']-eq3) "point GET count expected 3, got $($global:MockState.GetCounts['stfixturezrs'])"
            Add-Fail $fails ($global:MockState.Sleeps.Count-eq0) "reconciled 202 slept or performed redundant verification: '$($global:MockState.Sleeps-join',')'"
            Add-Fail $fails ([int](V $row httpStatus 0)-eq202) "httpStatus was '$(V $row httpStatus)'"
            Add-Fail $fails ([string](V $row message '')-like'*re-read*') "reconciliation message was '$(V $row message)'"
        }
        S36 {
            $row=V $terminal 'stfixturezrs';$reasons=@(V $row reasons @())-join'|'
            Add-Fail $fails ([int](V $row httpStatus 0)-eq409) "httpStatus was '$(V $row httpStatus)'"
            Add-Fail $fails ([string](V $row armCode '')-ceq'FeatureNotSupportForAccount') "armCode was '$(V $row armCode)'"
            Add-Fail $fails ([string](V $row requestId '')-ceq'req-409-definitive') "requestId was '$(V $row requestId)'"
            Add-Fail $fails ($reasons-like'*Rejected:FeatureNotSupportForAccount*') "reason was '$reasons'"
        }
        S37 {
            $row=V $terminal 'stfixturezrs'
            Add-Fail $fails ($global:MockState.Sleeps.Count-eq0) "Retry-After 400 was shortened: '$($global:MockState.Sleeps-join',')'"
            Add-Fail $fails ($global:MockState.Patches.Count-eq1) 'Retry-After 400 caused a retry'
            Add-Fail $fails ($global:MockState.HttpResponses.Count-eq1) "expected one stored HttpResponseMessage, got $($global:MockState.HttpResponses.Count)"
            if($global:MockState.HttpResponses.Count){Add-Fail $fails ($global:MockState.HttpResponses[0].Headers-is[System.Net.Http.Headers.HttpResponseHeaders]) 'mock headers were not HttpResponseHeaders'}
            Add-Fail $fails ($global:MockState.FaultResponses.Count-eq1-and$global:MockState.FaultResponses[0].Headers-is[System.Net.Http.Headers.HttpResponseHeaders]) "returned response headers type was '$($global:MockState.FaultResponses[0].Headers.GetType().FullName)'"
            $retryValues=$null;$retryFound=$global:MockState.FaultResponses[0].Headers.TryGetValues('Retry-After',[ref]$retryValues)
            Add-Fail $fails ($retryFound-and[string]@($retryValues)[0]-ceq'400') "mock Retry-After values were '$(@($retryValues)-join',')'"
            Add-Fail $fails ([int](V $row httpStatus 0)-eq429) "httpStatus was '$(V $row httpStatus)'"
            Add-Fail $fails ([string](V $row requestId '')-ceq'req-httpheaders-429') "requestId was '$(V $row requestId)'"
        }
        S38 {
            $row=V $terminal 'stfixturezrs'
            Add-Fail $fails ([int]$global:MockState.GetCounts['stfixturezrs']-eq4) "point GET count expected 4, got $($global:MockState.GetCounts['stfixturezrs'])"
            Add-Fail $fails ($global:MockState.Sleeps.Count-eq3) "GET 501 retry sleeps expected 3, got $($global:MockState.Sleeps.Count)"
            Add-Fail $fails ([int](V $row httpStatus 0)-eq501) "httpStatus was '$(V $row httpStatus)'"
            Add-Fail $fails ([string](V $row armCode '')-ceq'NotImplemented') "armCode was '$(V $row armCode)'"
            Add-Fail $fails ([string](V $row requestId '')-ceq'req-get-501-stfixturezrs') "requestId was '$(V $row requestId)'"
        }
        S39 {
            $row=V $terminal 'stfixturezrs'
            Add-Fail $fails ($global:MockState.ThrownResponseCount-eq1) "thrown-response count was $($global:MockState.ThrownResponseCount)"
            Add-Fail $fails ([int]$global:MockState.GetCounts['stfixturezrs']-eq2) "point GET count expected 2, got $($global:MockState.GetCounts['stfixturezrs'])"
            Add-Fail $fails ([int](V $row httpStatus 0)-eq400) "httpStatus was '$(V $row httpStatus)'"
            Add-Fail $fails ([string](V $row armCode '')-ceq'InvalidRequest') "armCode was '$(V $row armCode)'"
            Add-Fail $fails ([string](V $row requestId '')-ceq'req-thrown-response') "requestId was '$(V $row requestId)'"
        }
        S40 {
            $row=V $terminal 'stfixturezrs'
            Add-Fail $fails ([string](V $row message '')-like"*'tags'*not a JSON object*") "message was '$(V $row message)'"
        }
        S41 {
            $reasons=@(V (V $terminal 'stfixturezrs') reasons @())-join'|'
            Add-Fail $fails ($reasons-ceq'ExclusionTag:SmartTierExclude=null') "reason was '$reasons'"
        }
        S42 {
            $reasons=@(V (V $terminal 'stfixturezrs') reasons @())-join'|'
            Add-Fail $fails ($reasons-like'*found non-string true*') "reason was '$reasons'"
        }
        S43 {
            $row=V $terminal 'stfixturezrs'
            Add-Fail $fails ([string](V $row event '')-ceq'Classification') "event was '$(V $row event)'"
            Add-Fail $fails ([string](V $row message '')-like'*listing*point read*disagree*') "message was '$(V $row message)'"
        }
        S44 {
            Add-Fail $fails (@($global:MockState.Calls|Where-Object{$_.Uri-notlike"$($global:MockState.Endpoint)/*"}).Count-eq0) 'cloud case called a different ARM host'
            if($c.Variant-ceq'refused German'){
                Add-Fail $fails ($classificationRows.Count-eq1-and[string](V $classificationRows[0] status '')-ceq'WouldRemediate') 'German-cloud target was not classified WouldRemediate before refusal'
                Add-Fail $fails ($outcomeRows.Count-eq1) "German-cloud candidate Outcome rows expected 1, got $($outcomeRows.Count)"
            }
        }
        S45 {
            Add-Fail $fails ($global:MockState.AzCalls.Count-eq0) "parameter validation made $($global:MockState.AzCalls.Count) Az call(s)"
            Add-Fail $fails ([string](V $summary abortMessage '')-like'*ExpectedChanges cannot exceed 1*') "abortMessage was '$(V $summary abortMessage)'"
            Add-Fail $fails (@($runbookSource|Where-Object{$_-match'^\s*#requires\b'}).Count-eq0) 'runbook still contains a #requires directive'
        }
    }
    $statusText=@($terminal.Keys|ForEach-Object{"$_=$([string](V $terminal[$_] status))"})-join','
    [pscustomobject]@{
        Case=$c;Pass=$fails.Count-eq0;Failures=@($fails);Rows=@($rows);Intents=@($intents);Summary=$summary;Outputs=@($records);Thrown=$thrown;Invalid=@($invalid)
        Calls=@($global:MockState.Calls);Patches=@($global:MockState.Patches);Sleeps=@($global:MockState.Sleeps)
        Actual="statuses=$statusText; rows=$($rows.Count); PATCH=$($global:MockState.Patches.Count); sleeps=$($global:MockState.Sleeps-join','); throw=$([bool]$thrown); abort=$(V $summary abortReason '<none>')"
    }
}

$run=@($cases|ForEach-Object{Invoke-Case $_})
$passed=@($run|Where-Object Pass).Count;$failed=$run.Count-$passed
$hash=(Get-FileHash -LiteralPath $RunbookPath -Algorithm SHA256).Hash.ToLowerInvariant()
$pwsh='/home/kevo/codex-debate-blob-smarttier-20260825/tools/pwsh74/pwsh'
$rerun="$pwsh -NoProfile -File ./harness.ps1 -RunbookPath $RunbookPath -ResultsPath $ResultsPath"
$tick=[char]96;$md=[Collections.Generic.List[string]]::new()
$md.Add('# Enable-AzStorageSmartTier 1.1 offline behavior results');$md.Add('')
$md.Add("Re-run: $tick$rerun$tick");$md.Add('')
$md.Add("PowerShell $($PSVersionTable.PSVersion); real runbook $tick$RunbookPath$tick; SHA-256 $tick$hash$tick; case executions $($run.Count); oracle PASS $passed; oracle FAIL $failed.")
$md.Add('')
$md.Add('HTTP statuses use PSHttpResponse-shaped objects. Most scenarios use case-insensitive Dictionary<string,string[]> headers; S37 uses a real HttpResponseHeaders and S39 throws an exception carrying Response. Expected runbook throws are observations, not harness failures.')
$md.Add('')
$md.Add('Final SPEC §3 resolves the draft lock conflict: locks are not enumerated, so stfixturelock is the fourth WouldRemediate row in S01; ScopeLocked is classified by ARM code only at write time, regardless of HTTP status.')
$md.Add('');$md.Add('S29 validates that JobTimeBudgetSeconds=60 binds. The Start-Sleep mock does not advance DateTime.UtcNow, so budget exhaustion cannot be simulated without a clock seam; this is the requested documented gap.')
$md.Add('');$md.Add('S30 treats Disable-AzContextAutosave and Connect-AzAccount as context bootstrap. It requires Set-AzContext to receive the exact connection context and every later Get-AzEnvironment/Invoke-AzRestMethod call to receive the exact selected context.')
$md.Add('')
$md.Add('| Scenario | Expected | Actual | Result | Exact responsible source line(s) |')
$md.Add('|---|---|---|---|---|')
foreach($r in $run){
    $variant=if($r.Case.Variant){" [$($r.Case.Variant)]"}else{''};$mark=if($r.Pass){'PASS'}else{'**FAIL**'}
    $exp="statuses=$(@($r.Case.Expect.Statuses.Keys|ForEach-Object{"$_=$($r.Case.Expect.Statuses[$_])"})-join','); PATCH=$($r.Case.Expect.Patches); throw=$($r.Case.Expect.Throw)"
    $md.Add("| $($r.Case.Id)$variant — $(Cell $r.Case.Purpose) | $(Cell $exp) | $(Cell $r.Actual) | $mark | $(Cell $r.Case.Lines) |")
}
$md.Add('');$md.Add('## Failed-oracle diagnostics');$md.Add('')
if(-not$failed){$md.Add('- None.')}else{
    foreach($r in $run|Where-Object{-not$_.Pass}){
        foreach($f in $r.Failures){$md.Add("- $($r.Case.Id)$(if($r.Case.Variant){" [$($r.Case.Variant)]"}): $f")}
    }
}
$md.Add('');$md.Add('## Proven runbook defects');$md.Add('')
$defectCount=0
if(@($run|Where-Object{$_.Case.Id-eq'S05'-and-not$_.Pass}).Count){
    $defectCount++;$md.Add('- `Enable-AzStorageSmartTier.ps1:851-861`: the generic HTTP 403 branch runs before the `ScopeLocked` ARM-code branch, so HTTP 403 + `ScopeLocked` becomes `Failed`/`Forbidden` instead of `BlockedScopeLock`.')
}
if(@($run|Where-Object{$_.Case.Id-eq'S12'-and-not$_.Pass}).Count){
    $defectCount++;$md.Add('- `Enable-AzStorageSmartTier.ps1:386-470,835-844`: a 429 retry creates a second wire PATCH inside `Invoke-ArmCall`, but INTENT and `patchesSubmitted` are emitted/incremented only once outside the retry loop.')
}
if(@($run|Where-Object{$_.Case.Id-in@('S24','S44')-and-not$_.Pass}).Count){
    $defectCount++;$md.Add('- `Enable-AzStorageSmartTier.ps1:776-794`: preflight `UnsupportedCloud` sets an abort and skips the remediation loop, leaving each discovered candidate without the required Outcome row.')
}
if(@($run|Where-Object{$_.Case.Id-eq'S37'-and-not$_.Pass}).Count){
    $defectCount++;$md.Add('- `Enable-AzStorageSmartTier.ps1:227-250,402-403`: `Get-PropertyValue` pipeline-enumerates a real `HttpResponseHeaders`; `Retry-After: 400` is therefore lost, shortened to backoff, and retried instead of being abandoned.')
}
if(-not$defectCount){$md.Add('- None.')}
$md.Add('');$md.Add('## Captured calls, streams, and PATCH bodies');$md.Add('')
foreach($r in $run){
    $variant=if($r.Case.Variant){" [$($r.Case.Variant)]"}else{''}
    $md.Add("<details><summary>$($r.Case.Id)$variant — $($r.Case.Purpose)</summary>");$md.Add('');$md.Add('~~~text')
    $md.Add("RESULT: $(if($r.Pass){'PASS'}else{'FAIL'})")
    $md.Add("THROWN: $(if($r.Thrown){$r.Thrown}else{'<none>'})");$md.Add("SLEEPS: $($r.Sleeps-join',')");$md.Add('CALLS:')
    foreach($call in $r.Calls){$md.Add("$($call.Method) $($call.Uri)")}
    $md.Add('OUTPUT:');if($r.Outputs.Count){foreach($line in $r.Outputs){$md.Add($line)}}else{$md.Add('<none>')};$md.Add('~~~')
    foreach($p in $r.Patches){
        $md.Add('');$md.Add("PATCH $tick$($p.Account)$($tick):");$md.Add('~~~json');$md.Add([string]$p.Raw);$md.Add('~~~')
    }
    $md.Add('');$md.Add('</details>');$md.Add('')
}
$md|Set-Content -LiteralPath $ResultsPath -Encoding utf8
Write-Output "Harness complete: $passed PASS, $failed FAIL. Results: $ResultsPath"
if($failed-gt0){exit 1}

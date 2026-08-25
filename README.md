# Azure Blob Storage smart tier automation

An audit-first Azure Automation runbook that enables **Azure Blob Storage smart tier**
(`properties.accessTier = Smart`) on eligible storage accounts that have explicitly opted in, one
bounded, verified wave at a time.

> **Not to be confused with** Azure Backup "Smart Tiering" (moving recovery points into the vault-archive
> tier), which is a different product with its own repository
> ([azure-backup-smart-tiering-automation](https://github.com/kevo099/azure-backup-smart-tiering-automation)).
> This runbook changes exactly one thing: a storage account's default blob access tier.

> **Status:** 1.0 is the runbook as published in the owner's Automation account on 2026-08-24 and exercised
> against an eight-account fixture; 1.1 is the hardening release produced by an adversarial multi-model
> review (see [CHANGELOG.md](CHANGELOG.md) and [docs/validation.md](docs/validation.md) for exactly what
> has and has not been proven live).

## What smart tier does — and what it costs

Smart tier is an account-level default: block blobs land in **hot**, move to **cool** after 30 days without
access and to **cold** after 60 more, and return to hot when accessed. Azure manages the moves; there are no
transition, early-deletion or retrieval charges inside smart tier. Two things an approver must know:

- **Monitoring fee.** Azure charges a monthly monitoring fee per 10,000 objects larger than 128 KiB. The
  runbook cannot see object counts (control plane only); approve with your own inventory or metrics.
- **Leaving smart tier is not free.** Moving blobs *out* of smart tier costs one cool-write operation per
  object (blobs given an explicit tier never move and cannot return to Smart). "Undo" is a priced migration, never automatic.
- Blobs that carry an explicitly set tier are **not** enrolled by the account-level change; the first
  automatic move happens 30 days after enablement; redundancy can no longer be converted to LRS/GRS.

Prerequisites Azure enforces: Standard general-purpose v2 accounts with ZRS, GZRS or RA-GZRS; block blobs
only. Generally available in public-cloud regions; preview in Azure Government and 21Vianet.

## What the runbook does

| Account state | Audit result | Remediate behaviour |
|---|---|---|
| Not `StorageV2`, or SKU not ZRS/GZRS/RA-GZRS, or not `Succeeded` | `Skipped` (with reasons) | No write |
| Exclusion tag present (`SmartTierExclude`) | `SkippedExcluded` | No write — exclusion always wins |
| Opt-in tag missing or not matching `SmartTierManaged=true` | `SkippedNotOptedIn` (reason shows the value found) | No write |
| Already `Smart` | `AlreadySmart` | No write |
| A `ReadOnly` lock blocks the PATCH (`409 ScopeLocked`, Remediate only) | `BlockedScopeLock` | Not retried, never green: remove the lock deliberately and rerun |
| Eligible and opted in | `WouldRemediate` | `PATCH {"properties":{"accessTier":"Smart"}}`, verify by re-read → `Remediated` |

Writes only happen with `Mode=Remediate` — resource-group scope, **one named account per run** — after the whole scope has been classified, and only when the
preflight guards pass: no discovery errors, candidates ≤ `MaxChanges` (default **1**), candidates =
`ExpectedChanges` when set, opt-in enforced unless `AllowUntaggedRemediation` is set, the named account
eligible (a target that is neither `WouldRemediate` nor `AlreadySmart` aborts with `TargetNotEligible`; an
already-Smart target is the idempotent success), and public cloud unless `AllowNonPublicCloud` (honoured
only for the documented Azure Government / 21Vianet previews, which need feature registration).

Every write outcome is reported honestly: `Remediated` (verified), `BlockedScopeLock`,
`SkippedPreconditionChanged`, `Deferred` (a transient conflict — try the next run), `Failed`
(definitive), or `WriteOutcomeUnknown` (a lost response that re-reads could not resolve — the job fails
and nothing is resubmitted). A `403` on the first write aborts the rest of the run rather than failing
every account one by one.

## Repository contents

```text
src/Enable-AzStorageSmartTier.ps1         Azure Automation runbook (PowerShell 7.4, Az.Accounts)
infra/test-environment.bicep              Nine-account disposable fixture (optional ReadOnly lock)
infra/rbac/*.template.json                Discovery reader and remediator custom-role templates
tests/StaticValidation.ps1                Parser and safety-marker checks
tests/BehaviorHarness.ps1                 Behavioural harness: real runbook + mocked Az cmdlets
docs/design-and-limitations.md            Method comparison, limitations, hardening status
docs/validation.md                        Sanitised live evidence for 1.0 and 1.1
CHANGELOG.md · LICENSE · SECURITY.md
.github/workflows/validate.yml            Static checks, harness, PSScriptAnalyzer, RBAC, Bicep CI
```

Raw subscription, tenant, principal and job identifiers and live account names are intentionally excluded.

## Prerequisites

- Commercial Azure subscription; permission to create an Automation Account, storage accounts, custom
  roles and role assignments (custom roles and assignments need Owner or User Access Administrator).
- Azure CLI with the `automation` extension; Bicep.
- An Automation **PowerShell 7.4** runtime environment with the **Az** default package (validated with
  Az 12.3.0). Record the package version you deploy; runtime-environment updates change behaviour for
  every linked runbook.

## Deploy the fixture

Create a **new, empty** resource group (the deployment is incremental and would overwrite same-named
accounts), then deploy:

```bash
az group create --name <fixture-rg> --location <zrs-region>
az deployment group create --resource-group <fixture-rg> \
  --template-file infra/test-environment.bicep \
  --parameters namePrefix=<3-11 lowercase chars> createLock=false
```

The fixture creates nine empty accounts: ZRS opted-in, ZRS untagged, ZRS wrong tag value, GZRS Cool
opted-in, ZRS hierarchical-namespace opted-in, ZRS already Smart, ZRS opted-in "lock" target, LRS opted-in
(ineligible), Premium block-blob opted-in (ineligible). Pass `createLock=true` (Owner/UAA required) to add a
`ReadOnly` lock to the lock target and reproduce `409 ScopeLocked` live. Empty accounts cost nothing
material; delete the resource group when done.

## RBAC model

Render both templates by replacing `REPLACE_WITH_SUBSCRIPTION_ID`, create them with
`az role definition create --role-definition @<file>`, then assign to the Automation Account's
system-assigned identity:

- **Azure Storage Smart Tier Discovery Reader** (`storageAccounts/read`, subscription and resource-group
  reads) — at resource-group scope for `ScopeType=ResourceGroup`, at subscription scope only
  for subscription discovery.
- **Azure Storage Smart Tier Remediator** (`storageAccounts/read`, `storageAccounts/write`) —
  **only** at the resource group(s) of the current ring.

Be explicit about what the remediator is: `Microsoft.Storage/storageAccounts/write` is full account-update
authority (network rules, shared-key access, TLS, public access…); there is no field-level action for
`accessTier`, and ABAC conditions cannot inspect a control-plane PATCH body. The runbook only ever sends
`accessTier=Smart`, but anyone who can publish or start runbooks in the account can send anything with that
identity — keep the account dedicated, the assignment narrow and temporary, and treat "start runbook" as
writer-equivalent. Do **not** use built-in *Storage Account Contributor*: it also grants key access.

Also decide who may set the opt-in tag: tagging is consent, and a Tag Contributor can enrol an account
they could not otherwise change.

## Publish the runbook

```bash
az automation runbook create  --resource-group <rg> --automation-account-name <account> \
  --name Enable-AzStorageSmartTier --type PowerShell --location <region>
az automation runbook replace-content --resource-group <rg> --automation-account-name <account> \
  --name Enable-AzStorageSmartTier --content @src/Enable-AzStorageSmartTier.ps1
az automation runbook publish --resource-group <rg> --automation-account-name <account> \
  --name Enable-AzStorageSmartTier
sha256sum src/Enable-AzStorageSmartTier.ps1   # record it; the SUMMARY line reports runbookVersion
```

Link the runbook to your PowerShell 7.4 runtime environment (`PATCH .../runbooks/{name}?api-version=2024-10-23`
with `{"properties":{"runtimeEnvironment":"<name>"}}`, or the Portal).

## Parameters

| Parameter | Default | Meaning |
|---|---|---|
| `Mode` | `Audit` | `Audit` or `Remediate` |
| `ScopeType` | `ResourceGroup` | `ResourceGroup` or `Subscription`; `Remediate` requires `ResourceGroup` |
| `SubscriptionId` | required | Target subscription — never inferred from the identity |
| `ResourceGroupName` | | Required for `ResourceGroup`; rejected for `Subscription` |
| `AccountName` | | Exact storage-account name. **Required for `Remediate`** (one account per run); optional filter for `Audit` |
| `RequireOptInTag` | `true` | Only accounts tagged `<RequiredTagName>=true` are candidates |
| `RequiredTagName` | `SmartTierManaged` | Opt-in tag name (matched case-insensitively, as Azure does). The consent value is fixed to `true` and compared exactly — Azure tag values are case-sensitive, so `True` is **not** consent; the reason string shows the value found |
| `ExclusionTagName` | `SmartTierExclude` | Any value present excludes the account |
| `AllowUntaggedRemediation` | `false` | Required to remediate with `RequireOptInTag=false` (the named account is written without the tag; the exclusion tag still wins) |
| `MaxChanges` | `1` | Preflight abort before the first write if more accounts would change (a named target yields at most one) |
| `ExpectedChanges` | `0` | Optional assertion (0 or 1 with a named target): if set and the account would change, the candidate count must equal it; an already-Smart target is not a mismatch |
| `JobTimeBudgetSeconds` | `8400` | No new write starts after this; the job fails closed with the remainder reported |
| `AllowNonPublicCloud` | `false` | Required to remediate outside public Azure; honoured only for Azure Government and 21Vianet (documented previews, feature registration required) — other environments are refused |

## Run audit first, then one account

```bash
az automation runbook start --resource-group <rg> --automation-account-name <account> \
  --name Enable-AzStorageSmartTier --parameters \
    Mode=Audit ScopeType=ResourceGroup ResourceGroupName=<fixture-rg> SubscriptionId=<subscription-id>
```

Read the JSON lines and the `SUMMARY`. Tag exactly one eligible account `SmartTierManaged=true`, grant the
remediator role at that resource group, then:

```bash
... --parameters Mode=Remediate ScopeType=ResourceGroup ResourceGroupName=<fixture-rg> \
    SubscriptionId=<subscription-id> AccountName=<account> ExpectedChanges=1 MaxChanges=1
```

Expect one `Remediated` row and `remediated=1`; run it again and expect `AlreadySmart` with `remediated=0`.
Widen the ring by repeating this per account: the runbook writes one named account per run by design
(the review's judges rejected count-based fleet writes; see `docs/design-and-limitations.md`).
No recurring schedule is created by this repository; if you schedule anything, schedule **Audit**.

## Policy or runbook?

The owner's earlier Azure Policy solution (DeployIfNotExists on the same eligibility) enforces smart tier
continuously on every eligible account, including new ones, with no opt-in. This runbook is the opposite:
bounded, opt-in, per-account evidence. Use Policy in `AuditIfNotExists` for standing compliance reporting and
this runbook for approved waves; run Policy `DeployIfNotExists` only if smart tier is mandatory
organisation-wide — and never both writers on the same scope.

## Teardown

```bash
az role assignment delete --assignee <automation-identity-object-id> --role "Azure Storage Smart Tier Remediator" --scope /subscriptions/<subscription-id>/resourceGroups/<fixture-rg>
az group delete --name <fixture-rg> --yes --no-wait
```

Deleting the fixture accounts deletes nothing of value (they hold no data). Reverting a *real* account from
Smart is a priced migration — see the cost section.

## Local validation

```bash
pwsh -NoProfile -File tests/StaticValidation.ps1
pwsh -NoProfile -File tests/BehaviorHarness.ps1
pwsh -NoProfile -Command "Invoke-ScriptAnalyzer -Path src/Enable-AzStorageSmartTier.ps1 -Severity Error,Warning"
jq empty infra/rbac/*.json
az bicep build --file infra/test-environment.bicep --stdout > /dev/null
```

## Official references

- [Optimize Azure Blob Storage costs with smart tier](https://learn.microsoft.com/azure/storage/blobs/access-tiers-smart)
- [Access tiers for blob data](https://learn.microsoft.com/azure/storage/blobs/access-tiers-overview)
- [Storage Accounts — Update (REST, 2025-08-01)](https://learn.microsoft.com/rest/api/storagerp/storage-accounts/update?view=rest-storagerp-2025-08-01)
- [Lock your Azure resources](https://learn.microsoft.com/azure/azure-resource-manager/management/lock-resources)
- [ARM request limits and throttling](https://learn.microsoft.com/azure/azure-resource-manager/management/request-limits-and-throttling)
- [Invoke-AzRestMethod](https://learn.microsoft.com/powershell/module/az.accounts/invoke-azrestmethod)
- [Azure Automation runtime environments](https://learn.microsoft.com/azure/automation/runtime-environment-overview)
- [Azure Automation limits](https://learn.microsoft.com/azure/automation/automation-subscription-limits-faq)

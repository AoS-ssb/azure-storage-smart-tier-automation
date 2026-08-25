# Validation

Identifiers (subscription, tenant, principal, job) and live account names are omitted.

## 1.0 — as published (2026-08-24)

Source SHA-256 `b7e85626…` (the first commit of this repository, tag `v1.0.0`). Ten jobs ran against a
since-deleted eight-account fixture (ZRS opted-in, GZRS opted-in, ZRS Cool opted-in, ZRS hierarchical
namespace opted-in, ZRS already Smart, ZRS untagged, ZRS wrong tag value, LRS opted-in):

| Job | Parameters | Result |
|---|---|---|
| Audit, RG scope | opt-in required | 8 discovered, 4 `WouldRemediate`, 3 `Skipped` (`MissingOptInTag` ×2, `UnsupportedSku` ×1), 1 `AlreadySmart` |
| Audit, subscription scope | same | identical classification |
| Audit, RG scope | opt-in **not** required | 6 candidates (the untagged and wrong-tag accounts joined) |
| Remediate, RG scope, `MaxChanges=1` | 4 candidates | job **Failed** at preflight, no writes — and **no output document** |
| Remediate, subscription scope, `MaxChanges=4` | 4 candidates | 3 `Remediated`, 1 `Failed`: HTTP **409 `ScopeLocked`** (a `ReadOnly` lock on the GZRS account); job Failed after the other three had changed |
| Remediate, RG scope, `MaxChanges=1` (×3) | one candidate each | `Remediated`; the formerly locked account succeeded once its lock was removed; a manually reset Cool account was re-enabled |

The identity that authorised those writes was not captured; today the account's identity holds only a
read-only custom role.

## 1.0 — baseline audit against the new fixture (2026-08-25)

A fresh nine-account fixture (`infra/test-environment.bicep`, no lock) was created and the 1.0 runbook run
in Audit mode at resource-group scope: 9 discovered, 4 `WouldRemediate` (ZRS opted-in, GZRS Cool, ZRS
hierarchical namespace, the future lock target), 4 `Skipped` (`UnsupportedSku:Standard_LRS`;
`UnsupportedKind:BlockBlobStorage` + `UnsupportedSku:Premium_LRS`; `MissingOptInTag` ×2 — one untagged,
one tagged `maybe`), 1 `AlreadySmart`. Zero writes.

## 1.1 — offline verification (2026-08-25)

`tests/BehaviorHarness.ps1` executes the unmodified runbook under PowerShell 7.4 with mocked Az cmdlets
(`Connect-AzAccount`, `Set-AzContext`, `Disable-AzContextAutosave`, `Invoke-AzRestMethod`) and asserts
per-account statuses and reasons, counters, PATCH bodies, abort reasons, sleeps and thrown errors. Scenario
coverage and the pass count are recorded in the harness output and in the pull request.

## 1.1 — live qualification (2026-08-25, demo Automation Account, PowerShell 7.4 runtime `PowerShell74-SmartTier`, Az 12.3.0)

The candidate bytes were published as the **additive** runbook `Enable-AzStorageSmartTier-v11` (the 1.0
runbook stayed untouched until release) and driven with `az automation runbook start`. The identity was the
account's system-assigned managed identity holding only the discovery-reader permissions, so no write could
succeed — which makes the last guard a genuine negative RBAC test.

| Run | Parameters | Result |
|---|---|---|
| `q2-audit` | `Mode=Audit ScopeType=ResourceGroup` on the nine-account fixture | **Completed**; 9 `Classification` rows: 4 `WouldRemediate` (ZRS/Hot, GZRS/Cool, ZRS/HNS, the lock target), 1 `AlreadySmart`, 2 `Skipped` (`UnsupportedSku:Standard_LRS`; `UnsupportedKind:BlockBlobStorage` + `UnsupportedSku:Premium_LRS`), 2 `SkippedNotOptedIn` (reasons `MissingOptInTag:SmartTierManaged=true (absent)` and `(found 'maybe')`); `patchesSubmitted=0` |
| `q3a` | `Mode=Remediate` without `AccountName` | Failed closed before any ARM call: `SUMMARY … abortReason=InvalidParameters` |
| `q3b` | `Mode=Audit ScopeType=Subscription` with a `ResourceGroupName` | `InvalidParameters` |
| `q3c` | `Mode=Remediate AccountName=<not-opted-in account>` | one `Classification` row (`SkippedNotOptedIn`), `abortReason=TargetNotEligible`, `patchesSubmitted=0` |
| `q3d` | `Mode=Remediate AccountName=nosuchaccount0` | `abortReason=NoAccountMatched` |
| `q3e` | `Mode=Remediate AccountName=… RequireOptInTag=false` without `AllowUntaggedRemediation` | `InvalidParameters` — also proves the CLI's textual `false` binds as `[bool] $false` |
| `q3f` | `Mode=Remediate ScopeType=Subscription AccountName=…` | `InvalidParameters` (writes are resource-group scoped) |
| `q3g` | `Mode=Remediate AccountName=<eligible ZRS account> ExpectedChanges=1` with the reader-only identity | one `INTENT` line, exactly one PATCH (`patchesSubmitted=1`), HTTP **403** → `Outcome` row `Failed` (`Forbidden`, with request id), `abortReason=Forbidden`; the account still reads `Hot` |

Earlier iterations of the same day caught two real runtime facts that the offline mocks could not:
`Invoke-AzRestMethod` rejects an empty `-Payload` on GET (the first live audit aborted with
`UnexpectedError` — fixed by passing the payload only for PATCH) and `PSHttpResponse.Headers` is
`HttpResponseHeaders`, not a dictionary (header reading now uses `TryGetValues`).

Not yet exercised live: the ring-of-one write (`Remediated`) and the idempotent repeat, which need the
remediator role assigned at the fixture resource group; the `409 ScopeLocked` path, which needs the
fixture's optional `ReadOnly` lock (`createLock=true`, Owner/User Access Administrator required). Both are
scripted (`live-qualify.sh` step 4 in the private workspace) and were proven offline by the behavioural
harness.

Tested content SHA-256 (fetch-back of the published `-v11` runbook): `5215c3210d4e9fba…` for the guard set
above; the released bytes are recorded in the release notes as `<FINAL-SHA>`.

# Replicate this in Azure — step by step

A complete path from an empty subscription to a live-qualified ring of one, with the checkpoint you
should see at every step. Times are wall-clock; nothing here costs more than cents while the accounts
stay empty. Read [gotchas.md](gotchas.md) first.

## 0. Prerequisites (5 min)

- Commercial Azure subscription. Owner or User Access Administrator is needed **only** for the RBAC steps
  (5, 7); Contributor is enough for everything else.
- Azure CLI ≥ 2.60 with Bicep (`az bicep install`) and the `automation` extension
  (`az extension add --name automation`; it is marked experimental — the warnings are harmless).
- Automation Accounts are quota-limited **per region** on small subscriptions; if the deployment in step 1
  fails with `Conflict … exceeded your quota for Automation accounts`, pick another region.
- PowerShell 7.4 locally only if you want to run the offline harness (`tests/BehaviorHarness.ps1`).

```bash
SUB=<subscription-id>
AA_RG=<automation-rg>            # owns the Automation Account
AA=<automation-account-name>     # 6–50 chars
FIXTURE_RG=<fixture-rg>          # will hold the nine test accounts
REGION=<zrs-capable region>      # e.g. eastus2, westeurope, centralus
```

## 1. Automation Account, PowerShell 7.4 runtime, runbook (3 min)

`infra/automation-account.bicep` creates the account (system-assigned identity, local auth disabled), a
runtime environment `PowerShell74-SmartTier` with **Az 12.3.0** pinned, and imports the runbook straight from
a tagged release of this repository, already linked to that runtime and published.

```bash
az group create -n $AA_RG -l $REGION
az deployment group create -g $AA_RG --template-file infra/automation-account.bicep \
  --parameters automationAccountName=$AA sourceRef=v1.1.0
PRINCIPAL=$(az automation account show -g $AA_RG -n $AA --query identity.principalId -o tsv)
```

**Checkpoint** — the published content must equal the release file. The import appends exactly one
trailing newline (observed 2026-08-26: 51 361 vs 51 360 bytes), so compare with `diff`, not by hash:

```bash
ARM=https://management.azure.com
az rest --method get --url "$ARM/subscriptions/$SUB/resourceGroups/$AA_RG/providers/Microsoft.Automation/automationAccounts/$AA/runbooks/Enable-AzStorageSmartTier?api-version=2024-10-23" \
  --query '{state:properties.state, runtime:properties.runtimeEnvironment}'      # Published / PowerShell74-SmartTier
az rest --method get --url "$ARM/subscriptions/$SUB/resourceGroups/$AA_RG/providers/Microsoft.Automation/automationAccounts/$AA/runbooks/Enable-AzStorageSmartTier/content?api-version=2023-11-01" -o tsv | tr -d '\r' > published.ps1
git show v1.1.0:src/Enable-AzStorageSmartTier.ps1 | diff - published.ps1        # expect only: "1059a1060 > " (one empty trailing line)
```

If you need byte-exact provenance (hash equality), publish with `scripts/publish-runbook.sh` instead — it
uploads the file itself and the fetch-back hash then matches.

*Alternative without Bicep / for a fork or a local change:* create the runtime environment in the Portal
(PowerShell 7.4, Az 12.3.0) and run `scripts/publish-runbook.sh`, which creates/updates the runbook, links the
runtime (a REST `PATCH` — the CLI cannot), publishes, and fails unless the fetch-back hash equals your file:

```bash
SUBSCRIPTION_ID=$SUB RESOURCE_GROUP=$AA_RG AUTOMATION_ACCOUNT=$AA scripts/publish-runbook.sh
```

## 2. Fixture: nine empty storage accounts (2 min)

```bash
az group create -n $FIXTURE_RG -l $REGION
az deployment group create -g $FIXTURE_RG --template-file infra/test-environment.bicep \
  --parameters namePrefix=<3-11 lowercase chars> createLock=false
```

One account per classification: ZRS opted-in (`…zrstag`), ZRS untagged, ZRS wrong tag value, GZRS Cool
opted-in, ZRS hierarchical-namespace opted-in, ZRS already Smart, ZRS opted-in lock target, LRS opted-in
(ineligible), Premium block-blob opted-in (ineligible).

## 3. First audit — before any RBAC (1 min)

Deliberately run the audit before granting anything, to see the fail-closed path:

```bash
az automation runbook start -g $AA_RG --automation-account-name $AA -n Enable-AzStorageSmartTier \
  --parameters Mode=Audit ScopeType=ResourceGroup ResourceGroupName=$FIXTURE_RG SubscriptionId=$SUB
```

**Checkpoint** (observed on a fresh account, 2026-08-26) — job `Failed`; the last output line is
`SUMMARY {… "abortReason":"UnexpectedError","abortMessage":"Please provide a valid tenant or a valid subscription.", … "counts":{"discovered":0, … "patchesSubmitted":0}}`.
An identity with no role assignment at all cannot even select the subscription (`Set-AzContext` fails before
any ARM call); once it holds *any* role inside the subscription but not on the target, the same run ends with
`ARM GET failed … HTTP 403 AuthorizationFailed` instead. Either way: no rows, no writes, reason spelled out.

## 4. Reader role at the audit scope (2 min, Owner/UAA)

```bash
sed "s#<subscription-id>#$SUB#" infra/rbac/discovery-reader-role.template.json > /tmp/reader.json
az role definition create --role-definition @/tmp/reader.json
az role assignment create --assignee-object-id $PRINCIPAL --assignee-principal-type ServicePrincipal \
  --role "Azure Storage Smart Tier Discovery Reader" --scope /subscriptions/$SUB/resourceGroups/$FIXTURE_RG
```

Use subscription scope only when you need `ScopeType=Subscription` audits. Allow up to ten minutes for
propagation; a job started too early fails exactly like step 3.

## 5. Audit (1 min)

Same command as step 3. **Checkpoint** — job `Completed`, nine `Classification` rows:
4 `WouldRemediate`, 1 `AlreadySmart`, 2 `Skipped` (`UnsupportedSku:Standard_LRS`; `UnsupportedKind:BlockBlobStorage,UnsupportedSku:Premium_LRS`),
2 `SkippedNotOptedIn` (`… (absent)` and `… (found 'maybe')`), and
`SUMMARY … "counts":{"discovered":9,"candidates":4,…,"patchesSubmitted":0}`.

## 6. Guards — prove that nothing can be written by accident (5 min)

Each of these must end `Failed` with a `SUMMARY` line and `patchesSubmitted=0`:

| Parameters (in addition to `ScopeType=ResourceGroup ResourceGroupName=$FIXTURE_RG SubscriptionId=$SUB`) | `abortReason` |
|---|---|
| `Mode=Remediate` (no `AccountName`) | `InvalidParameters` |
| `Mode=Remediate AccountName=<the untagged account>` | `TargetNotEligible` |
| `Mode=Remediate AccountName=nosuchaccount0` | `NoAccountMatched` |
| `Mode=Remediate AccountName=<untagged> RequireOptInTag=false` | `InvalidParameters` |
| `Mode=Remediate ScopeType=Subscription AccountName=<zrstag>` (drop `ResourceGroupName`) | `InvalidParameters` |
| `Mode=Remediate AccountName=<zrstag> ExpectedChanges=1` **with only the reader role** | `Forbidden` — one `INTENT`, one PATCH refused with 403, `patchesSubmitted=1`, account still `Hot` |

The last row is the negative half of the RBAC proof; keep its job id.

## 7. Ring of one (10 min, Owner/UAA for the grant)

```bash
scripts/ring-role.sh grant $SUB $FIXTURE_RG $PRINCIPAL          # custom role, assignable only to this RG
az storage account show -n <zrstag> -g $FIXTURE_RG -o json > before.json
az automation runbook start -g $AA_RG --automation-account-name $AA -n Enable-AzStorageSmartTier --parameters \
  Mode=Remediate ScopeType=ResourceGroup ResourceGroupName=$FIXTURE_RG SubscriptionId=$SUB AccountName=<zrstag> ExpectedChanges=1
```

**Checkpoint** — `Completed`; rows `WouldRemediate` (Classification) → `INTENT …` → `Remediated` (Outcome,
`Hot→Smart`, stage `Verify`); `SUMMARY … "remediated":1,"patchesSubmitted":1`. If you get `Forbidden`, RBAC has
not propagated yet — wait and rerun; nothing was changed.

```bash
az storage account show -n <zrstag> -g $FIXTURE_RG -o json > after.json
diff <(jq -S 'del(.accessTier)' before.json) <(jq -S 'del(.accessTier)' after.json) && echo "only accessTier changed"
```

Run the same command again: `AlreadySmart`, `patchesSubmitted=0`, job `Completed` (idempotent).
Optionally repeat for the GZRS/Cool and the hierarchical-namespace accounts.

Live lock case (optional): `az lock create --name smart-tier-fixture-lock --lock-type ReadOnly -g $FIXTURE_RG --resource-name <zrslock> --resource-type Microsoft.Storage/storageAccounts`,
run the ring command with `AccountName=<zrslock>` → job `Failed` **by design**, Outcome `BlockedScopeLock`
(`ReadOnlyLock, ScopeLocked`), `locked=1`, account unchanged. Remove the lock afterwards.

**Revoke immediately after:**

```bash
scripts/ring-role.sh revoke $SUB $FIXTURE_RG $PRINCIPAL
```

## 8. Operate

- Schedule **audits only** (weekly is plenty). Every write is a human-started, named-target job.
- Alert on `counts.unknown > 0` or `counts.errors > 0`; treat `locked` / `deferred` as tickets.
- Forward job streams to Log Analytics if you audit large subscriptions (1 MiB stream limit).
- Re-publish from a new tag with `scripts/publish-runbook.sh` and record the fetch-back hash in your change record.

## 9. Teardown

```bash
az group delete -n $FIXTURE_RG --yes --no-wait        # empty accounts; remove any ReadOnly lock first
az role assignment delete --assignee $PRINCIPAL --role "Azure Storage Smart Tier Discovery Reader" --scope /subscriptions/$SUB/resourceGroups/$FIXTURE_RG
az role definition delete --name "Azure Storage Smart Tier Discovery Reader"
az group delete -n $AA_RG --yes --no-wait             # only if the Automation Account is not shared
```

## What "replicated" looks like

The 2026-08-25 qualification record in [validation.md](validation.md) is exactly this sequence run against the
released bytes (`ba11f641…`): 9/9 audit, seven guards, ring of one with an 84-property diff, GZRS/Cool and
HNS writes, idempotent repeats, the live lock, and a final audit. If your checkpoints match, you have the same
thing.

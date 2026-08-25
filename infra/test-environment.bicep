// Disposable fixture for Azure Blob Storage smart-tier automation tests. Nine EMPTY storage accounts
// covering every classification the runbook makes, plus a CanNotDelete lock on one eligible account
// to reproduce the HTTP 409 ScopeLocked case. Costs ~nothing while empty (no data, no transactions).
@description('Azure region with zone redundancy (ZRS/GZRS) available.')
param location string = resourceGroup().location

@description('3-11 lowercase alphanumerics; account names are <prefix><suffix> and must be globally unique.')
@minLength(3)
@maxLength(11)
param namePrefix string

@description('Opt-in tag name the runbook requires.')
param optInTagName string = 'SmartTierManaged'

@description('Create the CanNotDelete lock on the "zrslock" account (needs Microsoft.Authorization/locks/write, i.e. Owner or User Access Administrator). Without it the 409 ScopeLocked case is harness-only.')
param createLock bool = false

@description('Set true to seed the already-Smart account as Smart (default) or Hot (to test enablement twice).')
param seedSmartAccountAsSmart bool = true

var baseTags = {
  Purpose: 'SmartTierAutomationFixture'
  CreatedBy: 'azure-storage-smart-tier-automation'
  DataClassification: 'NoData'
  Lifecycle: 'CleanupCandidate'
}

// name suffix, sku, kind, accessTier, opt-in tag, hns, locked
var accounts = [
  { suffix: 'zrstag',   sku: 'Standard_ZRS',    kind: 'StorageV2',        tier: 'Hot',   optIn: true,  hns: false, lock: false }
  { suffix: 'zrsnotag', sku: 'Standard_ZRS',    kind: 'StorageV2',        tier: 'Hot',   optIn: false, hns: false, lock: false }
  { suffix: 'zrsbadtag', sku: 'Standard_ZRS',   kind: 'StorageV2',        tier: 'Hot',   optIn: null,  hns: false, lock: false }
  { suffix: 'gzrscool', sku: 'Standard_GZRS',   kind: 'StorageV2',        tier: 'Cool',  optIn: true,  hns: false, lock: false }
  { suffix: 'zrshns',   sku: 'Standard_ZRS',    kind: 'StorageV2',        tier: 'Hot',   optIn: true,  hns: true,  lock: false }
  { suffix: 'zrssmart', sku: 'Standard_ZRS',    kind: 'StorageV2',        tier: seedSmartAccountAsSmart ? 'Smart' : 'Hot', optIn: true, hns: false, lock: false }
  { suffix: 'zrslock',  sku: 'Standard_ZRS',    kind: 'StorageV2',        tier: 'Hot',   optIn: true,  hns: false, lock: true }
  { suffix: 'lrstag',   sku: 'Standard_LRS',    kind: 'StorageV2',        tier: 'Hot',   optIn: true,  hns: false, lock: false }
  { suffix: 'premtag',  sku: 'Premium_LRS',     kind: 'BlockBlobStorage', tier: null,    optIn: true,  hns: false, lock: false }
]

resource storage 'Microsoft.Storage/storageAccounts@2025-08-01' = [for a in accounts: {
  name: toLower('${namePrefix}${a.suffix}')
  location: location
  kind: a.kind
  sku: { name: a.sku }
  tags: union(baseTags, a.optIn == true ? { '${optInTagName}': 'true' } : (a.optIn == null ? { '${optInTagName}': 'maybe' } : {}))
  properties: union({
    minimumTlsVersion: 'TLS1_2'
    allowBlobPublicAccess: false
    allowSharedKeyAccess: false
    supportsHttpsTrafficOnly: true
    publicNetworkAccess: 'Disabled'
    isHnsEnabled: a.hns
  }, a.tier == null ? {} : { accessTier: a.tier })
}]

resource lock 'Microsoft.Authorization/locks@2020-05-01' = [for (a, i) in accounts: if (createLock && a.lock) {
  name: 'smart-tier-fixture-lock'
  scope: storage[i]
  properties: {
    level: 'CanNotDelete'
    notes: 'Fixture: reproduces HTTP 409 ScopeLocked for the smart-tier runbook.'
  }
}]

output accountNames array = [for (a, i) in accounts: storage[i].name]

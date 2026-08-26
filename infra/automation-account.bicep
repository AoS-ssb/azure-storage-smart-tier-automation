// Automation Account + PowerShell 7.4 runtime environment (Az pinned) + the runbook, imported and published
// straight from a tagged release of this repository. Deploy into the resource group that will own the
// Automation Account (not the fixture). RBAC is deliberately not part of this template: grant the reader
// role at the scope you audit and the remediator role only at a ring resource group (see docs/replicate-in-azure.md).
targetScope = 'resourceGroup'

@description('Region for the Automation Account.')
param location string = resourceGroup().location

@minLength(6)
@maxLength(50)
@description('Automation Account name.')
param automationAccountName string

@description('Runtime environment name; the runbook is linked to it.')
param runtimeEnvironmentName string = 'PowerShell74-SmartTier'

@description('Az default-package version for the PowerShell 7.4 runtime. 12.3.0 is the validated version; changing it changes behaviour for every runbook linked to the environment.')
param azPackageVersion string = '12.3.0'

@description('Git ref (tag or commit) of this repository to import the runbook from. Use a release tag so the published bytes are reproducible.')
param sourceRef string = 'v1.1.0'

@description('Raw content base URL of the repository (change only for a fork).')
param sourceBaseUrl string = 'https://raw.githubusercontent.com/AoS-ssb/azure-storage-smart-tier-automation'

@description('Runbook name in the Automation Account.')
param runbookName string = 'Enable-AzStorageSmartTier'

param createdOn string = utcNow('yyyy-MM-dd')

var tags = {
  Purpose: 'SmartTierAutomation'
  CreatedBy: 'azure-storage-smart-tier-automation'
  CreatedOn: createdOn
}

resource automationAccount 'Microsoft.Automation/automationAccounts@2024-10-23' = {
  name: automationAccountName
  location: location
  identity: {
    type: 'SystemAssigned'
  }
  tags: tags
  properties: {
    disableLocalAuth: true
    publicNetworkAccess: true
    sku: {
      name: 'Basic'
    }
  }
}

resource runtimeEnvironment 'Microsoft.Automation/automationAccounts/runtimeEnvironments@2024-10-23' = {
  parent: automationAccount
  name: runtimeEnvironmentName
  location: location
  tags: tags
  properties: {
    description: 'PowerShell 7.4 with Az ${azPackageVersion} for the Blob Storage smart-tier runbook.'
    defaultPackages: {
      Az: azPackageVersion
    }
    runtime: {
      language: 'PowerShell'
      version: '7.4'
    }
  }
}

resource runbook 'Microsoft.Automation/automationAccounts/runbooks@2024-10-23' = {
  parent: automationAccount
  name: runbookName
  location: location
  tags: tags
  properties: {
    runbookType: 'PowerShell'
    runtimeEnvironment: runtimeEnvironment.name
    logProgress: false
    logVerbose: false
    description: 'Audit / enable Blob Storage smart tier on eligible, opted-in storage accounts. Source: ${sourceBaseUrl}/${sourceRef}/src/Enable-AzStorageSmartTier.ps1'
    publishContentLink: {
      uri: '${sourceBaseUrl}/${sourceRef}/src/Enable-AzStorageSmartTier.ps1'
      version: sourceRef
    }
  }
}

output automationAccountPrincipalId string = automationAccount.identity.principalId
output automationAccountId string = automationAccount.id
output runtimeEnvironmentName string = runtimeEnvironment.name
output runbookName string = runbook.name
output importedFrom string = '${sourceBaseUrl}/${sourceRef}/src/Enable-AzStorageSmartTier.ps1'

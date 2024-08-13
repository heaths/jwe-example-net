targetScope = 'subscription'

@minLength(1)
@maxLength(64)
@description('Name of the environment that can be used as part of naming resource convention')
param environmentName string

@minLength(1)
@description('Primary location for all resources')
param location string

@description('User principal ID')
param principalId string

@description('Override the name of the resource group')
param resourceGroupName string = 'rg-${environmentName}'

@description('The vault name. The default will be generated from the resource group ID.')
param vaultName string = ''

@description('How long until the resource group is cleaned up by automated processes.')
param deleteAfterTime string = dateTimeAdd(utcNow('o'), 'P1D')

// Tags that should be applied to all resources.
//
// Note that 'azd-service-name' tags should be applied separately to service host resources.
// Example usage:
//   tags: union(tags, { 'azd-service-name': <service name in azure.yaml> })
var tags = {
  'azd-env-name': environmentName
  DeleteAfter: deleteAfterTime
}

resource rg 'Microsoft.Resources/resourceGroups@2022-09-01' = {
  name: 'rg-${environmentName}'
  location: location
  tags: tags
}

module resources 'resources.bicep' = {
  name: 'resources'
  scope: rg
  params: {
    environmentName: environmentName
    location: location
    principalId: principalId
    vaultName: vaultName
  }
}

output AZURE_RESOURCE_GROUP string = resourceGroupName
output AZURE_PRINCIPAL_ID string = resources.outputs.AZURE_PRINCIPAL_ID
output AZURE_KEYVAULT_NAME string = resources.outputs.AZURE_KEYVAULT_NAME
output AZURE_KEYVAULT_URL string = resources.outputs.AZURE_KEYVAULT_URL
output AZURE_KEY_ID string = resources.outputs.AZURE_KEY_ID

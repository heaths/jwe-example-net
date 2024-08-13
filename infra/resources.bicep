@minLength(1)
@maxLength(64)
@description('Name of the the environment which is used to generate a short unique hash used in all resources.')
param environmentName string

@minLength(1)
@description('Primary location for all resources')
param location string = resourceGroup().location

@description('User principal ID')
param principalId string

@description('The vault name; default is a unique string based on the resource group ID')
param vaultName string = ''

var vaultNameOverride = empty(vaultName) ? 't${uniqueString(resourceGroup().id, environmentName)}' : vaultName
var tenantId = subscription().tenantId

resource vault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: vaultNameOverride
  location: location
  properties: {
    sku: {
      name: 'standard'
      family: 'A'
    }
    tenantId: tenantId
    enableRbacAuthorization: true
    softDeleteRetentionInDays: 7
  }

}

resource kek 'Microsoft.KeyVault/vaults/keys@2023-07-01' = {
  parent: vault
  name: 'kek'
  properties: {
    kty: 'RSA'
    keySize: 4096
  }
}

var cryptoUserDefinitionId = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '12338af0-0e69-4776-bea7-57ae8d297424')

resource rbac 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(resourceGroup().id, environmentName, principalId, cryptoUserDefinitionId)
  properties: {
    principalId: principalId
    roleDefinitionId: cryptoUserDefinitionId
  }
}

output AZURE_PRINCIPAL_ID string = principalId
output AZURE_KEYVAULT_NAME string = vault.name
output AZURE_KEYVAULT_URL string = vault.properties.vaultUri
output AZURE_KEY_ID string = kek.properties.keyUriWithVersion

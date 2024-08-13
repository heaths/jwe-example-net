# JWE Example using Key Vault

This is a simple example using Key Vault (or Managed HSM) to encrypt a content encryption key (CEK) used to
encrypt plaintext and generate a JWE to store all information necessary to decrypt it using Key Vault (or Managed HSM).

## Prerequisites

* [.NET 8.0](https://dot.net)
* Key Vault (or Managed HSM) and RSA key
* (Optional) [Azure Developer CLI][azd]

### Provisioning

You can easily provision a Key Vault with an RSA 4096 key to use with this example using [azd]:

```bash
azd up
. .azure/dev/.env # path may vary if you provision a different environment
```

## Running the example

Assuming your key ID is stored in the `$AZURE_KEY_ID` environment variable, which it would be if you followed the
provisioning instructions above:

```bash
JWE=$(dotnet run -- encrypt 'This is plaintext' --id $AZURE_KEY_ID)
echo $JWE
dotnet run -- decrypt $JWE
```

[azd]: https://aka.ms/azd

using System.CommandLine;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Azure.Identity;
using Azure.Security.KeyVault.Keys.Cryptography;

// Encrypt plaintext using a Key Vault (or Managed HSM) key URI. This should always specify a version URI in case the key is later rotated.
// This simple example is hardcoded to use A256GCM for encrypting plaintext, and RSA-OAEP-256 for encrypting the CEK.
async Task EncryptAsync(string plaintext, Uri keyId)
{
    if (plaintext is null || plaintext == "-")
    {
        plaintext = await Console.In.ReadToEndAsync();
    }

    // Encode our plaintext.
    byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);

    // Create our content encryption key (CEK).
    Aes cek = Aes.Create();
    cek.KeySize = 256;

    // Encrypt our CEK.
    byte[] encryptedCek = await WrapAsync(keyId, cek.Key);

    // Create our nonce.
    byte[] nonce = new byte[AesGcm.NonceByteSizes.MaxSize];
    RandomNumberGenerator.Fill(nonce.AsSpan());

    // Allocate our tag.
    byte[] tag = new byte[AesGcm.TagByteSizes.MaxSize];

    // Allocate our ciphertext which, for AES-GCM, is the same length as our plaintext.
    byte[] ciphertextBytes = new byte[plaintextBytes.Length];

    // Encrypt our plaintext.
    using AesGcm contentEncryptor = new(cek.Key, tag.Length);
    contentEncryptor.Encrypt(nonce, plaintextBytes, ciphertextBytes, tag);

    // Construct our JWE header.
    string header = $$"""{"alg":"RSA-OAEP-256","enc":"A256GCM","kid":"{{keyId}}","typ":"JWE"}""";
    string encodedHeader = Base64UrlEncode(Encoding.UTF8.GetBytes(header));

    // Encode the encrypted CEK.
    string encodedEncryptedCek = Base64UrlEncode(encryptedCek);

    // Encode the nonce.
    string encodedNonce = Base64UrlEncode(nonce);

    // Encode the ciphertext.
    string encodedCiphertext = Base64UrlEncode(ciphertextBytes);

    // Encode the authentication tag.
    string encodedTag = Base64UrlEncode(tag);

    Console.WriteLine($"{encodedHeader}.{encodedEncryptedCek}.{encodedNonce}.{encodedCiphertext}.{encodedTag}");
}

// Decrypt the JWE, which contains the original key URI as well as other information needed to decrypt the information.
async Task DecryptAsync(string jwe)
{
    if (jwe is null || jwe == "-")
    {
        jwe = await Console.In.ReadToEndAsync();
    }

    string[] segments = jwe.Split('.');
    if (segments.Length != 5)
    {
        throw new Exception($"Expected 5 segments in the JWE but found {segments.Length}");
    }

    // Assert the header is supported and get our kid.
    string header = Encoding.UTF8.GetString(Base64UrlDecode(segments[0]));
    using JsonDocument doc = JsonDocument.Parse(header);

    string? alg = doc.RootElement.GetProperty("alg").GetString();
    if (alg != "RSA-OAEP-256")
    {
        throw new Exception($"This example supports only the RSA-OAEP-256 algorithm, not {alg}");
    }

    string? enc = doc.RootElement.GetProperty("enc").GetString();
    if (enc != "A256GCM")
    {
        throw new Exception($"This example supports only the A256GCM encoding, not {enc}");
    }

    string? kid = doc.RootElement.GetProperty("kid").GetString() ?? throw new Exception("Key ID not found");

    // Decode our encrypted CEK and nonce.
    byte[] encryptedCek = Base64UrlDecode(segments[1]);
    byte[] nonce = Base64UrlDecode(segments[2]);

    // Decode the ciphertext.
    byte[] ciphertextBytes = Base64UrlDecode(segments[3]);

    // Allocate our plaintext, which is the same length as the ciphertext.
    byte[] plaintextBytes = new byte[ciphertextBytes.Length];

    // Decode the authentication tag.
    byte[] tag = Base64UrlDecode(segments[4]);

    // Unwrap our CEK.
    byte[] cek = await UnwrapAsync(new Uri(kid), encryptedCek);

    // Decrypt our ciphertext.
    using AesGcm contentDecryptor = new(cek, tag.Length);
    contentDecryptor.Decrypt(nonce, ciphertextBytes, tag, plaintextBytes);

    string plaintext = Encoding.UTF8.GetString(plaintextBytes);
    Console.WriteLine(plaintext);
}

// Wrap the content encryption key (CEK) using Key Vault (or Managed HSM). Hardcoded to RSA-OAEP-256 for this simple example.
async Task<byte[]> WrapAsync(Uri keyId, byte[] cek)
{
    CryptographyClient client = new(keyId, new DefaultAzureCredential());
    WrapResult result = await client.WrapKeyAsync(KeyWrapAlgorithm.RsaOaep256, cek);

    return result.EncryptedKey;
}

// Unwrap the CEK using Key Vault (or Managed HSM). Hardcoded to RSA-OAEP-256 for this simple example.
async Task<byte[]> UnwrapAsync(Uri keyId, byte[] encryptedCek)
{
    CryptographyClient client = new(keyId, new DefaultAzureCredential());
    UnwrapResult result = await client.UnwrapKeyAsync(KeyWrapAlgorithm.RsaOaep256, encryptedCek);

    return result.Key;
}

string Base64UrlEncode(byte[] data) => Convert.ToBase64String(data).Replace("+", "-").Replace("/", "_").TrimEnd('=');
byte[] Base64UrlDecode(string data) => Convert.FromBase64String(data.Replace("_", "/").Replace("-", "+") + (data.Length % 4) switch
{
    2 => "==",
    3 => "=",
    _ => "",
});

// Set up the CLI.
RootCommand root = new("Example using Key Vault to encrypt to or decrypt from a JWE.");

// Encryption requires a Key Vault key ID (URI including version) and plaintext.
Argument<string> plaintext = new("plaintext", """The plaintext to encrypt. If "-" or absent, content is read from stdin.""")
{
    Arity = ArgumentArity.ZeroOrOne,
};
Option<Uri> keyId = new("--id", "Key Vault key ID.")
{
    IsRequired = true,
};
Command encryptCommand = new("encrypt", "Encrypt plaintext to JWE.")
{
    plaintext,
    keyId,
};
encryptCommand.SetHandler(EncryptAsync, plaintext, keyId);
root.AddCommand(encryptCommand);

// Decryption requires the JWE, which has the key ID, encrypted content encryption key (CEK), and ciphertext.
Argument<string> jwe = new("jwe", """The JWE to decrypt. If "-" or absent, content is read from stdin.""")
{
    Arity = ArgumentArity.ZeroOrOne,
};
Command decryptCommand = new("decrypt", "Decrypt JWE.")
{
    jwe,
};
decryptCommand.SetHandler(DecryptAsync, jwe);
root.AddCommand(decryptCommand);

// Run the CLI.
await root.InvokeAsync(args);

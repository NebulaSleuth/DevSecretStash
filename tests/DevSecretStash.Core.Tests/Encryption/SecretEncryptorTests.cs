using System.Security.Cryptography;
using DevSecretStash.Core.Encryption;
using FluentAssertions;

namespace DevSecretStash.Core.Tests.Encryption;

public class SecretEncryptorTests
{
    private static byte[] GenerateKey() => RandomNumberGenerator.GetBytes(EncryptionConstants.KeySizeBytes);

    [Fact]
    public void RoundTrip_ProducesOriginalContent()
    {
        var key = GenerateKey();
        var original = """{"ConnectionStrings:Default": "Server=localhost", "ApiKey": "abc123"}""";

        var encrypted = SecretEncryptor.Encrypt(original, key);
        var decrypted = SecretEncryptor.Decrypt(encrypted, key);

        decrypted.Should().Be(original);
    }

    [Fact]
    public void Encrypt_SamePlaintext_ProducesDifferentCiphertext()
    {
        var key = GenerateKey();
        var plaintext = "test data";

        var enc1 = SecretEncryptor.Encrypt(plaintext, key);
        var enc2 = SecretEncryptor.Encrypt(plaintext, key);

        // Different nonces should produce different ciphertext
        enc1.Nonce.Should().NotEqual(enc2.Nonce);
        enc1.Ciphertext.Should().NotEqual(enc2.Ciphertext);
    }

    [Fact]
    public void Decrypt_WrongKey_Throws()
    {
        var key1 = GenerateKey();
        var key2 = GenerateKey();
        var encrypted = SecretEncryptor.Encrypt("secret", key1);

        var act = () => SecretEncryptor.Decrypt(encrypted, key2);
        act.Should().Throw<CryptographicException>();
    }

    [Fact]
    public void Decrypt_TamperedCiphertext_Throws()
    {
        var key = GenerateKey();
        var encrypted = SecretEncryptor.Encrypt("secret", key);

        // Tamper with ciphertext
        encrypted.Ciphertext[0] ^= 0xFF;

        var act = () => SecretEncryptor.Decrypt(encrypted, key);
        act.Should().Throw<CryptographicException>();
    }

    [Fact]
    public void RoundTrip_EmptyString()
    {
        var key = GenerateKey();
        var encrypted = SecretEncryptor.Encrypt("", key);
        var decrypted = SecretEncryptor.Decrypt(encrypted, key);

        decrypted.Should().BeEmpty();
    }

    [Fact]
    public void RoundTrip_ViaBase64Combined()
    {
        var key = GenerateKey();
        var original = """{"key": "value"}""";

        var encrypted = SecretEncryptor.Encrypt(original, key);
        var base64 = encrypted.ToBase64Combined();
        var restored = EncryptedPayload.FromBase64Combined(base64);
        var decrypted = SecretEncryptor.Decrypt(restored, key);

        decrypted.Should().Be(original);
    }

    [Fact]
    public void Encrypt_InvalidKeyLength_Throws()
    {
        var shortKey = new byte[16];
        var act = () => SecretEncryptor.Encrypt("test", shortKey);

        act.Should().Throw<ArgumentException>();
    }
}

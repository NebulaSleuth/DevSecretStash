using System.Security.Cryptography;
using System.Text;

namespace DevSecrets.Core.Encryption;

public static class SecretEncryptor
{
    public static EncryptedPayload Encrypt(string plaintext, byte[] masterKey)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        if (masterKey.Length != EncryptionConstants.KeySizeBytes)
            throw new ArgumentException($"Master key must be {EncryptionConstants.KeySizeBytes} bytes.", nameof(masterKey));

        var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
        var nonce = RandomNumberGenerator.GetBytes(EncryptionConstants.NonceSizeBytes);
        var ciphertext = new byte[plaintextBytes.Length];
        var tag = new byte[EncryptionConstants.TagSizeBytes];

        using var aes = new AesGcm(masterKey, EncryptionConstants.TagSizeBytes);
        aes.Encrypt(nonce, plaintextBytes, ciphertext, tag);

        return new EncryptedPayload(ciphertext, nonce, tag);
    }

    public static string Decrypt(EncryptedPayload payload, byte[] masterKey)
    {
        ArgumentNullException.ThrowIfNull(payload);
        if (masterKey.Length != EncryptionConstants.KeySizeBytes)
            throw new ArgumentException($"Master key must be {EncryptionConstants.KeySizeBytes} bytes.", nameof(masterKey));

        var plaintext = new byte[payload.Ciphertext.Length];

        using var aes = new AesGcm(masterKey, EncryptionConstants.TagSizeBytes);
        aes.Decrypt(payload.Nonce, payload.Ciphertext, payload.Tag, plaintext);

        return Encoding.UTF8.GetString(plaintext);
    }
}

public record EncryptedPayload(byte[] Ciphertext, byte[] Nonce, byte[] Tag)
{
    public string ToBase64Combined()
    {
        // Format: [nonce][tag][ciphertext]
        var combined = new byte[Nonce.Length + Tag.Length + Ciphertext.Length];
        Nonce.CopyTo(combined, 0);
        Tag.CopyTo(combined, Nonce.Length);
        Ciphertext.CopyTo(combined, Nonce.Length + Tag.Length);
        return Convert.ToBase64String(combined);
    }

    public static EncryptedPayload FromBase64Combined(string base64)
    {
        var combined = Convert.FromBase64String(base64);
        var nonce = combined[..EncryptionConstants.NonceSizeBytes];
        var tag = combined[EncryptionConstants.NonceSizeBytes..(EncryptionConstants.NonceSizeBytes + EncryptionConstants.TagSizeBytes)];
        var ciphertext = combined[(EncryptionConstants.NonceSizeBytes + EncryptionConstants.TagSizeBytes)..];
        return new EncryptedPayload(ciphertext, nonce, tag);
    }
}

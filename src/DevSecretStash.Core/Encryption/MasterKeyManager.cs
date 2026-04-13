using System.Security.Cryptography;
using DevSecretStash.Core.Models;

namespace DevSecretStash.Core.Encryption;

public static class MasterKeyManager
{
    /// <summary>
    /// Generates a new random master key and wraps it with a KEK derived from the password.
    /// Used during registration.
    /// </summary>
    public static EncryptedMasterKeyBundle GenerateAndWrap(string password)
    {
        var masterKey = RandomNumberGenerator.GetBytes(EncryptionConstants.KeySizeBytes);
        try
        {
            return Wrap(masterKey, password);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(masterKey);
        }
    }

    /// <summary>
    /// Wraps an existing master key with a new password-derived KEK.
    /// Used during password change.
    /// </summary>
    public static EncryptedMasterKeyBundle Wrap(byte[] masterKey, string password)
    {
        var salt = Argon2KeyDeriver.GenerateSalt();
        var argon2Params = Argon2Params.Default;
        var kek = Argon2KeyDeriver.DeriveKey(password, salt, argon2Params);

        try
        {
            var nonce = RandomNumberGenerator.GetBytes(EncryptionConstants.NonceSizeBytes);
            var ciphertext = new byte[masterKey.Length];
            var tag = new byte[EncryptionConstants.TagSizeBytes];

            using var aes = new AesGcm(kek, EncryptionConstants.TagSizeBytes);
            aes.Encrypt(nonce, masterKey, ciphertext, tag);

            return new EncryptedMasterKeyBundle(
                EncryptedKey: Convert.ToBase64String(ciphertext),
                Salt: Convert.ToBase64String(salt),
                Nonce: Convert.ToBase64String(nonce),
                Tag: Convert.ToBase64String(tag),
                Argon2Params: argon2Params
            );
        }
        finally
        {
            CryptographicOperations.ZeroMemory(kek);
        }
    }

    /// <summary>
    /// Unwraps the master key using the password-derived KEK.
    /// Used during login.
    /// </summary>
    public static byte[] Unwrap(string password, EncryptedMasterKeyBundle bundle)
    {
        var salt = Convert.FromBase64String(bundle.Salt);
        var kek = Argon2KeyDeriver.DeriveKey(password, salt, bundle.Argon2Params);

        try
        {
            var nonce = Convert.FromBase64String(bundle.Nonce);
            var ciphertext = Convert.FromBase64String(bundle.EncryptedKey);
            var tag = Convert.FromBase64String(bundle.Tag);
            var masterKey = new byte[ciphertext.Length];

            using var aes = new AesGcm(kek, EncryptionConstants.TagSizeBytes);
            aes.Decrypt(nonce, ciphertext, tag, masterKey);

            return masterKey;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(kek);
        }
    }

    /// <summary>
    /// Re-wraps the master key with a new password. Used for password change.
    /// Client unwraps with old password, then re-wraps with new password.
    /// </summary>
    public static EncryptedMasterKeyBundle Rewrap(
        string oldPassword,
        string newPassword,
        EncryptedMasterKeyBundle currentBundle)
    {
        var masterKey = Unwrap(oldPassword, currentBundle);
        try
        {
            return Wrap(masterKey, newPassword);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(masterKey);
        }
    }
}

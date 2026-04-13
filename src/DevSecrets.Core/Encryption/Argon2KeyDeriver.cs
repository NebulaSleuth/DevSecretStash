using System.Security.Cryptography;
using Konscious.Security.Cryptography;

namespace DevSecrets.Core.Encryption;

public static class Argon2KeyDeriver
{
    public static byte[] DeriveKey(string password, byte[] salt, Argon2Params? argon2Params = null)
    {
        var p = argon2Params ?? Argon2Params.Default;
        var passwordBytes = System.Text.Encoding.UTF8.GetBytes(password);

        using var argon2 = new Argon2id(passwordBytes);
        argon2.Salt = salt;
        argon2.MemorySize = p.MemoryKB;
        argon2.Iterations = p.Iterations;
        argon2.DegreeOfParallelism = p.Parallelism;

        return argon2.GetBytes(EncryptionConstants.KeySizeBytes);
    }

    public static byte[] GenerateSalt()
    {
        return RandomNumberGenerator.GetBytes(EncryptionConstants.SaltSizeBytes);
    }
}

public record Argon2Params(int MemoryKB, int Iterations, int Parallelism)
{
    public static readonly Argon2Params Default = new(
        EncryptionConstants.Argon2MemoryKB,
        EncryptionConstants.Argon2Iterations,
        EncryptionConstants.Argon2Parallelism
    );
}

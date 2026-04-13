using System.Security.Cryptography;
using Konscious.Security.Cryptography;

namespace DevSecrets.Api.Services;

public static class PasswordHasher
{
    private const int HashSize = 32;
    private const int SaltSize = 16;
    private const int MemoryKB = 65536;
    private const int Iterations = 3;
    private const int Parallelism = 1;

    public static (string hash, string salt) Hash(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var hash = ComputeHash(password, salt);
        return (Convert.ToBase64String(hash), Convert.ToBase64String(salt));
    }

    public static bool Verify(string password, string hashBase64, string saltBase64)
    {
        var salt = Convert.FromBase64String(saltBase64);
        var expectedHash = Convert.FromBase64String(hashBase64);
        var actualHash = ComputeHash(password, salt);
        return CryptographicOperations.FixedTimeEquals(expectedHash, actualHash);
    }

    private static byte[] ComputeHash(string password, byte[] salt)
    {
        var passwordBytes = System.Text.Encoding.UTF8.GetBytes(password);
        using var argon2 = new Argon2id(passwordBytes);
        argon2.Salt = salt;
        argon2.MemorySize = MemoryKB;
        argon2.Iterations = Iterations;
        argon2.DegreeOfParallelism = Parallelism;
        return argon2.GetBytes(HashSize);
    }
}

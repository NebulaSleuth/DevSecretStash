namespace DevSecrets.Core.Encryption;

public static class EncryptionConstants
{
    /// <summary>AES-256-GCM key size in bytes.</summary>
    public const int KeySizeBytes = 32;

    /// <summary>AES-GCM nonce size in bytes (96 bits per NIST recommendation).</summary>
    public const int NonceSizeBytes = 12;

    /// <summary>AES-GCM authentication tag size in bytes.</summary>
    public const int TagSizeBytes = 16;

    /// <summary>Argon2id salt size in bytes.</summary>
    public const int SaltSizeBytes = 16;

    /// <summary>Argon2id memory cost in KB (64 MB).</summary>
    public const int Argon2MemoryKB = 65536;

    /// <summary>Argon2id iteration count.</summary>
    public const int Argon2Iterations = 3;

    /// <summary>Argon2id degree of parallelism.</summary>
    public const int Argon2Parallelism = 1;
}

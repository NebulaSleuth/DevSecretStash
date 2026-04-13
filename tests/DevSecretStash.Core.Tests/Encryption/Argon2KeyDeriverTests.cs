using DevSecretStash.Core.Encryption;
using FluentAssertions;

namespace DevSecretStash.Core.Tests.Encryption;

public class Argon2KeyDeriverTests
{
    // Use fast params for tests to avoid long test times
    private static readonly Argon2Params FastParams = new(MemoryKB: 1024, Iterations: 1, Parallelism: 1);

    [Fact]
    public void DeriveKey_SameInputs_ProducesSameKey()
    {
        var salt = Argon2KeyDeriver.GenerateSalt();
        var key1 = Argon2KeyDeriver.DeriveKey("password123", salt, FastParams);
        var key2 = Argon2KeyDeriver.DeriveKey("password123", salt, FastParams);

        key1.Should().Equal(key2);
    }

    [Fact]
    public void DeriveKey_DifferentPasswords_ProducesDifferentKeys()
    {
        var salt = Argon2KeyDeriver.GenerateSalt();
        var key1 = Argon2KeyDeriver.DeriveKey("password123", salt, FastParams);
        var key2 = Argon2KeyDeriver.DeriveKey("password456", salt, FastParams);

        key1.Should().NotEqual(key2);
    }

    [Fact]
    public void DeriveKey_DifferentSalts_ProducesDifferentKeys()
    {
        var salt1 = Argon2KeyDeriver.GenerateSalt();
        var salt2 = Argon2KeyDeriver.GenerateSalt();
        var key1 = Argon2KeyDeriver.DeriveKey("password123", salt1, FastParams);
        var key2 = Argon2KeyDeriver.DeriveKey("password123", salt2, FastParams);

        key1.Should().NotEqual(key2);
    }

    [Fact]
    public void DeriveKey_ProducesCorrectKeyLength()
    {
        var salt = Argon2KeyDeriver.GenerateSalt();
        var key = Argon2KeyDeriver.DeriveKey("password123", salt, FastParams);

        key.Length.Should().Be(EncryptionConstants.KeySizeBytes);
    }

    [Fact]
    public void GenerateSalt_ProducesCorrectLength()
    {
        var salt = Argon2KeyDeriver.GenerateSalt();
        salt.Length.Should().Be(EncryptionConstants.SaltSizeBytes);
    }

    [Fact]
    public void GenerateSalt_ProducesUniqueSalts()
    {
        var salt1 = Argon2KeyDeriver.GenerateSalt();
        var salt2 = Argon2KeyDeriver.GenerateSalt();

        salt1.Should().NotEqual(salt2);
    }
}

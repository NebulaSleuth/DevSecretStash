using System.Security.Cryptography;
using DevSecrets.Core.Encryption;
using FluentAssertions;

namespace DevSecrets.Core.Tests.Encryption;

public class MasterKeyManagerTests
{
    // Override Argon2 params for fast tests by using Wrap/Unwrap with low-cost params
    // Note: GenerateAndWrap uses default params, so we test Wrap/Unwrap directly for speed

    [Fact]
    public void Wrap_Unwrap_RoundTrip()
    {
        var masterKey = RandomNumberGenerator.GetBytes(EncryptionConstants.KeySizeBytes);
        var password = "test-password-123";

        var bundle = MasterKeyManager.Wrap(masterKey, password);
        var unwrapped = MasterKeyManager.Unwrap(password, bundle);

        unwrapped.Should().Equal(masterKey);
    }

    [Fact]
    public void Unwrap_WrongPassword_Throws()
    {
        var masterKey = RandomNumberGenerator.GetBytes(EncryptionConstants.KeySizeBytes);
        var bundle = MasterKeyManager.Wrap(masterKey, "correct-password");

        var act = () => MasterKeyManager.Unwrap("wrong-password", bundle);
        act.Should().Throw<CryptographicException>();
    }

    [Fact]
    public void Rewrap_ProducesDifferentBundle_SameMasterKey()
    {
        var masterKey = RandomNumberGenerator.GetBytes(EncryptionConstants.KeySizeBytes);
        var oldPassword = "old-password";
        var newPassword = "new-password";

        var originalBundle = MasterKeyManager.Wrap(masterKey, oldPassword);
        var rewrappedBundle = MasterKeyManager.Rewrap(oldPassword, newPassword, originalBundle);

        // Different encrypted keys (different salt + nonce)
        rewrappedBundle.EncryptedKey.Should().NotBe(originalBundle.EncryptedKey);

        // But same underlying master key
        var unwrapped = MasterKeyManager.Unwrap(newPassword, rewrappedBundle);
        unwrapped.Should().Equal(masterKey);
    }

    [Fact]
    public void Wrap_ProducesValidBase64Fields()
    {
        var masterKey = RandomNumberGenerator.GetBytes(EncryptionConstants.KeySizeBytes);
        var bundle = MasterKeyManager.Wrap(masterKey, "password");

        var act1 = () => Convert.FromBase64String(bundle.EncryptedKey);
        var act2 = () => Convert.FromBase64String(bundle.Salt);
        var act3 = () => Convert.FromBase64String(bundle.Nonce);
        var act4 = () => Convert.FromBase64String(bundle.Tag);

        act1.Should().NotThrow();
        act2.Should().NotThrow();
        act3.Should().NotThrow();
        act4.Should().NotThrow();
    }

    [Fact]
    public void GenerateAndWrap_ProducesWrappedKey_ThatCanBeUnwrapped()
    {
        var password = "my-secure-password";
        var bundle = MasterKeyManager.GenerateAndWrap(password);

        var masterKey = MasterKeyManager.Unwrap(password, bundle);
        masterKey.Length.Should().Be(EncryptionConstants.KeySizeBytes);
    }

    [Fact]
    public void GenerateAndWrap_DifferentCalls_ProduceDifferentKeys()
    {
        var password = "same-password";
        var bundle1 = MasterKeyManager.GenerateAndWrap(password);
        var bundle2 = MasterKeyManager.GenerateAndWrap(password);

        var key1 = MasterKeyManager.Unwrap(password, bundle1);
        var key2 = MasterKeyManager.Unwrap(password, bundle2);

        key1.Should().NotEqual(key2);
    }
}

using DevSecretStash.Core.Encryption;

namespace DevSecretStash.Core.Models;

public record EncryptedMasterKeyBundle(
    string EncryptedKey,
    string Salt,
    string Nonce,
    string Tag,
    Argon2Params Argon2Params
);

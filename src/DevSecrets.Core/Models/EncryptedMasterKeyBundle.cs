using DevSecrets.Core.Encryption;

namespace DevSecrets.Core.Models;

public record EncryptedMasterKeyBundle(
    string EncryptedKey,
    string Salt,
    string Nonce,
    string Tag,
    Argon2Params Argon2Params
);

using DevSecretStash.Core.Encryption;

namespace DevSecretStash.Core.Dtos;

public record RegisterRequest(
    string Email,
    string Password,
    string EncryptedMasterKey,
    string MasterKeySalt,
    string MasterKeyNonce,
    string MasterKeyTag,
    Argon2Params Argon2Params
);

public record LoginRequest(string Email, string Password);

public record AuthResponse(
    string Token,
    string RefreshToken,
    DateTime ExpiresAt,
    string? EncryptedMasterKey = null,
    string? MasterKeySalt = null,
    string? MasterKeyNonce = null,
    string? MasterKeyTag = null,
    Argon2Params? Argon2Params = null
);

public record RefreshRequest(string RefreshToken);

public record ChangePasswordRequest(
    string CurrentPassword,
    string NewPassword,
    string NewEncryptedMasterKey,
    string NewMasterKeySalt,
    string NewMasterKeyNonce,
    string NewMasterKeyTag,
    Argon2Params NewArgon2Params
);

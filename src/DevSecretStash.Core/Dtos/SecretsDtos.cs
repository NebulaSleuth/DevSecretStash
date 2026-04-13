namespace DevSecretStash.Core.Dtos;

public record SecretCollectionSummary(
    string UserSecretsId,
    DateTime LastModified,
    int Version
);

public record PushSecretsRequest(
    string EncryptedData,
    int? ExpectedVersion = null
);

public record PullSecretsResponse(
    string UserSecretsId,
    string EncryptedData,
    DateTime LastModified,
    int Version
);

public record PushSecretsResponse(
    string UserSecretsId,
    DateTime LastModified,
    int Version
);

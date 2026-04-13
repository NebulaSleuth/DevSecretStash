using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using DevSecrets.Api.Tests.Helpers;
using DevSecrets.Core.Dtos;
using DevSecrets.Core.Encryption;
using DevSecrets.Core.Models;
using FluentAssertions;

namespace DevSecrets.Api.Tests;

public class SecretsEndpointTests : IClassFixture<TestWebApplicationFactory>
{
    private readonly TestWebApplicationFactory _factory;
    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true };

    public SecretsEndpointTests(TestWebApplicationFactory factory)
    {
        _factory = factory;
    }

    private async Task<(HttpClient client, byte[] masterKey)> CreateAuthenticatedClient(string email)
    {
        var client = _factory.CreateClient();
        var password = "TestPassword123!";
        var auth = await AuthHelper.RegisterAndGetToken(client, email, password);

        var loginResp = await client.PostAsJsonAsync("/api/auth/login", new LoginRequest(email, password));
        var loginAuth = (await loginResp.Content.ReadFromJsonAsync<AuthResponse>(JsonOptions))!;

        var bundle = new EncryptedMasterKeyBundle(
            loginAuth.EncryptedMasterKey!, loginAuth.MasterKeySalt!,
            loginAuth.MasterKeyNonce!, loginAuth.MasterKeyTag!, loginAuth.Argon2Params!);
        var masterKey = MasterKeyManager.Unwrap(password, bundle);

        AuthHelper.SetAuth(client, auth.Token);
        return (client, masterKey);
    }

    [Fact]
    public async Task ListCollections_NoAuth_Returns401()
    {
        var client = _factory.CreateClient();
        var response = await client.GetAsync("/api/secrets");
        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task ListCollections_Empty_ReturnsEmptyList()
    {
        var (client, _) = await CreateAuthenticatedClient("list-empty@example.com");

        var response = await client.GetAsync("/api/secrets");
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var collections = await response.Content.ReadFromJsonAsync<List<SecretCollectionSummary>>(JsonOptions);
        collections.Should().NotBeNull();
        collections.Should().BeEmpty();
    }

    [Fact]
    public async Task Push_NewCollection_CreatesWithVersion1()
    {
        var (client, masterKey) = await CreateAuthenticatedClient("push-new@example.com");

        var secretsJson = """{"ConnectionString": "Server=localhost", "ApiKey": "secret123"}""";
        var encrypted = SecretEncryptor.Encrypt(secretsJson, masterKey);

        var request = new PushSecretsRequest(EncryptedData: encrypted.ToBase64Combined());
        var response = await client.PutAsJsonAsync("/api/secrets/test-secrets-id-1", request);
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var result = await response.Content.ReadFromJsonAsync<PushSecretsResponse>(JsonOptions);
        result.Should().NotBeNull();
        result!.UserSecretsId.Should().Be("test-secrets-id-1");
        result.Version.Should().Be(1);
    }

    [Fact]
    public async Task Push_ExistingCollection_IncrementsVersion()
    {
        var (client, masterKey) = await CreateAuthenticatedClient("push-update@example.com");

        var encrypted1 = SecretEncryptor.Encrypt("{}", masterKey);
        await client.PutAsJsonAsync("/api/secrets/version-test", new PushSecretsRequest(encrypted1.ToBase64Combined()));

        var encrypted2 = SecretEncryptor.Encrypt("""{"key": "updated"}""", masterKey);
        var response = await client.PutAsJsonAsync("/api/secrets/version-test", new PushSecretsRequest(encrypted2.ToBase64Combined()));

        var result = (await response.Content.ReadFromJsonAsync<PushSecretsResponse>(JsonOptions))!;
        result.Version.Should().Be(2);
    }

    [Fact]
    public async Task Push_VersionConflict_Returns409()
    {
        var (client, masterKey) = await CreateAuthenticatedClient("push-conflict@example.com");

        var encrypted = SecretEncryptor.Encrypt("{}", masterKey);
        await client.PutAsJsonAsync("/api/secrets/conflict-test", new PushSecretsRequest(encrypted.ToBase64Combined()));

        // Push with wrong expected version
        var request = new PushSecretsRequest(encrypted.ToBase64Combined(), ExpectedVersion: 99);
        var response = await client.PutAsJsonAsync("/api/secrets/conflict-test", request);
        response.StatusCode.Should().Be(HttpStatusCode.Conflict);
    }

    [Fact]
    public async Task Pull_ExistingCollection_ReturnsEncryptedData()
    {
        var (client, masterKey) = await CreateAuthenticatedClient("pull-test@example.com");

        var originalJson = """{"DbPassword": "super-secret", "ApiKey": "abc123"}""";
        var encrypted = SecretEncryptor.Encrypt(originalJson, masterKey);
        await client.PutAsJsonAsync("/api/secrets/pull-test-id", new PushSecretsRequest(encrypted.ToBase64Combined()));

        var response = await client.GetAsync("/api/secrets/pull-test-id");
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var result = (await response.Content.ReadFromJsonAsync<PullSecretsResponse>(JsonOptions))!;
        result.UserSecretsId.Should().Be("pull-test-id");
        result.Version.Should().Be(1);

        // Decrypt and verify
        var payload = EncryptedPayload.FromBase64Combined(result.EncryptedData);
        var decrypted = SecretEncryptor.Decrypt(payload, masterKey);
        decrypted.Should().Be(originalJson);
    }

    [Fact]
    public async Task Pull_NonexistentCollection_Returns404()
    {
        var (client, _) = await CreateAuthenticatedClient("pull-404@example.com");

        var response = await client.GetAsync("/api/secrets/nonexistent-id");
        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task Delete_ExistingCollection_Returns204()
    {
        var (client, masterKey) = await CreateAuthenticatedClient("delete-test@example.com");

        var encrypted = SecretEncryptor.Encrypt("{}", masterKey);
        await client.PutAsJsonAsync("/api/secrets/delete-me", new PushSecretsRequest(encrypted.ToBase64Combined()));

        var response = await client.DeleteAsync("/api/secrets/delete-me");
        response.StatusCode.Should().Be(HttpStatusCode.NoContent);

        // Verify it's gone
        var getResponse = await client.GetAsync("/api/secrets/delete-me");
        getResponse.StatusCode.Should().Be(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task Delete_NonexistentCollection_Returns404()
    {
        var (client, _) = await CreateAuthenticatedClient("delete-404@example.com");

        var response = await client.DeleteAsync("/api/secrets/does-not-exist");
        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task ListCollections_AfterPush_ShowsCollection()
    {
        var (client, masterKey) = await CreateAuthenticatedClient("list-after@example.com");

        var encrypted = SecretEncryptor.Encrypt("{}", masterKey);
        await client.PutAsJsonAsync("/api/secrets/list-id-1", new PushSecretsRequest(encrypted.ToBase64Combined()));
        await client.PutAsJsonAsync("/api/secrets/list-id-2", new PushSecretsRequest(encrypted.ToBase64Combined()));

        var response = await client.GetAsync("/api/secrets");
        var collections = (await response.Content.ReadFromJsonAsync<List<SecretCollectionSummary>>(JsonOptions))!;

        collections.Should().HaveCount(2);
        collections.Select(c => c.UserSecretsId).Should().Contain("list-id-1").And.Contain("list-id-2");
    }

    [Fact]
    public async Task UserIsolation_UserACannotAccessUserBSecrets()
    {
        var (clientA, masterKeyA) = await CreateAuthenticatedClient("user-a@example.com");
        var (clientB, _) = await CreateAuthenticatedClient("user-b@example.com");

        // User A pushes secrets
        var encrypted = SecretEncryptor.Encrypt("""{"secret": "belongs to A"}""", masterKeyA);
        await clientA.PutAsJsonAsync("/api/secrets/user-a-secrets", new PushSecretsRequest(encrypted.ToBase64Combined()));

        // User B tries to access User A's secrets
        var response = await clientB.GetAsync("/api/secrets/user-a-secrets");
        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task UserIsolation_UserBCannotDeleteUserASecrets()
    {
        var (clientA, masterKeyA) = await CreateAuthenticatedClient("iso-del-a@example.com");
        var (clientB, _) = await CreateAuthenticatedClient("iso-del-b@example.com");

        var encrypted = SecretEncryptor.Encrypt("{}", masterKeyA);
        await clientA.PutAsJsonAsync("/api/secrets/iso-del-test", new PushSecretsRequest(encrypted.ToBase64Combined()));

        var response = await clientB.DeleteAsync("/api/secrets/iso-del-test");
        response.StatusCode.Should().Be(HttpStatusCode.NotFound);

        // Verify A can still access it
        var getResponse = await clientA.GetAsync("/api/secrets/iso-del-test");
        getResponse.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task E2E_FullPushPullCycle_DataRoundTrips()
    {
        var (client, masterKey) = await CreateAuthenticatedClient("e2e-roundtrip@example.com");

        // Simulate a realistic secrets.json
        var originalSecrets = JsonSerializer.Serialize(new Dictionary<string, string>
        {
            ["ConnectionStrings:DefaultConnection"] = "Server=prod.db.internal;Database=myapp;User=admin;Password=s3cret!",
            ["Jwt:SigningKey"] = "my-super-secret-jwt-key-that-is-long-enough",
            ["ExternalApi:Key"] = "ak_live_1234567890abcdef",
            ["ExternalApi:Secret"] = "sk_live_abcdef1234567890",
            ["SmtpPassword"] = "email-password-123"
        });

        // Push
        var encrypted = SecretEncryptor.Encrypt(originalSecrets, masterKey);
        var pushResp = await client.PutAsJsonAsync("/api/secrets/e2e-test-id",
            new PushSecretsRequest(encrypted.ToBase64Combined()));
        pushResp.StatusCode.Should().Be(HttpStatusCode.OK);

        // Pull
        var pullResp = await client.GetAsync("/api/secrets/e2e-test-id");
        var pullResult = (await pullResp.Content.ReadFromJsonAsync<PullSecretsResponse>(JsonOptions))!;

        // Decrypt and verify exact match
        var payload = EncryptedPayload.FromBase64Combined(pullResult.EncryptedData);
        var decryptedSecrets = SecretEncryptor.Decrypt(payload, masterKey);
        decryptedSecrets.Should().Be(originalSecrets);

        // Parse and verify individual keys
        var parsed = JsonSerializer.Deserialize<Dictionary<string, string>>(decryptedSecrets)!;
        parsed.Should().HaveCount(5);
        parsed["SmtpPassword"].Should().Be("email-password-123");
    }

    [Fact]
    public async Task ServerNeverSeesPlaintext_EncryptedDataIsNotPlaintext()
    {
        var (client, masterKey) = await CreateAuthenticatedClient("no-plaintext@example.com");

        var secretValue = "this-should-never-appear-in-server-storage";
        var originalJson = "{\"key\": \"" + secretValue + "\"}";

        var encrypted = SecretEncryptor.Encrypt(originalJson, masterKey);
        var encryptedBase64 = encrypted.ToBase64Combined();

        // The encrypted data sent to server should not contain the plaintext
        encryptedBase64.Should().NotContain(secretValue);

        await client.PutAsJsonAsync("/api/secrets/plaintext-check",
            new PushSecretsRequest(encryptedBase64));

        var pullResp = await client.GetAsync("/api/secrets/plaintext-check");
        var result = (await pullResp.Content.ReadFromJsonAsync<PullSecretsResponse>(JsonOptions))!;

        // Server-stored data should not contain plaintext
        result.EncryptedData.Should().NotContain(secretValue);
    }
}

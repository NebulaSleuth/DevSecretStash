using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using DevSecrets.Api.Data;
using DevSecrets.Cli.Services;
using DevSecrets.Core;
using DevSecrets.Core.Dtos;
using DevSecrets.Core.Encryption;
using DevSecrets.Core.Models;
using FluentAssertions;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace DevSecrets.Cli.Tests;

public class CliTestFixture : WebApplicationFactory<Program>, IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly string _tempDir;

    public string ConfigDir => _tempDir;

    public CliTestFixture()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        _tempDir = Path.Combine(Path.GetTempPath(), $"devsecrets-test-{Guid.NewGuid()}");
        Directory.CreateDirectory(_tempDir);
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Development");
        builder.ConfigureServices(services =>
        {
            var descriptor = services.SingleOrDefault(
                d => d.ServiceType == typeof(DbContextOptions<AppDbContext>));
            if (descriptor != null)
                services.Remove(descriptor);

            services.AddDbContext<AppDbContext>(options =>
                options.UseSqlite(_connection));
        });
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (disposing)
        {
            _connection.Dispose();
            if (Directory.Exists(_tempDir))
                Directory.Delete(_tempDir, true);
        }
    }
}

/// <summary>
/// Integration tests that exercise the CLI services (ApiClient, CredentialStore, ConfigStore)
/// against an in-process API server, simulating the full CLI workflow without console I/O.
/// </summary>
public class CliIntegrationTests : IClassFixture<CliTestFixture>
{
    private readonly CliTestFixture _fixture;
    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true };

    public CliIntegrationTests(CliTestFixture fixture)
    {
        _fixture = fixture;
    }

    private (ApiClient client, CredentialStore credStore, ConfigStore configStore, HttpClient httpClient) CreateCliServices()
    {
        var httpClient = _fixture.CreateClient();
        var configDir = Path.Combine(_fixture.ConfigDir, Guid.NewGuid().ToString());
        Directory.CreateDirectory(configDir);

        var configStore = new TestConfigStore(configDir, httpClient.BaseAddress!.ToString());
        var credStore = new TestCredentialStore(configDir);
        var apiClient = new ApiClient(credStore, configStore, httpClient);

        return (apiClient, credStore, configStore, httpClient);
    }

    private async Task<(ApiClient client, CredentialStore credStore, byte[] masterKey)> RegisterAndLoginViaCliServices(string email, string password = "TestPassword123!")
    {
        var (client, credStore, _, _) = CreateCliServices();

        // Simulate register command logic
        var bundle = MasterKeyManager.GenerateAndWrap(password);
        var registerRequest = new RegisterRequest(
            email, password,
            bundle.EncryptedKey, bundle.Salt,
            bundle.Nonce, bundle.Tag, bundle.Argon2Params);

        var registerResponse = await client.Register(registerRequest);
        registerResponse.Should().NotBeNull();

        // Simulate login command logic
        var loginResponse = await client.Login(new LoginRequest(email, password));
        loginResponse.Should().NotBeNull();

        var loginBundle = new EncryptedMasterKeyBundle(
            loginResponse!.EncryptedMasterKey!, loginResponse.MasterKeySalt!,
            loginResponse.MasterKeyNonce!, loginResponse.MasterKeyTag!,
            loginResponse.Argon2Params!);

        var masterKey = MasterKeyManager.Unwrap(password, loginBundle);

        credStore.Save(new StoredCredentials
        {
            Jwt = loginResponse.Token,
            RefreshToken = loginResponse.RefreshToken,
            MasterKeyBase64 = Convert.ToBase64String(masterKey),
            ExpiresAt = loginResponse.ExpiresAt
        });

        return (client, credStore, masterKey);
    }

    [Fact]
    public async Task FullWorkflow_Register_Push_Pull_RoundTrips()
    {
        var (client, credStore, masterKey) = await RegisterAndLoginViaCliServices("cli-e2e@example.com");

        // Simulate push command
        var userSecretsId = $"test-{Guid.NewGuid()}";
        var originalSecrets = """{"ConnectionString": "Server=prod;Password=s3cret", "ApiKey": "key123"}""";

        var encrypted = SecretEncryptor.Encrypt(originalSecrets, masterKey);
        var pushResponse = await client.PushSecrets(userSecretsId, new PushSecretsRequest(encrypted.ToBase64Combined()));
        pushResponse.Should().NotBeNull();
        pushResponse!.Version.Should().Be(1);

        // Simulate pull command
        var pullResponse = await client.PullSecrets(userSecretsId);
        pullResponse.Should().NotBeNull();

        var payload = EncryptedPayload.FromBase64Combined(pullResponse!.EncryptedData);
        var decrypted = SecretEncryptor.Decrypt(payload, masterKey);
        decrypted.Should().Be(originalSecrets);
    }

    [Fact]
    public async Task FullWorkflow_Register_Push_List_ShowsCollections()
    {
        var (client, _, masterKey) = await RegisterAndLoginViaCliServices("cli-list@example.com");

        var id1 = $"list-{Guid.NewGuid()}";
        var id2 = $"list-{Guid.NewGuid()}";
        var encrypted = SecretEncryptor.Encrypt("{}", masterKey);

        await client.PushSecrets(id1, new PushSecretsRequest(encrypted.ToBase64Combined()));
        await client.PushSecrets(id2, new PushSecretsRequest(encrypted.ToBase64Combined()));

        var collections = await client.ListCollections();
        collections.Should().HaveCount(2);
        collections.Select(c => c.UserSecretsId).Should().Contain(id1).And.Contain(id2);
    }

    [Fact]
    public async Task FullWorkflow_Push_Update_VersionIncrements()
    {
        var (client, _, masterKey) = await RegisterAndLoginViaCliServices("cli-version@example.com");
        var id = $"ver-{Guid.NewGuid()}";

        var encrypted1 = SecretEncryptor.Encrypt("""{"v": "1"}""", masterKey);
        var push1 = await client.PushSecrets(id, new PushSecretsRequest(encrypted1.ToBase64Combined()));
        push1!.Version.Should().Be(1);

        var encrypted2 = SecretEncryptor.Encrypt("""{"v": "2"}""", masterKey);
        var push2 = await client.PushSecrets(id, new PushSecretsRequest(encrypted2.ToBase64Combined()));
        push2!.Version.Should().Be(2);

        // Pull should get latest
        var pull = await client.PullSecrets(id);
        var decrypted = SecretEncryptor.Decrypt(EncryptedPayload.FromBase64Combined(pull!.EncryptedData), masterKey);
        decrypted.Should().Be("""{"v": "2"}""");
    }

    [Fact]
    public async Task FullWorkflow_Push_Delete_ConfirmsRemoval()
    {
        var (client, _, masterKey) = await RegisterAndLoginViaCliServices("cli-delete@example.com");
        var id = $"del-{Guid.NewGuid()}";

        var encrypted = SecretEncryptor.Encrypt("{}", masterKey);
        await client.PushSecrets(id, new PushSecretsRequest(encrypted.ToBase64Combined()));

        await client.DeleteSecrets(id);

        var pull = await client.PullSecrets(id);
        pull.Should().BeNull();
    }

    [Fact]
    public async Task FullWorkflow_PasswordChange_MasterKeyStillWorks()
    {
        var email = "cli-pwchange@example.com";
        var oldPassword = "OldPassword123!";
        var newPassword = "NewPassword456!";

        var (_, credStore, _, httpClient) = CreateCliServices();

        // Register
        var bundle = MasterKeyManager.GenerateAndWrap(oldPassword);
        var regReq = new RegisterRequest(email, oldPassword,
            bundle.EncryptedKey, bundle.Salt, bundle.Nonce, bundle.Tag, bundle.Argon2Params);
        var regResp = await httpClient.PostAsJsonAsync("/api/auth/register", regReq);
        regResp.EnsureSuccessStatusCode();

        // Login
        var loginResp = await httpClient.PostAsJsonAsync("/api/auth/login", new LoginRequest(email, oldPassword));
        var loginAuth = (await loginResp.Content.ReadFromJsonAsync<AuthResponse>(JsonOptions))!;

        var loginBundle = new EncryptedMasterKeyBundle(
            loginAuth.EncryptedMasterKey!, loginAuth.MasterKeySalt!,
            loginAuth.MasterKeyNonce!, loginAuth.MasterKeyTag!, loginAuth.Argon2Params!);
        var masterKey = MasterKeyManager.Unwrap(oldPassword, loginBundle);

        // Push a secret
        httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", loginAuth.Token);
        var secretId = $"pwchange-{Guid.NewGuid()}";
        var originalSecrets = """{"important": "data"}""";
        var encrypted = SecretEncryptor.Encrypt(originalSecrets, masterKey);
        await httpClient.PutAsJsonAsync($"/api/secrets/{secretId}", new PushSecretsRequest(encrypted.ToBase64Combined()));

        // Change password
        var newBundle = MasterKeyManager.Rewrap(oldPassword, newPassword, loginBundle);
        var changeReq = new ChangePasswordRequest(oldPassword, newPassword,
            newBundle.EncryptedKey, newBundle.Salt, newBundle.Nonce, newBundle.Tag, newBundle.Argon2Params);
        var changeResp = await httpClient.PostAsJsonAsync("/api/auth/change-password", changeReq);
        changeResp.EnsureSuccessStatusCode();

        // Login with new password
        var newLoginResp = await httpClient.PostAsJsonAsync("/api/auth/login", new LoginRequest(email, newPassword));
        var newLoginAuth = (await newLoginResp.Content.ReadFromJsonAsync<AuthResponse>(JsonOptions))!;

        var newLoginBundle = new EncryptedMasterKeyBundle(
            newLoginAuth.EncryptedMasterKey!, newLoginAuth.MasterKeySalt!,
            newLoginAuth.MasterKeyNonce!, newLoginAuth.MasterKeyTag!, newLoginAuth.Argon2Params!);
        var newMasterKey = MasterKeyManager.Unwrap(newPassword, newLoginBundle);

        // Master key should be the same (rewrap doesn't change it)
        newMasterKey.Should().Equal(masterKey);

        // Pull and decrypt with new master key
        httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", newLoginAuth.Token);
        var pullResp = await httpClient.GetAsync($"/api/secrets/{secretId}");
        var pullResult = (await pullResp.Content.ReadFromJsonAsync<PullSecretsResponse>(JsonOptions))!;
        var decrypted = SecretEncryptor.Decrypt(EncryptedPayload.FromBase64Combined(pullResult.EncryptedData), newMasterKey);
        decrypted.Should().Be(originalSecrets);
    }

    [Fact]
    public void CredentialStore_SaveAndLoad_RoundTrips()
    {
        var configDir = Path.Combine(_fixture.ConfigDir, Guid.NewGuid().ToString());
        Directory.CreateDirectory(configDir);
        var store = new TestCredentialStore(configDir);

        var creds = new StoredCredentials
        {
            Jwt = "test-jwt-token",
            RefreshToken = "test-refresh-token",
            MasterKeyBase64 = Convert.ToBase64String(new byte[32]),
            ExpiresAt = DateTime.UtcNow.AddMinutes(15)
        };

        store.Save(creds);
        var loaded = store.Load();

        loaded.Should().NotBeNull();
        loaded!.Jwt.Should().Be(creds.Jwt);
        loaded.RefreshToken.Should().Be(creds.RefreshToken);
        loaded.MasterKeyBase64.Should().Be(creds.MasterKeyBase64);
    }

    [Fact]
    public void CredentialStore_Clear_RemovesCredentials()
    {
        var configDir = Path.Combine(_fixture.ConfigDir, Guid.NewGuid().ToString());
        Directory.CreateDirectory(configDir);
        var store = new TestCredentialStore(configDir);

        store.Save(new StoredCredentials { Jwt = "token" });
        store.IsLoggedIn().Should().BeTrue();

        store.Clear();
        store.IsLoggedIn().Should().BeFalse();
        store.Load().Should().BeNull();
    }

    [Fact]
    public void UserSecretsLocator_WriteAndRead_RoundTrips()
    {
        var testId = $"cli-test-{Guid.NewGuid()}";
        var json = """{"TestKey": "TestValue", "Nested:Key": "NestedValue"}""";

        try
        {
            UserSecretsLocator.WriteSecrets(testId, json);
            var result = UserSecretsLocator.ReadSecrets(testId);
            result.Should().Be(json);
        }
        finally
        {
            var path = UserSecretsLocator.GetSecretsFilePath(testId);
            var dir = Path.GetDirectoryName(path);
            if (dir != null && Directory.Exists(dir))
                Directory.Delete(dir, true);
        }
    }

    [Fact]
    public async Task ApiClient_NotLoggedIn_ThrowsApiException()
    {
        var (client, _, _, _) = CreateCliServices();

        var act = () => client.ListCollections();
        await act.Should().ThrowAsync<ApiException>().WithMessage("*Not logged in*");
    }
}

/// <summary>
/// Test-specific ConfigStore that uses a custom directory instead of ~/.devsecrets
/// </summary>
internal class TestConfigStore : ConfigStore
{
    private readonly string _configPath;

    public TestConfigStore(string configDir, string serverUrl)
    {
        _configPath = Path.Combine(configDir, "config.json");
        var config = new DevSecretsConfig { ServerUrl = serverUrl.TrimEnd('/') };
        Directory.CreateDirectory(configDir);
        File.WriteAllText(_configPath, JsonSerializer.Serialize(config));
    }

    public override DevSecretsConfig Load()
    {
        if (!File.Exists(_configPath))
            return new DevSecretsConfig();
        return JsonSerializer.Deserialize<DevSecretsConfig>(File.ReadAllText(_configPath)) ?? new DevSecretsConfig();
    }
}

/// <summary>
/// Test-specific CredentialStore that uses a custom directory instead of ~/.devsecrets
/// </summary>
internal class TestCredentialStore : CredentialStore
{
    private readonly string _credPath;

    public TestCredentialStore(string configDir)
    {
        _credPath = Path.Combine(configDir, "credentials.json");
    }

    public override StoredCredentials? Load()
    {
        if (!File.Exists(_credPath))
            return null;
        return JsonSerializer.Deserialize<StoredCredentials>(File.ReadAllText(_credPath));
    }

    public override void Save(StoredCredentials credentials)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_credPath)!);
        File.WriteAllText(_credPath, JsonSerializer.Serialize(credentials));
    }

    public override void Clear()
    {
        if (File.Exists(_credPath))
            File.Delete(_credPath);
    }

    public override bool IsLoggedIn() => Load() != null;

    public override byte[]? GetMasterKey()
    {
        var creds = Load();
        return creds?.MasterKeyBase64 != null ? Convert.FromBase64String(creds.MasterKeyBase64) : null;
    }
}

using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using DevSecretStash.Core.Dtos;
using DevSecretStash.Core.Encryption;

namespace DevSecretStash.Api.Tests.Helpers;

public static class AuthHelper
{
    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true };

    public static RegisterRequest CreateRegisterRequest(string email = "test@example.com", string password = "TestPassword123!")
    {
        var bundle = MasterKeyManager.GenerateAndWrap(password);
        return new RegisterRequest(
            Email: email,
            Password: password,
            EncryptedMasterKey: bundle.EncryptedKey,
            MasterKeySalt: bundle.Salt,
            MasterKeyNonce: bundle.Nonce,
            MasterKeyTag: bundle.Tag,
            Argon2Params: bundle.Argon2Params
        );
    }

    public static async Task<AuthResponse> RegisterAndGetToken(HttpClient client, string email = "test@example.com", string password = "TestPassword123!")
    {
        var request = CreateRegisterRequest(email, password);
        var response = await client.PostAsJsonAsync("/api/auth/register", request);
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<AuthResponse>(JsonOptions))!;
    }

    public static void SetAuth(HttpClient client, string token)
    {
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
    }
}

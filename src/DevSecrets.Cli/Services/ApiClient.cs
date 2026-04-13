using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using DevSecrets.Core.Dtos;

namespace DevSecrets.Cli.Services;

public class ApiClient
{
    private readonly HttpClient _http;
    private readonly CredentialStore _credentialStore;
    private readonly ConfigStore _configStore;
    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true };

    public ApiClient(CredentialStore credentialStore, ConfigStore configStore, HttpClient? httpClient = null)
    {
        _credentialStore = credentialStore;
        _configStore = configStore;

        if (httpClient != null)
        {
            _http = httpClient;
        }
        else
        {
            var handler = new HttpClientHandler();
            // Allow self-signed certs in development
            handler.ServerCertificateCustomValidationCallback = (_, _, _, _) => true;
            _http = new HttpClient(handler);
        }

        _http.BaseAddress = new Uri(_configStore.Load().ServerUrl);
        VerboseOutput.Log($"Server URL: {_http.BaseAddress}");
    }

    private static void Log(string message) => VerboseOutput.Log(message);

    public async Task<AuthResponse?> Register(RegisterRequest request)
    {
        Log("POST /api/auth/register");
        var response = await _http.PostAsJsonAsync("/api/auth/register", request);
        Log($"Response: {(int)response.StatusCode} {response.StatusCode}");
        if (response.StatusCode == HttpStatusCode.Conflict)
            throw new ApiException("Email already registered.");
        await EnsureSuccess(response);
        return await response.Content.ReadFromJsonAsync<AuthResponse>(JsonOptions);
    }

    public async Task<AuthResponse?> Login(LoginRequest request)
    {
        Log("POST /api/auth/login");
        var response = await _http.PostAsJsonAsync("/api/auth/login", request);
        Log($"Response: {(int)response.StatusCode} {response.StatusCode}");
        if (response.StatusCode == HttpStatusCode.Unauthorized)
            throw new ApiException("Invalid email or password.");
        await EnsureSuccess(response);
        return await response.Content.ReadFromJsonAsync<AuthResponse>(JsonOptions);
    }

    public async Task<List<SecretCollectionSummary>> ListCollections()
    {
        await EnsureAuthenticated();
        Log("GET /api/secrets");
        var response = await _http.GetAsync("/api/secrets");
        Log($"Response: {(int)response.StatusCode} {response.StatusCode}");
        await HandleAuthFailure(response);
        await EnsureSuccess(response);
        return await response.Content.ReadFromJsonAsync<List<SecretCollectionSummary>>(JsonOptions) ?? [];
    }

    public async Task<PullSecretsResponse?> PullSecrets(string userSecretsId)
    {
        await EnsureAuthenticated();
        Log($"GET /api/secrets/{userSecretsId}");
        var response = await _http.GetAsync($"/api/secrets/{Uri.EscapeDataString(userSecretsId)}");
        Log($"Response: {(int)response.StatusCode} {response.StatusCode}");
        if (response.StatusCode == HttpStatusCode.NotFound)
            return null;
        await HandleAuthFailure(response);
        await EnsureSuccess(response);
        return await response.Content.ReadFromJsonAsync<PullSecretsResponse>(JsonOptions);
    }

    public async Task<PushSecretsResponse?> PushSecrets(string userSecretsId, PushSecretsRequest request)
    {
        await EnsureAuthenticated();
        Log($"PUT /api/secrets/{userSecretsId}");
        var response = await _http.PutAsJsonAsync($"/api/secrets/{Uri.EscapeDataString(userSecretsId)}", request);
        Log($"Response: {(int)response.StatusCode} {response.StatusCode}");
        if (response.StatusCode == HttpStatusCode.Conflict)
            throw new ApiException("Version conflict. Remote was modified since last pull.");
        await HandleAuthFailure(response);
        await EnsureSuccess(response);
        return await response.Content.ReadFromJsonAsync<PushSecretsResponse>(JsonOptions);
    }

    public async Task DeleteSecrets(string userSecretsId)
    {
        await EnsureAuthenticated();
        Log($"DELETE /api/secrets/{userSecretsId}");
        var response = await _http.DeleteAsync($"/api/secrets/{Uri.EscapeDataString(userSecretsId)}");
        Log($"Response: {(int)response.StatusCode} {response.StatusCode}");
        await HandleAuthFailure(response);
        await EnsureSuccess(response);
    }

    private async Task EnsureSuccess(HttpResponseMessage response)
    {
        if (!response.IsSuccessStatusCode)
        {
            var body = await response.Content.ReadAsStringAsync();
            Log($"Error response body: {body}");
            throw new ApiException($"Server error ({(int)response.StatusCode}): {body}");
        }
    }

    private async Task EnsureAuthenticated()
    {
        var creds = _credentialStore.Load();
        if (creds == null)
            throw new ApiException("Not logged in. Run 'devsecrets login' first.");

        // Try refresh if token expired
        if (creds.ExpiresAt.HasValue && creds.ExpiresAt.Value < DateTime.UtcNow && creds.RefreshToken != null)
        {
            await TryRefresh(creds);
            creds = _credentialStore.Load();
        }

        _http.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", creds?.Jwt);
    }

    private async Task TryRefresh(StoredCredentials creds)
    {
        try
        {
            var response = await _http.PostAsJsonAsync("/api/auth/refresh", new RefreshRequest(creds.RefreshToken!));
            if (response.IsSuccessStatusCode)
            {
                var auth = await response.Content.ReadFromJsonAsync<AuthResponse>(JsonOptions);
                if (auth != null)
                {
                    _credentialStore.Save(new StoredCredentials
                    {
                        Jwt = auth.Token,
                        RefreshToken = auth.RefreshToken,
                        MasterKeyBase64 = creds.MasterKeyBase64,
                        ExpiresAt = auth.ExpiresAt
                    });
                }
            }
        }
        catch
        {
            // Refresh failed, user will need to login again
        }
    }

    private Task HandleAuthFailure(HttpResponseMessage response)
    {
        if (response.StatusCode == HttpStatusCode.Unauthorized)
        {
            _credentialStore.Clear();
            throw new ApiException("Session expired. Run 'devsecrets login' again.");
        }
        return Task.CompletedTask;
    }
}

public class ApiException(string message) : Exception(message);

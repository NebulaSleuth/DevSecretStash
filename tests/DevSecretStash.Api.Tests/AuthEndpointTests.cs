using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using DevSecretStash.Api.Tests.Helpers;
using DevSecretStash.Core.Dtos;
using DevSecretStash.Core.Encryption;
using DevSecretStash.Core.Models;
using FluentAssertions;

namespace DevSecretStash.Api.Tests;

public class AuthEndpointTests : IClassFixture<TestWebApplicationFactory>
{
    private readonly TestWebApplicationFactory _factory;
    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true };

    public AuthEndpointTests(TestWebApplicationFactory factory)
    {
        _factory = factory;
    }

    [Fact]
    public async Task Register_ValidRequest_ReturnsToken()
    {
        var client = _factory.CreateClient();
        var request = AuthHelper.CreateRegisterRequest("register-test@example.com");
        var response = await client.PostAsJsonAsync("/api/auth/register", request);

        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var auth = await response.Content.ReadFromJsonAsync<AuthResponse>(JsonOptions);
        auth.Should().NotBeNull();
        auth!.Token.Should().NotBeNullOrEmpty();
        auth.RefreshToken.Should().NotBeNullOrEmpty();
        auth.ExpiresAt.Should().BeAfter(DateTime.UtcNow);
    }

    [Fact]
    public async Task Register_DuplicateEmail_Returns409()
    {
        var client = _factory.CreateClient();
        var email = "duplicate@example.com";
        var request = AuthHelper.CreateRegisterRequest(email);

        var first = await client.PostAsJsonAsync("/api/auth/register", request);
        first.StatusCode.Should().Be(HttpStatusCode.OK);

        var second = await client.PostAsJsonAsync("/api/auth/register", request);
        second.StatusCode.Should().Be(HttpStatusCode.Conflict);
    }

    [Fact]
    public async Task Login_ValidCredentials_ReturnsTokenAndMasterKeyBundle()
    {
        var client = _factory.CreateClient();
        var email = "login-test@example.com";
        var password = "TestPassword123!";
        await AuthHelper.RegisterAndGetToken(client, email, password);

        var loginResponse = await client.PostAsJsonAsync("/api/auth/login", new LoginRequest(email, password));
        loginResponse.StatusCode.Should().Be(HttpStatusCode.OK);

        var auth = await loginResponse.Content.ReadFromJsonAsync<AuthResponse>(JsonOptions);
        auth.Should().NotBeNull();
        auth!.Token.Should().NotBeNullOrEmpty();
        auth.EncryptedMasterKey.Should().NotBeNullOrEmpty();
        auth.MasterKeySalt.Should().NotBeNullOrEmpty();
        auth.MasterKeyNonce.Should().NotBeNullOrEmpty();
        auth.MasterKeyTag.Should().NotBeNullOrEmpty();
        auth.Argon2Params.Should().NotBeNull();
    }

    [Fact]
    public async Task Login_WrongPassword_Returns401()
    {
        var client = _factory.CreateClient();
        var email = "wrong-pw@example.com";
        await AuthHelper.RegisterAndGetToken(client, email, "CorrectPassword123!");

        var response = await client.PostAsJsonAsync("/api/auth/login", new LoginRequest(email, "WrongPassword456!"));
        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Login_NonexistentUser_Returns401()
    {
        var client = _factory.CreateClient();
        var response = await client.PostAsJsonAsync("/api/auth/login", new LoginRequest("nobody@example.com", "password"));
        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Login_MasterKey_CanBeUnwrapped()
    {
        var client = _factory.CreateClient();
        var email = "unwrap-test@example.com";
        var password = "TestPassword123!";
        await AuthHelper.RegisterAndGetToken(client, email, password);

        var loginResponse = await client.PostAsJsonAsync("/api/auth/login", new LoginRequest(email, password));
        var auth = (await loginResponse.Content.ReadFromJsonAsync<AuthResponse>(JsonOptions))!;

        var bundle = new EncryptedMasterKeyBundle(
            auth.EncryptedMasterKey!,
            auth.MasterKeySalt!,
            auth.MasterKeyNonce!,
            auth.MasterKeyTag!,
            auth.Argon2Params!
        );

        var masterKey = MasterKeyManager.Unwrap(password, bundle);
        masterKey.Should().HaveCount(EncryptionConstants.KeySizeBytes);
    }

    [Fact]
    public async Task Refresh_ValidToken_ReturnsNewTokens()
    {
        var client = _factory.CreateClient();
        var auth = await AuthHelper.RegisterAndGetToken(client, "refresh-test@example.com");

        var response = await client.PostAsJsonAsync("/api/auth/refresh", new RefreshRequest(auth.RefreshToken));
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var newAuth = await response.Content.ReadFromJsonAsync<AuthResponse>(JsonOptions);
        newAuth.Should().NotBeNull();
        newAuth!.Token.Should().NotBeNullOrEmpty();
        newAuth.RefreshToken.Should().NotBe(auth.RefreshToken, "old refresh token should be rotated");
    }

    [Fact]
    public async Task Refresh_RevokedToken_Returns401()
    {
        var client = _factory.CreateClient();
        var auth = await AuthHelper.RegisterAndGetToken(client, "revoke-test@example.com");

        // Use refresh token once (this revokes it)
        await client.PostAsJsonAsync("/api/auth/refresh", new RefreshRequest(auth.RefreshToken));

        // Try using the same token again
        var response = await client.PostAsJsonAsync("/api/auth/refresh", new RefreshRequest(auth.RefreshToken));
        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Refresh_InvalidToken_Returns401()
    {
        var client = _factory.CreateClient();
        var response = await client.PostAsJsonAsync("/api/auth/refresh", new RefreshRequest("not-a-real-token"));
        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task ChangePassword_ValidRequest_UpdatesCredentials()
    {
        var client = _factory.CreateClient();
        var email = "changepw@example.com";
        var oldPassword = "OldPassword123!";
        var newPassword = "NewPassword456!";

        var auth = await AuthHelper.RegisterAndGetToken(client, email, oldPassword);
        AuthHelper.SetAuth(client, auth.Token);

        // Login to get the master key bundle for rewrap
        var loginResp = await client.PostAsJsonAsync("/api/auth/login", new LoginRequest(email, oldPassword));
        var loginAuth = (await loginResp.Content.ReadFromJsonAsync<AuthResponse>(JsonOptions))!;

        var oldBundle = new EncryptedMasterKeyBundle(
            loginAuth.EncryptedMasterKey!, loginAuth.MasterKeySalt!,
            loginAuth.MasterKeyNonce!, loginAuth.MasterKeyTag!, loginAuth.Argon2Params!);

        var newBundle = MasterKeyManager.Rewrap(oldPassword, newPassword, oldBundle);

        var changeRequest = new ChangePasswordRequest(
            oldPassword, newPassword,
            newBundle.EncryptedKey, newBundle.Salt,
            newBundle.Nonce, newBundle.Tag, newBundle.Argon2Params);

        var response = await client.PostAsJsonAsync("/api/auth/change-password", changeRequest);
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        // Old password should no longer work
        var oldLoginResp = await client.PostAsJsonAsync("/api/auth/login", new LoginRequest(email, oldPassword));
        oldLoginResp.StatusCode.Should().Be(HttpStatusCode.Unauthorized);

        // New password should work
        var newLoginResp = await client.PostAsJsonAsync("/api/auth/login", new LoginRequest(email, newPassword));
        newLoginResp.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task ChangePassword_WrongCurrentPassword_ReturnsBadRequest()
    {
        var client = _factory.CreateClient();
        var email = "changepw-bad@example.com";
        var password = "CorrectPassword123!";

        var auth = await AuthHelper.RegisterAndGetToken(client, email, password);
        AuthHelper.SetAuth(client, auth.Token);

        var bundle = MasterKeyManager.GenerateAndWrap("dummy");
        var request = new ChangePasswordRequest(
            "WrongPassword!", "NewPassword!",
            bundle.EncryptedKey, bundle.Salt,
            bundle.Nonce, bundle.Tag, bundle.Argon2Params);

        var response = await client.PostAsJsonAsync("/api/auth/change-password", request);
        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task ChangePassword_NoAuth_Returns401()
    {
        var client = _factory.CreateClient();
        var bundle = MasterKeyManager.GenerateAndWrap("dummy");
        var request = new ChangePasswordRequest(
            "old", "new",
            bundle.EncryptedKey, bundle.Salt,
            bundle.Nonce, bundle.Tag, bundle.Argon2Params);

        var response = await client.PostAsJsonAsync("/api/auth/change-password", request);
        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }
}

using System.Security.Claims;
using System.Text.Json;
using DevSecrets.Api.Data;
using DevSecrets.Api.Services;
using DevSecrets.Core.Dtos;
using DevSecrets.Core.Encryption;
using Microsoft.EntityFrameworkCore;

namespace DevSecrets.Api.Endpoints;

public static class AuthEndpoints
{
    public static RouteGroupBuilder MapAuthEndpoints(this WebApplication app)
    {
        var group = app.MapGroup("/api/auth").WithTags("Auth");

        group.MapPost("/register", Register);
        group.MapPost("/login", Login);
        group.MapPost("/refresh", Refresh);
        group.MapPost("/change-password", ChangePassword).RequireAuthorization();

        return group;
    }

    private static async Task<IResult> Register(
        RegisterRequest request,
        AppDbContext db,
        TokenService tokenService)
    {
        if (await db.Users.AnyAsync(u => u.Email == request.Email))
            return Results.Conflict(new { error = "Email already registered." });

        var (hash, salt) = PasswordHasher.Hash(request.Password);

        var user = new User
        {
            Email = request.Email,
            PasswordHash = hash,
            PasswordSalt = salt,
            EncryptedMasterKey = request.EncryptedMasterKey,
            MasterKeySalt = request.MasterKeySalt,
            MasterKeyNonce = request.MasterKeyNonce,
            MasterKeyTag = request.MasterKeyTag,
            Argon2Params = JsonSerializer.Serialize(request.Argon2Params),
            CreatedAt = DateTime.UtcNow
        };

        db.Users.Add(user);
        await db.SaveChangesAsync();

        var accessToken = tokenService.GenerateAccessToken(user.Id, user.Email);
        var refreshToken = tokenService.GenerateRefreshToken();

        db.RefreshTokens.Add(new RefreshToken
        {
            UserId = user.Id,
            Token = refreshToken,
            Expires = tokenService.GetRefreshTokenExpiry(),
            CreatedAt = DateTime.UtcNow
        });
        await db.SaveChangesAsync();

        return Results.Ok(new AuthResponse(
            Token: accessToken,
            RefreshToken: refreshToken,
            ExpiresAt: tokenService.GetAccessTokenExpiry()
        ));
    }

    private static async Task<IResult> Login(
        LoginRequest request,
        AppDbContext db,
        TokenService tokenService)
    {
        var user = await db.Users.FirstOrDefaultAsync(u => u.Email == request.Email);
        if (user == null || !PasswordHasher.Verify(request.Password, user.PasswordHash, user.PasswordSalt))
            return Results.Unauthorized();

        var accessToken = tokenService.GenerateAccessToken(user.Id, user.Email);
        var refreshToken = tokenService.GenerateRefreshToken();

        db.RefreshTokens.Add(new RefreshToken
        {
            UserId = user.Id,
            Token = refreshToken,
            Expires = tokenService.GetRefreshTokenExpiry(),
            CreatedAt = DateTime.UtcNow
        });
        await db.SaveChangesAsync();

        var argon2Params = JsonSerializer.Deserialize<Argon2Params>(user.Argon2Params);

        return Results.Ok(new AuthResponse(
            Token: accessToken,
            RefreshToken: refreshToken,
            ExpiresAt: tokenService.GetAccessTokenExpiry(),
            EncryptedMasterKey: user.EncryptedMasterKey,
            MasterKeySalt: user.MasterKeySalt,
            MasterKeyNonce: user.MasterKeyNonce,
            MasterKeyTag: user.MasterKeyTag,
            Argon2Params: argon2Params
        ));
    }

    private static async Task<IResult> Refresh(
        RefreshRequest request,
        AppDbContext db,
        TokenService tokenService)
    {
        var existing = await db.RefreshTokens
            .Include(r => r.User)
            .FirstOrDefaultAsync(r => r.Token == request.RefreshToken && !r.IsRevoked);

        if (existing == null || existing.Expires < DateTime.UtcNow)
            return Results.Unauthorized();

        // Rotate: revoke old, issue new
        existing.IsRevoked = true;
        var newRefreshToken = tokenService.GenerateRefreshToken();
        existing.ReplacedByToken = newRefreshToken;

        db.RefreshTokens.Add(new RefreshToken
        {
            UserId = existing.UserId,
            Token = newRefreshToken,
            Expires = tokenService.GetRefreshTokenExpiry(),
            CreatedAt = DateTime.UtcNow
        });
        await db.SaveChangesAsync();

        var accessToken = tokenService.GenerateAccessToken(existing.UserId, existing.User.Email);

        return Results.Ok(new AuthResponse(
            Token: accessToken,
            RefreshToken: newRefreshToken,
            ExpiresAt: tokenService.GetAccessTokenExpiry()
        ));
    }

    private static async Task<IResult> ChangePassword(
        ChangePasswordRequest request,
        AppDbContext db,
        ClaimsPrincipal principal)
    {
        var userId = int.Parse(principal.FindFirstValue("sub")!);
        var user = await db.Users.FindAsync(userId);
        if (user == null)
            return Results.NotFound();

        if (!PasswordHasher.Verify(request.CurrentPassword, user.PasswordHash, user.PasswordSalt))
            return Results.BadRequest(new { error = "Current password is incorrect." });

        var (newHash, newSalt) = PasswordHasher.Hash(request.NewPassword);
        user.PasswordHash = newHash;
        user.PasswordSalt = newSalt;
        user.EncryptedMasterKey = request.NewEncryptedMasterKey;
        user.MasterKeySalt = request.NewMasterKeySalt;
        user.MasterKeyNonce = request.NewMasterKeyNonce;
        user.MasterKeyTag = request.NewMasterKeyTag;
        user.Argon2Params = JsonSerializer.Serialize(request.NewArgon2Params);

        await db.SaveChangesAsync();
        return Results.Ok(new { success = true });
    }
}

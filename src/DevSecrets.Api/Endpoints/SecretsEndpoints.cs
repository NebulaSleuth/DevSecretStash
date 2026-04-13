using System.Security.Claims;
using DevSecrets.Api.Data;
using DevSecrets.Core.Dtos;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;

namespace DevSecrets.Api.Endpoints;

public static class SecretsEndpoints
{
    public static RouteGroupBuilder MapSecretsEndpoints(this WebApplication app)
    {
        var group = app.MapGroup("/api/secrets")
            .WithTags("Secrets")
            .RequireAuthorization(policy =>
            {
                policy.AddAuthenticationSchemes(JwtBearerDefaults.AuthenticationScheme);
                policy.RequireAuthenticatedUser();
            });

        group.MapGet("/", ListCollections);
        group.MapGet("/{userSecretsId}", GetCollection);
        group.MapPut("/{userSecretsId}", PushCollection);
        group.MapDelete("/{userSecretsId}", DeleteCollection);

        return group;
    }

    private static int GetUserId(ClaimsPrincipal principal) =>
        int.Parse(principal.FindFirstValue("sub")!);

    private static async Task<IResult> ListCollections(
        AppDbContext db,
        ClaimsPrincipal principal)
    {
        var userId = GetUserId(principal);
        var collections = await db.SecretCollections
            .Where(s => s.UserId == userId)
            .Select(s => new SecretCollectionSummary(s.UserSecretsId, s.LastModified, s.Version))
            .ToListAsync();

        return Results.Ok(collections);
    }

    private static async Task<IResult> GetCollection(
        string userSecretsId,
        AppDbContext db,
        ClaimsPrincipal principal)
    {
        var userId = GetUserId(principal);
        var collection = await db.SecretCollections
            .FirstOrDefaultAsync(s => s.UserId == userId && s.UserSecretsId == userSecretsId);

        if (collection == null)
            return Results.NotFound();

        return Results.Ok(new PullSecretsResponse(
            collection.UserSecretsId,
            collection.EncryptedData,
            collection.LastModified,
            collection.Version
        ));
    }

    private static async Task<IResult> PushCollection(
        string userSecretsId,
        PushSecretsRequest request,
        AppDbContext db,
        ClaimsPrincipal principal)
    {
        var userId = GetUserId(principal);
        var existing = await db.SecretCollections
            .FirstOrDefaultAsync(s => s.UserId == userId && s.UserSecretsId == userSecretsId);

        if (existing != null)
        {
            // Optimistic concurrency check
            if (request.ExpectedVersion.HasValue && request.ExpectedVersion.Value != existing.Version)
                return Results.Conflict(new { error = "Version conflict. Remote was modified.", currentVersion = existing.Version });

            existing.EncryptedData = request.EncryptedData;
            existing.LastModified = DateTime.UtcNow;
            existing.Version++;
        }
        else
        {
            existing = new SecretCollection
            {
                UserId = userId,
                UserSecretsId = userSecretsId,
                EncryptedData = request.EncryptedData,
                LastModified = DateTime.UtcNow,
                Version = 1
            };
            db.SecretCollections.Add(existing);
        }

        await db.SaveChangesAsync();

        return Results.Ok(new PushSecretsResponse(
            existing.UserSecretsId,
            existing.LastModified,
            existing.Version
        ));
    }

    private static async Task<IResult> DeleteCollection(
        string userSecretsId,
        AppDbContext db,
        ClaimsPrincipal principal)
    {
        var userId = GetUserId(principal);
        var collection = await db.SecretCollections
            .FirstOrDefaultAsync(s => s.UserId == userId && s.UserSecretsId == userSecretsId);

        if (collection == null)
            return Results.NotFound();

        db.SecretCollections.Remove(collection);
        await db.SaveChangesAsync();

        return Results.NoContent();
    }
}

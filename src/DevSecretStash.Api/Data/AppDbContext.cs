using Microsoft.EntityFrameworkCore;

namespace DevSecretStash.Api.Data;

public class AppDbContext(DbContextOptions<AppDbContext> options) : DbContext(options)
{
    public DbSet<User> Users => Set<User>();
    public DbSet<SecretCollection> SecretCollections => Set<SecretCollection>();
    public DbSet<RefreshToken> RefreshTokens => Set<RefreshToken>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<User>(e =>
        {
            e.HasIndex(u => u.Email).IsUnique();
        });

        modelBuilder.Entity<SecretCollection>(e =>
        {
            e.HasIndex(s => new { s.UserId, s.UserSecretsId }).IsUnique();
        });

        modelBuilder.Entity<RefreshToken>(e =>
        {
            e.HasIndex(r => r.Token).IsUnique();
        });
    }
}

public class User
{
    public int Id { get; set; }
    public required string Email { get; set; }
    public required string PasswordHash { get; set; }
    public required string PasswordSalt { get; set; }
    public required string EncryptedMasterKey { get; set; }
    public required string MasterKeySalt { get; set; }
    public required string MasterKeyNonce { get; set; }
    public required string MasterKeyTag { get; set; }
    public required string Argon2Params { get; set; }
    public DateTime CreatedAt { get; set; }
    public ICollection<SecretCollection> SecretCollections { get; set; } = [];
    public ICollection<RefreshToken> RefreshTokens { get; set; } = [];
}

public class SecretCollection
{
    public int Id { get; set; }
    public int UserId { get; set; }
    public required string UserSecretsId { get; set; }
    public required string EncryptedData { get; set; }
    public DateTime LastModified { get; set; }
    public int Version { get; set; }
    public User User { get; set; } = null!;
}

public class RefreshToken
{
    public int Id { get; set; }
    public int UserId { get; set; }
    public required string Token { get; set; }
    public DateTime Expires { get; set; }
    public DateTime CreatedAt { get; set; }
    public bool IsRevoked { get; set; }
    public string? ReplacedByToken { get; set; }
    public User User { get; set; } = null!;
}

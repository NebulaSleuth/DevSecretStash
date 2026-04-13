using System.Runtime.InteropServices;
using System.Text.Json;

namespace DevSecrets.Cli.Services;

public class CredentialStore
{
    private static readonly string ConfigDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".devsecrets");
    private static readonly string CredPath = Path.Combine(ConfigDir, "credentials.json");

    public virtual StoredCredentials? Load()
    {
        if (!File.Exists(CredPath))
            return null;

        var json = File.ReadAllText(CredPath);
        return JsonSerializer.Deserialize<StoredCredentials>(json);
    }

    public virtual void Save(StoredCredentials credentials)
    {
        Directory.CreateDirectory(ConfigDir);
        var json = JsonSerializer.Serialize(credentials, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(CredPath, json);
        SetSecurePermissions();
    }

    public virtual void Clear()
    {
        if (File.Exists(CredPath))
            File.Delete(CredPath);
    }

    public virtual bool IsLoggedIn()
    {
        var creds = Load();
        return creds != null;
    }

    public virtual byte[]? GetMasterKey()
    {
        var creds = Load();
        return creds?.MasterKeyBase64 != null ? Convert.FromBase64String(creds.MasterKeyBase64) : null;
    }

    private static void SetSecurePermissions()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            File.SetUnixFileMode(CredPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
    }
}

public class StoredCredentials
{
    public string? Jwt { get; set; }
    public string? RefreshToken { get; set; }
    public string? MasterKeyBase64 { get; set; }
    public DateTime? ExpiresAt { get; set; }
}

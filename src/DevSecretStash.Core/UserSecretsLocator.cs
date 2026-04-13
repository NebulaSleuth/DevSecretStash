using System.Runtime.InteropServices;
using System.Xml.Linq;

namespace DevSecretStash.Core;

public static class UserSecretsLocator
{
    public static string GetSecretsFilePath(string userSecretsId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userSecretsId);

        string baseDir;
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            baseDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "Microsoft", "UserSecrets");
        }
        else
        {
            baseDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                ".microsoft", "usersecrets");
        }

        return Path.Combine(baseDir, userSecretsId, "secrets.json");
    }

    public static string? ReadSecrets(string userSecretsId)
    {
        var path = GetSecretsFilePath(userSecretsId);
        return File.Exists(path) ? File.ReadAllText(path) : null;
    }

    public static void WriteSecrets(string userSecretsId, string jsonContent)
    {
        var path = GetSecretsFilePath(userSecretsId);
        var dir = Path.GetDirectoryName(path)!;
        Directory.CreateDirectory(dir);
        File.WriteAllText(path, jsonContent);
    }

    public static string? FindUserSecretsId(string? directory = null)
    {
        directory ??= Directory.GetCurrentDirectory();
        var csprojFiles = Directory.GetFiles(directory, "*.csproj");

        foreach (var csproj in csprojFiles)
        {
            var id = ExtractUserSecretsId(csproj);
            if (id != null)
                return id;
        }

        return null;
    }

    public static string? ExtractUserSecretsId(string csprojPath)
    {
        var doc = XDocument.Load(csprojPath);
        return doc.Descendants("UserSecretsId").FirstOrDefault()?.Value;
    }
}

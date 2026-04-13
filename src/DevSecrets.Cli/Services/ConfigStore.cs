using System.Text.Json;

namespace DevSecrets.Cli.Services;

public class ConfigStore
{
    private static readonly string ConfigDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".devsecrets");
    private static readonly string ConfigPath = Path.Combine(ConfigDir, "config.json");

    public DevSecretsConfig Load()
    {
        if (!File.Exists(ConfigPath))
            return new DevSecretsConfig();

        var json = File.ReadAllText(ConfigPath);
        return JsonSerializer.Deserialize<DevSecretsConfig>(json) ?? new DevSecretsConfig();
    }

    public void Save(DevSecretsConfig config)
    {
        Directory.CreateDirectory(ConfigDir);
        var json = JsonSerializer.Serialize(config, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(ConfigPath, json);
    }
}

public class DevSecretsConfig
{
    public string ServerUrl { get; set; } = "https://localhost:5001";
}

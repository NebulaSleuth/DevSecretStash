using System.Text.Json;

namespace DevSecretStash.Cli.Services;

public class ConfigStore
{
    private static readonly string ConfigDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".devsecretstash");
    private static readonly string ConfigPath = Path.Combine(ConfigDir, "config.json");

    public virtual DevSecretStashConfig Load()
    {
        if (!File.Exists(ConfigPath))
            return new DevSecretStashConfig();

        var json = File.ReadAllText(ConfigPath);
        return JsonSerializer.Deserialize<DevSecretStashConfig>(json) ?? new DevSecretStashConfig();
    }

    public virtual void Save(DevSecretStashConfig config)
    {
        Directory.CreateDirectory(ConfigDir);
        var json = JsonSerializer.Serialize(config, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(ConfigPath, json);
    }
}

public class DevSecretStashConfig
{
    public string ServerUrl { get; set; } = "https://devsecretstash.com";
}

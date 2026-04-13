using System.CommandLine;
using System.Text.Json;
using DevSecretStash.Cli.Services;
using DevSecretStash.Core;
using DevSecretStash.Core.Encryption;

namespace DevSecretStash.Cli.Commands;

public static class PullCommand
{
    public static Command Create()
    {
        var idArg = new Argument<string?>("userSecretsId", () => null,
            "The UserSecretsId to pull. If omitted, reads from .csproj in current directory.");

        var forceOption = new Option<bool>("--force", "Overwrite local secrets without confirmation");

        var command = new Command("pull", "Download and decrypt secrets from the server")
        {
            idArg,
            forceOption
        };

        command.SetHandler(Handle, idArg, forceOption);
        return command;
    }

    private static async Task Handle(string? userSecretsId, bool force)
    {
        userSecretsId ??= UserSecretsLocator.FindUserSecretsId();
        if (userSecretsId == null)
        {
            Console.Error.WriteLine("No UserSecretsId provided and none found in .csproj files in current directory.");
            return;
        }

        var credStore = new CredentialStore();
        var masterKey = credStore.GetMasterKey();
        if (masterKey == null)
        {
            Console.Error.WriteLine("Not logged in. Run 'dss login' first.");
            return;
        }

        var configStore = new ConfigStore();
        var client = new ApiClient(credStore, configStore);

        try
        {
            var response = await client.PullSecrets(userSecretsId);
            if (response == null)
            {
                Console.Error.WriteLine($"No secrets found on server for {userSecretsId}");
                return;
            }

            var payload = EncryptedPayload.FromBase64Combined(response.EncryptedData);
            var json = SecretEncryptor.Decrypt(payload, masterKey);

            // Check if local file exists and warn
            var existing = UserSecretsLocator.ReadSecrets(userSecretsId);
            if (existing != null && !force)
            {
                if (!ConsolePrompt.Confirm("Local secrets exist. Overwrite?"))
                {
                    Console.WriteLine("Pull cancelled.");
                    return;
                }
            }

            UserSecretsLocator.WriteSecrets(userSecretsId, json);

            var keys = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(json);
            Console.WriteLine($"Pulled {keys?.Count ?? 0} keys for {userSecretsId} (version: {response.Version})");
        }
        catch (ApiException ex)
        {
            Console.Error.WriteLine($"Error: {ex.Message}");
        }
    }
}

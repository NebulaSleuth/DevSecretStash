using System.CommandLine;
using System.Text.Json;
using DevSecrets.Cli.Services;
using DevSecrets.Core;
using DevSecrets.Core.Dtos;
using DevSecrets.Core.Encryption;

namespace DevSecrets.Cli.Commands;

public static class PushCommand
{
    public static Command Create()
    {
        var idArg = new Argument<string?>("userSecretsId", () => null,
            "The UserSecretsId to push. If omitted, reads from .csproj in current directory.");

        var forceOption = new Option<bool>("--force", "Force push even if version conflict");

        var command = new Command("push", "Encrypt and upload local secrets to the server")
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
            Console.Error.WriteLine("Not logged in. Run 'devsecrets login' first.");
            return;
        }

        var json = UserSecretsLocator.ReadSecrets(userSecretsId);
        if (json == null)
        {
            Console.Error.WriteLine($"No local secrets found for {userSecretsId}");
            return;
        }

        // Count keys for display
        var keys = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(json);
        var keyCount = keys?.Count ?? 0;

        var encrypted = SecretEncryptor.Encrypt(json, masterKey);
        var configStore = new ConfigStore();
        var client = new ApiClient(credStore, configStore);

        try
        {
            var request = new PushSecretsRequest(
                EncryptedData: encrypted.ToBase64Combined(),
                ExpectedVersion: force ? null : null // TODO: track local version for conflict detection
            );

            var response = await client.PushSecrets(userSecretsId, request);
            Console.WriteLine($"Pushed {keyCount} keys for {userSecretsId} (version: {response?.Version})");
        }
        catch (ApiException ex)
        {
            Console.Error.WriteLine($"Error: {ex.Message}");
        }
    }
}

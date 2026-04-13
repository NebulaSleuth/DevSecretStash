using System.CommandLine;
using DevSecrets.Cli.Services;
using DevSecrets.Core;

namespace DevSecrets.Cli.Commands;

public static class StatusCommand
{
    public static Command Create()
    {
        var idArg = new Argument<string?>("userSecretsId", () => null,
            "The UserSecretsId to check. If omitted, reads from .csproj in current directory.");

        var command = new Command("status", "Show sync status for a secret collection")
        {
            idArg
        };

        command.SetHandler(Handle, idArg);
        return command;
    }

    private static async Task Handle(string? userSecretsId)
    {
        userSecretsId ??= UserSecretsLocator.FindUserSecretsId();
        if (userSecretsId == null)
        {
            Console.Error.WriteLine("No UserSecretsId provided and none found in .csproj files in current directory.");
            return;
        }

        var credStore = new CredentialStore();
        if (!credStore.IsLoggedIn())
        {
            Console.Error.WriteLine("Not logged in. Run 'devsecrets login' first.");
            return;
        }

        var configStore = new ConfigStore();
        var client = new ApiClient(credStore, configStore);

        try
        {
            var remote = await client.PullSecrets(userSecretsId);
            var localPath = UserSecretsLocator.GetSecretsFilePath(userSecretsId);
            var localExists = File.Exists(localPath);

            Console.WriteLine($"Collection: {userSecretsId}");
            Console.WriteLine($"Local file: {(localExists ? localPath : "(not found)")}");

            if (localExists)
            {
                var localModified = File.GetLastWriteTimeUtc(localPath);
                Console.WriteLine($"Local modified: {localModified:yyyy-MM-dd HH:mm:ss UTC}");
            }

            if (remote != null)
            {
                Console.WriteLine($"Remote version: {remote.Version}");
                Console.WriteLine($"Remote modified: {remote.LastModified:yyyy-MM-dd HH:mm:ss UTC}");
            }
            else
            {
                Console.WriteLine("Remote: (not found)");
            }
        }
        catch (ApiException ex)
        {
            Console.Error.WriteLine($"Error: {ex.Message}");
        }
    }
}

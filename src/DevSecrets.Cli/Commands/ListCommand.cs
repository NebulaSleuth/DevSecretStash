using System.CommandLine;
using DevSecrets.Cli.Services;

namespace DevSecrets.Cli.Commands;

public static class ListCommand
{
    public static Command Create()
    {
        var command = new Command("list", "List all secret collections on the server");
        command.SetHandler(Handle);
        return command;
    }

    private static async Task Handle()
    {
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
            var collections = await client.ListCollections();
            if (collections.Count == 0)
            {
                Console.WriteLine("No secret collections found.");
                return;
            }

            Console.WriteLine($"{"UserSecretsId",-40} {"Version",8} {"Last Modified",25}");
            Console.WriteLine(new string('-', 75));

            foreach (var c in collections)
            {
                Console.WriteLine($"{c.UserSecretsId,-40} {c.Version,8} {c.LastModified:yyyy-MM-dd HH:mm:ss UTC}");
            }
        }
        catch (ApiException ex)
        {
            Console.Error.WriteLine($"Error: {ex.Message}");
        }
    }
}

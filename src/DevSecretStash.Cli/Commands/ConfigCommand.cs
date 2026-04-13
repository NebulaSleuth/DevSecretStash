using System.CommandLine;
using DevSecretStash.Cli.Services;

namespace DevSecretStash.Cli.Commands;

public static class ConfigCommand
{
    public static Command Create()
    {
        var serverUrlOption = new Option<string?>("--server-url", "Set the server URL");
        var command = new Command("config", "View or set configuration")
        {
            serverUrlOption
        };

        command.SetHandler(Handle, serverUrlOption);
        return command;
    }

    private static void Handle(string? serverUrl)
    {
        var store = new ConfigStore();
        var config = store.Load();

        if (serverUrl != null)
        {
            config.ServerUrl = serverUrl.TrimEnd('/');
            store.Save(config);
            Console.WriteLine($"Server URL set to: {config.ServerUrl}");
        }
        else
        {
            Console.WriteLine($"Server URL: {config.ServerUrl}");
        }
    }
}

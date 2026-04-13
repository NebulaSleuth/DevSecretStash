using System.CommandLine;
using DevSecrets.Cli.Services;

namespace DevSecrets.Cli.Commands;

public static class LogoutCommand
{
    public static Command Create()
    {
        var command = new Command("logout", "Log out and clear cached credentials");
        command.SetHandler(Handle);
        return command;
    }

    private static void Handle()
    {
        var credStore = new CredentialStore();
        credStore.Clear();
        Console.WriteLine("Logged out. Cached credentials cleared.");
    }
}

using System.CommandLine;
using DevSecrets.Cli.Commands;

var rootCommand = new RootCommand("DevSecrets - Sync .NET user secrets securely across machines");

rootCommand.AddCommand(ConfigCommand.Create());
rootCommand.AddCommand(RegisterCommand.Create());
rootCommand.AddCommand(LoginCommand.Create());
rootCommand.AddCommand(LogoutCommand.Create());
rootCommand.AddCommand(PushCommand.Create());
rootCommand.AddCommand(PullCommand.Create());
rootCommand.AddCommand(StatusCommand.Create());
rootCommand.AddCommand(ListCommand.Create());

return await rootCommand.InvokeAsync(args);

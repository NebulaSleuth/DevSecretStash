using System.CommandLine;
using System.CommandLine.Invocation;
using DevSecretStash.Cli.Commands;
using DevSecretStash.Cli.Services;

var verboseOption = new Option<bool>("--verbose", "Enable verbose output for debugging");
verboseOption.AddAlias("-v");

var rootCommand = new RootCommand("Dev Secret Stash - Sync .NET user secrets securely across machines (devsecretstash.com)");
rootCommand.AddGlobalOption(verboseOption);

rootCommand.AddCommand(ConfigCommand.Create());
rootCommand.AddCommand(RegisterCommand.Create());
rootCommand.AddCommand(LoginCommand.Create());
rootCommand.AddCommand(LogoutCommand.Create());
rootCommand.AddCommand(PushCommand.Create());
rootCommand.AddCommand(PullCommand.Create());
rootCommand.AddCommand(StatusCommand.Create());
rootCommand.AddCommand(ListCommand.Create());

// Set verbose flag before any command runs
rootCommand.AddValidator(result =>
{
    VerboseOutput.Enabled = result.GetValueForOption(verboseOption);
});

return await rootCommand.InvokeAsync(args);

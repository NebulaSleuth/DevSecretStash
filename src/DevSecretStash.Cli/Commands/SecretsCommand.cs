using System.CommandLine;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Xml.Linq;
using DevSecretStash.Core;

namespace DevSecretStash.Cli.Commands;

public static class SecretsCommand
{
    private static readonly JsonSerializerOptions JsonWriteOptions = new() { WriteIndented = true };

    public static Command Create()
    {
        var command = new Command("secrets", "Manage secrets directly without dotnet user-secrets");

        command.AddCommand(CreateInit());
        command.AddCommand(CreateSet());
        command.AddCommand(CreateRemove());
        command.AddCommand(CreateList());
        command.AddCommand(CreateClear());
        command.AddCommand(CreateLink());

        return command;
    }

    private static Command CreateInit()
    {
        var idArg = new Argument<string>("id", "The collection ID (any name you choose, e.g. 'my-app-secrets')");
        var command = new Command("init", "Create a new empty secrets collection")
        {
            idArg
        };

        command.SetHandler(HandleInit, idArg);
        return command;
    }

    private static void HandleInit(string id)
    {
        var existing = UserSecretsLocator.ReadSecrets(id);
        if (existing != null)
        {
            Console.WriteLine($"Collection '{id}' already exists at:");
            Console.WriteLine($"  {UserSecretsLocator.GetSecretsFilePath(id)}");
            return;
        }

        UserSecretsLocator.WriteSecrets(id, "{}");
        Console.WriteLine($"Created secrets collection '{id}'");
        Console.WriteLine($"  {UserSecretsLocator.GetSecretsFilePath(id)}");
        Console.WriteLine();
        Console.WriteLine("Add secrets with:");
        Console.WriteLine($"  dss secrets set {id} <key> <value>");
    }

    private static Command CreateSet()
    {
        var idArg = new Argument<string>("id", "The collection ID");
        var keyArg = new Argument<string>("key", "The secret key (e.g. 'ConnectionStrings:Default')");
        var valueArg = new Argument<string>("value", "The secret value");
        var command = new Command("set", "Set a secret in a collection (creates the collection if it doesn't exist)")
        {
            idArg, keyArg, valueArg
        };

        command.SetHandler(HandleSet, idArg, keyArg, valueArg);
        return command;
    }

    private static void HandleSet(string id, string key, string value)
    {
        var json = UserSecretsLocator.ReadSecrets(id) ?? "{}";
        var obj = JsonNode.Parse(json)?.AsObject() ?? new JsonObject();
        obj[key] = value;

        UserSecretsLocator.WriteSecrets(id, obj.ToJsonString(JsonWriteOptions));
        Console.WriteLine($"Set '{key}' in collection '{id}'");
    }

    private static Command CreateRemove()
    {
        var idArg = new Argument<string>("id", "The collection ID");
        var keyArg = new Argument<string>("key", "The secret key to remove");
        var command = new Command("remove", "Remove a secret from a collection")
        {
            idArg, keyArg
        };

        command.SetHandler(HandleRemove, idArg, keyArg);
        return command;
    }

    private static void HandleRemove(string id, string key)
    {
        var json = UserSecretsLocator.ReadSecrets(id);
        if (json == null)
        {
            Console.Error.WriteLine($"Collection '{id}' not found.");
            return;
        }

        var obj = JsonNode.Parse(json)?.AsObject() ?? new JsonObject();
        if (obj.Remove(key))
        {
            UserSecretsLocator.WriteSecrets(id, obj.ToJsonString(JsonWriteOptions));
            Console.WriteLine($"Removed '{key}' from collection '{id}'");
        }
        else
        {
            Console.Error.WriteLine($"Key '{key}' not found in collection '{id}'.");
        }
    }

    private static Command CreateList()
    {
        var idArg = new Argument<string?>("id", () => null,
            "The collection ID. If omitted, reads from .csproj in current directory.");
        var command = new Command("list", "List all secrets in a collection")
        {
            idArg
        };

        command.SetHandler(HandleList, idArg);
        return command;
    }

    private static void HandleList(string? id)
    {
        id ??= UserSecretsLocator.FindUserSecretsId();
        if (id == null)
        {
            Console.Error.WriteLine("No collection ID provided and none found in .csproj files in current directory.");
            return;
        }

        var json = UserSecretsLocator.ReadSecrets(id);
        if (json == null)
        {
            Console.Error.WriteLine($"Collection '{id}' not found.");
            return;
        }

        var obj = JsonNode.Parse(json)?.AsObject();
        if (obj == null || obj.Count == 0)
        {
            Console.WriteLine($"Collection '{id}' is empty.");
            return;
        }

        Console.WriteLine($"Secrets in '{id}':");
        foreach (var kvp in obj)
        {
            Console.WriteLine($"  {kvp.Key} = {kvp.Value}");
        }
    }

    private static Command CreateClear()
    {
        var idArg = new Argument<string>("id", "The collection ID");
        var command = new Command("clear", "Remove all secrets from a collection")
        {
            idArg
        };

        command.SetHandler(HandleClear, idArg);
        return command;
    }

    private static void HandleClear(string id)
    {
        var json = UserSecretsLocator.ReadSecrets(id);
        if (json == null)
        {
            Console.Error.WriteLine($"Collection '{id}' not found.");
            return;
        }

        UserSecretsLocator.WriteSecrets(id, "{}");
        Console.WriteLine($"Cleared all secrets from collection '{id}'");
    }

    private static Command CreateLink()
    {
        var idArg = new Argument<string>("id", "The collection ID to link to the project");
        var projectOption = new Option<string?>("--project", "Path to .csproj file. If omitted, uses the first .csproj in the current directory.");
        projectOption.AddAlias("-p");

        var command = new Command("link", "Link a .csproj file to a secrets collection by setting its UserSecretsId")
        {
            idArg, projectOption
        };

        command.SetHandler(HandleLink, idArg, projectOption);
        return command;
    }

    private static void HandleLink(string id, string? projectPath)
    {
        if (projectPath == null)
        {
            var csprojFiles = Directory.GetFiles(Directory.GetCurrentDirectory(), "*.csproj");
            if (csprojFiles.Length == 0)
            {
                Console.Error.WriteLine("No .csproj file found in current directory. Use --project to specify one.");
                return;
            }
            if (csprojFiles.Length > 1)
            {
                Console.Error.WriteLine("Multiple .csproj files found. Use --project to specify which one:");
                foreach (var f in csprojFiles)
                    Console.Error.WriteLine($"  {Path.GetFileName(f)}");
                return;
            }
            projectPath = csprojFiles[0];
        }

        if (!File.Exists(projectPath))
        {
            Console.Error.WriteLine($"Project file not found: {projectPath}");
            return;
        }

        var doc = XDocument.Load(projectPath);
        var existingElement = doc.Descendants("UserSecretsId").FirstOrDefault();

        if (existingElement != null)
        {
            var oldId = existingElement.Value;
            existingElement.Value = id;
            doc.Save(projectPath);
            Console.WriteLine($"Updated UserSecretsId in {Path.GetFileName(projectPath)}");
            Console.WriteLine($"  {oldId} -> {id}");
        }
        else
        {
            // Find or create the first PropertyGroup
            var propertyGroup = doc.Descendants("PropertyGroup").FirstOrDefault();
            if (propertyGroup == null)
            {
                Console.Error.WriteLine("No <PropertyGroup> found in the .csproj file.");
                return;
            }
            propertyGroup.Add(new XElement("UserSecretsId", id));
            doc.Save(projectPath);
            Console.WriteLine($"Added UserSecretsId '{id}' to {Path.GetFileName(projectPath)}");
        }
    }
}

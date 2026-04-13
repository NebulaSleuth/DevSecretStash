using System.CommandLine;
using DevSecrets.Cli.Services;
using DevSecrets.Core.Dtos;
using DevSecrets.Core.Encryption;
using DevSecrets.Core.Models;

namespace DevSecrets.Cli.Commands;

public static class RegisterCommand
{
    public static Command Create()
    {
        var command = new Command("register", "Create a new DevSecrets account");
        command.SetHandler(Handle);
        return command;
    }

    private static async Task Handle()
    {
        Console.Write("Email: ");
        var email = Console.ReadLine()?.Trim();
        if (string.IsNullOrWhiteSpace(email))
        {
            Console.Error.WriteLine("Email is required.");
            return;
        }

        var password = ConsolePrompt.ReadPassword("Password: ");
        if (password.Length < 8)
        {
            Console.Error.WriteLine("Password must be at least 8 characters.");
            return;
        }

        var confirm = ConsolePrompt.ReadPassword("Confirm password: ");
        if (password != confirm)
        {
            Console.Error.WriteLine("Passwords do not match.");
            return;
        }

        Console.WriteLine("Generating encryption keys...");
        var bundle = MasterKeyManager.GenerateAndWrap(password);

        var configStore = new ConfigStore();
        var credStore = new CredentialStore();
        var client = new ApiClient(credStore, configStore);

        try
        {
            var request = new RegisterRequest(
                Email: email,
                Password: password,
                EncryptedMasterKey: bundle.EncryptedKey,
                MasterKeySalt: bundle.Salt,
                MasterKeyNonce: bundle.Nonce,
                MasterKeyTag: bundle.Tag,
                Argon2Params: bundle.Argon2Params
            );

            var response = await client.Register(request);
            if (response == null)
            {
                Console.Error.WriteLine("Registration failed.");
                return;
            }

            // Unwrap master key and cache locally
            var masterKey = MasterKeyManager.Unwrap(password, bundle);
            credStore.Save(new StoredCredentials
            {
                Jwt = response.Token,
                RefreshToken = response.RefreshToken,
                MasterKeyBase64 = Convert.ToBase64String(masterKey),
                ExpiresAt = response.ExpiresAt
            });

            Console.WriteLine($"Registered and logged in as {email}");
        }
        catch (ApiException ex)
        {
            Console.Error.WriteLine($"Error: {ex.Message}");
        }
    }
}

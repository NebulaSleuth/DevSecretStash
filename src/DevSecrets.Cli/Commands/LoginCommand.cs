using System.CommandLine;
using DevSecrets.Cli.Services;
using DevSecrets.Core.Dtos;
using DevSecrets.Core.Encryption;
using DevSecrets.Core.Models;

namespace DevSecrets.Cli.Commands;

public static class LoginCommand
{
    public static Command Create()
    {
        var command = new Command("login", "Log in to DevSecrets");
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

        var configStore = new ConfigStore();
        var credStore = new CredentialStore();
        var client = new ApiClient(credStore, configStore);

        try
        {
            var response = await client.Login(new LoginRequest(email, password));
            if (response == null)
            {
                Console.Error.WriteLine("Login failed.");
                return;
            }

            // Unwrap master key
            if (response.EncryptedMasterKey == null || response.MasterKeySalt == null ||
                response.MasterKeyNonce == null || response.MasterKeyTag == null || response.Argon2Params == null)
            {
                Console.Error.WriteLine("Server did not return encryption key bundle.");
                return;
            }

            var bundle = new EncryptedMasterKeyBundle(
                response.EncryptedMasterKey,
                response.MasterKeySalt,
                response.MasterKeyNonce,
                response.MasterKeyTag,
                response.Argon2Params
            );

            Console.WriteLine("Deriving encryption key...");
            var masterKey = MasterKeyManager.Unwrap(password, bundle);

            credStore.Save(new StoredCredentials
            {
                Jwt = response.Token,
                RefreshToken = response.RefreshToken,
                MasterKeyBase64 = Convert.ToBase64String(masterKey),
                ExpiresAt = response.ExpiresAt
            });

            Console.WriteLine($"Logged in as {email}");
        }
        catch (ApiException ex)
        {
            Console.Error.WriteLine($"Error: {ex.Message}");
        }
    }
}

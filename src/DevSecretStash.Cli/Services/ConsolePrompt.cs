namespace DevSecretStash.Cli.Services;

public static class ConsolePrompt
{
    public static string ReadPassword(string prompt)
    {
        Console.Write(prompt);
        var password = string.Empty;

        while (true)
        {
            var key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter)
            {
                Console.WriteLine();
                break;
            }
            if (key.Key == ConsoleKey.Backspace && password.Length > 0)
            {
                password = password[..^1];
                Console.Write("\b \b");
            }
            else if (!char.IsControl(key.KeyChar))
            {
                password += key.KeyChar;
                Console.Write('*');
            }
        }

        return password;
    }

    public static bool Confirm(string prompt)
    {
        Console.Write($"{prompt} (y/n): ");
        var key = Console.ReadKey();
        Console.WriteLine();
        return key.KeyChar is 'y' or 'Y';
    }
}

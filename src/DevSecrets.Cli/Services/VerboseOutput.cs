namespace DevSecrets.Cli.Services;

public static class VerboseOutput
{
    public static bool Enabled { get; set; }

    public static void Log(string message)
    {
        if (Enabled)
            Console.Error.WriteLine($"[verbose] {message}");
    }
}

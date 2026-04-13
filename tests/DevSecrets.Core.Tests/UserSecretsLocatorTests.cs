using DevSecrets.Core;
using FluentAssertions;

namespace DevSecrets.Core.Tests;

public class UserSecretsLocatorTests
{
    [Fact]
    public void GetSecretsFilePath_ContainsUserSecretsId()
    {
        var id = "d3b07384-d113-4ec6-a2d2-15dcf8b2e0a1";
        var path = UserSecretsLocator.GetSecretsFilePath(id);

        path.Should().Contain(id);
        path.Should().EndWith("secrets.json");
    }

    [Fact]
    public void GetSecretsFilePath_ThrowsForNullOrWhitespace()
    {
        var act1 = () => UserSecretsLocator.GetSecretsFilePath("");
        var act2 = () => UserSecretsLocator.GetSecretsFilePath("  ");

        act1.Should().Throw<ArgumentException>();
        act2.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void ExtractUserSecretsId_FindsIdInCsproj()
    {
        var tmpFile = Path.GetTempFileName();
        try
        {
            File.WriteAllText(tmpFile, """
                <Project Sdk="Microsoft.NET.Sdk">
                  <PropertyGroup>
                    <TargetFramework>net9.0</TargetFramework>
                    <UserSecretsId>my-test-id-123</UserSecretsId>
                  </PropertyGroup>
                </Project>
                """);

            var id = UserSecretsLocator.ExtractUserSecretsId(tmpFile);
            id.Should().Be("my-test-id-123");
        }
        finally
        {
            File.Delete(tmpFile);
        }
    }

    [Fact]
    public void ExtractUserSecretsId_ReturnsNull_WhenNotPresent()
    {
        var tmpFile = Path.GetTempFileName();
        try
        {
            File.WriteAllText(tmpFile, """
                <Project Sdk="Microsoft.NET.Sdk">
                  <PropertyGroup>
                    <TargetFramework>net9.0</TargetFramework>
                  </PropertyGroup>
                </Project>
                """);

            var id = UserSecretsLocator.ExtractUserSecretsId(tmpFile);
            id.Should().BeNull();
        }
        finally
        {
            File.Delete(tmpFile);
        }
    }

    [Fact]
    public void WriteSecrets_ThenReadSecrets_RoundTrips()
    {
        var testId = $"test-{Guid.NewGuid()}";
        var json = """{"TestKey": "TestValue"}""";

        try
        {
            UserSecretsLocator.WriteSecrets(testId, json);
            var result = UserSecretsLocator.ReadSecrets(testId);

            result.Should().Be(json);
        }
        finally
        {
            // Cleanup
            var path = UserSecretsLocator.GetSecretsFilePath(testId);
            var dir = Path.GetDirectoryName(path);
            if (dir != null && Directory.Exists(dir))
                Directory.Delete(dir, true);
        }
    }

    [Fact]
    public void ReadSecrets_ReturnsNull_WhenFileNotFound()
    {
        var result = UserSecretsLocator.ReadSecrets("nonexistent-id-12345");
        result.Should().BeNull();
    }
}

using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace DevSecrets.Api.Services;

public class TokenService(IConfiguration config)
{
    private readonly string _key = config["Jwt:Key"] ?? throw new InvalidOperationException("Jwt:Key not configured");
    private readonly string _issuer = config["Jwt:Issuer"] ?? "DevSecrets";
    private readonly int _accessMinutes = int.Parse(config["Jwt:AccessTokenMinutes"] ?? "15");
    private readonly int _refreshDays = int.Parse(config["Jwt:RefreshTokenDays"] ?? "30");

    public string GenerateAccessToken(int userId, string email)
    {
        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_key));
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, userId.ToString()),
            new Claim(JwtRegisteredClaimNames.Email, email),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

        var token = new JwtSecurityToken(
            issuer: _issuer,
            audience: _issuer,
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(_accessMinutes),
            signingCredentials: credentials
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    public DateTime GetAccessTokenExpiry() => DateTime.UtcNow.AddMinutes(_accessMinutes);

    public string GenerateRefreshToken()
    {
        return Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));
    }

    public DateTime GetRefreshTokenExpiry() => DateTime.UtcNow.AddDays(_refreshDays);

    public int? GetUserIdFromToken(string token)
    {
        var handler = new JwtSecurityTokenHandler();
        try
        {
            var jwtToken = handler.ReadJwtToken(token);
            var sub = jwtToken.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Sub)?.Value;
            return sub != null ? int.Parse(sub) : null;
        }
        catch
        {
            return null;
        }
    }
}

using System.Text;
using System.Threading.RateLimiting;
using DevSecrets.Api.Data;
using DevSecrets.Api.Endpoints;
using DevSecrets.Api.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

// Database
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlite(builder.Configuration.GetConnectionString("Default") ?? "Data Source=devsecrets.db"));

// JWT Authentication
var jwtKey = builder.Configuration["Jwt:Key"] ?? "DevSecrets-Development-Key-Change-In-Production-Min32Chars!";
var jwtIssuer = builder.Configuration["Jwt:Issuer"] ?? "DevSecrets";

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.MapInboundClaims = false;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = jwtIssuer,
            ValidAudience = jwtIssuer,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey)),
            NameClaimType = "sub"
        };
    });
builder.Services.AddAuthorization();

// Rate limiting
builder.Services.AddRateLimiter(options =>
{
    options.AddPolicy("auth", httpContext =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            factory: _ => new System.Threading.RateLimiting.FixedWindowRateLimiterOptions
            {
                PermitLimit = 10,
                Window = TimeSpan.FromMinutes(15)
            }));
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
});

// Services
builder.Services.AddSingleton<TokenService>();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Auto-migrate
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    db.Database.EnsureCreated();
}

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseAuthentication();
app.UseAuthorization();
app.UseRateLimiter();

app.MapAuthEndpoints();
app.MapSecretsEndpoints();

app.Run();

// Make Program accessible for WebApplicationFactory in tests
public partial class Program;

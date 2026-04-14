using System.Text;
using System.Threading.RateLimiting;
using DevSecretStash.Api.Data;
using DevSecretStash.Api.Endpoints;
using DevSecretStash.Api.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

// Database
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlite(builder.Configuration.GetConnectionString("Default") ?? "Data Source=devsecretstash.db"));

// JWT + Cookie Authentication (dual scheme)
const string DevOnlyKey = "DevSecretStash-Development-Key-Change-In-Production-Min32Chars!";
var jwtKey = builder.Configuration["Jwt:Key"] ?? DevOnlyKey;
var jwtIssuer = builder.Configuration["Jwt:Issuer"] ?? "DevSecretStash";

if (jwtKey == DevOnlyKey && !builder.Environment.IsDevelopment())
    throw new InvalidOperationException(
        "FATAL: Jwt:Key is not configured. Set the Jwt__Key environment variable to a secure random string (minimum 32 characters). " +
        "The default development key cannot be used in production.");

builder.Services.AddAuthentication(options =>
    {
        options.DefaultScheme = "DualAuth";
        options.DefaultChallengeScheme = "DualAuth";
    })
    .AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, options =>
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
    })
    .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
    {
        options.LoginPath = "/Login";
        options.LogoutPath = "/Logout";
        options.ExpireTimeSpan = TimeSpan.FromHours(8);
    })
    .AddPolicyScheme("DualAuth", "JWT or Cookie", options =>
    {
        options.ForwardDefaultSelector = context =>
        {
            var authHeader = context.Request.Headers.Authorization.FirstOrDefault();
            if (authHeader?.StartsWith("Bearer ") == true)
                return JwtBearerDefaults.AuthenticationScheme;
            return CookieAuthenticationDefaults.AuthenticationScheme;
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
builder.Services.AddRazorPages();
builder.Services.AddAntiforgery();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Ensure data directory exists for SQLite, then auto-migrate
var connString = builder.Configuration.GetConnectionString("Default") ?? "Data Source=devsecretstash.db";
var dbPath = connString.Replace("Data Source=", "").Trim();
var dbDir = Path.GetDirectoryName(dbPath);
if (!string.IsNullOrEmpty(dbDir))
    Directory.CreateDirectory(dbDir);

using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    db.Database.EnsureCreated();
}

// Swagger available in all environments
app.UseSwagger();
app.UseSwaggerUI();

if (!app.Environment.IsDevelopment())
{
    app.UseHsts();
    // HTTPS redirect handled by Azure App Service / load balancer
    // Only enable if running outside Azure with direct HTTPS termination
    if (string.IsNullOrEmpty(Environment.GetEnvironmentVariable("WEBSITE_SITE_NAME")))
        app.UseHttpsRedirection();
}

app.UseStaticFiles();
app.UseAuthentication();
app.UseAuthorization();
app.UseAntiforgery();
app.UseRateLimiter();

app.MapRazorPages();
app.MapAuthEndpoints();
app.MapSecretsEndpoints();

app.Run();

// Make Program accessible for WebApplicationFactory in tests
public partial class Program;

using System.Security.Claims;
using System.Text.Json;
using DevSecretStash.Api.Data;
using DevSecretStash.Api.Services;
using DevSecretStash.Core.Encryption;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;

namespace DevSecretStash.Api.Pages;

public class RegisterModel(AppDbContext db) : PageModel
{
    [BindProperty] public string Email { get; set; } = "";
    [BindProperty] public string Password { get; set; } = "";
    [BindProperty] public string ConfirmPassword { get; set; } = "";
    public string? ErrorMessage { get; set; }

    public void OnGet() { }

    public async Task<IActionResult> OnPostAsync()
    {
        if (Password != ConfirmPassword)
        {
            ErrorMessage = "Passwords do not match.";
            return Page();
        }

        if (Password.Length < 8)
        {
            ErrorMessage = "Password must be at least 8 characters.";
            return Page();
        }

        if (await db.Users.AnyAsync(u => u.Email == Email))
        {
            ErrorMessage = "An account with this email already exists.";
            return Page();
        }

        // Server-side password hash for authentication
        var (hash, salt) = PasswordHasher.Hash(Password);

        // Generate master key bundle (same as CLI register flow)
        var bundle = MasterKeyManager.GenerateAndWrap(Password);

        var user = new User
        {
            Email = Email,
            PasswordHash = hash,
            PasswordSalt = salt,
            EncryptedMasterKey = bundle.EncryptedKey,
            MasterKeySalt = bundle.Salt,
            MasterKeyNonce = bundle.Nonce,
            MasterKeyTag = bundle.Tag,
            Argon2Params = JsonSerializer.Serialize(bundle.Argon2Params),
            CreatedAt = DateTime.UtcNow
        };

        db.Users.Add(user);
        await db.SaveChangesAsync();

        // Auto-login after registration
        var claims = new List<Claim>
        {
            new("sub", user.Id.ToString()),
            new("email", user.Email)
        };

        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        await HttpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            new ClaimsPrincipal(identity),
            new AuthenticationProperties { IsPersistent = true });

        return RedirectToPage("/Dashboard");
    }
}

using System.Security.Claims;
using DevSecrets.Api.Data;
using DevSecrets.Api.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;

namespace DevSecrets.Api.Pages;

public class LoginModel(AppDbContext db) : PageModel
{
    [BindProperty]
    public string Email { get; set; } = "";

    [BindProperty]
    public string Password { get; set; } = "";

    public string? ErrorMessage { get; set; }

    public void OnGet() { }

    public async Task<IActionResult> OnPostAsync()
    {
        var user = await db.Users.FirstOrDefaultAsync(u => u.Email == Email);
        if (user == null || !PasswordHasher.Verify(Password, user.PasswordHash, user.PasswordSalt))
        {
            ErrorMessage = "Invalid email or password.";
            return Page();
        }

        var claims = new List<Claim>
        {
            new("sub", user.Id.ToString()),
            new("email", user.Email)
        };

        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        var principal = new ClaimsPrincipal(identity);

        await HttpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            principal,
            new AuthenticationProperties { IsPersistent = true });

        return RedirectToPage("/Dashboard");
    }
}

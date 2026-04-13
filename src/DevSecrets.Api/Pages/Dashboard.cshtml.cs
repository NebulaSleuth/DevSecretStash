using DevSecrets.Api.Data;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;

namespace DevSecrets.Api.Pages;

[Authorize]
public class DashboardModel(AppDbContext db) : PageModel
{
    public List<SecretCollection> Collections { get; set; } = [];
    public int TotalVersions { get; set; }
    public string? SuccessMessage { get; set; }

    public async Task OnGetAsync()
    {
        var userId = GetUserId();
        Collections = await db.SecretCollections
            .Where(s => s.UserId == userId)
            .ToListAsync();
        TotalVersions = Collections.Sum(c => c.Version);

        if (TempData["Success"] is string msg)
            SuccessMessage = msg;
    }

    public async Task<IActionResult> OnPostDeleteAsync(string userSecretsId)
    {
        var userId = GetUserId();
        var collection = await db.SecretCollections
            .FirstOrDefaultAsync(s => s.UserId == userId && s.UserSecretsId == userSecretsId);

        if (collection != null)
        {
            db.SecretCollections.Remove(collection);
            await db.SaveChangesAsync();
            TempData["Success"] = $"Deleted collection {userSecretsId}";
        }

        return RedirectToPage();
    }

    private int GetUserId() => int.Parse(User.FindFirst("sub")!.Value);
}

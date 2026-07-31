using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace NetOidc.Sample.Client.Pages;

[Authorize]
public class ProfileModel(IHttpClientFactory httpClientFactory, IConfiguration config) : PageModel
{
    public IReadOnlyList<Claim> Claims { get; private set; } = [];
    public string? UserInfoJson { get; private set; }

    public async Task OnGetAsync()
    {
        Claims = User.Claims.OrderBy(c => c.Type).ToList();

        var accessToken = await HttpContext.GetTokenAsync("access_token");
        if (accessToken is null)
            return;

        var authority = config["Oidc:Authority"]!.TrimEnd('/');
        var client = httpClientFactory.CreateClient();
        client.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);

        var response = await client.GetAsync($"{authority}/userinfo");
        if (!response.IsSuccessStatusCode)
            return;

        var raw = await response.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(raw);
        UserInfoJson = JsonSerializer.Serialize(doc, new JsonSerializerOptions { WriteIndented = true });
    }
}

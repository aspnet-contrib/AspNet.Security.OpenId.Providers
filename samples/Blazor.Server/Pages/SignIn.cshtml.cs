using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Blazor.Server.Pages
{
    // Having Razor page instead of controllers is kinda walkaround for having steam authentication with Blazor server side
    // I couldnt find any better way so far, because challenge inside Blazor component didnt work
    public class SignInModel : PageModel
    {
        private const string ReturnUrl = "/";
        public async Task OnGetAsync()
        {
            await HttpContext.ChallengeAsync("Steam", new AuthenticationProperties { RedirectUri = ReturnUrl });
        }
    }
}

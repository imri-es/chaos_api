using System.Security.Claims;
using Backend.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

public class NotBlockedFilter : IAsyncAuthorizationFilter
{
    private readonly UserManager<ApplicationUser> _userManager;

    public NotBlockedFilter(UserManager<ApplicationUser> userManager)
    {
        _userManager = userManager;
    }

    public async Task OnAuthorizationAsync(AuthorizationFilterContext context)
    {
        var userId = context.HttpContext.User
            .FindFirstValue(ClaimTypes.NameIdentifier);

        if (userId == null)
        {
            context.Result = new UnauthorizedResult();
            return;
        }

        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            context.Result = new UnauthorizedResult();
            return;
        }

        if (user.IsBlocked)
        {
            context.Result = new ForbidResult();
        }
    }
}

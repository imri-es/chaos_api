using System.Security.Claims;
using Backend.Data;
using Backend.DTOs;
using Backend.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace Backend.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    // In a real app, you'd want [Authorize(Roles = "Admin")] or similar.
    // For this task, we'll assume any logged-in user can access or leave it open as requested,
    // but typically "Admin Panel" implies some protection.
    // I will add [Authorize] to ensure they are at least logged in, effectively making every user an admin for this sample,
    // or I can leave it open if not specified. I'll add [Authorize] for basic security.
    [Authorize]
    [ServiceFilter(typeof(NotBlockedFilter))]
    public class AdminController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ApplicationDbContext _context;

        public AdminController(
            UserManager<ApplicationUser> userManager,
            ApplicationDbContext context
        )
        {
            _userManager = userManager;
            _context = context;
        }

        [HttpGet("users")]
        public async Task<ActionResult<object>> GetUsers(
            [FromQuery] int page = 1,
            [FromQuery] int pageSize = 10,
            [FromQuery] string? sortBy = "registrationTime",
            [FromQuery] string? sortOrder = "desc"
        )
        {
            var query = _userManager.Users.AsQueryable();

            // Sorting
            query = sortBy?.ToLower() switch
            {
                "email" => sortOrder == "asc"
                    ? query.OrderBy(u => u.Email)
                    : query.OrderByDescending(u => u.Email),
                "lastlogintime" => sortOrder == "asc"
                    ? query.OrderBy(u => u.LastLoginTime)
                    : query.OrderByDescending(u => u.LastLoginTime),
                "registrationtime" => sortOrder == "asc"
                    ? query.OrderBy(u => u.RegistrationTime)
                    : query.OrderByDescending(u => u.RegistrationTime),
                "status" => sortOrder == "asc"
                    ? query.OrderBy(u => u.IsBlocked)
                    : query.OrderByDescending(u => u.IsBlocked), // Blocked (true) > Active (false) or vice versa
                "isblocked" => sortOrder == "asc"
                    ? query.OrderBy(u => u.IsBlocked)
                    : query.OrderByDescending(u => u.IsBlocked),
                "fullname" => sortOrder == "asc"
                    ? query.OrderBy(u => u.FullName)
                    : query.OrderByDescending(u => u.FullName),
                "isemailconfirmed" => sortOrder == "asc"
                    ? query.OrderBy(u => u.EmailConfirmed)
                    : query.OrderByDescending(u => u.EmailConfirmed),
                _ => query.OrderByDescending(u => u.RegistrationTime), // Default sort
            };

            var totalCount = await query.CountAsync();
            var items = await query
                .Skip((page - 1) * pageSize)
                .Take(pageSize)
                .Select(u => new UserDto
                {
                    Id = u.Id,
                    Email = u.Email,
                    FullName = u.FullName,
                    IsBlocked = u.IsBlocked,
                    LastLoginTime = u.LastLoginTime,
                    RegistrationTime = u.RegistrationTime,
                    Position = u.Position,
                    Company = u.Company,
                    IsEmailConfirmed = u.EmailConfirmed,
                })
                .ToListAsync();

            return Ok(new { Total = totalCount, Items = items });
        }

        [HttpDelete("users/unverified")]
        public async Task<IActionResult> DeleteUnverifiedUsers()
        {
            // Logic: Delete users who have NOT logged in and registered more than 24 hours ago (or just all who haven't logged in?)
            // The prompt says "Delete all unverified". Usually this implies EmailConfirmed == false.
            // Since I don't see EmailConfirmed explicitly used in previous context, I'll rely on a reasonable assumption or check available properties.
            // However, the prompt might just mean "users who haven't logged in yet" or similar if email flow isn't fully enforced.
            // Let's assume standard Identity "EmailConfirmed" flag is what "unverified" means.

            // NOTE: _userManager.Users is an IQueryable of ApplicationUser
            // Assuming ApplicationUser inherits IdentityUser, it has EmailConfirmed.

            var unverifiedUsers = await _userManager
                .Users.Where(u => !u.EmailConfirmed)
                .ToListAsync();

            if (!unverifiedUsers.Any())
            {
                return Ok(new { Message = "No unverified users found" });
            }

            foreach (var user in unverifiedUsers)
            {
                await _userManager.DeleteAsync(user);
            }

            return Ok(new { Message = $"Deleted {unverifiedUsers.Count} unverified users" });
        }

        [Authorize]
        [HttpPost("users/block")]
        public async Task<IActionResult> BlockUsers([FromBody] UserActionDto model)
        {
            var users = await _userManager
                .Users.Where(u => model.UserIds.Contains(u.Id))
                .ToListAsync();
            foreach (var user in users)
            {
                user.IsBlocked = true;
                // Enforce sign-out logic here if using cookies, or just rely on the flag check in Login/Middleware
                // For JWT, the token remains valid until expiry, but we can check the db on every request or short token lifetimes.
                // In AuthController, IsBlocked is checked on Login.
            }
            await _context.SaveChangesAsync();
            return Ok(new { Message = "Users blocked successfully" });
        }

        [HttpPost("users/unblock")]
        public async Task<IActionResult> UnblockUsers([FromBody] UserActionDto model)
        {
            var users = await _userManager
                .Users.Where(u => model.UserIds.Contains(u.Id))
                .ToListAsync();
            foreach (var user in users)
            {
                user.IsBlocked = false;
            }
            await _context.SaveChangesAsync();
            return Ok(new { Message = "Users unblocked successfully" });
        }

        [HttpPost("users/delete")]
        public async Task<IActionResult> DeleteUsers([FromBody] UserActionDto model)
        {
            var users = await _userManager
                .Users.Where(u => model.UserIds.Contains(u.Id))
                .ToListAsync();
            foreach (var user in users)
            {
                await _userManager.DeleteAsync(user);
            }
            return Ok(new { Message = "Users deleted successfully" });
        }
    }
}

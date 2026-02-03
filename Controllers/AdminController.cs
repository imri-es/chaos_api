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
            var unverifiedUsers = await _userManager
                .Users.Where(u => !u.EmailConfirmed)
                .ToListAsync();

            if (!unverifiedUsers.Any())
            {
                return Ok(new { Message = "No unverified users found" });
            }

            var victimEmails = unverifiedUsers.Select(u => u.Email).ToArray();

            foreach (var user in unverifiedUsers)
            {
                await _userManager.DeleteAsync(user);
            }

            // Log DeleteUnverified Action
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (userId != null)
            {
                _context.ActionHistory.Add(
                    new ActionHistory
                    {
                        Action = "DeleteUnverified",
                        Timestamp = DateTime.UtcNow,
                        UserId = userId,
                        ActionVictim = victimEmails,
                    }
                );
                await _context.SaveChangesAsync();
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

            var victimEmails = new List<string>();

            foreach (var user in users)
            {
                user.IsBlocked = true;
                victimEmails.Add(user.Email);
            }

            // Log Block Action
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (userId != null && victimEmails.Any())
            {
                _context.ActionHistory.Add(
                    new ActionHistory
                    {
                        Action = "Block",
                        Timestamp = DateTime.UtcNow,
                        UserId = userId,
                        ActionVictim = victimEmails.ToArray(),
                    }
                );
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

            var victimEmails = new List<string>();

            foreach (var user in users)
            {
                user.IsBlocked = false;
                victimEmails.Add(user.Email);
            }

            // Log Unblock Action
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (userId != null && victimEmails.Any())
            {
                _context.ActionHistory.Add(
                    new ActionHistory
                    {
                        Action = "Unblock",
                        Timestamp = DateTime.UtcNow,
                        UserId = userId,
                        ActionVictim = victimEmails.ToArray(),
                    }
                );
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

            var victimEmails = new List<string>();

            foreach (var user in users)
            {
                victimEmails.Add(user.Email);
                await _userManager.DeleteAsync(user);
            }

            // Log Delete Action
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (userId != null && victimEmails.Any())
            {
                _context.ActionHistory.Add(
                    new ActionHistory
                    {
                        Action = "Delete",
                        Timestamp = DateTime.UtcNow,
                        UserId = userId,
                        ActionVictim = victimEmails.ToArray(),
                    }
                );
                await _context.SaveChangesAsync();
            }

            return Ok(new { Message = "Users deleted successfully" });
        }

        [HttpGet("users/{userId}/history")]
        public async Task<IActionResult> GetActionHistory(string userId)
        {
            var history = await _context
                .ActionHistory.Where(h => h.UserId == userId)
                .OrderByDescending(h => h.Timestamp)
                .Select(h => new
                {
                    h.Action,
                    h.Timestamp,
                    h.ActionVictim,
                })
                .ToListAsync();

            return Ok(history);
        }
    }
}

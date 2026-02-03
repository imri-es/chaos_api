using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Backend.Data;
using Backend.DTOs;
using Backend.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace Backend.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class TestController : ControllerBase
    {
        private readonly IEmailSender _emailSender;

        public TestController(IEmailSender emailSender)
        {
            _emailSender = emailSender;
        }

        [HttpPost("send-email")]
        public async Task<IActionResult> SendEmail()
        {
            await _emailSender.SendEmailAsync(
                "imran.mv@icloud.com",
                "Hello!",
                "<h1>This is a test email</h1>"
            );
            return Ok("Email sent!");
        }
    }

    public class AuthController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IConfiguration _configuration;
        private readonly IEmailSender _emailSender;
        private readonly ILogger<AuthController> _logger;
        private readonly ApplicationDbContext _context;

        public AuthController(
            UserManager<ApplicationUser> userManager,
            IConfiguration configuration,
            IEmailSender emailSender,
            ILogger<AuthController> logger,
            ApplicationDbContext context
        )
        {
            _userManager = userManager;
            _configuration = configuration;
            _emailSender = emailSender;
            _logger = logger;
            _context = context;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterDto model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            // var existingUser = await _userManager.FindByEmailAsync(model.Email);
            // if (existingUser != null)
            // {
            //     return BadRequest(new { Message = "User already exists" });
            // }

            var user = new ApplicationUser
            {
                FullName = model.FullName,
                Email = model.Email,
                UserName = model.Email,
                Status = UserStatus.Unverified,
                RegistrationTime = DateTime.UtcNow,
                Position = model.WorkingPosition,
                Company = model.Company,
            };

            var result = await _userManager.CreateAsync(user, model.Password);

            if (result.Succeeded)
            {
                var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                var confirmationLink = Url.Action(
                    nameof(VerifyEmail),
                    "Auth",
                    new { userId = user.Id, code = token },
                    Request.Scheme
                );

                _logger.LogInformation($"Verification Link for {user.Email}: {confirmationLink}");

                await _emailSender.SendEmailAsync(
                    user.Email,
                    "Confirm your email",
                    $"Please confirm your account by <a href='{confirmationLink}'>clicking here</a>."
                );

                var jwtToken = GenerateJwtToken(user);
                return Ok(
                    new
                    {
                        Message = "User registered successfully. Please check your email for verification.",
                        Token = jwtToken,
                        User = new
                        {
                            user.Id,
                            user.Email,
                            user.Status,
                        },
                    }
                );
            }
            if (result.Errors.Any(e => e.Code == "DuplicateEmail"))
            {
                return BadRequest(new { Message = "User already exists" });
            }

            return BadRequest(result.Errors);
        }

        [HttpGet("verify-email")]
        public async Task<IActionResult> VerifyEmail(string userId, string code)
        {
            if (userId == null || code == null)
            {
                return BadRequest("Invalid email confirmation request");
            }

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return BadRequest($"Unable to load user with ID '{userId}'.");
            }

            var result = await _userManager.ConfirmEmailAsync(user, code);
            if (result.Succeeded)
            {
                user.Status = UserStatus.Active;
                await _userManager.UpdateAsync(user);
                return Ok("Email confirmed successfully!");
            }

            return BadRequest("Error confirming your email.");
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginDto model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var user = await _userManager.FindByEmailAsync(model.Email);

            if (user == null || !await _userManager.CheckPasswordAsync(user, model.Password))
            {
                return Unauthorized(new { Message = "Invalid credentials" });
            }

            if (user.IsBlocked)
            {
                return Unauthorized(new { Message = "User is blocked" });
            }

            user.LastLoginTime = DateTime.UtcNow;
            await _userManager.UpdateAsync(user);

            // Log Login Action
            var loginAction = new ActionHistory
            {
                Action = "Login",
                Timestamp = DateTime.UtcNow,
                UserId = user.Id,
                ActionVictim = null,
            };
            _context.ActionHistory.Add(loginAction);
            await _context.SaveChangesAsync();

            var token = GenerateJwtToken(user);
            return Ok(
                new
                {
                    Token = token,
                    User = new
                    {
                        user.Id,
                        user.Email,
                        user.Status,
                    },
                }
            );
        }

        [HttpPost("forgot-password")]
        public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordDto model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                // Don't reveal that the user does not exist
                return Ok(
                    new
                    {
                        Message = "If an account with that email exists, a password reset link has been sent.",
                    }
                );
            }

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var frontendUrl = _configuration["FrontendUrl"] ?? "http://localhost:5173";

            // Encode the token and email to ensure they are URL-safe
            var encodedToken = Uri.EscapeDataString(token);
            var encodedEmail = Uri.EscapeDataString(user.Email);

            var resetLink =
                $"{frontendUrl}/reset-password?token={encodedToken}&email={encodedEmail}";

            await _emailSender.SendEmailAsync(
                user.Email,
                "Reset Password",
                $"Please reset your password by <a href='{resetLink}'>clicking here</a>."
            );

            return Ok(
                new
                {
                    Message = "If an account with that email exists, a password reset link has been sent.",
                }
            );
        }

        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordDto model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                return BadRequest(new { Message = "Invalid request" });
            }

            var result = await _userManager.ResetPasswordAsync(
                user,
                model.Token,
                model.NewPassword
            );
            if (result.Succeeded)
            {
                return Ok(new { Message = "Password has been reset successfully." });
            }

            return BadRequest(result.Errors);
        }

        private string GenerateJwtToken(ApplicationUser user)
        {
            var jwtSettings = _configuration.GetSection("JwtSettings");
            var key = Encoding.ASCII.GetBytes(jwtSettings["Secret"]);

            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(
                    new[]
                    {
                        new Claim(JwtRegisteredClaimNames.Sub, user.Id),
                        new Claim(JwtRegisteredClaimNames.Email, user.Email),
                        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    }
                ),
                Expires = DateTime.UtcNow.AddDays(7),
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(key),
                    SecurityAlgorithms.HmacSha256Signature
                ),
                Issuer = jwtSettings["Issuer"],
                Audience = jwtSettings["Audience"],
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }
    }
}

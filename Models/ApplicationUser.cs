using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.AspNetCore.Identity;
// user table extends from identity user
namespace Backend.Models
{
    public enum UserStatus
    {
        Active,
        Blocked,
        Unverified,
    }

    public class ApplicationUser : IdentityUser
    {
        [Required]
        public bool IsBlocked { get; set; } = false;
        public string? FullName { get; set; }
        public DateTime RegistrationTime { get; set; } = DateTime.UtcNow;
        public DateTime? LastLoginTime { get; set; } = DateTime.UtcNow;
        public DateTime? LastActivityTime { get; set; }
        public string? LastActivityType { get; set; }

        [Required]
        [Column(TypeName = "varchar(20)")]
        public UserStatus Status { get; set; } = UserStatus.Unverified;

        public string? Position { get; set; }
        public string? Company { get; set; }
    }
}

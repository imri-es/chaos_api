using System.ComponentModel.DataAnnotations;

namespace Backend.Models
{
    public class ActionHistory
    {
        [Key]
        public int Id { get; set; }

        [Required]
        public string Action { get; set; } = null!; // delete\block and so on

        [Required]
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;

        [Required]
        public string UserId { get; set; } = null!;

        public string[]? ActionVictim { get; set; }
    }
}

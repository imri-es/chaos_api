namespace Backend.DTOs
{
    public class UserDto
    {
        public string Id { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string FullName { get; set; } = string.Empty;
        public bool IsBlocked { get; set; }
        public DateTime? LastLoginTime { get; set; }
        public DateTime RegistrationTime { get; set; }
        public string? Position { get; set; }
        public string? Company { get; set; }
        public bool IsEmailConfirmed { get; set; }
    }

    public class UserActionDto
    {
        public List<string> UserIds { get; set; } = new();
    }
}

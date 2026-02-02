public class EmailSettings
{
    public string SmtpServer { get; set; } = null!;
    public int Port { get; set; }
    public string SenderName { get; set; } = null!;
    public string SenderEmail { get; set; } = null!;
    public string Username { get; set; } = null!;
    public string Password { get; set; } = null!;
    public bool UseSsl { get; set; } = true;
}

public interface IEmailSender
{
    Task SendEmailAsync(string toEmail, string subject, string body);
}

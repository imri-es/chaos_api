using System.Net.Http;
using System.Net.Http.Json;

public class EmailSender : IEmailSender
{
    private readonly HttpClient _httpClient;

    public EmailSender(HttpClient httpClient)
    {
        _httpClient = httpClient;
    }

    public async Task SendEmailAsync(string toEmail, string subject, string body)
    {
        var emailData = new
        {
            recipient = toEmail,
            subject = subject,
            content = body,
        };

        var response = await _httpClient.PostAsJsonAsync(
            "http://94.131.85.239:3000/send-email",
            emailData
        );
        response.EnsureSuccessStatusCode();
    }
}

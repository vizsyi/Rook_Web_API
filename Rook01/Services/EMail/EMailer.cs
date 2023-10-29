using MailKit.Net.Smtp;
using MimeKit;

namespace Rook01.Services.EMail
{
    public class EMailer
    {
        private readonly IConfiguration _config;

        public EMailer(IConfiguration config)
        {
            this._config = config;
        }
        public Task SendEMailAsync(string emailTo, string subject, string htmlMessage)
        {
            var mailBoxAddress = _config["Mailbox:Address"];
            var mailBoxPassword = _config["Mailbox:App_password"];
            var mailToSend = new MimeMessage();
            mailToSend.From.Add(MailboxAddress.Parse(mailBoxAddress));
            mailToSend.To.Add(MailboxAddress.Parse(emailTo));
            mailToSend.Subject = subject;
            mailToSend.Body = new TextPart(MimeKit.Text.TextFormat.Html){ Text = htmlMessage};

            //Sending e-mail
            using (var mailClient = new SmtpClient())
            {
                mailClient.Connect("smtp.gmail.com", 587, MailKit.Security.SecureSocketOptions.StartTls);
                mailClient.Authenticate(mailBoxAddress, mailBoxPassword);
                mailClient.Send(mailToSend);
                mailClient.Disconnect(true);
            }

            return Task.CompletedTask;
        }
    }
}

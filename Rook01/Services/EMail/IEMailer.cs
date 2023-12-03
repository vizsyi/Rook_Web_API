namespace Rook01.Services.EMail
{
    public interface IEMailer
    {

        public static abstract Task SendEMailAsync(string emailTo, string subject, string htmlMessage);

    }
}

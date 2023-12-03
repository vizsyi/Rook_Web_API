namespace Rook01.Models.Auth.Tokens.DTOs
{
    public class TokenRequest
    {
        //public string Token { get; set; }
        public string RefreshToken { get; set; } = string.Empty;
    }
}
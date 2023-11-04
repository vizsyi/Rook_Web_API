using System.ComponentModel.DataAnnotations;

namespace Rook01.Models.Auth
{
    public class SigninDTO
    {
        [Required(ErrorMessage = "Username must be provided.")]
        public string UserName { get; set; } = "";

        [Required(ErrorMessage = "Password must be provided.")]
        [DataType(DataType.Password, ErrorMessage = "Incorrect or missing password")]
        public string Password { get; set; } = "";

        public bool RememberMe { get; set; }
    }
}

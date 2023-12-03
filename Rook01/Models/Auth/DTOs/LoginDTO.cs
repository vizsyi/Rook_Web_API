using System.ComponentModel.DataAnnotations;

namespace Rook01.Models.Auth.DTOs
{
    public class LoginDTO
    {
        [Required]
        [DataType(DataType.EmailAddress, ErrorMessage = "E-mail address is missing or invalid")]
        public string Email { get; set; } = "";

        [Required]
        [DataType(DataType.Password, ErrorMessage = "Incorrect or missing password")]
        public string Password { get; set; } = "";
    }
}

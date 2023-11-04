using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace Rook01.Data.Identity
{
    public class ApplicationUser : IdentityUser<String>
    {
        [Required]
        public string Petname { get; set; } = "";

        //[Required]
        //public string NormalizedPetname { get; set; } = "";
    }
}

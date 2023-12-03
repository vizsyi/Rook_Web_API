using Microsoft.AspNetCore.Identity;
using Rook01.Models.Auth.DTOs;
using Rook01.Services.Auth;
using System.ComponentModel.DataAnnotations;

namespace Rook01.Models.Auth
{
    public class ApplicationUser : IdentityUser<int>
    {
        public ApplicationUser() : base()
        {
        }
        public ApplicationUser(RegisterDTO model) : base(model.UserName)
        {
            this.Email= model.Email;
            this.UserKey = Chid.NewChid(64, 8);
            //this.SecurityStamp = Guid.NewGuid().ToString(); //todo: test
        }

        [Required]
        [StringLength(8)]
        public string UserKey { get; set; }

    }
}

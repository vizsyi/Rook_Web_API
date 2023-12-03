using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Rook01.Models.Auth.Tokens
{
    public class RefreshToken
    {
        [Key]
        [StringLength(8)]
        public string UserKey { get; set; }

        [Required]
        public int UserId { get; set; }

        [Required]
        [StringLength(7)]
        public string SecKey { get; set; }

        [Required]
        [StringLength(12)]
        public string LongToken { get; set; }

        [Required]
        public DateTime DateExpire { get; set; }

        public bool IsRevoked { get; set; } = false;

        [ForeignKey(nameof(UserId))]
        public ApplicationUser User { get; set; }

    }
}

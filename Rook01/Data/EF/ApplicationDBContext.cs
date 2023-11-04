using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Rook01.Data.Identity;
using Rook01.Models.Celeb;
using System.Reflection.Metadata;

namespace Rook01.Data.EF
{
    public class ApplicationDBContext : IdentityDbContext<ApplicationUser, IdentityRole, String>
    {
        public ApplicationDBContext(DbContextOptions options) : base(options)
        {

        }

        public DbSet<Profession> Profession { get; set; }

        public DbSet<Celeb> Celeb { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);
            modelBuilder.HasDefaultSchema("Auth");

            modelBuilder.Entity<Profession>()
                .ToTable("Profession", schema: "Celeb");

            modelBuilder.Entity<Celeb>()
                .ToTable("Celeb", schema: "Celeb");

            modelBuilder.Entity<Celeb>().Property(x => x.Id)
                .HasColumnType("char");

            modelBuilder.Entity<Celeb>().Property(x => x.PhotoFile)
                .HasColumnType("char");

        }

    }
}

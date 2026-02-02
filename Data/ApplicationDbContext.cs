using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Backend.Models;

namespace Backend.Data
{
    public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
        {
        }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);
            // unique index email
            builder.Entity<ApplicationUser>()
                .HasIndex(u => u.Email)
                .IsUnique();

            // index on timestamp
            builder.Entity<ActionHistory>()
                .HasIndex(a => a.Timestamp);

            // composite index userid and timestamp
            builder.Entity<ActionHistory>()
                .HasIndex(a => new { a.UserId, a.Timestamp });
        }
    }
}

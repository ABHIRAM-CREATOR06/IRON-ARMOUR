using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;

namespace IronArmour
{
    public class PasswordEntry
    {
        [Key]
        public int Id { get; set; }
        public string Account { get; set; } = string.Empty;
        public string EncryptedPassword { get; set; } = string.Empty;
        public string Nonce { get; set; } = string.Empty;
        public string Salt { get; set; } = string.Empty;
    }

    public class MasterPassword
    {
        [Key]
        public int Id { get; set; }
        public string HashedPassword { get; set; } = string.Empty;
        public string Salt { get; set; } = string.Empty;
        public DateTime CreatedAt { get; set; }
    }

    public class VaultContext : DbContext
    {
        public DbSet<PasswordEntry> PasswordEntries { get; set; }
        public DbSet<MasterPassword> MasterPasswords { get; set; }

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            optionsBuilder.UseSqlite("Data Source=vault.db");
        }
    }
}
using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;

namespace IronArmour
{
    public class PasswordEntry
    {
        [Key]
        public int Id { get; set; }
        public int UserId { get; set; }
        public string Account { get; set; } = string.Empty;
        public string EncryptedPassword { get; set; } = string.Empty;
        public string Nonce { get; set; } = string.Empty;
        public string Salt { get; set; } = string.Empty;
        public DateTime CreatedAt { get; set; } = DateTime.Now;
        public DateTime ModifiedAt { get; set; } = DateTime.Now;
        public long Version { get; set; } = 1;
    }

    public class User
    {
        [Key]
        public int Id { get; set; }
        public string Username { get; set; } = string.Empty;
        public string HashedPassword { get; set; } = string.Empty;
        public string Salt { get; set; } = string.Empty;
        public DateTime CreatedAt { get; set; }
    }

    public class MasterPassword
    {
        [Key]
        public int Id { get; set; }
        public int UserId { get; set; }
        public string HashedPassword { get; set; } = string.Empty;
        public string Salt { get; set; } = string.Empty;
        public DateTime CreatedAt { get; set; }
    }

    public class VaultContext : DbContext
    {
        public DbSet<User> Users { get; set; }
        public DbSet<PasswordEntry> PasswordEntries { get; set; }
        public DbSet<MasterPassword> MasterPasswords { get; set; }
        public DbSet<SyncSettings> SyncSettings { get; set; }

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            optionsBuilder.UseSqlite("Data Source=vault.db");
        }
    }
}
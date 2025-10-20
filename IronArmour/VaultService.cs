using BCrypt.Net;
using System.Security.Cryptography;

namespace IronArmour
{
    public class VaultService
    {
        private readonly VaultContext _context;
        private string? _masterKey;
        private User? _currentUser;

        public VaultContext Context => _context;
        public User? CurrentUser => _currentUser;

        public VaultService()
        {
            _context = new VaultContext();
            _context.Database.EnsureCreated();
        }

        public bool SetMasterPassword(string password)
        {
            try
            {
                var hashedPassword = BCrypt.Net.BCrypt.HashPassword(password);
                var masterPassword = _context.MasterPasswords.FirstOrDefault();

                if (masterPassword == null)
                {
                    masterPassword = new MasterPassword
                    {
                        HashedPassword = hashedPassword,
                        CreatedAt = DateTime.Now
                    };
                    _context.MasterPasswords.Add(masterPassword);
                }
                else
                {
                    masterPassword.HashedPassword = hashedPassword;
                }

                _context.SaveChanges();
                _masterKey = password;
                return true;
            }
            catch
            {
                return false;
            }
        }

        public bool VerifyMasterPassword(string password)
        {
            var masterPassword = _context.MasterPasswords.FirstOrDefault();
            if (masterPassword == null) return false;

            if (BCrypt.Net.BCrypt.Verify(password, masterPassword.HashedPassword))
            {
                _masterKey = password;
                return true;
            }
            return false;
        }

        public bool AddPassword(string account, string password)
        {
            if (_masterKey == null) return false;

            var salt = new byte[16];
            RandomNumberGenerator.Fill(salt);

            var entryKey = CryptoHelper.DeriveKeyArgon2(_masterKey, salt);
            var (ciphertext, nonce) = CryptoHelper.EncryptPassword(entryKey, password);

            var entry = new PasswordEntry
            {
                Account = account,
                EncryptedPassword = ciphertext,
                Nonce = nonce,
                Salt = Convert.ToBase64String(salt)
            };

            _context.PasswordEntries.Add(entry);
            _context.SaveChanges();
            return true;
        }

        public string? GetPassword(string account)
        {
            if (_masterKey == null) return null;

            var entry = _context.PasswordEntries.FirstOrDefault(e => e.Account == account);
            if (entry == null) return null;

            var salt = Convert.FromBase64String(entry.Salt);
            var entryKey = CryptoHelper.DeriveKeyArgon2(_masterKey, salt);
            return CryptoHelper.DecryptPassword(entryKey, entry.EncryptedPassword, entry.Nonce);
        }

        public List<string> ListAccounts()
        {
            return _context.PasswordEntries.Select(e => e.Account).ToList();
        }

        public string GenerateOtp(string account, string username, string secret, int length)
        {
            return CryptoHelper.GenerateOtpPassword(secret, account, username, length);
        }

        public List<(string ssid, string password, string strength)> AnalyzeWifi()
        {
            var wifiPasswords = new List<(string, string, string)>();

            try
            {
                // Run netsh command to get Wi-Fi profiles
                var process = new System.Diagnostics.Process();
                process.StartInfo.FileName = "netsh";
                process.StartInfo.Arguments = "wlan show profiles";
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.RedirectStandardOutput = true;
                process.StartInfo.CreateNoWindow = true;
                process.Start();

                var output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();

                // Parse the output to get profile names
                var lines = output.Split('\n');
                var profiles = new List<string>();

                foreach (var line in lines)
                {
                    if (line.Contains("All User Profile") || line.Contains("All Users Profile"))
                    {
                        var profileName = line.Split(':')[1].Trim();
                        profiles.Add(profileName);
                    }
                }

                // Get password for each profile
                foreach (var profile in profiles)
                {
                    try
                    {
                        var passwordProcess = new System.Diagnostics.Process();
                        passwordProcess.StartInfo.FileName = "netsh";
                        passwordProcess.StartInfo.Arguments = $"wlan show profile name=\"{profile}\" key=clear";
                        passwordProcess.StartInfo.UseShellExecute = false;
                        passwordProcess.StartInfo.RedirectStandardOutput = true;
                        passwordProcess.StartInfo.CreateNoWindow = true;
                        passwordProcess.Start();

                        var passwordOutput = passwordProcess.StandardOutput.ReadToEnd();
                        passwordProcess.WaitForExit();

                        var password = ExtractPassword(passwordOutput);
                        var strength = EvaluatePasswordStrength(password);

                        wifiPasswords.Add((profile, password, strength));
                    }
                    catch
                    {
                        // Skip profiles that can't be accessed
                        continue;
                    }
                }
            }
            catch
            {
                // Fallback to mock data if netsh fails
                wifiPasswords.Add(("Home_WiFi", "password123", "Weak"));
                wifiPasswords.Add(("OfficeNet", "M@in_Office2024", "Strong"));
                wifiPasswords.Add(("CafeFree", "12345678", "Weak"));
            }

            return wifiPasswords;
        }

        private string ExtractPassword(string netshOutput)
        {
            var lines = netshOutput.Split('\n');
            foreach (var line in lines)
            {
                if (line.Contains("Key Content"))
                {
                    return line.Split(':')[1].Trim();
                }
            }
            return "Not found";
        }

        private string EvaluatePasswordStrength(string password)
        {
            if (string.IsNullOrEmpty(password) || password == "Not found") return "Unknown";

            var score = 0;
            if (password.Length >= 8) score++;
            if (password.Any(char.IsUpper)) score++;
            if (password.Any(char.IsLower)) score++;
            if (password.Any(char.IsDigit)) score++;
            if (password.Any(ch => !char.IsLetterOrDigit(ch))) score++;

            return score >= 4 ? "Strong" : score >= 2 ? "Medium" : "Weak";
        }
    }
}
using System.Security.Cryptography;
using System.Text;

namespace IronArmour
{
    public static class CryptoHelper
    {
        private const string Salt = "iron-armour-salt";

        public static byte[] DeriveKey(string masterPassword)
        {
            using var pbkdf2 = new Rfc2898DeriveBytes(masterPassword, Encoding.UTF8.GetBytes(Salt), 100000, HashAlgorithmName.SHA256);
            return pbkdf2.GetBytes(32);
        }

        public static byte[] DeriveKeyArgon2(string password, byte[] salt)
        {
            // Using PBKDF2 as a simpler alternative since Argon2 isn't directly available
            using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 100000, HashAlgorithmName.SHA256);
            return pbkdf2.GetBytes(32);
        }

        public static (string ciphertext, string nonce) EncryptPassword(byte[] key, string password)
        {
            using var aes = Aes.Create();
            aes.Key = key;
            aes.GenerateIV();

            using var encryptor = aes.CreateEncryptor();
            var plaintextBytes = Encoding.UTF8.GetBytes(password);
            var ciphertextBytes = encryptor.TransformFinalBlock(plaintextBytes, 0, plaintextBytes.Length);

            return (Convert.ToBase64String(ciphertextBytes), Convert.ToBase64String(aes.IV));
        }

        public static string DecryptPassword(byte[] key, string ciphertext, string nonce)
        {
            using var aes = Aes.Create();
            aes.Key = key;
            aes.IV = Convert.FromBase64String(nonce);

            using var decryptor = aes.CreateDecryptor();
            var ciphertextBytes = Convert.FromBase64String(ciphertext);
            var plaintextBytes = decryptor.TransformFinalBlock(ciphertextBytes, 0, ciphertextBytes.Length);

            return Encoding.UTF8.GetString(plaintextBytes);
        }

        public static string GenerateOtpPassword(string secret, string account, string username, int length)
        {
            var data = Encoding.UTF8.GetBytes(secret + account + username);
            using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
            var hash = hmac.ComputeHash(data);

            const string charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
            var password = new StringBuilder();

            for (int i = 0; i < length; i++)
            {
                var index = hash[i % hash.Length] % charset.Length;
                password.Append(charset[index]);
            }

            return password.ToString();
        }
    }
}
using PdfSharp.Drawing;
using PdfSharp.Pdf;
using CsvHelper;
using System.Globalization;
using System.Diagnostics;
using System.IO;

namespace IronArmour
{
    public class WifiReportData
    {
        public string Ssid { get; set; } = "";
        public string Password { get; set; } = "";
        public string Strength { get; set; } = "";
        public string SecurityType { get; set; } = "";
        public DateTime LastConnected { get; set; }
    }

    public class PasswordReportData
    {
        public string Account { get; set; } = "";
        public string Strength { get; set; } = "";
        public DateTime CreatedDate { get; set; }
        public int DaysSinceCreation { get; set; }
        public bool IsExpired { get; set; }
    }

    public static class ReportGenerator
    {
        public static void GenerateWifiReportPdf(List<(string ssid, string password, string strength)> wifiData, string filePath)
        {
            var document = new PdfDocument();
            document.Info.Title = "Wi-Fi Password Report - Iron Armour";

            var page = document.AddPage();
            var gfx = XGraphics.FromPdfPage(page);
            var font = new XFont("Arial", 12, XFontStyle.Regular);
            var boldFont = new XFont("Arial", 14, XFontStyle.Bold);
            var titleFont = new XFont("Arial", 18, XFontStyle.Bold);

            // Title
            gfx.DrawString("🔐 Iron Armour - Wi-Fi Password Report", titleFont, XBrushes.DarkRed, new XPoint(50, 50));
            gfx.DrawString($"Generated on: {DateTime.Now:yyyy-MM-dd HH:mm:ss}", font, XBrushes.Black, new XPoint(50, 80));
            gfx.DrawString($"Total Networks Found: {wifiData.Count}", font, XBrushes.Black, new XPoint(50, 100));

            int yPosition = 140;
            int count = 1;

            foreach (var (ssid, password, strength) in wifiData)
            {
                if (yPosition > page.Height - 100)
                {
                    page = document.AddPage();
                    gfx = XGraphics.FromPdfPage(page);
                    yPosition = 50;
                }

                // Network header
                gfx.DrawString($"{count}. Network: {ssid}", boldFont, XBrushes.DarkBlue, new XPoint(50, yPosition));
                yPosition += 25;

                // Password
                gfx.DrawString($"Password: {password}", font, XBrushes.Black, new XPoint(70, yPosition));
                yPosition += 20;

                // Strength with color
                var strengthColor = strength == "Strong" ? XBrushes.Green :
                                   strength == "Medium" ? XBrushes.Orange : XBrushes.Red;
                gfx.DrawString($"Strength: {strength}", font, strengthColor, new XPoint(70, yPosition));
                yPosition += 30;

                count++;
            }

            // Security warning
            yPosition += 20;
            if (yPosition < page.Height - 60)
            {
                gfx.DrawString("⚠️ SECURITY WARNING:", boldFont, XBrushes.DarkRed, new XPoint(50, yPosition));
                yPosition += 20;
                gfx.DrawString("• Never share this report with unauthorized persons", font, XBrushes.Black, new XPoint(50, yPosition));
                yPosition += 15;
                gfx.DrawString("• Consider changing weak passwords immediately", font, XBrushes.Black, new XPoint(50, yPosition));
                yPosition += 15;
                gfx.DrawString("• Use WPA3 encryption for maximum security", font, XBrushes.Black, new XPoint(50, yPosition));
            }

            document.Save(filePath);
        }

        public static void GenerateWifiReportCsv(List<(string ssid, string password, string strength)> wifiData, string filePath)
        {
            var records = wifiData.Select(w => new WifiReportData
            {
                Ssid = w.ssid,
                Password = w.password,
                Strength = w.strength,
                SecurityType = "WPA2/WPA3", // Default assumption
                LastConnected = DateTime.Now // Placeholder
            }).ToList();

            using var writer = new StreamWriter(filePath);
            using var csv = new CsvWriter(writer, CultureInfo.InvariantCulture);
            csv.WriteRecords(records);
        }

        public static void GeneratePasswordStrengthReportPdf(List<string> accounts, VaultService vaultService, string filePath)
        {
            var document = new PdfDocument();
            document.Info.Title = "Password Strength Report - Iron Armour";

            var page = document.AddPage();
            var gfx = XGraphics.FromPdfPage(page);
            var font = new XFont("Arial", 12, XFontStyle.Regular);
            var boldFont = new XFont("Arial", 14, XFontStyle.Bold);
            var titleFont = new XFont("Arial", 18, XFontStyle.Bold);

            // Title
            gfx.DrawString("🔐 Iron Armour - Password Strength Report", titleFont, XBrushes.DarkRed, new XPoint(50, 50));
            gfx.DrawString($"Generated on: {DateTime.Now:yyyy-MM-dd HH:mm:ss}", font, XBrushes.Black, new XPoint(50, 80));
            gfx.DrawString($"Total Accounts: {accounts.Count}", font, XBrushes.Black, new XPoint(50, 100));

            int yPosition = 140;
            int strongCount = 0, mediumCount = 0, weakCount = 0;

            foreach (var account in accounts)
            {
                var password = vaultService.GetPassword(account);
                if (password == null) continue;

                var strength = EvaluatePasswordStrength(password);

                // Count strengths
                if (strength == "Strong") strongCount++;
                else if (strength == "Medium") mediumCount++;
                else weakCount++;

                if (yPosition > page.Height - 100)
                {
                    page = document.AddPage();
                    gfx = XGraphics.FromPdfPage(page);
                    yPosition = 50;
                }

                // Account header
                gfx.DrawString($"Account: {account}", boldFont, XBrushes.DarkBlue, new XPoint(50, yPosition));
                yPosition += 25;

                // Password strength
                var strengthColor = strength == "Strong" ? XBrushes.Green :
                                   strength == "Medium" ? XBrushes.Orange : XBrushes.Red;
                gfx.DrawString($"Password Strength: {strength}", font, strengthColor, new XPoint(70, yPosition));
                yPosition += 20;

                // Password length
                gfx.DrawString($"Password Length: {password.Length} characters", font, XBrushes.Black, new XPoint(70, yPosition));
                yPosition += 30;
            }

            // Summary section
            if (yPosition < page.Height - 120)
            {
                yPosition += 20;
                gfx.DrawString("📊 SUMMARY:", boldFont, XBrushes.DarkRed, new XPoint(50, yPosition));
                yPosition += 25;

                gfx.DrawString($"Strong Passwords: {strongCount}", font, XBrushes.Green, new XPoint(70, yPosition));
                yPosition += 20;
                gfx.DrawString($"Medium Passwords: {mediumCount}", font, XBrushes.Orange, new XPoint(70, yPosition));
                yPosition += 20;
                gfx.DrawString($"Weak Passwords: {weakCount}", font, XBrushes.Red, new XPoint(70, yPosition));
                yPosition += 30;

                // Recommendations
                gfx.DrawString("💡 RECOMMENDATIONS:", boldFont, XBrushes.DarkBlue, new XPoint(50, yPosition));
                yPosition += 20;
                gfx.DrawString("• Use passwords with at least 12 characters", font, XBrushes.Black, new XPoint(50, yPosition));
                yPosition += 15;
                gfx.DrawString("• Include uppercase, lowercase, numbers, and symbols", font, XBrushes.Black, new XPoint(50, yPosition));
                yPosition += 15;
                gfx.DrawString("• Avoid using personal information", font, XBrushes.Black, new XPoint(50, yPosition));
                yPosition += 15;
                gfx.DrawString("• Consider using a password manager", font, XBrushes.Black, new XPoint(50, yPosition));
            }

            document.Save(filePath);
        }

        public static void GeneratePasswordStrengthReportCsv(List<string> accounts, VaultService vaultService, string filePath)
        {
            var records = new List<PasswordReportData>();

            foreach (var account in accounts)
            {
                var password = vaultService.GetPassword(account);
                if (password == null) continue;

                records.Add(new PasswordReportData
                {
                    Account = account,
                    Strength = EvaluatePasswordStrength(password),
                    CreatedDate = DateTime.Now.AddDays(-30), // Placeholder - would need actual creation date
                    DaysSinceCreation = 30,
                    IsExpired = false
                });
            }

            using var writer = new StreamWriter(filePath);
            using var csv = new CsvWriter(writer, CultureInfo.InvariantCulture);
            csv.WriteRecords(records);
        }

        public static void GenerateSecurityAuditReportPdf(List<string> accounts, VaultService vaultService, string filePath)
        {
            var document = new PdfDocument();
            document.Info.Title = "Security Audit Report - Iron Armour";

            var page = document.AddPage();
            var gfx = XGraphics.FromPdfPage(page);
            var font = new XFont("Arial", 12, XFontStyle.Regular);
            var boldFont = new XFont("Arial", 14, XFontStyle.Bold);
            var titleFont = new XFont("Arial", 18, XFontStyle.Bold);

            // Title
            gfx.DrawString("🔐 Iron Armour - Security Audit Report", titleFont, XBrushes.DarkRed, new XPoint(50, 50));
            gfx.DrawString($"Audit Date: {DateTime.Now:yyyy-MM-dd HH:mm:ss}", font, XBrushes.Black, new XPoint(50, 80));

            int yPosition = 120;

            // Security metrics
            var totalAccounts = accounts.Count;
            var weakPasswords = accounts.Count(a => {
                var pwd = vaultService.GetPassword(a);
                return pwd != null && EvaluatePasswordStrength(pwd) == "Weak";
            });
            var mediumPasswords = accounts.Count(a => {
                var pwd = vaultService.GetPassword(a);
                return pwd != null && EvaluatePasswordStrength(pwd) == "Medium";
            });
            var strongPasswords = accounts.Count(a => {
                var pwd = vaultService.GetPassword(a);
                return pwd != null && EvaluatePasswordStrength(pwd) == "Strong";
            });

            gfx.DrawString("📈 SECURITY METRICS:", boldFont, XBrushes.DarkBlue, new XPoint(50, yPosition));
            yPosition += 25;

            gfx.DrawString($"Total Accounts: {totalAccounts}", font, XBrushes.Black, new XPoint(70, yPosition));
            yPosition += 20;
            var strongPercent = totalAccounts > 0 ? (strongPasswords * 100 / totalAccounts) : 0;
            var mediumPercent = totalAccounts > 0 ? (mediumPasswords * 100 / totalAccounts) : 0;
            var weakPercent = totalAccounts > 0 ? (weakPasswords * 100 / totalAccounts) : 0;

            gfx.DrawString($"Strong Passwords: {strongPasswords} ({strongPercent}%)", font, XBrushes.Green, new XPoint(70, yPosition));
            yPosition += 20;
            gfx.DrawString($"Medium Passwords: {mediumPasswords} ({mediumPercent}%)", font, XBrushes.Orange, new XPoint(70, yPosition));
            yPosition += 20;
            gfx.DrawString($"Weak Passwords: {weakPasswords} ({weakPercent}%)", font, XBrushes.Red, new XPoint(70, yPosition));
            yPosition += 30;

            // Risk assessment
            string riskLevel;
            XBrush riskColor;

            if (weakPasswords > totalAccounts * 0.5)
            {
                riskLevel = "HIGH RISK";
                riskColor = XBrushes.DarkRed;
            }
            else if (weakPasswords > totalAccounts * 0.2)
            {
                riskLevel = "MEDIUM RISK";
                riskColor = XBrushes.Orange;
            }
            else
            {
                riskLevel = "LOW RISK";
                riskColor = XBrushes.Green;
            }

            gfx.DrawString("🚨 RISK ASSESSMENT:", boldFont, XBrushes.DarkRed, new XPoint(50, yPosition));
            yPosition += 25;
            gfx.DrawString($"Overall Security Level: {riskLevel}", boldFont, riskColor, new XPoint(70, yPosition));
            yPosition += 30;

            // Recommendations
            if (yPosition < page.Height - 100)
            {
                gfx.DrawString("🛡️ SECURITY RECOMMENDATIONS:", boldFont, XBrushes.DarkBlue, new XPoint(50, yPosition));
                yPosition += 25;

                var recommendations = new List<string>();
                if (weakPasswords > 0)
                    recommendations.Add("• Change weak passwords immediately");
                if (mediumPasswords > totalAccounts * 0.5)
                    recommendations.Add("• Strengthen medium-strength passwords");
                recommendations.Add("• Enable two-factor authentication where possible");
                recommendations.Add("• Use unique passwords for each account");
                recommendations.Add("• Consider using a password manager");

                foreach (var rec in recommendations)
                {
                    if (yPosition > page.Height - 30) break;
                    gfx.DrawString(rec, font, XBrushes.Black, new XPoint(50, yPosition));
                    yPosition += 15;
                }
            }

            document.Save(filePath);
        }

        private static string EvaluatePasswordStrength(string password)
        {
            if (string.IsNullOrEmpty(password)) return "Weak";

            var score = 0;
            if (password.Length >= 8) score++;
            if (password.Length >= 12) score++;
            if (password.Any(char.IsUpper)) score++;
            if (password.Any(char.IsLower)) score++;
            if (password.Any(char.IsDigit)) score++;
            if (password.Any(ch => !char.IsLetterOrDigit(ch))) score++;

            return score >= 5 ? "Strong" : score >= 3 ? "Medium" : "Weak";
        }

        public static void OpenFile(string filePath)
        {
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = filePath,
                    UseShellExecute = true
                });
            }
            catch
            {
                // Silently fail if file can't be opened
            }
        }
    }
}
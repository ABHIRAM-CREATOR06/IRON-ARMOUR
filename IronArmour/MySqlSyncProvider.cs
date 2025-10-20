using System.Net.Http;
using System.Net.Http.Json;

namespace IronArmour
{
    public class SyncPassword
    {
        public string Id { get; set; } = "";
        public string Account { get; set; } = "";
        public string EncryptedPassword { get; set; } = "";
        public string Nonce { get; set; } = "";
        public string Salt { get; set; } = "";
        public DateTime LastModified { get; set; }
        public bool IsDeleted { get; set; } = false;
    }

    public class MySqlSyncProvider : ISyncProvider
    {
        private readonly string _serverUrl;
        private readonly string _authToken;
        private readonly HttpClient _httpClient;

        public MySqlSyncProvider(string serverUrl, string authToken)
        {
            _serverUrl = serverUrl.TrimEnd('/');
            _authToken = authToken;
            _httpClient = new HttpClient();
            _httpClient.DefaultRequestHeaders.Add("Authorization", $"Bearer {_authToken}");
        }

        public async Task<SyncResponse> SyncPasswordsAsync(SyncRequest request)
        {
            try
            {
                var response = await _httpClient.PostAsJsonAsync($"{_serverUrl}/api/sync", request);
                response.EnsureSuccessStatusCode();

                var syncResponse = await response.Content.ReadFromJsonAsync<SyncResponse>();
                return syncResponse ?? new SyncResponse { Success = false, Message = "Invalid response from server" };
            }
            catch (Exception ex)
            {
                return new SyncResponse { Success = false, Message = $"Sync failed: {ex.Message}" };
            }
        }

        public async Task<AuthResponse> AuthenticateAsync(AuthRequest request)
        {
            try
            {
                var response = await _httpClient.PostAsJsonAsync($"{_serverUrl}/api/auth", request);
                response.EnsureSuccessStatusCode();

                var authResponse = await response.Content.ReadFromJsonAsync<AuthResponse>();
                return authResponse ?? new AuthResponse { Success = false, Message = "Authentication failed" };
            }
            catch (Exception ex)
            {
                return new AuthResponse { Success = false, Message = $"Authentication failed: {ex.Message}" };
            }
        }

        public async Task<bool> TestConnectionAsync()
        {
            try
            {
                var response = await _httpClient.GetAsync($"{_serverUrl}/api/health");
                return response.IsSuccessStatusCode;
            }
            catch
            {
                return false;
            }
        }

        public async Task<bool> RegisterDeviceAsync(string deviceId, string deviceName)
        {
            try
            {
                var registerRequest = new { DeviceId = deviceId, DeviceName = deviceName };
                var response = await _httpClient.PostAsJsonAsync($"{_serverUrl}/api/devices/register", registerRequest);
                return response.IsSuccessStatusCode;
            }
            catch
            {
                return false;
            }
        }

        public async Task<List<SyncPassword>> GetServerPasswordsAsync(string userId, DateTime lastSync)
        {
            try
            {
                var response = await _httpClient.GetAsync($"{_serverUrl}/api/passwords?userId={userId}&lastSync={lastSync:o}");
                response.EnsureSuccessStatusCode();

                var passwords = await response.Content.ReadFromJsonAsync<List<SyncPassword>>();
                return passwords ?? new List<SyncPassword>();
            }
            catch
            {
                return new List<SyncPassword>();
            }
        }

        public async Task<bool> UploadPasswordsAsync(string userId, List<SyncPassword> passwords)
        {
            try
            {
                var uploadRequest = new { UserId = userId, Passwords = passwords };
                var response = await _httpClient.PostAsJsonAsync($"{_serverUrl}/api/passwords/upload", uploadRequest);
                return response.IsSuccessStatusCode;
            }
            catch
            {
                return false;
            }
        }

        public async Task<bool> DeletePasswordAsync(string userId, string passwordId)
        {
            try
            {
                var response = await _httpClient.DeleteAsync($"{_serverUrl}/api/passwords/{passwordId}?userId={userId}");
                return response.IsSuccessStatusCode;
            }
            catch
            {
                return false;
            }
        }
    }
}
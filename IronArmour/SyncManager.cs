using System.Net.Http;
using System.Text;
using Newtonsoft.Json;

namespace IronArmour
{
    public interface ISyncProvider
    {
        Task<bool> TestConnectionAsync();
        Task<SyncResponse> SyncPasswordsAsync(SyncRequest request);
        Task<AuthResponse> AuthenticateAsync(AuthRequest request);
    }

    public class HttpSyncProvider : ISyncProvider
    {
        private readonly HttpClient _httpClient;
        private readonly string _baseUrl;
        private string _authToken;

        public HttpSyncProvider(string baseUrl, string authToken = "")
        {
            _httpClient = new HttpClient();
            _baseUrl = baseUrl.TrimEnd('/');
            _authToken = authToken;

            // Set default headers
            _httpClient.DefaultRequestHeaders.Add("User-Agent", "IronArmour/1.0");
            _httpClient.Timeout = TimeSpan.FromSeconds(30);
        }

        public void SetAuthToken(string token)
        {
            _authToken = token;
        }

        public async Task<bool> TestConnectionAsync()
        {
            try
            {
                var response = await _httpClient.GetAsync($"{_baseUrl}/health");
                return response.IsSuccessStatusCode;
            }
            catch
            {
                return false;
            }
        }

        public async Task<AuthResponse> AuthenticateAsync(AuthRequest request)
        {
            try
            {
                var json = JsonConvert.SerializeObject(request);
                var content = new StringContent(json, Encoding.UTF8, "application/json");

                var response = await _httpClient.PostAsync($"{_baseUrl}/auth", content);
                var responseJson = await response.Content.ReadAsStringAsync();

                if (response.IsSuccessStatusCode)
                {
                    var authResponse = JsonConvert.DeserializeObject<AuthResponse>(responseJson);
                    if (authResponse.Success)
                    {
                        _authToken = authResponse.Token;
                        _httpClient.DefaultRequestHeaders.Authorization =
                            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", _authToken);
                    }
                    return authResponse;
                }
                else
                {
                    return new AuthResponse
                    {
                        Success = false,
                        Message = $"Authentication failed: {response.StatusCode}"
                    };
                }
            }
            catch (Exception ex)
            {
                return new AuthResponse
                {
                    Success = false,
                    Message = $"Connection error: {ex.Message}"
                };
            }
        }

        public async Task<SyncResponse> SyncPasswordsAsync(SyncRequest request)
        {
            try
            {
                var json = JsonConvert.SerializeObject(request);
                var content = new StringContent(json, Encoding.UTF8, "application/json");

                if (!string.IsNullOrEmpty(_authToken))
                {
                    _httpClient.DefaultRequestHeaders.Authorization =
                        new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", _authToken);
                }

                var response = await _httpClient.PostAsync($"{_baseUrl}/sync", content);
                var responseJson = await response.Content.ReadAsStringAsync();

                if (response.IsSuccessStatusCode)
                {
                    return JsonConvert.DeserializeObject<SyncResponse>(responseJson);
                }
                else
                {
                    return new SyncResponse
                    {
                        Success = false,
                        Message = $"Sync failed: {response.StatusCode} - {responseJson}"
                    };
                }
            }
            catch (Exception ex)
            {
                return new SyncResponse
                {
                    Success = false,
                    Message = $"Connection error: {ex.Message}"
                };
            }
        }
    }

    public class SyncManager
    {
        private readonly VaultContext _context;
        private readonly ISyncProvider _syncProvider;
        private readonly SyncSettings _settings;
        private readonly User _currentUser;

        public SyncStatus Status { get; private set; } = new SyncStatus();

        public SyncManager(VaultContext context, ISyncProvider syncProvider, SyncSettings settings, User currentUser)
        {
            _context = context;
            _syncProvider = syncProvider;
            _settings = settings;
            _currentUser = currentUser;
        }

        public async Task<bool> TestConnectionAsync()
        {
            Status.CurrentState = SyncState.Syncing;
            Status.StatusMessage = "Testing connection...";

            try
            {
                var result = await _syncProvider.TestConnectionAsync();
                Status.IsOnline = result;
                Status.CurrentState = result ? SyncState.Success : SyncState.Error;
                Status.StatusMessage = result ? "Connection successful" : "Connection failed";
                return result;
            }
            catch (Exception ex)
            {
                Status.CurrentState = SyncState.Error;
                Status.StatusMessage = $"Connection error: {ex.Message}";
                Status.IsOnline = false;
                return false;
            }
        }

        public async Task<SyncResponse> PerformSyncAsync()
        {
            if (!_settings.IsSyncEnabled)
            {
                return new SyncResponse
                {
                    Success = false,
                    Message = "Sync is disabled"
                };
            }

            Status.CurrentState = SyncState.Syncing;
            Status.StatusMessage = "Preparing sync...";

            try
            {
                // Get local passwords for sync
                var localPasswords = GetLocalPasswordsForSync();
                Status.StatusMessage = $"Found {localPasswords.Count} local passwords to sync";

                var syncRequest = new SyncRequest
                {
                    UserId = _currentUser.Id.ToString(),
                    Passwords = localPasswords,
                    LastSyncVersion = GetLastSyncVersion(),
                    DeviceId = GetDeviceId()
                };

                Status.StatusMessage = "Sending data to server...";
                var response = await _syncProvider.SyncPasswordsAsync(syncRequest);

                if (response.Success)
                {
                    Status.StatusMessage = "Processing server response...";
                    await ProcessSyncResponse(response);
                    Status.LastSyncTime = DateTime.Now;
                    Status.CurrentState = SyncState.Success;
                    Status.StatusMessage = $"Sync completed successfully. Processed {response.ServerPasswords.Count} server items.";
                }
                else
                {
                    Status.CurrentState = SyncState.Error;
                    Status.StatusMessage = response.Message;
                }

                return response;
            }
            catch (Exception ex)
            {
                Status.CurrentState = SyncState.Error;
                Status.StatusMessage = $"Sync error: {ex.Message}";
                return new SyncResponse
                {
                    Success = false,
                    Message = ex.Message
                };
            }
        }

        private List<SyncPasswordDto> GetLocalPasswordsForSync()
        {
            return _context.PasswordEntries
                .Where(p => p.UserId == _currentUser.Id && !_settings.ExcludedAccounts.Contains(p.Account))
                .Select(p => new SyncPasswordDto
                {
                    Account = p.Account,
                    EncryptedPassword = p.EncryptedPassword,
                    Nonce = p.Nonce,
                    Salt = p.Salt,
                    CreatedAt = p.CreatedAt,
                    ModifiedAt = p.ModifiedAt,
                    DeviceId = GetDeviceId(),
                    Version = p.Version
                })
                .ToList();
        }

        private long GetLastSyncVersion()
        {
            // Get the highest version number from local database
            return _context.PasswordEntries
                .Where(p => p.UserId == _currentUser.Id)
                .Max(p => (long?)p.Version) ?? 0;
        }

        private async Task ProcessSyncResponse(SyncResponse response)
        {
            if (!response.Success) return;

            // Process server passwords (newer versions)
            foreach (var serverPassword in response.ServerPasswords)
            {
                var localPassword = _context.PasswordEntries
                    .FirstOrDefault(p => p.UserId == _currentUser.Id && p.Account == serverPassword.Account);

                if (localPassword == null)
                {
                    // New password from server
                    var newPassword = new PasswordEntry
                    {
                        UserId = _currentUser.Id,
                        Account = serverPassword.Account,
                        EncryptedPassword = serverPassword.EncryptedPassword,
                        Nonce = serverPassword.Nonce,
                        Salt = serverPassword.Salt,
                        CreatedAt = serverPassword.CreatedAt,
                        ModifiedAt = serverPassword.ModifiedAt,
                        Version = serverPassword.Version
                    };
                    _context.PasswordEntries.Add(newPassword);
                }
                else if (serverPassword.Version > localPassword.Version)
                {
                    // Server has newer version
                    localPassword.EncryptedPassword = serverPassword.EncryptedPassword;
                    localPassword.Nonce = serverPassword.Nonce;
                    localPassword.Salt = serverPassword.Salt;
                    localPassword.ModifiedAt = serverPassword.ModifiedAt;
                    localPassword.Version = serverPassword.Version;
                }
            }

            await _context.SaveChangesAsync();

            // Handle conflicts if any
            if (response.Conflicts.Any())
            {
                Status.CurrentState = SyncState.Conflict;
                Status.StatusMessage = $"Sync completed with {response.Conflicts.Count} conflicts. Manual resolution required.";
            }
        }

        private string GetDeviceId()
        {
            // Generate a unique device ID (could be stored in settings)
            return Environment.MachineName + "_" + Environment.UserName;
        }
    }
}
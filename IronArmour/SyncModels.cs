using System.ComponentModel.DataAnnotations;

namespace IronArmour
{
    public enum SyncDirection
    {
        Disabled,
        OneWayUp,      // Local → Server only
        OneWayDown,    // Server → Local only
        TwoWay,        // Bidirectional sync
        Manual         // User-triggered only
    }

    public enum SyncState
    {
        Idle,
        Syncing,
        Success,
        Error,
        Conflict
    }

    public class SyncSettings
    {
        [Key]
        public int Id { get; set; }
        public bool IsSyncEnabled { get; set; } = false;
        public string ServerUrl { get; set; } = "https://api.ironarmour.com";
        public string AuthToken { get; set; } = "";
        public string DatabaseType { get; set; } = "HTTP"; // HTTP or MySQL
        public string MySqlConnectionString { get; set; } = "";
        public SyncDirection SyncDirection { get; set; } = SyncDirection.Disabled;
        public List<string> ExcludedAccounts { get; set; } = new();
        public DateTime LastSyncTime { get; set; }
        public bool AutoSyncEnabled { get; set; } = false;
        public int SyncIntervalMinutes { get; set; } = 60;
    }

    public class SyncStatus
    {
        public SyncState CurrentState { get; set; } = SyncState.Idle;
        public string StatusMessage { get; set; } = "Ready";
        public DateTime LastSyncTime { get; set; }
        public int PendingChanges { get; set; } = 0;
        public bool IsOnline { get; set; } = false;
    }

    // DTOs for server communication
    public class SyncPasswordDto
    {
        public string Account { get; set; } = "";
        public string EncryptedPassword { get; set; } = "";
        public string Nonce { get; set; } = "";
        public string Salt { get; set; } = "";
        public DateTime CreatedAt { get; set; }
        public DateTime ModifiedAt { get; set; }
        public string DeviceId { get; set; } = "";
        public long Version { get; set; }
    }

    public class SyncRequest
    {
        public string UserId { get; set; } = "";
        public List<SyncPasswordDto> Passwords { get; set; } = new();
        public long LastSyncVersion { get; set; }
        public string DeviceId { get; set; } = "";
    }

    public class SyncResponse
    {
        public bool Success { get; set; }
        public string Message { get; set; } = "";
        public List<SyncPasswordDto> ServerPasswords { get; set; } = new();
        public List<SyncConflict> Conflicts { get; set; } = new();
        public long LatestVersion { get; set; }
    }

    public class SyncConflict
    {
        public string Account { get; set; } = "";
        public SyncPasswordDto LocalVersion { get; set; } = new();
        public SyncPasswordDto ServerVersion { get; set; } = new();
        public ConflictResolution Resolution { get; set; } = ConflictResolution.Manual;
    }

    public enum ConflictResolution
    {
        Manual,
        UseLocal,
        UseServer,
        Merge
    }

    public class AuthRequest
    {
        public string Username { get; set; } = "";
        public string ChallengeResponse { get; set; } = "";
        public string DeviceId { get; set; } = "";
    }

    public class AuthResponse
    {
        public bool Success { get; set; }
        public string Token { get; set; } = "";
        public string UserId { get; set; } = "";
        public string Message { get; set; } = "";
    }

    public class DeviceInfo
    {
        public string DeviceId { get; set; } = "";
        public string DeviceName { get; set; } = "";
        public string DeviceType { get; set; } = "";
        public DateTime LastSeen { get; set; }
        public bool IsActive { get; set; }
    }
}
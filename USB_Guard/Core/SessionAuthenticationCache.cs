using System;
using System.Collections.Concurrent;
using System.Timers;

namespace USB_Guard.Core
{
    /// <summary>
    /// In-memory authentication cache for session-based device authorization
    /// Cache clears on app restart (no persistent whitelist)
    /// </summary>
    public class SessionAuthenticationCache
    {
        private readonly ConcurrentDictionary<string, AuthenticationEntry> _cache;
        private readonly SecurityLogger _logger;
        private readonly Timer _cleanupTimer;
        private readonly TimeSpan _expirationTime;

        public SessionAuthenticationCache(TimeSpan? expirationTime = null)
        {
            _cache = new ConcurrentDictionary<string, AuthenticationEntry>();
            _logger = new SecurityLogger();
            _expirationTime = expirationTime ?? TimeSpan.FromMinutes(5); // Default: 5 minutes
            
            // Setup automatic cleanup timer (runs every minute)
            _cleanupTimer = new Timer(60000); // 1 minute
            _cleanupTimer.Elapsed += CleanupExpiredEntries;
            _cleanupTimer.Start();
            
            _logger.LogInfo($"Session authentication cache initialized (expiration: {_expirationTime.TotalMinutes} minutes)");
        }

        /// <summary>
        /// Add authenticated device to cache
        /// </summary>
        public void AddAuthenticated(string hardwareId, string deviceName, string deviceType)
        {
            try
            {
                if (string.IsNullOrEmpty(hardwareId))
                {
                    _logger.LogWarning("Cannot add null/empty Hardware ID to cache");
                    return;
                }

                var entry = new AuthenticationEntry
                {
                    HardwareID = hardwareId,
                    DeviceName = deviceName ?? "Unknown Device",
                    DeviceType = deviceType ?? "Unknown",
                    AuthenticatedTime = DateTime.Now,
                    ExpirationTime = DateTime.Now.Add(_expirationTime),
                    IsAuthenticated = true
                };

                _cache[hardwareId] = entry;
                
                _logger.LogInfo($"Device added to authentication cache: {deviceName} ({hardwareId}) - Expires in {_expirationTime.TotalMinutes} minutes");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error adding device to cache: {ex.Message}");
            }
        }

        /// <summary>
        /// Check if device is authenticated and cache is still valid
        /// </summary>
        public bool IsAuthenticated(string hardwareId)
        {
            try
            {
                if (string.IsNullOrEmpty(hardwareId))
                {
                    return false;
                }

                if (_cache.TryGetValue(hardwareId, out var entry))
                {
                    // Check if expired
                    if (entry.ExpirationTime < DateTime.Now)
                    {
                        _logger.LogInfo($"Authentication expired for {hardwareId}");
                        RemoveAuthenticated(hardwareId);
                        return false;
                    }

                    _logger.LogInfo($"Device found in cache (authenticated): {entry.DeviceName} ({hardwareId})");
                    return entry.IsAuthenticated;
                }

                return false;
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error checking authentication: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Remove device from authentication cache
        /// </summary>
        public void RemoveAuthenticated(string hardwareId)
        {
            try
            {
                if (_cache.TryRemove(hardwareId, out var entry))
                {
                    _logger.LogInfo($"Device removed from authentication cache: {entry.DeviceName} ({hardwareId})");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error removing device from cache: {ex.Message}");
            }
        }

        /// <summary>
        /// Clear all authenticated devices from cache
        /// </summary>
        public void ClearAll()
        {
            try
            {
                var count = _cache.Count;
                _cache.Clear();
                _logger.LogInfo($"Authentication cache cleared ({count} entries removed)");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error clearing cache: {ex.Message}");
            }
        }

        /// <summary>
        /// Get authentication entry details
        /// </summary>
        public AuthenticationEntry GetEntry(string hardwareId)
        {
            _cache.TryGetValue(hardwareId, out var entry);
            return entry;
        }

        /// <summary>
        /// Get all authenticated devices (for display)
        /// </summary>
        public ConcurrentDictionary<string, AuthenticationEntry> GetAllAuthenticated()
        {
            return new ConcurrentDictionary<string, AuthenticationEntry>(_cache);
        }

        /// <summary>
        /// Get count of authenticated devices
        /// </summary>
        public int GetAuthenticatedCount()
        {
            return _cache.Count;
        }

        /// <summary>
        /// Extend authentication for a device (reset expiration timer)
        /// </summary>
        public void ExtendAuthentication(string hardwareId)
        {
            try
            {
                if (_cache.TryGetValue(hardwareId, out var entry))
                {
                    entry.ExpirationTime = DateTime.Now.Add(_expirationTime);
                    _cache[hardwareId] = entry;
                    
                    _logger.LogInfo($"Authentication extended for {entry.DeviceName} ({hardwareId})");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error extending authentication: {ex.Message}");
            }
        }

        /// <summary>
        /// Get time remaining until authentication expires
        /// </summary>
        public TimeSpan? GetTimeRemaining(string hardwareId)
        {
            if (_cache.TryGetValue(hardwareId, out var entry))
            {
                var remaining = entry.ExpirationTime - DateTime.Now;
                if (remaining > TimeSpan.Zero)
                {
                    return remaining;
                }
                return null;
            }
            
            return null;
        }

        /// <summary>
        /// Automatic cleanup of expired entries
        /// </summary>
        private void CleanupExpiredEntries(object sender, ElapsedEventArgs e)
        {
            try
            {
                var now = DateTime.Now;
                var expiredKeys = new System.Collections.Generic.List<string>();

                foreach (var kvp in _cache)
                {
                    if (kvp.Value.ExpirationTime < now)
                    {
                        expiredKeys.Add(kvp.Key);
                    }
                }

                foreach (var key in expiredKeys)
                {
                    RemoveAuthenticated(key);
                }

                if (expiredKeys.Count > 0)
                {
                    _logger.LogInfo($"Cleaned up {expiredKeys.Count} expired authentication entries");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error in cleanup timer: {ex.Message}");
            }
        }

        /// <summary>
        /// Dispose resources
        /// </summary>
        public void Dispose()
        {
            _cleanupTimer?.Stop();
            _cleanupTimer?.Dispose();
            ClearAll();
            _logger.LogInfo("Session authentication cache disposed");
        }
    }

    /// <summary>
    /// Represents an authenticated device entry in cache
    /// </summary>
    public class AuthenticationEntry
    {
        public string HardwareID { get; set; }
        public string DeviceName { get; set; }
        public string DeviceType { get; set; }
        public DateTime AuthenticatedTime { get; set; }
        public DateTime ExpirationTime { get; set; }
        public bool IsAuthenticated { get; set; }

        public TimeSpan TimeRemaining => ExpirationTime - DateTime.Now;
        
        public bool IsExpired => ExpirationTime < DateTime.Now;

        public override string ToString()
        {
            return $"{DeviceName} ({DeviceType}) - Authenticated: {AuthenticatedTime}, Expires: {ExpirationTime}";
        }
    }
}

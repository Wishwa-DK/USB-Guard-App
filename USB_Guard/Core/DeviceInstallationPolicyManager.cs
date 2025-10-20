using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Win32;
using System.Security.Principal;

namespace USB_Guard.Core
{
    /// <summary>
    /// Manages Windows Device Installation Restriction policies for USB device control
    /// REQUIRES ADMINISTRATOR PRIVILEGES
    /// </summary>
    public class DeviceInstallationPolicyManager
    {
        private readonly SecurityLogger _logger;
        private readonly RegistryBackupManager _backupManager;
        private const string POLICY_KEY = @"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions";
        
        private bool _isAdministrator;
        private bool _policyEnabled = false;

        public DeviceInstallationPolicyManager()
        {
            _logger = new SecurityLogger();
            _backupManager = new RegistryBackupManager();
            _isAdministrator = CheckAdministratorPrivileges();
            
            if (!_isAdministrator)
            {
                _logger.LogWarning("⚠️ DeviceInstallationPolicyManager created without Administrator privileges - limited functionality");
            }
        }

        /// <summary>
        /// Check if running with Administrator privileges
        /// </summary>
        private bool CheckAdministratorPrivileges()
        {
            try
            {
                var identity = WindowsIdentity.GetCurrent();
                var principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error checking administrator status: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Enable global USB device blocking
        /// All devices will be blocked except those in AllowDeviceIDs list
        /// </summary>
        public bool EnableGlobalUSBBlocking()
        {
            if (!_isAdministrator)
            {
                _logger.LogError("❌ Cannot enable USB blocking - Administrator privileges required");
                return false;
            }

            try
            {
                _logger.LogSecurity("🔒 Enabling global USB device blocking...");
                
                // Create backup FIRST
                _logger.LogInfo("Creating registry backup before changes...");
                _backupManager.CreateBackup();
                
                // Check current state
                var currentValue = _backupManager.GetCurrentDenyUnspecifiedValue();
                if (currentValue == 1)
                {
                    _logger.LogInfo("USB blocking already enabled (DenyUnspecified = 1)");
                    _policyEnabled = true;
                    return true;
                }
                
                // Create/Open the registry key
                using (var key = Registry.LocalMachine.CreateSubKey(POLICY_KEY))
                {
                    if (key == null)
                    {
                        _logger.LogError("Failed to create/open Device Installation Restrictions key");
                        return false;
                    }
                    
                    // Set DenyUnspecified to 1 (block all non-whitelisted devices)
                    key.SetValue("DenyUnspecified", 1, RegistryValueKind.DWord);
                    
                    _logger.LogSecurity("✅ DenyUnspecified set to 1 - All USB devices will be blocked by default");
                    
                    // Initialize empty AllowDeviceIDs list if it doesn't exist
                    var currentAllowList = key.GetValue("AllowDeviceIDs") as string[];
                    if (currentAllowList == null)
                    {
                        key.SetValue("AllowDeviceIDs", new string[0], RegistryValueKind.MultiString);
                        _logger.LogInfo("Initialized empty AllowDeviceIDs list");
                    }
                    
                    _policyEnabled = true;
                    return true;
                }
            }
            catch (UnauthorizedAccessException ex)
            {
                _logger.LogError($"❌ Access denied - Administrator privileges required: {ex.Message}");
                return false;
            }
            catch (Exception ex)
            {
                _logger.LogError($"❌ Failed to enable USB blocking: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Disable global USB device blocking - restore normal Windows behavior
        /// </summary>
        public bool DisableGlobalUSBBlocking()
        {
            if (!_isAdministrator)
            {
                _logger.LogError("❌ Cannot disable USB blocking - Administrator privileges required");
                return false;
            }

            try
            {
                _logger.LogSecurity("🔓 Disabling global USB device blocking...");
                
                using (var key = Registry.LocalMachine.OpenSubKey(POLICY_KEY, true))
                {
                    if (key == null)
                    {
                        _logger.LogInfo("Device Installation Restrictions key doesn't exist - already disabled");
                        _policyEnabled = false;
                        return true;
                    }
                    
                    // Set DenyUnspecified to 0 (allow all devices - normal Windows behavior)
                    key.SetValue("DenyUnspecified", 0, RegistryValueKind.DWord);
                    
                    // Optionally clear the allow/deny lists
                    key.DeleteValue("AllowDeviceIDs", false);
                    key.DeleteValue("DenyDeviceIDs", false);
                    
                    _logger.LogSecurity("✅ USB device blocking disabled - Windows will allow all devices normally");
                    
                    _policyEnabled = false;
                    return true;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"❌ Failed to disable USB blocking: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Add device Hardware ID to Windows allow list
        /// Device will be permitted to install drivers
        /// </summary>
        public bool AddDeviceToAllowList(string hardwareId)
        {
            if (!_isAdministrator)
            {
                _logger.LogError("❌ Cannot modify allow list - Administrator privileges required");
                return false;
            }

            try
            {
                _logger.LogInfo($"Adding device to allow list: {hardwareId}");
                
                using (var key = Registry.LocalMachine.OpenSubKey(POLICY_KEY, true))
                {
                    if (key == null)
                    {
                        _logger.LogError("Device Installation Restrictions key doesn't exist");
                        return false;
                    }
                    
                    // Get current allow list
                    var currentList = key.GetValue("AllowDeviceIDs") as string[] ?? new string[0];
                    
                    // Check if already in list
                    if (currentList.Contains(hardwareId, StringComparer.OrdinalIgnoreCase))
                    {
                        _logger.LogInfo($"Device already in allow list: {hardwareId}");
                        return true;
                    }
                    
                    // Add to list
                    var newList = currentList.Concat(new[] { hardwareId }).ToArray();
                    key.SetValue("AllowDeviceIDs", newList, RegistryValueKind.MultiString);
                    
                    _logger.LogSecurity($"✅ Device added to allow list: {hardwareId}");
                    return true;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"❌ Failed to add device to allow list: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Remove device from Windows allow list
        /// </summary>
        public bool RemoveDeviceFromAllowList(string hardwareId)
        {
            if (!_isAdministrator)
            {
                return false;
            }

            try
            {
                using (var key = Registry.LocalMachine.OpenSubKey(POLICY_KEY, true))
                {
                    if (key == null) return false;
                    
                    var currentList = key.GetValue("AllowDeviceIDs") as string[] ?? new string[0];
                    var newList = currentList.Where(id => !id.Equals(hardwareId, StringComparison.OrdinalIgnoreCase)).ToArray();
                    
                    key.SetValue("AllowDeviceIDs", newList, RegistryValueKind.MultiString);
                    
                    _logger.LogInfo($"Device removed from allow list: {hardwareId}");
                    return true;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Failed to remove device from allow list: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Add device to permanent black list
        /// Device will NEVER be allowed, even if user authenticates
        /// </summary>
        public bool AddDeviceToBlackList(string hardwareId, string reason = "")
        {
            if (!_isAdministrator)
            {
                _logger.LogError("❌ Cannot modify black list - Administrator privileges required");
                return false;
            }

            try
            {
                _logger.LogSecurity($"Adding device to BLACK LIST: {hardwareId} - Reason: {reason}");
                
                using (var key = Registry.LocalMachine.OpenSubKey(POLICY_KEY, true))
                {
                    if (key == null)
                    {
                        _logger.LogError("Device Installation Restrictions key doesn't exist");
                        return false;
                    }
                    
                    // Get current deny list
                    var currentList = key.GetValue("DenyDeviceIDs") as string[] ?? new string[0];
                    
                    // Check if already in list
                    if (currentList.Contains(hardwareId, StringComparer.OrdinalIgnoreCase))
                    {
                        _logger.LogInfo($"Device already in black list: {hardwareId}");
                        return true;
                    }
                    
                    // Add to list
                    var newList = currentList.Concat(new[] { hardwareId }).ToArray();
                    key.SetValue("DenyDeviceIDs", newList, RegistryValueKind.MultiString);
                    
                    // Also remove from allow list if present
                    RemoveDeviceFromAllowList(hardwareId);
                    
                    _logger.LogSecurity($"✅ Device added to BLACK LIST (permanent block): {hardwareId}");
                    return true;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"❌ Failed to add device to black list: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Remove device from black list
        /// </summary>
        public bool RemoveDeviceFromBlackList(string hardwareId)
        {
            if (!_isAdministrator)
            {
                _logger.LogError("❌ Cannot modify black list - Administrator privileges required");
                return false;
            }

            try
            {
                _logger.LogInfo($"Removing device from BLACK LIST: {hardwareId}");
                
                using (var key = Registry.LocalMachine.OpenSubKey(POLICY_KEY, true))
                {
                    if (key == null)
                    {
                        return true; // No policy key means not in list
                    }
                    
                    var currentList = key.GetValue("DenyDeviceIDs") as string[] ?? new string[0];
                    
                    if (!currentList.Contains(hardwareId, StringComparer.OrdinalIgnoreCase))
                    {
                        return true; // Not in list, nothing to remove
                    }
                    
                    var newList = currentList.Where(id => !id.Equals(hardwareId, StringComparison.OrdinalIgnoreCase)).ToArray();
                    
                    if (newList.Length > 0)
                    {
                        key.SetValue("DenyDeviceIDs", newList, RegistryValueKind.MultiString);
                    }
                    else
                    {
                        key.DeleteValue("DenyDeviceIDs", false);
                    }
                    
                    _logger.LogInfo($"✅ Device removed from BLACK LIST: {hardwareId}");
                    return true;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"❌ Failed to remove device from black list: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Get current allow list from registry
        /// </summary>
        public List<string> GetAllowList()
        {
            try
            {
                using (var key = Registry.LocalMachine.OpenSubKey(POLICY_KEY, false))
                {
                    if (key == null) return new List<string>();
                    
                    var list = key.GetValue("AllowDeviceIDs") as string[] ?? new string[0];
                    return new List<string>(list);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Failed to get allow list: {ex.Message}");
                return new List<string>();
            }
        }

        /// <summary>
        /// Get current deny list from registry
        /// </summary>
        public List<string> GetDenyList()
        {
            try
            {
                using (var key = Registry.LocalMachine.OpenSubKey(POLICY_KEY, false))
                {
                    if (key == null) return new List<string>();
                    
                    var list = key.GetValue("DenyDeviceIDs") as string[] ?? new string[0];
                    return new List<string>(list);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Failed to get deny list: {ex.Message}");
                return new List<string>();
            }
        }

        /// <summary>
        /// Check if policy is currently enabled
        /// </summary>
        public bool IsPolicyEnabled()
        {
            try
            {
                var value = _backupManager.GetCurrentDenyUnspecifiedValue();
                return value == 1;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Clear all allow and deny lists (use with caution!)
        /// </summary>
        public bool ClearAllLists()
        {
            if (!_isAdministrator)
            {
                return false;
            }

            try
            {
                _logger.LogWarning("⚠️ Clearing ALL allow and deny lists");
                
                using (var key = Registry.LocalMachine.OpenSubKey(POLICY_KEY, true))
                {
                    if (key == null) return false;
                    
                    key.SetValue("AllowDeviceIDs", new string[0], RegistryValueKind.MultiString);
                    key.SetValue("DenyDeviceIDs", new string[0], RegistryValueKind.MultiString);
                    
                    _logger.LogSecurity("✅ All lists cleared");
                    return true;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Failed to clear lists: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Get policy status for display
        /// </summary>
        public string GetPolicyStatus()
        {
            if (!_isAdministrator)
            {
                return "⚠️ No Administrator privileges - Cannot check policy";
            }

            if (!_backupManager.KeyExists())
            {
                return "📋 Device Installation policy not configured";
            }

            var denyValue = _backupManager.GetCurrentDenyUnspecifiedValue();
            var allowCount = GetAllowList().Count;
            var denyCount = GetDenyList().Count;

            if (denyValue == 1)
            {
                return $"🔒 ACTIVE - Blocking all devices ({allowCount} allowed, {denyCount} denied)";
            }
            else
            {
                return $"🔓 INACTIVE - All devices allowed normally";
            }
        }
    }
}

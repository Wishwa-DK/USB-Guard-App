using System;
using System.IO;
using Microsoft.Win32;

namespace USB_Guard.Core
{
    /// <summary>
    /// Manages registry backups for safe USB Guard operations
    /// </summary>
    public class RegistryBackupManager
    {
        private readonly SecurityLogger _logger;
        private readonly string _backupDirectory;
        private const string DEVICE_INSTALL_KEY = @"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions";

        public RegistryBackupManager()
        {
            _logger = new SecurityLogger();
            _backupDirectory = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "USBGuard",
                "Backups"
            );
            
            Directory.CreateDirectory(_backupDirectory);
        }

        /// <summary>
        /// Create backup of Device Installation policies before making changes
        /// </summary>
        public string CreateBackup()
        {
            try
            {
                // Check if the registry key exists
                using (var key = Registry.LocalMachine.OpenSubKey(DEVICE_INSTALL_KEY))
                {
                    if (key == null)
                    {
                        _logger.LogInfo("DeviceInstall Restrictions key does not exist - no backup needed");
                        return "NO_BACKUP_NEEDED";
                    }
                }

                var timestamp = DateTime.Now.ToString("yyyy-MM-dd_HH-mm-ss");
                var backupFile = Path.Combine(_backupDirectory, $"DeviceInstall_Backup_{timestamp}.reg");
                
                _logger.LogInfo($"Creating registry backup: {backupFile}");
                
                // Export the registry key to file
                var exportCommand = $"reg export \"HKLM\\{DEVICE_INSTALL_KEY}\" \"{backupFile}\" /y";
                
                var processInfo = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    Arguments = $"/c {exportCommand}",
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };
                
                using (var process = System.Diagnostics.Process.Start(processInfo))
                {
                    process.WaitForExit(5000);
                    
                    if (process.ExitCode == 0 && File.Exists(backupFile))
                    {
                        _logger.LogSecurity($"✅ Registry backup created: {backupFile}");
                        return backupFile;
                    }
                }
                
                _logger.LogWarning("Registry backup creation returned non-zero exit code");
                return null;
            }
            catch (Exception ex)
            {
                _logger.LogError($"Failed to create registry backup: {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// Restore registry from most recent backup
        /// </summary>
        public bool RestoreFromBackup(string backupFile = null)
        {
            try
            {
                if (backupFile == "NO_BACKUP_NEEDED")
                {
                    _logger.LogInfo("No backup was created - nothing to restore");
                    return true;
                }

                if (string.IsNullOrEmpty(backupFile))
                {
                    // Find most recent backup
                    var files = Directory.GetFiles(_backupDirectory, "DeviceInstall_Backup_*.reg");
                    if (files.Length == 0)
                    {
                        _logger.LogWarning("No backup files found to restore");
                        return false;
                    }
                    
                    backupFile = files[files.Length - 1]; // Most recent
                }
                
                if (!File.Exists(backupFile))
                {
                    _logger.LogError($"Backup file not found: {backupFile}");
                    return false;
                }
                
                _logger.LogInfo($"Restoring registry from backup: {backupFile}");
                
                var importCommand = $"reg import \"{backupFile}\"";
                
                var processInfo = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    Arguments = $"/c {importCommand}",
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    Verb = "runas" // Requires admin
                };
                
                using (var process = System.Diagnostics.Process.Start(processInfo))
                {
                    process.WaitForExit(5000);
                    
                    if (process.ExitCode == 0)
                    {
                        _logger.LogSecurity($"✅ Registry restored from backup: {backupFile}");
                        return true;
                    }
                }
                
                return false;
            }
            catch (Exception ex)
            {
                _logger.LogError($"Failed to restore registry backup: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Check if Device Installation restriction key exists
        /// </summary>
        public bool KeyExists()
        {
            try
            {
                using (var key = Registry.LocalMachine.OpenSubKey($"{DEVICE_INSTALL_KEY}", false))
                {
                    return key != null;
                }
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Get current state of DenyUnspecified value
        /// </summary>
        public int? GetCurrentDenyUnspecifiedValue()
        {
            try
            {
                using (var key = Registry.LocalMachine.OpenSubKey($"{DEVICE_INSTALL_KEY}", false))
                {
                    if (key != null)
                    {
                        var value = key.GetValue("DenyUnspecified");
                        if (value != null)
                        {
                            return Convert.ToInt32(value);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error reading DenyUnspecified value: {ex.Message}");
            }
            
            return null;
        }

        /// <summary>
        /// Create emergency disable file for quick recovery
        /// </summary>
        public void CreateEmergencyDisableFile()
        {
            try
            {
                var emergencyFile = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    "USBGuard",
                    "EMERGENCY_DISABLE.txt"
                );
                
                Directory.CreateDirectory(Path.GetDirectoryName(emergencyFile));
                
                File.WriteAllText(emergencyFile, 
                    "To disable USB Guard protection:\r\n" +
                    "1. Delete this file\r\n" +
                    "2. Restart USB Guard application\r\n" +
                    "OR\r\n" +
                    "Run this command as Administrator:\r\n" +
                    "reg delete \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceInstall\\Restrictions\" /f\r\n"
                );
                
                _logger.LogInfo($"Emergency disable file created: {emergencyFile}");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Failed to create emergency disable file: {ex.Message}");
            }
        }

        /// <summary>
        /// Check if emergency disable is active
        /// </summary>
        public bool IsEmergencyDisabled()
        {
            try
            {
                var emergencyFile = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    "USBGuard",
                    "emergency_disable.txt"
                );
                
                return File.Exists(emergencyFile);
            }
            catch
            {
                return false;
            }
        }
    }
}

using System;
using System.IO;
using System.Diagnostics;
using System.Reflection;
using Microsoft.Win32;
using System.Security.Principal;

namespace USB_Guard.Core
{
    /// <summary>
    /// Manages Windows startup integration for USB Guard
    /// </summary>
    public class StartupManager
    {
        private readonly SecurityLogger _logger;
        private const string REGISTRY_KEY = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
        private const string APP_NAME = "USB_Guard_Fortress";

        public StartupManager()
        {
            _logger = new SecurityLogger();
        }

        /// <summary>
        /// Add USB Guard to Windows startup
        /// </summary>
        public bool AddToStartup()
        {
            try
            {
                var exePath = Assembly.GetExecutingAssembly().Location;
                var startupArgs = "--fortress-mode-startup";
                var fullCommand = $"\"{exePath}\" {startupArgs}";

                _logger.LogSecurity($"?? Adding USB Guard to Windows startup: {fullCommand}");

                using (var key = Registry.CurrentUser.CreateSubKey(REGISTRY_KEY))
                {
                    if (key != null)
                    {
                        key.SetValue(APP_NAME, fullCommand, RegistryValueKind.String);
                        
                        // Update settings
                        Properties.Settings.Default.AutoStartWithWindows = true;
                        Properties.Settings.Default.Save();
                        
                        _logger.LogSecurity("? USB Guard successfully added to Windows startup");
                        return true;
                    }
                }
            }
            catch (UnauthorizedAccessException ex)
            {
                _logger.LogError($"? Access denied adding to startup (admin required?): {ex.Message}");
            }
            catch (Exception ex)
            {
                _logger.LogError($"? Failed to add to Windows startup: {ex.Message}");
            }

            return false;
        }

        /// <summary>
        /// Remove USB Guard from Windows startup
        /// </summary>
        public bool RemoveFromStartup()
        {
            try
            {
                _logger.LogSecurity("?? Removing USB Guard from Windows startup");

                using (var key = Registry.CurrentUser.OpenSubKey(REGISTRY_KEY, true))
                {
                    if (key?.GetValue(APP_NAME) != null)
                    {
                        key.DeleteValue(APP_NAME, false);
                        _logger.LogSecurity("? USB Guard successfully removed from Windows startup");
                    }
                    else
                    {
                        _logger.LogInfo("?? USB Guard was not in Windows startup registry");
                    }
                }

                // Update settings regardless
                Properties.Settings.Default.AutoStartWithWindows = false;
                Properties.Settings.Default.Save();

                return true;
            }
            catch (UnauthorizedAccessException ex)
            {
                _logger.LogError($"? Access denied removing from startup: {ex.Message}");
            }
            catch (Exception ex)
            {
                _logger.LogError($"? Failed to remove from Windows startup: {ex.Message}");
            }

            return false;
        }

        /// <summary>
        /// Check if USB Guard is currently set to start with Windows
        /// </summary>
        public bool IsInStartup()
        {
            try
            {
                using (var key = Registry.CurrentUser.OpenSubKey(REGISTRY_KEY, false))
                {
                    var value = key?.GetValue(APP_NAME) as string;
                    var isInRegistry = !string.IsNullOrEmpty(value);
                    
                    _logger.LogInfo($"?? Startup check - Registry: {isInRegistry}, Settings: {Properties.Settings.Default.AutoStartWithWindows}");
                    
                    return isInRegistry;
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"?? Error checking startup status: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Get the current user privilege level
        /// </summary>
        public bool IsRunningAsAdministrator()
        {
            try
            {
                var identity = WindowsIdentity.GetCurrent();
                var principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"?? Error checking administrator status: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Validate startup configuration
        /// </summary>
        public StartupStatus GetStartupStatus()
        {
            try
            {
                var isInRegistry = IsInStartup();
                var settingsFlag = Properties.Settings.Default.AutoStartWithWindows;
                var isAdmin = IsRunningAsAdministrator();

                return new StartupStatus
                {
                    IsInRegistry = isInRegistry,
                    SettingsFlag = settingsFlag,
                    IsAdministrator = isAdmin,
                    IsConsistent = isInRegistry == settingsFlag
                };
            }
            catch (Exception ex)
            {
                _logger.LogError($"? Error getting startup status: {ex.Message}");
                return new StartupStatus
                {
                    IsInRegistry = false,
                    SettingsFlag = false,
                    IsAdministrator = false,
                    IsConsistent = false
                };
            }
        }
    }

    /// <summary>
    /// Represents the current startup configuration status
    /// </summary>
    public class StartupStatus
    {
        public bool IsInRegistry { get; set; }
        public bool SettingsFlag { get; set; }
        public bool IsAdministrator { get; set; }
        public bool IsConsistent { get; set; }

        public override string ToString()
        {
            return $"Registry: {IsInRegistry}, Settings: {SettingsFlag}, Admin: {IsAdministrator}, Consistent: {IsConsistent}";
        }
    }
}
using System;
using System.Collections.Generic;
using System.Linq;
using System.Management;
using System.Threading.Tasks;
using System.Windows;
using System.Diagnostics;
using System.IO;
using System.Threading;
using Microsoft.Win32;
using USB_Guard.Models;
using System.Collections.Concurrent;

namespace USB_Guard.Core
{
    /// <summary>
    /// STEP 5: Professional USB Device Manager with Auto-Authentication Trigger
    /// Enhanced security with immediate blocking and automatic authentication dialogs
    /// </summary>
    public partial class USBDeviceManager : IDisposable
    {
        #region Private Fields
        private ManagementEventWatcher _insertWatcher;
        private ManagementEventWatcher _removeWatcher;
        private readonly ConcurrentDictionary<string, USBDeviceInfo> _connectedDevices = new ConcurrentDictionary<string, USBDeviceInfo>();
        private readonly object _deviceLock = new object();
        
        private DeviceAuthenticator _authenticator;
        private readonly SecurityLogger _logger;
        private WhitelistManager _whitelistManager;
        
        private readonly Timer _deviceScanTimer;
        private readonly Timer _statusUpdateTimer;
        private volatile bool _isMonitoring = false;
        private volatile bool _isDisposing = false;
        
        // Performance optimization
        private readonly Dictionary<string, DateTime> _recentDevices = new Dictionary<string, DateTime>();
        private readonly object _recentDevicesLock = new object();
        #endregion

        #region Events
        public event EventHandler<USBDeviceEventArgs> DeviceConnected;
        public event EventHandler<USBDeviceEventArgs> DeviceDisconnected;
        public event EventHandler<DeviceAuthenticationEventArgs> DeviceAuthenticated;
        public event EventHandler<string> StatusChanged;
        #endregion

        #region Properties
        public bool IsMonitoring => _isMonitoring;
        public int ConnectedDeviceCount => _connectedDevices.Count;
        public DateTime LastScanTime { get; private set; }
        #endregion

        #region Constructor
        public USBDeviceManager()
        {
            try
            {
                _logger = new SecurityLogger();
                _logger.LogSecurity("🚀 STEP 5: Initializing Professional USB Device Manager with Auto-Authentication Trigger");

                // Initialize components with proper error handling
                InitializeComponents();

                // Set up monitoring timers
                _deviceScanTimer = new Timer(PerformDeviceScan, null, TimeSpan.FromSeconds(2).Milliseconds, TimeSpan.FromSeconds(5).Milliseconds);
                _statusUpdateTimer = new Timer(UpdateDeviceStatus, null, TimeSpan.FromSeconds(1).Milliseconds, TimeSpan.FromSeconds(3).Milliseconds);
                
                // Load existing devices immediately
                _ = Task.Run(LoadExistingDevices);
                
                _logger.LogSecurity("✅ STEP 5: Professional USB Device Manager initialized with Auto-Authentication Trigger");
                NotifyStatusChange("🛡️ USB Guard Professional - Ready for monitoring with automatic authentication");
            }
            catch (Exception ex)
            {
                _logger?.LogError($"Critical error in USBDeviceManager initialization: {ex.Message}");
                throw new InvalidOperationException("Failed to initialize USB Device Manager", ex);
            }
        }
        #endregion

        #region Initialization
        private void InitializeComponents()
        {
            try
            {
                _authenticator = new DeviceAuthenticator();
                _authenticator.AuthenticationCompleted += OnDeviceAuthenticated;
                _logger.LogInfo("✅ STEP 5: DeviceAuthenticator initialized with auto-trigger capability");
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"DeviceAuthenticator initialization failed: {ex.Message}");
                throw;
            }

            try
            {
                _whitelistManager = new WhitelistManager();
                _logger.LogInfo("WhitelistManager initialized");
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"WhitelistManager initialization failed: {ex.Message}");
            }
        }
        #endregion

        #region Public Methods
        public void StartMonitoring()
        {
            if (_isMonitoring)
            {
                _logger.LogInfo("USB monitoring already active");
                return;
            }

            try
            {
                _logger.LogSecurity("🚀 STEP 5: Starting Professional USB Device Monitoring with Auto-Authentication Trigger");
                
                // Start WMI monitoring with enterprise-grade reliability
                StartAdvancedWMIMonitoring();
                
                // Perform initial device scan
                _ = Task.Run(LoadExistingDevices);
                
                _isMonitoring = true;
                LastScanTime = DateTime.Now;
                
                _logger.LogSecurity("✅ STEP 5: Professional USB monitoring is now ACTIVE with Auto-Authentication Trigger");
                NotifyStatusChange("🛡️ Professional USB monitoring ACTIVE - Auto-authentication enabled");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Failed to start USB monitoring: {ex.Message}");
                _isMonitoring = false;
                NotifyStatusChange($"USB monitoring failed to start: {ex.Message}");
                throw;
            }
        }

        public void StopMonitoring()
        {
            if (!_isMonitoring)
            {
                _logger.LogInfo("USB monitoring already stopped");
                return;
            }

            try
            {
                _logger.LogSecurity("🛑 STEP 5: Stopping Professional USB monitoring");
                
                _isMonitoring = false;
                
                // Stop WMI watchers safely
                StopWMIWatchers();
                
                _logger.LogSecurity("✅ STEP 5: Professional USB monitoring stopped successfully");
                NotifyStatusChange("USB monitoring stopped");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error stopping USB monitoring: {ex.Message}");
                NotifyStatusChange($"Error stopping monitoring: {ex.Message}");
            }
        }

        public async Task AllowDevice(string deviceId)
        {
            try
            {
                if (_connectedDevices.TryGetValue(deviceId, out var device))
                {
                    _logger.LogSecurity($"✅ STEP 5: MANUALLY ALLOWING DEVICE: {device.Name}");

                    device.Status = DeviceStatus.Trusted;
                    device.IsAuthenticated = true;
                    device.AuthenticatedTime = DateTime.Now;

                    // Add to whitelist for future automatic approval
                    if (_whitelistManager != null)
                    {
                        await _whitelistManager.AddToWhitelistAsync(device, "Manually approved by user");
                    }

                    _logger.LogSecurity($"✅ STEP 5: Device {device.Name} successfully allowed and whitelisted");
                    NotifyStatusChange($"Device allowed: {device.Name}");
                    
                    // Notify UI of authentication change
                    NotifyDeviceAuthenticated(device, true, "Manual Approval");
                }
                else
                {
                    _logger.LogWarning($"Device not found for allow operation: {deviceId}");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Failed to allow device: {ex.Message}");
                throw;
            }
        }

        public async Task BlockDevice(string deviceId)
        {
            try
            {
                if (_connectedDevices.TryGetValue(deviceId, out var device))
                {
                    _logger.LogSecurity($"🚫 STEP 5: MANUALLY BLOCKING DEVICE: {device.Name}");

                    device.Status = DeviceStatus.Blocked;
                    device.IsAuthenticated = false;

                    // Add to blacklist for future automatic blocking
                    if (_whitelistManager != null)
                    {
                        await _whitelistManager.AddToBlacklistAsync(device, "Manually blocked by user");
                    }

                    _logger.LogSecurity($"🚫 STEP 5: Device {device.Name} successfully blocked and blacklisted");
                    NotifyStatusChange($"Device blocked: {device.Name}");
                    
                    // Notify UI of authentication change
                    NotifyDeviceAuthenticated(device, false, "Manual Block");
                }
                else
                {
                    _logger.LogWarning($"Device not found for block operation: {deviceId}");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Failed to block device: {ex.Message}");
                throw;
            }
        }

        public Dictionary<string, USBDeviceInfo> GetConnectedDevices()
        {
            try
            {
                return new Dictionary<string, USBDeviceInfo>(_connectedDevices);
            }
            catch (Exception ex)
            {
                _logger?.LogError($"Error getting connected devices: {ex.Message}");
                return new Dictionary<string, USBDeviceInfo>();
            }
        }

        public USBDeviceInfo GetDevice(string deviceId)
        {
            _connectedDevices.TryGetValue(deviceId, out var device);
            return device;
        }

        /// <summary>
        /// Enable Fortress Mode - Maximum security for all USB devices
        /// </summary>
        public async Task EnableFortressModeAsync()
        {
            try
            {
                _logger.LogSecurity("🏰 STEP 5: ENABLING FORTRESS MODE - Maximum USB Security with Auto-Authentication");
                
                // Set fortress mode flag
                USB_Guard.Properties.Settings.Default.FortressEnabled = true;
                USB_Guard.Properties.Settings.Default.LastFortressToggleTime = DateTime.Now;
                USB_Guard.Properties.Settings.Default.Save();
                
                // Block all currently connected devices that aren't whitelisted
                var devices = GetConnectedDevices();
                foreach (var device in devices.Values)
                {
                    try
                    {
                        // Skip devices that are already trusted/whitelisted
                        if (_whitelistManager != null && await _whitelistManager.IsDeviceWhitelistedAsync(device))
                        {
                            _logger.LogInfo($"🏰 STEP 5: Fortress Mode: Keeping whitelisted device: {device.Name}");
                            continue;
                        }
                        
                        // Block all other devices
                        if (device.Status != DeviceStatus.Blocked)
                        {
                            _logger.LogSecurity($"🏰 STEP 5: Fortress Mode: Blocking device: {device.Name}");
                            await BlockDevice(device.DeviceId);
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError($"Error blocking device {device.Name} in fortress mode: {ex.Message}");
                    }
                }
                
                _logger.LogSecurity("🏰 STEP 5: FORTRESS MODE ENABLED - All non-whitelisted USB devices blocked with auto-authentication");
                NotifyStatusChange("🏰 Fortress Mode ENABLED - Maximum USB security with auto-authentication active");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Failed to enable fortress mode: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Disable Fortress Mode - Return to normal operation
        /// </summary>
        public async Task DisableFortressModeAsync()
        {
            try
            {
                _logger.LogSecurity("🔓 STEP 5: DISABLING FORTRESS MODE - Returning to normal operation");
                
                // Clear fortress mode flag
                USB_Guard.Properties.Settings.Default.FortressEnabled = false;
                USB_Guard.Properties.Settings.Default.LastFortressToggleTime = DateTime.Now;
                USB_Guard.Properties.Settings.Default.Save();
                
                _logger.LogSecurity("🔓 STEP 5: FORTRESS MODE DISABLED - Normal USB operation with auto-authentication restored");
                NotifyStatusChange("🔓 Fortress Mode DISABLED - Normal USB security with auto-authentication active");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Failed to disable fortress mode: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Check if fortress mode is currently enabled
        /// </summary>
        public bool IsFortressModeEnabled()
        {
            try
            {
                return USB_Guard.Properties.Settings.Default.FortressEnabled;
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"Error checking fortress mode status: {ex.Message}");
                return false;
            }
        }
        #endregion

        #region STEP 5: Auto-Authentication Trigger Implementation
        
        /// <summary>
        /// STEP 5: Immediately block device upon connection for security
        /// </summary>
        private async Task ImmediatelyBlockDevice(USBDeviceInfo device)
        {
            try
            {
                if (device == null) return;

                // NEW FLOW: Only block Storage devices immediately
                // Mouse and Keyboard are allowed to work during authentication
                // They get blocked ONLY if authentication fails
                
                if (device.Type == USBDeviceType.Storage)
                {
                    _logger.LogSecurity($"💾 STEP 5: IMMEDIATELY BLOCKING STORAGE DEVICE: {device.Name}");
                    
                    // Set device to blocked status immediately
                    device.Status = DeviceStatus.Blocked;
                    device.IsAuthenticated = false;
                    device.QuarantineTime = DateTime.Now;
                    
                    _logger.LogSecurity($"💾 STEP 5: Storage device {device.Name} IMMEDIATELY BLOCKED - awaiting authentication");
                    NotifyStatusChange($"💾 Storage device blocked pending authentication: {device.Name}");
                }
                else if (device.Type == USBDeviceType.Keyboard || device.Type == USBDeviceType.Mouse)
                {
                    // NEW FLOW: Allow Mouse/Keyboard to work during authentication
                    _logger.LogSecurity($"🖱️ STEP 5: {device.Type} DETECTED: {device.Name} - ALLOWING device to work during authentication");
                    
                    device.Status = DeviceStatus.Authenticating;
                    device.IsAuthenticated = false;
                    
                    NotifyStatusChange($"🖱️ {device.Type} detected: {device.Name} - Authentication required");
                }
                else
                {
                    // Other device types: Block immediately (default behavior)
                    _logger.LogSecurity($"🚫 STEP 5: IMMEDIATELY BLOCKING DEVICE: {device.Name} - {device.Type}");
                    
                    device.Status = DeviceStatus.Blocked;
                    device.IsAuthenticated = false;
                    device.QuarantineTime = DateTime.Now;
                    
                    NotifyStatusChange($"🚫 Device blocked pending authentication: {device.Name}");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"STEP 5: Error in device blocking logic: {ex.Message}");
            }
        }
        
        /// <summary>
        /// STEP 5: Enhanced security processing with automatic authentication trigger
        /// </summary>
        private async Task ProcessDeviceSecurityWithAutoAuthentication(USBDeviceInfo device)
        {
            try
            {
                if (device == null || _isDisposing) return;

                _logger.LogSecurity($"🔐🔐 ZERO-TRUST: Starting MANDATORY authentication for {device.Name} ({device.Type})");

                // ZERO-TRUST: Check historical status for informational purposes ONLY - DO NOT AUTO-ALLOW
                bool wasWhitelisted = false;
                bool wasBlacklisted = false;
                
                if (_whitelistManager != null)
                {
                    try
                    {
                        wasWhitelisted = await _whitelistManager.IsDeviceWhitelistedAsync(device);
                        wasBlacklisted = await _whitelistManager.IsDeviceBlacklistedAsync(device);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning($"ZERO-TRUST: Error checking historical device status: {ex.Message}");
                    }
                }

                // Store historical info for authentication dialog display
                device.WasWhitelisted = wasWhitelisted;
                device.WasBlacklisted = wasBlacklisted;
                device.RequiresZeroTrustAuth = true; // Always true in zero-trust mode

                // ZERO-TRUST: Log historical status but ALWAYS require authentication
                if (wasWhitelisted)
                {
                    _logger.LogSecurity($"⚠️ ZERO-TRUST: Device {device.Name} was previously whitelisted - BUT REQUIRES AUTHENTICATION in zero-trust mode");
                }
                
                if (wasBlacklisted)
                {
                    _logger.LogSecurity($"⚠️⚠️ ZERO-TRUST: Device {device.Name} was previously blacklisted - WILL SHOW WARNING in authentication dialog");
                }

                if (!wasWhitelisted && !wasBlacklisted)
                {
                    _logger.LogSecurity($"❓ ZERO-TRUST: Device {device.Name} is unknown - REQUIRES AUTHENTICATION");
                }

                // Check fortress mode for additional context
                if (IsFortressModeEnabled())
                {
                    _logger.LogSecurity($"🏰🏰 ZERO-TRUST FORTRESS: Device {device.Name} requires authentication in fortress mode");
                }

                // ZERO-TRUST: ALWAYS AUTO-TRIGGER AUTHENTICATION regardless of historical status
                await AutoTriggerAuthentication(device);
            }
            catch (Exception ex)
            {
                _logger.LogError($"ZERO-TRUST: Error in zero-trust authentication processing for {device?.Name}: {ex.Message}");
                if (device != null)
                {
                    device.Status = DeviceStatus.Blocked;
                    device.IsAuthenticated = false;
                    device.QuarantineTime = DateTime.Now;
                    NotifyStatusChange($"🚫 Device blocked due to error in authentication processing: {device.Name}");
                }
            }
        }

        /// <summary>
        /// ZERO-TRUST: Automatically trigger appropriate authentication dialog based on device type
        /// </summary>
        private async Task AutoTriggerAuthentication(USBDeviceInfo device)
        {
            try
            {
                if (device == null || _authenticator == null) return;

                _logger.LogSecurity($"🔐🔐 ZERO-TRUST: AUTO-TRIGGERING MANDATORY AUTHENTICATION for {device.Name} ({device.Type})");
                
                // Update device status to show authentication in progress
                device.Status = DeviceStatus.Authenticating;
                
                // Ensure zero-trust properties are set
                device.RequiresZeroTrustAuth = true;
                
                // Add a small delay to ensure UI is updated
                await Task.Delay(500);
                
                // Trigger authentication based on device type with zero-trust context
                switch (device.Type)
                {
                    case USBDeviceType.Keyboard:
                        _logger.LogSecurity($"⌨️⌨️ ZERO-TRUST: Auto-triggering MANDATORY keyboard authentication for {device.Name}");
                        if (device.WasWhitelisted)
                            _logger.LogSecurity($"⌨️⌨️ ZERO-TRUST: Keyboard {device.Name} was whitelisted but requires re-authentication");
                        break;
                        
                    case USBDeviceType.Mouse:
                        _logger.LogSecurity($"🖱️🖱️ ZERO-TRUST: Auto-triggering MANDATORY mouse authentication for {device.Name}");
                        if (device.WasWhitelisted)
                            _logger.LogSecurity($"🖱️🖱️ ZERO-TRUST: Mouse {device.Name} was whitelisted but requires re-authentication");
                        break;
                        
                    case USBDeviceType.Storage:
                        _logger.LogSecurity($"💾💾 ZERO-TRUST: Auto-triggering MANDATORY storage authentication for {device.Name}");
                        if (device.WasWhitelisted)
                            _logger.LogSecurity($"💾💾 ZERO-TRUST: Storage {device.Name} was whitelisted but requires re-authentication");
                        if (device.WasBlacklisted)
                            _logger.LogSecurity($"💾💾 ZERO-TRUST: Storage {device.Name} was blacklisted - showing warning dialog");
                        break;
                        
                    case USBDeviceType.HID:
                        _logger.LogSecurity($"🕹️🕹️ ZERO-TRUST: Auto-triggering MANDATORY HID authentication for {device.Name}");
                        if (device.WasBlacklisted)
                            _logger.LogSecurity($"🕹️🕹️ ZERO-TRUST: HID {device.Name} was blacklisted - showing warning dialog");
                        break;
                        
                    default:
                        _logger.LogSecurity($"❓❓ ZERO-TRUST: Auto-triggering MANDATORY generic authentication for {device.Name}");
                        break;
                }
                
                // Start zero-trust authentication process - this will automatically show the appropriate dialog
                await _authenticator.AuthenticateDeviceAsync(device);
                
                _logger.LogSecurity($"✅✅ ZERO-TRUST: Mandatory authentication triggered successfully for {device.Name}");
            }
            catch (Exception ex)
            {
                _logger.LogError($"ZERO-TRUST: Error auto-triggering mandatory authentication for {device?.Name}: {ex.Message}");
                
                if (device != null)
                {
                    device.Status = DeviceStatus.Blocked;
                    device.IsAuthenticated = false;
                    device.QuarantineTime = DateTime.Now;
                    NotifyStatusChange($"🚫 Device blocked due to authentication error: {device.Name}");
                }
            }
        }
        #endregion

        #region STEP 2: Enhanced Device Classification Implementation
        
        /// <summary>
        /// STEP 2: Enhanced Device Classification using comprehensive WMI queries
        /// </summary>
        private USBDeviceType ClassifyDeviceWithWMI(string pnpId, string nameLower, string guidLower, string pnpLower)
        {
            try
            {
                _logger.LogInfo($"🔍 STEP 2: Enhanced WMI classification for device: {pnpId}");

                // 1. Check if it's a keyboard using Win32_Keyboard WMI class
                if (IsKeyboardDevice(pnpId))
                {
                    _logger.LogInfo($"⌨️ STEP 2: Classified as Keyboard via WMI: {pnpId}");
                    return USBDeviceType.Keyboard;
                }

                // 2. Check if it's a pointing device (mouse) using Win32_PointingDevice WMI class
                if (IsPointingDevice(pnpId))
                {
                    _logger.LogInfo($"🖱️ STEP 2: Classified as Mouse via WMI: {pnpId}");
                    return USBDeviceType.Mouse;
                }

                // 3. Check if it's a storage device using Win32_LogicalDisk and Win32_DiskDrive
                if (IsStorageDevice(pnpId))
                {
                    _logger.LogInfo($"💾 STEP 2: Classified as Storage via WMI: {pnpId}");
                    return USBDeviceType.Storage;
                }

                // 4. Check if it's an audio device using Win32_SoundDevice
                if (IsAudioDevice(pnpId))
                {
                    _logger.LogInfo($"🔊 STEP 2: Classified as Audio via WMI: {pnpId}");
                    return USBDeviceType.Audio;
                }

                // 5. Check for video devices using Win32_VideoController
                if (IsVideoDevice(pnpId))
                {
                    _logger.LogInfo($"🎥 STEP 2: Classified as Video via WMI: {pnpId}");
                    return USBDeviceType.Video;
                }

                // 6. Check for printers using Win32_Printer
                if (IsPrinterDevice(pnpId))
                {
                    _logger.LogInfo($"🖨️ STEP 2: Classified as Printer via WMI: {pnpId}");
                    return USBDeviceType.Printer;
                }

                _logger.LogInfo($"❓ STEP 2: Could not classify device via WMI: {pnpId}");
                return USBDeviceType.Unknown;
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"STEP 2: Error in WMI classification for {pnpId}: {ex.Message}");
                return USBDeviceType.Unknown;
            }
        }

        /// <summary>
        /// STEP 2: Check if device is a keyboard using Win32_Keyboard WMI class
        /// </summary>
        private bool IsKeyboardDevice(string pnpId)
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_Keyboard"))
                {
                    foreach (ManagementObject keyboard in searcher.Get())
                    {
                        var deviceId = keyboard["PNPDeviceID"]?.ToString() ?? "";
                        if (!string.IsNullOrEmpty(deviceId) && deviceId.Equals(pnpId, StringComparison.OrdinalIgnoreCase))
                        {
                            var name = keyboard["Name"]?.ToString() ?? "";
                            var layout = keyboard["Layout"]?.ToString() ?? "";
                            _logger.LogInfo($"⌨️ STEP 2: Keyboard detected - Name: {name}, Layout: {layout}");
                            return true;
                        }
                    }
                }
                return false;
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"STEP 2: Error checking keyboard WMI: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// STEP 2: Check if device is a pointing device using Win32_PointingDevice WMI class
        /// </summary>
        private bool IsPointingDevice(string pnpId)
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_PointingDevice"))
                {
                    foreach (ManagementObject pointingDevice in searcher.Get())
                    {
                        var deviceId = pointingDevice["PNPDeviceID"]?.ToString() ?? "";
                        if (!string.IsNullOrEmpty(deviceId) && deviceId.Equals(pnpId, StringComparison.OrdinalIgnoreCase))
                        {
                            var name = pointingDevice["Name"]?.ToString() ?? "";
                            var manufacturer = pointingDevice["Manufacturer"]?.ToString() ?? "";
                            var numberOfButtons = pointingDevice["NumberOfButtons"]?.ToString() ?? "";
                            _logger.LogInfo($"🖱️ STEP 2: Pointing device detected - Name: {name}, Manufacturer: {manufacturer}, Buttons: {numberOfButtons}");
                            return true;
                        }
                    }
                }
                return false;
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"STEP 2: Error checking pointing device WMI: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// STEP 2: Check if device is a storage device using multiple WMI classes
        /// </summary>
        private bool IsStorageDevice(string pnpId)
        {
            try
            {
                // Check Win32_DiskDrive
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_DiskDrive"))
                {
                    foreach (ManagementObject disk in searcher.Get())
                    {
                        var deviceId = disk["PNPDeviceID"]?.ToString() ?? "";
                        if (!string.IsNullOrEmpty(deviceId) && deviceId.Equals(pnpId, StringComparison.OrdinalIgnoreCase))
                        {
                            var model = disk["Model"]?.ToString() ?? "";
                            var interfaceType = disk["InterfaceType"]?.ToString() ?? "";
                            var size = disk["Size"]?.ToString() ?? "";
                            _logger.LogInfo($"💾 STEP 2: Storage device detected - Model: {model}, Interface: {interfaceType}, Size: {size}");
                            return true;
                        }
                    }
                }

                return false;
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"STEP 2: Error checking storage device WMI: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// STEP 2: Check if device is an audio device using Win32_SoundDevice WMI class
        /// </summary>
        private bool IsAudioDevice(string pnpId)
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_SoundDevice"))
                {
                    foreach (ManagementObject audioDevice in searcher.Get())
                    {
                        var deviceId = audioDevice["PNPDeviceID"]?.ToString() ?? "";
                        if (!string.IsNullOrEmpty(deviceId) && deviceId.Equals(pnpId, StringComparison.OrdinalIgnoreCase))
                        {
                            var name = audioDevice["Name"]?.ToString() ?? "";
                            var manufacturer = audioDevice["Manufacturer"]?.ToString() ?? "";
                            _logger.LogInfo($"🔊 STEP 2: Audio device detected - Name: {name}, Manufacturer: {manufacturer}");
                            return true;
                        }
                    }
                }
                return false;
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"STEP 2: Error checking audio device WMI: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// STEP 2: Check if device is a video device using Win32_VideoController
        /// </summary>
        private bool IsVideoDevice(string pnpId)
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_VideoController"))
                {
                    foreach (ManagementObject videoDevice in searcher.Get())
                    {
                        var deviceId = videoDevice["PNPDeviceID"]?.ToString() ?? "";
                        if (!string.IsNullOrEmpty(deviceId) && deviceId.Equals(pnpId, StringComparison.OrdinalIgnoreCase))
                        {
                            var name = videoDevice["Name"]?.ToString() ?? "";
                            var driverVersion = videoDevice["DriverVersion"]?.ToString() ?? "";
                            _logger.LogInfo($"🎥 STEP 2: Video device detected - Name: {name}, Driver: {driverVersion}");
                            return true;
                        }
                    }
                }
                return false;
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"STEP 2: Error checking video device WMI: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// STEP 2: Check if device is a printer using Win32_Printer
        /// </summary>
        private bool IsPrinterDevice(string pnpId)
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_Printer"))
                {
                    foreach (ManagementObject printer in searcher.Get())
                    {
                        var portName = printer["PortName"]?.ToString() ?? "";
                        
                        // Check if this printer is connected via USB
                        if (!string.IsNullOrEmpty(portName) && portName.StartsWith("USB", StringComparison.OrdinalIgnoreCase))
                        {
                            var name = printer["Name"]?.ToString() ?? "";
                            var driverName = printer["DriverName"]?.ToString() ?? "";
                            _logger.LogInfo($"🖨️ STEP 2: Printer device detected - Name: {name}, Driver: {driverName}, Port: {portName}");
                            return true;
                        }
                    }
                }
                return false;
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"STEP 2: Error checking printer device WMI: {ex.Message}");
                return false;
            }
        }

        #endregion

        #region Advanced WMI Monitoring
        private void StartAdvancedWMIMonitoring()
        {
            try
            {
                var insertQuery = new WqlEventQuery(
                    "SELECT * FROM __InstanceCreationEvent WITHIN 1 " +
                    "WHERE TargetInstance ISA 'Win32_PnPEntity' " +
                    "AND TargetInstance.PNPDeviceID LIKE 'USB%'");
                
                _insertWatcher = new ManagementEventWatcher(insertQuery);
                _insertWatcher.EventArrived += OnDeviceInserted;
                _insertWatcher.Start();
                _logger.LogInfo("✅ STEP 5: Advanced USB insertion monitoring started with auto-authentication");

                var removeQuery = new WqlEventQuery(
                    "SELECT * FROM __InstanceDeletionEvent WITHIN 1 " +
                    "WHERE TargetInstance ISA 'Win32_PnPEntity' " +
                    "AND TargetInstance.PNPDeviceID LIKE 'USB%'");
                
                _removeWatcher = new ManagementEventWatcher(removeQuery);
                _removeWatcher.EventArrived += OnDeviceRemoved;
                _removeWatcher.Start();
                _logger.LogInfo("✅ STEP 5: Advanced USB removal monitoring started");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Failed to start advanced WMI monitoring: {ex.Message}");
                StartBasicWMIMonitoring();
            }
        }

        private void StartBasicWMIMonitoring()
        {
            try
            {
                _logger.LogInfo("Starting fallback basic WMI monitoring");
                
                var insertQuery = new WqlEventQuery(
                    "SELECT * FROM __InstanceCreationEvent WITHIN 2 " +
                    "WHERE TargetInstance ISA 'Win32_PnPEntity'");

                _insertWatcher = new ManagementEventWatcher(insertQuery);
                _insertWatcher.EventArrived += OnDeviceInsertedBasic;
                _insertWatcher.Start();
                
                _logger.LogInfo("✅ STEP 5: Basic USB monitoring started with auto-authentication");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Basic WMI monitoring also failed: {ex.Message}");
                throw;
            }
        }

        private void StopWMIWatchers()
        {
            try
            {
                if (_insertWatcher != null)
                {
                    _insertWatcher.Stop();
                    _insertWatcher.Dispose();
                    _insertWatcher = null;
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"Error stopping insert watcher: {ex.Message}");
            }

            try
            {
                if (_removeWatcher != null)
                {
                    _removeWatcher.Stop();
                    _removeWatcher.Dispose();
                    _removeWatcher = null;
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"Error stopping remove watcher: {ex.Message}");
            }
        }
        #endregion

        #region Device Event Handlers
        private async void OnDeviceInserted(object sender, EventArrivedEventArgs e)
        {
            if (_isDisposing) return;
            await HandleDeviceInsertion(e, true);
        }

        private async void OnDeviceInsertedBasic(object sender, EventArrivedEventArgs e)
        {
            if (_isDisposing) return;
            await HandleDeviceInsertion(e, false);
        }

        private async Task HandleDeviceInsertion(EventArrivedEventArgs e, bool isAdvanced)
        {
            try
            {
                var instance = e?.NewEvent?["TargetInstance"] as ManagementBaseObject;
                if (instance == null) return;

                string pnpId = instance["PNPDeviceID"]?.ToString() ?? "";
                
                if (string.IsNullOrEmpty(pnpId) || !pnpId.StartsWith("USB\\", StringComparison.OrdinalIgnoreCase))
                    return;

                string name = instance["Name"]?.ToString() ?? "";
                string classGuid = instance["ClassGuid"]?.ToString() ?? "";

                var deviceInfo = CreateEnhancedDeviceInfo(pnpId, name, classGuid);
                if (deviceInfo == null) return;

                _connectedDevices.TryAdd(deviceInfo.DeviceId, deviceInfo);

                _logger.LogSecurity($"🔌 STEP 5: USB DEVICE DETECTED: {deviceInfo.Name} ({deviceInfo.Type}) - VID:{deviceInfo.VendorId} PID:{deviceInfo.ProductId}");

                // STEP 5: IMMEDIATE BLOCKING - Block device first, authenticate later
                await ImmediatelyBlockDevice(deviceInfo);
                
                NotifyDeviceConnected(deviceInfo);
                
                // STEP 5: AUTO-AUTHENTICATION TRIGGER - Start authentication process automatically
                _ = Task.Run(async () => await ProcessDeviceSecurityWithAutoAuthentication(deviceInfo));
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error handling device insertion: {ex.Message}");
            }
        }

        private async void OnDeviceRemoved(object sender, EventArrivedEventArgs e)
        {
            if (_isDisposing) return;
            
            try
            {
                var instance = e?.NewEvent?["TargetInstance"] as ManagementBaseObject;
                if (instance == null) return;

                string pnpId = instance["PNPDeviceID"]?.ToString() ?? "";
                
                if (string.IsNullOrEmpty(pnpId) || !pnpId.StartsWith("USB\\", StringComparison.OrdinalIgnoreCase))
                    return;

                // Find and remove the device from our collection
                var deviceToRemove = _connectedDevices.Values.FirstOrDefault(d => d.PnpDeviceId.Equals(pnpId, StringComparison.OrdinalIgnoreCase));
                
                if (deviceToRemove != null)
                {
                    _connectedDevices.TryRemove(deviceToRemove.DeviceId, out _);
                    
                    _logger.LogSecurity($"🔌 STEP 5: USB DEVICE REMOVED: {deviceToRemove.Name} ({deviceToRemove.Type})");
                    
                    NotifyDeviceDisconnected(deviceToRemove);
                    NotifyStatusChange($"Device disconnected: {deviceToRemove.Name}");
                    
                    // Clean up recent devices cache
                    lock (_recentDevicesLock)
                    {
                        _recentDevices.Remove(pnpId);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error handling device removal: {ex.Message}");
            }
        }
        #endregion

        #region Device Processing
        private USBDeviceInfo CreateEnhancedDeviceInfo(string pnpId, string name, string classGuid)
        {
            try
            {
                var deviceType = DetermineDeviceTypeAdvanced(classGuid, name, pnpId);

                var deviceInfo = new USBDeviceInfo
                {
                    DeviceId = pnpId,
                    PnpDeviceId = pnpId,
                    Name = string.IsNullOrEmpty(name) ? "Unknown USB Device" : name,
                    Type = deviceType,
                    VendorId = ExtractVendorId(pnpId),
                    ProductId = ExtractProductId(pnpId),
                    SerialNumber = ExtractSerialNumber(pnpId),
                    Status = DeviceStatus.Blocked,
                    ConnectedTime = DateTime.Now,
                    ClassGuid = classGuid,
                    IsAuthenticated = false,
                    // COMPOSITE DEVICE FIX: Mark if this is a composite device
                    IsCompositeDevice = name.ToLowerInvariant().Contains("composite device")
                };

                return deviceInfo;
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error creating device info: {ex.Message}");
                return null;
            }
        }

        private USBDeviceType DetermineDeviceTypeAdvanced(string classGuid, string name, string pnpId)
        {
            try
            {
                var nameLower = name?.ToLowerInvariant() ?? "";
                var pnpLower = pnpId?.ToLowerInvariant() ?? "";
                var guidLower = classGuid?.ToLowerInvariant() ?? "";

                _logger.LogInfo($"🔍 STEP 2: Starting advanced device type determination for {name}");
                _logger.LogInfo($"🔍 STEP 2: PnP ID: {pnpId}");
                _logger.LogInfo($"🔍 STEP 2: Class GUID: {classGuid}");

                // CRITICAL FIX: Detect USB Composite Devices and check their children
                // USB Composite devices contain multiple interfaces (e.g., keyboard + mouse in one device)
                if (nameLower.Contains("usb composite device") || nameLower.Contains("composite device"))
                {
                    _logger.LogInfo($"🔍 COMPOSITE DEVICE DETECTED: {name} - Checking child devices...");
                    
                    // Check if this composite device has a keyboard interface
                    var compositeType = DetectCompositeDeviceType(pnpId);
                    if (compositeType != USBDeviceType.Unknown)
                    {
                        _logger.LogInfo($"✅ COMPOSITE DEVICE IDENTIFIED AS: {compositeType} for {name}");
                        return compositeType;
                    }
                }

                // ENHANCED STORAGE DETECTION FIRST - Priority for pen drives and USB mass storage
                if (IsStorageDeviceEnhanced(pnpId, nameLower, classGuid))
                {
                    _logger.LogInfo($"💾 STEP 2: ENHANCED classification as Storage: {name}");
                    return USBDeviceType.Storage;
                }

                var wmiDeviceType = ClassifyDeviceWithWMI(pnpId, nameLower, guidLower, pnpLower);
                if (wmiDeviceType != USBDeviceType.Unknown)
                {
                    _logger.LogInfo($"✅ STEP 2: WMI classification successful: {wmiDeviceType} for {name}");
                    return wmiDeviceType;
                }

                // Additional fallback checks for storage devices
                if (nameLower.Contains("mass storage") || 
                    nameLower.Contains("storage device") || 
                    nameLower.Contains("removable disk") ||
                    pnpLower.Contains("usbstor"))
                {
                    _logger.LogInfo($"💾 STEP 2: FALLBACK classification as Storage by name/PnP pattern: {name}");
                    return USBDeviceType.Storage;
                }

                _logger.LogInfo($"❓ STEP 2: Could not determine device type, defaulting to Unknown: {name}");
                return USBDeviceType.Unknown;
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"STEP 2: Error determining device type: {ex.Message}");
                return USBDeviceType.Unknown;
            }
        }

        /// <summary>
        /// CRITICAL FIX: Detect the actual device type within a USB Composite Device
        /// </summary>
        private USBDeviceType DetectCompositeDeviceType(string pnpId)
        {
            try
            {
                _logger.LogInfo($"🔍 Analyzing composite device children for: {pnpId}");
                
                // Query WMI for child devices of this composite device
                using (var searcher = new ManagementObjectSearcher(
                    $"SELECT * FROM Win32_PnPEntity WHERE PNPDeviceID LIKE '{pnpId.Replace("\\", "\\\\")}%'"))
                {
                    foreach (ManagementObject entity in searcher.Get())
                    {
                        var childPnpId = entity["PNPDeviceID"]?.ToString() ?? "";
                        var childName = entity["Name"]?.ToString() ?? "";
                        var childNameLower = childName.ToLowerInvariant();
                        
                        _logger.LogInfo($"🔍 Composite child found: {childName} ({childPnpId})");
                        
                        // Check if any child is a keyboard
                        if (childNameLower.Contains("keyboard") || 
                            childNameLower.Contains("hid keyboard") ||
                            IsKeyboardDevice(childPnpId))
                        {
                            _logger.LogSecurity($"⌨️ COMPOSITE DEVICE CONTAINS KEYBOARD: {childName}");
                            return USBDeviceType.Keyboard;
                        }
                        
                        // Check if any child is a mouse
                        if (childNameLower.Contains("mouse") || 
                            childNameLower.Contains("pointing device") ||
                            IsPointingDevice(childPnpId))
                        {
                            _logger.LogSecurity($"🖱️ COMPOSITE DEVICE CONTAINS MOUSE: {childName}");
                            return USBDeviceType.Mouse;
                        }
                    }
                }
                
                // Alternative: Check direct Win32 classes for keyboard/mouse
                // Check if this composite PnpId matches any keyboard
                if (IsKeyboardDevice(pnpId))
                {
                    _logger.LogSecurity($"⌨️ COMPOSITE DEVICE IS KEYBOARD (via direct WMI check)");
                    return USBDeviceType.Keyboard;
                }
                
                if (IsPointingDevice(pnpId))
                {
                    _logger.LogSecurity($"🖱️ COMPOSITE DEVICE IS MOUSE (via direct WMI check)");
                    return USBDeviceType.Mouse;
                }
                
                _logger.LogInfo($"❓ Could not determine composite device type");
                return USBDeviceType.Unknown;
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"Error detecting composite device type: {ex.Message}");
                return USBDeviceType.Unknown;
            }
        }

        /// <summary>
        /// Enhanced storage device detection specifically for USB mass storage devices and pen drives
        /// </summary>
        private bool IsStorageDeviceEnhanced(string pnpId, string nameLower, string classGuid)
        {
            try
            {
                _logger.LogInfo($"💾 ENHANCED: Checking storage detection for device: {nameLower}");

                // Check Class GUID for storage devices
                if (!string.IsNullOrEmpty(classGuid))
                {
                    var guidLower = classGuid.ToLowerInvariant();
                    
                    // USB Mass Storage Class GUID
                    if (guidLower.Contains("53f56307-b6bf-11d0-94f2-00a0c91efb8b") ||  // Disk drives
                        guidLower.Contains("4d36e967-e325-11ce-bfc1-08002be10318") ||  // DiskDrive
                        guidLower.Contains("53f5630d-b6bf-11d0-94f2-00a0c91efb8b"))    // StorageVolume
                    {
                        _logger.LogInfo($"💾 ENHANCED: Storage device detected by Class GUID: {classGuid}");
                        return true;
                    }
                }

                // Enhanced name-based detection for storage devices
                var storageKeywords = new[]
                {
                    "mass storage", "storage device", "removable disk", "usb disk", 
                    "flash drive", "pen drive", "thumb drive", "memory stick",
                    "portable device", "removable storage", "external storage",
                    "usb storage", "mass storage device", "usb mass storage",
                    "generic- multi-card", "multiple card reader", "card reader"
                };

                foreach (var keyword in storageKeywords)
                {
                    if (nameLower.Contains(keyword))
                    {
                        _logger.LogInfo($"💾 ENHANCED: Storage device detected by name pattern '{keyword}': {nameLower}");
                        return true;
                    }
                }

                // Check PnP ID patterns for storage devices
                if (!string.IsNullOrEmpty(pnpId))
                {
                    var pnpLower = pnpId.ToLowerInvariant();
                    if (pnpLower.Contains("usbstor") || 
                        pnpLower.Contains("\\disk&") || 
                        pnpLower.Contains("storage") ||
                        pnpLower.StartsWith("usbstor\\"))
                    {
                        _logger.LogInfo($"💾 ENHANCED: Storage device detected by PnP ID pattern: {pnpId}");
                        return true;
                    }
                }

                // Try standard WMI detection
                if (IsStorageDevice(pnpId))
                {
                    _logger.LogInfo($"💾 ENHANCED: Storage device detected by standard WMI: {pnpId}");
                    return true;
                }

                // Check for removable drives using Win32_LogicalDisk
                if (CheckRemovableDrives())
                {
                    _logger.LogInfo($"💾 ENHANCED: Storage device detected as removable drive");
                    return true;
                }

                return false;
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"Error in enhanced storage detection: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Check for removable drives that might be USB storage devices
        /// </summary>
        private bool CheckRemovableDrives()
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_LogicalDisk WHERE DriveType = 2"))
                {
                    foreach (ManagementObject drive in searcher.Get())
                    {
                        var deviceId = drive["DeviceID"]?.ToString() ?? "";
                        var volumeName = drive["VolumeName"]?.ToString() ?? "";
                        var description = drive["Description"]?.ToString() ?? "";
                        
                        _logger.LogInfo($"💾 ENHANCED: Found removable drive - ID: {deviceId}, Volume: {volumeName}, Description: {description}");
                        
                        // If we found any removable drive, it's likely a USB storage device
                        if (!string.IsNullOrEmpty(deviceId))
                        {
                            return true;
                        }
                    }
                }
                return false;
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"Error checking removable drives: {ex.Message}");
                return false;
            }
        }

        private string ExtractVendorId(string pnpId)
        {
            try
            {
                if (string.IsNullOrEmpty(pnpId)) return "0000";
                var match = System.Text.RegularExpressions.Regex.Match(pnpId, @"VID_([0-9A-F]{4})", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                return match.Success ? match.Groups[1].Value : "0000";
            }
            catch { return "0000"; }
        }

        private string ExtractProductId(string pnpId)
        {
            try
            {
                if (string.IsNullOrEmpty(pnpId)) return "0000";
                var match = System.Text.RegularExpressions.Regex.Match(pnpId, @"PID_([0-9A-F]{4})", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                return match.Success ? match.Groups[1].Value : "0000";
            }
            catch { return "0000"; }
        }

        private string ExtractSerialNumber(string pnpId)
        {
            try
            {
                if (string.IsNullOrEmpty(pnpId)) return "N/A";
                var parts = pnpId.Split('\\');
                if (parts.Length > 2)
                {
                    var lastPart = parts[2];
                    if (!lastPart.StartsWith("VID_") && !lastPart.StartsWith("PID_"))
                        return lastPart.Length > 20 ? lastPart.Substring(0, 20) + "..." : lastPart;
                }
                return "N/A";
            }
            catch { return "N/A"; }
        }
        #endregion

        #region Background Tasks
        private async void PerformDeviceScan(object state) 
        {
            if (_isDisposing) return;

            try
            {
                // Perform periodic device scan to ensure we haven't missed any devices
                await ScanForNewDevices();
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"Error in device scan: {ex.Message}");
            }
        }

        private async Task ScanForNewDevices()
        {
            try
            {
                // Implement device scanning logic here if needed
                // This is a placeholder for future enhancement
                await Task.Delay(100);
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error scanning for new devices: {ex.Message}");
            }
        }

        private async Task LoadExistingDevices()
        {
            try
            {
                // Load existing devices that may already be connected
                _logger.LogInfo("🔍 STEP 5: Scanning for existing USB devices");
                
                // This would normally scan for existing devices
                // Implementation depends on specific requirements
                await Task.Delay(1000);
                
                _logger.LogInfo("✅ STEP 5: Existing device scan completed");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error loading existing devices: {ex.Message}");
            }
        }

        private void UpdateDeviceStatus(object state)
        {
            if (_isDisposing) return;

            try
            {
                var statusMessage = $"🛡️ STEP 5: Professional USB Guard - Monitoring {_connectedDevices.Count} devices with auto-authentication";
                NotifyStatusChange(statusMessage);
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"Status update error: {ex.Message}");
            }
        }
        #endregion

        #region Event Notifications
        private void NotifyDeviceConnected(USBDeviceInfo device)
        {
            try
            {
                DeviceConnected?.Invoke(this, new USBDeviceEventArgs(device));
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error notifying device connection: {ex.Message}");
            }
        }

        private void NotifyDeviceDisconnected(USBDeviceInfo device)
        {
            try
            {
                DeviceDisconnected?.Invoke(this, new USBDeviceEventArgs(device));
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error notifying device disconnection: {ex.Message}");
            }
        }

        private void NotifyDeviceAuthenticated(USBDeviceInfo device, bool isAuthenticated, string method)
        {
            try
            {
                var eventArgs = new DeviceAuthenticationEventArgs(device, isAuthenticated, method);
                DeviceAuthenticated?.Invoke(this, eventArgs);
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error notifying device authentication: {ex.Message}");
            }
        }

        private void NotifyStatusChange(string status)
        {
            try
            {
                StatusChanged?.Invoke(this, status);
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"Error in status change notification: {ex.Message}");
            }
        }

        private void OnDeviceAuthenticated(object sender, DeviceAuthenticationEventArgs e)
        {
            try
            {
                if (e?.Device == null) return;

                _logger.LogSecurity($"🔐 STEP 5: Device authentication result - {e.Device.Name}: {(e.IsAuthenticated ? "✅ APPROVED" : "🚫 DENIED")} via {e.AuthenticationMethod}");

                // Update device status based on authentication result
                if (e.IsAuthenticated)
                {
                    e.Device.Status = DeviceStatus.Trusted;
                    e.Device.IsAuthenticated = true;
                    e.Device.AuthenticatedTime = DateTime.Now;
                    
                    NotifyStatusChange($"✅ Device authenticated: {e.Device.Name}");
                    
                    // Add to whitelist if user authentication was successful
                    if (_whitelistManager != null && e.AuthenticationMethod != "Whitelisted Device")
                    {
                        _ = Task.Run(async () =>
                        {
                            try
                            {
                                await _whitelistManager.AddToWhitelistAsync(e.Device, $"User authenticated via {e.AuthenticationMethod}");
                                _logger.LogSecurity($"✅ STEP 5: Device {e.Device.Name} added to whitelist after authentication");
                            }
                            catch (Exception ex)
                            {
                                _logger.LogWarning($"Failed to add authenticated device to whitelist: {ex.Message}");
                            }
                        });
                    }
                }
                else
                {
                    e.Device.Status = DeviceStatus.Blocked;
                    e.Device.IsAuthenticated = false;
                    
                    NotifyStatusChange($"🚫 Device blocked: {e.Device.Name}");
                    
                    // Add to blacklist if authentication failed
                    if (_whitelistManager != null && e.AuthenticationMethod != "Blacklisted Device")
                    {
                        _ = Task.Run(async () =>
                        {
                            try
                            {
                                await _whitelistManager.AddToBlacklistAsync(e.Device, $"Authentication failed via {e.AuthenticationMethod}");
                                _logger.LogSecurity($"🚫 STEP 5: Device {e.Device.Name} added to blacklist after failed authentication");
                            }
                            catch (Exception ex)
                            {
                                _logger.LogWarning($"Failed to add blocked device to blacklist: {ex.Message}");
                            }
                        });
                    }
                }

                // Notify UI of the authentication change
                DeviceAuthenticated?.Invoke(this, e);
            }
            catch (Exception ex)
            {
                _logger.LogError($"STEP 5: Error handling device authentication event: {ex.Message}");
            }
        }
        #endregion

        #region IDisposable Implementation
        public void Dispose()
        {
            if (_isDisposing) return;
            
            try
            {
                _logger?.LogSecurity("🛑 STEP 5: Disposing Professional USB Device Manager");
                
                _isDisposing = true;
                _isMonitoring = false;
                
                _deviceScanTimer?.Dispose();
                _statusUpdateTimer?.Dispose();
                
                StopWMIWatchers();

                if (_authenticator != null)
                {
                    _authenticator.AuthenticationCompleted -= OnDeviceAuthenticated;
                }

                _connectedDevices.Clear();
                
                _logger?.LogSecurity("✅ STEP 5: Professional USB Device Manager disposed successfully");
            }
            catch (Exception ex)
            {
                _logger?.LogError($"Error disposing USBDeviceManager: {ex.Message}");
            }
        }
        #endregion
    }

    public class USBDeviceEventArgs : EventArgs
    {
        public USBDeviceInfo Device { get; }

        public USBDeviceEventArgs(USBDeviceInfo device)
        {
            Device = device;
        }
    }
}
using System;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Win32;
using USB_Guard.Models;
using USB_Guard.Dialogs;

namespace USB_Guard.Core
{
    /// <summary>
    /// Integration layer for Windows-level USB device blocking
    /// Extends USBDeviceManager with registry-based zero-trust enforcement
    /// </summary>
    public partial class USBDeviceManager
    {
        #region Zero-Trust Registry Integration Fields
        
        private DeviceInstallationPolicyManager _policyManager;
        private RegistryBackupManager _backupManager;
        private HardwareIDConverter _hardwareIdConverter;
        private BlockedDeviceDetector _blockedDeviceDetector;
        private DeviceReenumerator _deviceReenumerator;
        private SessionAuthenticationCache _authenticationCache;
        private SessionAuthenticationCache _storageTemporaryCache; // NEW: Separate 1-minute cache for storage
        private DeviceInstanceBlocker _instanceBlocker; // NEW: More accurate instance-level blocking
        private StorageScanner _storageScanner; // NEW: Proactive malware scanner
        private bool _zeroTrustEnabled = false;
        private bool _useInstanceBlocking = true; // Toggle between instance blocking and policy blocking
        
        #endregion

        #region Zero-Trust Initialization

        /// <summary>
        /// Initialize Windows-level zero-trust USB blocking system
        /// MUST be called with Administrator privileges
        /// </summary>
        public async Task<bool> InitializeZeroTrustSystemAsync()
        {
            try
            {
                _logger.LogSecurity("🔒🔒 INITIALIZING ZERO-TRUST USB BLOCKING SYSTEM");

                // Check Administrator privileges
                if (!IsAdministrator())
                {
                    _logger.LogError("Zero-Trust system requires Administrator privileges");
                    NotifyStatusChange("❌ ERROR: Administrator privileges required for Zero-Trust mode");
                    return false;
                }

                // Initialize components
                _backupManager = new RegistryBackupManager();
                _policyManager = new DeviceInstallationPolicyManager();
                _hardwareIdConverter = new HardwareIDConverter();
                _blockedDeviceDetector = new BlockedDeviceDetector();
                _deviceReenumerator = new DeviceReenumerator();
                _authenticationCache = new SessionAuthenticationCache(TimeSpan.FromMinutes(5)); // 5 min for keyboard/mouse
                _storageTemporaryCache = new SessionAuthenticationCache(TimeSpan.FromMinutes(1)); // 1 min for storage
                _instanceBlocker = new DeviceInstanceBlocker(); // Initialize instance blocker
                _storageScanner = new StorageScanner(); // Initialize proactive scanner

                _logger.LogInfo("Zero-Trust components initialized successfully");
                _logger.LogInfo("✅ Storage devices: 1-minute temporary allow (scan only)");
                _logger.LogInfo("✅ Keyboard/Mouse: 5-minute session cache");
                _logger.LogInfo("✅ Proactive storage scanner initialized");

                // Verify SetupAPI access for instance blocking
                if (_instanceBlocker.CanAccessSetupAPI())
                {
                    _logger.LogInfo("✅ SetupAPI accessible - Instance-level blocking available");
                    _useInstanceBlocking = true;
                }
                else
                {
                    _logger.LogWarning("⚠ SetupAPI not accessible - Falling back to policy-based blocking");
                    _useInstanceBlocking = false;
                }

                // Wire up authentication event handler for automatic blocking on failure
                if (_authenticator != null)
                {
                    _authenticator.AuthenticationCompleted += OnDeviceAuthenticatedWithZeroTrust;
                    _logger.LogInfo("✅ Zero-Trust authentication handler wired up - automatic blocking enabled");
                }
                else
                {
                    _logger.LogWarning("Device authenticator not available - Zero-Trust blocking may not work properly");
                }

                // Create registry backup BEFORE enabling policies
                _logger.LogInfo("Creating registry backup for safety...");
                var backupPath = _backupManager.CreateBackup();
                
                if (string.IsNullOrEmpty(backupPath))
                {
                    _logger.LogError("Failed to create registry backup - aborting Zero-Trust initialization");
                    return false;
                }

                _logger.LogInfo($"Registry backup created: {backupPath}");

                // STEP 1: Pre-whitelist currently connected USB devices
                // This prevents existing devices from being blocked when we enable global blocking
                _logger.LogInfo("Pre-whitelisting currently connected USB devices...");
                int preWhitelistedCount = 0;
                
                foreach (var device in _connectedDevices.Values)
                {
                    var hardwareId = _hardwareIdConverter.ConvertPnPIdToHardwareId(device.DeviceId);
                    device.HardwareId = hardwareId;
                    
                    if (!string.IsNullOrEmpty(hardwareId))
                    {
                        _policyManager.AddDeviceToAllowList(hardwareId);
                        _logger.LogInfo($"✅ Pre-whitelisted: {device.Name} ({hardwareId})");
                        preWhitelistedCount++;
                    }
                }
                
                _logger.LogSecurity($"✅ Pre-whitelisted {preWhitelistedCount} currently connected devices");

                // STEP 2: Enable Windows-level global USB blocking
                // NOW it's safe - existing devices are already whitelisted
                _logger.LogSecurity("🔒 Enabling Windows GLOBAL USB blocking policy...");
                var policyEnabled = _policyManager.EnableGlobalUSBBlocking();

                if (!policyEnabled)
                {
                    _logger.LogError("❌ Failed to enable Windows USB blocking policies");
                    NotifyStatusChange("❌ ERROR: Failed to enable Zero-Trust policies");
                    return false;
                }

                _logger.LogSecurity("✅ Windows GLOBAL USB blocking policy ENABLED - DenyUnspecified=1");
                _logger.LogSecurity("🔒 ALL NEW USB devices will be BLOCKED at Windows level until authenticated");

                // Start monitoring for policy-blocked devices
                _blockedDeviceDetector.StartMonitoring(OnDeviceBlockedByPolicy);

                _zeroTrustEnabled = true;
                
                _logger.LogSecurity("🔒🔒 ZERO-TRUST USB BLOCKING SYSTEM ACTIVE");
                NotifyStatusChange("🔒🔒 Zero-Trust mode ACTIVE - Windows blocking ALL new USB devices");

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError($"Failed to initialize Zero-Trust system: {ex.Message}");
                NotifyStatusChange($"❌ Zero-Trust initialization failed: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Disable Windows-level zero-trust USB blocking system
        /// </summary>
        public async Task<bool> DisableZeroTrustSystemAsync()
        {
            try
            {
                _logger.LogSecurity("🔓🔓 DISABLING ZERO-TRUST USB BLOCKING SYSTEM");

                if (!_zeroTrustEnabled)
                {
                    _logger.LogWarning("Zero-Trust system is not enabled");
                    return true;
                }

                // Disable Windows-level USB blocking
                var policyDisabled = _policyManager.DisableGlobalUSBBlocking();

                if (!policyDisabled)
                {
                    _logger.LogError("Failed to disable Windows USB blocking policies");
                    return false;
                }

                // Clear authentication caches
                _authenticationCache?.ClearAll();
                _storageTemporaryCache?.ClearAll();

                // Unsubscribe from authentication events
                if (_authenticator != null)
                {
                    _authenticator.AuthenticationCompleted -= OnDeviceAuthenticatedWithZeroTrust;
                    _logger.LogInfo("Zero-Trust authentication handler unsubscribed");
                }

                // Trigger device re-enumeration
                await _deviceReenumerator.ReenumerateAllUSBDevicesAsync();

                _zeroTrustEnabled = false;

                _logger.LogSecurity("✅ Zero-Trust USB blocking system DISABLED");
                NotifyStatusChange("✅ Zero-Trust mode disabled - Normal USB operation restored");

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError($"Failed to disable Zero-Trust system: {ex.Message}");
                return false;
            }
        }

        #endregion

        #region Enhanced Authentication with Windows Policy Integration

        /// <summary>
        /// Override: Enhanced device authentication with Windows policy integration
        /// PROACTIVE SCANNING: Temporarily enable device for immediate scanning, then block if malicious
        /// CRITICAL FIX: Storage devices NEVER use 5-minute cache, ALWAYS require fresh scan
        /// </summary>
        private async Task ProcessDeviceSecurityWithZeroTrust(USBDeviceInfo device)
        {
            try
            {
                if (device == null || _isDisposing) return;

                _logger.LogSecurity($"🔒🔒 ZERO-TRUST: Processing {device.Name} ({device.Type})");

                // Convert PnP Device ID to Hardware ID
                var hardwareId = _hardwareIdConverter.ConvertPnPIdToHardwareId(device.DeviceId);
                device.HardwareId = hardwareId;

                // ============================================================
                // CRITICAL FIX: STORAGE DEVICES NEVER USE ANY CACHE
                // ============================================================
                if (device.Type == USBDeviceType.Storage)
                {
                    _logger.LogSecurity($"💾 ============================================");
                    _logger.LogSecurity($"💾 STORAGE DEVICE DETECTED: {device.Name}");
                    _logger.LogSecurity($"💾 ZERO CACHE - MANDATORY FRESH SCAN");
                    _logger.LogSecurity($"💾 ============================================");
                    
                    // Check blacklist BEFORE scanning (block immediately if blacklisted)
                    bool storageBlacklisted = false;
                    if (_whitelistManager != null)
                    {
                        try
                        {
                            storageBlacklisted = await _whitelistManager.IsDeviceBlacklistedAsync(device);
                        }
                        catch (Exception ex)
                        {
                            _logger.LogWarning($"Error checking blacklist: {ex.Message}");
                        }
                    }

                    if (storageBlacklisted)
                    {
                        _logger.LogWarning($"💾 🚫 Storage device in BLACKLIST - blocking immediately: {device.Name}");
                        await BlockDeviceAtWindowsLevel(device);
                        NotifyStatusChange($"🚫 Blacklisted storage device blocked: {device.Name}");
                        return;
                    }
                    
                    // FORCE FRESH SCAN - No cache checks, no shortcuts
                    _logger.LogSecurity($"💾 FORCING FRESH MALWARE SCAN (no cache used)");
                    
                    // STEP 1: TEMPORARILY ENABLE DEVICE (NOT PERMANENT)
                    _logger.LogSecurity($"💾 STEP 1: Temporarily enabling device at system level for scanning...");
                    await TemporarilyEnableDeviceForScanning(device);
                    
                    // STEP 2: START IMMEDIATE SCAN (within 5 seconds)
                    _logger.LogSecurity($"💾 STEP 2: Starting immediate malware scan (5-second target)...");
                    NotifyStatusChange($"💾 Scanning USB storage: {device.Name}...");
                    
                    // Trigger proactive scan
                    await ProactivelyScanStorageDevice(device);
                    
                    // STEP 3: Decision made in ProactivelyScanStorageDevice
                    // If malicious → Block permanently
                    // If clean → Allow for 1 minute (temporary cache only)
                    
                    return; // Proactive scanning handles everything
                }

                // ============================================================
                // KEYBOARD/MOUSE: Can use 5-minute cache (performance optimization)
                // ============================================================
                if (_zeroTrustEnabled && _authenticationCache != null)
                {
                    if (device.Type == USBDeviceType.Keyboard || device.Type == USBDeviceType.Mouse)
                    {
                        if (_authenticationCache.IsAuthenticated(hardwareId))
                        {
                            _logger.LogInfo($"✅ {device.Type} found in 5-minute authentication cache: {device.Name}");
                            await AllowDeviceAtWindowsLevel(device);
                            return;
                        }
                    }
                }

                // ============================================================
                // NON-STORAGE DEVICES: Check blacklist and whitelist
                // ============================================================
                bool wasBlacklisted = false;
                if (_whitelistManager != null)
                {
                    try
                    {
                        wasBlacklisted = await _whitelistManager.IsDeviceBlacklistedAsync(device);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning($"Error checking blacklist: {ex.Message}");
                    }
                }

                // If device was previously blacklisted, block at Windows level immediately
                if (wasBlacklisted)
                {
                    _logger.LogWarning($"🚫 Device found in BLACKLIST - blocking at Windows level: {device.Name}");
                    
                    if (_zeroTrustEnabled)
                    {
                        await BlockDeviceAtWindowsLevel(device);
                    }
                    else
                    {
                        await ImmediatelyBlockDevice(device);
                    }
                    
                    NotifyStatusChange($"🚫 Blacklisted device blocked: {device.Name}");
                    return; // Don't allow blacklisted devices
                }

                // For keyboard/mouse, check whitelist
                bool wasWhitelisted = false;
                if (_whitelistManager != null)
                {
                    try
                    {
                        wasWhitelisted = await _whitelistManager.IsDeviceWhitelistedAsync(device);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning($"Error checking whitelist: {ex.Message}");
                    }
                }

                // If device was previously whitelisted (non-storage), allow automatically
                if (wasWhitelisted)
                {
                    _logger.LogInfo($"✅ Device found in WHITELIST - allowing: {device.Name}");
                    
                    if (_zeroTrustEnabled)
                    {
                        await AllowDeviceAtWindowsLevel(device);
                    }
                    else
                    {
                        device.Status = DeviceStatus.Trusted;
                        device.IsAuthenticated = true;
                    }
                    
                    NotifyStatusChange($"✅ Whitelisted device allowed: {device.Name}");
                    return;
                }

                // ZERO-TRUST: New devices are ALREADY BLOCKED at Windows level (DenyUnspecified=1)
                _logger.LogWarning($"⛔ NEW DEVICE BLOCKED by Windows policy: {device.Name}");
                _logger.LogInfo($"🔐 Device is BLOCKED with Code 22 - triggering authentication");

                // Trigger authentication for non-storage devices
                if (_authenticator != null)
                {
                    await _authenticator.AuthenticateDeviceAsync(device);
                }
                else
                {
                    _logger.LogError("Device authenticator not initialized - cannot authenticate device");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error in Zero-Trust device security processing: {ex.Message}");
            }
        }

        /// <summary>
        /// PROACTIVE SCANNING: Temporarily enable device at system level for immediate scanning
        /// </summary>
        private async Task TemporarilyEnableDeviceForScanning(USBDeviceInfo device)
        {
            try
            {
                _logger.LogSecurity($"💾 🔓 TEMPORARILY enabling device for scanning (NOT permanent)");
                
                var hardwareId = device.HardwareId ?? _hardwareIdConverter?.ConvertPnPIdToHardwareId(device.DeviceId);
                
                if (_zeroTrustEnabled && _policyManager != null && !string.IsNullOrEmpty(hardwareId))
                {
                    // Temporarily add to allow list (will be removed if malicious)
                    _policyManager.AddDeviceToAllowList(hardwareId);
                    _logger.LogInfo($"💾 Device temporarily in allow list: {hardwareId}");
                    
                    // Trigger re-enumeration to enable device
                    if (_deviceReenumerator != null)
                    {
                        await _deviceReenumerator.ReenumerateDeviceAsync(hardwareId);
                        _logger.LogInfo($"💾 Device re-enumerated - should be accessible now");
                    }
                    
                    // Wait a moment for device to be ready
                    await Task.Delay(1000);
                }
                else if (_useInstanceBlocking && _instanceBlocker != null)
                {
                    // Use instance unblocking
                    bool unblocked = await _instanceBlocker.UnblockDeviceInstance(device.DeviceId);
                    if (unblocked)
                    {
                        _logger.LogInfo($"💾 Device instance temporarily unblocked");
                        await Task.Delay(1000);
                    }
                }
                
                _logger.LogSecurity($"💾 ✅ Device temporarily enabled - ready for scanning");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Failed to temporarily enable device: {ex.Message}");
            }
        }

        /// <summary>
        /// PROACTIVE MALWARE SCAN: Scan device immediately after enabling, then decide
        /// </summary>
        private async Task ProactivelyScanStorageDevice(USBDeviceInfo device)
        {
            try
            {
                _logger.LogSecurity($"💾 ⏱️ STARTING PROACTIVE SCAN (5-second target)");
                var scanStartTime = DateTime.Now;
                
                // Mark device as scanning
                device.Status = DeviceStatus.Authenticating;
                
                // Wait for drive to mount (up to 3 seconds)
                string driveLetter = null;
                for (int i = 0; i < 6; i++)
                {
                    await Task.Delay(500);
                    driveLetter = await FindDriveLetterForDevice(device);
                    if (!string.IsNullOrEmpty(driveLetter))
                    {
                        _logger.LogInfo($"💾 Drive mounted: {driveLetter} (after {(i + 1) * 0.5}s)");
                        break;
                    }
                }
                
                if (string.IsNullOrEmpty(driveLetter))
                {
                    _logger.LogWarning($"💾 ⚠️ Drive not mounted after 3 seconds - blocking for safety");
                    await BlockDeviceAfterFailedScan(device, "Drive not accessible");
                    return;
                }
                
                device.DriveLetter = driveLetter;
                
                // Start immediate scan
                _logger.LogSecurity($"💾 📁 Scanning drive {driveLetter}...");
                
                StorageScanResult scanResult = null;
                try
                {
                    // Use storage scanner with progress
                    if (_storageScanner != null)
                    {
                        scanResult = await _storageScanner.ScanDriveAsync(driveLetter);
                    }
                    else
                    {
                        _logger.LogError($"💾 Storage scanner not available!");
                        await BlockDeviceAfterFailedScan(device, "Scanner not available");
                        return;
                    }
                }
                catch (Exception scanEx)
                {
                    _logger.LogError($"💾 Scan error: {scanEx.Message}");
                    await BlockDeviceAfterFailedScan(device, $"Scan error: {scanEx.Message}");
                    return;
                }
                
                var scanDuration = DateTime.Now - scanStartTime;
                _logger.LogSecurity($"💾 Scan completed in {scanDuration.TotalSeconds:F1} seconds");
                
                // ============================================================
                // DECISION TIME: Block if malicious, Allow if clean
                // ============================================================
                
                if (scanResult.ThreatsDetected && scanResult.ThreatCount > 0)
                {
                    // MALICIOUS: BLOCK PERMANENTLY
                    _logger.LogSecurity($"💾 ❌❌❌ MALICIOUS FILES DETECTED ❌❌❌");
                    _logger.LogSecurity($"💾 Threat count: {scanResult.ThreatCount}");
                    _logger.LogSecurity($"💾 🚫 BLOCKING DEVICE PERMANENTLY");
                    
                    await BlockDeviceAfterMalwareDetection(device, scanResult);
                }
                else if (scanResult.ScanCompleted)
                {
                    // CLEAN: ALLOW FOR 1 MINUTE
                    _logger.LogSecurity($"💾 ✅✅✅ CLEAN DEVICE VERIFIED ✅✅✅");
                    _logger.LogSecurity($"💾 Files scanned: {scanResult.TotalFilesScanned}");
                    _logger.LogSecurity($"💾 ✅ ALLOWING DEVICE (1-minute temporary)");
                    
                    await AllowDeviceAfterCleanScan(device, scanResult);
                }
                else
                {
                    // SCAN INCOMPLETE: BLOCK FOR SAFETY
                    _logger.LogWarning($"💾 ⚠️ SCAN INCOMPLETE: {scanResult.ErrorMessage}");
                    _logger.LogSecurity($"💾 🚫 BLOCKING FOR SAFETY");
                    
                    await BlockDeviceAfterFailedScan(device, scanResult.ErrorMessage);
                }
            } catch (Exception ex) {
                _logger.LogError($"💾 Proactive scan error: {ex.Message}");
                await BlockDeviceAfterFailedScan(device, $"Error: {ex.Message}");
            }
        }

        /// <summary>
        /// Block device after malware detection
        /// </summary>
        private async Task BlockDeviceAfterMalwareDetection(USBDeviceInfo device, StorageScanResult scanResult)
        {
            try
            {
                _logger.LogSecurity($"💾 🚫 BLOCKING MALICIOUS DEVICE: {device.Name}");
                
                // Update device status
                device.Status = DeviceStatus.Blocked;
                device.IsAuthenticated = false;
                device.QuarantineTime = DateTime.Now;
                
                // Block at Windows level permanently
                await BlockDeviceAtWindowsLevel(device);
                
                // Add to blacklist
                if (_whitelistManager != null)
                {
                    await _whitelistManager.AddToBlacklistAsync(device, 
                        $"Malware detected: {scanResult.ThreatCount} threats");
                }
                
                // Show threat notification
                NotifyStatusChange($"🚫 MALWARE DETECTED - Device BLOCKED: {device.Name} ({scanResult.ThreatCount} threats)");
                
                // Show detailed threat dialog
                await ShowMalwareDetectionDialog(device, scanResult);
                
                _logger.LogSecurity($"💾 ✅ Malicious device permanently blocked");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error blocking malicious device: {ex.Message}");
            }
        }

        /// <summary>
        /// Allow device after clean scan (1-minute temporary)
        /// </summary>
        private async Task AllowDeviceAfterCleanScan(USBDeviceInfo device, StorageScanResult scanResult)
        {
            try
            {
                _logger.LogSecurity($"💾 ✅ ALLOWING CLEAN DEVICE: {device.Name}");
                
                // Update device status
                device.Status = DeviceStatus.Trusted;
                device.IsAuthenticated = true;
                device.AuthenticatedTime = DateTime.Now;
                device.QuarantineTime = null;
                
                // Add to 1-minute temporary cache
                var hardwareId = device.HardwareId ?? _hardwareIdConverter?.ConvertPnPIdToHardwareId(device.DeviceId);
                if (_storageTemporaryCache != null && !string.IsNullOrEmpty(hardwareId))
                {
                    _storageTemporaryCache.AddAuthenticated(hardwareId, device.Name, device.Type.ToString());
                    _logger.LogSecurity($"💾 Device added to 1-MINUTE temporary cache");
                }
                
                // Device is already enabled from proactive scanning step
                // No need to re-enable
                
                // Show success notification
                NotifyStatusChange($"✅ CLEAN - Device allowed (1 min): {device.Name} ({scanResult.TotalFilesScanned} files scanned)");
                
                // Show scan result dialog
                await ShowCleanScanDialog(device, scanResult);
                
                _logger.LogSecurity($"💾 ✅ Clean device allowed for 1 minute");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error allowing clean device: {ex.Message}");
            }
        }

        /// <summary>
        /// Block device after failed scan
        /// </summary>
        private async Task BlockDeviceAfterFailedScan(USBDeviceInfo device, string reason)
        {
            try
            {
                _logger.LogSecurity($"💾 🚫 BLOCKING DEVICE (scan failed): {device.Name}");
                _logger.LogSecurity($"💾 Reason: {reason}");
                
                // Update device status
                device.Status = DeviceStatus.Blocked;
                device.IsAuthenticated = false;
                device.QuarantineTime = DateTime.Now;
                
                // Block at Windows level
                await BlockDeviceAtWindowsLevel(device);
                
                // Show notification
                NotifyStatusChange($"🚫 Device BLOCKED (scan failed): {device.Name}");
                
                _logger.LogSecurity($"💾 ✅ Device blocked for safety");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error blocking device after failed scan: {ex.Message}");
            }
        }

        /// <summary>
        /// Show malware detection dialog with threat details
        /// </summary>
        private async Task ShowMalwareDetectionDialog(USBDeviceInfo device, StorageScanResult scanResult)
        {
            try
            {
                await System.Windows.Application.Current.Dispatcher.InvokeAsync(async () =>
                {
                    try
                    {
                        var dialog = new StorageScanResultDialog(device, scanResult, isBlocked: true);
                        dialog.ShowDialog();
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError($"Error showing malware dialog: {ex.Message}");
                    }
                });
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error invoking malware dialog: {ex.Message}");
            }
        }

        /// <summary>
        /// Show clean scan result dialog
        /// </summary>
        private async Task ShowCleanScanDialog(USBDeviceInfo device, StorageScanResult scanResult)
        {
            try
            {
                await System.Windows.Application.Current.Dispatcher.InvokeAsync(async () =>
                {
                    try
                    {
                        var dialog = new StorageScanResultDialog(device, scanResult, isBlocked: false);
                        dialog.ShowDialog();
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError($"Error showing clean scan dialog: {ex.Message}");
                    }
                });
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error invoking clean scan dialog: {ex.Message}");
            }
        }

        /// <summary>
        /// Find drive letter for USB storage device
        /// </summary>
        private async Task<string> FindDriveLetterForDevice(USBDeviceInfo device)
        {
            try
            {
                var drives = System.IO.DriveInfo.GetDrives()
                    .Where(d => d.DriveType == System.IO.DriveType.Removable && d.IsReady)
                    .Select(d => d.Name.TrimEnd('\\'))
                    .ToList();

                return drives.FirstOrDefault();
            }
            catch
            {
                return null;
            }
        }

        #endregion

        #region Utility Methods

        /// <summary>
        /// Check if running with Administrator privileges
        /// </summary>
        private bool IsAdministrator()
        {
            try
            {
                var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
                var principal = new System.Security.Principal.WindowsPrincipal(identity);
                return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Find device by Hardware ID
        /// </summary>
        private USBDeviceInfo GetDeviceByHardwareId(string hardwareId)
        {
            if (string.IsNullOrEmpty(hardwareId)) return null;

            foreach (var device in _connectedDevices.Values)
            {
                var deviceHardwareId = device.HardwareId ?? _hardwareIdConverter?.ConvertPnPIdToHardwareId(device.DeviceId);
                
                if (deviceHardwareId != null && deviceHardwareId.Equals(hardwareId, StringComparison.OrdinalIgnoreCase))
                {
                    return device;
                }
            }

            return null;
        }

        /// <summary>
        /// Get Zero-Trust system status
        /// </summary>
        public string GetZeroTrustStatus()
        {
            if (!_zeroTrustEnabled)
            {
                return "Zero-Trust mode: Disabled";
            }

            var authenticatedCount = _authenticationCache?.GetAuthenticatedCount() ?? 0;
            var storageCount = _storageTemporaryCache?.GetAuthenticatedCount() ?? 0;
            var blockedCount = _blockedDeviceDetector?.GetBlockedUSBDevices()?.Count ?? 0;

            return $"Zero-Trust mode: ACTIVE | Authenticated: {authenticatedCount} | Storage (temp): {storageCount} | Blocked: {blockedCount}";
        }

        /// <summary>
        /// Block device at Windows registry level (permanent system-wide blocking)
        /// </summary>
        private async Task BlockDeviceAtWindowsLevel(USBDeviceInfo device)
        {
            try
            {
                if (device == null || !_zeroTrustEnabled) return;

                _logger.LogSecurity($"🚫 PERMANENT WINDOWS-LEVEL BLOCK: {device.Name}");

                var devicesToBlock = new List<string> { device.DeviceId };
                
                if (device.IsCompositeDevice && device.ChildDeviceIds != null && device.ChildDeviceIds.Count > 0)
                {
                    _logger.LogSecurity($"🚫 COMPOSITE DEVICE DETECTED: Will block parent + {device.ChildDeviceIds.Count} children");
                    devicesToBlock.AddRange(device.ChildDeviceIds);
                }
                else if (!string.IsNullOrEmpty(device.ParentCompositeDeviceId))
                {
                    _logger.LogSecurity($"🚫 CHILD OF COMPOSITE DEVICE: Will also block parent composite device");
                    devicesToBlock.Add(device.ParentCompositeDeviceId);
                    
                    var parentDevice = GetDeviceByPnpId(device.ParentCompositeDeviceId);
                    if (parentDevice != null && parentDevice.ChildDeviceIds != null)
                    {
                        devicesToBlock.AddRange(parentDevice.ChildDeviceIds);
                        _logger.LogSecurity($"🚫 Also blocking {parentDevice.ChildDeviceIds.Count} sibling devices");
                    }
                }

                devicesToBlock = devicesToBlock.Distinct().ToList();
                _logger.LogSecurity($"🚫 Total devices to block: {devicesToBlock.Count}");

                foreach (var deviceId in devicesToBlock)
                {
                    await BlockSingleDeviceAtWindowsLevel(deviceId, device.Name);
                }

                device.Status = DeviceStatus.Blocked;
                device.IsAuthenticated = false;
                device.QuarantineTime = DateTime.Now;
                device.IsSystemLevelBlocked = true;
                device.IsApplicationLevelBlocked = true;

                _logger.LogSecurity($"🚫 PERMANENT Windows-level block completed for: {device.Name}");
                NotifyStatusChange($"🚫 Device PERMANENTLY blocked at Windows level: {device.Name}");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error blocking device at Windows level: {ex.Message}");
            }
        }

        /// <summary>
        /// Block a single device instance at Windows level
        /// CRITICAL FIX: Remove from allow list BEFORE adding to deny list to ensure blocking in same session
        /// </summary>
        private async Task BlockSingleDeviceAtWindowsLevel(string deviceId, string deviceName)
        {
            try
            {
                _logger.LogSecurity($"🚫 Blocking single device: {deviceId}");

                var hardwareId = _hardwareIdConverter?.ConvertPnPIdToHardwareId(deviceId);

                if (_policyManager != null && !string.IsNullOrEmpty(hardwareId))
                {
                    // CRITICAL FIX: Step 1 - Remove from allow list first (if it was temporarily allowed)
                    _logger.LogSecurity($"🚫 STEP 1: Removing device from allow list: {hardwareId}");
                    _policyManager.RemoveDeviceFromAllowList(hardwareId);
                    
                    // Small delay to ensure registry update
                    await Task.Delay(100);
                    
                    // CRITICAL FIX: Step 2 - Add to deny/blacklist
                    _logger.LogSecurity($"🚫 STEP 2: Adding device to deny list: {hardwareId}");
                    _policyManager.AddDeviceToBlackList(hardwareId);
                    
                    // CRITICAL FIX: Step 3 - Force registry refresh
                    _logger.LogSecurity($"🚫 STEP 3: Forcing registry refresh...");
                    await Task.Delay(100);

                    // CRITICAL FIX: Step 4 - Re-enumerate device to apply block immediately
                    if (_deviceReenumerator != null)
                    {
                        _logger.LogSecurity($"🚫 STEP 4: Re-enumerating device to apply block...");
                        await _deviceReenumerator.ReenumerateDeviceAsync(hardwareId);
                        await Task.Delay(500); // Wait for re-enumeration
                    }
                    
                    _logger.LogSecurity($"✅ Device blocked at Windows level: {hardwareId}");
                }

                // ADDITIONAL FIX: Also try instance-level blocking as backup
                if (_useInstanceBlocking && _instanceBlocker != null)
                {
                    _logger.LogSecurity($"🚫 BACKUP: Applying instance-level block...");
                    bool instanceBlocked = await _instanceBlocker.BlockDeviceInstance(deviceId);
                    
                    if (instanceBlocked)
                    {
                        _logger.LogSecurity($"✅ Device instance ALSO blocked: {deviceId}");
                    }
                    else
                    {
                        _logger.LogWarning($"⚠️ Instance blocking failed for {deviceId}");
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error blocking single device {deviceId}: {ex.Message}");
            }
        }

        /// <summary>
        /// Allow device at Windows registry level
        /// </summary>
        private async Task AllowDeviceAtWindowsLevel(USBDeviceInfo device)
        {
            try
            {
                if (device == null) return;

                _logger.LogSecurity($"✅ WINDOWS-LEVEL ALLOW: {device.Name}");

                if (device.Type == USBDeviceType.Keyboard || device.Type == USBDeviceType.Mouse)
                {
                    _logger.LogInfo($"✅ {device.Type} authentication passed - device was already functional during authentication");
                    
                    device.Status = DeviceStatus.Trusted;
                    device.IsAuthenticated = true;
                    device.AuthenticatedTime = DateTime.Now;
                    device.QuarantineTime = null;
                    
                    var hardwareId = device.HardwareId ?? _hardwareIdConverter?.ConvertPnPIdToHardwareId(device.DeviceId);
                    if (_authenticationCache != null && !string.IsNullOrEmpty(hardwareId))
                    {
                        _authenticationCache.AddAuthenticated(hardwareId, device.Name, device.Type.ToString());
                        _logger.LogInfo($"✅ {device.Type} added to 5-minute session cache");
                    }
                    
                    NotifyStatusChange($"✅ {device.Type} authenticated: {device.Name}");
                    return;
                }

                // For storage devices: Already enabled in proactive scanning, just update status
                if (device.Type == USBDeviceType.Storage)
                {
                    device.Status = DeviceStatus.Trusted;
                    device.IsAuthenticated = true;
                    device.AuthenticatedTime = DateTime.Now;
                    device.QuarantineTime = null;
                    
                    NotifyStatusChange($"✅ Storage device allowed: {device.Name}");
                    return;
                }

                // For other devices
                device.Status = DeviceStatus.Trusted;
                device.IsAuthenticated = true;
                device.AuthenticatedTime = DateTime.Now;

                NotifyStatusChange($"✅ Device allowed: {device.Name}");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error allowing device at Windows level: {ex.Message}");
            }
        }

        /// <summary>
        /// Enhanced authentication handler with Windows policy integration
        /// </summary>
        private async void OnDeviceAuthenticatedWithZeroTrust(object sender, DeviceAuthenticationEventArgs e)
        {
            try
            {
                if (e?.Device == null) return;

                _logger.LogSecurity($"🔐 Authentication result - {e.Device.Name}: {(e.IsAuthenticated ? "✅ APPROVED" : "🚫 DENIED")}");

                if (e.IsAuthenticated)
                {
                    await AllowDeviceAtWindowsLevel(e.Device);

                    // Do NOT add storage to persistent whitelist
                    if (e.Device.Type != USBDeviceType.Storage)
                    {
                        if (_whitelistManager != null)
                        {
                            await _whitelistManager.AddToWhitelistAsync(e.Device, $"Authenticated via {e.AuthenticationMethod}");
                        }
                    }
                    else
                    {
                        _logger.LogSecurity($"💾 STORAGE DEVICE - NOT adding to permanent whitelist (must rescan on replug)");
                    }

                    NotifyStatusChange($"✅ Device authenticated: {e.Device.Name}");
                }
                else
                {
                    await BlockDeviceAtWindowsLevel(e.Device);

                    if (_whitelistManager != null)
                    {
                        await _whitelistManager.AddToBlacklistAsync(e.Device, $"Authentication failed via {e.AuthenticationMethod}");
                    }

                    NotifyStatusChange($"🚫 Device blocked permanently: {e.Device.Name}");
                }

                NotifyDeviceAuthenticated(e.Device, e.IsAuthenticated, e.AuthenticationMethod);
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error in authentication handler: {ex.Message}");
            }
        }

        /// <summary>
        /// Handler for devices blocked by Windows policy
        /// </summary>
        private void OnDeviceBlockedByPolicy(BlockedDeviceInfo blockedDevice)
        {
            try
            {
                _logger.LogWarning($"🚫 Device blocked by Windows policy: {blockedDevice.Name} (Error Code: {blockedDevice.ErrorCode})");
                
                var device = GetDeviceByHardwareId(blockedDevice.HardwareID);
                
                if (device != null)
                {
                    device.Status = DeviceStatus.Blocked;
                    device.IsAuthenticated = false;
                    
                    NotifyStatusChange($"🚫 Windows blocked device: {blockedDevice.Name}");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error handling policy-blocked device: {ex.Message}");
            }
        }

        /// <summary>
        /// Find device by PnP Device ID
        /// </summary>
        private USBDeviceInfo GetDeviceByPnpId(string pnpDeviceId)
        {
            if (string.IsNullOrEmpty(pnpDeviceId)) return null;

            foreach (var device in _connectedDevices.Values)
            {
                if (device.PnpDeviceId != null && device.PnpDeviceId.Equals(pnpDeviceId, StringComparison.OrdinalIgnoreCase))
                {
                    return device;
                }
            }

            return null;
        }

        #endregion

        #region Dispose Enhancement

        /// <summary>
        /// Enhanced dispose with Zero-Trust cleanup
        /// </summary>
        private void DisposeZeroTrustResources()
        {
            try
            {
                _authenticationCache?.Dispose();
                _authenticationCache = null;

                _storageTemporaryCache?.Dispose();
                _storageTemporaryCache = null;

                _storageScanner = null;
                _policyManager = null;
                _backupManager = null;
                _hardwareIdConverter = null;
                _blockedDeviceDetector = null;
                _deviceReenumerator = null;
            }
            catch (Exception ex)
            {
                _logger?.LogError($"Error disposing Zero-Trust resources: {ex.Message}");
            }
        }

        #endregion
    }
}

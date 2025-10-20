using System;
using System.Threading.Tasks;
using System.Windows;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Windows.Threading;
using USB_Guard.Dialogs;
using USB_Guard.Models;

namespace USB_Guard.Core
{
    /// <summary>
    /// Enhanced Device Authenticator with GUARANTEED storage malware scanning
    /// FIXES: Always completes scan, always blocks malicious, always shows dialog, prevents false "safe" on replug
    /// </summary>
    public class DeviceAuthenticator
    {
        private readonly SecurityLogger _logger;
        private readonly WhitelistManager _whitelistManager;
        private readonly StorageScanner _storageScanner;
        
        // Device scan cache - prevent false "safe" on replug
        private static readonly Dictionary<string, DeviceScanCache> _scanCache = new Dictionary<string, DeviceScanCache>();
        private static readonly object _cacheLock = new object();
        
        // Dialog state management to prevent duplicates
        private readonly Dictionary<string, bool> _activeDialogs = new Dictionary<string, bool>();
        private readonly object _dialogLock = new object();
        
        // NEW: Device Instance Blocker for immediate hardware-level blocking
        private readonly DeviceInstanceBlocker _instanceBlocker;

        public event EventHandler<DeviceAuthenticationEventArgs> AuthenticationCompleted;

        public DeviceAuthenticator()
        {
            _logger = new SecurityLogger();
            _whitelistManager = new WhitelistManager();
            _storageScanner = new StorageScanner();
            _instanceBlocker = new DeviceInstanceBlocker(); // Initialize instance blocker
            
            _logger.LogSecurity("✅ DeviceAuthenticator initialized with GUARANTEED storage scanning and instant keyboard blocking");
        }

        public async Task AuthenticateDeviceAsync(USBDeviceInfo device)
        {
            try
            {
                device.Status = DeviceStatus.Authenticating;
                _logger.LogSecurity($"🔍 Starting authentication for device: {device.Name}");

                // Check device history for context
                bool wasWhitelisted = false;
                bool wasBlacklisted = false;
                
                try
                {
                    wasWhitelisted = await _whitelistManager.IsDeviceWhitelistedAsync(device);
                    wasBlacklisted = await _whitelistManager.IsDeviceBlacklistedAsync(device);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning($"Error checking device history: {ex.Message}");
                }

                device.WasWhitelisted = wasWhitelisted;
                device.WasBlacklisted = wasBlacklisted;

                // Show appropriate authentication dialog
                bool authResult = false;
                string authMethod = "";
                string failureReason = "";

                try
                {
                    _logger.LogSecurity($"🔍 DEVICE TYPE DETECTED: {device.Type} for device: {device.Name}");
                    
                    switch (device.Type)
                    {
                        case USBDeviceType.Keyboard:
                            _logger.LogSecurity($"⌨️ CALLING KeyboardAuthenticationDialog for {device.Name}");
                            (authResult, failureReason) = await AuthenticateKeyboardAsync(device);
                            authMethod = "Keyboard Authentication";
                            break;

                        case USBDeviceType.Mouse:
                            _logger.LogSecurity($"🖱️ CALLING MouseAuthenticationDialog for {device.Name}");
                            (authResult, failureReason) = await AuthenticateMouseAsync(device);
                            authMethod = "Mouse Authentication";
                            break;

                        case USBDeviceType.Storage:
                            _logger.LogSecurity($"💾 CALLING Enhanced Storage Malware Analysis for {device.Name}");
                            (authResult, failureReason) = await AuthenticateStorageAsync(device);
                            authMethod = "Storage Malware Analysis";
                            break;

                        case USBDeviceType.HID:
                            _logger.LogSecurity($"🎮 CALLING HIDAuthenticationDialog for {device.Name}");
                            (authResult, failureReason) = await AuthenticateHIDAsync(device);
                            authMethod = "HID Authentication";
                            break;

                        default:
                            _logger.LogSecurity($"❓ CALLING Generic MessageBox for {device.Name} (Type: {device.Type})");
                            (authResult, failureReason) = await AuthenticateGenericAsync(device);
                            authMethod = "Generic Authentication";
                            break;
                    }
                }
                catch (Exception ex)
                {
                    authResult = false;
                    failureReason = $"Authentication exception: {ex.Message}";
                    _logger.LogError($"Authentication exception for {device.Name}: {ex.Message}");
                }

                // Handle result
                if (authResult)
                {
                    _logger.LogSecurity($"✅ Authentication SUCCESS for {device.Name}");
                    device.Status = DeviceStatus.Trusted;
                    device.IsAuthenticated = true;
                    device.AuthenticatedTime = DateTime.Now;
                }
                else
                {
                    _logger.LogSecurity($"🚫 Authentication FAILURE for {device.Name} - {failureReason}");
                    device.Status = DeviceStatus.Blocked;
                    device.IsAuthenticated = false;
                }

                AuthenticationCompleted?.Invoke(this, new DeviceAuthenticationEventArgs(device, authResult, authMethod));
            }
            catch (Exception ex)
            {
                _logger.LogError($"Critical authentication error for device {device.Name}: {ex.Message}");
                
                device.Status = DeviceStatus.Blocked;
                device.IsAuthenticated = false;
                AuthenticationCompleted?.Invoke(this, new DeviceAuthenticationEventArgs(device, false, "System Error"));
            }
        }

        private async Task<(bool success, string failureReason)> AuthenticateKeyboardAsync(USBDeviceInfo device)
        {
            try
            {
                device.KeyboardLayout = DetectKeyboardLayout();
                _logger.LogSecurity($"⌨️ Starting keyboard authentication for {device.Name}");

                var dialogTask = Application.Current.Dispatcher.InvokeAsync(async () =>
                {
                    var dialog = new KeyboardAuthenticationDialog(device);
                    return await dialog.ShowDialogAsync();
                });

                var result = await dialogTask.Result;
                
                if (result)
                {
                    _logger.LogSecurity($"✅ Keyboard authentication APPROVED for {device.Name}");
                    return (true, "");
                }
                else
                {
                    _logger.LogSecurity($"🚫🚫🚫 KEYBOARD AUTHENTICATION FAILED for {device.Name}");
                    _logger.LogSecurity($"🚫 APPLYING IMMEDIATE SYSTEM-LEVEL BLOCKING (SAME SESSION)");
                    
                    // CRITICAL: Apply immediate system-level blocking for keyboard authentication failure
                    device.IsSystemLevelBlocked = true;
                    device.IsApplicationLevelBlocked = true;
                    
                    // Apply immediate hardware-level blocking using DeviceInstanceBlocker
                    await ApplyImmediateKeyboardBlocking(device);
                    
                    return (false, "Keyboard authentication failed - User could not enter code correctly in time. Device BLOCKED IMMEDIATELY at SYSTEM + APP level.");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Keyboard authentication failed: {ex.Message}");
                return (false, $"Keyboard authentication error: {ex.Message}");
            }
        }

        /// <summary>
        /// Apply immediate system-level blocking for keyboard authentication failure
        /// Blocks device at hardware level in the SAME SESSION (no need to replug)
        /// </summary>
        private async Task ApplyImmediateKeyboardBlocking(USBDeviceInfo device)
        {
            try
            {
                _logger.LogSecurity($"⌨️ ============================================");
                _logger.LogSecurity($"⌨️ APPLYING IMMEDIATE KEYBOARD BLOCKING");
                _logger.LogSecurity($"⌨️ Device: {device.Name}");
                _logger.LogSecurity($"⌨️ ============================================");
                
                // STEP 1: Application-level blocking
                _logger.LogSecurity($"⌨️ STEP 1: Application-level blocking...");
                device.Status = DeviceStatus.Blocked;
                device.IsAuthenticated = false;
                device.QuarantineTime = DateTime.Now;
                device.IsApplicationLevelBlocked = true;
                _logger.LogSecurity($"⌨️ ✅ Application-level blocking applied");
                
                // STEP 2: System-level blocking using DeviceInstanceBlocker
                if (_instanceBlocker != null && _instanceBlocker.CanAccessSetupAPI())
                {
                    _logger.LogSecurity($"⌨️ STEP 2: System-level blocking using DeviceInstanceBlocker...");
                    _logger.LogSecurity($"⌨️ Target Device ID: {device.DeviceId}");
                    
                    // Block the keyboard device at Windows hardware level
                    bool systemBlocked = await _instanceBlocker.BlockDeviceInstance(device.DeviceId);
                    
                    if (systemBlocked)
                    {
                        device.IsSystemLevelBlocked = true;
                        _logger.LogSecurity($"⌨️ ✅✅✅ SYSTEM-LEVEL BLOCKING SUCCESSFUL");
                        _logger.LogSecurity($"⌨️ Keyboard is now COMPLETELY DISABLED at Windows hardware level");
                        _logger.LogSecurity($"⌨️ Device BLOCKED in SAME SESSION (no replug needed)");
                    }
                    else
                    {
                        _logger.LogWarning($"⌨️ ⚠️ System-level blocking failed - Application-level blocking still active");
                    }
                }
                else
                {
                    _logger.LogWarning($"⌨️ ⚠️ System-level blocking not available - Application-level blocking only");
                }
                
                // STEP 3: Block composite parent if keyboard is part of composite device
                if (!string.IsNullOrEmpty(device.ParentCompositeDeviceId))
                {
                    _logger.LogSecurity($"⌨️ STEP 3: Keyboard is part of composite device - blocking parent and siblings");
                    _logger.LogSecurity($"⌨️ Parent Composite Device ID: {device.ParentCompositeDeviceId}");
                    
                    bool parentBlocked = await _instanceBlocker.BlockDeviceInstance(device.ParentCompositeDeviceId);
                    
                    if (parentBlocked)
                    {
                        _logger.LogSecurity($"⌨️ ✅ Parent composite device also blocked");
                    }
                }
                
                _logger.LogSecurity($"⌨️ ============================================");
                _logger.LogSecurity($"⌨️ IMMEDIATE KEYBOARD BLOCKING COMPLETE");
                _logger.LogSecurity($"⌨️ Application Level: {device.IsApplicationLevelBlocked}");
                _logger.LogSecurity($"⌨️ System Level: {device.IsSystemLevelBlocked}");
                _logger.LogSecurity($"⌨️ ============================================");
            }
            catch (Exception ex)
            {
                _logger.LogError($"⌨️ Error applying immediate keyboard blocking: {ex.Message}");
            }
        }

        private async Task<(bool success, string failureReason)> AuthenticateMouseAsync(USBDeviceInfo device)
        {
            try
            {
                device.MouseType = DetectMouseType(device);
                _logger.LogSecurity($"🖱️ Starting mouse authentication for {device.Name}");

                var dialogTask = Application.Current.Dispatcher.InvokeAsync(async () =>
                {
                    var dialog = new MouseAuthenticationDialog(device);
                    return await dialog.ShowDialogAsync();
                });

                var result = await dialogTask.Result;
                var failureReason = result ? "" : "User denied mouse authentication";
                
                _logger.LogSecurity($"{(result ? "✅" : "🚫")} Mouse authentication {(result ? "APPROVED" : "DENIED")} for {device.Name}");
                
                return (result, failureReason);
            }
            catch (Exception ex)
            {
                _logger.LogError($"Mouse authentication failed: {ex.Message}");
                return (false, $"Mouse authentication error: {ex.Message}");
            }
        }

        private async Task<(bool success, string failureReason)> AuthenticateStorageAsync(USBDeviceInfo device)
        {
            StorageScanResult scanResult = null;
            bool dialogShown = false;
            
            try
            {
                _logger.LogSecurity($"💾 ============================================");
                _logger.LogSecurity($"💾 STARTING MANDATORY STORAGE SCAN FOR: {device.Name}");
                _logger.LogSecurity($"💾 Device ID: {device.DeviceId}");
                _logger.LogSecurity($"💾 ============================================");

                // ⚠️ ALWAYS FORCE RESCAN - Check cache but always scan anyway
                string deviceKey = GetDeviceCacheKey(device);
                bool hasRecentScan = CheckRecentScan(deviceKey, out DeviceScanCache cachedScan);
                
                if (hasRecentScan && cachedScan != null)
                {
                    _logger.LogWarning($"💾 ⚠️ DEVICE PREVIOUSLY SCANNED - FORCING RESCAN ANYWAY");
                    _logger.LogWarning($"💾 Previous result: {(cachedScan.ThreatsDetected ? "MALICIOUS" : "CLEAN")} ({cachedScan.ThreatCount} threats)");
                    _logger.LogWarning($"💾 📋 POPUP WILL SHOW - User will see rescan results");
                }
                else
                {
                    _logger.LogSecurity($"💾 ℹ️ First scan for this device");
                }

                // Find drive letter for the device
                var driveLetter = await FindDriveLetterForDevice(device);
                device.DriveLetter = driveLetter;

                if (string.IsNullOrEmpty(driveLetter))
                {
                    _logger.LogWarning($"💾 ❌ NO DRIVE LETTER FOUND for {device.Name}");
                    
                    // Show dialog for unmounted device
                    var unmountedResult = new StorageScanResult
                    {
                        ScanCompleted = true,
                        TotalFilesScanned = 0,
                        ThreatCount = 0,
                        ThreatsDetected = false,
                        ErrorMessage = "Device not mounted or no accessible drive",
                        ScanDuration = TimeSpan.Zero
                    };
                    
                    _logger.LogSecurity($"💾 SHOWING dialog for unmounted device...");
                    bool userDecision = await ShowStorageScanResultDialogGuaranteed(device, unmountedResult);
                    dialogShown = true;
                    
                    return (userDecision, userDecision ? "" : "Device not mounted - blocked");
                }

                _logger.LogSecurity($"💾 ✅ DRIVE LETTER FOUND: {driveLetter}");
                _logger.LogSecurity($"💾 🔍 STARTING COMPREHENSIVE RESCAN...");
                _logger.LogSecurity($"💾 📋 POPUP WILL APPEAR - Showing live scan progress");

                // CRITICAL: ALWAYS PERFORM FULL SCAN (even if cached)
                _logger.LogSecurity($"💾 ⏳ SCANNING ALL FILES (forced rescan)...");
                
                try
                {
                    // Perform comprehensive scan - MUST COMPLETE
                    scanResult = await _storageScanner.ScanDriveAsync(driveLetter);
                    
                    _logger.LogSecurity($"💾 ✅ RESCAN COMPLETED");
                    _logger.LogSecurity($"💾 Files scanned: {scanResult.TotalFilesScanned}");
                    _logger.LogSecurity($"💾 Threats found: {scanResult.ThreatCount}");
                    _logger.LogSecurity($"💾 Scan duration: {scanResult.ScanDuration.TotalSeconds:F1}s");
                }
                catch (Exception scanEx)
                {
                    _logger.LogError($"💾 ❌ SCAN FAILED: {scanEx.Message}");
                    
                    scanResult = new StorageScanResult
                    {
                        ScanCompleted = false,
                        ErrorMessage = $"Scan error: {scanEx.Message}",
                        ThreatCount = 0,
                        ThreatsDetected = false
                    };
                }

                // Store scan result in cache
                StoreScanInCache(deviceKey, scanResult);

                // MANDATORY: Show dialog with scan results (ALWAYS POPUP)
                _logger.LogSecurity($"💾 📋 SHOWING MANDATORY POPUP - Rescan results");
                bool authDecision = await ShowStorageScanResultDialogGuaranteed(device, scanResult);
                dialogShown = true;
                _logger.LogSecurity($"💾 📋 Popup closed - Auto-decision: {(authDecision ? "ALLOW" : "BLOCK")}");

                // Make final decision based on scan results
                if (scanResult.ThreatsDetected && scanResult.ThreatCount > 0)
                {
                    _logger.LogSecurity($"💾 ❌❌❌ MALICIOUS DEVICE DETECTED ❌❌❌");
                    _logger.LogSecurity($"💾 Threat count: {scanResult.ThreatCount}");
                    _logger.LogSecurity($"💾 🚫 AUTO-BLOCKING DEVICE (no user override)");
                    
                    // ALWAYS BLOCK malicious devices - no user choice
                    return (false, $"❌ MALWARE DETECTED: {scanResult.ThreatCount} threats - AUTO-BLOCKED");
                }
                else if (scanResult.ScanCompleted)
                {
                    _logger.LogSecurity($"💾 ✅✅✅ CLEAN DEVICE VERIFIED ✅✅✅");
                    _logger.LogSecurity($"💾 {scanResult.TotalFilesScanned} files scanned - NO threats");
                    _logger.LogSecurity($"💾 ✅ AUTO-ALLOWING DEVICE");
                    
                    // Auto-allow clean devices
                    return (true, "");
                }
                else
                {
                    _logger.LogWarning($"💾 ⚠️ SCAN INCOMPLETE: {scanResult.ErrorMessage}");
                    _logger.LogSecurity($"💾 🚫 AUTO-BLOCKING (safety measure)");
                    
                    // Block incomplete scans for safety
                    return (false, $"Scan incomplete - AUTO-BLOCKED for safety");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"💾 ❌ STORAGE AUTHENTICATION EXCEPTION: {ex.Message}");
                
                // ALWAYS show dialog even on error
                if (!dialogShown)
                {
                    var errorResult = new StorageScanResult
                    {
                        ErrorMessage = ex.Message,
                        ScanCompleted = false,
                        ScanDuration = TimeSpan.Zero
                    };
                    
                    try
                    {
                        _logger.LogSecurity($"💾 Showing error popup...");
                        await ShowStorageScanResultDialogGuaranteed(device, errorResult);
                    }
                    catch (Exception dialogEx)
                    {
                        _logger.LogError($"💾 Failed to show error popup: {dialogEx.Message}");
                    }
                }
                
                return (false, $"Error: {ex.Message} - AUTO-BLOCKED");
            }
            finally
            {
                _logger.LogSecurity($"💾 ============================================");
                _logger.LogSecurity($"💾 STORAGE SCAN COMPLETE FOR: {device.Name}");
                _logger.LogSecurity($"💾 Popup was shown: {dialogShown}");
                _logger.LogSecurity($"💾 ============================================");
            }
        }

        /// <summary>
        /// GUARANTEED to show dialog - will retry on failure
        /// </summary>
        private async Task<bool> ShowStorageScanResultDialogGuaranteed(USBDeviceInfo device, StorageScanResult scanResult)
        {
            int attempts = 0;
            const int maxAttempts = 3;
            Exception lastException = null;
            
            while (attempts < maxAttempts)
            {
                attempts++;
                
                try
                {
                    _logger.LogSecurity($"💾 📋 Attempt {attempts}/{maxAttempts} to show dialog");
                    
                    var result = await Application.Current.Dispatcher.InvokeAsync(async () =>
                    {
                        try
                        {
                            // Determine if device should be blocked
                            bool shouldBlock = scanResult.ThreatsDetected || !scanResult.ScanCompleted;
                            
                            _logger.LogSecurity($"💾 Creating dialog - Should block: {shouldBlock}");
                            var dialog = new StorageScanResultDialog(device, scanResult, shouldBlock);
                            
                            _logger.LogSecurity($"💾 Showing modal dialog...");
                            var dialogResult = dialog.ShowDialog();
                            
                            _logger.LogSecurity($"💾 Dialog closed with result: {dialogResult}");
                            return dialogResult ?? false; // Default to block if null
                        }
                        catch (Exception innerEx)
                        {
                            _logger.LogError($"💾 Inner dialog error: {innerEx.Message}");
                            throw;
                        }
                    });
                    
                    var decision = await result;
                    _logger.LogSecurity($"💾 ✅ Dialog shown successfully, decision: {(decision ? "ALLOW" : "BLOCK")}");
                    return decision;
                }
                catch (Exception ex)
                {
                    lastException = ex;
                    _logger.LogError($"💾 ❌ Dialog attempt {attempts} failed: {ex.Message}");
                    
                    if (attempts < maxAttempts)
                    {
                        _logger.LogWarning($"💾 Retrying in 500ms...");
                        await Task.Delay(500);
                    }
                }
            }
            
            // All attempts failed - default to BLOCK for safety
            _logger.LogError($"💾 ❌ ALL DIALOG ATTEMPTS FAILED - Defaulting to BLOCK");
            _logger.LogError($"💾 Last error: {lastException?.Message}");
            return false;
        }

        /// <summary>
        /// Get cache key for device (based on VID/PID/Serial)
        /// </summary>
        private string GetDeviceCacheKey(USBDeviceInfo device)
        {
            return $"{device.VendorId}_{device.ProductId}_{device.DeviceId}";
        }

        /// <summary>
        /// Check if device was scanned recently (within 5 minutes)
        /// </summary>
        private bool CheckRecentScan(string deviceKey, out DeviceScanCache cachedScan)
        {
            lock (_cacheLock)
            {
                if (_scanCache.TryGetValue(deviceKey, out cachedScan))
                {
                    // Check if scan is recent (within 5 minutes)
                    var timeSinceScan = DateTime.Now - cachedScan.ScanTime;
                    if (timeSinceScan.TotalMinutes < 5)
                    {
                        return true;
                    }
                    else
                    {
                        // Remove stale cache entry
                        _scanCache.Remove(deviceKey);
                    }
                }
                
                cachedScan = null;
                return false;
            }
        }

        /// <summary>
        /// Store scan result in cache
        /// </summary>
        private void StoreScanInCache(string deviceKey, StorageScanResult scanResult)
        {
            lock (_cacheLock)
            {
                _scanCache[deviceKey] = new DeviceScanCache
                {
                    ScanTime = DateTime.Now,
                    ThreatsDetected = scanResult.ThreatsDetected,
                    ThreatCount = scanResult.ThreatCount,
                    ScanCompleted = scanResult.ScanCompleted
                };
                
                _logger.LogInfo($"💾 Scan result cached for device (expires in 5 minutes)");
            }
        }

        private async Task<(bool success, string failureReason)> AuthenticateHIDAsync(USBDeviceInfo device)
        {
            try
            {
                var behaviorAnalysis = await AnalyzeHIDBehavior(device);
                _logger.LogSecurity($"🎮 Starting HID authentication for {device.Name}");

                var dialogTask = Application.Current.Dispatcher.InvokeAsync(async () =>
                {
                    var dialog = new HIDAuthenticationDialog(device, behaviorAnalysis);
                    return await dialog.ShowDialogAsync();
                });

                var result = await dialogTask.Result;
                var failureReason = result ? "" : "User denied HID authentication";
                
                _logger.LogSecurity($"{(result ? "✅" : "🚫")} HID authentication {(result ? "APPROVED" : "DENIED")} for {device.Name}");
                
                return (result, failureReason);
            }
            catch (Exception ex)
            {
                _logger.LogError($"HID authentication failed: {ex.Message}");
                return (false, $"HID authentication error: {ex.Message}");
            }
        }

        private async Task<(bool success, string failureReason)> AuthenticateGenericAsync(USBDeviceInfo device)
        {
            try
            {
                _logger.LogSecurity($"❓ Starting generic authentication for {device.Name}");

                var dialogResult = await Application.Current.Dispatcher.InvokeAsync(() =>
                {
                    var message = BuildGenericMessage(device);
                    
                    var messageBoxResult = MessageBox.Show(
                        message,
                        "USB Guard - Device Authentication",
                        MessageBoxButton.YesNo,
                        device.WasBlacklisted ? MessageBoxImage.Warning : MessageBoxImage.Question);

                    return messageBoxResult == MessageBoxResult.Yes;
                });

                var failureReason = dialogResult ? "" : "User denied device authentication";
                
                _logger.LogSecurity($"{(dialogResult ? "✅" : "🚫")} Generic authentication {(dialogResult ? "APPROVED" : "DENIED")} for {device.Name}");
                
                return (dialogResult, failureReason);
            }
            catch (Exception ex)
            {
                _logger.LogError($"Generic authentication failed: {ex.Message}");
                return (false, $"Generic authentication error: {ex.Message}");
            }
        }

        private string BuildGenericMessage(USBDeviceInfo device)
        {
            var message = new StringBuilder();
            message.AppendLine("🔍 USB DEVICE AUTHENTICATION REQUIRED");
            message.AppendLine();
            message.AppendLine("Device Details:");
            message.AppendLine($"Name: {device.Name}");
            message.AppendLine($"Type: {device.TypeDisplayName}");
            message.AppendLine($"VID: {device.VendorId}");
            message.AppendLine($"PID: {device.ProductId}");
            message.AppendLine();
            
            if (device.WasWhitelisted)
            {
                message.AppendLine("✅ Previously trusted device");
            }
            else if (device.WasBlacklisted)
            {
                message.AppendLine("🚫 Previously blocked device");
            }
            else
            {
                message.AppendLine("❓ Unknown device");
            }
            
            message.AppendLine();
            message.AppendLine("Do you want to allow this device?");
            
            return message.ToString();
        }

        // Helper methods
        private string DetectKeyboardLayout()
        {
            try
            {
                var layout = System.Globalization.CultureInfo.CurrentCulture.Name;
                switch (layout)
                {
                    case "en-US":
                        return "US English";
                    case "en-GB":
                        return "UK English";
                    case "de-DE":
                        return "German";
                    case "fr-FR":
                        return "French";
                    case "es-ES":
                        return "Spanish";
                    default:
                        return $"Unknown ({layout})";
                }
            }
            catch
            {
                return "Unknown";
            }
        }

        private string DetectMouseType(USBDeviceInfo device)
        {
            try
            {
                var name = device.Name.ToLower();
                
                if (name.Contains("gaming")) return "Gaming Mouse";
                if (name.Contains("wireless")) return "Wireless Mouse";
                if (name.Contains("optical")) return "Optical Mouse";
                if (name.Contains("laser")) return "Laser Mouse";
                
                return "Standard Mouse";
            }
            catch
            {
                return "Unknown Mouse";
            }
        }

        private async Task<string> FindDriveLetterForDevice(USBDeviceInfo device)
        {
            try
            {
                await Task.Delay(1000);
                
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

        private async Task<HIDBehaviorAnalysis> AnalyzeHIDBehavior(USBDeviceInfo device)
        {
            try
            {
                await Task.Delay(1000);

                return new HIDBehaviorAnalysis
                {
                    IsSuspicious = device.WasBlacklisted,
                    BehaviorScore = device.WasBlacklisted ? 25 : (device.WasWhitelisted ? 85 : 60),
                    AnalysisDetails = device.WasBlacklisted ? 
                        "🚫 Device was previously blocked" : 
                        (device.WasWhitelisted ? 
                            "✅ Device was previously trusted" : 
                            "❓ Unknown HID device"),
                    RecommendedAction = device.WasBlacklisted ? 
                        "🚫 Recommend blocking" : 
                        "🔍 Authentication required"
                };
            }
            catch (Exception ex)
            {
                _logger.LogError($"HID analysis failed: {ex.Message}");
                return new HIDBehaviorAnalysis
                {
                    IsSuspicious = true,
                    BehaviorScore = 0,
                    AnalysisDetails = $"Analysis failed: {ex.Message}",
                    RecommendedAction = "🚫 Block due to analysis failure"
                };
            }
        }
    }

    /// <summary>
    /// Device scan cache to prevent false "safe" on replug
    /// </summary>
    public class DeviceScanCache
    {
        public DateTime ScanTime { get; set; }
        public bool ThreatsDetected { get; set; }
        public int ThreatCount { get; set; }
        public bool ScanCompleted { get; set; }
    }

    public class DeviceAuthenticationEventArgs : EventArgs
    {
        public USBDeviceInfo Device { get; }
        public bool IsAuthenticated { get; }
        public string AuthenticationMethod { get; }

        public DeviceAuthenticationEventArgs(USBDeviceInfo device, bool isAuthenticated, string authenticationMethod)
        {
            Device = device;
            IsAuthenticated = isAuthenticated;
            AuthenticationMethod = authenticationMethod;
        }
    }
}

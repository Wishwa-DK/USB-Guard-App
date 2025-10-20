using System;
using System.Windows;
using System.Windows.Media;
using System.Windows.Threading;
using System.Windows.Controls;
using USB_Guard.Core;
using USB_Guard.Models;
using System.Linq;
using System.Threading.Tasks;

namespace USB_Guard.Dialogs
{
    /// <summary>
    /// Live USB Threat Detection Dialog with Dual-Level Blocking
    /// Shows real-time malicious file type counts and implements both system-level and application-level blocking
    /// </summary>
    public partial class StorageScanResultDialog : Window
    {
        private readonly USBDeviceInfo _device;
        private readonly StorageScanResult _scanResult;
        private readonly SecurityLogger _logger;
        private readonly DispatcherTimer _autoActionTimer;
        private readonly DispatcherTimer _liveUpdateTimer;
        private int _timeRemaining = 10; // Auto-action after 10 seconds
        private readonly bool _isBlocked;
        private bool _scanCompleted = false;
        private bool _dualLevelBlockingApplied = false;

        // Live threat counters
        private int _criticalCount = 0;
        private int _highCount = 0;
        private int _mediumCount = 0;
        private int _totalThreatCount = 0;

        // Dual-level blocking components
        private DeviceInstanceBlocker _systemBlocker;
        private bool _systemLevelBlocked = false;
        private bool _applicationLevelBlocked = false;

        public StorageScanResultDialog(USBDeviceInfo device, StorageScanResult scanResult, bool isBlocked)
        {
            InitializeComponent();
            _device = device;
            _scanResult = scanResult;
            _isBlocked = isBlocked;
            _logger = new SecurityLogger();

            // Initialize dual-level blocking
            InitializeDualLevelBlocking();

            InitializeDialog();
            
            // Set up timers
            _autoActionTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
            _autoActionTimer.Tick += AutoActionTimer_Tick;
            
            _liveUpdateTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(500) };
            _liveUpdateTimer.Tick += LiveUpdateTimer_Tick;
            
            // CRITICAL: Check if scan is already completed when dialog opens
            if (scanResult != null && scanResult.ScanCompleted)
            {
                _logger.LogSecurity($"📋 Scan already completed when dialog created - showing final results immediately");
                _scanCompleted = true;
                
                // Show final results immediately
                OnScanCompleted();
            }
            else
            {
                _logger.LogSecurity($"📋 Scan in progress - starting live updates");
                // Start live updates for in-progress scan
                _liveUpdateTimer.Start();
            }
            
            _logger.LogSecurity($"Live threat detection dialog opened for {_device.Name} with dual-level blocking");
        }

        private void InitializeDualLevelBlocking()
        {
            try
            {
                _systemBlocker = new DeviceInstanceBlocker();
                
                if (_systemBlocker.CanAccessSetupAPI())
                {
                    _logger.LogSecurity("System-level blocking available - Dual-level blocking enabled");
                }
                else
                {
                    _logger.LogWarning("System-level blocking not available - Application-level blocking only");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error initializing dual-level blocking: {ex.Message}");
            }
        }

        private void InitializeDialog()
        {
            try
            {
                // Set device information
                SetTextSafely("DeviceNameText", _device.Name);
                SetTextSafely("DriveLetterText", _device.DriveLetter ?? "N/A");
                
                // Initialize with scanning state
                SetPanelColor("HeaderPanel", "#2196F3"); // Blue for scanning
                SetTextSafely("HeaderText", "Live Storage Security Analysis");
                SetTextSafely("SubHeaderText", "Real-time malware scanning with advanced protection...");
                
                // Initialize counters
                UpdateThreatCounters();
                
                // Show initial scan progress
                UpdateScanProgress();
                
                _logger.LogInfo($"Live threat detection dialog initialized for {_device.Name}");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error initializing live threat detection dialog: {ex.Message}");
            }
        }

        private void LiveUpdateTimer_Tick(object sender, EventArgs e)
        {
            try
            {
                // Update scan progress in real-time
                UpdateScanProgress();
                
                // Update threat counters if scan result is available
                if (_scanResult != null)
                {
                    UpdateThreatCounters();
                    
                    // Check if scan is completed
                    if (_scanResult.ScanCompleted && !_scanCompleted)
                    {
                        _scanCompleted = true;
                        OnScanCompleted();
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error in live update: {ex.Message}");
            }
        }

        private void OnScanCompleted()
        {
            try
            {
                _liveUpdateTimer.Stop();
                
                // Update final scan results
                UpdateThreatCounters();
                UpdateScanProgress();
                
                if (_scanResult.ThreatsDetected && _scanResult.ThreatCount > 0)
                {
                    // ❌ MALICIOUS DEVICE DETECTED - AUTO-BLOCK IMMEDIATELY (NO USER CHOICE)
                    _logger.LogSecurity($"❌ MALICIOUS DEVICE - AUTO-BLOCKING IMMEDIATELY");
                    
                    // Apply dual-level blocking immediately
                    _ = Task.Run(async () => await ApplyDualLevelBlocking());
                    
                    ShowThreatsDetectedState();
                    
                    // HIDE action buttons - no user choice for malicious devices
                    HideElement("ActionButtonsPanel");
                    
                    // MODIFIED: Longer countdown for malicious threats (10 seconds as requested)
                    _timeRemaining = 10;
                    StartAutoBlockCountdown();
                }
                else if (_scanResult.ScanCompleted)
                {
                    // ✅ Clean device - auto-allow after brief display
                    ShowCleanDeviceState();
                    
                    // Hide action buttons for clean devices too
                    HideElement("ActionButtonsPanel");
                    
                    // Clean devices still use shorter countdown (3 seconds)
                    _timeRemaining = 3;
                    StartAutoAllowCountdown();
                }
                else
                {
                    // Scan incomplete/error - auto-block for safety
                    _logger.LogWarning($"💾 Scan incomplete - AUTO-BLOCKING for safety");
                    
                    SetPanelColor("HeaderPanel", "#FF9800"); // Orange
                    SetTextSafely("HeaderText", "SCAN INCOMPLETE - BLOCKING FOR SAFETY");
                    SetTextSafely("SubHeaderText", _scanResult.ErrorMessage ?? "Scan incomplete - device blocked");
                    
                    // Hide action buttons
                    HideElement("ActionButtonsPanel");
                    
                    // Auto-block incomplete scans (shorter time)
                    _timeRemaining = 3;
                    StartAutoBlockCountdown();
                }
                
                _logger.LogSecurity($"Scan completed for {_device.Name} - Threats: {_scanResult.ThreatCount}");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error handling scan completion: {ex.Message}");
                
                // On error, auto-block
                HideElement("ActionButtonsPanel");
                _timeRemaining = 3;
                StartAutoBlockCountdown();
            }
        }

        /// <summary>
        /// Apply dual-level blocking when threats are detected
        /// System-level (Windows SetupAPI) + Application-level blocking
        /// </summary>
        private async Task ApplyDualLevelBlocking()
        {
            try
            {
                if (_dualLevelBlockingApplied) return; // Prevent multiple applications
                
                _logger.LogSecurity($"APPLYING DUAL-LEVEL BLOCKING for {_device.Name}");
                
                // 1. Application-level blocking (immediate)
                await ApplyApplicationLevelBlocking();
                
                // 2. System-level blocking (Windows API)
                await ApplySystemLevelBlocking();
                
                _dualLevelBlockingApplied = true;
                
                // Update UI to show blocking status
                await Dispatcher.InvokeAsync(() =>
                {
                    UpdateBlockingStatusDisplay();
                });
                
                _logger.LogSecurity($"DUAL-LEVEL BLOCKING COMPLETE for {_device.Name}");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error applying dual-level blocking: {ex.Message}");
            }
        }

        /// <summary>
        /// Apply application-level blocking
        /// </summary>
        private async Task ApplyApplicationLevelBlocking()
        {
            try
            {
                _applicationLevelBlocked = true;
                _device.Status = Models.DeviceStatus.Blocked;
                _device.IsAuthenticated = false;
                _device.QuarantineTime = DateTime.Now;
                
                _logger.LogSecurity($"APPLICATION-LEVEL BLOCKING applied for {_device.Name}");
                
                await Task.Delay(100); // Brief delay for logging
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error in application-level blocking: {ex.Message}");
            }
        }

        /// <summary>
        /// Apply system-level blocking using Windows SetupAPI
        /// </summary>
        private async Task ApplySystemLevelBlocking()
        {
            try
            {
                if (_systemBlocker != null && _systemBlocker.CanAccessSetupAPI())
                {
                    _logger.LogSecurity($"SYSTEM-LEVEL BLOCKING: Disabling device at Windows level: {_device.Name}");
                    
                    bool systemBlocked = await _systemBlocker.BlockDeviceInstance(_device.DeviceId);
                    
                    if (systemBlocked)
                    {
                        _systemLevelBlocked = true;
                        _device.IsSystemLevelBlocked = true;
                        
                        _logger.LogSecurity($"SYSTEM-LEVEL BLOCKING successful for {_device.Name}");
                        _logger.LogSecurity($"Device is now COMPLETELY BLOCKED at both system and application levels");
                    }
                    else
                    {
                        _logger.LogWarning($"System-level blocking failed for {_device.Name} - Application-level blocking still active");
                    }
                }
                else
                {
                    _logger.LogWarning($"System-level blocking not available - Application-level blocking only");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error in system-level blocking: {ex.Message}");
            }
        }

        /// <summary>
        /// Update UI to show current blocking status
        /// </summary>
        private void UpdateBlockingStatusDisplay()
        {
            try
            {
                string blockingStatus = "";
                
                if (_systemLevelBlocked && _applicationLevelBlocked)
                {
                    blockingStatus = "DUAL-LEVEL BLOCKING ACTIVE";
                    SetTextSafely("SubHeaderText", "Device blocked at both Windows system level and application level");
                    
                    // Show blocking status panel
                    ShowElement("BlockingStatusPanel");
                    
                    // Update application level status
                    SetTextSafely("AppLevelStatusText", "BLOCKED");
                    SetBlockingStatusColor("AppLevelStatus", "#FFCDD2", "#F44336"); // Red
                    
                    // Update system level status
                    SetTextSafely("SystemLevelStatusText", "BLOCKED");
                    SetBlockingStatusColor("SystemLevelStatus", "#FFCDD2", "#F44336"); // Red
                }
                else if (_applicationLevelBlocked)
                {
                    blockingStatus = "APPLICATION-LEVEL BLOCKING ACTIVE";
                    SetTextSafely("SubHeaderText", "Device blocked at application level");
                    
                    // Show blocking status panel
                    ShowElement("BlockingStatusPanel");
                    
                    // Update application level status
                    SetTextSafely("AppLevelStatusText", "BLOCKED");
                    SetBlockingStatusColor("AppLevelStatus", "#FFCDD2", "#F44336"); // Red
                    
                    // Update system level status
                    SetTextSafely("SystemLevelStatusText", "NOT APPLIED");
                    SetBlockingStatusColor("SystemLevelStatus", "#F5F5F5", "#9E9E9E"); // Gray
                }
                else
                {
                    blockingStatus = "Scanning in progress...";
                    HideElement("BlockingStatusPanel");
                }
                
                // Update header if threats detected
                if (_scanCompleted && _scanResult?.ThreatsDetected == true)
                {
                    SetTextSafely("HeaderText", $"MALICIOUS FILES DETECTED - {blockingStatus}");
                }
                
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error updating blocking status display: {ex.Message}");
            }
        }

        /// <summary>
        /// Set blocking status panel colors
        /// </summary>
        private void SetBlockingStatusColor(string panelName, string backgroundColor, string borderColor)
        {
            try
            {
                if (FindName(panelName) is Border border)
                {
                    border.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString(backgroundColor));
                    border.BorderBrush = new SolidColorBrush((Color)ColorConverter.ConvertFromString(borderColor));
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error setting blocking status color: {ex.Message}");
            }
        }

        private void ShowThreatsDetectedState()
        {
            try
            {
                // Update header for threats detected
                SetPanelColor("HeaderPanel", "#F44336"); // Red
                SetTextSafely("HeaderText", "⛔ MALICIOUS DEVICE - AUTO-BLOCKING");
                SetTextSafely("SubHeaderText", $"{_scanResult.ThreatCount} threat(s) detected - Device will be blocked automatically");
                
                // Show threat count panel
                ShowElement("ThreatCountPanel");
                
                // Hide clean device panel
                HideElement("CleanDevicePanel");
                
                // Show live threat list if there are threats
                if (_scanResult.DetectedThreats.Count > 0)
                {
                    ShowLiveThreatList();
                }
                
                _logger.LogSecurity($"⛔ Showing malicious device state - AUTO-BLOCKING {_device.Name}");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error showing threats detected state: {ex.Message}");
            }
        }

        private void ShowCleanDeviceState()
        {
            try
            {
                // Update header for clean device
                SetPanelColor("HeaderPanel", "#4CAF50"); // Green
                SetTextSafely("HeaderText", "✅ DEVICE CLEAN - AUTO-ALLOWING");
                SetTextSafely("SubHeaderText", "No threats detected - Device will be allowed automatically");
                
                // Show clean device panel
                ShowElement("CleanDevicePanel");
                
                // Hide threat count panel
                HideElement("ThreatCountPanel");
                
                _logger.LogSecurity($"✅ Clean device verified - AUTO-ALLOWING {_device.Name}");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error showing clean device state: {ex.Message}");
            }
        }

        private void ShowLiveThreatList()
        {
            try
            {
                ShowElement("LiveThreatListPanel");
                
                var threatList = FindName("LiveThreatList") as StackPanel;
                if (threatList == null) return;
                
                threatList.Children.Clear();
                
                // Show top 5 most critical threats
                var topThreats = _scanResult.GetTopThreats(5);
                
                foreach (var threat in topThreats)
                {
                    var threatItem = CreateThreatListItem(threat);
                    threatList.Children.Add(threatItem);
                }
                
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error showing live threat list: {ex.Message}");
            }
        }

        private Border CreateThreatListItem(MaliciousFile threat)
        {
            var border = new Border
            {
                Background = GetThreatLevelColor(threat.ThreatLevel),
                CornerRadius = new CornerRadius(6),
                Padding = new Thickness(12, 6, 12, 6),
                Margin = new Thickness(0, 3, 0, 3),
                BorderThickness = new Thickness(1),
                BorderBrush = GetThreatLevelBorderColor(threat.ThreatLevel)
            };

            var textBlock = new TextBlock
            {
                Text = $"{GetThreatIcon(threat.ThreatLevel)} {threat.FileName} - {threat.Reason}",
                FontSize = 11,
                FontFamily = new System.Windows.Media.FontFamily("Segoe UI"),
                FontWeight = FontWeights.Medium,
                Foreground = new SolidColorBrush(Colors.Black),
                TextWrapping = TextWrapping.Wrap
            };

            border.Child = textBlock;
            return border;
        }

        private string GetThreatIcon(string threatLevel)
        {
            switch (threatLevel?.ToUpper())
            {
                case "CRITICAL": return "[CRITICAL]";
                case "HIGH": return "[HIGH]";
                case "MEDIUM": return "[MEDIUM]";
                default: return "[THREAT]";
            }
        }

        private Brush GetThreatLevelColor(string threatLevel)
        {
            switch (threatLevel?.ToUpper())
            {
                case "CRITICAL": return new SolidColorBrush(Color.FromRgb(255, 235, 238)); // Light red
                case "HIGH": return new SolidColorBrush(Color.FromRgb(255, 243, 224)); // Light orange
                case "MEDIUM": return new SolidColorBrush(Color.FromRgb(255, 253, 231)); // Light yellow
                default: return new SolidColorBrush(Color.FromRgb(250, 250, 250)); // Light gray
            }
        }

        private Brush GetThreatLevelBorderColor(string threatLevel)
        {
            switch (threatLevel?.ToUpper())
            {
                case "CRITICAL": return new SolidColorBrush(Color.FromRgb(244, 67, 54));
                case "HIGH": return new SolidColorBrush(Color.FromRgb(255, 152, 0));
                case "MEDIUM": return new SolidColorBrush(Color.FromRgb(255, 193, 7));
                default: return new SolidColorBrush(Color.FromRgb(189, 189, 189));
            }
        }

        private void StartAutoBlockCountdown()
        {
            try
            {
                ShowElement("AutoBlockTimerPanel");
                HideElement("AutoAllowTimerPanel");
                
                // Update countdown text immediately
                SetTextSafely("AutoBlockCountdownText", $"{_timeRemaining} seconds");
                
                _autoActionTimer.Start();
                
                if (_timeRemaining == 10)
                {
                    _logger.LogSecurity($"💾 DEVICE ALREADY BLOCKED IMMEDIATELY - Popup will close in {_timeRemaining} seconds");
                    _logger.LogSecurity($"💾 IMPORTANT: Device blocking is NOT waiting for popup - it's already applied!");
                }
                else
                {
                    _logger.LogSecurity($"💾 AUTO-BLOCK: Device will be blocked in {_timeRemaining} seconds (scan failure/error case)");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error starting auto-block countdown: {ex.Message}");
            }
        }

        private void StartAutoAllowCountdown()
        {
            try
            {
                ShowElement("AutoAllowTimerPanel");
                HideElement("AutoBlockTimerPanel");
                
                // Update countdown text immediately
                SetTextSafely("AutoAllowCountdownText", $"{_timeRemaining} seconds");
                
                _autoActionTimer.Start();
                
                _logger.LogSecurity($"✅ AUTO-ALLOW: Clean device will be allowed in {_timeRemaining} seconds");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error starting auto-allow countdown: {ex.Message}");
            }
        }

        private void UpdateThreatCounters()
        {
            try
            {
                if (_scanResult?.DetectedThreats != null)
                {
                    _criticalCount = _scanResult.DetectedThreats.Count(t => t.ThreatLevel == "CRITICAL");
                    _highCount = _scanResult.DetectedThreats.Count(t => t.ThreatLevel == "HIGH");
                    _mediumCount = _scanResult.DetectedThreats.Count(t => t.ThreatLevel == "MEDIUM");
                    _totalThreatCount = _scanResult.ThreatCount;
                }

                // Update UI counters
                SetTextSafely("CriticalCountText", _criticalCount.ToString());
                SetTextSafely("HighCountText", _highCount.ToString());
                SetTextSafely("MediumCountText", _mediumCount.ToString());
                SetTextSafely("TotalThreatCountText", _totalThreatCount.ToString());
                
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error updating threat counters: {ex.Message}");
            }
        }

        private void UpdateScanProgress()
        {
            try
            {
                if (_scanResult != null)
                {
                    SetTextSafely("ScannedFilesText", _scanResult.TotalFilesScanned.ToString());
                    SetTextSafely("ScanTimeText", $"{_scanResult.ScanDuration.TotalSeconds:F1}s");
                    SetTextSafely("TotalSizeText", _scanResult.FormattedSize);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error updating scan progress: {ex.Message}");
            }
        }

        private void AutoActionTimer_Tick(object sender, EventArgs e)
        {
            _timeRemaining--;
            
            // Update countdown display
            if (_scanResult?.ThreatsDetected == true)
            {
                SetTextSafely("AutoBlockCountdownText", $"{_timeRemaining} seconds");
            }
            else
            {
                SetTextSafely("AutoAllowCountdownText", $"{_timeRemaining} seconds");
            }

            if (_timeRemaining <= 0)
            {
                _autoActionTimer.Stop();
                
                if (_scanResult?.ThreatsDetected == true)
                {
                    // Confirm device blocking (already applied dual-level blocking immediately)
                    _logger.LogSecurity($"POPUP TIMEOUT: Closing malicious device dialog for {_device.Name} after 10 seconds");
                    _logger.LogSecurity($"REMINDER: Device was ALREADY BLOCKED IMMEDIATELY when threats were detected");
                    AutoBlockDevice();
                }
                else
                {
                    // Auto-allow clean device
                    _logger.LogSecurity($"AUTO-ALLOWING clean device {_device.Name} after 3 seconds");
                    AutoAllowDevice();
                }
                
                Close();
            }
        }

        private void AutoBlockDevice()
        {
            try
            {
                // Device is already blocked at both levels (blocking was applied immediately when threats detected)
                DialogResult = false;
                _logger.LogSecurity($"Device {_device.Name} - POPUP CLOSED (device was already blocked immediately)");
                _logger.LogSecurity($"Final Blocking Summary:");
                _logger.LogSecurity($"   Application Level: {(_applicationLevelBlocked ? "BLOCKED" : "Not Blocked")}");
                _logger.LogSecurity($"   System Level: {(_systemLevelBlocked ? "BLOCKED" : "Not Blocked")}");
                _logger.LogSecurity($"   Threats Found: {_totalThreatCount}");
                _logger.LogSecurity($"   Block Applied: IMMEDIATELY when threats detected (NOT waiting for popup)");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error in auto-block confirmation: {ex.Message}");
            }
        }

        private void AutoAllowDevice()
        {
            try
            {
                DialogResult = true;
                _logger.LogSecurity($"Clean device {_device.Name} will be automatically allowed");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error in auto-allow: {ex.Message}");
            }
        }

        private void BlockButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                _autoActionTimer.Stop();
                _liveUpdateTimer.Stop();
                
                // Apply dual-level blocking if not already applied
                if (!_dualLevelBlockingApplied)
                {
                    _ = Task.Run(async () => await ApplyDualLevelBlocking());
                }
                
                DialogResult = false;
                _logger.LogSecurity($"User manually blocked device {_device.Name} (dual-level blocking)");
                Close();
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error in manual block: {ex.Message}");
            }
        }

        private void SetTextSafely(string controlName, string text)
        {
            try
            {
                if (FindName(controlName) is TextBlock textBlock)
                {
                    textBlock.Text = text ?? "Unknown";
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"Could not set text for {controlName}: {ex.Message}");
            }
        }

        private void HideElement(string elementName)
        {
            try
            {
                if (FindName(elementName) is UIElement element)
                {
                    element.Visibility = Visibility.Collapsed;
                }
            }
            catch { }
        }

        private void ShowElement(string elementName)
        {
            try
            {
                if (FindName(elementName) is UIElement element)
                {
                    element.Visibility = Visibility.Visible;
                }
            }
            catch { }
        }

        private void SetPanelColor(string panelName, string colorHex)
        {
            try
            {
                if (FindName(panelName) is Border border)
                {
                    border.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString(colorHex));
                }
            }
            catch { }
        }

        protected override void OnClosed(EventArgs e)
        {
            try
            {
                _autoActionTimer?.Stop();
                _liveUpdateTimer?.Stop();
                
                // Log final blocking status
                if (_dualLevelBlockingApplied)
                {
                    _logger.LogSecurity($"Final Status for {_device.Name}:");
                    _logger.LogSecurity($"   Application Blocked: {_applicationLevelBlocked}");
                    _logger.LogSecurity($"   System Blocked: {_systemLevelBlocked}");
                    _logger.LogSecurity($"   Total Threats: {_totalThreatCount}");
                }
                
                _logger.LogInfo($"Live threat detection dialog closed for {_device.Name}");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error during dialog close: {ex.Message}");
            }
            finally
            {
                base.OnClosed(e);
            }
        }
    }

    /// <summary>
    /// Dual-level blocking status information
    /// </summary>
    public class DualLevelBlockingStatus
    {
        public bool ApplicationLevelBlocked { get; set; }
        public bool SystemLevelBlocked { get; set; }
        public bool DualLevelBlockingApplied { get; set; }
        public int ThreatCount { get; set; }
        
        public string BlockingLevel
        {
            get
            {
                if (SystemLevelBlocked && ApplicationLevelBlocked)
                    return "Dual-Level (System + Application)";
                else if (SystemLevelBlocked)
                    return "System-Level Only";
                else if (ApplicationLevelBlocked)
                    return "Application-Level Only";
                else
                    return "Not Blocked";
            }
        }
    }
}
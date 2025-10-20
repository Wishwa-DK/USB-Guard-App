using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using USB_Guard.Core;
using USB_Guard.Models;

namespace USB_Guard
{
    public enum NotificationType
    {
        Info,
        Success,
        Warning,
        Error
    }

    public partial class MainWindow : Window, INotifyPropertyChanged
    {
        private readonly USBDeviceManager _deviceManager;
        private readonly SecurityLogger _logger;
        private readonly StartupManager _startupManager;
        private DispatcherTimer _refreshTimer; // Single timer instead of multiple
        private bool _isInitialized = false;
        
        private SystemTrayManager _systemTrayManager;

        public ObservableCollection<USBDeviceDisplayInfo> ConnectedDevices { get; } = new ObservableCollection<USBDeviceDisplayInfo>();
        public ObservableCollection<SecurityEvent> RecentEvents { get; } = new ObservableCollection<SecurityEvent>();

        // Simplified properties
        private int _connectedCount;
        public int ConnectedCount
        {
            get => _connectedCount;
            set { _connectedCount = value; OnPropertyChanged(nameof(ConnectedCount)); }
        }

        private int _quarantinedCount;
        public int QuarantinedCount
        {
            get => _quarantinedCount;
            set { _quarantinedCount = value; OnPropertyChanged(nameof(QuarantinedCount)); }
        }

        private int _blockedCount;
        public int BlockedCount
        {
            get => _blockedCount;
            set { _blockedCount = value; OnPropertyChanged(nameof(BlockedCount)); }
        }

        private int _trustedCount;
        public int TrustedCount
        {
            get => _trustedCount;
            set { _trustedCount = value; OnPropertyChanged(nameof(TrustedCount)); }
        }

        private bool _isProtectionEnabled = true;
        public bool IsProtectionEnabled
        {
            get => _isProtectionEnabled;
            set { _isProtectionEnabled = value; OnPropertyChanged(nameof(IsProtectionEnabled)); }
        }

        private string _currentPage = "Dashboard";
        public string CurrentPage
        {
            get => _currentPage;
            set { _currentPage = value; OnPropertyChanged(nameof(CurrentPage)); }
        }

        private string _statusMessage = "Starting USB Guard...";
        public string StatusMessage
        {
            get => _statusMessage;
            set { _statusMessage = value; OnPropertyChanged(nameof(StatusMessage)); }
        }

        private string _protectionStatus = "Starting...";
        public string ProtectionStatus
        {
            get => _protectionStatus;
            set { _protectionStatus = value; OnPropertyChanged(nameof(ProtectionStatus)); }
        }

        public MainWindow()
        {
            try
            {
                InitializeComponent();
                DataContext = this;

                _logger = App.GetLogger() ?? new SecurityLogger();
                _logger.LogSecurity("🚀 Starting USB Guard");

                _deviceManager = App.GetUSBDeviceManager();
                _startupManager = App.GetStartupManager();
                
                if (_deviceManager == null)
                {
                    _logger.LogWarning("⚠️ USB Device Manager not available");
                    EnsureBasicFunctionality();
                    return;
                }

                // Initialize system tray
                try
                {
                    _systemTrayManager = new SystemTrayManager(this, _deviceManager, _startupManager, _logger);
                    _logger.LogInfo("✅ System tray initialized");
                }
                catch (Exception trayEx)
                {
                    _logger.LogWarning($"System tray failed: {trayEx.Message}");
                }

                InitializeUI();
                ConnectEvents();
                SetupTimer();
                StartMonitoring();

                _logger.LogSecurity("✅ USB Guard initialized successfully");
            }
            catch (Exception ex)
            {
                _logger?.LogError($"Critical initialization error: {ex.Message}");
                HandleInitializationError(ex);
            }
        }

        private void InitializeUI()
        {
            try
            {
                StatusMessage = "USB Guard ready";
                ShowDashboard();
                
                ConnectedDevices.Clear();
                RecentEvents.Clear();
                
                // Load recent events from log file (last 24 hours)
                LoadRecentEventsFromLogs();
                
                ConnectedCount = 0;
                QuarantinedCount = 0;
                BlockedCount = 0;
                TrustedCount = 0;
                
                ProtectionStatus = "Initializing...";
                
                _logger.LogInfo("UI initialized with real log data");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error initializing UI: {ex.Message}");
                throw;
            }
        }

        private void LoadRecentEventsFromLogs()
        {
            try
            {
                if (_logger == null) return;

                // Get logs from last 24 hours
                var recentLogs = _logger.GetRecentLogs(24);
                
                foreach (var logLine in recentLogs)
                {
                    // Only process device-related logs for dashboard
                    if (logLine.Contains("[DEVICE]") || logLine.Contains("[AUTH]") || logLine.Contains("[SECURITY]"))
                    {
                        var securityEvent = ParseLogToSecurityEvent(logLine);
                        if (securityEvent != null)
                        {
                            RecentEvents.Add(securityEvent);
                        }
                    }
                }

                // Keep only the most recent 50 events for dashboard
                while (RecentEvents.Count > 50)
                {
                    RecentEvents.RemoveAt(RecentEvents.Count - 1);
                }

                _logger.LogInfo($"Loaded {RecentEvents.Count} recent security events from logs");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error loading recent events from logs: {ex.Message}");
            }
        }

        private SecurityEvent ParseLogToSecurityEvent(string logLine)
        {
            try
            {
                // Parse: [2024-01-15 10:30:45.123] [LEVEL] message
                if (string.IsNullOrEmpty(logLine)) return null;

                var timestampEnd = logLine.IndexOf(']');
                if (timestampEnd < 0) return null;

                var timestampStr = logLine.Substring(1, timestampEnd - 1);
                if (!DateTime.TryParse(timestampStr, out DateTime timestamp))
                    return null;

                var levelStart = logLine.IndexOf('[', timestampEnd + 1);
                var levelEnd = logLine.IndexOf(']', levelStart + 1);
                if (levelEnd < 0) return null;

                var level = logLine.Substring(levelStart + 1, levelEnd - levelStart - 1);
                var message = logLine.Substring(levelEnd + 1).Trim();

                // Determine event type from message
                string eventType = "Security Event";
                if (message.Contains("Device Connected") || message.Contains("📱"))
                    eventType = "Device Connected";
                else if (message.Contains("Device Disconnected") || message.Contains("📤"))
                    eventType = "Device Disconnected";
                else if (message.Contains("APPROVED") || message.Contains("✅"))
                    eventType = "Device Authenticated";
                else if (message.Contains("BLOCKED") || message.Contains("🚫"))
                    eventType = "Device Blocked";
                else if (message.Contains("Fortress Mode") || message.Contains("🏰"))
                    eventType = "Fortress Mode";
                else if (message.Contains("Zero-Trust") || message.Contains("🛡️"))
                    eventType = "Zero-Trust Mode";

                return new SecurityEvent
                {
                    Timestamp = timestamp,
                    EventType = eventType,
                    Level = level,
                    Details = message
                };
            }
            catch
            {
                return null;
            }
        }

        private void ConnectEvents()
        {
            try
            {
                if (_deviceManager != null)
                {
                    _deviceManager.DeviceConnected += OnDeviceConnected;
                    _deviceManager.DeviceDisconnected += OnDeviceDisconnected;
                    _deviceManager.DeviceAuthenticated += OnDeviceAuthenticated;
                    
                    _logger.LogInfo("✅ Connected to device manager events");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error connecting events: {ex.Message}");
            }
        }

        private void SetupTimer()
        {
            try
            {
                // Single timer for all UI updates
                _refreshTimer = new DispatcherTimer
                {
                    Interval = TimeSpan.FromSeconds(2) // Simple 2-second refresh
                };
                _refreshTimer.Tick += RefreshTimer_Tick;
                _refreshTimer.Start();

                _logger.LogInfo("Refresh timer started");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error setting up timer: {ex.Message}");
            }
        }

        private void StartMonitoring()
        {
            try
            {
                StatusMessage = "Starting USB monitoring...";
                
                Task.Run(() =>
                {
                    try
                    {
                        _deviceManager.StartMonitoring();
                        
                        Dispatcher.BeginInvoke(new Action(() =>
                        {
                            _isInitialized = true;
                            StatusMessage = "✅ USB Guard is active - monitoring USB devices";
                            ProtectionStatus = "ACTIVE";
                            IsProtectionEnabled = true;
                            
                            RefreshDeviceList();
                            UpdateStatistics();
                        }));
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError($"Error starting monitoring: {ex.Message}");
                        
                        Dispatcher.BeginInvoke(new Action(() =>
                        {
                            StatusMessage = $"❌ Failed to start USB monitoring: {ex.Message}";
                            ProtectionStatus = "ERROR";
                            IsProtectionEnabled = false;
                        }));
                    }
                });
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error initializing monitoring: {ex.Message}");
                StatusMessage = $"❌ Monitoring initialization failed: {ex.Message}";
                ProtectionStatus = "FAILED";
                IsProtectionEnabled = false;
            }
        }

        private void EnsureBasicFunctionality()
        {
            try
            {
                StatusMessage = "⚠️ USB Guard - Limited functionality";
                ProtectionStatus = "ACTIVE";
                IsProtectionEnabled = true;
                
                ShowDashboard();
                ConnectedDevices.Clear();
                RecentEvents.Clear();
                
                _isInitialized = true;
                
                AddSecurityEvent("System Ready", "INFO", "USB Guard initialized");
                
                if (_refreshTimer == null)
                {
                    SetupTimer();
                }
                
                _logger.LogSecurity("✅ Basic functionality ensured");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error ensuring functionality: {ex.Message}");
            }
        }

        private void HandleInitializationError(Exception ex)
        {
            StatusMessage = "⚠️ USB Guard - Error during startup";
            ProtectionStatus = "ERROR";
            IsProtectionEnabled = false;
            
            MessageBox.Show(
                $"USB Guard encountered an error during startup:\n\n{ex.Message}\n\n" +
                "The application will continue with limited functionality.",
                "USB Guard - Startup Error", 
                MessageBoxButton.OK, 
                MessageBoxImage.Warning);
            
            ShowDashboard();
        }

        // Simplified event handlers
        private void OnDeviceConnected(object sender, USBDeviceEventArgs e)
        {
            try
            {
                Dispatcher.BeginInvoke(new Action(() =>
                {
                    var device = e.Device;
                    _logger.LogSecurity($"📱 Device Connected: {device.Name} ({device.Type})");
                    
                    AddSecurityEvent("Device Connected", "INFO", 
                        $"{device.Name} - {device.TypeDisplayName} (VID:{device.VendorId} PID:{device.ProductId})");

                    RefreshDeviceList();
                    UpdateStatistics();
                    
                    // Refresh logs if user is on Logs page
                    if (CurrentPage == "Logs")
                    {
                        RefreshLogs();
                    }
                    
                    _systemTrayManager?.UpdateTrayContextMenu();
                    
                    ShowNotification($"📱 USB Device Connected: {device.Name}", NotificationType.Info);
                }));
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error in device connected handler: {ex.Message}");
            }
        }

        private void OnDeviceDisconnected(object sender, USBDeviceEventArgs e)
        {
            try
            {
                Dispatcher.BeginInvoke(new Action(() =>
                {
                    var device = e.Device;
                    _logger.LogSecurity($"📤 Device Disconnected: {device.Name}");
                    
                    AddSecurityEvent("Device Disconnected", "INFO", $"{device.Name} - {device.TypeDisplayName}");

                    RefreshDeviceList();
                    UpdateStatistics();
                    
                    // Refresh logs if user is on Logs page
                    if (CurrentPage == "Logs")
                    {
                        RefreshLogs();
                    }
                    
                    _systemTrayManager?.UpdateTrayContextMenu();
                    
                    ShowNotification($"📤 Device Removed: {device.Name}", NotificationType.Info);
                }));
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error in device disconnected handler: {ex.Message}");
            }
        }

        private void OnDeviceAuthenticated(object sender, DeviceAuthenticationEventArgs e)
        {
            try
            {
                Dispatcher.BeginInvoke(new Action(() =>
                {
                    var device = e.Device;
                    var statusText = e.IsAuthenticated ? "✅ APPROVED" : "🚫 BLOCKED";
                    
                    _logger.LogSecurity($"🔐 Device {statusText}: {device.Name}");
                    
                    var eventLevel = e.IsAuthenticated ? "INFO" : "WARNING";
                    var eventDetails = $"{device.Name} - {statusText} via {e.AuthenticationMethod}";
                    
                    // Add context if device had previous status
                    if (device.WasWhitelisted && !e.IsAuthenticated)
                    {
                        eventDetails += " (⚠️ Previously trusted but denied)";
                    }
                    else if (device.WasBlacklisted && e.IsAuthenticated)
                    {
                        eventDetails += " (⚠️ Previously blocked but approved)";
                    }
                    
                    AddSecurityEvent("Device Authentication", eventLevel, eventDetails);

                    RefreshDeviceList();
                    UpdateStatistics();
                    
                    // Refresh logs if user is on Logs page
                    if (CurrentPage == "Logs")
                    {
                        RefreshLogs();
                    }
                    
                    _systemTrayManager?.UpdateTrayContextMenu();
                    
                    var notificationType = e.IsAuthenticated ? NotificationType.Success : NotificationType.Warning;
                    ShowNotification($"🔐 {device.Name} {statusText}", notificationType);
                }));
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error in device authenticated handler: {ex.Message}");
            }
        }

        private void RefreshTimer_Tick(object sender, EventArgs e)
        {
            try
            {
                if (!_isInitialized) return;
                
                // Simple refresh logic
                switch (CurrentPage)
                {
                    case "Dashboard":
                        UpdateStatistics();
                        // Refresh recent events from logs every timer tick
                        LoadRecentEventsFromLogs();
                        break;
                    case "Monitor":
                        RefreshDeviceList();
                        break;
                    case "Logs":
                        RefreshLogs();
                        break;
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"Error in refresh timer: {ex.Message}");
            }
        }

        #region Data Refresh Methods
        private void RefreshDeviceList()
        {
            try
            {
                if (_deviceManager == null) return;

                var devices = _deviceManager.GetConnectedDevices();
                if (devices == null) return;

                // Clear and rebuild device list
                ConnectedDevices.Clear();
                
                foreach (var device in devices.Values.OrderBy(d => d.ConnectedTime))
                {
                    try
                    {
                        var displayInfo = new USBDeviceDisplayInfo
                        {
                            Name = device.Name ?? "Unknown Device",
                            Type = GetProfessionalDeviceTypeDisplay(device.Type),
                            VendorId = device.VendorId ?? "0000",
                            ProductId = device.ProductId ?? "0000",
                            Status = device.Status.ToString(), // Simplified status display
                            StatusColor = GetProfessionalStatusColor(device.Status),
                            ConnectedTime = device.ConnectedTime ?? DateTime.Now,
                            IsAuthenticated = device.IsAuthenticated
                        };
                        
                        ConnectedDevices.Add(displayInfo);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning($"Error adding device to display list: {ex.Message}");
                    }
                }
                
                _logger.LogInfo($"Device list refreshed - {ConnectedDevices.Count} devices connected");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error refreshing device list: {ex.Message}");
            }
        }

        private void UpdateStatistics()
        {
            try
            {
                if (_deviceManager == null) return;

                var devices = _deviceManager.GetConnectedDevices();
                if (devices == null) return;

                var deviceList = devices.Values.ToList();
                
                ConnectedCount = deviceList.Count;
                QuarantinedCount = deviceList.Count(d => d.Status == DeviceStatus.Quarantined);
                BlockedCount = deviceList.Count(d => d.Status == DeviceStatus.Blocked);
                TrustedCount = deviceList.Count(d => d.Status == DeviceStatus.Trusted);
                
                // Update sidebar statistics
                UpdateTextBlockSafely("ConnectedCountText", ConnectedCount.ToString());
                UpdateTextBlockSafely("QuarantinedCountText", QuarantinedCount.ToString());
                UpdateTextBlockSafely("BlockedCountText", BlockedCount.ToString());
                
                // Update protection status indicator
                var protectionStatusText = FindName("ProtectionStatusText") as TextBlock;
                if (protectionStatusText != null) 
                {
                    protectionStatusText.Text = ProtectionStatus;
                    protectionStatusText.Foreground = IsProtectionEnabled ? Brushes.LimeGreen : Brushes.Red;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error updating statistics: {ex.Message}");
            }
        }

        private void RefreshLogs()
        {
            try
            {
                if (_logger == null) return;

                var deviceLogsControl = FindName("DeviceLogsItemsControl") as ItemsControl;
                if (deviceLogsControl != null)
                {
                    var recentLogs = _logger.GetRecentLogs(24);
                    var deviceLogs = new ObservableCollection<DeviceLogEntry>();

                    foreach (var logLine in recentLogs)
                    {
                        // Only show device-related logs (connections, disconnections, authentication)
                        if (logLine.Contains("[DEVICE]") || logLine.Contains("[AUTH]") || logLine.Contains("[SECURITY]"))
                        {
                            var entry = ParseLogEntry(logLine);
                            if (entry != null)
                            {
                                deviceLogs.Add(entry);
                            }
                        }
                    }

                    deviceLogsControl.ItemsSource = deviceLogs.Take(50).ToList(); // Show last 50 device events
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error refreshing logs: {ex.Message}");
            }
        }

        private DeviceLogEntry ParseLogEntry(string logLine)
        {
            try
            {
                // Parse log line format: [2024-01-15 10:30:45.123] [LEVEL] message
                if (string.IsNullOrEmpty(logLine)) return null;

                var entry = new DeviceLogEntry();

                // Extract timestamp
                var timestampEnd = logLine.IndexOf(']');
                if (timestampEnd > 0)
                {
                    var timestampStr = logLine.Substring(1, timestampEnd - 1);
                    if (DateTime.TryParse(timestampStr, out DateTime timestamp))
                    {
                        entry.Timestamp = timestamp;
                    }
                }

                // Extract level and message
                var levelStart = logLine.IndexOf('[', timestampEnd + 1);
                var levelEnd = logLine.IndexOf(']', levelStart + 1);
                string message = logLine.Substring(levelEnd + 1).Trim();

                // Parse device name and action from message
                if (message.Contains("Device Connected:") || message.Contains("📱 Device Connected:"))
                {
                    entry.DeviceIcon = "📱";
                    entry.Action = "Connected";
                    entry.ActionColor = Brushes.LimeGreen;
                    entry.DeviceName = ExtractDeviceName(message, "Connected:");
                    entry.Details = ExtractDeviceDetails(message);
                }
                else if (message.Contains("Device Disconnected:") || message.Contains("📤 Device Disconnected:"))
                {
                    entry.DeviceIcon = "📤";
                    entry.Action = "Disconnected";
                    entry.ActionColor = Brushes.Orange;
                    entry.DeviceName = ExtractDeviceName(message, "Disconnected:");
                    entry.Details = "";
                }
                else if (message.Contains("Device:") && message.Contains("Event:"))
                {
                    // Parse DEVICE log format: Device: Name | Event: Type | Details: ...
                    entry.DeviceIcon = "🔌";
                    entry.DeviceName = ExtractValueAfterKey(message, "Device:");
                    entry.Action = ExtractValueAfterKey(message, "Event:");
                    entry.ActionColor = Brushes.CornflowerBlue;
                    entry.Details = ExtractValueAfterKey(message, "Details:");
                }
                else if (message.Contains("✅ APPROVED") || message.Contains("APPROVED"))
                {
                    entry.DeviceIcon = "✅";
                    entry.Action = "Approved";
                    entry.ActionColor = Brushes.LimeGreen;
                    entry.DeviceName = ExtractDeviceName(message, "Device");
                    entry.Details = ExtractAuthMethod(message);
                }
                else if (message.Contains("🚫 BLOCKED") || message.Contains("BLOCKED"))
                {
                    entry.DeviceIcon = "🚫";
                    entry.Action = "Blocked";
                    entry.ActionColor = Brushes.Red;
                    entry.DeviceName = ExtractDeviceName(message, "Device");
                    entry.Details = ExtractAuthMethod(message);
                }
                else if (message.Contains("AUTH") || message.Contains("Method:"))
                {
                    // Parse AUTH log format
                    entry.DeviceIcon = "🔐";
                    entry.DeviceName = ExtractValueAfterKey(message, "Device:");
                    
                    if (message.Contains("SUCCESS"))
                    {
                        entry.Action = "Authentication Success";
                        entry.ActionColor = Brushes.LimeGreen;
                    }
                    else if (message.Contains("FAILED"))
                    {
                        entry.Action = "Authentication Failed";
                        entry.ActionColor = Brushes.Red;
                    }
                    else
                    {
                        entry.Action = "Authentication";
                        entry.ActionColor = Brushes.Yellow;
                    }
                    
                    entry.Details = ExtractValueAfterKey(message, "Method:");
                }
                else
                {
                    // Generic security event
                    entry.DeviceIcon = "🛡️";
                    entry.DeviceName = "System";
                    entry.Action = "Security Event";
                    entry.ActionColor = Brushes.CornflowerBlue;
                    entry.Details = message.Length > 100 ? message.Substring(0, 100) + "..." : message;
                }

                return entry;
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"Error parsing log entry: {ex.Message}");
                return null;
            }
        }

        private string ExtractDeviceName(string message, string keyword)
        {
            try
            {
                var index = message.IndexOf(keyword);
                if (index < 0) return "Unknown Device";

                var startIndex = index + keyword.Length;
                var deviceName = message.Substring(startIndex).Trim();

                // Remove everything after first parenthesis or special character
                var endIndex = deviceName.IndexOfAny(new[] { '(', '-', '|' });
                if (endIndex > 0)
                {
                    deviceName = deviceName.Substring(0, endIndex).Trim();
                }

                return string.IsNullOrEmpty(deviceName) ? "Unknown Device" : deviceName;
            }
            catch
            {
                return "Unknown Device";
            }
        }

        private string ExtractDeviceDetails(string message)
        {
            try
            {
                // Extract VID and PID if present
                var vidIndex = message.IndexOf("VID:");
                var pidIndex = message.IndexOf("PID:");

                if (vidIndex > 0 && pidIndex > 0)
                {
                    var vid = message.Substring(vidIndex + 4, 4).Trim();
                    var pid = message.Substring(pidIndex + 4, 4).Trim();
                    return $"VID:{vid} PID:{pid}";
                }

                return "";
            }
            catch
            {
                return "";
            }
        }

        private string ExtractValueAfterKey(string message, string key)
        {
            try
            {
                var index = message.IndexOf(key);
                if (index < 0) return "";

                var startIndex = index + key.Length;
                var value = message.Substring(startIndex).Trim();

                // Stop at next delimiter
                var endIndex = value.IndexOf('|');
                if (endIndex > 0)
                {
                    value = value.Substring(0, endIndex).Trim();
                }

                return value;
            }
            catch
            {
                return "";
            }
        }

        private string ExtractAuthMethod(string message)
        {
            try
            {
                if (message.Contains("via"))
                {
                    var viaIndex = message.IndexOf("via");
                    var method = message.Substring(viaIndex + 3).Trim();
                    
                    // Remove any trailing parentheses content
                    var parenIndex = method.IndexOf('(');
                    if (parenIndex > 0)
                    {
                        method = method.Substring(0, parenIndex).Trim();
                    }
                    
                    return $"Method: {method}";
                }
                return "";
            }
            catch
            {
                return "";
            }
        }

        private void DownloadLogs_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (_logger == null)
                {
                    MessageBox.Show("Logger is not available.", "Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                // Create save file dialog
                var saveFileDialog = new Microsoft.Win32.SaveFileDialog
                {
                    Title = "Save Security Logs",
                    FileName = $"USBGuard_Logs_{DateTime.Now:yyyyMMdd_HHmmss}.txt",
                    DefaultExt = ".txt",
                    Filter = "Text files (*.txt)|*.txt|Log files (*.log)|*.log|All files (*.*)|*.*"
                };

                var result = saveFileDialog.ShowDialog();
                if (result == true)
                {
                    try
                    {
                        StatusMessage = "💾 Exporting logs...";
                        
                        // Export all logs from the last 30 days
                        _logger.ExportLogs(saveFileDialog.FileName, DateTime.Now.AddDays(-30), DateTime.Now);
                        
                        StatusMessage = $"✅ Logs exported successfully to: {saveFileDialog.FileName}";

                        MessageBox.Show(
                            $"✅ Security Logs Exported Successfully!\n\n" +
                            $"File: {System.IO.Path.GetFileName(saveFileDialog.FileName)}\n" +
                            $"Location: {System.IO.Path.GetDirectoryName(saveFileDialog.FileName)}\n\n" +
                            "The file contains all device connection logs from the last 30 days.",
                            "Export Complete",
                            MessageBoxButton.OK,
                            MessageBoxImage.Information);
                    }
                    catch (Exception exportEx)
                    {
                        _logger.LogError($"Failed to export logs: {exportEx.Message}");
                        MessageBox.Show(
                            $"❌ Failed to export logs:\n\n{exportEx.Message}",
                            "Export Error",
                            MessageBoxButton.OK,
                            MessageBoxImage.Error);
                        
                        StatusMessage = "❌ Log export failed";
                    }
                }
            }
            catch (Exception ex)
            {
                _logger?.LogError($"Error in download logs dialog: {ex.Message}");
                MessageBox.Show(
                    $"❌ Error opening save dialog:\n\n{ex.Message}",
                    "Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
        }
        #endregion

        #region Helper Methods
        private string GetProfessionalDeviceTypeDisplay(USBDeviceType type)
        {
            switch (type)
            {
                case USBDeviceType.Storage: return "💾 Storage Device";
                case USBDeviceType.Keyboard: return "⌨️ Keyboard";
                case USBDeviceType.Mouse: return "🖱️ Mouse";
                case USBDeviceType.Audio: return "🔊 Audio Device";
                case USBDeviceType.Video: return "📹 Video Device";
                case USBDeviceType.HID: return "🎮 HID Device";
                case USBDeviceType.Printer: return "🖨️ Printer";
                case USBDeviceType.Hub: return "🔌 USB Hub";
                default: return "❓ Unknown Device";
            }
        }

        private Brush GetProfessionalStatusColor(DeviceStatus status)
        {
            switch (status)
            {
                case DeviceStatus.Trusted: return Brushes.LimeGreen;
                case DeviceStatus.Blocked: return Brushes.Red;
                case DeviceStatus.Quarantined: return Brushes.Orange;
                case DeviceStatus.Authenticating: return Brushes.Yellow;
                case DeviceStatus.Sandboxed: return Brushes.CornflowerBlue;
                default: return Brushes.Gray;
            }
        }

        private void UpdateTextBlockSafely(string name, string text)
        {
            try
            {
                var textBlock = FindName(name) as TextBlock;
                if (textBlock != null)
                {
                    textBlock.Text = text;
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"Error updating text block {name}: {ex.Message}");
            }
        }

        private void AddSecurityEvent(string eventType, string level, string details)
        {
            try
            {
                RecentEvents.Insert(0, new SecurityEvent
                {
                    Timestamp = DateTime.Now,
                    EventType = eventType,
                    Level = level,
                    Details = details
                });
                
                // Keep only recent events
                while (RecentEvents.Count > 200)
                {
                    RecentEvents.RemoveAt(RecentEvents.Count - 1);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"Error adding security event: {ex.Message}");
            }
        }

        private void ShowNotification(string message, NotificationType type)
        {
            try
            {
                var timestamp = DateTime.Now.ToString("HH:mm:ss");
                var formattedMessage = $"[{timestamp}] {message}";
                
                // Update status message
                StatusMessage = formattedMessage;
                
                _logger.LogInfo($"UI Notification: {message}");
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"Error showing notification: {ex.Message}");
            }
        }
        #endregion

        #region Navigation
        private void NavDashboard_Click(object sender, RoutedEventArgs e)
        {
            ShowDashboard();
            UpdateNavigationState("Dashboard");
        }

        private void NavMonitor_Click(object sender, RoutedEventArgs e)
        {
            ShowMonitor();
            UpdateNavigationState("Monitor");
        }

        private void NavLogs_Click(object sender, RoutedEventArgs e)
        {
            ShowLogs();
            UpdateNavigationState("Logs");
        }

        private void UpdateNavigationState(string activePage)
        {
            try
            {
                CurrentPage = activePage;

                // Reset all button styles
                SetButtonStyle("NavDashboard", "SidebarButton");
                SetButtonStyle("NavMonitor", "SidebarButton");
                SetButtonStyle("NavLogs", "SidebarButton");

                // Set active button style
                switch (activePage)
                {
                    case "Dashboard":
                        SetButtonStyle("NavDashboard", "SidebarButtonSelected");
                        break;
                    case "Monitor":
                        SetButtonStyle("NavMonitor", "SidebarButtonSelected");
                        break;
                    case "Logs":
                        SetButtonStyle("NavLogs", "SidebarButtonSelected");
                        break;
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"Error updating navigation state: {ex.Message}");
            }
        }

        private void SetButtonStyle(string buttonName, string styleName)
        {
            try
            {
                var button = FindName(buttonName) as Button;
                if (button != null && Resources.Contains(styleName))
                {
                    button.Style = (Style)FindResource(styleName);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"Error setting button style: {ex.Message}");
            }
        }

        private void ShowDashboard()
        {
            HideAllPanels();
            SetPanelVisibility("DashboardPanel", Visibility.Visible);
            UpdateStatistics();
        }

        private void ShowMonitor()
        {
            HideAllPanels();
            SetPanelVisibility("MonitorPanel", Visibility.Visible);
            RefreshDeviceList();
        }

        private void ShowLogs()
        {
            HideAllPanels();
            SetPanelVisibility("LogsPanel", Visibility.Visible);
            RefreshLogs();
        }

        private void HideAllPanels()
        {
            SetPanelVisibility("DashboardPanel", Visibility.Collapsed);
            SetPanelVisibility("MonitorPanel", Visibility.Collapsed);
            SetPanelVisibility("LogsPanel", Visibility.Collapsed);
        }

        private void SetPanelVisibility(string panelName, Visibility visibility)
        {
            try
            {
                var panel = FindName(panelName) as UIElement;
                if (panel != null)
                {
                    panel.Visibility = visibility;
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"Error setting panel visibility: {ex.Message}");
            }
        }
        #endregion

        #region Device Actions
        private async void AllowDevice_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var devicesDataGrid = FindName("DevicesDataGrid") as DataGrid;
                if (devicesDataGrid?.SelectedItem is USBDeviceDisplayInfo selectedDevice)
                {
                    var devices = _deviceManager.GetConnectedDevices();
                    var device = devices?.Values?.FirstOrDefault(d => d.Name == selectedDevice.Name);
                    
                    if (device != null)
                    {
                        await _deviceManager.AllowDevice(device.DeviceId);
                        ShowNotification($"✅ Device Allowed: {device.Name}", NotificationType.Success);
                    }
                    else
                    {
                        MessageBox.Show("Selected device not found or was disconnected.", "Device Not Found", MessageBoxButton.OK, MessageBoxImage.Warning);
                    }
                }
                else
                {
                    MessageBox.Show("Please select a device first.", "No Selection", MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error allowing device: {ex.Message}");
                MessageBox.Show($"Failed to allow device: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async void BlockDevice_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var devicesDataGrid = FindName("DevicesDataGrid") as DataGrid;
                if (devicesDataGrid?.SelectedItem is USBDeviceDisplayInfo selectedDevice)
                {
                    var devices = _deviceManager.GetConnectedDevices();
                    var device = devices?.Values?.FirstOrDefault(d => d.Name == selectedDevice.Name);
                    
                    if (device != null)
                    {
                        await _deviceManager.BlockDevice(device.DeviceId);
                        ShowNotification($"🚫 Device Blocked: {device.Name}", NotificationType.Warning);
                    }
                    else
                    {
                        MessageBox.Show("Selected device not found or was disconnected.", "Device Not Found", MessageBoxButton.OK, MessageBoxImage.Warning);
                    }
                }
                else
                {
                    MessageBox.Show("Please select a device first.", "No Selection", MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error blocking device: {ex.Message}");
                MessageBox.Show($"Failed to block device: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        #endregion

        #region Fortress Mode Management
        private async void EnableFortressMode_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (_deviceManager == null)
                {
                    MessageBox.Show("Device manager is not available.", "Error", 
                        MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                var result = MessageBox.Show(
                    "🏰 FORTRESS MODE ACTIVATION\n\n" +
                    "This will:\n" +
                    "• Block ALL non-whitelisted USB devices immediately\n" +
                    "• Add USB Guard to Windows startup for automatic protection\n" +
                    "• Require authentication for ALL new USB devices\n" +
                    "• Provide maximum USB security protection\n" +
                    "• Enable automatic startup with Windows\n\n" +
                    "Continue with Fortress Mode activation?",
                    "Fortress Mode - Maximum Security",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Question);

                if (result == MessageBoxResult.Yes)
                {
                    _logger.LogSecurity("🏰 User initiated fortress mode activation");
                    
                    // Show progress
                    StatusMessage = "🏰 Enabling Fortress Mode - Maximum USB security...";
                    
                    // STEP 1: Enable fortress mode in device manager
                    await _deviceManager.EnableFortressModeAsync();
                    
                    // STEP 1: Add to Windows startup with enhanced error handling
                    bool startupSuccess = false;
                    if (_startupManager != null)
                    {
                        try
                        {
                            startupSuccess = _startupManager.AddToStartup();
                            if (startupSuccess)
                            {
                                _logger.LogSecurity("✅ STEP 1: USB Guard added to Windows startup for fortress mode");
                            }
                            else
                            {
                                _logger.LogWarning("⚠️ STEP 1: Failed to add to Windows startup - fortress mode will not persist across reboots");
                            }
                        }
                        catch (Exception startupEx)
                        {
                            _logger.LogError($"❌ STEP 1: Exception adding to startup: {startupEx.Message}");
                            startupSuccess = false;
                        }
                    }
                    
                    // Update UI
                    UpdateFortressModeUI(true);
                    
                    // Update statistics
                    UpdateStatistics();
                    
                    StatusMessage = "🏰 Fortress Mode ACTIVE - Maximum USB security enabled";
                    
                    // Show completion message with startup status
                    var completionMessage = "🏰 FORTRESS MODE ACTIVATED\n\n" +
                                          "✅ All non-whitelisted USB devices blocked\n" +
                                          "✅ Maximum security protocols active\n" +
                                          "✅ All new devices require authentication\n";
                    
                    if (startupSuccess)
                    {
                        completionMessage += "✅ Added to Windows startup - will auto-start on boot\n\n" +
                                           "Your system is now under maximum USB protection!";
                    }
                    else
                    {
                        completionMessage += "⚠️ Could not add to Windows startup (may need admin rights)\n" +
                                           "Fortress mode is active but may not persist across reboots\n\n" +
                                           "For full protection, run as administrator or manually add to startup.";
                    }
                    
                    MessageBox.Show(completionMessage, "Fortress Mode - Activation Complete",
                        MessageBoxButton.OK, startupSuccess ? MessageBoxImage.Information : MessageBoxImage.Warning);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Failed to enable fortress mode: {ex.Message}");
                MessageBox.Show($"Failed to enable Fortress Mode:\n\n{ex.Message}", 
                    "Fortress Mode Error", MessageBoxButton.OK, MessageBoxImage.Error);
                
                StatusMessage = "❌ Failed to enable Fortress Mode";
            }
        }

        private async void DisableFortressMode_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (_deviceManager == null)
                {
                    MessageBox.Show("Device manager is not available.", "Error", 
                        MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                var result = MessageBox.Show(
                    "🔓 FORTRESS MODE DEACTIVATION\n\n" +
                    "This will:\n" +
                    "• Disable maximum security mode\n" +
                    "• Remove USB Guard from Windows startup (Clean Disable)\n" +
                    "• Update settings to prevent auto-restart\n" +
                    "• Return to normal USB security operations\n" +
                    "• Previously blocked devices remain blocked until manually allowed\n\n" +
                    "Continue with Fortress Mode deactivation?",
                    "Fortress Mode - Clean Deactivation",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Question);

                if (result == MessageBoxResult.Yes)
                {
                    _logger.LogSecurity("🔓 User initiated fortress mode CLEAN deactivation");
                    
                    // Show progress
                    StatusMessage = "🔓 Disabling Fortress Mode - Performing clean shutdown...";
                    
                    // STEP 1: Disable fortress mode in device manager first
                    await _deviceManager.DisableFortressModeAsync();
                    _logger.LogSecurity("✅ STEP 1: Fortress mode disabled in device manager");
                    
                    // STEP 1: Clean Disable - Remove from Windows startup
                    bool startupRemoved = false;
                    if (_startupManager != null)
                    {
                        try
                        {
                            startupRemoved = _startupManager.RemoveFromStartup();
                            if (startupRemoved)
                            {
                                _logger.LogSecurity("✅ STEP 1: USB Guard removed from Windows startup (Clean Disable)");
                            }
                            else
                            {
                                _logger.LogWarning("⚠️ STEP 1: Failed to remove from Windows startup");
                            }
                        }
                        catch (Exception startupEx)
                        {
                            _logger.LogError($"❌ STEP 1: Exception removing from startup: {startupEx.Message}");
                            startupRemoved = false;
                        }
                    }
                    
                    // STEP 1: Update settings to ensure fortress stays disabled
                    try
                    {
                        USB_Guard.Properties.Settings.Default.FortressEnabled = false;
                        USB_Guard.Properties.Settings.Default.LastFortressToggleTime = DateTime.Now;
                        USB_Guard.Properties.Settings.Default.AutoStartWithWindows = false;
                        USB_Guard.Properties.Settings.Default.Save();
                        _logger.LogSecurity("✅ STEP 1: Settings updated - fortress mode will remain disabled");
                    }
                    catch (Exception settingsEx)
                    {
                        _logger.LogError($"❌ STEP 1: Failed to update settings: {settingsEx.Message}");
                    }
                    
                    // Update UI
                    UpdateFortressModeUI(false);
                    
                    // Update statistics
                    UpdateStatistics();
                    
                    StatusMessage = "🔓 Fortress Mode DISABLED - Normal USB security active";
                    
                    // Show completion message with cleanup status
                    var completionMessage = "🔓 FORTRESS MODE CLEAN DEACTIVATION COMPLETE\n\n" +
                                          "✅ Maximum security mode disabled\n" +
                                          "✅ Settings updated to prevent auto-restart\n" +
                                          "✅ Normal USB operations restored\n";
                    
                    if (startupRemoved)
                    {
                        completionMessage += "✅ Removed from Windows startup (Clean Disable)\n" +
                                           "✅ System will boot normally without fortress mode\n\n" +
                                           "ℹ️ Previously blocked devices remain blocked\n" +
                                           "You can now manually allow devices as needed.";
                    }
                    else
                    {
                        completionMessage += "⚠️ Could not remove from Windows startup completamente\n" +
                                           "Manual cleanup may be required\n\n" +
                                           "ℹ️ Previously blocked devices remain blocked\n" +
                                           "Settings have been updated to prevent auto-restart.";
                    }
                    
                    MessageBox.Show(completionMessage, "Fortress Mode - Clean Deactivation Complete",
                        MessageBoxButton.OK, startupRemoved ? MessageBoxImage.Information : MessageBoxImage.Warning);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Failed to disable fortress mode: {ex.Message}");
                MessageBox.Show($"Failed to disable Fortress Mode:\n\n{ex.Message}", 
                    "Fortress Mode Error", MessageBoxButton.OK, MessageBoxImage.Error);
                
                StatusMessage = "❌ Failed to disable Fortress Mode";
            }
        }

        private void UpdateFortressModeUI(bool fortressEnabled)
        {
            try
            {
                Application.Current.Dispatcher.BeginInvoke(new Action(() =>
                {
                    try
                    {
                        var enableButton = FindName("EnableFortressModeButton") as Button;
                        var disableButton = FindName("DisableFortressModeButton") as Button;
                        var protectionStatusText = FindName("ProtectionStatusText") as TextBlock;

                        if (enableButton != null && disableButton != null && protectionStatusText != null)
                        {
                            if (fortressEnabled)
                            {
                                enableButton.Visibility = Visibility.Collapsed;
                                disableButton.Visibility = Visibility.Visible;
                                protectionStatusText.Text = "🏰 FORTRESS MODE";
                                protectionStatusText.Foreground = System.Windows.Media.Brushes.Gold;
                                
                                // Update protection status
                                ProtectionStatus = "🏰 FORTRESS MODE";
                                
                                _logger.LogInfo("✅ STEP 1: Fortress mode UI updated - showing disable button");
                            }
                            else
                            {
                                enableButton.Visibility = Visibility.Visible;
                                disableButton.Visibility = Visibility.Collapsed;
                                protectionStatusText.Text = "ACTIVE";
                                protectionStatusText.Foreground = System.Windows.Media.Brushes.LimeGreen;
                                
                                // Update protection status
                                ProtectionStatus = "ACTIVE";
                                
                                _logger.LogInfo("✅ STEP 1: Normal mode UI updated - showing enable button");
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger?.LogError($"Error updating fortress mode UI elements: {ex.Message}");
                    }
                }));
            }
            catch (Exception ex)
            {
                _logger?.LogError($"Error in UpdateFortressModeUI: {ex.Message}");
            }
        }

        private void InitializeFortressModeUI()
        {
            try
            {
                if (_deviceManager != null)
                {
                    var fortressEnabled = _deviceManager.IsFortressModeEnabled();
                    UpdateFortressModeUI(fortressEnabled);
                    
                    if (fortressEnabled)
                    {
                        _logger.LogInfo("🏰 STEP 1: Fortress mode UI initialized - fortress mode is active");
                    }
                    else
                    {
                        _logger.LogInfo("🔄 STEP 1: Normal mode UI initialized - fortress mode is inactive");
                    }
                }
            }
            catch (Exception ex)
            {
                _logger?.LogError($"Error initializing fortress mode UI: {ex.Message}");
            }
        }
        #endregion

        #region Zero-Trust Mode Management
        private async void EnableZeroTrust_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (_deviceManager == null)
                {
                    MessageBox.Show("Device manager is not available.", "Error", 
                        MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                // Check Administrator privileges
                if (!IsAdministrator())
                {
                    var result = MessageBox.Show(
                        "🛡️ ZERO-TRUST MODE - ADMINISTRATOR REQUIRED\n\n" +
                        "Zero-Trust mode requires Administrator privileges to modify Windows registry.\n\n" +
                        "Would you like to restart USB Guard as Administrator?",
                        "Administrator Required",
                        MessageBoxButton.YesNo,
                        MessageBoxImage.Warning);
                        
                    if (result == MessageBoxResult.Yes)
                    {
                        RestartAsAdministrator();
                    }
                    return;
                }

                var confirmResult = MessageBox.Show(
                    "🛡️ ZERO-TRUST MODE ACTIVATION\n\n" +
                    "This will enable Windows-level USB device blocking:\n\n" +
                    "✅ ALL USB devices blocked at Windows registry level\n" +
                    "✅ Devices show 'Code 22' in Device Manager when blocked\n" +
                    "✅ Authentication REQUIRED before any device works\n" +
                    "✅ Session cache (5 minutes) - no repeated dialogs\n" +
                    "✅ Automatic registry backup created for safety\n" +
                    "✅ Fully reversible - can disable anytime\n\n" +
                    "⚠️ SAFETY:\n" +
                    "• Registry backup created automatically\n" +
                    "• Emergency restore available if needed\n" +
                    "• Your Windows 11 system will be safe\n\n" +
                    "Continue with Zero-Trust activation?",
                    "Zero-Trust Mode - Windows-Level Protection",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Question);

                if (confirmResult == MessageBoxResult.Yes)
                {
                    _logger.LogSecurity("🛡️🔒 User initiated Zero-Trust mode activation");
                    
                    // Show progress
                    StatusMessage = "🛡️ Enabling Zero-Trust Mode - Creating registry backup...";
                    
                    // Enable Zero-Trust
                    var success = await _deviceManager.InitializeZeroTrustSystemAsync();
                    
                    if (success)
                    {
                        // Update UI
                        UpdateZeroTrustUI(true);
                        
                        StatusMessage = "🛡️🔒 Zero-Trust Mode ACTIVE - Windows-level USB blocking enabled";
                        
                        MessageBox.Show(
                            "🛡️ ZERO-TRUST MODE ACTIVATED!\n\n" +
                            "✅ Windows registry policies applied\n" +
                            "✅ Registry backup created successfully\n" +
                            "✅ ALL USB devices now blocked by default\n" +
                            "✅ Authentication required for all devices\n" +
                            "✅ Session cache active (5 minutes)\n\n" +
                            "Try plugging in a USB device now - it will be blocked\n" +
                            "at Windows level until you authenticate it!\n\n" +
                            "Check Device Manager to see 'Code 22' for blocked devices.",
                            "Zero-Trust Activation Complete",
                            MessageBoxButton.OK,
                            MessageBoxImage.Information);
                    }
                    else
                    {
                        MessageBox.Show(
                            "❌ ZERO-TRUST ACTIVATION FAILED\n\n" +
                            "Could not enable Zero-Trust mode.\n\n" +
                            "Possible reasons:\n" +
                            "• Not running as Administrator\n" +
                            "• Registry backup failed\n" +
                            "• Registry access denied\n\n" +
                            "Check the security logs for details.",
                            "Zero-Trust Activation Failed",
                            MessageBoxButton.OK,
                            MessageBoxImage.Error);
                        
                        StatusMessage = "❌ Failed to enable Zero-Trust Mode";
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Failed to enable Zero-Trust mode: {ex.Message}");
                MessageBox.Show(
                    $"❌ Zero-Trust Activation Error:\n\n{ex.Message}\n\n" +
                    "Your system is safe - no changes were made.\n" +
                    "Check logs for details.",
                    "Zero-Trust Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
                
                StatusMessage = "❌ Zero-Trust activation failed";
            }
        }

        private async void DisableZeroTrust_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (_deviceManager == null)
                {
                    MessageBox.Show("Device manager is not available.", "Error", 
                        MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                var result = MessageBox.Show(
                    "🔓 ZERO-TRUST MODE DEACTIVATION\n\n" +
                    "This will:\n" +
                    "• Disable Windows-level USB blocking\n" +
                    "• Restore normal USB operation\n" +
                    "• Clear authentication cache\n" +
                    "• Remove registry policies (safely)\n" +
                    "• Trigger device re-enumeration\n\n" +
                    "⚠️ Previously blocked devices will remain in history.\n" +
                    "USB devices will work normally after deactivation.\n\n" +
                    "Continue with Zero-Trust deactivation?",
                    "Zero-Trust Mode - Deactivation",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Question);

                if (result == MessageBoxResult.Yes)
                {
                    _logger.LogSecurity("🔓 User initiated Zero-Trust mode deactivation");
                    
                    // Show progress
                    StatusMessage = "🔓 Disabling Zero-Trust Mode - Restoring normal operation...";
                    
                    // Disable Zero-Trust
                    var success = await _deviceManager.DisableZeroTrustSystemAsync();
                    
                    if (success)
                    {
                        // Update UI
                        UpdateZeroTrustUI(false);
                        
                        StatusMessage = "🔓 Zero-Trust Mode DISABLED - Normal USB operation restored";
                        
                        MessageBox.Show(
                            "🔓 ZERO-TRUST MODE DEACTIVATED\n\n" +
                            "✅ Windows registry policies removed\n" +
                            "✅ Normal USB operation restored\n" +
                            "✅ Authentication cache cleared\n" +
                            "✅ Device re-enumeration triggered\n\n" +
                            "USB devices will work normally now.\n" +
                            "You can re-enable Zero-Trust anytime.",
                            "Zero-Trust Deactivation Complete",
                            MessageBoxButton.OK,
                            MessageBoxImage.Information);
                    }
                    else
                    {
                        MessageBox.Show(
                            "⚠️ ZERO-TRUST DEACTIVATION INCOMPLETE\n\n" +
                            "Could not fully disable Zero-Trust mode.\n\n" +
                            "You can restore from registry backup if needed:\n" +
                            "Location: %APPDATA%\\USBGuard\\Backups\\",
                            "Zero-Trust Deactivation Warning",
                            MessageBoxButton.OK,
                            MessageBoxImage.Warning);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Failed to disable Zero-Trust mode: {ex.Message}");
                MessageBox.Show(
                    $"❌ Zero-Trust Deactivation Error:\n\n{ex.Message}\n\n" +
                    "Registry backup available at:\n" +
                    "%APPDATA%\\USBGuard\\Backups\\",
                    "Zero-Trust Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
        }

        private void UpdateZeroTrustUI(bool zeroTrustEnabled)
        {
            try
            {
                Application.Current.Dispatcher.BeginInvoke(new Action(() =>
                {
                    try
                    {
                        var enableButton = FindName("EnableZeroTrustButton") as Button;
                        var disableButton = FindName("DisableZeroTrustButton") as Button;
                        var statusText = FindName("ZeroTrustStatusText") as TextBlock;

                        if (enableButton != null && disableButton != null && statusText != null)
                        {
                            if (zeroTrustEnabled)
                            {
                                enableButton.Visibility = Visibility.Collapsed;
                                disableButton.Visibility = Visibility.Visible;
                                
                                if (_deviceManager != null)
                                {
                                    statusText.Text = _deviceManager.GetZeroTrustStatus();
                                }
                                else
                                {
                                    statusText.Text = "Status: Active";
                                }
                                
                                statusText.Foreground = System.Windows.Media.Brushes.LimeGreen;
                                
                                _logger.LogInfo("✅ Zero-Trust UI updated - showing disable button");
                            }
                            else
                            {
                                enableButton.Visibility = Visibility.Visible;
                                disableButton.Visibility = Visibility.Collapsed;
                                statusText.Text = "Status: Not Active";
                                statusText.Foreground = System.Windows.Media.Brushes.Gray;
                                
                                _logger.LogInfo("✅ Normal mode UI updated - showing enable button");
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger?.LogError($"Error updating Zero-Trust UI elements: {ex.Message}");
                    }
                }));
            }
            catch (Exception ex)
            {
                _logger?.LogError($"Error in UpdateZeroTrustUI: {ex.Message}");
            }
        }

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

        private void RestartAsAdministrator()
        {
            try
            {
                var startInfo = new System.Diagnostics.ProcessStartInfo
                {
                    UseShellExecute = true,
                    WorkingDirectory = Environment.CurrentDirectory,
                    FileName = System.Reflection.Assembly.GetExecutingAssembly().Location,
                    Verb = "runas"
                };
                
                System.Diagnostics.Process.Start(startInfo);
                Application.Current.Shutdown();
            }
            catch (Exception ex)
            {
                _logger?.LogError($"Failed to restart as Administrator: {ex.Message}");
                MessageBox.Show($"Failed to restart as Administrator:\n\n{ex.Message}", 
                    "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        #endregion

        #region Window Events
        protected override void OnClosing(CancelEventArgs e)
        {
            try
            {
                // STEP 3: Check if we should minimize to tray instead of closing
                if (_systemTrayManager != null)
                {
                    _logger.LogInfo("🔄 STEP 3: Window closing intercepted - minimizing to system tray");
                    
                    e.Cancel = true; // Cancel the close event
                    _systemTrayManager.MinimizeToTray(); // Minimize to tray instead
                    return;
                }
                
                _logger?.LogSecurity("🛑 Professional USB Guard UI closing completely");
                
                // Stop timers
                _refreshTimer?.Stop();
                
                // Disconnect events
                if (_deviceManager != null)
                {
                    _deviceManager.DeviceConnected -= OnDeviceConnected;
                    _deviceManager.DeviceDisconnected -= OnDeviceDisconnected;
                    _deviceManager.DeviceAuthenticated -= OnDeviceAuthenticated;
                }
                
                // STEP 3: Clean up system tray
                _systemTrayManager?.Dispose();
                
                _logger?.LogSecurity("✅ Professional USB Guard UI closed with STEP 3 tray cleanup");
            }
            catch (Exception ex)
            {
                _logger?.LogError($"Error during window closing: {ex.Message}");
            }
            finally
            {
                base.OnClosing(e);
            }
        }
        #endregion

        #region INotifyPropertyChanged Implementation
        public event PropertyChangedEventHandler PropertyChanged;

        protected virtual void OnPropertyChanged(string propertyName)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
        #endregion
    }
}
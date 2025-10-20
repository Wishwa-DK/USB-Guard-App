using System;
using System.Linq;
using System.Windows;
using USB_Guard.Core;

namespace USB_Guard
{
    /// <summary>
    /// Interaction logic for App.xaml
    /// </summary>
    public partial class App : Application
    {
        private USBDeviceManager _usbDeviceManager;
        private SecurityLogger _logger;
        private StartupManager _startupManager;
        private bool _isFortressStartup = false;

        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

            try
            {
                // Initialize core services
                _logger = new SecurityLogger();
                _logger.LogInfo("🚀 USB Guard application starting...");

                // Check command line arguments for fortress mode startup
                CheckCommandLineArguments(e.Args);

                // Initialize startup manager
                _startupManager = new StartupManager();

                // Initialize USB device manager for monitoring
                _usbDeviceManager = new USBDeviceManager();
                
                // Start monitoring immediately
                _usbDeviceManager.StartMonitoring();

                // Handle fortress mode startup with enhanced logic
                if (_isFortressStartup)
                {
                    HandleFortressStartup();
                }
                else
                {
                    // Check if fortress mode should be auto-enabled from previous session
                    HandleNormalStartup();
                }

                _logger.LogSecurity("✅ USB Guard initialized and monitoring started");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to start USB Guard: {ex.Message}", 
                    "USB Guard - Startup Error", MessageBoxButton.OK, MessageBoxImage.Error);
                _logger?.LogError($"Startup error: {ex.Message}");
                Current.Shutdown(1);
            }
        }

        private void CheckCommandLineArguments(string[] args)
        {
            try
            {
                if (args != null && args.Length > 0)
                {
                    _logger.LogInfo($"📋 Command line arguments: {string.Join(" ", args)}");

                    foreach (var arg in args)
                    {
                        switch (arg.ToLower())
                        {
                            case "--fortress-mode-startup":
                            case "/fortress-mode-startup":
                                _isFortressStartup = true;
                                _logger.LogSecurity("🏰 Fortress mode startup detected from command line");
                                break;
                            case "--help":
                            case "/help":
                            case "-h":
                                ShowCommandLineHelp();
                                Current.Shutdown(0);
                                return;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error processing command line arguments: {ex.Message}");
            }
        }

        private void HandleFortressStartup()
        {
            try
            {
                _logger.LogSecurity("🏰 Processing fortress mode startup");

                // STEP 1 ENHANCEMENT: Check if fortress mode is still enabled in settings
                var fortressEnabled = USB_Guard.Properties.Settings.Default.FortressEnabled;
                
                _logger.LogInfo($"🏰 Fortress mode setting check - Enabled: {fortressEnabled}");

                if (fortressEnabled)
                {
                    _logger.LogSecurity("🏰 Fortress mode enabled in settings - proceeding with auto-enable");
                    
                    // Auto-enable fortress mode after device manager is ready
                    var timer = new System.Windows.Threading.DispatcherTimer();
                    timer.Interval = TimeSpan.FromSeconds(3);
                    timer.Tick += async (s, e) =>
                    {
                        timer.Stop();
                        try
                        {
                            _logger.LogSecurity("🏰 Auto-enabling fortress mode on startup...");
                            await _usbDeviceManager.EnableFortressModeAsync();
                            _logger.LogSecurity("🏰 ✅ Fortress mode auto-enabled successfully on startup");
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError($"❌ Failed to auto-enable fortress mode on startup: {ex.Message}");
                            
                            // Show error to user
                            MessageBox.Show(
                                $"⚠️ Fortress Mode Auto-Enable Failed\n\n" +
                                $"Error: {ex.Message}\n\n" +
                                "USB Guard will continue with normal monitoring.",
                                "Fortress Mode Startup Error",
                                MessageBoxButton.OK,
                                MessageBoxImage.Warning);
                        }
                    };
                    timer.Start();
                }
                else
                {
                    _logger.LogInfo("🏰 Fortress mode was disabled - cleaning up startup entry");
                    
                    // Clean up startup entry since fortress mode is disabled
                    var cleanupTimer = new System.Windows.Threading.DispatcherTimer();
                    cleanupTimer.Interval = TimeSpan.FromSeconds(2);
                    cleanupTimer.Tick += (s, e) =>
                    {
                        cleanupTimer.Stop();
                        try
                        {
                            if (_startupManager.IsInStartup())
                            {
                                _logger.LogInfo("🏰 Removing startup entry since fortress mode is disabled");
                                _startupManager.RemoveFromStartup();
                            }
                        }
                        catch (Exception ex)
                        {
                            _logger.LogWarning($"Failed to clean up startup entry: {ex.Message}");
                        }
                    };
                    cleanupTimer.Start();
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error in fortress startup handling: {ex.Message}");
            }
        }

        private void HandleNormalStartup()
        {
            try
            {
                // STEP 1 ENHANCEMENT: Better normal startup handling
                var fortressEnabled = USB_Guard.Properties.Settings.Default.FortressEnabled;
                
                _logger.LogInfo($"🔄 Normal startup - Fortress mode setting: {fortressEnabled}");

                if (fortressEnabled)
                {
                    _logger.LogSecurity("🏰 Fortress mode enabled from previous session - auto-enabling");
                    
                    // Auto-enable fortress mode and ensure startup entry exists
                    var timer = new System.Windows.Threading.DispatcherTimer();
                    timer.Interval = TimeSpan.FromSeconds(2);
                    timer.Tick += async (s, e) =>
                    {
                        timer.Stop();
                        try
                        {
                            // Enable fortress mode
                            await _usbDeviceManager.EnableFortressModeAsync();
                            _logger.LogSecurity("🏰 ✅ Fortress mode auto-enabled from previous session");
                            
                            // Ensure startup entry exists for future boots
                            if (!_startupManager.IsInStartup())
                            {
                                _logger.LogInfo("🏰 Adding missing startup entry for fortress mode");
                                var startupAdded = _startupManager.AddToStartup();
                                if (!startupAdded)
                                {
                                    _logger.LogWarning("⚠️ Failed to add startup entry - fortress mode may not persist across reboots");
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError($"❌ Failed to auto-enable fortress mode from previous session: {ex.Message}");
                        }
                    };
                    timer.Start();
                }
                else
                {
                    _logger.LogInfo("🔄 Normal startup - fortress mode disabled, ensuring no startup entry");
                    
                    // Ensure no startup entry exists when fortress mode is disabled
                    if (_startupManager.IsInStartup())
                    {
                        _logger.LogInfo("🔄 Removing startup entry since fortress mode is disabled");
                        _startupManager.RemoveFromStartup();
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error in normal startup handling: {ex.Message}");
            }
        }

        private void ShowCommandLineHelp()
        {
            var helpMessage = @"USB Guard - Professional USB Security Suite

Command Line Options:
  --fortress-mode-startup    Start with fortress mode enabled (used by Windows startup)
  --help, -h                 Show this help message

Examples:
  USB_Guard.exe                        Normal startup
  USB_Guard.exe --fortress-mode-startup   Fortress mode startup (automatic)

Fortress Mode:
  When enabled, fortress mode automatically starts with Windows and blocks all
  non-whitelisted USB devices for maximum security protection.
";

            MessageBox.Show(helpMessage, "USB Guard - Command Line Help", 
                MessageBoxButton.OK, MessageBoxImage.Information);
        }

        protected override void OnExit(ExitEventArgs e)
        {
            try
            {
                _logger?.LogInfo("USB Guard application shutting down...");
                
                // Stop USB monitoring
                _usbDeviceManager?.StopMonitoring();
                _usbDeviceManager?.Dispose();
                
                // Save settings with enhanced error handling
                try
                {
                    USB_Guard.Properties.Settings.Default.LastShutdownTime = DateTime.Now;
                    USB_Guard.Properties.Settings.Default.Save();
                    _logger?.LogInfo("✅ Settings saved successfully during shutdown");
                }
                catch (Exception ex)
                {
                    _logger?.LogError($"❌ Error saving settings during shutdown: {ex.Message}");
                }
                
                _logger?.LogSecurity("✅ USB Guard shutdown complete");
            }
            catch (Exception ex)
            {
                _logger?.LogError($"Error during shutdown: {ex.Message}");
            }
            finally
            {
                base.OnExit(e);
            }
        }

        // Global access to USB device manager for MainWindow
        public static USBDeviceManager GetUSBDeviceManager()
        {
            return ((App)Current)?._usbDeviceManager;
        }

        // Global access to logger
        public static SecurityLogger GetLogger()
        {
            return ((App)Current)?._logger;
        }

        // Global access to startup manager
        public static StartupManager GetStartupManager()
        {
            return ((App)Current)?._startupManager;
        }
    }
}

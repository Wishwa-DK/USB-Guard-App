using System;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Forms;
using USB_Guard.Models;

namespace USB_Guard.Core
{
    /// <summary>
    /// System Tray Manager for USB Guard Professional
    /// Handles minimize to tray functionality
    /// </summary>
    public class SystemTrayManager : IDisposable
    {
        #region Private Fields
        private readonly SecurityLogger _logger;
        private readonly USBDeviceManager _deviceManager;
        private readonly StartupManager _startupManager;
        private NotifyIcon _notifyIcon;
        private ContextMenuStrip _trayContextMenu;
        private MainWindow _mainWindow;
        private bool _isDisposed = false;
        #endregion

        #region Constructor
        public SystemTrayManager(MainWindow mainWindow, USBDeviceManager deviceManager, StartupManager startupManager, SecurityLogger logger)
        {
            _mainWindow = mainWindow ?? throw new ArgumentNullException(nameof(mainWindow));
            _deviceManager = deviceManager ?? throw new ArgumentNullException(nameof(deviceManager));
            _startupManager = startupManager ?? throw new ArgumentNullException(nameof(startupManager));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            
            InitializeSystemTray();
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Minimize main window to system tray
        /// </summary>
        public void MinimizeToTray()
        {
            try
            {
                _logger.LogInfo("Minimizing to system tray - USB Guard will continue running in background");

                _mainWindow.Hide();
                _notifyIcon.Visible = true;

                // Show tray notification
                _notifyIcon.ShowBalloonTip(3000,
                    "USB Guard Professional",
                    "Application minimized to system tray.\nUSB monitoring continues in background.\nDouble-click tray icon to restore.",
                    ToolTipIcon.Info);

                _logger.LogSecurity("Successfully minimized to system tray - background monitoring active");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error minimizing to tray: {ex.Message}");
            }
        }

        /// <summary>
        /// Show main window from tray
        /// </summary>
        public void ShowMainWindowFromTray()
        {
            try
            {
                if (!_mainWindow.IsVisible)
                {
                    _mainWindow.Show();
                }

                if (_mainWindow.WindowState == WindowState.Minimized)
                {
                    _mainWindow.WindowState = WindowState.Normal;
                }

                _mainWindow.Activate();
                _mainWindow.Topmost = true;
                _mainWindow.Topmost = false;
                _mainWindow.Focus();

                _notifyIcon.Visible = false;

                _logger.LogInfo("Main window restored from system tray");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error showing main window from tray: {ex.Message}");
            }
        }

        /// <summary>
        /// Update tray menu when device status changes
        /// </summary>
        public void UpdateTrayContextMenu()
        {
            try
            {
                if (_trayContextMenu == null || _deviceManager == null) return;

                var fortressEnabled = _deviceManager.IsFortressModeEnabled();
                var connectedDeviceCount = _deviceManager.ConnectedDeviceCount;

                // Update tray icon tooltip
                var tooltipText = $"USB Guard Professional - {(fortressEnabled ? "FORTRESS MODE" : "ACTIVE")}\n" +
                                 $"Connected Devices: {connectedDeviceCount}\n" +
                                 "Double-click to show main window";
                _notifyIcon.Text = tooltipText.Length > 63 ? tooltipText.Substring(0, 60) + "..." : tooltipText;
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"Error updating tray context menu: {ex.Message}");
            }
        }
        #endregion

        #region Private Methods
        /// <summary>
        /// Initialize System Tray
        /// </summary>
        private void InitializeSystemTray()
        {
            try
            {
                _logger.LogInfo("Initializing Professional System Tray");

                // Create the NotifyIcon
                _notifyIcon = new NotifyIcon();
                _notifyIcon.Icon = System.Drawing.Icon.ExtractAssociatedIcon(System.Reflection.Assembly.GetExecutingAssembly().Location);
                _notifyIcon.Text = "USB Guard Professional - Ready";
                _notifyIcon.Visible = false; // Start hidden, show when minimized

                // Create context menu
                CreateTrayContextMenu();

                // Handle tray icon events
                _notifyIcon.DoubleClick += TrayIcon_DoubleClick;

                _logger.LogSecurity("Professional System Tray initialized successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error initializing system tray: {ex.Message}");
            }
        }

        /// <summary>
        /// Create simplified tray context menu with only essential options
        /// </summary>
        private void CreateTrayContextMenu()
        {
            try
            {
                _trayContextMenu = new ContextMenuStrip();
                _trayContextMenu.Name = "TrayContextMenu";

                // Show Main Window
                var showMainWindowItem = new ToolStripMenuItem("Show Main Window");
                showMainWindowItem.Font = new System.Drawing.Font(showMainWindowItem.Font, System.Drawing.FontStyle.Bold);
                showMainWindowItem.Click += ShowMainWindow_Click;
                _trayContextMenu.Items.Add(showMainWindowItem);

                _trayContextMenu.Items.Add(new ToolStripSeparator());

                // Exit USB Guard
                var exitItem = new ToolStripMenuItem("Exit USB Guard");
                exitItem.Click += TrayExit_Click;
                _trayContextMenu.Items.Add(exitItem);

                _notifyIcon.ContextMenuStrip = _trayContextMenu;

                _logger.LogInfo("Tray context menu created successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error creating tray context menu: {ex.Message}");
            }
        }
        #endregion

        #region Event Handlers
        private void TrayIcon_DoubleClick(object sender, EventArgs e)
        {
            try
            {
                _logger.LogInfo("User double-clicked tray icon - showing main window");
                ShowMainWindowFromTray();
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error handling tray double click: {ex.Message}");
            }
        }

        private void ShowMainWindow_Click(object sender, EventArgs e)
        {
            try
            {
                _logger.LogInfo("User clicked 'Show Main Window' from tray menu");
                ShowMainWindowFromTray();
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error in show main window: {ex.Message}");
            }
        }

        private void TrayExit_Click(object sender, EventArgs e)
        {
            try
            {
                _logger.LogSecurity("User initiated application exit from system tray");

                // Dispose tray icon first
                if (_notifyIcon != null)
                {
                    _notifyIcon.Visible = false;
                    _notifyIcon.Dispose();
                }

                // Gracefully shutdown the application
                System.Windows.Application.Current.Dispatcher.Invoke(() =>
                {
                    System.Windows.Application.Current.Shutdown();
                });
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error during tray exit: {ex.Message}");
                // Force exit if graceful shutdown fails
                Environment.Exit(0);
            }
        }
        #endregion

        #region IDisposable Implementation
        public void Dispose()
        {
            if (_isDisposed) return;

            try
            {
                if (_notifyIcon != null)
                {
                    _notifyIcon.Visible = false;
                    _notifyIcon.Dispose();
                    _notifyIcon = null;
                }

                if (_trayContextMenu != null)
                {
                    _trayContextMenu.Dispose();
                    _trayContextMenu = null;
                }

                _isDisposed = true;
                _logger?.LogInfo("SystemTrayManager disposed successfully");
            }
            catch (Exception ex)
            {
                _logger?.LogError($"Error disposing SystemTrayManager: {ex.Message}");
            }
        }
        #endregion
    }
}
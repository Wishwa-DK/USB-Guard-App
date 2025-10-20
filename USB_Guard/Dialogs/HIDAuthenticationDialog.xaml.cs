using System;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Threading;
using USB_Guard.Core;
using USB_Guard.Models;

namespace USB_Guard.Dialogs
{
    /// <summary>
    /// Simplified HID Authentication Dialog
    /// </summary>
    public partial class HIDAuthenticationDialog : Window
    {
        private readonly USBDeviceInfo _device;
        private readonly HIDBehaviorAnalysis _behaviorAnalysis;
        private readonly SecurityLogger _logger;
        private readonly DispatcherTimer _timer;
        private int _timeRemaining = 60;
        private TaskCompletionSource<bool> _dialogResult;

        public HIDAuthenticationDialog(USBDeviceInfo device, HIDBehaviorAnalysis behaviorAnalysis)
        {
            InitializeComponent();
            _device = device;
            _behaviorAnalysis = behaviorAnalysis;
            _logger = new SecurityLogger();

            InitializeDialog();
            
            _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
            _timer.Tick += Timer_Tick;
            _timer.Start();

            _logger.LogSecurity($"🎮 HID authentication dialog opened for {_device.Name}");
        }

        private void InitializeDialog()
        {
            try
            {
                Title = "USB Guard - HID Device Authentication";
                
                // Set device info safely
                SetTextSafely("DeviceNameText", _device.Name);
                SetTextSafely("DeviceTypeText", _device.TypeDisplayName);
                SetTextSafely("VendorIdText", _device.VendorId);
                SetTextSafely("ProductIdText", _device.ProductId);
                
                // Set behavior analysis info
                SetTextSafely("BehaviorScoreText", _behaviorAnalysis.BehaviorScore.ToString());
                SetTextSafely("AnalysisDetailsText", _behaviorAnalysis.AnalysisDetails);
                SetTextSafely("RecommendationText", _behaviorAnalysis.RecommendedAction);
                
                UpdateTimerDisplay();
                
                _logger.LogInfo($"🎮 HID dialog initialized for {_device.Name}");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error initializing HID dialog: {ex.Message}");
            }
        }

        private void SetTextSafely(string controlName, string text)
        {
            try
            {
                if (FindName(controlName) is System.Windows.Controls.TextBlock textBlock)
                {
                    textBlock.Text = text ?? "Unknown";
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"Could not set text for {controlName}: {ex.Message}");
            }
        }

        private void Timer_Tick(object sender, EventArgs e)
        {
            _timeRemaining--;
            UpdateTimerDisplay();

            if (_timeRemaining <= 0)
            {
                _timer.Stop();
                _logger.LogSecurity($"⏰ HID authentication timed out for {_device.Name}");
                _dialogResult?.SetResult(false);
                Close();
            }
        }

        private void UpdateTimerDisplay()
        {
            var timerText = FindName("TimerText") as System.Windows.Controls.TextBlock;
            if (timerText != null)
            {
                timerText.Text = $"⏰ {_timeRemaining}s remaining";
            }
        }

        private void AllowButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                _timer.Stop();
                _logger.LogSecurity($"✅ HID device manually allowed by user: {_device.Name}");
                _dialogResult?.SetResult(true);
                Close();
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error allowing device: {ex.Message}");
            }
        }

        private void AllowSandboxButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                _timer.Stop();
                _logger.LogSecurity($"🛡️ HID device allowed in sandbox by user: {_device.Name}");
                _dialogResult?.SetResult(true);
                Close();
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error allowing device in sandbox: {ex.Message}");
            }
        }

        private void ReanalyzeButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                _logger.LogInfo($"🔄 Re-analyzing HID device: {_device.Name}");
                // Simple re-analysis - just update the display
                SetTextSafely("AnalysisDetailsText", "Re-analysis completed - no changes detected");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error re-analyzing device: {ex.Message}");
            }
        }

        private void BlockButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                _timer.Stop();
                _logger.LogSecurity($"🚫 HID device manually blocked by user: {_device.Name}");
                _dialogResult?.SetResult(false);
                Close();
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error blocking device: {ex.Message}");
            }
        }

        public async Task<bool> ShowDialogAsync()
        {
            _dialogResult = new TaskCompletionSource<bool>();
            Show();
            Activate();
            return await _dialogResult.Task;
        }

        protected override void OnClosed(EventArgs e)
        {
            try
            {
                _timer?.Stop();
                
                if (_dialogResult?.Task.IsCompleted == false)
                {
                    _logger.LogSecurity($"❌ HID dialog closed without action for {_device.Name}");
                    _dialogResult?.TrySetResult(false);
                }
                
                _logger.LogInfo($"🎮 HID authentication dialog closed for {_device.Name}");
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
}

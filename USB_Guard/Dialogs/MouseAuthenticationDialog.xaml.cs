using System;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using USB_Guard.Core;
using USB_Guard.Models;

namespace USB_Guard.Dialogs
{
    /// <summary>
    /// Enhanced Mouse Authentication Dialog with detailed tracking
    /// </summary>
    public partial class MouseAuthenticationDialog : Window
    {
        private readonly USBDeviceInfo _device;
        private readonly SecurityLogger _logger;
        private readonly DispatcherTimer _timer;
        private int _timeRemaining = 30; // 30 seconds for authentication
        private TaskCompletionSource<bool> _dialogResult;
        
        // Detailed mouse verification tracking
        private int _leftClickCount = 0;
        private int _rightClickCount = 0;
        private int _scrollCount = 0;
        private int _moveCount = 0;
        private bool _testCompleted = false;
        
        // Updated requirements for each action
        private const int REQUIRED_LEFT_CLICKS = 2;  // Changed from 3
        private const int REQUIRED_RIGHT_CLICKS = 2; // Changed from 3
        private const int REQUIRED_SCROLLS = 3;      // Changed from 5
        private const int REQUIRED_MOVES = 5;        // Changed from 10
        
        // Auto-authentication tracking
        private bool _allTestsPassed = false;
        private bool _autoAuthenticating = false;

        public MouseAuthenticationDialog(USBDeviceInfo device)
        {
            try
            {
                InitializeComponent();
                _device = device ?? throw new ArgumentNullException(nameof(device));
                _logger = new SecurityLogger();

                InitializeDialog();
                
                _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
                _timer.Tick += Timer_Tick;
                _timer.Start();

                _logger.LogSecurity($"??? Mouse authentication dialog opened for {_device.Name}");
            }
            catch (Exception ex)
            {
                _logger?.LogError($"Mouse dialog initialization failed: {ex.Message}");
                _device = device ?? new USBDeviceInfo { Name = "Unknown Mouse", Type = USBDeviceType.Mouse };
            }
        }

        private void InitializeDialog()
        {
            try
            {
                Title = "USB Guard - Mouse Authentication";
                
                SetTextSafely("DeviceNameText", _device.Name);
                SetTextSafely("DeviceTypeText", _device.TypeDisplayName);
                SetTextSafely("VendorIdText", _device.VendorId);
                SetTextSafely("ProductIdText", _device.ProductId);
                
                // Set mouse-specific information
                var mouseType = DetectMouseType(_device);
                SetTextSafely("MouseButtonsText", "Standard (Left/Right/Scroll)");
                
                ShowDeviceContext();
                UpdateTimerDisplay();
                UpdateProgress();
                UpdateDetailedStatus();
                
                _logger.LogInfo($"??? Mouse dialog initialized for {_device.Name}");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error initializing mouse dialog: {ex.Message}");
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

        private void ShowDeviceContext()
        {
            try
            {
                if (_device.WasWhitelisted)
                {
                    _logger.LogInfo($"? Mouse {_device.Name} was previously trusted");
                    SetTextSafely("StatusText", "Previously trusted device - performing re-authentication");
                }
                else if (_device.WasBlacklisted)
                {
                    _logger.LogInfo($"?? Mouse {_device.Name} was previously blocked");
                    SetTextSafely("StatusText", "?? Previously blocked device - proceed with caution");
                    
                    // Show warning panel
                    var warningPanel = FindName("WarningPanel") as System.Windows.Controls.Border;
                    var warningText = FindName("WarningText") as System.Windows.Controls.TextBlock;
                    if (warningPanel != null && warningText != null)
                    {
                        warningPanel.Visibility = Visibility.Visible;
                        warningText.Text = "This mouse was previously blocked. Ensure this is a legitimate device before proceeding.";
                    }
                }
                else
                {
                    SetTextSafely("StatusText", "Unknown device - complete all tests to authenticate");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error showing context: {ex.Message}");
            }
        }

        private void Timer_Tick(object sender, EventArgs e)
        {
            _timeRemaining--;
            UpdateTimerDisplay();

            if (_timeRemaining <= 0)
            {
                _timer.Stop();
                _logger.LogSecurity($"?? Mouse authentication timed out for {_device.Name}");
                _dialogResult?.SetResult(false);
                Close();
            }
        }

        private void UpdateTimerDisplay()
        {
            var timerText = FindName("TimerText") as System.Windows.Controls.TextBlock;
            if (timerText != null)
            {
                var minutes = _timeRemaining / 60;
                var seconds = _timeRemaining % 60;
                timerText.Text = $"?? Time remaining: {minutes:D2}:{seconds:D2}";
                
                if (_timeRemaining <= 30)
                {
                    timerText.Foreground = Brushes.Red;
                }
                else if (_timeRemaining <= 60)
                {
                    timerText.Foreground = Brushes.Orange;
                }
                else
                {
                    timerText.Foreground = new SolidColorBrush(Color.FromRgb(211, 47, 47));
                }
            }
        }

        private void UpdateProgress()
        {
            try
            {
                var progressText = FindName("ProgressText") as System.Windows.Controls.TextBlock;
                var progressBar = FindName("ProgressBar") as System.Windows.Controls.ProgressBar;
                var allowButton = FindName("AllowButton") as System.Windows.Controls.Button;
                
                int completedTests = 0;
                if (_leftClickCount >= REQUIRED_LEFT_CLICKS) completedTests++;
                if (_rightClickCount >= REQUIRED_RIGHT_CLICKS) completedTests++;
                if (_scrollCount >= REQUIRED_SCROLLS) completedTests++;
                if (_moveCount >= REQUIRED_MOVES) completedTests++;
                
                if (progressText != null)
                {
                    progressText.Text = $"Progress: {completedTests}/4 tests completed";
                }
                
                if (progressBar != null)
                {
                    progressBar.Value = (completedTests / 4.0) * 100;
                }
                
                if (completedTests == 4 && !_testCompleted)
                {
                    _testCompleted = true;
                    
                    if (progressText != null)
                    {
                        progressText.Text = "? All mouse tests completed!";
                        progressText.Foreground = Brushes.Green;
                    }
                    
                    if (allowButton != null)
                    {
                        allowButton.IsEnabled = true;
                        allowButton.Background = new SolidColorBrush(Color.FromRgb(76, 175, 80));
                    }
                    
                    SetTextSafely("StatusText", "? Authentication complete! Click 'Authenticate Mouse' to approve.");
                    
                    _logger.LogSecurity($"? Mouse test completed for {_device.Name}");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error updating progress: {ex.Message}");
            }
        }

        private void UpdateDetailedStatus()
        {
            try
            {
                // Update left click status
                UpdateStatusIndicator("LeftClickStatus", "LeftClickCountText", 
                    _leftClickCount >= REQUIRED_LEFT_CLICKS, 
                    $"Clicks: {_leftClickCount}/{REQUIRED_LEFT_CLICKS}",
                    _leftClickCount >= REQUIRED_LEFT_CLICKS ? "? Left Click" : "? Left Click");

                // Update right click status
                UpdateStatusIndicator("RightClickStatus", "RightClickCountText", 
                    _rightClickCount >= REQUIRED_RIGHT_CLICKS, 
                    $"Clicks: {_rightClickCount}/{REQUIRED_RIGHT_CLICKS}",
                    _rightClickCount >= REQUIRED_RIGHT_CLICKS ? "? Right Click" : "? Right Click");

                // Update scroll status
                UpdateStatusIndicator("ScrollStatus", "ScrollCountText", 
                    _scrollCount >= REQUIRED_SCROLLS, 
                    $"Scrolls: {_scrollCount}/{REQUIRED_SCROLLS}",
                    _scrollCount >= REQUIRED_SCROLLS ? "? Scroll Wheel" : "? Scroll Wheel");

                // Update movement status
                UpdateStatusIndicator("MoveStatus", "MoveCountText", 
                    _moveCount >= REQUIRED_MOVES, 
                    $"Moves: {_moveCount}/{REQUIRED_MOVES}",
                    _moveCount >= REQUIRED_MOVES ? "? Movement" : "? Movement");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error updating detailed status: {ex.Message}");
            }
        }

        private void UpdateStatusIndicator(string statusName, string countName, bool isComplete, string countText, string statusText)
        {
            try
            {
                var statusControl = FindName(statusName) as System.Windows.Controls.TextBlock;
                var countControl = FindName(countName) as System.Windows.Controls.TextBlock;
                
                if (statusControl != null)
                {
                    statusControl.Text = statusText;
                    statusControl.Foreground = isComplete ? Brushes.Green : Brushes.Gray;
                }
                
                if (countControl != null)
                {
                    countControl.Text = countText;
                    countControl.Foreground = isComplete ? Brushes.Green : new SolidColorBrush(Color.FromRgb(102, 102, 102));
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error updating status indicator {statusName}: {ex.Message}");
            }
        }

        // Enhanced event handlers for detailed tracking

        private void TestArea_MouseMove(object sender, MouseEventArgs e)
        {
            try
            {
                if (!_testCompleted && _moveCount < REQUIRED_MOVES)
                {
                    _moveCount++;
                    UpdateProgress();
                    UpdateDetailedStatus();
                    
                    if (_moveCount == 1)
                    {
                        _logger.LogInfo($"🖱️ Mouse movement detected for {_device.Name}");
                    }
                    
                    // Check if all tests completed
                    if (_moveCount >= REQUIRED_MOVES)
                    {
                        CheckAllTestsCompletion();
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error in mouse move: {ex.Message}");
            }
        }

        private void TestArea_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            try
            {
                if (!_testCompleted && _leftClickCount < REQUIRED_LEFT_CLICKS)
                {
                    _leftClickCount++;
                    UpdateProgress();
                    UpdateDetailedStatus();
                    _logger.LogInfo($"🖱️ Left click {_leftClickCount} detected for {_device.Name}");
                    
                    // Check if all tests completed
                    if (_leftClickCount >= REQUIRED_LEFT_CLICKS)
                    {
                        CheckAllTestsCompletion();
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error in left click: {ex.Message}");
            }
        }

        private void TestArea_MouseRightButtonDown(object sender, MouseButtonEventArgs e)
        {
            try
            {
                if (!_testCompleted && _rightClickCount < REQUIRED_RIGHT_CLICKS)
                {
                    _rightClickCount++;
                    UpdateProgress();
                    UpdateDetailedStatus();
                    _logger.LogInfo($"🖱️ Right click {_rightClickCount} detected for {_device.Name}");
                    
                    // Check if all tests completed
                    if (_rightClickCount >= REQUIRED_RIGHT_CLICKS)
                    {
                        CheckAllTestsCompletion();
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error in right click: {ex.Message}");
            }
        }

        private void TestArea_MouseLeftButtonUp(object sender, MouseButtonEventArgs e)
        {
            // Optional: Handle mouse up events for additional verification
        }

        private void TestArea_MouseRightButtonUp(object sender, MouseButtonEventArgs e)
        {
            // Optional: Handle mouse up events for additional verification
        }

        private void TestScrollViewer_PreviewMouseWheel(object sender, MouseWheelEventArgs e)
        {
            try
            {
                if (!_testCompleted && _scrollCount < REQUIRED_SCROLLS)
                {
                    _scrollCount++;
                    UpdateProgress();
                    UpdateDetailedStatus();
                    _logger.LogInfo($"🖱️ Scroll {_scrollCount} detected for {_device.Name} (Delta: {e.Delta})");
                    
                    // Check if all tests completed
                    if (_scrollCount >= REQUIRED_SCROLLS)
                    {
                        CheckAllTestsCompletion();
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error in mouse wheel: {ex.Message}");
            }
        }

        private void AllowButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                _timer.Stop();
                
                if (_testCompleted)
                {
                    _logger.LogSecurity($"? Mouse authentication successful for {_device.Name}");
                    _dialogResult?.SetResult(true);
                }
                else
                {
                    _logger.LogSecurity($"? Mouse authentication failed - test incomplete for {_device.Name}");
                    
                    // Show error
                    var errorPanel = FindName("ErrorPanel") as System.Windows.Controls.Border;
                    var errorText = FindName("ErrorText") as System.Windows.Controls.TextBlock;
                    if (errorPanel != null && errorText != null)
                    {
                        errorPanel.Visibility = Visibility.Visible;
                        errorText.Text = "Cannot authenticate: Please complete all required tests first.";
                    }
                    
                    _timer.Start(); // Restart timer
                    return;
                }
                
                Close();
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error allowing device: {ex.Message}");
            }
        }

        private void BlockButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                _timer.Stop();
                _logger.LogSecurity($"?? Mouse manually blocked by user: {_device.Name}");
                _dialogResult?.SetResult(false);
                Close();
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error blocking device: {ex.Message}");
            }
        }

        private void ResetButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                _leftClickCount = 0;
                _rightClickCount = 0;
                _scrollCount = 0;
                _moveCount = 0;
                _testCompleted = false;
                
                UpdateProgress();
                UpdateDetailedStatus();
                
                var allowButton = FindName("AllowButton") as System.Windows.Controls.Button;
                if (allowButton != null)
                {
                    allowButton.IsEnabled = false;
                    allowButton.Background = new SolidColorBrush(Color.FromRgb(204, 204, 204));
                }
                
                // Hide error panel
                var errorPanel = FindName("ErrorPanel") as System.Windows.Controls.Border;
                if (errorPanel != null)
                {
                    errorPanel.Visibility = Visibility.Collapsed;
                }
                
                SetTextSafely("StatusText", "Test reset - use the new mouse to perform all required actions");
                
                _logger.LogInfo($"🔄 Mouse test reset for {_device.Name}");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error resetting test: {ex.Message}");
            }
        }

        /// <summary>
        /// Check if all mouse tests are completed and trigger auto-authentication
        /// </summary>
        private void CheckAllTestsCompletion()
        {
            try
            {
                // Check if ALL requirements met
                bool movementComplete = (_moveCount >= REQUIRED_MOVES);
                bool scrollComplete = (_scrollCount >= REQUIRED_SCROLLS);
                bool leftClickComplete = (_leftClickCount >= REQUIRED_LEFT_CLICKS);
                bool rightClickComplete = (_rightClickCount >= REQUIRED_RIGHT_CLICKS);
                
                if (movementComplete && scrollComplete && leftClickComplete && rightClickComplete && !_allTestsPassed)
                {
                    // ALL TESTS PASSED
                    _allTestsPassed = true;
                    _testCompleted = true;
                    
                    // Stop timer
                    _timer.Stop();
                    
                    // Log success
                    _logger.LogSecurity($"✅ Mouse authentication tests completed for {_device.Name}");
                    
                    // Update UI
                    UpdateUIForSuccess();
                    
                    // Auto-authenticate after 1 second delay (show success message)
                    Task.Delay(1000).ContinueWith(_ => 
                    {
                        Dispatcher.Invoke(() => AutoAuthenticate());
                    });
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error checking test completion: {ex.Message}");
            }
        }

        /// <summary>
        /// Update UI to show success when all tests pass
        /// </summary>
        private void UpdateUIForSuccess()
        {
            try
            {
                // Update status text
                SetTextSafely("StatusText", "✅ ALL TESTS PASSED");
                
                // Change status text color to green
                var statusText = FindName("StatusText") as System.Windows.Controls.TextBlock;
                if (statusText != null)
                {
                    statusText.Foreground = Brushes.Green;
                    statusText.FontWeight = FontWeights.Bold;
                }
                
                // Update progress text
                var progressText = FindName("ProgressText") as System.Windows.Controls.TextBlock;
                if (progressText != null)
                {
                    progressText.Text = "✅ All mouse tests completed!";
                    progressText.Foreground = Brushes.Green;
                }
                
                // Show authenticating message
                var instructionText = FindName("TestInstructionsText") as System.Windows.Controls.TextBlock;
                if (instructionText != null)
                {
                    instructionText.Text = "🔄 Authenticating device... Please wait.";
                }
                
                // Disable Block button (user passed tests)
                var blockButton = FindName("BlockButton") as System.Windows.Controls.Button;
                if (blockButton != null)
                {
                    blockButton.IsEnabled = false;
                }
                
                // Hide or disable Allow button (auto-authenticating)
                var allowButton = FindName("AllowButton") as System.Windows.Controls.Button;
                if (allowButton != null)
                {
                    allowButton.Visibility = Visibility.Collapsed;
                }
                
                _logger.LogInfo($"✅ UI updated for success - {_device.Name}");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error updating UI for success: {ex.Message}");
            }
        }

        /// <summary>
        /// Automatically authenticate device after tests pass
        /// </summary>
        private void AutoAuthenticate()
        {
            if (_autoAuthenticating) return; // Prevent double-execution
            _autoAuthenticating = true;
            
            try
            {
                _logger.LogSecurity($"✅ Auto-authenticating mouse: {_device.Name}");
                
                // Set dialog result to TRUE (device allowed)
                _dialogResult?.SetResult(true);
                
                // Close dialog
                Close();
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error in auto-authentication: {ex.Message}");
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
                if (name.Contains("bluetooth")) return "Bluetooth Mouse";
                
                return "Standard Mouse";
            }
            catch
            {
                return "Unknown Mouse";
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
                    _logger.LogSecurity($"? Mouse dialog closed without action for {_device.Name}");
                    _dialogResult?.TrySetResult(false);
                }
                
                _logger.LogInfo($"??? Mouse authentication dialog closed for {_device.Name}");
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

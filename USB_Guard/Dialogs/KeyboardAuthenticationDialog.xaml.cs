using System;
using System.Linq;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using USB_Guard.Core;
using USB_Guard.Models;
using System.Windows.Interop;
using System.Runtime.InteropServices;

namespace USB_Guard.Dialogs
{
    /// <summary>
    /// Enhanced Keyboard Authentication Dialog with System-Level Blocking
    /// </summary>
    public partial class KeyboardAuthenticationDialog : Window
    {
        #region Win32 API Imports for System-Level Device Control
        [DllImport("setupapi.dll", SetLastError = true)]
        private static extern IntPtr SetupDiGetClassDevs(ref Guid classGuid, IntPtr enumerator, IntPtr hwndParent, uint flags);

        [DllImport("setupapi.dll", SetLastError = true)]
        private static extern bool SetupDiEnumDeviceInfo(IntPtr deviceInfoSet, uint memberIndex, ref SP_DEVINFO_DATA deviceInfoData);

        [DllImport("setupapi.dll", SetLastError = true)]
        private static extern bool SetupDiCallClassInstaller(uint installFunction, IntPtr deviceInfoSet, ref SP_DEVINFO_DATA deviceInfoData);

        [DllImport("setupapi.dll", SetLastError = true)]
        private static extern bool SetupDiDestroyDeviceInfoList(IntPtr deviceInfoSet);

        [StructLayout(LayoutKind.Sequential)]
        private struct SP_DEVINFO_DATA
        {
            public uint cbSize;
            public Guid classGuid;
            public uint devInst;
            public IntPtr reserved;
        }

        private const uint DIGCF_PRESENT = 0x00000002;
        private const uint DIGCF_DEVICEINTERFACE = 0x00000010;
        private const uint DIF_PROPERTYCHANGE = 0x00000012;
        private const uint DICS_ENABLE = 0x00000001;
        private const uint DICS_DISABLE = 0x00000002;
        private const uint DICS_FLAG_GLOBAL = 0x00000001;
        #endregion

        private readonly USBDeviceInfo _device;
        private readonly SecurityLogger _logger;
        private readonly DispatcherTimer _timer;
        private int _timeRemaining = 30; // 30 seconds for keyboard authentication
        private TaskCompletionSource<bool> _dialogResult;
        private string _authCode;
        private List<TextBox> _codeInputs;
        
        // Input detection tracking
        private int _inputCount = 0;
        private bool _keyboardInputDetected = false;
        
        // Auto-authentication tracking
        private bool _autoAuthenticating = false;
        private bool _deviceBlocked = false;

        public KeyboardAuthenticationDialog(USBDeviceInfo device)
        {
            InitializeComponent();
            _device = device;
            _logger = new SecurityLogger();

            InitializeDialog();
            
            _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
            _timer.Tick += Timer_Tick;
            _timer.Start();

            _logger.LogSecurity($"⌨️ Keyboard authentication dialog opened for {_device.Name}");
        }

        private void InitializeDialog()
        {
            try
            {
                Title = "USB Guard - Keyboard Authentication";
                
                SetTextSafely("DeviceNameText", _device.Name);
                SetTextSafely("DeviceTypeText", _device.TypeDisplayName);
                SetTextSafely("VendorIdText", _device.VendorId);
                SetTextSafely("ProductIdText", _device.ProductId);
                
                // Set keyboard layout information
                var keyboardLayout = DetectKeyboardLayout();
                SetTextSafely("KeyboardLayoutText", keyboardLayout);
                
                // Initialize code input list
                _codeInputs = new List<TextBox> { Code1, Code2, Code3, Code4, Code5, Code6 };
                
                // Generate simple 6-digit code
                GenerateNewCode();
                
                ShowDeviceContext();
                UpdateTimerDisplay();
                
                // 🔧 CRITICAL FIX: Ensure the dialog can receive keyboard input
                EnsureKeyboardInputReady();
                
                _logger.LogInfo($"⌨️ Keyboard dialog initialized - Code: {_authCode}");
                _logger.LogSecurity($"⌨️ KEYBOARD AUTHENTICATION: {_device.Name} can now type in authentication dialog");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error initializing keyboard dialog: {ex.Message}");
                ShowError("Failed to initialize authentication dialog.");
            }
        }

        /// <summary>
        /// 🔧 CRITICAL FIX: Ensure the dialog is ready to receive keyboard input
        /// </summary>
        private void EnsureKeyboardInputReady()
        {
            try
            {
                // Set window properties for maximum focus capture
                this.Topmost = true;
                this.WindowState = WindowState.Normal;
                this.ShowInTaskbar = true;
                this.Activate();
                
                // Force focus to the window and first input box
                this.Focus();
                Code1?.Focus();
                
                // Set up multiple delayed focus attempts to ensure keyboard input works
                this.Dispatcher.BeginInvoke(new Action(() =>
                {
                    try
                    {
                        this.Activate();
                        this.Focus();
                        Code1?.Focus();
                        Keyboard.Focus(Code1);
                        
                        // Update instruction text to indicate keyboard setup
                        var instructionText = FindName("InstructionText") as TextBlock;
                        if (instructionText != null)
                        {
                            instructionText.Text = "⌨️ Ready for input - Type the 6-digit code using the new USB keyboard";
                            instructionText.Foreground = Brushes.Blue;
                        }
                        
                        _logger.LogSecurity($"✅ Keyboard input focus established for {_device.Name}");
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError($"Error in focus setup: {ex.Message}");
                    }
                }), DispatcherPriority.Input);

                // Add another delayed attempt for better reliability
                Task.Delay(500).ContinueWith(_ =>
                {
                    Dispatcher.BeginInvoke(new Action(() =>
                    {
                        try
                        {
                            this.Activate();
                            Code1?.Focus();
                            _logger.LogInfo($"⌨️ Second focus attempt completed for {_device.Name}");
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError($"Error in second focus attempt: {ex.Message}");
                        }
                    }), DispatcherPriority.Input);
                });
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error ensuring keyboard input ready: {ex.Message}");
            }
        }

        /// <summary>
        /// Detect keyboard layout for display
        /// </summary>
        private string DetectKeyboardLayout()
        {
            try
            {
                var layout = System.Globalization.CultureInfo.CurrentCulture.Name;
                switch (layout)
                {
                    case "en-US":
                        return "US English (QWERTY)";
                    case "en-GB":
                        return "UK English (QWERTY)";
                    case "de-DE":
                        return "German (QWERTZ)";
                    case "fr-FR":
                        return "French (AZERTY)";
                    case "es-ES":
                        return "Spanish (QWERTY)";
                    default:
                        return $"System Default ({layout})";
                }
            }
            catch
            {
                return "Unknown Layout";
            }
        }

        private void GenerateNewCode()
        {
            try
            {
                var random = new Random();
                _authCode = random.Next(100000, 999999).ToString();
                SetTextSafely("ChallengeCodeText", _authCode);
                
                // Clear input fields
                foreach (var input in _codeInputs)
                {
                    if (input != null)
                    {
                        input.Text = "";
                        input.Background = Brushes.White;
                        input.IsEnabled = true;
                    }
                }
                
                SetTextSafely("VerificationStatusText", "⏳ Waiting for input...");
                SetButtonEnabled("VerifyButton", false);
                
                // Reset tracking variables
                _inputCount = 0;
                _keyboardInputDetected = false;
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error generating code: {ex.Message}");
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

        private void SetButtonEnabled(string buttonName, bool enabled)
        {
            try
            {
                if (FindName(buttonName) is Button button)
                {
                    button.IsEnabled = enabled;
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"Could not set button enabled for {buttonName}: {ex.Message}");
            }
        }

        private void ShowDeviceContext()
        {
            try
            {
                // This would show device context if UI elements exist
                // Simplified version - just log the context
                if (_device.WasWhitelisted)
                {
                    _logger.LogInfo($"✅ Device {_device.Name} was previously trusted");
                }
                else if (_device.WasBlacklisted)
                {
                    _logger.LogInfo($"❌ Device {_device.Name} was previously blocked");
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
                _logger.LogSecurity($"⏰ Keyboard authentication timed out for {_device.Name}");
                _dialogResult?.SetResult(false);
                Close();
            }
        }

        private void UpdateTimerDisplay()
        {
            try
            {
                var timerText = FindName("TimerText") as TextBlock;
                if (timerText != null)
                {
                    var minutes = _timeRemaining / 60;
                    var seconds = _timeRemaining % 60;
                    timerText.Text = $"⏰ Time remaining: {minutes:D2}:{seconds:D2}";
                    
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
            catch (Exception ex)
            {
                _logger.LogError($"Error updating timer: {ex.Message}");
            }
        }

        // Enhanced event handlers for keyboard input
        private void CodeInput_TextChanged(object sender, TextChangedEventArgs e)
        {
            try
            {
                var textBox = sender as TextBox;
                if (textBox == null) return;

                // Log first keystroke to confirm keyboard is working
                if (!_keyboardInputDetected)
                {
                    _keyboardInputDetected = true;
                    _logger.LogSecurity($"🎯 FIRST KEYSTROKE DETECTED from {_device.Name} - Keyboard authentication working!");
                    
                    // Update instruction text to show keyboard is working
                    var instructionText = FindName("InstructionText") as TextBlock;
                    if (instructionText != null)
                    {
                        instructionText.Text = "🎯 Keyboard input detected! Continue typing the 6-digit code.";
                        instructionText.Foreground = Brushes.Green;
                    }
                }

                _inputCount++;

                // Ensure only digits and limit to single character
                var text = new string(textBox.Text.Where(char.IsDigit).ToArray());
                if (text.Length > 1)
                {
                    text = text.Substring(0, 1); // Only allow single digit
                }
                
                if (text != textBox.Text)
                {
                    textBox.Text = text;
                    textBox.SelectionStart = text.Length;
                }

                // Move to next input if current is filled
                if (text.Length == 1)
                {
                    var currentIndex = _codeInputs.IndexOf(textBox);
                    if (currentIndex >= 0 && currentIndex < _codeInputs.Count - 1)
                    {
                        _codeInputs[currentIndex + 1].Focus();
                    }
                }

                CheckCodeCompletion();
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error in code input: {ex.Message}");
            }
        }

        private void CodeInput_KeyDown(object sender, KeyEventArgs e)
        {
            try
            {
                var textBox = sender as TextBox;
                if (textBox == null) return;

                var currentIndex = _codeInputs.IndexOf(textBox);

                // Handle backspace navigation
                if (e.Key == Key.Back)
                {
                    if (string.IsNullOrEmpty(textBox.Text) && currentIndex > 0)
                    {
                        _codeInputs[currentIndex - 1].Focus();
                        _codeInputs[currentIndex - 1].Text = "";
                    }
                }
                // Handle Enter key to verify when all boxes are filled
                else if (e.Key == Key.Enter)
                {
                    var enteredCode = string.Join("", _codeInputs.Select(tb => tb.Text));
                    if (enteredCode.Length == 6)
                    {
                        VerifyCode(enteredCode);
                    }
                }
                // Handle Tab navigation
                else if (e.Key == Key.Tab && !Keyboard.Modifiers.HasFlag(ModifierKeys.Shift))
                {
                    if (currentIndex >= 0 && currentIndex < _codeInputs.Count - 1)
                    {
                        _codeInputs[currentIndex + 1].Focus();
                        e.Handled = true;
                    }
                }
                else if (e.Key == Key.Tab && Keyboard.Modifiers.HasFlag(ModifierKeys.Shift))
                {
                    if (currentIndex > 0)
                    {
                        _codeInputs[currentIndex - 1].Focus();
                        e.Handled = true;
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error in key handling: {ex.Message}");
            }
        }

        private void CheckCodeCompletion()
        {
            try
            {
                var enteredCode = string.Join("", _codeInputs.Select(tb => tb.Text));
                
                if (enteredCode.Length == 6)
                {
                    // All boxes filled - verify automatically
                    _logger.LogSecurity($"🔑 Full code entered: {enteredCode} for {_device.Name}");
                    VerifyCode(enteredCode);
                }
                else
                {
                    SetTextSafely("VerificationStatusText", $"⏳ Waiting for input... ({enteredCode.Length}/6)");
                    SetButtonEnabled("VerifyButton", enteredCode.Length == 6);
                    
                    // Reset input box colors to white
                    foreach (var input in _codeInputs)
                    {
                        if (input != null && input.Background != Brushes.White) 
                        {
                            input.Background = Brushes.White;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error checking code completion: {ex.Message}");
            }
        }

        /// <summary>
        /// Verify the entered code and auto-authenticate if correct
        /// </summary>
        private void VerifyCode(string enteredCode)
        {
            try
            {
                _logger.LogInfo($"🔑 Verifying keyboard code: Expected={_authCode}, Entered={enteredCode}");
                
                bool isCorrect = enteredCode == _authCode;
                
                if (isCorrect)
                {
                    // ✅ CODE MATCHED
                    _logger.LogSecurity($"✅ Keyboard code matched for {_device.Name}");
                    
                    // Stop timer
                    _timer.Stop();
                    
                    // Update UI to show success
                    UpdateUIForSuccess();
                    
                    // Auto-authenticate after 1 second delay (show success message)
                    Task.Delay(1000).ContinueWith(_ => 
                    {
                        Dispatcher.Invoke(() => AutoAuthenticate());
                    });
                }
                else
                {
                    // ❌ CODE INCORRECT - Block immediately like mouse
                    _logger.LogWarning($"❌ Keyboard code mismatch for {_device.Name}");
                    
                    // Stop timer
                    _timer.Stop();
                    
                    // Update UI to show error
                    UpdateUIForFailure();
                    
                    // Return failure and close immediately (like mouse dialog)
                    _dialogResult?.SetResult(false);
                    Close();
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error verifying code: {ex.Message}");
                _dialogResult?.SetResult(false);
                Close();
            }
        }

        /// <summary>
        /// Update UI to show success when code matches
        /// </summary>
        private void UpdateUIForSuccess()
        {
            try
            {
                // Update status text
                SetTextSafely("VerificationStatusText", "✅ CODE MATCHED");
                
                // Change status color to green
                var statusText = FindName("VerificationStatusText") as TextBlock;
                if (statusText != null)
                {
                    statusText.Foreground = Brushes.Green;
                    statusText.FontWeight = FontWeights.Bold;
                    statusText.FontSize = 18;
                }
                
                // Show authenticating message
                var instructionText = FindName("InstructionText") as TextBlock;
                if (instructionText != null)
                {
                    instructionText.Text = "🔄 Authenticating keyboard... Please wait.";
                }
                
                // Turn all input boxes green (success indication)
                foreach (var textBox in _codeInputs)
                {
                    if (textBox != null)
                    {
                        textBox.Background = Brushes.LightGreen;
                        textBox.IsEnabled = false; // Prevent further input
                    }
                }
                
                // Disable buttons
                SetButtonEnabled("VerifyButton", false);
                
                var blockButton = FindName("BlockButton") as Button;
                if (blockButton != null)
                {
                    blockButton.IsEnabled = false;
                }
                
                _logger.LogInfo($"✅ UI updated for success - {_device.Name}");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error updating UI for success: {ex.Message}");
            }
        }

        /// <summary>
        /// Update UI to show error when code doesn't match
        /// </summary>
        private void UpdateUIForFailure()
        {
            try
            {
                // Update status text
                SetTextSafely("VerificationStatusText", "❌ AUTHENTICATION FAILED - BLOCKING DEVICE");
                
                // Change status color to red
                var statusText = FindName("VerificationStatusText") as TextBlock;
                if (statusText != null)
                {
                    statusText.Foreground = Brushes.Red;
                    statusText.FontWeight = FontWeights.Bold;
                    statusText.FontSize = 16;
                }
                
                // Turn all input boxes red (error indication)
                foreach (var textBox in _codeInputs)
                {
                    if (textBox != null)
                    {
                        textBox.Background = Brushes.LightCoral;
                        textBox.IsEnabled = false;
                    }
                }
                
                // Disable all buttons
                SetButtonEnabled("VerifyButton", false);
                SetButtonEnabled("RegenerateButton", false);
                
                _logger.LogWarning($"❌ Authentication failed for {_device.Name} - device will be blocked");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error updating UI for failure: {ex.Message}");
            }
        }

        /// <summary>
        /// Automatically authenticate device after code matches
        /// </summary>
        private void AutoAuthenticate()
        {
            if (_autoAuthenticating) return; // Prevent double-execution
            _autoAuthenticating = true;
            
            try
            {
                _logger.LogSecurity($"✅ Auto-authenticating keyboard: {_device.Name}");
                
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

        private void VerifyButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var enteredCode = string.Join("", _codeInputs.Select(tb => tb.Text));
                VerifyCode(enteredCode);
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error in manual code verification: {ex.Message}");
                ShowError("Authentication failed due to an error.");
                _dialogResult?.SetResult(false);
            }
        }

        private void RegenerateButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                GenerateNewCode();
                Code1?.Focus();
                _logger.LogInfo($"🔄 Challenge code regenerated for {_device.Name}");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error regenerating code: {ex.Message}");
            }
        }

        private void BlockButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                _timer.Stop();
                _logger.LogSecurity($"🚫 Keyboard manually blocked by user: {_device.Name}");
                _dialogResult?.SetResult(false);
                Close();
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error blocking device: {ex.Message}");
            }
        }

        private void ShowError(string message)
        {
            try
            {
                var errorText = FindName("ErrorText") as TextBlock;
                var errorPanel = FindName("ErrorPanel") as Border;
                
                if (errorText != null && errorPanel != null)
                {
                    errorText.Text = message;
                    errorPanel.Visibility = Visibility.Visible;
                }
                else
                {
                    MessageBox.Show(message, "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error showing error message: {ex.Message}");
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
                    _logger.LogSecurity($"⚠️ Keyboard dialog closed without action for {_device.Name}");
                    _dialogResult?.TrySetResult(false);
                }
                
                _logger.LogInfo($"🚪 Keyboard authentication dialog closed for {_device.Name}");
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

        /// <summary>
        /// Override to handle window activation and ensure keyboard focus
        /// </summary>
        protected override void OnActivated(EventArgs e)
        {
            base.OnActivated(e);
            
            try
            {
                // Ensure first input box gets focus when window is activated
                if (_codeInputs != null && _codeInputs.Count > 0 && _codeInputs[0] != null)
                {
                    _codeInputs[0].Focus();
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error in window activation: {ex.Message}");
            }
        }
    }
}

using System;
using USB_Guard.Models;

namespace USB_Guard.Core
{
    /// <summary>
    /// Simple failure statistics class
    /// </summary>
    public class FailureStatistics
    {
        public int TotalFailures { get; set; }
        public int DevicesBlocked { get; set; }
        public DateTime LastFailure { get; set; }
    }

    /// <summary>
    /// Simple authentication failure manager replacement
    /// </summary>
    public class AuthenticationFailureManager
    {
        public static readonly int MAX_FAILED_ATTEMPTS = 3;
        public static AuthenticationFailureManager Instance { get; } = new AuthenticationFailureManager();

        public void RecordFailedAttempt(USBDeviceInfo device, string reason)
        {
            // Simple logging - no complex tracking needed
            Console.WriteLine($"Failed attempt recorded for {device.Name}: {reason}");
        }

        public void ClearFailedAttempts(USBDeviceInfo device)
        {
            // Simple clearing
            Console.WriteLine($"Failed attempts cleared for {device.Name}");
        }

        public int GetFailureCount(USBDeviceInfo device)
        {
            // Always return 0 for simplified version
            return 0;
        }

        public bool IsDevicePermanentlyBlocked(USBDeviceInfo device)
        {
            // No permanent blocking in simplified version
            return false;
        }
    }
}
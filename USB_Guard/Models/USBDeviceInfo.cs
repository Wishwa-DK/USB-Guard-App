using System;
using System.Collections.Generic;

namespace USB_Guard.Models
{
    public enum USBDeviceType
    {
        Unknown,
        Storage,
        Keyboard,
        Mouse,
        HID,
        Audio,
        Video,
        Printer,
        Hub,
        CDC,
        MassStorage
    }

    public enum DeviceStatus
    {
        Unknown,
        Connected,
        Authenticating,
        Trusted,
        Blocked,
        Sandboxed,
        Quarantined
    }

    public class HIDBehaviorAnalysis
    {
        public bool IsSuspicious { get; set; }
        public int BehaviorScore { get; set; }
        public string AnalysisDetails { get; set; } = "";
        public string RecommendedAction { get; set; } = "";
    }

    public class USBDeviceInfo
    {
        public string Name { get; set; } = "";
        public string DeviceId { get; set; } = "";
        public string VendorId { get; set; } = "";
        public string ProductId { get; set; } = "";
        public string SerialNumber { get; set; } = "";
        public string HardwareId { get; set; } = ""; // Hardware ID for registry matching
        public USBDeviceType Type { get; set; } = USBDeviceType.Unknown;
        public DeviceStatus Status { get; set; } = DeviceStatus.Unknown;
        public bool IsAuthenticated { get; set; } = false;
        public DateTime? AuthenticatedTime { get; set; }
        public DateTime? QuarantineTime { get; set; }
        public string DriveLetter { get; set; } = "";
        public string AuthenticationToken { get; set; } = "";
        public string KeyboardLayout { get; set; } = "";
        public string MouseType { get; set; } = "";
        
        // STEP 4: Mouse authentication properties
        public int? MouseButtons { get; set; }
        
        // Additional fields used by USBDeviceManager
        public string PnpDeviceId { get; set; } = "";
        public DateTime? ConnectedTime { get; set; }
        public string ClassGuid { get; set; } = "";

        // ZERO-TRUST: Properties for historical device status
        public bool WasWhitelisted { get; set; } = false;
        public bool WasBlacklisted { get; set; } = false;
        public DateTime? LastAuthenticationTime { get; set; }
        public string LastAuthenticationMethod { get; set; } = "";
        public int AuthenticationAttempts { get; set; } = 0;
        public bool RequiresZeroTrustAuth { get; set; } = true; // Always true in zero-trust mode
        
        // System-level blocking status (for dual-level blocking)
        public bool IsSystemLevelBlocked { get; set; } = false;
        public bool IsApplicationLevelBlocked { get; set; } = false;

        // COMPOSITE DEVICE FIX: Track composite device relationships
        public bool IsCompositeDevice { get; set; } = false;
        public string ParentCompositeDeviceId { get; set; } = "";
        public List<string> ChildDeviceIds { get; set; } = new List<string>();

        public string TypeDisplayName
        {
            get
            {
                // C# 7.3 compatible switch statement
                switch (Type)
                {
                    case USBDeviceType.Storage: return "?? Storage Device";
                    case USBDeviceType.Keyboard: return "?? Keyboard";
                    case USBDeviceType.Mouse: return "??? Mouse";
                    case USBDeviceType.HID: return "?? HID Device";
                    case USBDeviceType.Audio: return "?? Audio Device";
                    case USBDeviceType.Video: return "?? Video Device";
                    case USBDeviceType.Printer: return "??? Printer";
                    case USBDeviceType.Hub: return "?? USB Hub";
                    default: return "? Unknown Device";
                }
            }
        }

        public string StatusDisplayText
        {
            get
            {
                switch (Status)
                {
                    case DeviceStatus.Connected: return "?? Connected";
                    case DeviceStatus.Authenticating: return "?? Authenticating...";
                    case DeviceStatus.Trusted: return "? Trusted";
                    case DeviceStatus.Blocked: return "?? Blocked";
                    case DeviceStatus.Sandboxed: return "?? Sandboxed";
                    case DeviceStatus.Quarantined: return "?? Quarantined";
                    default: return "? Unknown";
                }
            }
        }

        public string ZeroTrustStatusText
        {
            get
            {
                var statusText = StatusDisplayText;
                
                if (WasWhitelisted && !IsAuthenticated)
                    statusText += " (? Was Whitelisted)";
                else if (WasBlacklisted && !IsAuthenticated)
                    statusText += " (?? Was Blacklisted)";
                else if (RequiresZeroTrustAuth && !IsAuthenticated)
                    statusText += " (?? Zero-Trust Auth Required)";
                
                return statusText;
            }
        }
    }
}
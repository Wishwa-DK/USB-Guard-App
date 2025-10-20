using System;

namespace USB_Guard.Models
{
    /// <summary>
    /// Simplified device rule for whitelist/blacklist management
    /// </summary>
    public class DeviceRule
    {
        public string Id { get; set; } = Guid.NewGuid().ToString();
        public string DeviceId { get; set; }
        public string Name { get; set; }
        public string VendorId { get; set; }
        public string ProductId { get; set; }
        public string SerialNumber { get; set; } = "";
        public USBDeviceType Type { get; set; }
        public USBDeviceType DeviceType { get; set; } // Alias for Type
        public bool IsWhitelisted { get; set; }
        public bool IsEnabled { get; set; } = true;
        public DateTime CreatedDate { get; set; } = DateTime.Now;
        public string Reason { get; set; } = "";
        public string CreatedBy { get; set; } = "User";
        
        public override string ToString()
        {
            return $"{Name} (VID:{VendorId} PID:{ProductId})";
        }
    }
}
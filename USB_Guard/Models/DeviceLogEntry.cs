using System;
using System.Windows;
using System.Windows.Media;

namespace USB_Guard.Models
{
    public class DeviceLogEntry
    {
        public DateTime Timestamp { get; set; }
        public string DeviceName { get; set; }
        public string DeviceIcon { get; set; }
        public string Action { get; set; }
        public string Details { get; set; }
        public Brush ActionColor { get; set; }
        
        public Visibility HasDetails
        {
            get { return string.IsNullOrEmpty(Details) ? Visibility.Collapsed : Visibility.Visible; }
        }
    }
}

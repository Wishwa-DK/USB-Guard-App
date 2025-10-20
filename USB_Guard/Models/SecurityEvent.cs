using System;

namespace USB_Guard.Models
{
    public class SecurityEvent
    {
        public string Id { get; set; } = Guid.NewGuid().ToString();
        public DateTime Timestamp { get; set; } = DateTime.Now;
        public string EventType { get; set; } = "";
        public string Level { get; set; } = "INFO"; // INFO, WARN, ERROR, CRITICAL
        public string DeviceName { get; set; } = "";
        public string DeviceId { get; set; } = "";
        public string VendorId { get; set; } = "";
        public string ProductId { get; set; } = "";
        public string Action { get; set; } = "";
        public string Result { get; set; } = "";
        public string Details { get; set; } = "";
        public string ThreatLevel { get; set; } = "";
        public TimeSpan? AuthenticationDuration { get; set; }
        public bool IsBlocked { get; set; } = false;

        // Storage scan properties
        public int? FilesScanned { get; set; }
        public int? ThreatsDetected { get; set; }
        public string ThreatTypes { get; set; } = "";
        public TimeSpan? ScanDuration { get; set; }

        public string FormattedTimestamp => Timestamp.ToString("HH:mm:ss");
        public string Summary => $"[{Level}] {EventType}: {Details}";
        
        public string FullSummary
        {
            get
            {
                var summary = Summary;
                if (FilesScanned.HasValue && ThreatsDetected.HasValue)
                {
                    summary += $" | Scanned: {FilesScanned} files, Threats: {ThreatsDetected}";
                }
                return summary;
            }
        }
    }
}

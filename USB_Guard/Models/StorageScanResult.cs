using System;
using System.Collections.Generic;
using System.Linq;

namespace USB_Guard.Models
{
    /// <summary>
    /// Enhanced result of USB storage device malware scan with automatic blocking logic
    /// </summary>
    public class StorageScanResult
    {
        public bool ScanCompleted { get; set; } = false;
        public bool ThreatsDetected { get; set; } = false;
        public int TotalFilesScanned { get; set; } = 0;
        public int ThreatCount { get; set; } = 0;
        public TimeSpan ScanDuration { get; set; }
        public long TotalSizeBytes { get; set; } = 0;
        public List<MaliciousFile> DetectedThreats { get; set; } = new List<MaliciousFile>();
        public string ErrorMessage { get; set; } = "";
        public bool HasError => !string.IsNullOrEmpty(ErrorMessage);
        
        /// <summary>
        /// Automatic blocking decision based on threat analysis
        /// </summary>
        public bool ShouldBlockAutomatically
        {
            get
            {
                if (!ThreatsDetected) return false;
                
                // Block if any CRITICAL threats found
                var criticalThreats = DetectedThreats.Count(t => t.ThreatLevel == "CRITICAL");
                if (criticalThreats > 0) return true;
                
                // Block if multiple HIGH threats found
                var highThreats = DetectedThreats.Count(t => t.ThreatLevel == "HIGH");
                if (highThreats >= 3) return true;
                
                // Block if many MEDIUM threats (likely malware collection)
                var mediumThreats = DetectedThreats.Count(t => t.ThreatLevel == "MEDIUM");
                if (mediumThreats >= 5) return true;
                
                return false;
            }
        }
        
        /// <summary>
        /// Threat summary for logging and notifications
        /// </summary>
        public string ThreatSummary
        {
            get
            {
                if (!ThreatsDetected) return "No threats detected";
                
                var critical = DetectedThreats.Count(t => t.ThreatLevel == "CRITICAL");
                var high = DetectedThreats.Count(t => t.ThreatLevel == "HIGH");
                var medium = DetectedThreats.Count(t => t.ThreatLevel == "MEDIUM");
                var low = DetectedThreats.Count(t => t.ThreatLevel == "LOW");
                
                var parts = new List<string>();
                if (critical > 0) parts.Add($"?? {critical} Critical");
                if (high > 0) parts.Add($"?? {high} High");
                if (medium > 0) parts.Add($"?? {medium} Medium");
                if (low > 0) parts.Add($"?? {low} Low");
                
                return string.Join(", ", parts);
            }
        }
        
        /// <summary>
        /// Security recommendation based on scan results and automatic blocking logic
        /// </summary>
        public string Recommendation
        {
            get
            {
                if (HasError)
                    return "?? Unable to scan device - AUTOMATIC BLOCK for safety";
                
                if (ThreatsDetected)
                {
                    if (ShouldBlockAutomatically)
                        return "?? CRITICAL THREATS DETECTED - AUTOMATIC BLOCK activated";
                    else
                        return "?? Threats detected - Manual review required";
                }
                
                if (TotalFilesScanned == 0)
                    return "? Empty device - Safe to allow";
                
                if (ThreatCount == 0 && TotalFilesScanned > 0)
                    return "? No threats detected - AUTOMATIC ALLOW";
                
                return "? Unable to determine safety - Use caution";
            }
        }

        /// <summary>
        /// Formatted total size
        /// </summary>
        public string FormattedSize
        {
            get
            {
                if (TotalSizeBytes < 1024)
                    return $"{TotalSizeBytes} B";
                else if (TotalSizeBytes < 1024 * 1024)
                    return $"{TotalSizeBytes / 1024.0:F2} KB";
                else if (TotalSizeBytes < 1024 * 1024 * 1024)
                    return $"{TotalSizeBytes / (1024.0 * 1024):F2} MB";
                else
                    return $"{TotalSizeBytes / (1024.0 * 1024 * 1024):F2} GB";
            }
        }
        
        /// <summary>
        /// Get top threats for display (limit to most critical)
        /// </summary>
        public List<MaliciousFile> GetTopThreats(int maxCount = 5)
        {
            return DetectedThreats
                .OrderByDescending(t => GetThreatSeverity(t.ThreatLevel))
                .ThenBy(t => t.FileName)
                .Take(maxCount)
                .ToList();
        }
        
        /// <summary>
        /// Convert threat level to numeric severity for sorting
        /// </summary>
        private int GetThreatSeverity(string threatLevel)
        {
            switch (threatLevel?.ToUpper())
            {
                case "CRITICAL": return 4;
                case "HIGH": return 3;
                case "MEDIUM": return 2;
                case "LOW": return 1;
                default: return 0;
            }
        }
        
        /// <summary>
        /// Performance score based on scan speed and thoroughness
        /// </summary>
        public string PerformanceScore
        {
            get
            {
                if (ScanDuration.TotalSeconds <= 10)
                    return "? Very Fast";
                else if (ScanDuration.TotalSeconds <= 30)
                    return "?? Fast";
                else if (ScanDuration.TotalSeconds <= 60)
                    return "?? Normal";
                else
                    return "?? Slow";
            }
        }
    }

    /// <summary>
    /// Enhanced malicious file information with more detailed threat analysis
    /// </summary>
    public class MaliciousFile
    {
        public string FilePath { get; set; } = "";
        public string FileName { get; set; } = "";
        public string ThreatType { get; set; } = "";
        public string ThreatLevel { get; set; } = "MEDIUM"; // CRITICAL, HIGH, MEDIUM, LOW
        public long FileSize { get; set; } = 0;
        public DateTime DetectedTime { get; set; } = DateTime.Now;
        public string Reason { get; set; } = "";
        
        /// <summary>
        /// Formatted file size for display
        /// </summary>
        public string FormattedFileSize
        {
            get
            {
                if (FileSize < 1024)
                    return $"{FileSize} B";
                else if (FileSize < 1024 * 1024)
                    return $"{FileSize / 1024.0:F1} KB";
                else if (FileSize < 1024 * 1024 * 1024)
                    return $"{FileSize / (1024.0 * 1024):F1} MB";
                else
                    return $"{FileSize / (1024.0 * 1024 * 1024):F1} GB";
            }
        }
        
        /// <summary>
        /// Threat level icon for UI display
        /// </summary>
        public string ThreatIcon
        {
            get
            {
                switch (ThreatLevel?.ToUpper())
                {
                    case "CRITICAL": return "??";
                    case "HIGH": return "??";
                    case "MEDIUM": return "??";
                    case "LOW": return "??";
                    default: return "?";
                }
            }
        }
        
        /// <summary>
        /// Risk assessment for this specific file
        /// </summary>
        public string RiskAssessment
        {
            get
            {
                switch (ThreatLevel?.ToUpper())
                {
                    case "CRITICAL": return "EXTREME RISK - Immediate threat to system security";
                    case "HIGH": return "HIGH RISK - Likely malicious file";
                    case "MEDIUM": return "MEDIUM RISK - Potentially dangerous file";
                    case "LOW": return "LOW RISK - Suspicious but may be legitimate";
                    default: return "UNKNOWN RISK";
                }
            }
        }

        public override string ToString()
        {
            return $"{ThreatIcon} [{ThreatLevel}] {FileName} ({FormattedFileSize}) - {Reason}";
        }
    }
}

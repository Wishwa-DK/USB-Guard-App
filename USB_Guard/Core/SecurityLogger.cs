using System;
using System.IO;
using System.Text;
using System.Globalization;
using System.Linq;

namespace USB_Guard.Core
{
    public class SecurityLogger
    {
        private readonly string _logDirectory;
        private readonly string _logFileName;
        private readonly object _lockObject = new object();

        public SecurityLogger()
        {
            _logDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "USBGuard", "Logs");
            _logFileName = $"USBGuard_{DateTime.Now:yyyyMMdd}.log";
            
            Directory.CreateDirectory(_logDirectory);
        }

        public void LogInfo(string message)
        {
            WriteLog("INFO", message);
        }

        public void LogWarning(string message)
        {
            WriteLog("WARN", message);
        }

        public void LogError(string message)
        {
            WriteLog("ERROR", message);
        }

        public void LogSecurity(string message)
        {
            WriteLog("SECURITY", message);
        }

        public void LogDeviceEvent(string deviceName, string eventType, string details = "")
        {
            string message = $"Device: {deviceName} | Event: {eventType}";
            if (!string.IsNullOrEmpty(details))
                message += $" | Details: {details}";
            
            WriteLog("DEVICE", message);
        }

        public void LogAuthentication(string deviceName, bool success, string method)
        {
            string result = success ? "SUCCESS" : "FAILED";
            string message = $"Device: {deviceName} | Method: {method} | Result: {result}";
            WriteLog("AUTH", message);
        }

        private void WriteLog(string level, string message)
        {
            try
            {
                lock (_lockObject)
                {
                    string logFilePath = Path.Combine(_logDirectory, _logFileName);
                    string timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff", CultureInfo.InvariantCulture);
                    string logEntry = $"[{timestamp}] [{level}] {message}{Environment.NewLine}";

                    File.AppendAllText(logFilePath, logEntry, Encoding.UTF8);
                }
            }
            catch (Exception ex)
            {
                // If logging fails, write to system event log as fallback
                try
                {
                    System.Diagnostics.EventLog.WriteEntry("USB Guard", 
                        $"Logging error: {ex.Message}. Original message: {message}", 
                        System.Diagnostics.EventLogEntryType.Error);
                }
                catch
                {
                    // If even event log fails, silently continue
                }
            }
        }

        public string[] GetRecentLogs(int hours = 24)
        {
            try
            {
                var cutoffTime = DateTime.Now.AddHours(-hours);
                var recentLines = new System.Collections.Generic.List<string>();

                // Get all log files from the last few days (to cover 24-hour window)
                var logFiles = Directory.GetFiles(_logDirectory, "USBGuard_*.log")
                    .OrderByDescending(f => File.GetLastWriteTime(f))
                    .Take(3) // Last 3 days should cover any 24-hour period
                    .ToArray();

                foreach (var logFile in logFiles)
                {
                    try
                    {
                        if (!File.Exists(logFile)) continue;

                        var lines = File.ReadAllLines(logFile);

                        foreach (var line in lines)
                        {
                            if (TryParseTimestamp(line, out DateTime lineTime))
                            {
                                // Only include logs from the last 24 hours
                                if (lineTime >= cutoffTime)
                                {
                                    recentLines.Add(line);
                                }
                            }
                        }
                    }
                    catch (Exception fileEx)
                    {
                        LogError($"Error reading log file {logFile}: {fileEx.Message}");
                    }
                }

                // Sort by timestamp descending (most recent first)
                return recentLines
                    .OrderByDescending(line =>
                    {
                        TryParseTimestamp(line, out DateTime timestamp);
                        return timestamp;
                    })
                    .ToArray();
            }
            catch (Exception ex)
            {
                LogError($"Failed to retrieve recent logs: {ex.Message}");
                return new string[0];
            }
        }

        private bool TryParseTimestamp(string logLine, out DateTime timestamp)
        {
            timestamp = DateTime.MinValue;
            
            if (string.IsNullOrEmpty(logLine) || !logLine.StartsWith("["))
                return false;

            int endBracket = logLine.IndexOf(']');
            if (endBracket <= 1)
                return false;

            string timestampStr = logLine.Substring(1, endBracket - 1);
            return DateTime.TryParseExact(timestampStr, "yyyy-MM-dd HH:mm:ss.fff", 
                CultureInfo.InvariantCulture, DateTimeStyles.None, out timestamp);
        }

        public void ExportLogs(string exportPath, DateTime? startDate = null, DateTime? endDate = null)
        {
            try
            {
                var professionalLogs = new System.Collections.Generic.List<string>();
                
                // Add professional header
                professionalLogs.Add("???????????????????????????????????????????????????????????????????????????");
                professionalLogs.Add("                   USB GUARD - SECURITY LOG REPORT                        ");
                professionalLogs.Add("???????????????????????????????????????????????????????????????????????????");
                professionalLogs.Add($"Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
                professionalLogs.Add($"Period: {(startDate.HasValue ? startDate.Value.ToString("yyyy-MM-dd") : "All time")} to {(endDate.HasValue ? endDate.Value.ToString("yyyy-MM-dd") : "Present")}");
                professionalLogs.Add("???????????????????????????????????????????????????????????????????????????");
                professionalLogs.Add("");
                
                // Get all log files in directory
                var logFiles = Directory.GetFiles(_logDirectory, "USBGuard_*.log");
                
                int deviceConnections = 0;
                int deviceDisconnections = 0;
                int authenticationsSuccess = 0;
                int authenticationsFailed = 0;
                
                foreach (var logFile in logFiles)
                {
                    var lines = File.ReadAllLines(logFile);
                    
                    foreach (var line in lines)
                    {
                        // Only include device-related logs
                        if (!line.Contains("[DEVICE]") && !line.Contains("[AUTH]") && !line.Contains("[SECURITY]"))
                            continue;
                            
                        bool includeLog = true;
                        
                        if (startDate.HasValue || endDate.HasValue)
                        {
                            if (TryParseTimestamp(line, out DateTime lineTime))
                            {
                                if (startDate.HasValue && lineTime < startDate.Value)
                                    includeLog = false;
                                if (endDate.HasValue && lineTime > endDate.Value)
                                    includeLog = false;
                            }
                        }
                        
                        if (includeLog)
                        {
                            // Format the log entry professionally
                            var formattedEntry = FormatLogEntryProfessionally(line);
                            if (!string.IsNullOrEmpty(formattedEntry))
                            {
                                professionalLogs.Add(formattedEntry);
                                
                                // Count statistics
                                if (line.Contains("Device Connected") || line.Contains("??"))
                                    deviceConnections++;
                                else if (line.Contains("Device Disconnected") || line.Contains("??"))
                                    deviceDisconnections++;
                                else if (line.Contains("APPROVED") || line.Contains("SUCCESS"))
                                    authenticationsSuccess++;
                                else if (line.Contains("BLOCKED") || line.Contains("FAILED"))
                                    authenticationsFailed++;
                            }
                        }
                    }
                }
                
                // Add summary statistics
                professionalLogs.Add("");
                professionalLogs.Add("???????????????????????????????????????????????????????????????????????????");
                professionalLogs.Add("                          SUMMARY STATISTICS                               ");
                professionalLogs.Add("???????????????????????????????????????????????????????????????????????????");
                professionalLogs.Add($"Total Device Connections:     {deviceConnections}");
                professionalLogs.Add($"Total Device Disconnections:  {deviceDisconnections}");
                professionalLogs.Add($"Successful Authentications:   {authenticationsSuccess}");
                professionalLogs.Add($"Failed/Blocked Attempts:      {authenticationsFailed}");
                professionalLogs.Add("???????????????????????????????????????????????????????????????????????????");
                professionalLogs.Add("");
                professionalLogs.Add("End of Report - USB Guard Security System");
                professionalLogs.Add("");

                File.WriteAllLines(exportPath, professionalLogs, Encoding.UTF8);
                LogInfo($"Professional log report exported to: {exportPath}");
            }
            catch (Exception ex)
            {
                LogError($"Failed to export logs: {ex.Message}");
                throw;
            }
        }

        private string FormatLogEntryProfessionally(string logLine)
        {
            try
            {
                // Parse: [2024-01-15 10:30:45.123] [LEVEL] message
                if (string.IsNullOrEmpty(logLine)) return null;

                var timestampEnd = logLine.IndexOf(']');
                if (timestampEnd < 0) return null;

                var timestamp = logLine.Substring(1, timestampEnd - 1);
                
                var levelStart = logLine.IndexOf('[', timestampEnd + 1);
                var levelEnd = logLine.IndexOf(']', levelStart + 1);
                if (levelEnd < 0) return null;
                
                var level = logLine.Substring(levelStart + 1, levelEnd - levelStart - 1).PadRight(8);
                var message = logLine.Substring(levelEnd + 1).Trim();

                // Clean up emojis and format nicely
                message = message.Replace("??", "[CONNECT]")
                               .Replace("??", "[DISCONNECT]")
                               .Replace("?", "[APPROVED]")
                               .Replace("??", "[BLOCKED]")
                               .Replace("??", "[AUTH]")
                               .Replace("???", "[SECURITY]");

                return $"[{timestamp}] {level} | {message}";
            }
            catch
            {
                return null;
            }
        }

    }

    public class LogStatistics
    {
        public int TotalEvents { get; set; }
        public int ErrorCount { get; set; }
        public int WarningCount { get; set; }
        public int SecurityEvents { get; set; }
        public int DeviceEvents { get; set; }
        public int AuthenticationEvents { get; set; }
        public int SuccessfulAuthentications { get; set; }
        public int FailedAuthentications { get; set; }
        
        public double SuccessRate
        {
            get
            {
                if (AuthenticationEvents == 0) return 0;
                return (double)SuccessfulAuthentications / AuthenticationEvents * 100;
            }
        }
    }
}

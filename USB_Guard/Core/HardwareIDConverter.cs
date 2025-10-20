using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace USB_Guard.Core
{
    /// <summary>
    /// Converts between PnP Device IDs and Hardware IDs for Windows policy matching
    /// </summary>
    public class HardwareIDConverter
    {
        private readonly SecurityLogger _logger;

        public HardwareIDConverter()
        {
            _logger = new SecurityLogger();
        }

        /// <summary>
        /// Convert PnP Device ID to Hardware ID format
        /// Example: USB\VID_046D&PID_C52B\5&2E0C3A&0&2 -> USB\VID_046D&PID_C52B
        /// </summary>
        public string ConvertPnPIdToHardwareId(string pnpDeviceId)
        {
            try
            {
                if (string.IsNullOrEmpty(pnpDeviceId))
                {
                    _logger.LogWarning("PnP Device ID is null or empty");
                    return null;
                }

                // PnP format: USB\VID_046D&PID_C52B\InstanceID
                // Hardware ID format: USB\VID_046D&PID_C52B

                // Remove everything after the second backslash (instance ID)
                var parts = pnpDeviceId.Split('\\');
                
                if (parts.Length >= 2)
                {
                    // Take first two parts: "USB" and "VID_046D&PID_C52B"
                    var hardwareId = $"{parts[0]}\\{parts[1]}";
                    _logger.LogInfo($"Converted PnP ID to Hardware ID: {pnpDeviceId} -> {hardwareId}");
                    return hardwareId;
                }
                
                _logger.LogWarning($"Unable to parse PnP Device ID: {pnpDeviceId}");
                return pnpDeviceId; // Return as-is if can't parse
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error converting PnP ID to Hardware ID: {ex.Message}");
                return pnpDeviceId;
            }
        }

        /// <summary>
        /// Generate multiple Hardware ID variations for matching
        /// Windows checks Hardware IDs in order, so we need all variations
        /// </summary>
        public List<string> GenerateHardwareIdVariations(string pnpDeviceId)
        {
            var variations = new List<string>();
            
            try
            {
                if (string.IsNullOrEmpty(pnpDeviceId))
                {
                    return variations;
                }

                // Extract VID and PID
                var vid = ExtractVID(pnpDeviceId);
                var pid = ExtractPID(pnpDeviceId);
                var rev = ExtractREV(pnpDeviceId);

                if (!string.IsNullOrEmpty(vid) && !string.IsNullOrEmpty(pid))
                {
                    // Most specific (with revision)
                    if (!string.IsNullOrEmpty(rev))
                    {
                        variations.Add($"USB\\VID_{vid}&PID_{pid}&REV_{rev}");
                    }
                    
                    // Standard format (most common)
                    variations.Add($"USB\\VID_{vid}&PID_{pid}");
                    
                    // Vendor-only (least specific)
                    variations.Add($"USB\\VID_{vid}");
                    
                    _logger.LogInfo($"Generated {variations.Count} Hardware ID variations for {pnpDeviceId}");
                }
                else
                {
                    _logger.LogWarning($"Could not extract VID/PID from: {pnpDeviceId}");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error generating Hardware ID variations: {ex.Message}");
            }
            
            return variations;
        }

        /// <summary>
        /// Extract Vendor ID from PnP Device ID
        /// </summary>
        public string ExtractVID(string pnpDeviceId)
        {
            try
            {
                var match = Regex.Match(pnpDeviceId, @"VID_([0-9A-F]{4})", RegexOptions.IgnoreCase);
                return match.Success ? match.Groups[1].Value : null;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Extract Product ID from PnP Device ID
        /// </summary>
        public string ExtractPID(string pnpDeviceId)
        {
            try
            {
                var match = Regex.Match(pnpDeviceId, @"PID_([0-9A-F]{4})", RegexOptions.IgnoreCase);
                return match.Success ? match.Groups[1].Value : null;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Extract Revision from PnP Device ID (if present)
        /// </summary>
        public string ExtractREV(string pnpDeviceId)
        {
            try
            {
                var match = Regex.Match(pnpDeviceId, @"REV_([0-9A-F]{4})", RegexOptions.IgnoreCase);
                return match.Success ? match.Groups[1].Value : null;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Check if a Hardware ID matches a pattern (supports wildcards)
        /// </summary>
        public bool MatchesPattern(string hardwareId, string pattern)
        {
            try
            {
                if (string.IsNullOrEmpty(hardwareId) || string.IsNullOrEmpty(pattern))
                {
                    return false;
                }

                // Exact match
                if (hardwareId.Equals(pattern, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }

                // Wildcard match (e.g., USB\VID_046D* matches USB\VID_046D&PID_C52B)
                var regexPattern = "^" + Regex.Escape(pattern).Replace("\\*", ".*") + "$";
                return Regex.IsMatch(hardwareId, regexPattern, RegexOptions.IgnoreCase);
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error matching pattern: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Validate Hardware ID format
        /// </summary>
        public bool IsValidHardwareId(string hardwareId)
        {
            try
            {
                if (string.IsNullOrEmpty(hardwareId))
                {
                    return false;
                }

                // Should start with USB\ and contain VID_
                return hardwareId.StartsWith("USB\\", StringComparison.OrdinalIgnoreCase) &&
                       hardwareId.Contains("VID_");
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Get best matching Hardware ID (most specific)
        /// </summary>
        public string GetBestMatchingHardwareId(string pnpDeviceId)
        {
            var variations = GenerateHardwareIdVariations(pnpDeviceId);
            
            // Return most specific variation (with REV if available, otherwise VID&PID)
            return variations.Count > 0 ? variations[0] : ConvertPnPIdToHardwareId(pnpDeviceId);
        }
    }
}

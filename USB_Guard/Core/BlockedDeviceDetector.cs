using System;
using System.Management;
using System.Collections.Generic;
using System.Linq;

namespace USB_Guard.Core
{
    /// <summary>
    /// Detects USB devices blocked by Windows Device Installation policies
    /// ConfigManagerErrorCode=22 indicates device is disabled by Windows policy
    /// </summary>
    public class BlockedDeviceDetector
    {
        private readonly SecurityLogger _logger;
        private readonly HardwareIDConverter _hardwareIdConverter;

        public BlockedDeviceDetector()
        {
            _logger = new SecurityLogger();
            _hardwareIdConverter = new HardwareIDConverter();
        }

        /// <summary>
        /// Check if a specific device is blocked by Windows policy
        /// </summary>
        public bool IsDeviceBlocked(string pnpDeviceId)
        {
            try
            {
                if (string.IsNullOrEmpty(pnpDeviceId))
                {
                    return false;
                }

                // Query WMI for device status
                var query = $"SELECT * FROM Win32_PnPEntity WHERE DeviceID = '{pnpDeviceId.Replace("\\", "\\\\")}'";
                
                using (var searcher = new ManagementObjectSearcher(query))
                {
                    foreach (ManagementObject device in searcher.Get())
                    {
                        var errorCode = device["ConfigManagerErrorCode"];
                        
                        if (errorCode != null)
                        {
                            uint code = Convert.ToUInt32(errorCode);
                            
                            // Code 22 = This device is disabled
                            // Code 28 = The drivers for this device are not installed
                            if (code == 22 || code == 28)
                            {
                                _logger.LogInfo($"Device blocked by policy: {pnpDeviceId} (Error Code: {code})");
                                return true;
                            }
                        }
                    }
                }
                
                return false;
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error checking if device is blocked: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Get all USB devices currently blocked by Windows policy
        /// </summary>
        public List<BlockedDeviceInfo> GetBlockedUSBDevices()
        {
            var blockedDevices = new List<BlockedDeviceInfo>();
            
            try
            {
                // Query all USB devices with error codes
                var query = "SELECT * FROM Win32_PnPEntity WHERE DeviceID LIKE 'USB%'";
                
                using (var searcher = new ManagementObjectSearcher(query))
                {
                    foreach (ManagementObject device in searcher.Get())
                    {
                        try
                        {
                            var errorCode = device["ConfigManagerErrorCode"];
                            
                            if (errorCode != null)
                            {
                                uint code = Convert.ToUInt32(errorCode);
                                
                                // Code 22 = Device disabled by policy
                                // Code 28 = Driver not installed (could be policy-blocked)
                                if (code == 22 || code == 28)
                                {
                                    var deviceId = device["DeviceID"]?.ToString();
                                    var name = device["Name"]?.ToString();
                                    var description = device["Description"]?.ToString();
                                    
                                    if (!string.IsNullOrEmpty(deviceId))
                                    {
                                        var blockedDevice = new BlockedDeviceInfo
                                        {
                                            PnPDeviceID = deviceId,
                                            Name = name ?? "Unknown Device",
                                            Description = description ?? "Unknown",
                                            ErrorCode = code,
                                            HardwareID = _hardwareIdConverter.ConvertPnPIdToHardwareId(deviceId),
                                            DetectedTime = DateTime.Now
                                        };
                                        
                                        blockedDevices.Add(blockedDevice);
                                        _logger.LogInfo($"Found blocked device: {name} ({deviceId}) - Error Code: {code}");
                                    }
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            _logger.LogWarning($"Error processing device: {ex.Message}");
                        }
                    }
                }
                
                _logger.LogInfo($"Found {blockedDevices.Count} blocked USB devices");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error getting blocked devices: {ex.Message}");
            }
            
            return blockedDevices;
        }

        /// <summary>
        /// Monitor for new devices being blocked by policy (real-time)
        /// </summary>
        public void StartMonitoring(Action<BlockedDeviceInfo> onDeviceBlocked)
        {
            try
            {
                // WMI event query for device modifications
                var query = new WqlEventQuery(
                    "SELECT * FROM __InstanceModificationEvent WITHIN 2 WHERE TargetInstance ISA 'Win32_PnPEntity' AND TargetInstance.DeviceID LIKE 'USB%'"
                );
                
                var watcher = new ManagementEventWatcher(query);
                
                watcher.EventArrived += (sender, args) =>
                {
                    try
                    {
                        var targetInstance = (ManagementBaseObject)args.NewEvent["TargetInstance"];
                        var errorCode = targetInstance["ConfigManagerErrorCode"];
                        
                        if (errorCode != null)
                        {
                            uint code = Convert.ToUInt32(errorCode);
                            
                            if (code == 22 || code == 28)
                            {
                                var deviceId = targetInstance["DeviceID"]?.ToString();
                                var name = targetInstance["Name"]?.ToString();
                                var description = targetInstance["Description"]?.ToString();
                                
                                if (!string.IsNullOrEmpty(deviceId))
                                {
                                    var blockedDevice = new BlockedDeviceInfo
                                    {
                                        PnPDeviceID = deviceId,
                                        Name = name ?? "Unknown Device",
                                        Description = description ?? "Unknown",
                                        ErrorCode = code,
                                        HardwareID = _hardwareIdConverter.ConvertPnPIdToHardwareId(deviceId),
                                        DetectedTime = DateTime.Now
                                    };
                                    
                                    _logger.LogWarning($"Device blocked by policy: {name} ({deviceId})");
                                    onDeviceBlocked?.Invoke(blockedDevice);
                                }
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError($"Error in blocked device monitor: {ex.Message}");
                    }
                };
                
                watcher.Start();
                _logger.LogInfo("Started monitoring for blocked devices");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error starting blocked device monitor: {ex.Message}");
            }
        }

        /// <summary>
        /// Get device error description
        /// </summary>
        public string GetErrorDescription(uint errorCode)
        {
            switch (errorCode)
            {
                case 0:
                    return "Device is working properly";
                case 1:
                    return "Device is not configured correctly";
                case 10:
                    return "Device cannot start";
                case 12:
                    return "Device cannot find enough free resources";
                case 18:
                    return "Device needs to be reinstalled";
                case 22:
                    return "Device is disabled (Windows policy)";
                case 28:
                    return "Drivers are not installed (possibly blocked)";
                case 31:
                    return "Device is not working properly";
                default:
                    return $"Unknown error code: {errorCode}";
            }
        }

        /// <summary>
        /// Check if any USB devices are currently blocked
        /// </summary>
        public bool HasBlockedDevices()
        {
            return GetBlockedUSBDevices().Count > 0;
        }
    }

    /// <summary>
    /// Information about a blocked USB device
    /// </summary>
    public class BlockedDeviceInfo
    {
        public string PnPDeviceID { get; set; }
        public string Name { get; set; }
        public string Description { get; set; }
        public uint ErrorCode { get; set; }
        public string HardwareID { get; set; }
        public DateTime DetectedTime { get; set; }

        public override string ToString()
        {
            return $"{Name} (Hardware ID: {HardwareID}) - Error Code: {ErrorCode}";
        }
    }
}

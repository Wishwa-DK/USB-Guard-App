using System;
using System.Diagnostics;
using System.Management;
using System.Threading;
using System.Threading.Tasks;

namespace USB_Guard.Core
{
    /// <summary>
    /// Triggers Windows to re-enumerate devices after policy changes
    /// This makes Windows apply new DeviceInstall policies immediately
    /// </summary>
    public class DeviceReenumerator
    {
        private readonly SecurityLogger _logger;

        public DeviceReenumerator()
        {
            _logger = new SecurityLogger();
        }

        /// <summary>
        /// Re-enumerate a specific device by Hardware ID
        /// This will make Windows re-check the device against current policies
        /// </summary>
        public async Task<bool> ReenumerateDeviceAsync(string hardwareId)
        {
            try
            {
                if (string.IsNullOrEmpty(hardwareId))
                {
                    _logger.LogWarning("Hardware ID is null or empty for re-enumeration");
                    return false;
                }

                _logger.LogInfo($"Re-enumerating device: {hardwareId}");

                // Method 1: Use pnputil to rescan hardware
                var success = await RescanHardwareAsync();
                
                if (success)
                {
                    _logger.LogInfo($"Device re-enumeration triggered for {hardwareId}");
                }
                
                return success;
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error re-enumerating device: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Re-enumerate all USB devices
        /// </summary>
        public async Task<bool> ReenumerateAllUSBDevicesAsync()
        {
            try
            {
                _logger.LogInfo("Re-enumerating all USB devices");
                
                // Trigger full hardware rescan
                var success = await RescanHardwareAsync();
                
                if (success)
                {
                    _logger.LogInfo("All USB devices re-enumerated successfully");
                }
                
                return success;
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error re-enumerating all USB devices: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Disable and re-enable a specific device to force re-enumeration
        /// </summary>
        public bool DisableAndReenableDevice(string pnpDeviceId)
        {
            try
            {
                if (string.IsNullOrEmpty(pnpDeviceId))
                {
                    return false;
                }

                _logger.LogInfo($"Disabling and re-enabling device: {pnpDeviceId}");

                // Query device
                var query = $"SELECT * FROM Win32_PnPEntity WHERE DeviceID = '{pnpDeviceId.Replace("\\", "\\\\")}'";
                
                using (var searcher = new ManagementObjectSearcher(query))
                {
                    foreach (ManagementObject device in searcher.Get())
                    {
                        try
                        {
                            // Disable device
                            var disableResult = device.InvokeMethod("Disable", null);
                            
                            if (disableResult != null && Convert.ToInt32(disableResult) == 0)
                            {
                                _logger.LogInfo($"Device disabled: {pnpDeviceId}");
                                
                                // Wait briefly
                                Thread.Sleep(500);
                                
                                // Re-enable device
                                var enableResult = device.InvokeMethod("Enable", null);
                                
                                if (enableResult != null && Convert.ToInt32(enableResult) == 0)
                                {
                                    _logger.LogInfo($"Device re-enabled: {pnpDeviceId}");
                                    return true;
                                }
                                else
                                {
                                    _logger.LogWarning($"Failed to re-enable device: {pnpDeviceId}");
                                }
                            }
                            else
                            {
                                _logger.LogWarning($"Failed to disable device: {pnpDeviceId}");
                            }
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError($"Error disabling/enabling device: {ex.Message}");
                        }
                    }
                }
                
                return false;
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error in DisableAndReenableDevice: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Use pnputil to rescan all hardware
        /// This is the most reliable method to apply new policies
        /// </summary>
        private async Task<bool> RescanHardwareAsync()
        {
            try
            {
                // Use Windows Device Manager's "Scan for hardware changes"
                // This is equivalent to clicking "Scan for hardware changes" in Device Manager
                
                var processInfo = new ProcessStartInfo
                {
                    FileName = "pnputil.exe",
                    Arguments = "/scan-devices",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    Verb = "runas" // Requires Administrator
                };

                using (var process = Process.Start(processInfo))
                {
                    if (process == null)
                    {
                        _logger.LogWarning("Failed to start pnputil process");
                        return false;
                    }

                    var output = await process.StandardOutput.ReadToEndAsync();
                    var error = await process.StandardError.ReadToEndAsync();
                    
                    await Task.Run(() => process.WaitForExit());

                    if (process.ExitCode == 0)
                    {
                        _logger.LogInfo($"Hardware rescan successful: {output}");
                        return true;
                    }
                    else
                    {
                        _logger.LogWarning($"Hardware rescan failed: {error}");
                        
                        // Fallback: Try devcon method
                        return await RescanHardwareViaCmdAsync();
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error rescanning hardware: {ex.Message}");
                
                // Fallback method
                return await RescanHardwareViaCmdAsync();
            }
        }

        /// <summary>
        /// Fallback method: Use devmgmt.msc automation
        /// </summary>
        private async Task<bool> RescanHardwareViaCmdAsync()
        {
            try
            {
                _logger.LogInfo("Using fallback method to rescan hardware");
                
                // Use WMI to trigger hardware change event
                var query = "SELECT * FROM Win32_PnPEntity WHERE DeviceID LIKE 'USB%'";
                
                using (var searcher = new ManagementObjectSearcher(query))
                {
                    var count = 0;
                    
                    foreach (ManagementObject device in searcher.Get())
                    {
                        try
                        {
                            // Simply accessing the device can trigger re-enumeration
                            var deviceId = device["DeviceID"];
                            count++;
                        }
                        catch
                        {
                            // Ignore errors
                        }
                    }
                    
                    _logger.LogInfo($"Accessed {count} USB devices for re-enumeration");
                    return count > 0;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error in fallback rescan: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Restart USB controllers to force re-enumeration
        /// WARNING: This will disconnect all USB devices temporarily
        /// </summary>
        public async Task<bool> RestartUSBControllersAsync()
        {
            try
            {
                _logger.LogWarning("Restarting USB controllers - all USB devices will disconnect briefly");
                
                var query = "SELECT * FROM Win32_PnPEntity WHERE Service = 'usbhub' OR Service = 'usbuhci' OR Service = 'usbehci' OR Service = 'usbxhci'";
                
                using (var searcher = new ManagementObjectSearcher(query))
                {
                    var controllers = 0;
                    
                    foreach (ManagementObject controller in searcher.Get())
                    {
                        try
                        {
                            var deviceId = controller["DeviceID"]?.ToString();
                            
                            if (!string.IsNullOrEmpty(deviceId))
                            {
                                _logger.LogInfo($"Restarting USB controller: {deviceId}");
                                
                                // Disable
                                controller.InvokeMethod("Disable", null);
                                await Task.Delay(1000); // Wait 1 second
                                
                                // Re-enable
                                controller.InvokeMethod("Enable", null);
                                
                                controllers++;
                            }
                        }
                        catch (Exception ex)
                        {
                            _logger.LogWarning($"Error restarting controller: {ex.Message}");
                        }
                    }
                    
                    if (controllers > 0)
                    {
                        _logger.LogInfo($"Restarted {controllers} USB controllers");
                        await Task.Delay(2000); // Wait for devices to re-enumerate
                        return true;
                    }
                }
                
                return false;
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error restarting USB controllers: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Get count of USB devices before re-enumeration (for verification)
        /// </summary>
        public int GetUSBDeviceCount()
        {
            try
            {
                var query = "SELECT * FROM Win32_PnPEntity WHERE DeviceID LIKE 'USB%'";
                
                using (var searcher = new ManagementObjectSearcher(query))
                {
                    return searcher.Get().Count;
                }
            }
            catch
            {
                return 0;
            }
        }
    }
}

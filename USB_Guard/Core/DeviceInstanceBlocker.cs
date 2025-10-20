using System;
using System.Management;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

namespace USB_Guard.Core
{
    /// <summary>
    /// USB Device Instance Blocking - Provides granular per-device control
    /// More accurate than driver-level blocking - blocks specific device instances by PnP Device ID
    /// Each physical device gets a unique instance ID making it impossible to bypass with identical devices
    /// </summary>
    public class DeviceInstanceBlocker
    {
        private readonly SecurityLogger _logger;

        #region SetupAPI P/Invoke Declarations

        // Device information set flags
        private const uint DIGCF_PRESENT = 0x00000002;
        private const uint DIGCF_ALLCLASSES = 0x00000004;

        // Device registry property keys
        private const uint SPDRP_DEVICEDESC = 0x00000000;
        private const uint SPDRP_HARDWAREID = 0x00000001;
        private const uint SPDRP_FRIENDLYNAME = 0x0000000C;

        // Device state change action
        private const uint DICS_ENABLE = 0x00000001;
        private const uint DICS_DISABLE = 0x00000002;

        // Device state change scope
        private const uint DICS_FLAG_GLOBAL = 0x00000001;
        private const uint DICS_FLAG_CONFIGSPECIFIC = 0x00000002;

        // Error codes
        private const int ERROR_NO_MORE_ITEMS = 259;
        private const int ERROR_INSUFFICIENT_BUFFER = 122;

        [StructLayout(LayoutKind.Sequential)]
        private struct SP_DEVINFO_DATA
        {
            public uint cbSize;
            public Guid ClassGuid;
            public uint DevInst;
            public IntPtr Reserved;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SP_CLASSINSTALL_HEADER
        {
            public uint cbSize;
            public uint InstallFunction;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SP_PROPCHANGE_PARAMS
        {
            public SP_CLASSINSTALL_HEADER ClassInstallHeader;
            public uint StateChange;
            public uint Scope;
            public uint HwProfile;
        }

        [DllImport("setupapi.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern IntPtr SetupDiGetClassDevs(
            IntPtr ClassGuid,
            string Enumerator,
            IntPtr hwndParent,
            uint Flags);

        [DllImport("setupapi.dll", SetLastError = true)]
        private static extern bool SetupDiEnumDeviceInfo(
            IntPtr DeviceInfoSet,
            uint MemberIndex,
            ref SP_DEVINFO_DATA DeviceInfoData);

        [DllImport("setupapi.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool SetupDiGetDeviceInstanceId(
            IntPtr DeviceInfoSet,
            ref SP_DEVINFO_DATA DeviceInfoData,
            StringBuilder DeviceInstanceId,
            uint DeviceInstanceIdSize,
            out uint RequiredSize);

        [DllImport("setupapi.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool SetupDiGetDeviceRegistryProperty(
            IntPtr DeviceInfoSet,
            ref SP_DEVINFO_DATA DeviceInfoData,
            uint Property,
            out uint PropertyRegDataType,
            byte[] PropertyBuffer,
            uint PropertyBufferSize,
            out uint RequiredSize);

        [DllImport("setupapi.dll", SetLastError = true)]
        private static extern bool SetupDiSetClassInstallParams(
            IntPtr DeviceInfoSet,
            ref SP_DEVINFO_DATA DeviceInfoData,
            ref SP_PROPCHANGE_PARAMS ClassInstallParams,
            uint ClassInstallParamsSize);

        [DllImport("setupapi.dll", SetLastError = true)]
        private static extern bool SetupDiChangeState(
            IntPtr DeviceInfoSet,
            ref SP_DEVINFO_DATA DeviceInfoData);

        [DllImport("setupapi.dll", SetLastError = true)]
        private static extern bool SetupDiDestroyDeviceInfoList(IntPtr DeviceInfoSet);

        private static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

        #endregion

        public DeviceInstanceBlocker()
        {
            _logger = new SecurityLogger();
        }

        /// <summary>
        /// Block a specific USB device instance - Most accurate blocking method
        /// Disables the exact physical device by its unique PnP Device Instance ID
        /// </summary>
        public async Task<bool> BlockDeviceInstance(string pnpDeviceId)
        {
            return await Task.Run(() =>
            {
                try
                {
                    if (string.IsNullOrEmpty(pnpDeviceId))
                    {
                        _logger.LogError("Cannot block device: PnP Device ID is null or empty");
                        return false;
                    }

                    _logger.LogInfo($"Attempting to block device instance: {pnpDeviceId}");

                    // Get device information set for all devices
                    IntPtr deviceInfoSet = SetupDiGetClassDevs(
                        IntPtr.Zero,
                        "USB",
                        IntPtr.Zero,
                        DIGCF_PRESENT | DIGCF_ALLCLASSES);

                    if (deviceInfoSet == INVALID_HANDLE_VALUE)
                    {
                        _logger.LogError($"Failed to get device info set. Error: {Marshal.GetLastWin32Error()}");
                        return false;
                    }

                    try
                    {
                        SP_DEVINFO_DATA deviceInfoData = new SP_DEVINFO_DATA();
                        deviceInfoData.cbSize = (uint)Marshal.SizeOf(typeof(SP_DEVINFO_DATA));

                        uint memberIndex = 0;
                        bool deviceFound = false;

                        // Enumerate all USB devices to find our target
                        while (SetupDiEnumDeviceInfo(deviceInfoSet, memberIndex, ref deviceInfoData))
                        {
                            StringBuilder instanceId = new StringBuilder(256);
                            uint requiredSize;

                            // Get the device instance ID
                            if (SetupDiGetDeviceInstanceId(deviceInfoSet, ref deviceInfoData, instanceId, (uint)instanceId.Capacity, out requiredSize))
                            {
                                string currentInstanceId = instanceId.ToString();

                                // Check if this is our target device
                                if (currentInstanceId.Equals(pnpDeviceId, StringComparison.OrdinalIgnoreCase))
                                {
                                    deviceFound = true;
                                    _logger.LogInfo($"Found target device: {currentInstanceId}");

                                    // Disable the device instance
                                    bool disableResult = ChangeDeviceState(deviceInfoSet, ref deviceInfoData, DICS_DISABLE);

                                    if (disableResult)
                                    {
                                        _logger.LogWarning($"✓ Device instance BLOCKED: {pnpDeviceId}");
                                        return true;
                                    }
                                    else
                                    {
                                        _logger.LogError($"Failed to disable device instance: {pnpDeviceId}");
                                        return false;
                                    }
                                }
                            }

                            memberIndex++;
                        }

                        if (!deviceFound)
                        {
                            _logger.LogWarning($"Device instance not found: {pnpDeviceId}");
                            return false;
                        }
                    }
                    finally
                    {
                        SetupDiDestroyDeviceInfoList(deviceInfoSet);
                    }

                    return false;
                }
                catch (Exception ex)
                {
                    _logger.LogError($"Error blocking device instance: {ex.Message}");
                    return false;
                }
            });
        }

        /// <summary>
        /// Unblock (enable) a specific USB device instance
        /// Enables the exact physical device by its unique PnP Device Instance ID
        /// </summary>
        public async Task<bool> UnblockDeviceInstance(string pnpDeviceId)
        {
            return await Task.Run(() =>
            {
                try
                {
                    if (string.IsNullOrEmpty(pnpDeviceId))
                    {
                        _logger.LogError("Cannot unblock device: PnP Device ID is null or empty");
                        return false;
                    }

                    _logger.LogInfo($"Attempting to unblock device instance: {pnpDeviceId}");

                    // Get device information set for all devices
                    IntPtr deviceInfoSet = SetupDiGetClassDevs(
                        IntPtr.Zero,
                        "USB",
                        IntPtr.Zero,
                        DIGCF_PRESENT | DIGCF_ALLCLASSES);

                    if (deviceInfoSet == INVALID_HANDLE_VALUE)
                    {
                        _logger.LogError($"Failed to get device info set. Error: {Marshal.GetLastWin32Error()}");
                        return false;
                    }

                    try
                    {
                        SP_DEVINFO_DATA deviceInfoData = new SP_DEVINFO_DATA();
                        deviceInfoData.cbSize = (uint)Marshal.SizeOf(typeof(SP_DEVINFO_DATA));

                        uint memberIndex = 0;
                        bool deviceFound = false;

                        // Enumerate all USB devices to find our target
                        while (SetupDiEnumDeviceInfo(deviceInfoSet, memberIndex, ref deviceInfoData))
                        {
                            StringBuilder instanceId = new StringBuilder(256);
                            uint requiredSize;

                            // Get the device instance ID
                            if (SetupDiGetDeviceInstanceId(deviceInfoSet, ref deviceInfoData, instanceId, (uint)instanceId.Capacity, out requiredSize))
                            {
                                string currentInstanceId = instanceId.ToString();

                                // Check if this is our target device
                                if (currentInstanceId.Equals(pnpDeviceId, StringComparison.OrdinalIgnoreCase))
                                {
                                    deviceFound = true;
                                    _logger.LogInfo($"Found target device: {currentInstanceId}");

                                    // Enable the device instance
                                    bool enableResult = ChangeDeviceState(deviceInfoSet, ref deviceInfoData, DICS_ENABLE);

                                    if (enableResult)
                                    {
                                        _logger.LogInfo($"✓ Device instance UNBLOCKED: {pnpDeviceId}");
                                        return true;
                                    }
                                    else
                                    {
                                        _logger.LogError($"Failed to enable device instance: {pnpDeviceId}");
                                        return false;
                                    }
                                }
                            }

                            memberIndex++;
                        }

                        if (!deviceFound)
                        {
                            _logger.LogWarning($"Device instance not found: {pnpDeviceId}");
                            return false;
                        }
                    }
                    finally
                    {
                        SetupDiDestroyDeviceInfoList(deviceInfoSet);
                    }

                    return false;
                }
                catch (Exception ex)
                {
                    _logger.LogError($"Error unblocking device instance: {ex.Message}");
                    return false;
                }
            });
        }

        /// <summary>
        /// Check if a specific device instance is currently blocked
        /// </summary>
        public bool IsDeviceInstanceBlocked(string pnpDeviceId)
        {
            try
            {
                if (string.IsNullOrEmpty(pnpDeviceId))
                {
                    return false;
                }

                // Use WMI to check device status
                var query = $"SELECT * FROM Win32_PnPEntity WHERE DeviceID = '{pnpDeviceId.Replace("\\", "\\\\")}'";

                using (var searcher = new ManagementObjectSearcher(query))
                {
                    foreach (ManagementObject device in searcher.Get())
                    {
                        var errorCode = device["ConfigManagerErrorCode"];

                        if (errorCode != null)
                        {
                            uint code = Convert.ToUInt32(errorCode);

                            // Code 22 = Device is disabled
                            if (code == 22)
                            {
                                return true;
                            }
                        }
                    }
                }

                return false;
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error checking device instance status: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Get detailed information about a device instance
        /// </summary>
        public DeviceInstanceInfo GetDeviceInstanceInfo(string pnpDeviceId)
        {
            try
            {
                if (string.IsNullOrEmpty(pnpDeviceId))
                {
                    return null;
                }

                IntPtr deviceInfoSet = SetupDiGetClassDevs(
                    IntPtr.Zero,
                    "USB",
                    IntPtr.Zero,
                    DIGCF_PRESENT | DIGCF_ALLCLASSES);

                if (deviceInfoSet == INVALID_HANDLE_VALUE)
                {
                    return null;
                }

                try
                {
                    SP_DEVINFO_DATA deviceInfoData = new SP_DEVINFO_DATA();
                    deviceInfoData.cbSize = (uint)Marshal.SizeOf(typeof(SP_DEVINFO_DATA));

                    uint memberIndex = 0;

                    while (SetupDiEnumDeviceInfo(deviceInfoSet, memberIndex, ref deviceInfoData))
                    {
                        StringBuilder instanceId = new StringBuilder(256);
                        uint requiredSize;

                        if (SetupDiGetDeviceInstanceId(deviceInfoSet, ref deviceInfoData, instanceId, (uint)instanceId.Capacity, out requiredSize))
                        {
                            string currentInstanceId = instanceId.ToString();

                            if (currentInstanceId.Equals(pnpDeviceId, StringComparison.OrdinalIgnoreCase))
                            {
                                // Get device properties
                                string friendlyName = GetDeviceProperty(deviceInfoSet, ref deviceInfoData, SPDRP_FRIENDLYNAME);
                                string description = GetDeviceProperty(deviceInfoSet, ref deviceInfoData, SPDRP_DEVICEDESC);
                                string hardwareId = GetDeviceProperty(deviceInfoSet, ref deviceInfoData, SPDRP_HARDWAREID);

                                return new DeviceInstanceInfo
                                {
                                    PnPDeviceID = currentInstanceId,
                                    FriendlyName = friendlyName ?? "Unknown Device",
                                    Description = description ?? "Unknown",
                                    HardwareID = hardwareId ?? "Unknown",
                                    IsBlocked = IsDeviceInstanceBlocked(currentInstanceId)
                                };
                            }
                        }

                        memberIndex++;
                    }
                }
                finally
                {
                    SetupDiDestroyDeviceInfoList(deviceInfoSet);
                }

                return null;
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error getting device instance info: {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// Change device state (enable/disable)
        /// </summary>
        private bool ChangeDeviceState(IntPtr deviceInfoSet, ref SP_DEVINFO_DATA deviceInfoData, uint stateChange)
        {
            try
            {
                SP_PROPCHANGE_PARAMS propChangeParams = new SP_PROPCHANGE_PARAMS();
                propChangeParams.ClassInstallHeader.cbSize = (uint)Marshal.SizeOf(typeof(SP_CLASSINSTALL_HEADER));
                propChangeParams.ClassInstallHeader.InstallFunction = 0x00000012; // DIF_PROPERTYCHANGE
                propChangeParams.StateChange = stateChange;
                propChangeParams.Scope = DICS_FLAG_GLOBAL;
                propChangeParams.HwProfile = 0;

                // Set the class install parameters
                if (!SetupDiSetClassInstallParams(deviceInfoSet, ref deviceInfoData, ref propChangeParams, (uint)Marshal.SizeOf(propChangeParams)))
                {
                    int error = Marshal.GetLastWin32Error();
                    _logger.LogError($"SetupDiSetClassInstallParams failed. Error: {error}");
                    return false;
                }

                // Apply the state change
                if (!SetupDiChangeState(deviceInfoSet, ref deviceInfoData))
                {
                    int error = Marshal.GetLastWin32Error();
                    _logger.LogError($"SetupDiChangeState failed. Error: {error}");
                    return false;
                }

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error changing device state: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Get a device registry property
        /// </summary>
        private string GetDeviceProperty(IntPtr deviceInfoSet, ref SP_DEVINFO_DATA deviceInfoData, uint property)
        {
            try
            {
                byte[] buffer = new byte[256];
                uint propertyRegDataType;
                uint requiredSize;

                if (SetupDiGetDeviceRegistryProperty(deviceInfoSet, ref deviceInfoData, property, out propertyRegDataType, buffer, (uint)buffer.Length, out requiredSize))
                {
                    return Encoding.Unicode.GetString(buffer).TrimEnd('\0');
                }

                return null;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Verify if SetupAPI is accessible (requires Administrator privileges)
        /// </summary>
        public bool CanAccessSetupAPI()
        {
            try
            {
                IntPtr deviceInfoSet = SetupDiGetClassDevs(
                    IntPtr.Zero,
                    "USB",
                    IntPtr.Zero,
                    DIGCF_PRESENT | DIGCF_ALLCLASSES);

                if (deviceInfoSet != INVALID_HANDLE_VALUE)
                {
                    SetupDiDestroyDeviceInfoList(deviceInfoSet);
                    _logger.LogInfo("SetupAPI access verification successful");
                    return true;
                }

                int error = Marshal.GetLastWin32Error();
                _logger.LogWarning($"SetupAPI access failed: Win32 Error {error}");
                return false;
            }
            catch (Exception ex)
            {
                _logger.LogError($"SetupAPI access check exception: {ex.Message}");
                return false;
            }
        }
    }

    /// <summary>
    /// Device instance information
    /// </summary>
    public class DeviceInstanceInfo
    {
        public string PnPDeviceID { get; set; }
        public string FriendlyName { get; set; }
        public string Description { get; set; }
        public string HardwareID { get; set; }
        public bool IsBlocked { get; set; }

        public override string ToString()
        {
            return $"{FriendlyName} - {PnPDeviceID} (Blocked: {IsBlocked})";
        }
    }
}

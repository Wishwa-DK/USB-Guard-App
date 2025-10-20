# USB Guard App

A comprehensive USB device security management application for Windows that provides advanced protection against unauthorized USB devices.

## Features

### Core Security Features
- **Device Whitelisting**: Manage allowed USB devices through whitelist management
- **Zero Trust Security**: Block all unknown devices by default
- **Real-time Monitoring**: Continuous monitoring of USB device connections
- **Device Authentication**: Multiple authentication methods for different device types

### Device Types Supported
- **Storage Devices**: Full scanning and security analysis
- **HID Devices**: Human Interface Devices with specialized authentication
- **Keyboards**: Dedicated keyboard authentication dialog
- **Mice**: Mouse-specific authentication handling

### Advanced Features
- **Registry Backup Management**: Automatic backup of system registry changes
- **Session Authentication Cache**: Temporary authentication for trusted sessions
- **Security Logging**: Comprehensive logging of all security events
- **System Tray Integration**: Minimalistic system tray management
- **Startup Management**: Automatic startup configuration
- **Device Re-enumeration**: Advanced device state management

## Architecture

### Core Components
- `USBDeviceManager_Step2.cs` - Primary device management logic
- `USBDeviceManager_ZeroTrust.cs` - Zero trust security implementation
- `DeviceAuthenticator.cs` - Authentication service
- `SecurityLogger.cs` - Security event logging
- `WhitelistManager.cs` - Whitelist management system

### Dialog Systems
- `HIDAuthenticationDialog` - HID device authentication
- `KeyboardAuthenticationDialog` - Keyboard-specific authentication
- `MouseAuthenticationDialog` - Mouse-specific authentication
- `StorageScanResultDialog` - Storage device scan results

### Models
- `USBDeviceInfo.cs` - Core device information model
- `DeviceRule.cs` - Security rule definitions
- `SecurityEvent.cs` - Security event data structure
- `StorageScanResult.cs` - Storage scanning results

## Installation

### Prerequisites
- Windows 10/11
- .NET Framework 4.7.2 or higher
- Administrator privileges (required for USB device management)

### Building from Source
1. Clone this repository
2. Open `USB_Guard.sln` in Visual Studio
3. Build the solution in Release mode
4. Run as Administrator

## Configuration

### Whitelist Configuration
Edit `Config/whitelist.txt` to add trusted devices:
```
VID_1234&PID_5678  # Example device
VID_ABCD&PID_EFGH  # Another trusted device
```

### Blacklist Configuration
Edit `Config/blacklist.txt` to add blocked devices:
```
VID_XXXX&PID_YYYY  # Blocked device
```

## Usage

1. **Launch Application**: Run USB_Guard.exe as Administrator
2. **System Tray**: The application runs in the system tray
3. **Device Connection**: When a USB device is connected:
   - Known whitelisted devices are allowed automatically
   - Unknown devices trigger authentication dialogs
   - Blacklisted devices are blocked immediately

### Authentication Process
- **Storage Devices**: Scan for malware and verify safety
- **HID Devices**: Hardware ID verification and user confirmation
- **Keyboards/Mice**: Specialized authentication for input devices

## Security Features

### Zero Trust Model
- All devices are untrusted by default
- Explicit approval required for each device type
- Session-based temporary trust for productivity

### Logging and Monitoring
- All device events are logged
- Security events tracked with timestamps
- Failed authentication attempts recorded

### Registry Protection
- Automatic backup before device policy changes
- Rollback capability for system recovery
- Safe modification of device installation policies

## Technical Details

### Device Detection
- WMI-based device monitoring
- Hardware ID extraction and validation
- Real-time device state tracking

### Security Implementation
- Windows Device Installation policies
- Registry-based device blocking
- Service-level device management

## Disclaimer

This software is designed for legitimate security purposes. Users are responsible for compliance with local laws and regulations regarding device monitoring and access control.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Text;
using USB_Guard.Models;

namespace USB_Guard.Core
{
    public class WhitelistManager
    {
        private readonly string _configDirectory;
        private readonly string _whitelistFile;
        private readonly string _blacklistFile;
        private readonly SecurityLogger _logger;
        private List<DeviceRule> _whitelist;
        private List<DeviceRule> _blacklist;

        public WhitelistManager()
        {
            _configDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "USBGuard", "Config");
            _whitelistFile = Path.Combine(_configDirectory, "whitelist.txt");
            _blacklistFile = Path.Combine(_configDirectory, "blacklist.txt");
            _logger = new SecurityLogger();
            
            Directory.CreateDirectory(_configDirectory);
            LoadLists();
        }

        public async Task<bool> IsDeviceWhitelistedAsync(USBDeviceInfo device)
        {
            try
            {
                return await Task.Run(() =>
                {
                    return _whitelist.Any(rule => MatchesRule(device, rule));
                });
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error checking whitelist for device {device.Name}: {ex.Message}");
                return false;
            }
        }

        public async Task<bool> IsDeviceBlacklistedAsync(USBDeviceInfo device)
        {
            try
            {
                return await Task.Run(() =>
                {
                    return _blacklist.Any(rule => MatchesRule(device, rule));
                });
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error checking blacklist for device {device.Name}: {ex.Message}");
                return false;
            }
        }

        public async Task AddToWhitelistAsync(USBDeviceInfo device, string reason = "User approved")
        {
            try
            {
                var rule = new DeviceRule
                {
                    Id = Guid.NewGuid().ToString(),
                    Name = device.Name,
                    VendorId = device.VendorId,
                    ProductId = device.ProductId,
                    SerialNumber = device.SerialNumber,
                    DeviceType = device.Type,
                    CreatedDate = DateTime.Now,
                    CreatedBy = Environment.UserName,
                    Reason = reason,
                    IsEnabled = true
                };

                _whitelist.Add(rule);
                await SaveWhitelistAsync();
                
                _logger.LogSecurity($"Device added to whitelist: {device.Name} (VID: {device.VendorId}, PID: {device.ProductId}) - Reason: {reason}");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Failed to add device to whitelist: {ex.Message}");
                throw;
            }
        }

        public async Task AddToBlacklistAsync(USBDeviceInfo device, string reason = "Security threat")
        {
            try
            {
                var rule = new DeviceRule
                {
                    Id = Guid.NewGuid().ToString(),
                    Name = device.Name,
                    VendorId = device.VendorId,
                    ProductId = device.ProductId,
                    SerialNumber = device.SerialNumber,
                    DeviceType = device.Type,
                    CreatedDate = DateTime.Now,
                    CreatedBy = Environment.UserName,
                    Reason = reason,
                    IsEnabled = true
                };

                _blacklist.Add(rule);
                await SaveBlacklistAsync();
                
                _logger.LogSecurity($"Device added to blacklist: {device.Name} (VID: {device.VendorId}, PID: {device.ProductId}) - Reason: {reason}");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Failed to add device to blacklist: {ex.Message}");
                throw;
            }
        }

        public List<DeviceRule> GetWhitelist()
        {
            return new List<DeviceRule>(_whitelist);
        }

        public List<DeviceRule> GetBlacklist()
        {
            return new List<DeviceRule>(_blacklist);
        }

        private bool MatchesRule(USBDeviceInfo device, DeviceRule rule)
        {
            if (!rule.IsEnabled) return false;

            // Check VID/PID match
            bool vidMatch = string.IsNullOrEmpty(rule.VendorId) || 
                           string.Equals(device.VendorId, rule.VendorId, StringComparison.OrdinalIgnoreCase);
            
            bool pidMatch = string.IsNullOrEmpty(rule.ProductId) || 
                           string.Equals(device.ProductId, rule.ProductId, StringComparison.OrdinalIgnoreCase);

            // Check serial number match (if specified)
            bool serialMatch = string.IsNullOrEmpty(rule.SerialNumber) || 
                              string.Equals(device.SerialNumber, rule.SerialNumber, StringComparison.OrdinalIgnoreCase);

            // Check device type match (if specified)
            bool typeMatch = rule.DeviceType == USBDeviceType.Unknown || device.Type == rule.DeviceType;

            return vidMatch && pidMatch && serialMatch && typeMatch;
        }

        private void LoadLists()
        {
            try
            {
                // Load whitelist using simple text format
                if (File.Exists(_whitelistFile))
                {
                    _whitelist = LoadFromTextFile(_whitelistFile);
                }
                else
                {
                    _whitelist = new List<DeviceRule>();
                    CreateDefaultWhitelist();
                }

                // Load blacklist using simple text format
                if (File.Exists(_blacklistFile))
                {
                    _blacklist = LoadFromTextFile(_blacklistFile);
                }
                else
                {
                    _blacklist = new List<DeviceRule>();
                    CreateDefaultBlacklist();
                }

                _logger.LogInfo($"Loaded {_whitelist.Count} whitelist rules and {_blacklist.Count} blacklist rules");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Failed to load device lists: {ex.Message}");
                _whitelist = new List<DeviceRule>();
                _blacklist = new List<DeviceRule>();
            }
        }

        private List<DeviceRule> LoadFromTextFile(string filePath)
        {
            var rules = new List<DeviceRule>();
            try
            {
                var lines = File.ReadAllLines(filePath);
                foreach (var line in lines)
                {
                    if (line.StartsWith("#") || string.IsNullOrWhiteSpace(line))
                        continue;

                    var parts = line.Split('|');
                    if (parts.Length >= 6)
                    {
                        var rule = new DeviceRule
                        {
                            Id = parts[0],
                            Name = parts[1],
                            VendorId = parts[2],
                            ProductId = parts[3],
                            DeviceType = ParseDeviceType(parts[4]),
                            Reason = parts[5],
                            IsEnabled = parts.Length > 6 ? bool.Parse(parts[6]) : true,
                            CreatedBy = parts.Length > 7 ? parts[7] : "Unknown",
                            CreatedDate = parts.Length > 8 ? DateTime.Parse(parts[8]) : DateTime.Now
                        };
                        rules.Add(rule);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error loading text file {filePath}: {ex.Message}");
            }
            return rules;
        }

        private USBDeviceType ParseDeviceType(string typeString)
        {
            if (Enum.TryParse<USBDeviceType>(typeString, out var deviceType))
                return deviceType;
            return USBDeviceType.Unknown;
        }

        private void CreateDefaultWhitelist()
        {
            // Add some common trusted devices
            _whitelist.AddRange(new[]
            {
                new DeviceRule
                {
                    Id = Guid.NewGuid().ToString(),
                    Name = "Microsoft USB Devices",
                    VendorId = "045E",
                    ProductId = "",
                    DeviceType = USBDeviceType.Unknown,
                    CreatedDate = DateTime.Now,
                    CreatedBy = "System",
                    Reason = "Default trusted vendor",
                    IsEnabled = true
                },
                new DeviceRule
                {
                    Id = Guid.NewGuid().ToString(),
                    Name = "Logitech USB Devices",
                    VendorId = "046D",
                    ProductId = "",
                    DeviceType = USBDeviceType.Unknown,
                    CreatedDate = DateTime.Now,
                    CreatedBy = "System",
                    Reason = "Default trusted vendor",
                    IsEnabled = true
                }
            });
        }

        private void CreateDefaultBlacklist()
        {
            // Add known malicious device signatures
            _blacklist.AddRange(new[]
            {
                new DeviceRule
                {
                    Id = Guid.NewGuid().ToString(),
                    Name = "USB Rubber Ducky",
                    VendorId = "F000",
                    ProductId = "0001",
                    DeviceType = USBDeviceType.HID,
                    CreatedDate = DateTime.Now,
                    CreatedBy = "System",
                    Reason = "Known attack device",
                    IsEnabled = true
                },
                new DeviceRule
                {
                    Id = Guid.NewGuid().ToString(),
                    Name = "Malicious HID Device",
                    VendorId = "DEAD",
                    ProductId = "BEEF",
                    DeviceType = USBDeviceType.HID,
                    CreatedDate = DateTime.Now,
                    CreatedBy = "System",
                    Reason = "Known malicious signature",
                    IsEnabled = true
                }
            });
        }

        private async Task SaveWhitelistAsync()
        {
            try
            {
                await SaveToTextFileAsync(_whitelistFile, _whitelist);
            }
            catch (Exception ex)
            {
                _logger.LogError($"Failed to save whitelist: {ex.Message}");
                throw;
            }
        }

        private async Task SaveBlacklistAsync()
        {
            try
            {
                await SaveToTextFileAsync(_blacklistFile, _blacklist);
            }
            catch (Exception ex)
            {
                _logger.LogError($"Failed to save blacklist: {ex.Message}");
                throw;
            }
        }

        private async Task SaveToTextFileAsync(string filePath, List<DeviceRule> rules)
        {
            try
            {
                var lines = new List<string>
                {
                    "# USB Guard Device Rules",
                    "# Format: ID|Name|VendorId|ProductId|DeviceType|Reason|IsEnabled|CreatedBy|CreatedDate",
                    "#"
                };

                foreach (var rule in rules)
                {
                    var line = $"{rule.Id}|{rule.Name}|{rule.VendorId}|{rule.ProductId}|{rule.DeviceType}|{rule.Reason}|{rule.IsEnabled}|{rule.CreatedBy}|{rule.CreatedDate:yyyy-MM-dd HH:mm:ss}";
                    lines.Add(line);
                }

                await Task.Run(() => File.WriteAllLines(filePath, lines, Encoding.UTF8));
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error saving to text file {filePath}: {ex.Message}");
                throw;
            }
        }
    }
}

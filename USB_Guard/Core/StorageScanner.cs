using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Text;
using System.Text.RegularExpressions;
using System.Security.Cryptography;
using USB_Guard.Models;

namespace USB_Guard.Core
{
    /// <summary>
    /// OPTIMIZED MALWARE SCANNER - Fast & Accurate threat detection
    /// Features: Parallel scanning, smart file filtering, optimized analysis
    /// </summary>
    public class StorageScanner
    {
        private readonly SecurityLogger _logger;
        private readonly TimeSpan _maxScanTime = TimeSpan.FromMinutes(3); // Reduced to 3 minutes

        // Real-time progress callbacks
        public event Action<int, string, int, long> ProgressUpdate;
        public event Action<MaliciousFile> ThreatDetected;

        // ???????????????????????????????????????????????????????????????
        // MALWARE SIGNATURE DATABASE (Real threat detection)
        // ???????????????????????????????????????????????????????????????

        // CRITICAL: Executable and script extensions - HIGH RISK
        private static readonly HashSet<string> ExecutableExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".exe", ".com", ".bat", ".cmd", ".msi", ".scr", ".pif", ".application",
            ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".ps1", ".psm1", ".ps2", ".psc1",
            ".vb", ".vba", ".py", ".pl", ".rb", ".sh", ".bash", ".zsh", ".fish",
            ".jar", ".app", ".run", ".bin", ".elf", ".out",
            ".sys", ".drv", ".dll", ".ocx", ".cpl", ".ax",
            ".apk", ".ipa", ".dex", ".so", ".dylib"
        };

        // Office macros and dangerous documents
        private static readonly HashSet<string> MacroExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".potm",
            ".ppam", ".xlam", ".ppsm", ".sldm"
        };

        // Archive files (can hide malware)
        private static readonly HashSet<string> ArchiveExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz",
            ".cab", ".ace", ".arj", ".lzh", ".z", ".tgz", ".tbz2"
        };

        // Disk images and virtualization
        private static readonly HashSet<string> DiskImageExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".iso", ".img", ".vhd", ".vmdk", ".vdi", ".qcow2", ".dmg"
        };

        // System/config files
        private static readonly HashSet<string> SystemExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".reg", ".inf", ".cfg", ".config", ".ini", ".dat"
        };

        // Shortcuts (can execute commands)
        private static readonly HashSet<string> ShortcutExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".lnk", ".url", ".website", ".scf"
        };

        // Web/HTML files with scripts
        private static readonly HashSet<string> WebScriptExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".hta", ".htm", ".html", ".mht", ".mhtml"
        };

        // Malicious/suspicious filenames (exact match)
        private static readonly HashSet<string> MaliciousFileNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "autorun.inf", "desktop.ini", "autoplay.exe", "autostart.exe",
            "rundll32.exe", "csrss.exe", "lsass.exe", "svchost.exe", // Fake system files
            "winlogon.exe", "smss.exe", "services.exe" // Common malware names
        };

        // Suspicious filename patterns (regex)
        private static readonly List<Regex> SuspiciousPatterns = new List<Regex>
        {
            // Random hex/alphanumeric strings (8+ chars)
            new Regex(@"^[a-f0-9]{8,}\.exe$", RegexOptions.IgnoreCase),
            
            // Double extensions (document.pdf.exe)
            new Regex(@"\.(jpg|jpeg|png|gif|pdf|doc|docx|xls|xlsx|txt)\.(exe|com|scr|bat|cmd|vbs|js)$", RegexOptions.IgnoreCase),
            
            // Piracy/crack tools (high malware risk)
            new Regex(@"(crack|keygen|patch|loader|activator|generator|serial|key)", RegexOptions.IgnoreCase),
            
            // Malware terms
            new Regex(@"(backdoor|trojan|keylog|rat|bot|rootkit|ransomware|cryptolocker|worm|virus)", RegexOptions.IgnoreCase),
            
            // Suspicious system names in user locations
            new Regex(@"^(system32|win32|windows|microsoft|adobe|update|installer)\.exe$", RegexOptions.IgnoreCase),
            
            // Hidden/unicode characters
            new Regex(@"[\u200B-\u200D\uFEFF]", RegexOptions.None),
            
            // Multiple dots/spaces (obfuscation)
            new Regex(@"\.{2,}|\s{5,}", RegexOptions.None)
        };

        // Known malware file signatures (magic bytes)
        private static readonly Dictionary<byte[], string> MalwareSignatures = new Dictionary<byte[], string>
        {
            // PE executables
            { new byte[] { 0x4D, 0x5A }, "PE Executable" },
            
            // ELF executables (Linux)
            { new byte[] { 0x7F, 0x45, 0x4C, 0x46 }, "ELF Executable" },
            
            // Script file markers
            { Encoding.ASCII.GetBytes("#!"), "Shell Script" },
            { Encoding.UTF8.GetBytes("<?php"), "PHP Script" },
            
            // Java class files
            { new byte[] { 0xCA, 0xFE, 0xBA, 0xBE }, "Java Class" }
        };

        // Dangerous script content patterns
        private static readonly List<Regex> ScriptContentPatterns = new List<Regex>
        {
            // PowerShell obfuscation/download
            new Regex(@"(IEX|Invoke-Expression|DownloadString|DownloadFile|WebClient|Net\.WebClient)", RegexOptions.IgnoreCase),
            
            // VBScript/JavaScript malicious patterns
            new Regex(@"(WScript\.Shell|Shell\.Application|CreateObject.*Shell|eval\()", RegexOptions.IgnoreCase),
            
            // Command execution
            new Regex(@"(cmd\.exe|powershell\.exe|wscript\.exe|cscript\.exe|regsvr32\.exe)", RegexOptions.IgnoreCase),
            
            // Registry manipulation
            new Regex(@"(HKLM|HKCU|Software\\Microsoft\\Windows\\CurrentVersion\\Run)", RegexOptions.IgnoreCase),
            
            // Encoding/obfuscation
            new Regex(@"(base64|fromBase64|encodedcommand|-enc\s)", RegexOptions.IgnoreCase)
        };

        // Files/folders to skip
        private static readonly HashSet<string> SkipSystemFolders = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "$Recycle.Bin", "System Volume Information", "RECYCLER",
            ".Trashes", ".fseventsd", ".Spotlight-V100", ".TemporaryItems"
        };

        // Optimizations
        private const int MAX_FILE_SIZE_FOR_CONTENT_SCAN = 50 * 1024 * 1024; // 50MB limit
        private const int MAX_FILES_TO_SCAN = 10000; // Safety limit
        private const int PARALLEL_DEGREE = 4; // Parallel analysis threads

        public StorageScanner()
        {
            _logger = new SecurityLogger();
        }

        /// <summary>
        /// OPTIMIZED SCAN - Fast threat detection with parallel processing
        /// </summary>
        public async Task<StorageScanResult> ScanDriveWithProgressAsync(string driveLetter)
        {
            var result = new StorageScanResult();
            var stopwatch = Stopwatch.StartNew();
            
            using (var cts = new CancellationTokenSource(_maxScanTime))
            {
                try
                {
                    _logger.LogSecurity($"? Starting OPTIMIZED malware scan on drive {driveLetter}");
                    _logger.LogInfo("? Parallel processing enabled - Fast & accurate detection");

                    // Validate drive letter
                    if (string.IsNullOrEmpty(driveLetter))
                    {
                        result.ErrorMessage = "No drive letter provided";
                        return result;
                    }

                    if (!driveLetter.EndsWith(":\\"))
                    {
                        driveLetter = driveLetter.TrimEnd(':', '\\') + ":\\";
                    }

                    if (!Directory.Exists(driveLetter))
                    {
                        result.ErrorMessage = $"Drive {driveLetter} not accessible";
                        _logger.LogWarning($"Drive {driveLetter} not accessible");
                        return result;
                    }

                    ProgressUpdate?.Invoke(0, "Starting optimized scan...", 0, 0);

                    // PHASE 1: FAST FILE DISCOVERY (with filtering)
                    _logger.LogInfo("? Phase 1: Smart file discovery...");
                    var allFiles = await DiscoverFilesOptimizedAsync(driveLetter, result, cts.Token);
                    
                    if (allFiles.Count == 0)
                    {
                        _logger.LogSecurity("? Empty drive - No files found");
                        result.ScanCompleted = true;
                        result.ThreatsDetected = false;
                        stopwatch.Stop();
                        result.ScanDuration = stopwatch.Elapsed;
                        ProgressUpdate?.Invoke(0, "Empty drive", 0, 0);
                        return result;
                    }

                    _logger.LogInfo($"? Found {allFiles.Count} files - Starting parallel analysis");

                    // PHASE 2: PARALLEL FILE ANALYSIS (Speed optimization)
                    _logger.LogInfo("? Phase 2: Parallel threat analysis...");
                    await PerformParallelScanAsync(allFiles, result, cts.Token);

                    stopwatch.Stop();
                    result.ScanDuration = stopwatch.Elapsed;
                    result.ScanCompleted = !cts.Token.IsCancellationRequested;
                    result.ThreatsDetected = result.ThreatCount > 0;

                    // Final report
                    if (result.ThreatsDetected)
                    {
                        _logger.LogSecurity($"? MALWARE DETECTED: {result.ThreatCount} threats in {result.TotalFilesScanned} files");
                        _logger.LogSecurity($"   Critical: {result.DetectedThreats.Count(t => t.ThreatLevel == "CRITICAL")}");
                        _logger.LogSecurity($"   High: {result.DetectedThreats.Count(t => t.ThreatLevel == "HIGH")}");
                        _logger.LogSecurity($"   Medium: {result.DetectedThreats.Count(t => t.ThreatLevel == "MEDIUM")}");
                        _logger.LogSecurity($"? Scan completed in {result.ScanDuration.TotalSeconds:F1}s - BLOCKING DEVICE");
                    }
                    else
                    {
                        _logger.LogSecurity($"? CLEAN: {result.TotalFilesScanned} files scanned in {result.ScanDuration.TotalSeconds:F1}s");
                        _logger.LogSecurity($"? NO threats detected - ALLOWING DEVICE");
                    }

                    ProgressUpdate?.Invoke(result.TotalFilesScanned, "Scan completed", result.ThreatCount, result.TotalSizeBytes);
                    return result;
                }
                catch (OperationCanceledException)
                {
                    stopwatch.Stop();
                    result.ScanDuration = stopwatch.Elapsed;
                    result.ScanCompleted = false;
                    result.ErrorMessage = "Scan timeout - Maximum time exceeded";
                    result.ThreatsDetected = result.ThreatCount > 0;
                    
                    _logger.LogWarning($"?? Scan timeout - {result.TotalFilesScanned} files analyzed");
                    return result;
                }
                catch (Exception ex)
                {
                    stopwatch.Stop();
                    result.ScanDuration = stopwatch.Elapsed;
                    result.ErrorMessage = $"Scan error: {ex.Message}";
                    result.ThreatsDetected = result.ThreatCount > 0;
                    
                    _logger.LogError($"? Scan failed: {ex.Message}");
                    return result;
                }
            }
        }

        /// <summary>
        /// OPTIMIZED file discovery with smart filtering
        /// </summary>
        private async Task<List<string>> DiscoverFilesOptimizedAsync(string rootPath, StorageScanResult result, CancellationToken ct)
        {
            var files = new List<string>();
            var queue = new Queue<string>();
            queue.Enqueue(rootPath);

            int foldersProcessed = 0;

            await Task.Run(() =>
            {
                while (queue.Count > 0 && !ct.IsCancellationRequested && files.Count < MAX_FILES_TO_SCAN)
                {
                    var currentPath = queue.Dequeue();
                    foldersProcessed++;

                    try
                    {
                        // Get all files in current directory
                        var dirFiles = Directory.GetFiles(currentPath);
                        
                        foreach (var file in dirFiles)
                        {
                            // Skip very large files for performance
                            try
                            {
                                var fileInfo = new FileInfo(file);
                                if (fileInfo.Length < MAX_FILE_SIZE_FOR_CONTENT_SCAN)
                                {
                                    files.Add(file);
                                }
                                else
                                {
                                    // Still check very large files by name/extension only
                                    files.Add(file);
                                }
                            }
                            catch
                            {
                                files.Add(file); // Add anyway if can't check size
                            }
                            
                            // Safety limit
                            if (files.Count >= MAX_FILES_TO_SCAN)
                            {
                                _logger.LogWarning($"?? Reached file limit ({MAX_FILES_TO_SCAN}) - stopping discovery");
                                break;
                            }
                        }

                        // Queue subdirectories (skip system folders)
                        if (files.Count < MAX_FILES_TO_SCAN)
                        {
                            var subdirs = Directory.GetDirectories(currentPath);
                            foreach (var subdir in subdirs)
                            {
                                var dirName = Path.GetFileName(subdir);
                                if (!SkipSystemFolders.Contains(dirName))
                                {
                                    queue.Enqueue(subdir);
                                }
                            }
                        }

                        // Update progress every 5 folders
                        if (foldersProcessed % 5 == 0)
                        {
                            ProgressUpdate?.Invoke(0, $"Discovering files... ({files.Count} found)", 0, 0);
                        }
                    }
                    catch (UnauthorizedAccessException)
                    {
                        // Skip inaccessible folders silently
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning($"Error accessing {currentPath}: {ex.Message}");
                    }
                }
            }, ct);

            _logger.LogInfo($"? Scanned {foldersProcessed} folders, found {files.Count} files");
            return files;
        }

        /// <summary>
        /// PARALLEL ANALYSIS - Process multiple files simultaneously for speed
        /// </summary>
        private async Task PerformParallelScanAsync(List<string> files, StorageScanResult result, CancellationToken ct)
        {
            var lockObject = new object();
            int processedCount = 0;

            // Process files in parallel batches
            var batches = files
                .Select((file, index) => new { file, index })
                .GroupBy(x => x.index / 100) // Process 100 files per batch
                .Select(g => g.Select(x => x.file).ToList());

            foreach (var batch in batches)
            {
                if (ct.IsCancellationRequested) break;

                // Process batch in parallel (up to 4 threads)
                await Task.Run(() =>
                {
                    Parallel.ForEach(batch,
                        new ParallelOptions
                        {
                            MaxDegreeOfParallelism = PARALLEL_DEGREE,
                            CancellationToken = ct
                        },
                        filePath =>
                        {
                            try
                            {
                                AnalyzeFileOptimized(filePath, result, lockObject);

                                lock (lockObject)
                                {
                                    processedCount++;
                                    
                                    // Update progress every 10 files
                                    if (processedCount % 10 == 0)
                                    {
                                        var fileName = Path.GetFileName(filePath);
                                        var progress = (int)((processedCount * 100.0) / files.Count);
                                        ProgressUpdate?.Invoke(result.TotalFilesScanned, 
                                            $"[{progress}%] {fileName}", 
                                            result.ThreatCount, 
                                            result.TotalSizeBytes);
                                    }
                                }
                            }
                            catch (Exception ex)
                            {
                                _logger.LogWarning($"Error analyzing {filePath}: {ex.Message}");
                            }
                        });
                }, ct);
            }
        }

        /// <summary>
        /// OPTIMIZED FILE ANALYSIS - Fast multi-layer threat detection
        /// </summary>
        private void AnalyzeFileOptimized(string filePath, StorageScanResult result, object lockObject)
        {
            lock (lockObject)
            {
                result.TotalFilesScanned++;
            }

            try
            {
                var fileInfo = new FileInfo(filePath);
                if (!fileInfo.Exists) return;

                lock (lockObject)
                {
                    result.TotalSizeBytes += fileInfo.Length;
                }

                var fileName = fileInfo.Name;
                var extension = fileInfo.Extension.ToLower();
                
                string threatLevel = null;
                string threatType = null;
                string reason = null;

                // LAYER 1: FAST FILENAME ANALYSIS
                if (MaliciousFileNames.Contains(fileName))
                {
                    threatLevel = "CRITICAL";
                    threatType = "Known Malicious File";
                    reason = $"Known malware filename: {fileName}";
                }
                else if (SuspiciousPatterns.Any(p => p.IsMatch(fileName)))
                {
                    threatLevel = "HIGH";
                    threatType = "Suspicious Filename Pattern";
                    reason = "Filename matches malware pattern";
                }

                // LAYER 2: FAST EXTENSION ANALYSIS
                if (ExecutableExtensions.Contains(extension))
                {
                    if (threatLevel == null)
                    {
                        threatLevel = "HIGH";
                        threatType = "Executable File";
                        reason = $"Executable file type: {extension}";
                    }
                }
                else if (MacroExtensions.Contains(extension))
                {
                    threatLevel = threatLevel ?? "MEDIUM";
                    threatType = "Office Macro Document";
                    reason = "Document with macros (can execute code)";
                }
                else if (ShortcutExtensions.Contains(extension))
                {
                    threatLevel = threatLevel ?? "MEDIUM";
                    threatType = "Shortcut File";
                    reason = "Shortcut can execute commands";
                }
                else if (WebScriptExtensions.Contains(extension))
                {
                    threatLevel = threatLevel ?? "MEDIUM";
                    threatType = "Web Script File";
                    reason = "HTML/HTA file can execute scripts";
                }

                // LAYER 3: SELECTIVE DEEP ANALYSIS (only for suspicious files)
                if (threatLevel != null || ExecutableExtensions.Contains(extension) || IsScriptFile(extension))
                {
                    // Only analyze suspicious files deeply
                    if (fileInfo.Length > 0 && fileInfo.Length < MAX_FILE_SIZE_FOR_CONTENT_SCAN)
                    {
                        try
                        {
                            // Quick header check (synchronous for speed)
                            using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read))
                            {
                                var buffer = new byte[Math.Min(512, fileInfo.Length)];
                                fs.Read(buffer, 0, buffer.Length);

                                // PE executable check
                                if (buffer.Length >= 2 && buffer[0] == 0x4D && buffer[1] == 0x5A)
                                {
                                    threatLevel = threatLevel ?? "HIGH";
                                    threatType = threatType ?? "PE Executable";
                                    reason = reason ?? "Windows executable detected";
                                }
                                // ELF executable check
                                else if (buffer.Length >= 4 && buffer[0] == 0x7F && buffer[1] == 0x45)
                                {
                                    threatLevel = "CRITICAL";
                                    threatType = "ELF Executable";
                                    reason = "Linux executable on Windows system";
                                }
                            }
                        }
                        catch
                        {
                            // Skip content analysis if file can't be read
                        }
                    }
                }

                // Record threat if detected
                if (threatLevel != null)
                {
                    var threat = new MaliciousFile
                    {
                        FilePath = filePath,
                        FileName = fileName,
                        ThreatType = threatType,
                        ThreatLevel = threatLevel,
                        FileSize = fileInfo.Length,
                        Reason = reason,
                        DetectedTime = DateTime.Now
                    };

                    lock (lockObject)
                    {
                        result.DetectedThreats.Add(threat);
                        result.ThreatCount++;
                    }

                    _logger.LogSecurity($"?? [{threatLevel}] {fileName} - {reason}");
                    ThreatDetected?.Invoke(threat);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"Error analyzing {filePath}: {ex.Message}");
            }
        }

        /// <summary>
        /// Analyze file header and magic bytes
        /// </summary>
        private async Task<FileHeaderAnalysis> AnalyzeFileHeader(string filePath, CancellationToken ct)
        {
            var analysis = new FileHeaderAnalysis();
            
            try
            {
                using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read))
                {
                    var buffer = new byte[512]; // Read first 512 bytes
                    var bytesRead = await fs.ReadAsync(buffer, 0, buffer.Length, ct);

                    if (bytesRead >= 2)
                    {
                        // Check for PE header (Windows executable)
                        if (buffer[0] == 0x4D && buffer[1] == 0x5A) // MZ
                        {
                            analysis.IsExecutable = true;
                            analysis.FileType = "PE Executable (Windows)";
                        }
                        // Check for ELF header (Linux executable)
                        else if (bytesRead >= 4 && buffer[0] == 0x7F && buffer[1] == 0x45 && buffer[2] == 0x4C && buffer[3] == 0x46)
                        {
                            analysis.IsExecutable = true;
                            analysis.FileType = "ELF Executable (Linux)";
                        }
                        // Check for Java class file
                        else if (bytesRead >= 4 && buffer[0] == 0xCA && buffer[1] == 0xFE && buffer[2] == 0xBA && buffer[3] == 0xBE)
                        {
                            analysis.IsExecutable = true;
                            analysis.FileType = "Java Class File";
                        }
                        // Check for script shebang
                        else if (buffer[0] == 0x23 && buffer[1] == 0x21) // #!
                        {
                            analysis.IsScript = true;
                            analysis.FileType = "Shell Script";
                        }
                    }
                }
            }
            catch { }

            return analysis;
        }

        /// <summary>
        /// Analyze script file content for malicious patterns
        /// </summary>
        private async Task<ScriptAnalysis> AnalyzeScriptContent(string filePath, CancellationToken ct)
        {
            var analysis = new ScriptAnalysis();
            
            try
            {
                // Read first 50KB of script for analysis
                var maxBytes = 50 * 1024;
                string content;

                using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read))
                {
                    var buffer = new byte[Math.Min(maxBytes, fs.Length)];
                    var bytesRead = await fs.ReadAsync(buffer, 0, buffer.Length, ct);
                    content = Encoding.UTF8.GetString(buffer, 0, bytesRead);
                }

                // Check for malicious patterns
                foreach (var pattern in ScriptContentPatterns)
                {
                    if (pattern.IsMatch(content))
                    {
                        analysis.IsMalicious = true;
                        analysis.Reason = $"Contains suspicious code: {pattern}";
                        break;
                    }
                }
            }
            catch { }

            return analysis;
        }

        /// <summary>
        /// Calculate file entropy (detect packed/encrypted malware)
        /// </summary>
        private async Task<double> CalculateFileEntropy(string filePath, CancellationToken ct)
        {
            try
            {
                // Read sample from file (first 64KB for performance)
                var sampleSize = 64 * 1024;
                byte[] buffer;

                using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read))
                {
                    var bytesToRead = (int)Math.Min(sampleSize, fs.Length);
                    buffer = new byte[bytesToRead];
                    await fs.ReadAsync(buffer, 0, bytesToRead, ct);
                }

                // Calculate Shannon entropy
                var frequency = new int[256];
                foreach (var b in buffer)
                {
                    frequency[b]++;
                }

                double entropy = 0.0;
                var len = buffer.Length;

                for (int i = 0; i < 256; i++)
                {
                    if (frequency[i] > 0)
                    {
                        var p = (double)frequency[i] / len;
                        entropy -= p * Math.Log(p, 2);
                    }
                }

                return entropy;
            }
            catch
            {
                return 0.0;
            }
        }

        /// <summary>
        /// Check if file is a script type
        /// </summary>
        private bool IsScriptFile(string extension)
        {
            var scriptExtensions = new[] { ".ps1", ".bat", ".cmd", ".vbs", ".js", ".py", ".sh", ".bash" };
            return scriptExtensions.Contains(extension.ToLower());
        }

        /// <summary>
        /// Legacy compatibility
        /// </summary>
        public async Task<StorageScanResult> ScanDriveAsync(string driveLetter)
        {
            return await ScanDriveWithProgressAsync(driveLetter);
        }

        // Helper classes for analysis results
        private class FileHeaderAnalysis
        {
            public bool IsExecutable { get; set; }
            public bool IsScript { get; set; }
            public string FileType { get; set; }
        }

        private class ScriptAnalysis
        {
            public bool IsMalicious { get; set; }
            public string Reason { get; set; }
        }
    }
}

# heuristics.py
import os
import math
import mimetypes # To check file types
from cli import CLI # Import CLI for logging

class HeuristicEngine:
    def __init__(self):
        self.cli = CLI()
        # Define suspicious keywords for various file types
        self.suspicious_keywords = {
            # Common script/shell commands
            "script": [
                "eval(", "exec(", "base64", "powershell", "cmd.exe", "/bin/bash",
                "wget ", "curl ", "system(", "chown ", "chmod ", "rm -rf",
                "mshta", "regsvr32", "rundll32",
            ],
            # Windows-specific (could be expanded by parsing PE files later)
            "executable": [
                "VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread", # API calls often used by malware
                "LoadLibrary", "GetProcAddress"
            ],
            # General file content (e.g., obfuscation indicators)
            "general": [
                "MZ", # PE magic bytes - if found in a non-exe file.
                "ELF" # ELF magic bytes - if found in a non-elf file.
            ]
        }
        self.entropy_threshold = 7.0 # Above this might be suspicious (0-8 range)
                                     # Adjust this based on testing with various file types.

    def calculate_entropy(self, data):
        """Calculates the Shannon entropy of data."""
        if not data:
            return 0.0

        frequency = {}
        for byte in data:
            frequency[byte] = frequency.get(byte, 0) + 1

        entropy = 0.0
        data_len = len(data)
        for count in frequency.values():
            probability = count / data_len
            entropy -= probability * math.log2(probability)
        return entropy

    def check_file_entropy(self, filepath):
        """Checks if a file's entropy is suspiciously high."""
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
            entropy = self.calculate_entropy(data)
            if entropy > self.entropy_threshold:
                return f"High Entropy ({entropy:.2f} > {self.entropy_threshold:.2f})"
        except FileNotFoundError:
            self.cli.print_warning(f"File not found for entropy check: {filepath}")
        except PermissionError:
            self.cli.print_warning(f"Permission denied for entropy check: {filepath}")
        except Exception as e:
            self.cli.print_error(f"Error checking entropy for {filepath}: {e}")
        return None

    def check_suspicious_keywords(self, filepath):
        """Checks for suspicious keywords in a file."""
        try:
            # Try to read as text, fall back to binary if text fails
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read().lower()
            except UnicodeDecodeError:
                with open(filepath, 'rb') as f:
                    content = f.read().lower().decode('latin-1', errors='ignore') # Decode binary to string
            
            detected_keywords = []

            # Determine file type for more specific keyword checks
            mime_type = mimetypes.guess_type(filepath)[0]
            
            # Check script-specific keywords
            if mime_type and ('script' in mime_type or 'text' in mime_type or filepath.endswith(('.ps1', '.sh', '.bat', '.js', '.vbs'))):
                for keyword in self.suspicious_keywords["script"]:
                    if keyword.lower() in content:
                        detected_keywords.append(keyword)
            
            # Check executable-specific keywords (basic, could be PE parsing for real)
            if mime_type and ('executable' in mime_type or filepath.endswith(('.exe', '.dll'))):
                 for keyword in self.suspicious_keywords["executable"]:
                    if keyword.lower() in content:
                        detected_keywords.append(keyword)

            # Check general keywords
            for keyword in self.suspicious_keywords["general"]:
                if keyword.lower() in content and not (mime_type and ('executable' in mime_type or filepath.endswith(('.exe', '.dll')))):
                    detected_keywords.append(f"'{keyword}' in non-executable")

            if detected_keywords:
                return f"Suspicious Keywords: {', '.join(set(detected_keywords))}"
        except FileNotFoundError:
            self.cli.print_warning(f"File not found for keyword check: {filepath}")
        except PermissionError:
            self.cli.print_warning(f"Permission denied for keyword check: {filepath}")
        except Exception as e:
            self.cli.print_error(f"Error checking keywords for {filepath}: {e}")
        return None

    def check_file_extension_mismatch(self, filepath):
        """Checks if a file's actual content type matches its extension."""
        filename = os.path.basename(filepath)
        _, ext = os.path.splitext(filename)
        ext = ext.lower()

        if not ext:
            return None # No extension to check

        try:
            # Use 'file' command if available for more accurate type detection
            # Otherwise, use mimetypes which is less reliable for executables
            detected_mime_type = None
            try:
                import subprocess
                # The 'file' command is common on Linux/macOS
                # On Windows, you might need a port or alternative
                result = subprocess.run(['file', '-b', '--mime-type', filepath], capture_output=True, text=True, check=True)
                detected_mime_type = result.stdout.strip()
            except (FileNotFoundError, subprocess.CalledProcessError):
                # Fallback to mimetypes if 'file' command not found or fails
                detected_mime_type = mimetypes.guess_type(filepath)[0]
            
            if not detected_mime_type:
                return None

            # Simple checks for common mismatches
            if ext == '.txt' and ('executable' in detected_mime_type or 'application/x-executable' in detected_mime_type or 'application/octet-stream' in detected_mime_type and detected_mime_type != 'text/plain'):
                return f"Extension mismatch: {ext} but detected as {detected_mime_type}"
            if ext in ['.jpg', '.png', '.gif'] and not ('image' in detected_mime_type):
                 return f"Extension mismatch: {ext} but detected as {detected_mime_type}"
            if ext in ['.exe', '.dll'] and not ('executable' in detected_mime_type or 'application/x-msdownload' in detected_mime_type or 'application/x-dosexec' in detected_mime_type):
                 return f"Extension mismatch: {ext} but detected as {detected_mime_type}"

        except FileNotFoundError:
            self.cli.print_warning(f"File not found for extension mismatch check: {filepath}")
        except PermissionError:
            self.cli.print_warning(f"Permission denied for extension mismatch check: {filepath}")
        except Exception as e:
            self.cli.print_error(f"Error checking extension mismatch for {filepath}: {e}")
        return None

    def analyze_file(self, filepath):
        """Runs all heuristic checks on a file."""
        detections = []

        if not os.path.exists(filepath) or not os.path.isfile(filepath):
            return []

        # High Entropy Check
        entropy_detection = self.check_file_entropy(filepath)
        if entropy_detection:
            detections.append(entropy_detection)

        # Suspicious Keywords Check
        keywords_detection = self.check_suspicious_keywords(filepath)
        if keywords_detection:
            detections.append(keywords_detection)

        # File Extension Mismatch Check
        ext_mismatch_detection = self.check_file_extension_mismatch(filepath)
        if ext_mismatch_detection:
            detections.append(ext_mismatch_detection)

        # Add more heuristic checks here (e.g., hidden file attributes, PE header analysis)
        
        return detections
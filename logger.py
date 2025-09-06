# logger.py
import os
import json
from datetime import datetime

# --- Configuration ---
LOGS_DIR = "logs"
SCAN_LOG_FILE = os.path.join(LOGS_DIR, "scan_history.log")
EVENT_LOG_FILE = os.path.join(LOGS_DIR, "system_events.log")

class Logger:
    def __init__(self):
        self.cli = self._get_cli_instance()
        self.ensure_log_dir()

    def _get_cli_instance(self):
        try:
            from cli import CLI
            return CLI()
        except ImportError:
            class DummyCLI:
                def print_warning(self, msg): pass
                def print_error(self, msg): pass
                def print_info(self, msg): pass
            return DummyCLI()

    def ensure_log_dir(self):
        """Ensures the logs directory exists."""
        if not os.path.exists(LOGS_DIR):
            try:
                os.makedirs(LOGS_DIR)
                self.cli.print_info(f"Created logs directory: {LOGS_DIR}")
            except OSError as e:
                self.cli.print_error(f"Error creating logs directory {LOGS_DIR}: {e}")

    def _write_log(self, log_file, entry):
        """Helper to write a log entry."""
        try:
            with open(log_file, 'a') as f:
                f.write(json.dumps(entry) + "\n")
        except Exception as e:
            self.cli.print_error(f"Error writing to log file {log_file}: {e}")

    def log_scan_result(self, filepath, status, threat=None, heuristics=None):
        """Logs the result of a file scan, including heuristics."""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "type": "SCAN_RESULT",
            "filepath": filepath,
            "status": status,
            "threat": threat,
            "heuristics": heuristics if heuristics else []
        }
        self._write_log(SCAN_LOG_FILE, log_entry)

    def log_event(self, event_description, level="INFO"):
        """Logs a general system event."""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "type": "SYSTEM_EVENT",
            "level": level,
            "description": event_description
        }
        self._write_log(EVENT_LOG_FILE, log_entry)

    def display_logs(self):
        """Displays recent logs from both files."""
        self.cli.print_info("\n--- Recent Scan History ---")
        try:
            with open(SCAN_LOG_FILE, 'r') as f:
                for line in f:
                    entry = json.loads(line)
                    status_color = "CYAN"
                    if entry['status'] == "INFECTED": status_color = "RED"
                    elif entry['status'] == "HEURISTIC_DETECTED": status_color = "MAGENTA"

                    heuristic_details = ""
                    if entry.get("heuristics"):
                        heuristic_details = f" (Heuristics: {', '.join(entry['heuristics'])})"

                    self.cli.print_colored(f"[{entry['timestamp']}] {entry['filepath']} -> {entry['status']} ({entry['threat'] or 'N/A'}){heuristic_details}", status_color)
        except FileNotFoundError:
            self.cli.print_info("No scan history available.")
        except Exception as e:
            self.cli.print_error(f"Error reading scan log: {e}")

        self.cli.print_info("\n--- Recent System Events ---")
        try:
            with open(EVENT_LOG_FILE, 'r') as f:
                for line in f:
                    entry = json.loads(line)
                    color = "BLUE"
                    if entry.get("level") == "WARNING": color = "YELLOW"
                    if entry.get("level") == "ERROR": color = "RED"
                    self.cli.print_colored(f"[{entry['timestamp']}] [{entry.get('level', 'INFO')}] {entry['description']}", color)
        except FileNotFoundError:
            self.cli.print_info("No system events available.")
        except Exception as e:
            self.cli.print_error(f"Error reading event log: {e}")
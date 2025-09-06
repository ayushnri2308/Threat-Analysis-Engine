# cli.py
import sys

class CLI:
    COLORS = {
        "RESET": "\033[0m",
        "RED": "\033[91m",
        "GREEN": "\033[92m",
        "YELLOW": "\033[93m",
        "BLUE": "\033[94m",
        "CYAN": "\033[96m",
        "MAGENTA": "\033[95m",
        "WHITE": "\033[97m",
    }

    def print_colored(self, message, color):
        print(f"{self.COLORS.get(color.upper(), self.COLORS['RESET'])}{message}{self.COLORS['RESET']}")

    def print_info(self, message):
        self.print_colored(f"[INFO] {message}", "BLUE")

    def print_success(self, message):
        self.print_colored(f"[SUCCESS] {message}", "GREEN")

    def print_warning(self, message):
        self.print_colored(f"[WARNING] {message}", "YELLOW")

    def print_error(self, message):
        self.print_colored(f"[ERROR] {message}", "RED")
        
    def print_scan_result(self, filepath, status, threat=None, heuristics=None):
        """Prints a color-coded scan result for a single file, including heuristics."""
        if status == "INFECTED":
            self.print_colored(f"[INFECTED] {filepath} -> {threat}", "RED")
        elif status == "HEURISTIC_DETECTED":
            self.print_colored(f"[HEURISTIC] {filepath} -> {threat}", "MAGENTA")
            if heuristics:
                for h in heuristics:
                    self.print_colored(f"    - {h}", "MAGENTA")
        elif status == "CLEAN":
            self.print_colored(f"[CLEAN] {filepath}", "GREEN")
        elif status == "NOT_FOUND":
            self.print_colored(f"[WARNING] {filepath} not found.", "YELLOW")
        elif status == "NOT_FILE":
            self.print_colored(f"[INFO] Skipping directory: {filepath}", "CYAN")
        elif status == "ERROR":
            self.print_colored(f"[ERROR] {filepath} -> {threat}", "RED")
        else:
            self.print_colored(f"[UNKNOWN] {filepath} -> {status}", "WHITE")

    def display_scan_results(self, scan_results):
        """Displays results for multiple files."""
        infected_count = 0
        heuristic_count = 0
        for filepath, data in scan_results.items():
            self.print_scan_result(filepath, data["status"], data["threat"], data.get("heuristics"))
            if data["status"] == "INFECTED":
                infected_count += 1
            elif data["status"] == "HEURISTIC_DETECTED":
                heuristic_count += 1
        
        print("\n--- Scan Summary ---")
        if infected_count > 0:
            self.print_colored(f"Found {infected_count} infection(s) by signature.", "RED")
        if heuristic_count > 0:
            self.print_colored(f"Found {heuristic_count} potential threat(s) by heuristics.", "MAGENTA")
        if infected_count == 0 and heuristic_count == 0:
            self.print_colored("No infections or suspicious files found.", "GREEN")

    def ask_yes_no(self, prompt):
        """Asks a yes/no question and returns True for yes, False for no."""
        while True:
            response = input(f"{self.COLORS['YELLOW']}{prompt}{self.COLORS['RESET']} ").strip().lower()
            if response in ['y', 'yes']:
                return True
            elif response in ['n', 'no']:
                return False
            else:
                self.print_warning("Please enter 'y' or 'n'.")
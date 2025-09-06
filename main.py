# main.py
import sys
import os
import time

from cli import CLI
from scanner import Scanner
from definitions import DefinitionManager
from quarantine import QuarantineManager
from logger import Logger
#from heuristics import HeuristicEngine # Import HeuristicEngine

# --- Main Application Logic ---
def main():
    cli = CLI()
    definition_manager = DefinitionManager()
    scanner = Scanner(definition_manager) # HeuristicEngine is now instantiated inside Scanner
    quarantine_manager = QuarantineManager()
    logger = Logger()

    # Initial load and check for updates
    cli.print_info("Loading virus definitions...")
    definition_manager.load_definitions()
    cli.print_info(f"Definitions loaded. Last updated: {definition_manager.get_last_updated()}")

    # Try to update definitions on startup
    if definition_manager.update_definitions():
        cli.print_success("Virus definitions updated successfully!")
    else:
        cli.print_warning("Failed to update virus definitions or no new updates available.")

    if len(sys.argv) < 2:
        cli.print_error("Usage: python main.py <scan|update|quarantine|logs> [path_or_option]")
        cli.print_error("Example: python main.py scan /path/to/scan")
        cli.print_error("Example: python main.py update")
        cli.print_error("Example: python main.py quarantine list")
        cli.print_error("Example: python main.py logs")
        sys.exit(1)

    command = sys.argv[1].lower()

    if command == "scan":
        if len(sys.argv) < 3:
            cli.print_error("Usage: python main.py scan <file_or_directory_path>")
            sys.exit(1)
        
        path_to_scan = sys.argv[2]
        if not os.path.exists(path_to_scan):
            cli.print_error(f"Error: Path '{path_to_scan}' does not exist.")
            sys.exit(1)

        cli.print_info(f"Starting scan of: {path_to_scan}")
        start_time = time.time()
        
        if os.path.isfile(path_to_scan):
            status, threat, heuristics = scanner.scan_file(path_to_scan)
            cli.print_scan_result(path_to_scan, status, threat, heuristics)
            logger.log_scan_result(path_to_scan, status, threat, heuristics)
            
            if status in ["INFECTED", "HEURISTIC_DETECTED"]:
                if cli.ask_yes_no("File detected. Quarantine it? (y/n): "):
                    quarantine_manager.quarantine_file(path_to_scan)
        elif os.path.isdir(path_to_scan):
            results = scanner.scan_directory(path_to_scan)
            cli.display_scan_results(results)
            for filepath, data in results.items():
                logger.log_scan_result(filepath, data["status"], data["threat"], data["heuristics"])
                if data["status"] in ["INFECTED", "HEURISTIC_DETECTED"]:
                    if cli.ask_yes_no(f"File '{filepath}' detected. Quarantine it? (y/n): "):
                        quarantine_manager.quarantine_file(filepath)
        
        end_time = time.time()
        cli.print_info(f"Scan finished in {end_time - start_time:.2f} seconds.")

    elif command == "update":
        cli.print_info("Attempting to update virus definitions...")
        if definition_manager.update_definitions(force=True):
            cli.print_success("Virus definitions updated successfully!")
            logger.log_event("Definitions updated.")
        else:
            cli.print_error("Failed to update virus definitions.")
    
    elif command == "quarantine":
        if len(sys.argv) < 3:
            cli.print_error("Usage: python main.py quarantine <list|restore|delete>")
            sys.exit(1)
        
        subcommand = sys.argv[2].lower()

        if subcommand == "list":
            quarantine_manager.list_quarantined_files()
        elif subcommand == "restore":
            if len(sys.argv) < 4:
                cli.print_error("Usage: python main.py quarantine restore <original_path_or_id>")
                sys.exit(1)
            original_path_or_id = sys.argv[3]
            quarantine_manager.restore_file(original_path_or_id)
        elif subcommand == "delete":
            if len(sys.argv) < 4:
                cli.print_error("Usage: python main.py quarantine delete <original_path_or_id>")
                sys.exit(1)
            original_path_or_id = sys.argv[3]
            quarantine_manager.delete_file(original_path_or_id)
        else:
            cli.print_error(f"Unknown quarantine subcommand: {subcommand}")

    elif command == "logs":
        logger.display_logs()

    else:
        cli.print_error(f"Unknown command: {command}")
        cli.print_error("Available commands: scan, update, quarantine, logs")

if __name__ == "__main__":
    main()
# definitions.py
import json
import os
import requests
from datetime import datetime

# --- Configuration ---
MD5_HASHES_FILE = "md5_hashes.txt"       # Your MD5 hash list
SHA256_HASHES_FILE = "sha_256_hashes.txt" # Your SHA256 hash list
VIRUS_DEFINITIONS_CACHE_FILE = "virus_definitions_cache.json" # Where we'll store definitions with metadata
LAST_UPDATED_FILE = "last_updated.txt"

# This would be a URL to your hosted JSON file for real updates
# The online update file would need to have a structure similar to what save_definitions() creates.
ONLINE_DEFINITIONS_URL = "http://localhost:8000/online_definitions_with_meta.json" # Placeholder for future JSON updates

class DefinitionManager:
    def __init__(self):
        self.definitions = {
            "md5": {},
            "sha256": {},
            "metadata": {
                "version": "0.1.0", # Default version for local TXT files
                "last_updated": "Never"
            }
        }
        self.last_updated_timestamp = "Never"
        self.cli = self._get_cli_instance() # For logging

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

    def _load_hashes_from_txt(self, filepath, hash_type):
        """Helper to load hashes from a TXT file."""
        hashes = {}
        if os.path.exists(filepath):
            try:
                with open(filepath, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line: # Skip empty lines
                            # Assuming format is just hash per line.
                            # If format is "hash,malware_name", split it:
                            if ',' in line:
                                parts = line.split(',', 1)
                                h = parts[0].strip()
                                name = parts[1].strip()
                            else:
                                h = line
                                name = f"Generic {hash_type.upper()} Threat"
                            
                            if len(h) == 32 and hash_type == "md5": # Basic validation
                                hashes[h] = name
                            elif len(h) == 64 and hash_type == "sha256": # Basic validation
                                hashes[h] = name
                            else:
                                self.cli.print_warning(f"Skipping invalid {hash_type} hash in {filepath}: '{h}'")

                self.cli.print_info(f"Loaded {len(hashes)} {hash_type} definitions from {filepath}.")
            except Exception as e:
                self.cli.print_error(f"Error loading {hash_type} hashes from {filepath}: {e}")
        else:
            self.cli.print_warning(f"'{filepath}' not found. No {hash_type} definitions loaded from this file.")
        return hashes

    def load_definitions(self):
        """
        Loads virus definitions, prioritizing the cached file with metadata,
        then the raw TXT hash files.
        """
        # Try to load from our cached file first (which includes metadata from previous saves/updates)
        if os.path.exists(VIRUS_DEFINITIONS_CACHE_FILE):
            try:
                with open(VIRUS_DEFINITIONS_CACHE_FILE, 'r') as f:
                    self.definitions = json.load(f)
                    self.last_updated_timestamp = self.definitions["metadata"].get("last_updated", "Never")
                    self.cli.print_info(f"Loaded definitions from cache: {VIRUS_DEFINITIONS_CACHE_FILE}")
                    return
            except json.JSONDecodeError as e:
                self.cli.print_error(f"Error decoding cached definitions file: {e}. Attempting to load raw TXT files.")
            except Exception as e:
                self.cli.print_error(f"Error loading cached definitions: {e}. Attempting to load raw TXT files.")

        # If cache fails or doesn't exist, load from the raw TXT files
        self.definitions["md5"] = self._load_hashes_from_txt(MD5_HASHES_FILE, "md5")
        self.definitions["sha256"] = self._load_hashes_from_txt(SHA256_HASHES_FILE, "sha256")
        
        # Update metadata for definitions loaded from TXT
        if self.definitions["md5"] or self.definitions["sha256"]:
            self.definitions["metadata"]["version"] = "1.0.0 (from local TXT files)"
            new_last_updated = datetime.now().isoformat()
            self.definitions["metadata"]["last_updated"] = new_last_updated
            self.last_updated_timestamp = new_last_updated
            self.save_definitions() # Save it to our cache with metadata
            self.cli.print_info("Loaded definitions from TXT files and cached with metadata.")
        else:
            self.cli.print_warning("No hash files found or loaded from TXT. Starting with empty definitions.")
            self.definitions = { # Reset to default empty if no hashes loaded
                "md5": {},
                "sha256": {},
                "metadata": {
                    "version": "0.0.0",
                    "last_updated": "Never"
                }
            }
            self.last_updated_timestamp = "Never"


    def save_definitions(self):
        """Saves current definitions (with metadata) to the cached JSON file."""
        try:
            with open(VIRUS_DEFINITIONS_CACHE_FILE, 'w') as f:
                json.dump(self.definitions, f, indent=4)
            self.cli.print_info(f"Definitions saved to {VIRUS_DEFINITIONS_CACHE_FILE}")
        except Exception as e:
            self.cli.print_error(f"Error saving definitions: {e}")

    def get_definitions(self):
        return self.definitions

    def get_last_updated(self):
        return self.last_updated_timestamp

    def update_definitions(self, force=False):
        """
        Fetches updated virus definitions from a URL (expects JSON with metadata).
        Returns True if updated, False otherwise.
        """
        if not ONLINE_DEFINITIONS_URL:
            self.cli.print_warning("ONLINE_DEFINITIONS_URL is not set. Skipping online update.")
            return False

        try:
            response = requests.get(ONLINE_DEFINITIONS_URL, timeout=10)
            response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
            
            online_defs = response.json()
            online_version = online_defs.get("metadata", {}).get("version", "0.0")
            local_version = self.definitions.get("metadata", {}).get("version", "0.0")

            if not force and online_version == local_version:
                self.cli.print_info(f"Definitions are already up-to-date (version {local_version}).")
                return False
            
            # Replace definitions with the online version
            self.definitions = online_defs
            new_last_updated = datetime.now().isoformat()
            self.definitions["metadata"]["last_updated"] = new_last_updated
            self.last_updated_timestamp = new_last_updated

            self.save_definitions() # Save the new definitions locally
            
            # Update the last_updated.txt file (redundant with metadata in definitions, but good for quick checks)
            with open(LAST_UPDATED_FILE, 'w') as f:
                f.write(self.last_updated_timestamp)
            
            self.cli.print_success(f"Definitions updated to version {online_version}.")
            return True
        except requests.exceptions.RequestException as e:
            self.cli.print_error(f"Network error during definition update: {e}")
        except json.JSONDecodeError as e:
            self.cli.print_error(f"Error parsing online definitions JSON: {e}")
        except Exception as e:
            self.cli.print_error(f"An unexpected error occurred during update: {e}")
        return False
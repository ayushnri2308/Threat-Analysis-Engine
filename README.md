Static Threat Analysis Engine
A lightweight, command-line static analysis tool designed to detect potential threats in files through signature-based scanning and heuristic analysis. It features a high-performance, multi-threaded scanning pipeline and a secure quarantine system for threat management.

📜 Table of Contents
Key Features

Architecture

Setup and Installation

Usage

Contributing

License

✨ Key Features
Signature-Based Detection: Utilizes a robust detection core that checks file hashes (MD5 and SHA256) against a versioned, metadata-rich definition database for known threats.

Heuristic Analysis: Implements a static analyzer that flags potentially obfuscated or suspicious binaries by calculating Shannon entropy and identifying malicious patterns.

High-Performance Scanning: Engineered with a multi-threaded scanning pipeline to process files concurrently. It includes a clean-file hash cache to skip previously verified files, significantly maximizing throughput and scan efficiency.

Secure Quarantine System: Features an isolated quarantine vault to safely store detected threats. Each quarantined file is tracked with a UUID and detailed manifest logging, allowing for safe management and restoration of false positives.

Command-Line Interface: A full-featured and user-friendly CLI for scanning, updating definitions, managing the quarantine, and viewing logs.

🏗️ Architecture
The engine is built with a modular design to ensure separation of concerns and maintainability:

main.py: The main entry point for the CLI application.

scanner.py: Contains the core logic for file/directory scanning, integrating both signature and heuristic engines.

definitions.py: Manages the loading and updating of threat signatures from the definition cache.

heuristics.py: Implements the algorithms for heuristic-based threat detection (e.g., Shannon entropy).

quarantine.py: Handles all operations related to the secure quarantine, including isolating, restoring, and deleting files.

cli.py: Manages all user-facing output, input prompts, and progress indicators.

logger.py: Responsible for logging all scan events, detections, and system actions to a file.

🚀 Setup and Installation
1. Prerequisites
Python 3.8 or newer.

2. Clone the Repository
Bash

git clone https://github.com/your-username/static-threat-analysis-engine.git
cd static-threat-analysis-engine
3. Set up a Virtual Environment (Recommended)
Bash

# For Unix/macOS
python3 -m venv venv
source venv/bin/activate

# For Windows
python -m venv venv
.\venv\Scripts\activate
4. Install Dependencies
This project uses standard Python libraries. If there are any specific external libraries, create a requirements.txt and run:

Bash

pip install -r requirements.txt
5. Initialize Threat Definitions
Make sure you have a definitions.json file in the project directory with the initial threat signatures. The engine will use and update this file.

🏃 Usage
The tool is operated entirely from the command line.

Scan a File or Directory
Bash

# Scan a single file
python main.py scan /path/to/suspicious/file.exe

# Scan an entire directory
python main.py scan /path/to/some/directory
Update Threat Definitions
Bash

python main.py update
Manage Quarantined Files
Bash

# List all files currently in quarantine
python main.py quarantine list

# Restore a file from quarantine using its original path or ID
python main.py quarantine restore /path/to/original/file.exe

# Permanently delete a file from quarantine
python main.py quarantine delete /path/to/original/file.exe
View Logs
Bash

# Display the scan and event logs
python main.py logs
🤝 Contributing
Contributions are welcome! If you find a bug or have an idea for a new feature, please open an issue or submit a pull request.

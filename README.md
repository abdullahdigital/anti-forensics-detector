# Anti-Forensics Detector

A comprehensive anti-forensics tool designed to detect and analyze suspicious file activities and anomalies in Linux environments. This tool combines a Python Flask backend for file system analysis with a modern Angular frontend.

## Key Features

The tool employs advanced heuristics to detect a wide range of anti-forensic techniques:

*   **🕵️ Suspicious Rename Detector**
    *   Identifies files renamed with random characters using Shannon Entropy analysis.
*   **🎭 Masquerade Detection**
    *   Detects file type spoofing by comparing file extensions against magic bytes references (e.g., an EXE renamed as JPG).
*   **🔒 Encryption Detection**
    *   Flags potential encrypted files using high-entropy checks and header analysis, identifying suspicious unknown formats.
*   **📝 Metadata Manipulation Detection**
    *   Cross-references file metadata with actual properties to uncover deep-fake timestamps and attributes.
*   **👁️ Steganography Detection**
    *   Analyzes files for appended data anomalies that suggest hidden payloads in images or binaries.
*   **🕒 Timestomping Detection**
    *   Examines timestamp nanosecond precision to detect artificial modification tools.
*   **📂 Hidden Artifacts (ADS/Xattr)**
    *   Scans for Alternate Data Streams (Windows) or suspicious Extended Attributes (Linux) used to hide data.
*   **🧹 Data Wiping & Log Tampering**
    *   Detects evidence of cleanup tools through byte histogram analysis and null-byte injection patterns.
*   **👻 Hidden File Detection**
    *   Identifies hidden files (dotfiles) and files with no extensions that may mask malicious content.

## Technology Stack

*   **Backend**: Python (Flask)
*   **Frontend**: Angular v20 + TailwindCSS
*   **Analysis**: Custom heuristic detection algorithms

## Prerequisites

*   **Python**: 3.8+
*   **Node.js**: 22+ (or 20.19+)
*   **npm**: 8+

## Installation & Usage

### 1. Start the Backend

The backend runs on `http://localhost:5000`.

Open a terminal and:

```bash
# Navigate to backend directory
cd backend/python

# Create and activate virtual environment (first time)
python3 -m venv venv
source venv/bin/activate

# Install dependencies (first time)
pip install -r requirements.txt

# Start the server
python main.py
```

### 2. Start the Frontend

The frontend runs on `http://localhost:4200`.

Open a **new** terminal and:

```bash
# Navigate to frontend directory
cd frontend

# Install dependencies (first time)
npm install

# Start the application
npm start
```

## Setup for Development

If you are setting up the project for the first time on a new machine:

1.  **Backend**: Ensure you create the virtual environment and install `requirements.txt`.
2.  **Frontend**: Ensure you run `npm install` to fetch all Node.js dependencies.
 
## Contributors

* [Muhammad Abdullah](https://www.linkedin.com/in/abdullahdigital/)
* [Huzaifa Ahmed](https://www.linkedin.com/in/huzaifa-ahmed-240b66258/)

---
*Note: This tool is for educational and defensive analysis purposes.*

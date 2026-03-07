# Advanced Anti-Forensics Detector (AI-Powered)

🚀 A full-stack digital forensics and threat hunting framework powered by a 12-module hybrid detection engine (7 predictive AI models, 5 fast heuristics). Designed to catch what traditional antivirus misses.

## Key Features

The tool employs a powerful hybrid engine containing **12 distinct detection modules** to expose a wide range of anti-forensic techniques:

### ⚡ Fast Heuristic Modules (5)
* **🎭 Masquerade Detection:** Detects file type spoofing by cross-referencing file extensions against raw magic byte signatures (e.g., an EXE renamed as a JPG).
* **🔒 Encryption Detection:** Flags potential encrypted files using Shannon Entropy calculations and header analysis.
* **📂 Hidden Artifacts (ADS/Xattr):** Scans for Alternate Data Streams (Windows) or suspicious Extended Attributes (Linux) used to hide malicious data.
* **👻 Hidden File Detection:** Identifies hidden files (dotfiles) and files with no extensions that mask malicious content.
* **⏱️ Timestamp Logic Checks:** Examines timestamp nanosecond precision to detect artificial modification tools.

### 🧠 AI-Powered Deep Inspection (7)
* **🕵️ Suspicious Rename Analyzer:** Uses AI to identify files renamed with random characters or evasive patterns.
* **📝 Fake Metadata Detector:** Employs AI to analyze textual representations of file metadata to uncover inconsistencies and deep-fake attributes.
* **👁️ Steganography Analyzer:** Uses AI text and behavioral analysis to detect hidden payloads appended to images or binaries.
* **🧹 Data Wiping Interpreter:** Uses AI to interpret byte histograms and null-byte injection patterns to find evidence of secure cleanup tools.
* **📜 Log Tampering Detector:** Analyzes log snippets contextually via AI to find subtle traces of manipulation.
* **⏳ Predictive Metadata Timeline:** Utilizes a predictive AI model to dynamically score long-term timestamp anomalies.
* **🎯 Dynamic Anomaly Scorer:** An AI aggregation engine that combines findings from all 11 other modules to generate a definitive threat score and plain-English explanation.

## Technology Stack

* **Backend**: Python (Flask)
* **Frontend**: Angular v20 + TailwindCSS
* **Analysis Engine**: Predictive AI Models + Custom Heuristic Algorithms

## Prerequisites

* **Python**: 3.8+
* **Node.js**: 22+ (or 20.19+)
* **npm**: 8+

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

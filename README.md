# AI Security Task Manager

A Python-based Task Manager that uses Google's Gemini AI to analyze running processes for potential security threats.

## Features

- **Process Viewer:** View all running processes with PID, Name, Status, and Path.
- **AI Analysis:** Select any process to get a detailed security analysis from Gemini AI (Safe, Suspicious, or Malware).
- **Batch Scan:** Scan *all* running processes at once to identify potential threats.
- **Process Control:** Terminate suspicious processes directly from the app.
- **Context Awareness:** Validates if a process is running from its standard path (e.g., ensuring `svchost.exe` is in System32).

## Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/amilaanjanab/AI-powered-Security-Task-Manager.git
    cd AI-powered-Security-Task-Manager
    ```

2.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

## Usage

1.  Run the application:
    ```bash
    python ai_security_manager.py
    ```

2.  **API Key Setup:**
    - Click the **"🔑 Set API Key"** button in the top right.
    - Enter your Google Gemini API Key.
    - The key is saved locally in a `.env` file for future use.

3.  **Analyze Processes:**
    - Select a process and click **"🤖 Analyze"**.
    - Or run a **"🔍 Full System Scan"** to check everything at once.

## Requirements

- Python 3.x
- `google-generativeai`
- `psutil`
- A Google Cloud API Key for Gemini.

## Disclaimer

This tool is for educational and assistance purposes only. Always verify AI findings with standard antivirus software.

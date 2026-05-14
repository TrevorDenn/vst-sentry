VST-Sentry
A desktop security scanner for Windows VST / DLL plugin files. VST-Sentry performs static analysis on Portable Executable (PE) files to detect indicators of malicious intent — DLL hijacking payloads, trojanised installers, crypto-miners, and packed/encrypted binaries — before they reach your DAW.


Installation
bash# Clone or download the project
cd vst-sentry

# Create a virtual environment (recommended)
python -m venv .venv
source .venv/bin/activate  # Linux / macOS
.venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt
Optional: Drag-and-Drop Support
For native OS drag-and-drop on the file drop zone, install tkinterdnd2:
bashpip install tkinterdnd2
The GUI falls back to a click-to-browse file dialog if this package is not installed.

Usage
Launch the GUI
bashpython vst_sentry_gui.py

Configure — Click the gear icon (or File > Settings) to set your DAW plugin folder and (optionally) a VirusTotal API key. Use "Auto-Detect" to find common plugin directories on your system.
Drop or browse — Drag one or more .dll / .vst3 files onto the drop zone, click to browse, or use Ctrl+O. Multiple dropped files are queued as a batch scan.
Review — Watch the analysis log for real-time results. Use Ctrl+F to search the log. The status indicator turns green (Safe), yellow (Suspicious), or red (High Risk).
Auto-install — Safe files are automatically copied to your configured plugin folder.
Batch scan — Use File > Scan Folder to scan an entire directory of plugins at once.
History — Toggle the scan history panel (Ctrl+H) to review and re-scan previous files. Hover cards for file details.
Export — Ctrl+E to save the report as TXT, HTML, PDF, or JSON.
Updates — Help > Check for Updates to see if a newer version is available.

Keyboard Shortcuts
ShortcutActionCtrl+OOpen file for analysisCtrl+EExport report (TXT/HTML/PDF/JSON)Ctrl+FFind in analysis logCtrl+LClear the analysis logCtrl+HToggle scan history panelF5Re-scan last analysed fileF1Keyboard shortcut cheat sheetEscapeClose search bar / dialog
Command-Line / Scripting
pythonfrom analyzer import analyze_file, generate_report

result = analyze_file(r"C:\path\to\plugin.dll", vt_api_key="YOUR_KEY")
print(result["verdict"])   # "Safe", "Suspicious", or "High Risk"
print(result["score"])     # Numeric risk score
print(generate_report(result))  # Full text report
VirusTotal API Key
A free-tier key supports 4 requests/minute and 500 requests/day. The scanner works fully offline without a key — the VT lookup is an additive signal, not a gate.

Running Tests
bashpip install pytest

# Run the full suite
python -m pytest test_analyzer.py test_virustotal.py test_gui.py -v

# Run a specific test class
python -m pytest test_gui.py::TestScanHistory -v
Expected output: 253 passed, 206 subtests passed.

Architecture
analyzer.py — The static analysis engine. Parses PE files with pefile, extracts the Import Address Table, and scores each imported function against the 103-entry Red Flag API database. Also performs Shannon entropy analysis on every PE section, checks for known packer section names (UPX, ASPack, etc.), and verifies Authenticode signatures. Produces a structured AnalysisResult dict and a human-readable text report.
virustotal.py — Isolated VirusTotal API v3 client. Handles hash lookups, sandbox behaviour retrieval, and MITRE ATT&CK technique enrichment from a local 90+ technique knowledge base. Designed to fail gracefully — network errors, rate limits, and missing API keys never block the local analysis pipeline.
vst_sentry_gui.py — Tkinter GUI v2.5 with a DAW-inspired dark theme. Features drag-and-drop file and folder loading with recursive plugin discovery, threaded analysis with animated progress bar, persistent scan history sidebar, batch folder scanning, export to TXT/HTML/PDF/JSON, quarantine folder, scan comparison view, statistics footer, and auto-update check.
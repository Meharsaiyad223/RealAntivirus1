# Real Antivirus - File Integrity Scanner

A modern, **dark-themed** GUI-based file integrity scanner with quarantine and delete capabilities. This tool scans directories for suspicious files based on file extensions and provides options to quarantine or delete them. Features a sleek, eye-friendly dark interface perfect for extended use.

## 🎨 UI Highlights

- 🌑 **Dark Theme**: Beautiful, modern dark interface for comfortable viewing
- 🎯 **Tabbed Interface**: Organized Scan, Quarantine, Logs, and About tabs
- 📊 **Real-time Progress**: Visual progress bar during scans
- 🎨 **Color-coded Results**: Info (blue), warnings (orange), errors (red), complete (green)

## Features

- 🔍 **Directory Scanning**: Recursively scans directories for suspicious files
- 🛡️ **Suspicious Extension Detection**: Detects files with potentially harmful extensions (.exe, .dll, .bat, .vbs, .ps1, .sh, .pyc)
- 🔐 **File Hashing**: Calculates SHA-256 hashes for file integrity verification
- 📦 **Quarantine System**: Safely moves suspicious files to a quarantine folder with metadata
- 🗑️ **Delete Function**: Permanently removes suspicious files (with confirmation)
- 📊 **Progress Tracking**: Real-time progress bar and detailed logging
- 📝 **Comprehensive Logging**: All actions are logged to `scan_log.txt`

## Requirements

- Python 3.6 or higher
- tkinter (usually comes with Python)

## Installation

### Option 1: Quick Start (Recommended)

1. Download or clone this repository
2. Double-click `run_antivirus.bat` to start the application

### Option 2: Using Advanced Launcher

1. Download or clone this repository
2. Double-click `run_antivirus_advanced.bat`
3. Use the menu to:
   - Check if Python is installed correctly
   - Install dependencies
   - Run the scanner
   - View logs

### Option 3: Run from Command Line

```bash
python antivirus_scanner.py
```

## Screenshots

*Beautiful dark theme interface ready to use*

## Usage

1. **Launch the Application**
   - Run `run_antivirus.bat` or double-click on it
   - Or run `python antivirus_scanner.py` from command line
   - Enjoy the sleek dark theme interface!

2. **Scan a Directory**
   - Click "Select Directory to Scan"
   - Choose the directory you want to scan
   - Watch the progress bar as files are scanned
   - Wait for the scan to complete

3. **Handle Suspicious Files**
   - If suspicious files are found, you'll see two options:
     - **Quarantine All**: Moves files to a `quarantine` folder (reversible)
     - **Delete All**: Permanently deletes files (cannot be undone)

4. **Review Results**
   - Check the results window for detailed, color-coded information
   - Review `scan_log.txt` for complete scan history
   - Check the Quarantine tab to see all quarantined files
   - Check `quarantine_metadata.json` for quarantined file information

## Files Created

- `scan_log.txt` - Complete scan history and logs
- `quarantine/` - Folder containing quarantined files
- `quarantine_metadata.json` - Metadata about quarantined files

## Safety Features

- ✅ Confirmation dialogs before quarantine/delete
- ✅ Double confirmation for permanent deletion
- ✅ Detailed logging of all actions
- ✅ Quarantine metadata preservation
- ✅ Color-coded results (info, warning, error, complete)
- ✅ Protective confirmation warnings for destructive actions
- ✅ Read-only quarantine viewer with full metadata

## Customization

### Add More Suspicious Extensions

Edit `antivirus_scanner.py` and modify the `SUSPICIOUS_EXTENSIONS` set:

```python
SUSPICIOUS_EXTENSIONS = {'.exe', '.dll', '.bat', '.vbs', '.ps1', '.sh', '.pyc', '.msi', '.scr'}
```

### Change Log File Location

Modify the `LOG_FILE` constant:

```python
LOG_FILE = 'my_custom_log.txt'
```

## Quarantine System

Quarantined files are stored in the `quarantine` folder with:
- Original file name and path
- Timestamp of quarantine
- File hash (SHA-256)
- File size
- Reason for quarantine

All this metadata is saved in `quarantine_metadata.json` for easy recovery or review.

## Restore Quarantined Files

To restore a quarantined file:
1. Open `quarantine_metadata.json`
2. Find the file you want to restore
3. Copy the file from the `quarantine` folder back to its `original_path`

## Troubleshooting

### Python not found
- Install Python from https://www.python.org/
- Make sure to check "Add Python to PATH" during installation
- Restart your computer after installation

### tkinter not available
- On Linux: Install tkinter with `sudo apt-get install python3-tk`
- On macOS: tkinter should come with Python
- On Windows: tkinter should come with Python

### Permission errors
- Run the script as administrator if scanning protected directories
- Some files may be in use by other programs

## Warning

⚠️ **USE WITH CAUTION**: This tool permanently deletes files when using the "Delete All" function. Only use it if you're certain about the files being scanned. Always review suspicious files before deleting them.

⚠️ The scanner is based on file extensions and heuristics. It's a simulation tool and should not be used as a replacement for professional antivirus software.

## License

This is a demonstration/educational tool. Use at your own risk.

## Version History

### Latest (Current)
- ✨ **New Dark Theme**: Complete UI overhaul with modern dark colors
- 🎨 Improved button styling with better visual feedback
- 🌙 Eye-friendly interface for extended use
- 🎯 Enhanced tab navigation
- 📊 Better visual distinction between different types of actions

### Previous Features
- Directory scanning with progress tracking
- SHA-256 file hashing
- Quarantine system with metadata
- Comprehensive logging

## Author

Created as a demonstration of file integrity scanning and quarantine systems with a focus on user experience and modern UI design.


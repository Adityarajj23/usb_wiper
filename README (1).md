# USB Wiper

## Overview
USB Wiper is a Windows-based GUI tool for securely wiping USB drives. Its core functions include:
- Detecting all system drives and classifying them (USB, SSD, HDD)
- Allowing only USB drives to be securely wiped for safety
- Securely deleting all files and folders on selected USB drives
- Optionally overwriting free space with random data
- Optionally formatting the USB drive after wiping
- Generating detailed wipe certificates for audit trails

**WARNING:** This tool is designed to prevent accidental system damage by restricting wipe operations to USB drives only.

## Features
- Modern Windows GUI (Tkinter)
- Multi-phase wipe: secure deletion, free-space overwrite, format
- Safety checks and confirmation dialogs
- Fast detection and classification of drives
- Certificate generation for wiped drives
- View past wipe certificates

## Requirements

### Python Libraries
- Python 3.7+
- pywin32
- wmi
- psutil
- tkinter (standard with Python)

Install dependencies via:
```sh
pip install pywin32 wmi psutil
```

### Windows Only
- This tool uses Windows-specific APIs and must be run with administrator privileges.

## Usage

1. Ensure you have Python 3.7+ and required libraries installed.
2. Run the batch file `run_wiper.bat` for easy startup, or run directly:
   ```sh
   python usb_wiper.py
   ```
3. Always run as Administrator!
4. Select your USB drive in the GUI, choose wipe options, and follow prompts.

## Batch File
The included `run_wiper.bat` script starts the program from the correct directory:
```batch
@echo off
cd /d "D:\usb_wiper"
python usb_wiper.py
pause
```

## Safety
- Only USB drives are allowed for wiping.
- Confirmation and admin checks prevent accidental wipes.
- Certificates are stored in `logs/NullBytes` or your TEMP directory.

## License
[Specify your license here]
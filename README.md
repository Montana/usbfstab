# usbfstab

![usbfstab](https://github.com/user-attachments/assets/eb17300f-8ef7-4ff0-97b5-61bbb0397e50)

# usbfstab

_Eductional Use Only._

`usbfstab` is a comprehensive security suite for monitoring and protecting against unauthorized USB device access, forensic tools, and mouse jiggler software.

## Features

- USB Device Monitoring
  - Real-time USB device detection
  - Whitelist-based access control
  - Automatic system shutdown on unauthorized access
  - Mass storage device blocking

- Cellebrite Protection
  - Database access monitoring
  - iOS device access blocking
  - Automatic backup and encryption
  - Forensic tool detection

- Mouse Jiggler Detection
  - Process monitoring
  - Network connection analysis
  - Port scanning
  - Automatic blocking of suspicious software

## Requirements

- Python 3.8 or higher
- Root/Administrator privileges
- Linux or macOS system

## Installation

1. Clone the repository:
```bash
git clone https://github.com/Montana/usbfstab.git
cd usbfstab
```

2. Run the setup script:
```bash
sudo ./setup.sh
```

This will:
- Install required dependencies
- Create necessary directories
- Set up system services
- Configure logging

## Configuration

The main configuration file is `usbfstab.ini`. Key settings include:

```ini
[General]
check_interval = 0.5
backup_interval = 1800
max_backups = 48
alert_threshold = 2

[USB]
monitor_interval = 0.5
block_unknown = true
allowed_vendors = 05ac,0483,0781,0951
allowed_products = 8600,5740,5583,1666

[Jiggler]
enabled = true
check_interval = 2.0
block_suspicious = true

[Cellebrite]
enabled = true
check_interval = 0.5
block_ios_access = true
```

## Usage

### Starting the Service

The service will start automatically after installation. To manually control:

Linux:
```bash
sudo systemctl start usbfstab
sudo systemctl stop usbfstab
sudo systemctl status usbfstab
```

macOS:
```bash
launchctl load ~/Library/LaunchAgents/com.usbfstab.plist
launchctl unload ~/Library/LaunchAgents/com.usbfstab.plist
```

### Running Individual Tools

```bash
python3 usbfstab.py    # USB monitoring
python3 cellebrite.py  # Cellebrite protection
python3 jiggler_block.py # Jiggler detection
```

## Logging

Logs are stored in `/var/log/usbfstab/`:
- `usbfstab.log`: Main application log
- `error.log`: Error messages
- `output.log`: Standard output

## Security Features

1. **USB Protection**
   - Whitelist-based device access
   - Automatic system shutdown on unauthorized access
   - Mass storage device blocking

2. **Cellebrite Protection**
   - Database access monitoring
   - iOS device access blocking
   - Encrypted backups
   - Forensic tool detection

3. **Jiggler Detection**
   - Process monitoring
   - Network analysis
   - Port scanning
   - Automatic blocking
     
## Author

Michael Mendy (c) 2025.

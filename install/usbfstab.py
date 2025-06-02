#!/usr/bin/env python3

import os
import sys
import shutil
import logging
import asyncio
from pathlib import Path
from typing import Optional

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

async def check_root() -> None:
    if os.geteuid() != 0:
        logger.error("This script must be run as root!")
        sys.exit(1)

async def copy_config() -> None:
    try:
        script_dir = Path(__file__).parent.absolute()
        config_file = script_dir / "usbfstab.ini"
        target_file = Path("/etc/usbfstab.ini")

        if not config_file.exists():
            logger.error(f"Configuration file not found: {config_file}")
            sys.exit(1)

        if target_file.exists():
            backup_file = target_file.with_suffix('.ini.bak')
            shutil.copy2(target_file, backup_file)
            logger.info(f"Created backup of existing config at {backup_file}")

        shutil.copy2(config_file, target_file)
        logger.info(f"Configuration file installed to {target_file}")

    except Exception as e:
        logger.error(f"Failed to copy configuration file: {e}")
        sys.exit(1)

async def create_log_directory() -> None:
    try:
        log_dir = Path("/var/log/usbfstab")
        log_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"Created log directory: {log_dir}")
    except Exception as e:
        logger.error(f"Failed to create log directory: {e}")
        sys.exit(1)

async def main() -> None:
    logger.info("Starting USBFSTab installation...")
    
    await check_root()
    await copy_config()
    await create_log_directory()
    
    logger.info("Installation completed successfully!")
    print("\nUSBFSTab has been installed successfully!")
    print("To start USBFSTab, run: sudo usbfstab")
    print("Make sure to configure allowed USB devices in /etc/usbfstab.ini")

if __name__ == "__main__":
    asyncio.run(main())

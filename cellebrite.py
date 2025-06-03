#!/usr/bin/env python3

import sqlite3
import os
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
import time
import sys
import logging
import argparse
from typing import List, Dict, Optional, Set
from dataclasses import dataclass
from contextlib import contextmanager
import psutil
import signal
import json
import hashlib
import shutil
import socket
import threading
import queue
import ssl
import requests
from cryptography.fernet import Fernet

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/usbfstab/cellebrite.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

USERNAME = os.getlogin()
DB_PATH = f"/Users/{USERNAME}/Library/Application Support/Knowledge/knowledgeC.db"
BACKUP_DB_PATH = f"{DB_PATH}.backup"
ENCRYPTION_KEY = Fernet.generate_key()

CELLEBRITE_PATTERNS = {
    'processes': {
        'UFED', 'Physical', 'Logical', 'Cellebrite', 'UFED4PC',
        'UFEDPhysicalAnalyzer', 'UFEDLogicalAnalyzer', 'UFEDReader',
        'UFED4PCReader', 'UFEDPhysicalAnalyzerReader', 'UFEDLogicalAnalyzerReader'
    },
    'keywords': {
        'cellebrite', 'ufed', 'forensic', 'extraction', 'analyzer',
        'physical', 'logical', 'backup', 'extract', 'reader', 'acquisition',
        'evidence', 'investigation', 'mobile', 'device', 'extraction'
    },
    'ports': {8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089},
    'files': {
        '.ufed', '.ufdr', '.ufdx', '.ufd', '.ufedx', '.ufdrx',
        '.ufdx', '.ufd', '.ufedx', '.ufdrx', '.ufdx', '.ufd'
    }
}

IOS_DEVICE_IDS = {
    'vendor_ids': {'05ac', '05ac', '05ac', '05ac'},
    'product_ids': {'12a8', '12ab', '12a9', '12aa', '12ac', '12ad', '12ae', '12af'}
}

@dataclass
class Settings:
    check_interval: float = 0.5
    backup_interval: int = 1800
    max_backups: int = 48
    alert_threshold: int = 2
    do_backup: bool = True
    do_monitor: bool = True
    do_cleanup: bool = True
    backup_location: str = '/var/backups/usbfstab'
    encrypt_backups: bool = True
    notify_email: bool = True
    notify_api: bool = True
    shred_files: bool = True
    block_network: bool = True
    max_retries: int = 3
    retry_delay: int = 5

    @classmethod
    def from_config(cls, config: Dict) -> 'Settings':
        return cls(
            check_interval=config.get('check_interval', 0.5),
            backup_interval=config.get('backup_interval', 1800),
            max_backups=config.get('max_backups', 48),
            alert_threshold=config.get('alert_threshold', 2),
            do_backup=config.get('do_backup', True),
            do_monitor=config.get('do_monitor', True),
            do_cleanup=config.get('do_cleanup', True),
            backup_location=config.get('backup_location', '/var/backups/usbfstab'),
            encrypt_backups=config.get('encrypt_backups', True),
            notify_email=config.get('notify_email', True),
            notify_api=config.get('notify_api', True),
            shred_files=config.get('shred_files', True),
            block_network=config.get('block_network', True),
            max_retries=config.get('max_retries', 3),
            retry_delay=config.get('retry_delay', 5)
        )

def setup_argparse() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Cellebrite Monitoring Tool')
    parser.add_argument('--config', type=str, help='Path to config file')
    parser.add_argument('--no-backup', action='store_true', help='Disable backups')
    parser.add_argument('--no-monitor', action='store_true', help='Disable monitoring')
    parser.add_argument('--interval', type=float, help='Check interval in seconds')
    parser.add_argument('--no-encrypt', action='store_true', help='Disable encryption')
    parser.add_argument('--no-notify', action='store_true', help='Disable notifications')
    parser.add_argument('--no-shred', action='store_true', help='Disable file shredding')
    return parser.parse_args()

def load_config(config_path: str) -> Dict:
    try:
        with open(config_path, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        logger.warning(f"Config file not found: {config_path}, using defaults")
        return {}
    except json.JSONDecodeError:
        logger.error(f"Invalid config file: {config_path}")
        sys.exit(1)

@contextmanager
def secure_db_connection(db_path: str):
    conn = None
    try:
        conn = sqlite3.connect(db_path)
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
        yield conn
    except sqlite3.Error as e:
        logger.error(f"Database error: {e}")
        raise
    finally:
        if conn:
            conn.close()

def encrypt_file(file_path: Path, key: bytes) -> bool:
    try:
        f = Fernet(key)
        with open(file_path, 'rb') as file:
            data = file.read()
        encrypted_data = f.encrypt(data)
        with open(file_path, 'wb') as file:
            file.write(encrypted_data)
        return True
    except Exception as e:
        logger.error(f"Encryption failed: {e}")
        return False

def shred_file(file_path: Path) -> bool:
    try:
        if not file_path.exists():
            return True
        with open(file_path, 'wb') as f:
            for _ in range(3):
                f.seek(0)
                f.write(os.urandom(file_path.stat().st_size))
        file_path.unlink()
        return True
    except Exception as e:
        logger.error(f"Shredding failed: {e}")
        return False

def backup_database(settings: Settings) -> bool:
    try:
        if not settings.do_backup:
            return True
            
        backup_dir = Path(settings.backup_location)
        backup_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_path = backup_dir / f"knowledgeC_{timestamp}.db"
        
        with get_db_connection() as conn:
            backup_conn = sqlite3.connect(backup_path)
            conn.backup(backup_conn)
            backup_conn.close()
            
            if settings.encrypt_backups:
                encrypt_file(backup_path, ENCRYPTION_KEY)
            
            if settings.do_cleanup:
                cleanup_old_backups(backup_dir, settings.max_backups)
                
        logger.info(f"Database backup created: {backup_path}")
        return True
    except Exception as e:
        logger.error(f"Backup failed: {e}")
        return False

def cleanup_old_backups(backup_dir: Path, max_backups: int):
    try:
        backups = sorted(backup_dir.glob("knowledgeC_*.db"), 
                        key=lambda x: x.stat().st_mtime, 
                        reverse=True)
        
        for old_backup in backups[max_backups:]:
            if shred_file(old_backup):
                logger.info(f"Removed old backup: {old_backup}")
    except Exception as e:
        logger.error(f"Cleanup failed: {e}")

def check_cellebrite_processes() -> Dict[str, List[str]]:
    suspicious = {'processes': [], 'connections': [], 'files': []}
    
    for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'connections', 'open_files']):
        try:
            if any(pattern.lower() in proc.info['name'].lower() 
                  for pattern in CELLEBRITE_PATTERNS['processes']):
                suspicious['processes'].append(proc.info['name'])
            
            if proc.info['cmdline']:
                cmdline = ' '.join(proc.info['cmdline']).lower()
                if any(keyword in cmdline 
                      for keyword in CELLEBRITE_PATTERNS['keywords']):
                    suspicious['processes'].append(f"{proc.info['name']} ({cmdline})")
            
            if proc.info['connections']:
                for conn in proc.info['connections']:
                    if conn.laddr.port in CELLEBRITE_PATTERNS['ports']:
                        suspicious['connections'].append(
                            f"{proc.info['name']} -> {conn.laddr.ip}:{conn.laddr.port}"
                        )
            
            if proc.info['open_files']:
                for file in proc.info['open_files']:
                    if any(file.path.endswith(ext) for ext in CELLEBRITE_PATTERNS['files']):
                        suspicious['files'].append(file.path)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    
    return suspicious

def is_ios_device(device_info: Dict) -> bool:
    vendor_id = device_info.get('vendor_id', '').lower()
    product_id = device_info.get('product_id', '').lower()
    
    return (vendor_id in IOS_DEVICE_IDS['vendor_ids'] and 
            product_id in IOS_DEVICE_IDS['product_ids'])

def check_ios_cellebrite_conflict() -> bool:
    try:
        ios_devices = []
        for device in psutil.disk_partitions():
            if is_ios_device({'vendor_id': device.mountpoint.split('/')[-1]}):
                ios_devices.append(device.mountpoint)
        
        cellebrite_running = bool(check_cellebrite_processes()['processes'])
        
        if ios_devices and cellebrite_running:
            logger.warning(f"iOS devices detected: {ios_devices}")
            logger.warning("Cellebrite processes running simultaneously")
            return True
            
        return False
    except Exception as e:
        logger.error(f"Error checking iOS-Cellebrite conflict: {e}")
        return False

def block_network_access():
    try:
        subprocess.run(['iptables', '-A', 'OUTPUT', '-p', 'tcp', '--dport', '8080:8089', '-j', 'DROP'], check=True)
        subprocess.run(['iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', '8080:8089', '-j', 'DROP'], check=True)
        return True
    except Exception as e:
        logger.error(f"Network blocking failed: {e}")
        return False

def send_alert(settings: Settings, message: str):
    if settings.notify_email:
        try:
            subprocess.run(['mail', '-s', 'Security Alert', ALERT_EMAIL], input=message.encode(), check=True)
        except Exception as e:
            logger.error(f"Email alert failed: {e}")
    
    if settings.notify_api:
        try:
            requests.post(API_ENDPOINT, json={'message': message}, timeout=5)
        except Exception as e:
            logger.error(f"API alert failed: {e}")

def handle_security_breach(settings: Settings):
    try:
        logger.warning("Security breach detected! Removing sensitive data...")
        
        db_path = Path(f"/Users/{USERNAME}/Library/Application Support/Knowledge/knowledgeC.db")
        if db_path.exists():
            if settings.shred_files:
                shred_file(db_path)
            else:
                db_path.unlink()
            logger.info("Database removed")
        
        backup_dir = Path(settings.backup_location)
        if backup_dir.exists():
            for backup in backup_dir.glob("knowledgeC_*.db"):
                if settings.shred_files:
                    shred_file(backup)
                else:
                    backup.unlink()
            logger.info("Backups removed")
        
        if settings.block_network:
            block_network_access()
        
        send_alert(settings, "Security breach detected and handled")
        
    except Exception as e:
        logger.error(f"Error during security breach handling: {e}")

def main():
    args = setup_argparse()
    config = load_config(args.config)
    settings = Settings.from_config(config)
    
    if args.interval:
        settings.check_interval = args.interval
    if args.no_backup:
        settings.do_backup = False
    if args.no_monitor:
        settings.do_monitor = False
    if args.no_encrypt:
        settings.encrypt_backups = False
    if args.no_notify:
        settings.notify_email = False
        settings.notify_api = False
    if args.no_shred:
        settings.shred_files = False
    
    logger.info("Starting Cellebrite monitoring...")
    
    try:
        while True:
            if settings.do_monitor:
                suspicious = check_cellebrite_processes()
                if suspicious['processes'] or suspicious['connections'] or suspicious['files']:
                    logger.warning("Suspicious activity detected!")
                    logger.warning(f"Processes: {suspicious['processes']}")
                    logger.warning(f"Connections: {suspicious['connections']}")
                    logger.warning(f"Files: {suspicious['files']}")
                    handle_security_breach(settings)
                
                if check_ios_cellebrite_conflict():
                    handle_security_breach(settings)
            
            if settings.do_backup:
                backup_database(settings)
            
            time.sleep(settings.check_interval)
            
    except KeyboardInterrupt:
        logger.info("Monitoring stopped by user")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

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

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('cellebrite_detection.log')
    ]
)
logger = logging.getLogger(__name__)

USERNAME = os.getlogin()
DB_PATH = f"/Users/{USERNAME}/Library/Application Support/Knowledge/knowledgeC.db"
BACKUP_DB_PATH = f"{DB_PATH}.backup"

CELLEBRITE_PATTERNS = {
    'process_names': [
        'cellebrite', 'ufed', 'physical', 'logical',
        'ufed4pc', 'ufedphysical', 'ufedlogical'
    ],
    'keywords': [
        'cellebrite', 'ufed', 'extraction', 'forensic',
        'physical', 'logical', 'backup'
    ],
    'suspicious_ports': [8080, 8081, 8082]
}

@dataclass
class Settings:
    check_interval: float
    backup_interval: int
    max_backups: int
    alert_threshold: int
    do_backup: bool
    do_monitor: bool
    do_cleanup: bool

    @classmethod
    def from_config(cls, config: Dict) -> 'Settings':
        return cls(
            check_interval=config.get('check_interval', 1.0),
            backup_interval=config.get('backup_interval', 3600),
            max_backups=config.get('max_backups', 24),
            alert_threshold=config.get('alert_threshold', 3),
            do_backup=config.get('do_backup', True),
            do_monitor=config.get('do_monitor', True),
            do_cleanup=config.get('do_cleanup', True)
        )

def setup_argparse() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Monitor and protect against Cellebrite access')
    parser.add_argument('--config', type=str, default='config.json', help='Path to config file')
    parser.add_argument('--no-backup', action='store_true', help='Disable database backup')
    parser.add_argument('--no-monitor', action='store_true', help='Disable monitoring')
    parser.add_argument('--no-cleanup', action='store_true', help='Disable cleanup')
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
    """Secure database connection with proper error handling"""
    conn = None
    try:
        conn = sqlite3.connect(db_path)
        conn.execute("PRAGMA foreign_keys = ON")
        yield conn
    except sqlite3.Error as e:
        logger.error(f"Database error: {e}")
        raise
    finally:
        if conn:
            conn.close()

def backup_database() -> bool:
    """Create a backup of the database"""
    try:
        if not os.path.exists(DB_PATH):
            logger.error("Database not found")
            return False

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = f"{BACKUP_DB_PATH}.{timestamp}"
        
        os.makedirs(os.path.dirname(backup_path), exist_ok=True)
        
        shutil.copy2(DB_PATH, backup_path)
        logger.info(f"Database backed up to {backup_path}")
        return True
    except Exception as e:
        logger.error(f"Backup failed: {e}")
        return False

def cleanup_old_backups(max_backups: int) -> None:
    """Remove old backup files keeping only the most recent ones"""
    try:
        backup_dir = os.path.dirname(BACKUP_DB_PATH)
        backups = sorted(
            [f for f in os.listdir(backup_dir) if f.startswith(os.path.basename(BACKUP_DB_PATH))],
            key=lambda x: os.path.getmtime(os.path.join(backup_dir, x)),
            reverse=True
        )
        
        for old_backup in backups[max_backups:]:
            try:
                os.remove(os.path.join(backup_dir, old_backup))
                logger.info(f"Removed old backup: {old_backup}")
            except OSError as e:
                logger.error(f"Failed to remove old backup {old_backup}: {e}")
    except Exception as e:
        logger.error(f"Cleanup failed: {e}")

def check_cellebrite_processes() -> bool:
    """Check for running Cellebrite processes"""
    try:
        for proc in psutil.process_iter(['name', 'cmdline']):
            try:
                name = proc.info['name'] or ""
                cmdline = " ".join(proc.info['cmdline']) if proc.info['cmdline'] else ""
                
                if any(pattern.lower() in name.lower() for pattern in CELLEBRITE_PATTERNS['process_names']):
                    logger.warning(f"Cellebrite process detected: {name}")
                    return True
                
                if any(keyword.lower() in cmdline.lower() for keyword in CELLEBRITE_PATTERNS['keywords']):
                    logger.warning(f"Cellebrite activity detected in process: {name}")
                    return True
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return False
    except Exception as e:
        logger.error(f"Error checking for Cellebrite processes: {e}")
        return False

def check_suspicious_connections() -> bool:
    """Check for suspicious network connections"""
    try:
        for conn in psutil.net_connections():
            if conn.laddr.port in CELLEBRITE_PATTERNS['suspicious_ports']:
                logger.warning(f"Suspicious connection on port {conn.laddr.port}")
                return True
        return False
    except Exception as e:
        logger.error(f"Error checking network connections: {e}")
        return False

def monitor_database_access() -> bool:
    """Monitor database access patterns"""
    try:
        if not os.path.exists(DB_PATH):
            return False

        for proc in psutil.process_iter(['name', 'open_files']):
            try:
                if proc.info['name'] and DB_PATH in [f.path for f in proc.open_files()]:
                    logger.warning(f"Database access by process: {proc.info['name']}")
                    return True
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return False
    except Exception as e:
        logger.error(f"Error monitoring database access: {e}")
        return False

def handle_security_breach() -> None:
    """Handle security breach by removing sensitive data"""
    try:
        logger.warning("Security breach detected! Removing sensitive data...")
        
        if os.path.exists(DB_PATH):
            os.remove(DB_PATH)
            logger.info("Database removed")
        
        backup_dir = os.path.dirname(BACKUP_DB_PATH)
        if os.path.exists(backup_dir):
            shutil.rmtree(backup_dir)
            logger.info("Backups removed")
        
        
    except Exception as e:
        logger.error(f"Error during security breach handling: {e}")

def main():
    args = setup_argparse()
    config = load_config(args.config)
    settings = Settings.from_config(config)
    
    if args.no_backup:
        settings.do_backup = False
    if args.no_monitor:
        settings.do_monitor = False
    if args.no_cleanup:
        settings.do_cleanup = False

    def signal_handler(signum, frame):
        logger.info("Received exit signal. Shutting down...")
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    last_backup_time = time.time()
    alert_count = 0

    logger.info("Starting Cellebrite monitoring...")
    
    while True:
        try:
            if settings.do_monitor:

                if check_cellebrite_processes():
                    alert_count += 1
                
                if check_suspicious_connections():
                    alert_count += 1
                
                if monitor_database_access():
                    alert_count += 1
                
                if alert_count >= settings.alert_threshold:
                    handle_security_breach()
                    sys.exit(1)
            
            if settings.do_backup and time.time() - last_backup_time >= settings.backup_interval:
                if backup_database():
                    last_backup_time = time.time()
                    if settings.do_cleanup:
                        cleanup_old_backups(settings.max_backups)
            
            time.sleep(settings.check_interval)
            
        except Exception as e:
            logger.error(f"Error in main loop: {e}")
            time.sleep(settings.check_interval)

if __name__ == "__main__":
    main()

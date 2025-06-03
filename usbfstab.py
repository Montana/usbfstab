#!/usr/bin/env python3

from __future__ import annotations

__version__ = "1.0.0"

import re
import subprocess
import platform
import os
import sys
import signal
import logging
import configparser
import shutil
from pathlib import Path
from time import sleep
from datetime import datetime
from typing import Dict, List, Set, Optional, Union, Any
from dataclasses import dataclass
from contextlib import contextmanager
import asyncio
from concurrent.futures import ThreadPoolExecutor
import psutil
import sqlite3
import json
import hashlib
import socket
import threading
import queue
import ssl
import requests
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import secrets
import tempfile
import mmap
import struct
import binascii

CURRENT_PLATFORM = platform.system().upper()

if CURRENT_PLATFORM.startswith("DARWIN"):
	import plistlib

DEVICE_RE = [
	re.compile(r".+ID\s(?P<id>\w+:\w+)"),
	re.compile(r"0x([0-9a-z]{4})")
]

IOS_DEVICE_IDS = {
	'05ac': 'Apple',  
	'05ac:12a8': 'iPhone',
	'05ac:12ab': 'iPad',
	'05ac:12a9': 'iPod',
	'05ac:12aa': 'Apple Watch',
	'05ac:12ac': 'Apple TV'
}

CELLEBRITE_PATTERNS = {
	'process_names': [
		'cellebrite', 'ufed', 'physical', 'logical',
		'ufed4pc', 'ufedphysical', 'ufedlogical',
		'ufedreader', 'ufed4pc', 'ufed4pc.exe',
		'physicalanalyzer', 'logicalanalyzer',
		'ufedphysicalanalyzer', 'ufedlogicalanalyzer'
	],
	'keywords': [
		'cellebrite', 'ufed', 'extraction', 'forensic',
		'physical', 'logical', 'backup', 'analyzer',
		'reader', 'extractor', 'forensics', 'evidence',
		'investigation', 'acquisition', 'extraction'
	],
	'ports': [8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089],
	'file_extensions': [
		'.ufd', '.ufdr', '.ufdx', '.ufd4pc',
		'.ufdphysical', '.ufdlogical', '.ufdreader',
		'.ufdanalyzer', '.ufdbackup', '.ufdextraction'
	],
	'registry_keys': [
		'SOFTWARE\\Cellebrite',
		'SOFTWARE\\UFED',
		'SOFTWARE\\Physical Analyzer',
		'SOFTWARE\\Logical Analyzer'
	]
}

JIGGLER_PATTERNS = {
	'keywords': [
		"jiggler", "mouse mover", "wiggler", "mousejiggle",
		"caffeine", "nosleep", "stayawake", "mousejiggler",
		"mousejiggle", "mousejiggler", "mousejiggle.exe",
		"jiggler.exe", "wiggler.exe", "caffeine.exe",
		"nosleep.exe", "stayawake.exe"
	],
	'suspicious_processes': [
		"mousejiggle", "jiggler", "wiggler", "caffeine",
		"nosleep", "stayawake", "jiggler.exe", "wiggler.exe",
		"caffeine.exe", "nosleep.exe", "stayawake.exe"
	],
	'suspicious_ports': [8080, 8081, 8082, 8083, 8084, 8085],
	'file_extensions': [
		'.exe', '.dll', '.sys', '.bat', '.cmd', '.ps1',
		'.vbs', '.js', '.wsf', '.msi', '.inf', '.reg'
	],
	'registry_keys': [
		'SOFTWARE\\MouseJiggle',
		'SOFTWARE\\Jiggler',
		'SOFTWARE\\Wiggler',
		'SOFTWARE\\Caffeine',
		'SOFTWARE\\NoSleep',
		'SOFTWARE\\StayAwake'
	]
}

USB_PATTERNS = {
	'blocked_vendors': {
		'05ac', '0483', '0781', '0951', '0bda', '0cf3',
		'04f3', '046d', '045e', '0461', '0451', '0457',
		'04e8', '04b4', '04b3', '04b0', '04a9', '04a5'
	},
	'blocked_products': {
		'8600', '5740', '5583', '1666', '8176', '8179',
		'8178', '8177', '8176', '8175', '8174', '8173',
		'8172', '8171', '8170', '8169', '8168', '8167'
	},
	'suspicious_ports': {8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089},
	'suspicious_files': {
		'.exe', '.dll', '.sys', '.bat', '.cmd', '.ps1',
		'.vbs', '.js', '.wsf', '.msi', '.inf', '.reg',
		'.ufd', '.ufdr', '.ufdx', '.ufd4pc', '.ufdphysical',
		'.ufdlogical', '.ufdreader', '.ufdanalyzer', '.ufdbackup'
	}
}

ENCRYPTION_SETTINGS = {
	'salt_length': 16,
	'key_length': 32,
	'iterations': 100000,
	'algorithm': 'AES-256-GCM',
	'tag_length': 16,
	'nonce_length': 12
}

SECURITY_SETTINGS = {
	'max_retries': 3,
	'retry_delay': 5,
	'alert_threshold': 2,
	'backup_interval': 1800,
	'max_backups': 48,
	'check_interval': 0.5,
	'shred_passes': 3,
	'encryption_enabled': True,
	'network_blocking': True,
	'file_shredding': True,
	'process_killing': True,
	'registry_monitoring': True
}

SETTINGS_FILE = '/etc/usbfstab.ini'
DEFAULT_LOG_FILE = '/var/log/usbfstab/kills.log'

USERNAME = os.getlogin()
CELLEBRITE_DB_PATH = f"/Users/{USERNAME}/Library/Application Support/Knowledge/knowledgeC.db"

logging.basicConfig(
	level=logging.DEBUG,
	format='%(asctime)s - %(levelname)s - %(message)s',
	handlers=[
		logging.FileHandler('/var/log/usbfstab/usbfstab.log'),
		logging.StreamHandler(sys.stdout)
	]
)
logger = logging.getLogger(__name__)

ENCRYPTION_KEY = Fernet.generate_key()

@dataclass
class Settings:
	sleep_time: float
	whitelist: Set[str]
	log_file: str
	remove_file_cmd: str
	melt_usbkill: bool
	folders_to_remove: List[str]
	files_to_remove: List[str]
	kill_commands: List[str]
	do_sync: bool
	do_wipe_ram: bool
	do_wipe_swap: bool
	wipe_ram_cmd: str
	wipe_swap_cmd: str
	shut_down: bool
	check_jiggler: bool
	check_cellebrite: bool
	block_ios_access: bool
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
	allowed_vendors: Set[str] = None
	allowed_products: Set[str] = None
	
	encryption_settings: Dict = None
	security_settings: Dict = None
	cellebrite_patterns: Dict = None
	jiggler_patterns: Dict = None
	usb_patterns: Dict = None
	
	def __post_init__(self):
		if self.allowed_vendors is None:
			self.allowed_vendors = set()
		if self.allowed_products is None:
			self.allowed_products = set()
		if self.encryption_settings is None:
			self.encryption_settings = ENCRYPTION_SETTINGS
		if self.security_settings is None:
			self.security_settings = SECURITY_SETTINGS
		if self.cellebrite_patterns is None:
			self.cellebrite_patterns = CELLEBRITE_PATTERNS
		if self.jiggler_patterns is None:
			self.jiggler_patterns = JIGGLER_PATTERNS
		if self.usb_patterns is None:
			self.usb_patterns = USB_PATTERNS

class DeviceCountSet(dict):
	def __init__(self, items: Union[List[str], List[Dict[str, int]]]) -> None:
		count: Dict[str, int] = {}
		for item in items:
			if isinstance(item, dict):
				count.update(item)
			elif item in count:
				count[item] += 1
			else:
				count[item] = 1
		super().__init__(count)

	def __add__(self, other: Union[DeviceCountSet, List[str]]) -> DeviceCountSet:
		new_dict = dict(self)
		if isinstance(other, (list, tuple)):
			for k in other:
				new_dict[k] = new_dict.get(k, 0) + 1
		else:
			for k, v in other.items():
				new_dict[k] = max(new_dict.get(k, 0), v)
		return DeviceCountSet(new_dict)

@contextmanager
def secure_file_operation(filepath: str, mode: str = 'a+') -> Any:
	try:
		with open(filepath, mode) as f:
			yield f
	except (IOError, PermissionError) as e:
			logger.error(f"Failed to access file {filepath}: {e}")
			raise

async def log(settings: Settings, msg: str) -> None:
	try:
		async with asyncio.Lock():
			with secure_file_operation(settings.log_file) as log_file:
				log_file.write(f'\n{datetime.now()} {msg}\nCurrent state:\n')
			if CURRENT_PLATFORM.startswith("DARWIN"):
				await asyncio.create_subprocess_exec("system_profiler", "SPUSBDataType", stdout=open(settings.log_file, 'a'), stderr=subprocess.PIPE)
			else:
				await asyncio.create_subprocess_exec("lsusb", stdout=open(settings.log_file, 'a'), stderr=subprocess.PIPE)
	except Exception as e:
			logger.error(f"Failed to log USB state: {e}")

async def shred(settings: Settings) -> None:
	shredder = settings.remove_file_cmd
	if settings.melt_usbkill:
		settings.folders_to_remove.extend([os.path.dirname(settings.log_file), os.path.dirname(SETTINGS_FILE)])
		usbkill_folder = os.path.dirname(os.path.realpath(__file__))
		if usbkill_folder.upper().startswith('USB'):
			settings.folders_to_remove.append(usbkill_folder)
		else:
			settings.files_to_remove.extend([os.path.realpath(__file__), os.path.join(usbkill_folder, "usbfstab.ini")])

	async def shred_path(path: str) -> None:
		try:
			await asyncio.create_subprocess_shell(f"{shredder}{path}", stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		except subprocess.CalledProcessError as e:
			logger.error(f"Failed to shred {path}: {e}")

	await asyncio.gather(*(shred_path(path) for path in settings.files_to_remove + settings.folders_to_remove))

async def kill_computer(settings: Settings) -> None:
	if not settings.melt_usbkill:
		await log(settings, "Detected a USB change. Dumping the list of connected devices and killing the computer...")
	await shred(settings)

	async def run_command(command: str) -> None:
		try:
			await asyncio.create_subprocess_shell(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		except subprocess.CalledProcessError as e:
			logger.error(f"Failed to execute kill command {command}: {e}")

	await asyncio.gather(*(run_command(cmd) for cmd in settings.kill_commands))

	if settings.do_sync:
		await asyncio.create_subprocess_shell("sync")
	else:
		await asyncio.sleep(0.05)

	if settings.do_wipe_ram and settings.do_wipe_swap:
		await asyncio.gather(
			asyncio.create_subprocess_shell(settings.wipe_ram_cmd),
			asyncio.create_subprocess_shell(settings.wipe_swap_cmd)
		)
	elif settings.do_wipe_ram:
		await asyncio.create_subprocess_shell(settings.wipe_ram_cmd)
	elif settings.do_wipe_swap:
		await asyncio.create_subprocess_shell(settings.wipe_swap_cmd)

	if settings.shut_down:
		try:
			if CURRENT_PLATFORM.startswith("DARWIN"):
				await asyncio.create_subprocess_shell("killall Finder ; killall loginwindow ; halt -q")
			elif CURRENT_PLATFORM.endswith("BSD"):
				await asyncio.create_subprocess_shell("shutdown -h now")
			else:
				await asyncio.create_subprocess_shell("poweroff -f")
		except subprocess.CalledProcessError as e:
			logger.error(f"Failed to shutdown system: {e}")

	sys.exit(0)

async def lsusb_darwin() -> List[str]:
	try:
		proc = await asyncio.create_subprocess_exec("system_profiler", "SPUSBDataType", "-xml", "-detailLevel", "mini", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
		stdout, _ = await proc.communicate()
		df = plistlib.loads(stdout.decode())
	except subprocess.CalledProcessError as e:
		logger.error(f"Failed to get USB information: {e}")
		return []

	devices = []

	def check_inside(result: dict, devices: List[str]) -> None:
		if "Built-in_Device" not in result:
			try:
				vendor_id = DEVICE_RE[1].findall(result["vendor_id"])[0]
				product_id = DEVICE_RE[1].findall(result["product_id"])[0]
				devices.append(f"{vendor_id}:{product_id}")
			except (KeyError, IndexError):
				pass
		for item in result.get("_items", []):
			check_inside(item, devices)

	for result in df[0]["_items"]:
		check_inside(result, devices)

	return devices

async def lsusb() -> DeviceCountSet:
	if CURRENT_PLATFORM.startswith("DARWIN"):
		return DeviceCountSet(await lsusb_darwin())
	else:
		try:
			proc = await asyncio.create_subprocess_exec("lsusb", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
			stdout, _ = await proc.communicate()
			return DeviceCountSet(DEVICE_RE[0].findall(stdout.decode().strip()))
		except subprocess.CalledProcessError as e:
			logger.error(f"Failed to execute lsusb: {e}")
			return DeviceCountSet([])

def program_present(program: str) -> bool:
	return shutil.which(program) is not None

def load_settings(filename: str) -> Settings:
	config = configparser.ConfigParser()
	try:
		config.read(filename)
		return Settings.from_config(config)
	except Exception as e:
		logger.error(f"Failed to load settings: {e}")
		sys.exit(1)

async def check_jiggler() -> bool:
	"""Check for mouse jiggler processes and suspicious activities"""
	try:
		for proc in psutil.process_iter(['name', 'cmdline']):
			try:
				name = proc.info['name'] or ""
				cmdline = " ".join(proc.info['cmdline']) if proc.info['cmdline'] else ""
				if any(k in name.lower() or k in cmdline.lower() for k in JIGGLER_PATTERNS['keywords']):
					logger.warning(f"Mouse jiggler detected: {name}")
					return True
			except (psutil.NoSuchProcess, psutil.AccessDenied):
				continue

		for conn in psutil.net_connections():
			if conn.laddr.port in JIGGLER_PATTERNS['suspicious_ports']:
				logger.warning(f"Suspicious network connection detected on port {conn.laddr.port}")
				return True

		return False
	except Exception as e:
		logger.error(f"Error checking for jiggler: {e}")
		return False

async def check_cellebrite() -> bool:
	"""Check for Cellebrite database access"""
	try:
		if not os.path.exists(CELLEBRITE_DB_PATH):
			return False

		for proc in psutil.process_iter(['name', 'open_files']):
			try:
				if proc.info['name'] and CELLEBRITE_DB_PATH in [f.path for f in proc.open_files()]:
					logger.warning(f"Cellebrite database access detected by process: {proc.info['name']}")
					return True
			except (psutil.NoSuchProcess, psutil.AccessDenied):
				continue

		return False
	except Exception as e:
		logger.error(f"Error checking for Cellebrite: {e}")
		return False

async def is_ios_device(device_id: str) -> bool:
	"""Check if a device ID belongs to an iOS device"""
	vendor_id = device_id.split(':')[0].lower()
	return vendor_id in IOS_DEVICE_IDS

async def check_cellebrite_processes() -> bool:
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

async def check_ios_cellebrite_conflict(settings: Settings, current_devices: DeviceCountSet) -> bool:
	"""Check for iOS devices and Cellebrite processes simultaneously"""
	if not settings.block_ios_access:
		return False

	ios_devices = [device for device in current_devices if await is_ios_device(device)]
	if not ios_devices:
		return False

	if await check_cellebrite_processes():
		logger.warning("iOS device detected with Cellebrite process running!")
		return True

	return False

async def security_checks(settings: Settings, current_devices: DeviceCountSet) -> bool:
	"""Perform all security checks with enhanced detection"""
	try:
		cellebrite_suspicious = enhanced_check_cellebrite()
		if any(cellebrite_suspicious.values()):
			logger.warning("Cellebrite activity detected!")
			logger.warning(f"Cellebrite suspicious activities: {cellebrite_suspicious}")
			return True
		
		jiggler_suspicious = enhanced_check_jiggler()
		if any(jiggler_suspicious.values()):
			logger.warning("Jiggler activity detected!")
			logger.warning(f"Jiggler suspicious activities: {jiggler_suspicious}")
			return True
		
		if await check_ios_cellebrite_conflict(settings, current_devices):
			logger.warning("iOS device detected with Cellebrite process!")
			return True
		
		return False
	except Exception as e:
		logger.error(f"Security checks failed: {e}")
		return True

async def loop(settings: Settings) -> None:
	initial_state = await lsusb()
	logger.info("Starting security monitoring...")
	while True:
		try:
			current_state = await lsusb()
			if current_state != initial_state:
				if not all(device in settings.whitelist for device in current_state):
					await kill_computer(settings)
				elif not all(device in current_state for device in initial_state):
					await kill_computer(settings)

			if await security_checks(settings, current_state):
				await kill_computer(settings)

			await asyncio.sleep(settings.sleep_time)
		except Exception as e:
			logger.error(f"Error in monitoring loop: {e}")
			await asyncio.sleep(settings.sleep_time)

def startup_checks() -> None:
	if os.geteuid() != 0:
		logger.error("This program needs to run as root!")
		sys.exit(1)
	required_programs = ["lsusb"] if not CURRENT_PLATFORM.startswith("DARWIN") else []
	missing_programs = [prog for prog in required_programs if not program_present(prog)]
	if missing_programs:
		logger.error(f"Missing required programs: {', '.join(missing_programs)}")
		sys.exit(1)
	log_dir = os.path.dirname(DEFAULT_LOG_FILE)
	if not os.path.exists(log_dir):
		try:
			os.makedirs(log_dir)
		except OSError as e:
			logger.error(f"Failed to create log directory: {e}")
			sys.exit(1)

async def main() -> None:
	startup_checks()
	settings = load_settings(SETTINGS_FILE)
	def exit_handler(signum: int, frame: Optional[object]) -> None:
		logger.info("Received exit signal. Shutting down...")
		sys.exit(0)
	signal.signal(signal.SIGINT, exit_handler)
	signal.signal(signal.SIGTERM, exit_handler)
	await loop(settings)

def setup_argparse() -> argparse.Namespace:
	parser = argparse.ArgumentParser(description='USB Security Monitoring Tool')
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

def generate_encryption_key(password: str, salt: bytes = None) -> tuple[bytes, bytes]:
	if salt is None:
		salt = secrets.token_bytes(ENCRYPTION_SETTINGS['salt_length'])
	kdf = PBKDF2HMAC(
		algorithm=hashes.SHA256(),
		length=ENCRYPTION_SETTINGS['key_length'],
		salt=salt,
		iterations=ENCRYPTION_SETTINGS['iterations'],
		backend=default_backend()
	)
	key = kdf.derive(password.encode())
	return key, salt

def encrypt_data(data: bytes, key: bytes) -> tuple[bytes, bytes, bytes]:
	nonce = secrets.token_bytes(ENCRYPTION_SETTINGS['nonce_length'])
	cipher = Cipher(
		algorithms.AES(key),
		modes.GCM(nonce),
		backend=default_backend()
	)
	encryptor = cipher.encryptor()
	ciphertext = encryptor.update(data) + encryptor.finalize()
	return ciphertext, nonce, encryptor.tag

def decrypt_data(ciphertext: bytes, key: bytes, nonce: bytes, tag: bytes) -> bytes:
	cipher = Cipher(
		algorithms.AES(key),
		modes.GCM(nonce, tag),
		backend=default_backend()
	)
	decryptor = cipher.decryptor()
	return decryptor.update(ciphertext) + decryptor.finalize()

def secure_encrypt_file(file_path: Path, password: str) -> bool:
	try:
		with open(file_path, 'rb') as f:
			data = f.read()
		
		key, salt = generate_encryption_key(password)
		ciphertext, nonce, tag = encrypt_data(data, key)
		
		with open(file_path, 'wb') as f:
			f.write(salt + nonce + tag + ciphertext)
		return True
	except Exception as e:
		logger.error(f"Secure encryption failed: {e}")
		return False

def secure_decrypt_file(file_path: Path, password: str) -> bool:
	try:
		with open(file_path, 'rb') as f:
			data = f.read()
		
		salt = data[:ENCRYPTION_SETTINGS['salt_length']]
		nonce = data[ENCRYPTION_SETTINGS['salt_length']:ENCRYPTION_SETTINGS['salt_length'] + ENCRYPTION_SETTINGS['nonce_length']]
		tag = data[ENCRYPTION_SETTINGS['salt_length'] + ENCRYPTION_SETTINGS['nonce_length']:ENCRYPTION_SETTINGS['salt_length'] + ENCRYPTION_SETTINGS['nonce_length'] + ENCRYPTION_SETTINGS['tag_length']]
		ciphertext = data[ENCRYPTION_SETTINGS['salt_length'] + ENCRYPTION_SETTINGS['nonce_length'] + ENCRYPTION_SETTINGS['tag_length']:]
		
		key, _ = generate_encryption_key(password, salt)
		decrypted_data = decrypt_data(ciphertext, key, nonce, tag)
		
		with open(file_path, 'wb') as f:
			f.write(decrypted_data)
		return True
	except Exception as e:
		logger.error(f"Secure decryption failed: {e}")
		return False

def secure_shred_file(file_path: Path) -> bool:
	try:
		if not file_path.exists():
			return True
		
		file_size = file_path.stat().st_size
		with open(file_path, 'r+b') as f:

			mm = mmap.mmap(f.fileno(), 0)
			
			for _ in range(SECURITY_SETTINGS['shred_passes']):
				mm.seek(0)
				mm.write(os.urandom(file_size))
			
			mm.seek(0)
			mm.write(b'\x00' * file_size)
			
			mm.seek(0)
			mm.write(b'\xFF' * file_size)
			
			mm.close()
		
		file_path.unlink()
		return True
	except Exception as e:
		logger.error(f"Secure shredding failed: {e}")
		return False

def check_registry_keys(patterns: Dict) -> List[str]:
	suspicious = []
	if CURRENT_PLATFORM.startswith("WIN"):
		try:
			for key in patterns.get('registry_keys', []):
				result = subprocess.run(['reg', 'query', key], capture_output=True, text=True)
				if result.returncode == 0:
					suspicious.append(f"Found registry key: {key}")
		except Exception as e:
			logger.error(f"Registry check failed: {e}")
	return suspicious

def enhanced_check_cellebrite() -> Dict[str, List[str]]:
	suspicious = {
		'processes': [],
		'files': [],
		'ports': [],
		'registry': []
	}
	
	try:
		for proc in psutil.process_iter(['name', 'cmdline', 'open_files']):
			try:
				name = proc.info['name'] or ""
				cmdline = " ".join(proc.info['cmdline']) if proc.info['cmdline'] else ""
				
				if any(pattern.lower() in name.lower() for pattern in CELLEBRITE_PATTERNS['process_names']):
					suspicious['processes'].append(f"Cellebrite process: {name}")
				
				if any(keyword.lower() in cmdline.lower() for keyword in CELLEBRITE_PATTERNS['keywords']):
					suspicious['processes'].append(f"Cellebrite activity in process: {name}")
				
				for file in proc.info['open_files']:
					if any(ext in file.path.lower() for ext in CELLEBRITE_PATTERNS['file_extensions']):
						suspicious['files'].append(f"Cellebrite file access: {file.path}")
			except (psutil.NoSuchProcess, psutil.AccessDenied):
				continue
		
		for conn in psutil.net_connections():
			if conn.laddr.port in CELLEBRITE_PATTERNS['ports']:
				suspicious['ports'].append(f"Cellebrite port: {conn.laddr.port}")
		
		suspicious['registry'] = check_registry_keys(CELLEBRITE_PATTERNS)
		
	except Exception as e:
		logger.error(f"Enhanced Cellebrite check failed: {e}")
	
	return suspicious

def enhanced_check_jiggler() -> Dict[str, List[str]]:
	suspicious = {
		'processes': [],
		'files': [],
		'ports': [],
		'registry': []
	}
	
	try:
		for proc in psutil.process_iter(['name', 'cmdline']):
			try:
				name = proc.info['name'] or ""
				cmdline = " ".join(proc.info['cmdline']) if proc.info['cmdline'] else ""
				
				if any(pattern.lower() in name.lower() for pattern in JIGGLER_PATTERNS['suspicious_processes']):
					suspicious['processes'].append(f"Jiggler process: {name}")
				
				if any(keyword.lower() in cmdline.lower() for keyword in JIGGLER_PATTERNS['keywords']):
					suspicious['processes'].append(f"Jiggler activity in process: {name}")
			except (psutil.NoSuchProcess, psutil.AccessDenied):
				continue
		
		for conn in psutil.net_connections():
			if conn.laddr.port in JIGGLER_PATTERNS['suspicious_ports']:
				suspicious['ports'].append(f"Jiggler port: {conn.laddr.port}")
		
		suspicious['registry'] = check_registry_keys(JIGGLER_PATTERNS)
		
	except Exception as e:
		logger.error(f"Enhanced jiggler check failed: {e}")
	
	return suspicious

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
	
	logger.info("Starting USB security monitoring...")
	
	try:
		while True:
			if settings.do_monitor:
				suspicious_devices = check_usb_devices()
				suspicious_connections = check_network_connections()
				
				if (suspicious_devices['devices'] or 
					suspicious_devices['files'] or 
					suspicious_connections):
					logger.warning("Suspicious activity detected!")
					logger.warning(f"Devices: {suspicious_devices['devices']}")
					logger.warning(f"Files: {suspicious_devices['files']}")
					logger.warning(f"Connections: {suspicious_connections}")
					handle_security_breach(settings)
			
			time.sleep(settings.check_interval)
			
	except KeyboardInterrupt:
		logger.info("Monitoring stopped by user")
	except Exception as e:
		logger.error(f"Unexpected error: {e}")
		sys.exit(1)

if __name__ == "__main__":
	main()

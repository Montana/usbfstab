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
from typing import Dict, List, Set, Optional, Union, Any, Tuple
from dataclasses import dataclass, field
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
import ctypes
import array
import argparse

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

MEMORY_PROTECTION = {
	'PAGE_EXECUTE': 0x10,
	'PAGE_EXECUTE_READ': 0x20,
	'PAGE_EXECUTE_READWRITE': 0x40,
	'PAGE_EXECUTE_WRITECOPY': 0x80,
	'PAGE_NOACCESS': 0x01,
	'PAGE_READONLY': 0x02,
	'PAGE_READWRITE': 0x04,
	'PAGE_WRITECOPY': 0x08,
	'PAGE_GUARD': 0x100,
	'PAGE_NOCACHE': 0x200,
	'PAGE_WRITECOMBINE': 0x400
}

@dataclass
class MemoryRegion:
	"""Represents a protected memory region."""
	start: int
	size: int
	protection: int
	hash: str = field(default='')
	last_check: float = field(default=0.0)

class IMSEProtection:
	"""IMSE attack protection and monitoring."""
	
	def __init__(self):
		self.protected_regions: List[MemoryRegion] = []
		self.memory_hashes: Dict[int, str] = {}
		self.suspicious_patterns: Set[bytes] = {
			b'\x90' * 16,  
			b'\xCC' * 16,  
			b'\xEB\xFF',   
			b'\xE8\x00\x00\x00\x00', 
		}
		self.check_interval: float = 0.1
		self.last_check: float = 0.0

	def protect_memory_region(self, start: int, size: int, protection: int) -> bool:
		"""Protect a memory region from modification.
		
		Args:
			start (int): Start address of memory region
			size (int): Size of memory region
			protection (int): Protection flags
			
		Returns:
			bool: True if protection was successful
		"""
		try:
			if CURRENT_PLATFORM.startswith("WIN"):
				kernel32 = ctypes.windll.kernel32
				old_protect = ctypes.c_ulong(0)
				result = kernel32.VirtualProtect(
					ctypes.c_void_p(start),
					ctypes.c_size_t(size),
					protection,
					ctypes.byref(old_protect)
				)
				if result:
					region = MemoryRegion(start, size, protection)
					region.hash = self._calculate_region_hash(start, size)
					self.protected_regions.append(region)
					return True
			else:
				# Linux/macOS memory protection
				libc = ctypes.CDLL('libc.so.6')
				result = libc.mprotect(
					ctypes.c_void_p(start),
					ctypes.c_size_t(size),
					protection
				)
				if result == 0:
					region = MemoryRegion(start, size, protection)
					region.hash = self._calculate_region_hash(start, size)
					self.protected_regions.append(region)
					return True
			return False
		except Exception as e:
			logger.error(f"Failed to protect memory region: {e}")
			return False

	def _calculate_region_hash(self, start: int, size: int) -> str:
		"""Calculate hash of memory region for integrity checking.
		
		Args:
			start (int): Start address
			size (int): Size of region
			
		Returns:
			str: SHA-256 hash of memory region
		"""
		try:
			if CURRENT_PLATFORM.startswith("WIN"):
				kernel32 = ctypes.windll.kernel32
				buffer = (ctypes.c_char * size)()
				bytes_read = ctypes.c_size_t(0)
				kernel32.ReadProcessMemory(
					kernel32.GetCurrentProcess(),
					ctypes.c_void_p(start),
					buffer,
					size,
					ctypes.byref(bytes_read)
				)
			else:
				with open(f"/proc/self/mem", "rb") as f:
					f.seek(start)
					buffer = f.read(size)
			
			return hashlib.sha256(buffer).hexdigest()
		except Exception as e:
			logger.error(f"Failed to calculate memory hash: {e}")
			return ""

	def check_memory_integrity(self) -> bool:
		"""Check integrity of protected memory regions.
		
		Returns:
			bool: True if all regions are intact
		"""
		try:
			current_time = time.time()
			if current_time - self.last_check < self.check_interval:
				return True

			for region in self.protected_regions:
				current_hash = self._calculate_region_hash(region.start, region.size)
				if current_hash != region.hash:
					logger.warning(f"Memory integrity violation detected at {hex(region.start)}")
					return False
				region.last_check = current_time

			self.last_check = current_time
			return True
		except Exception as e:
			logger.error(f"Memory integrity check failed: {e}")
			return False

	def scan_for_suspicious_patterns(self) -> List[Tuple[int, bytes]]:
		"""Scan memory for suspicious patterns.
		
		Returns:
			List[Tuple[int, bytes]]: List of (address, pattern) tuples
		"""
		suspicious_found = []
		try:
			if CURRENT_PLATFORM.startswith("WIN"):
				kernel32 = ctypes.windll.kernel32
				process = kernel32.GetCurrentProcess()
				address = 0
				while address < 0x7FFFFFFF:
					try:
						buffer = (ctypes.c_char * 4096)()
						bytes_read = ctypes.c_size_t(0)
						if kernel32.ReadProcessMemory(
							process,
							ctypes.c_void_p(address),
							buffer,
							4096,
							ctypes.byref(bytes_read)
						):
							for pattern in self.suspicious_patterns:
								if pattern in buffer:
									suspicious_found.append((address + buffer.index(pattern), pattern))
					except:
						pass
					address += 4096
			else:
				with open("/proc/self/maps", "r") as f:
					for line in f:
						if "r-xp" in line:  # Only scan executable regions
							start, end = map(lambda x: int(x, 16), line.split()[0].split("-"))
							with open("/proc/self/mem", "rb") as mem:
								mem.seek(start)
								data = mem.read(end - start)
								for pattern in self.suspicious_patterns:
									pos = 0
									while True:
										pos = data.find(pattern, pos)
										if pos == -1:
											break
										suspicious_found.append((start + pos, pattern))
										pos += 1

			return suspicious_found
		except Exception as e:
			logger.error(f"Memory pattern scan failed: {e}")
			return []

	def protect_critical_memory(self) -> None:
		"""Protect critical memory regions."""
		try:
			
			if CURRENT_PLATFORM.startswith("WIN"):
				kernel32 = ctypes.windll.kernel32
				module = kernel32.GetModuleHandleW(None)
				dos_header = ctypes.cast(module, ctypes.POINTER(ctypes.c_uint32))[0]
				pe_header = module + dos_header
				section_count = ctypes.cast(pe_header + 6, ctypes.POINTER(ctypes.c_uint16))[0]
				section_header = pe_header + 0xF8

				for _ in range(section_count):
					section = ctypes.cast(section_header, ctypes.POINTER(ctypes.c_uint32))
					if section[3] & 0x20:  
						self.protect_memory_region(
							module + section[0],
							section[1],
							MEMORY_PROTECTION['PAGE_EXECUTE_READ']
						)
					section_header += 40
			else:
				with open("/proc/self/maps", "r") as f:
					for line in f:
						if "r-xp" in line:  
							start, end = map(lambda x: int(x, 16), line.split()[0].split("-"))
							self.protect_memory_region(
								start,
								end - start,
								MEMORY_PROTECTION['PAGE_EXECUTE_READ']
							)
		except Exception as e:
			logger.error(f"Failed to protect critical memory: {e}")

class StingrayProtection:
	"""Stingray device detection and protection.
	
	This class implements detection and protection mechanisms against IMSI-catcher
	(Stingray) devices by monitoring cellular network parameters and patterns.
	"""

	def __init__(self):
		"""Initialize Stingray protection with default settings."""
		self.known_cells = {}
		self.suspicious_events = []
		self.check_interval = 1.0
		self.last_check = 0.0
		self.alert_threshold = 3
		self.force_airplane_mode = True
		self.known_operators = set()
		self.signal_history = []
		self.max_signal_history = 100
		self.signal_variance_threshold = 15.0
		self.frequency_hopping_detected = False
		self.last_frequencies = []
		self.max_frequency_history = 10

	def get_cellular_info(self):
		"""Get current cellular network information.
		
		Returns:
			Optional[CellularInfo]: Cellular network information if available.
		"""
		try:
			if not CURRENT_PLATFORM.startswith('DARWIN'):
				return None

			output = subprocess.check_output(
				['system_profiler', 'SPCellularDataType']
			).decode()

			if 'Cellular' not in output:
				return None

			mcc = int(re.search(r'MCC:\s*(\d+)', output).group(1))
			mnc = int(re.search(r'MNC:\s*(\d+)', output).group(1))
			cell_id = int(re.search(r'Cell ID:\s*(\d+)', output).group(1))
			lac = int(re.search(r'LAC:\s*(\d+)', output).group(1))
			signal = int(re.search(r'Signal Strength:\s*([-\d]+)', output).group(1))
			band = re.search(r'Band:\s*(\w+)', output).group(1)
			freq = int(re.search(r'Frequency:\s*(\d+)', output).group(1))

			self._update_signal_history(signal)
			self._update_frequency_history(freq)

			return CellularInfo(
				mcc=mcc,
				mnc=mnc,
				cell_id=cell_id,
				lac=lac,
				signal_strength=signal,
				band=band,
				frequency=freq,
			)

		except Exception as e:
			logger.error(f'Failed to get cellular info: {e}')
			return None

	def _update_signal_history(self, signal):
		"""Update signal strength history.
		
		Args:
			signal (int): Current signal strength.
		"""
		self.signal_history.append((time.time(), signal))
		if len(self.signal_history) > self.max_signal_history:
			self.signal_history.pop(0)

	def _update_frequency_history(self, freq):
		"""Update frequency history.
		
		Args:
			freq (int): Current frequency.
		"""
		self.last_frequencies.append(freq)
		if len(self.last_frequencies) > self.max_frequency_history:
			self.last_frequencies.pop(0)

	def detect_frequency_hopping(self):
		"""Detect frequency hopping patterns typical of Stingray devices.
		
		Returns:
			bool: True if frequency hopping is detected.
		"""
		if len(self.last_frequencies) < 3:
			return False

		freq_changes = [
			abs(self.last_frequencies[i] - self.last_frequencies[i - 1])
			for i in range(1, len(self.last_frequencies))
		]

		if any(change > 1000 for change in freq_changes):
			return True

		unique_freqs = len(set(self.last_frequencies))
		if unique_freqs > len(self.last_frequencies) * 0.7:
			return True

		return False

	def analyze_signal_patterns(self):
		"""Analyze signal patterns for suspicious behavior.
		
		Returns:
			Tuple[bool, List[str]]: (is_suspicious, list_of_reasons)
		"""
		if len(self.signal_history) < 10:
			return False, []

		reasons = []
		signals = [s[1] for s in self.signal_history]
		mean_signal = sum(signals) / len(signals)
		variance = sum((s - mean_signal) ** 2 for s in signals) / len(signals)

		if variance > self.signal_variance_threshold:
			reasons.append('Unusual signal variance')

		if any(s > -30 for s in signals):
			reasons.append('Abnormally strong signals detected')

		signal_changes = [
			abs(signals[i] - signals[i - 1])
			for i in range(1, len(signals))
		]
		if any(change > 20 for change in signal_changes):
			reasons.append('Rapid signal strength changes')

		return bool(reasons), reasons

	def check_for_stingray(self):
		"""Check for potential Stingray device presence.
		
		Returns:
			bool: True if Stingray is detected.
		"""
		try:
			current_time = time.time()
			if current_time - self.last_check < self.check_interval:
				return False

			cell_info = self.get_cellular_info()
			if not cell_info:
				return False

			reasons = []
			suspicious = False

			if cell_info.signal_strength in range(-50, -30):
				suspicious = True
				reasons.append('Unusually strong signal')

			if cell_info.cell_id in [0, 1, 65535]:
				suspicious = True
				reasons.append('Suspicious cell ID')

			if cell_info.lac in [0, 65535]:
				suspicious = True
				reasons.append('Suspicious location area code')

			freq_hopping = self.detect_frequency_hopping()
			if freq_hopping:
				suspicious = True
				reasons.append('Frequency hopping detected')
				self.frequency_hopping_detected = True

			signal_suspicious, signal_reasons = self.analyze_signal_patterns()
			if signal_suspicious:
				suspicious = True
				reasons.extend(signal_reasons)

			operator_key = f'{cell_info.mcc}:{cell_info.mnc}'
			if operator_key not in self.known_operators:
				self.known_operators.add(operator_key)
				if len(self.known_operators) > 2:
					suspicious = True
					reasons.append('Multiple operator changes detected')

			cell_key = f'{cell_info.mcc}:{cell_info.mnc}:{cell_info.cell_id}'
			if cell_key in self.known_cells:
				old_cell = self.known_cells[cell_key]
				if abs(old_cell.signal_strength - cell_info.signal_strength) > 20:
					suspicious = True
					reasons.append('Rapid signal strength change')

			self.known_cells[cell_key] = cell_info

			if suspicious:
				self._handle_suspicious_activity(
					current_time,
					reasons,
					cell_info,
					freq_hopping,
					signal_reasons,
				)

			self.last_check = current_time
			return suspicious

		except Exception as e:
			logger.error(f'Stingray check failed: {e}')
			return False

	def _handle_suspicious_activity(
		self,
		current_time,
		reasons,
		cell_info,
		freq_hopping,
		signal_reasons,
	):
		"""Handle suspicious cellular activity.
		
		Args:
			current_time (float): Current timestamp.
			reasons (List[str]): List of suspicious reasons.
			cell_info (CellularInfo): Current cellular info.
			freq_hopping (bool): Whether frequency hopping was detected.
			signal_reasons (List[str]): Signal analysis reasons.
		"""
		self.suspicious_events.append({
			'timestamp': current_time,
			'reasons': reasons,
			'cell_info': cell_info,
			'frequency_hopping': freq_hopping,
			'signal_analysis': signal_reasons,
		})

		recent_events = [
			e for e in self.suspicious_events
			if current_time - e['timestamp'] < 60
		]

		if len(recent_events) >= self.alert_threshold:
			logger.warning('Potential Stingray device detected!')
			logger.warning(f'Reasons: {reasons}')
			if freq_hopping:
				logger.warning('Frequency hopping pattern detected!')
			if signal_reasons:
				logger.warning('Suspicious signal patterns detected!')

	def enable_airplane_mode(self):
		"""Enable airplane mode to prevent cellular communication.
		
		Returns:
			bool: True if successful.
		"""
		try:
			if not CURRENT_PLATFORM.startswith('DARWIN'):
				return False

			commands = [
				['networksetup', '-setairportpower', 'en0', 'off'],
				['networksetup', '-setbluetoothpower', 'off'],
				['networksetup', '-setwwanpowerstate', 'off'],
				[
					'defaults',
					'write',
					'/Library/Preferences/com.apple.locationd',
					'LocationServicesEnabled',
					'-bool',
					'false',
				],
				['killall', 'locationd'],
			]

			for cmd in commands:
				subprocess.run(cmd, check=True)

			return True

		except Exception as e:
			logger.error(f'Failed to enable airplane mode: {e}')
			return False

@dataclass
class CellularInfo:
	"""Represents cellular network information."""
	mcc: int
	mnc: int
	cell_id: int
	lac: int
	signal_strength: int
	band: str
	frequency: int
	timestamp: float = field(default_factory=time.time)

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
	wipe_ram: bool = True
	wipe_swap: bool = True
	ram_wipe_passes: int = 3
	swap_wipe_passes: int = 3
	wipe_delay: float = 0.1
	safe_mode: bool = True
	dry_run: bool = False
	security_level: str = 'LOW'
	notify_only: bool = True
	backup_enabled: bool = True
	quarantine_enabled: bool = True
	quarantine_location: str = './quarantine'
	system_lock_enabled: bool = True
	network_block_enabled: bool = True
	memory_protection_enabled: bool = True
	file_monitoring_enabled: bool = True
	process_monitoring_enabled: bool = True
	device_monitoring_enabled: bool = True
	suspicious_patterns: Dict = field(default_factory=dict)
	custom_actions: Dict = field(default_factory=dict)
	
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
		if not hasattr(self, 'safe_mode'):
			self.safe_mode = True
		if not hasattr(self, 'dry_run'):
			self.dry_run = False
		if self.security_level == 'HIGH':
			self.safe_mode = False
			self.dry_run = False
			self.notify_only = False
			self.max_retries = 10
			self.retry_delay = 1
		elif self.security_level == 'MEDIUM':
			self.safe_mode = True
			self.dry_run = False
			self.notify_only = False
			self.max_retries = 5
			self.retry_delay = 3
		else:  # LOW
			self.safe_mode = True
			self.dry_run = True
			self.notify_only = True
			self.max_retries = 3
			self.retry_delay = 5

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

async def lock_system() -> bool:
	try:
		if CURRENT_PLATFORM.startswith("WIN"):
			subprocess.run(["rundll32.exe", "user32.dll,LockWorkStation"], check=True)
		elif CURRENT_PLATFORM.startswith("DARWIN"):
			subprocess.run(["pmset", "displaysleepnow"], check=True)
			subprocess.run(["/System/Library/CoreServices/Menu Extras/User.menu/Contents/Resources/CGSession", "-suspend"], check=True)
		else:
			subprocess.run(["loginctl", "lock-session"], check=True)
		return True
	except Exception as e:
		logger.error(f"System lock failed: {e}")
		return False

async def force_shutdown() -> bool:
	try:
		if CURRENT_PLATFORM.startswith("WIN"):
			subprocess.run(["shutdown", "/s", "/f", "/t", "0"], check=True)
		elif CURRENT_PLATFORM.startswith("DARWIN"):
			subprocess.run(["shutdown", "-h", "now"], check=True)
		else:
			subprocess.run(["shutdown", "-h", "now"], check=True)
		return True
	except Exception as e:
		logger.error(f"Force shutdown failed: {e}")
		return False

async def handle_usb_disconnect(settings: Settings) -> None:
	"""Enhanced USB disconnect handling with multiple security layers."""
	try:
		logger.warning("USB disconnect detected! Initiating security measures...")
		
		# Lock system if enabled
		if settings.system_lock_enabled:
			await lock_system()
		
		# Memory protection if enabled
		if settings.memory_protection_enabled and should_perform_destructive(settings):
			imse = IMSEProtection()
			imse.protect_critical_memory()
			if not imse.check_memory_integrity():
				logger.warning("Memory integrity violation detected!")
				suspicious = imse.scan_for_suspicious_patterns()
				if suspicious:
					logger.warning(f"Found suspicious memory patterns: {suspicious}")
		
		# Cellular monitoring if enabled
		if settings.cellular_monitoring_enabled:
			stingray = StingrayProtection()
			if stingray.check_for_stingray():
				logger.warning("Stingray device detected! Enabling airplane mode...")
				stingray.enable_airplane_mode()
		
		# Memory wiping if enabled and allowed
		if settings.wipe_ram and should_perform_destructive(settings):
			logger.info("Wiping RAM...")
			for _ in range(settings.ram_wipe_passes):
				if wipe_ram():
					logger.info("RAM wipe successful")
				await asyncio.sleep(settings.wipe_delay)
		
		if settings.wipe_swap and should_perform_destructive(settings):
			logger.info("Wiping swap...")
			for _ in range(settings.swap_wipe_passes):
				if wipe_swap():
					logger.info("Swap wipe successful")
				await asyncio.sleep(settings.wipe_delay)
		
		# File monitoring and shredding if enabled
		if settings.file_monitoring_enabled and settings.shred_files and should_perform_destructive(settings):
			logger.info("Shredding sensitive files...")
			for device in psutil.disk_partitions():
				if device.mountpoint:
					for root, _, files in os.walk(device.mountpoint):
						for file in files:
							if any(file.endswith(ext) for ext in USB_PATTERNS['suspicious_files']):
								secure_shred_file(Path(os.path.join(root, file)))
		
		# Network blocking if enabled
		if settings.network_block_enabled and settings.block_network and should_perform_destructive(settings):
			logger.info("Blocking network access...")
			block_network_access()
		
		# Create backup if enabled
		if settings.backup_enabled:
			await create_backup(settings)
		
		# Quarantine if enabled
		if settings.quarantine_enabled:
			await quarantine_suspicious_files(settings)
		
		# Send notifications
		send_alert(settings, "USB disconnect detected and security measures executed")
		
		# Shutdown if allowed
		if should_perform_destructive(settings):
			await force_shutdown()
		
	except Exception as e:
		logger.error(f"Error during USB disconnect handling: {e}")
		if should_perform_destructive(settings):
			await force_shutdown()

async def create_backup(settings: Settings) -> None:
	"""Create encrypted backup of critical data."""
	try:
		backup_dir = Path(settings.backup_location)
		backup_dir.mkdir(parents=True, exist_ok=True)
		
		timestamp = time.strftime("%Y%m%d_%H%M%S")
		backup_file = backup_dir / f"backup_{timestamp}.enc"
		
		# Collect data to backup
		backup_data = {
			'timestamp': timestamp,
			'settings': settings.__dict__,
			'usb_patterns': USB_PATTERNS,
			'security_settings': SECURITY_SETTINGS
		}
		
		# Encrypt and save
		if ENCRYPTION_KEY:
			encrypted_data = ENCRYPTION_KEY.encrypt(json.dumps(backup_data).encode())
			with open(backup_file, 'wb') as f:
				f.write(encrypted_data)
			logger.info(f"Backup created: {backup_file}")
		
	except Exception as e:
		logger.error(f"Backup creation failed: {e}")

async def quarantine_suspicious_files(settings: Settings) -> None:
	"""Quarantine suspicious files with proper logging."""
	try:
		quarantine_dir = Path(settings.quarantine_location)
		quarantine_dir.mkdir(parents=True, exist_ok=True)
		
		timestamp = time.strftime("%Y%m%d_%H%M%S")
		
		for device in psutil.disk_partitions():
			if device.mountpoint:
				for root, _, files in os.walk(device.mountpoint):
					for file in files:
						if any(file.endswith(ext) for ext in USB_PATTERNS['suspicious_files']):
							file_path = Path(os.path.join(root, file))
							quarantine_file = quarantine_dir / f"quarantine_{timestamp}_{file_path.name}"
							
							# Move file to quarantine
							if should_perform_destructive(settings):
								shutil.move(str(file_path), str(quarantine_file))
							else:
								shutil.copy2(str(file_path), str(quarantine_file))
							
							logger.info(f"File quarantined: {file_path}")
		
	except Exception as e:
		logger.error(f"Quarantine operation failed: {e}")

async def kill_computer(settings: Settings) -> None:
	"""Kill computer with security measures.
	
	Args:
		settings (Settings): Settings object containing security configuration.
	"""
	if not settings.melt_usbkill:
		await log(settings, "Detected a USB change. Dumping the list of connected devices and killing the computer...")
	
	await lock_system()
	await shred(settings)

	async def run_command(command: str) -> None:
		try:
			await asyncio.create_subprocess_shell(
				command,
				stdout=subprocess.PIPE,
				stderr=subprocess.PIPE,
			)
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
			asyncio.create_subprocess_shell(settings.wipe_swap_cmd),
		)
	elif settings.do_wipe_ram:
		await asyncio.create_subprocess_shell(settings.wipe_ram_cmd)
	elif settings.do_wipe_swap:
		await asyncio.create_subprocess_shell(settings.wipe_swap_cmd)

	await force_shutdown()
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

def wipe_memory_region(start: int, size: int, passes: int = 3) -> bool:
	try:
		if CURRENT_PLATFORM.startswith("WIN"):
			kernel32 = ctypes.windll.kernel32
			for _ in range(passes):
				buffer = (ctypes.c_char * size)()
				kernel32.WriteProcessMemory(
					kernel32.GetCurrentProcess(),
					start,
					buffer,
					size,
					None
				)
		else:
			for _ in range(passes):
				os.system(f"dd if=/dev/zero of=/dev/mem bs=1M count={size//1024//1024} seek={start//1024//1024}")
		return True
	except Exception as e:
		logger.error(f"Memory wipe failed: {e}")
		return False

def wipe_swap() -> bool:
	try:
		if CURRENT_PLATFORM.startswith("WIN"):
			subprocess.run(["wmic", "pagefileset", "delete"], check=True)
			subprocess.run(["wmic", "pagefileset", "create", "name='C:\\pagefile.sys'"], check=True)
		else:
			subprocess.run(["swapoff", "-a"], check=True)
			for swap_file in Path("/proc/swaps").read_text().splitlines()[1:]:
				if swap_file.strip():
					swap_path = swap_file.split()[0]
					if os.path.exists(swap_path):
						with open(swap_path, 'wb') as f:
							f.write(os.urandom(os.path.getsize(swap_path)))
			subprocess.run(["swapon", "-a"], check=True)
		return True
	except Exception as e:
		logger.error(f"Swap wipe failed: {e}")
		return False

def wipe_ram() -> bool:
	"""Wipe RAM memory with multiple passes.
	
	Returns:
		bool: True if wipe was successful, False otherwise.
	"""
	try:
		if CURRENT_PLATFORM.startswith("WIN"):
			subprocess.run(["wmic", "computersystem", "set", "AutomaticManagedPagefile=False"], check=True)
			subprocess.run(["wmic", "pagefileset", "delete"], check=True)
			subprocess.run(["wmic", "pagefileset", "create", "name='C:\\pagefile.sys'"], check=True)
		else:
			with open("/proc/meminfo", "r") as f:
				meminfo = f.read()
				total_mem = int(re.search(r"MemTotal:\s+(\d+)", meminfo).group(1)) * 1024
			
			chunk_size = 1024 * 1024
			for offset in range(0, total_mem, chunk_size):
				wipe_memory_region(offset, min(chunk_size, total_mem - offset))
		return True
	except Exception as e:
		logger.error(f"RAM wipe failed: {e}")
		return False

async def loop(settings: Settings) -> None:
	initial_state = await lsusb()
	logger.info("Starting security monitoring...")
	
	while True:
		try:
			current_state = await lsusb()
			if current_state != initial_state:
				if not all(device in settings.whitelist for device in current_state):
					await handle_usb_disconnect(settings)
					await kill_computer(settings)
				elif not all(device in current_state for device in initial_state):
					await handle_usb_disconnect(settings)
					await kill_computer(settings)

			if await security_checks(settings, current_state):
				await handle_usb_disconnect(settings)
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
	parser.add_argument('--safe-mode', action='store_true', help='Enable safe mode (no destructive actions)')
	parser.add_argument('--full-mode', action='store_true', help='Disable safe mode (allow destructive actions)')
	parser.add_argument('--dry-run', action='store_true', help='Simulate all actions without making changes')
	parser.add_argument('--security-level', choices=['LOW', 'MEDIUM', 'HIGH'],
					  default='LOW', help='Security level (LOW, MEDIUM, HIGH)')
	parser.add_argument('--backup', action='store_true', help='Enable backups')
	parser.add_argument('--quarantine', action='store_true', help='Enable quarantine')
	parser.add_argument('--notify-only', action='store_true',
					  help='Only send notifications, no destructive actions')
	return parser.parse_args()

def load_config(config_path: str) -> Dict:
	try:
		with open(config_path, 'r') as f:
			config = json.load(f)
			if 'safe_mode' not in config:
				config['safe_mode'] = True
			if 'dry_run' not in config:
				config['dry_run'] = False
			return config
	except FileNotFoundError:
		logger.warning(f"Config file not found: {config_path}, using defaults")
		return {'safe_mode': True, 'dry_run': False}
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

def should_perform_destructive(settings: Settings) -> bool:
	return not settings.safe_mode and not settings.dry_run

def main():
	args = setup_argparse()
	config = load_config(args.config)
	settings = Settings.from_config(config)
	
	# Apply command line arguments
	if args.security_level:
		settings.security_level = args.security_level
	if args.backup:
		settings.backup_enabled = True
	if args.quarantine:
		settings.quarantine_enabled = True
	if args.notify_only:
		settings.notify_only = True
	
	if args.interval:
		settings.sleep_time = args.interval
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
			
			time.sleep(settings.sleep_time)
			
	except KeyboardInterrupt:
		logger.info("Monitoring stopped by user")
	except Exception as e:
		logger.error(f"Unexpected error: {e}")
		sys.exit(1)

if __name__ == "__main__":
	main()

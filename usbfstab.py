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

CURRENT_PLATFORM = platform.system().upper()

if CURRENT_PLATFORM.startswith("DARWIN"):
	import plistlib

DEVICE_RE = [
	re.compile(r".+ID\s(?P<id>\w+:\w+)"),
	re.compile(r"0x([0-9a-z]{4})")
]

SETTINGS_FILE = '/etc/usbfstab.ini'
DEFAULT_LOG_FILE = '/var/log/usbfstab/kills.log'

JIGGLER_PATTERNS = {
	'keywords': [
		"jiggler", "mouse mover", "wiggler", "mousejiggle",
		"caffeine", "nosleep", "stayawake", "mousejiggler",
		"mousejiggle", "mousejiggler", "mousejiggle.exe"
	],
	'suspicious_processes': [
		"mousejiggle", "jiggler", "wiggler", "caffeine",
		"nosleep", "stayawake"
	],
	'suspicious_ports': [
		8080, 8081, 8082
	]
}

USERNAME = os.getlogin()
CELLEBRITE_DB_PATH = f"/Users/{USERNAME}/Library/Application Support/Knowledge/knowledgeC.db"

logging.basicConfig(
	level=logging.INFO,
	format='%(asctime)s - %(levelname)s - %(message)s',
	handlers=[
		logging.FileHandler(DEFAULT_LOG_FILE),
		logging.StreamHandler()
	]
)
logger = logging.getLogger(__name__)

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

	@classmethod
	def from_config(cls, config: configparser.ConfigParser) -> 'Settings':
		return cls(
			sleep_time=config.getfloat('Settings', 'sleep_time', fallback=0.25),
			whitelist=set(config.get('Settings', 'whitelist', fallback='').split()),
			log_file=config.get('Settings', 'log_file', fallback=DEFAULT_LOG_FILE),
			remove_file_cmd=config.get('Settings', 'remove_file_cmd', fallback='shred -u -z -n 1 '),
			melt_usbkill=config.getboolean('Settings', 'melt_usbkill', fallback=False),
			folders_to_remove=config.get('Settings', 'folders_to_remove', fallback='').split(),
			files_to_remove=config.get('Settings', 'files_to_remove', fallback='').split(),
			kill_commands=config.get('Settings', 'kill_commands', fallback='').split(),
			do_sync=config.getboolean('Settings', 'do_sync', fallback=True),
			do_wipe_ram=config.getboolean('Settings', 'do_wipe_ram', fallback=False),
			do_wipe_swap=config.getboolean('Settings', 'do_wipe_swap', fallback=False),
			wipe_ram_cmd=config.get('Settings', 'wipe_ram_cmd', fallback=''),
			wipe_swap_cmd=config.get('Settings', 'wipe_swap_cmd', fallback=''),
			shut_down=config.getboolean('Settings', 'shut_down', fallback=True),
			check_jiggler=config.getboolean('Settings', 'check_jiggler', fallback=True),
			check_cellebrite=config.getboolean('Settings', 'check_cellebrite', fallback=True)
		)

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

async def security_checks(settings: Settings) -> bool:
	"""Perform all security checks"""
	if settings.check_jiggler and await check_jiggler():
		logger.warning("Mouse jiggler detected!")
		return True

	if settings.check_cellebrite and await check_cellebrite():
		logger.warning("Cellebrite database access detected!")
		return True

	return False

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

			if await security_checks(settings):
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

if __name__ == "__main__":
	asyncio.run(main())

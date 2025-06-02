#!/usr/bin/env python3

import psutil
import sys
import logging
import argparse
import time
from typing import List, Dict, Set
from datetime import datetime
import json
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('jiggler_detection.log')
    ]
)

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

def get_process_details(proc: psutil.Process) -> Dict:
    """Get detailed information about a process"""
    try:
        return {
            'pid': proc.pid,
            'name': proc.name(),
            'cmdline': ' '.join(proc.cmdline()),
            'create_time': datetime.fromtimestamp(proc.create_time()).isoformat(),
            'username': proc.username(),
            'status': proc.status(),
            'cpu_percent': proc.cpu_percent(),
            'memory_percent': proc.memory_percent()
        }
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return {}

def check_network_connections() -> List[Dict]:
    """Check for suspicious network connections"""
    suspicious_conns = []
    for conn in psutil.net_connections():
        if conn.laddr.port in JIGGLER_PATTERNS['suspicious_ports']:
            try:
                proc = psutil.Process(conn.pid)
                suspicious_conns.append({
                    'pid': conn.pid,
                    'process_name': proc.name(),
                    'local_address': f"{conn.laddr.ip}:{conn.laddr.port}",
                    'status': conn.status
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    return suspicious_conns

def mouse_jiggler_detected(verbose: bool = False) -> Dict:
    """
    Detect mouse jiggler processes and suspicious activities
    Returns a dictionary with detection results
    """
    detection_results = {
        'suspicious_processes': [],
        'suspicious_connections': [],
        'detected': False
    }

    for proc in psutil.process_iter(['name', 'cmdline']):
        try:
            name = proc.info['name'] or ""
            cmdline = " ".join(proc.info['cmdline']) if proc.info['cmdline'] else ""
            
            if any(k in name.lower() or k in cmdline.lower() for k in JIGGLER_PATTERNS['keywords']):
                detection_results['detected'] = True
                if verbose:
                    detection_results['suspicious_processes'].append(get_process_details(proc))
                else:
                    detection_results['suspicious_processes'].append({
                        'pid': proc.pid,
                        'name': name
                    })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    suspicious_conns = check_network_connections()
    if suspicious_conns:
        detection_results['detected'] = True
        detection_results['suspicious_connections'] = suspicious_conns

    return detection_results

def save_detection_report(results: Dict, output_file: str = 'jiggler_detection_report.json'):
    """Save detection results to a JSON file"""
    try:
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        logging.info(f"Detection report saved to {output_file}")
    except Exception as e:
        logging.error(f"Error saving detection report: {e}")

def setup_argparse() -> argparse.Namespace:
    """Set up command line argument parsing"""
    parser = argparse.ArgumentParser(
        description='Detect and report mouse jiggler processes and suspicious activities'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Show detailed information about detected processes'
    )
    parser.add_argument(
        '--continuous', '-c',
        action='store_true',
        help='Run continuously and monitor for changes'
    )
    parser.add_argument(
        '--interval', '-i',
        type=int,
        default=60,
        help='Interval in seconds for continuous monitoring (default: 60)'
    )
    parser.add_argument(
        '--output', '-o',
        type=str,
        default='jiggler_detection_report.json',
        help='Output file for detection report (default: jiggler_detection_report.json)'
    )
    return parser.parse_args()

def main():
    args = setup_argparse()
    
    if args.continuous:
        logging.info(f"Starting continuous monitoring (interval: {args.interval}s)")
        try:
            while True:
                results = mouse_jiggler_detected(args.verbose)
                if results['detected']:
                    logging.warning("Mouse jiggler activity detected!")
                    if args.verbose:
                        logging.info(f"Details: {json.dumps(results, indent=2)}")
                    save_detection_report(results, args.output)
                else:
                    logging.info("No mouse jiggler activity detected")
                time.sleep(args.interval)
        except KeyboardInterrupt:
            logging.info("Monitoring stopped by user")
            sys.exit(0)
    else:
        results = mouse_jiggler_detected(args.verbose)
        if results['detected']:
            logging.warning("Mouse jiggler activity detected!")
            if args.verbose:
                logging.info(f"Details: {json.dumps(results, indent=2)}")
            save_detection_report(results, args.output)
            sys.exit(1)
        else:
            logging.info("No mouse jiggler activity detected")
            sys.exit(0)

if __name__ == "__main__":
    main()

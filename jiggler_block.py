#!/usr/bin/env python3

import psutil
import sys

def mouse_jiggler_detected():
    keywords = ["jiggler", "mouse mover", "wiggler"]
    for proc in psutil.process_iter(['name', 'cmdline']):
        try:
            name = proc.info['name'] or ""
            cmdline = " ".join(proc.info['cmdline']) if proc.info['cmdline'] else ""
            if any(k in name.lower() or k in cmdline.lower() for k in keywords):
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return False

def main():
    if mouse_jiggler_detected():
        print("Mouse jiggler process detected.")
        sys.exit(1)
    else:
        print("No mouse jiggler activity detected.")
        sys.exit(0)

if __name__ == "__main__":
    main()

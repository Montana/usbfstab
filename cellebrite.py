import sqlite3
import os
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
import time
import sys
import logging
import argparse
from typing import List, Tuple, Optional
from contextlib import contextmanager

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('cellebrite.log')
    ]
)

USERNAME = os.getlogin()
DB_PATH = f"/Users/{USERNAME}/Library/Application Support/Knowledge/knowledgeC.db"

def setup_argparse() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Monitor application usage data from macOS Knowledge database')
    parser.add_argument('--limit', type=int, default=100, help='Number of records to fetch (default: 100)')
    parser.add_argument('--force', action='store_true', help='Force execution even if USB is not connected')
    return parser.parse_args()

def usb_connected() -> bool:
    try:
        result = subprocess.run(
            ["system_profiler", "SPUSBDataType"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )
        return "External" in result.stdout
    except subprocess.CalledProcessError as e:
        logging.error(f"Error checking USB status: {e}")
        return False

@contextmanager
def get_db_connection():
    """Context manager for database connection"""
    conn = None
    try:
        conn = sqlite3.connect(DB_PATH)
        yield conn
    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
        raise
    finally:
        if conn:
            conn.close()

def fetch_app_usage(conn: sqlite3.Connection, limit: int) -> List[Tuple]:
    """Fetch application usage data from the database"""
    query = """
    SELECT
        ZOBJECT.ZSTARTDATE,
        ZOBJECT.ZENDDATE,
        ZOBJECT.ZVALUEINTEGER as ZSECONDS,
        ZBUNDLEID.ZBUNDLEID
    FROM
        ZOBJECT
    LEFT JOIN
        ZSTRUCTUREDMETADATA ON ZOBJECT.ZSTRUCTUREDMETADATA = ZSTRUCTUREDMETADATA.Z_PK
    LEFT JOIN
        ZSOURCE ON ZOBJECT.ZSOURCE = ZSOURCE.Z_PK
    LEFT JOIN
        ZBUNDLEID ON ZSOURCE.ZBUNDLEID = ZBUNDLEID.Z_PK
    WHERE
        ZOBJECT.ZSTREAMNAME = 'com.apple.runningapp'
        AND ZOBJECT.ZVALUEINTEGER IS NOT NULL
    ORDER BY
        ZOBJECT.ZSTARTDATE DESC
    LIMIT ?;
    """
    
    try:
        cursor = conn.cursor()
        cursor.execute(query, (limit,))
        return cursor.fetchall()
    except sqlite3.Error as e:
        logging.error(f"Error executing query: {e}")
        raise

def format_timestamp(timestamp: float) -> str:
    """Convert Apple timestamp to human-readable format"""
    return (datetime(2001, 1, 1) + timedelta(seconds=timestamp)).strftime('%Y-%m-%d %H:%M:%S')

def main():
    args = setup_argparse()
    
    if not os.path.exists(DB_PATH):
        logging.error(f"Database not found at {DB_PATH}")
        sys.exit(1)

    if not args.force and not usb_connected():
        logging.warning("USB device not detected. Deleting knowledgeC.db...")
        try:
            os.remove(DB_PATH)
        except OSError as e:
            logging.error(f"Error deleting database: {e}")
        sys.exit(0)

    try:
        with get_db_connection() as conn:
            rows = fetch_app_usage(conn, args.limit)
            
            print(f"\n{'Start':<25} {'End':<25} {'Seconds':<10} {'Bundle ID'}")
            print("-" * 80)
            
            for row in rows:
                start = format_timestamp(row[0])
                end = format_timestamp(row[1])
                seconds = row[2]
                bundle_id = row[3] if row[3] else "(Unknown)"
                print(f"{start:<25} {end:<25} {seconds:<10} {bundle_id}")
                
    except Exception as e:
        logging.error(f"An error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

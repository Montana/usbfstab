import sqlite3
import os
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
import time
import sys

USERNAME = os.getlogin()
DB_PATH = f"/Users/{USERNAME}/Library/Application Support/Knowledge/knowledgeC.db"

def usb_connected():
    result = subprocess.run(["system_profiler", "SPUSBDataType"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    return b"External" in result.stdout

if not os.path.exists(DB_PATH):
    raise FileNotFoundError(f"Database not found at {DB_PATH}")

if not usb_connected():
    print("USB device not detected. Deleting knowledgeC.db...")
    os.remove(DB_PATH)
    sys.exit(0)

conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

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
LIMIT 100;
"""

cursor.execute(query)
rows = cursor.fetchall()

print(f"{'Start':<25} {'End':<25} {'Seconds':<10} {'Bundle ID'}")
print("-" * 80)
for row in rows:
    start = datetime(2001, 1, 1) + timedelta(seconds=row[0])
    end = datetime(2001, 1, 1) + timedelta(seconds=row[1])
    seconds = row[2]
    bundle_id = row[3] if row[3] else "(Unknown)"
    print(f"{start:<25} {end:<25} {seconds:<10} {bundle_id}")

cursor.close()
conn.close()

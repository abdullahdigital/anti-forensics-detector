import os
import time
import datetime
from anti_forensics.timestomp_detector import detect_timestomping

def debug_timestamp():
    test_file = "debug_timestomp_test.sh"
    
    # 1. Create file
    with open(test_file, 'w') as f: f.write("content")
    print(f"File created: {test_file}")
    time.sleep(1.1)     # Wait to ensure distinct creation time

    # 2. Timestomp (Backdate to 2010)
    # Using os.utime to simulate 'touch -d' behavior in Python
    # Timestamp for 2010-01-01 12:00:00
    target_time = 1262347200.0 # Exactly .0 microseconds
    os.utime(test_file, (target_time, target_time))
    print(f"Timestomped to: 2010-01-01 12:00:00 ({target_time})")

    # 3. Inspect Raw Stat
    stat = os.stat(test_file)
    print("\n--- RAW STATS ---")
    print(f"st_mtime: {stat.st_mtime}")
    print(f"st_ctime: {stat.st_ctime}")
    print(f"st_mtime_ns: {stat.st_mtime_ns}")
    print(f"st_ctime_ns: {stat.st_ctime_ns}")
    
    m_dt = datetime.datetime.fromtimestamp(stat.st_mtime)
    c_dt = datetime.datetime.fromtimestamp(stat.st_ctime)
    
    print(f"\n--- DATETIME OBJECTS ---")
    print(f"M-Time: {m_dt} (Microsecond: {m_dt.microsecond})")
    print(f"C-Time: {c_dt} (Microsecond: {c_dt.microsecond})")

    # 4. Run Detector
    print("\n--- DETECTOR OUTPUT ---")
    res = detect_timestomping(test_file)
    print(res)
    
    if os.path.exists(test_file): os.remove(test_file)

if __name__ == "__main__":
    debug_timestamp()

import os
import datetime

def get_file_timestamps(file_path):
    """
    Retrieves the creation, modification, and access timestamps of a file.

    Args:
        file_path (str): The path to the file.

    Returns:
        dict: A dictionary containing 'creation_time', 'modification_time', and 'access_time'
              as datetime objects, or None if the file does not exist.
    """
    if not os.path.exists(file_path):
        return None

    try:
        # On Windows, ctime is creation time. On Unix, it's last metadata change time.
        # For cross-platform consistency, we'll note this.
        creation_timestamp = os.path.getctime(file_path)
        modification_timestamp = os.path.getmtime(file_path)
        access_timestamp = os.path.getatime(file_path)

        return {
            "creation_time": datetime.datetime.fromtimestamp(creation_timestamp),
            "modification_time": datetime.datetime.fromtimestamp(modification_timestamp),
            "access_time": datetime.datetime.fromtimestamp(access_timestamp)
        }
    except Exception as e:
        return {"error": str(e)}

def detect_timestomping(file_path):
    """
    Detects potential timestomping by analyzing inconsistencies in file timestamps.

    Args:
        file_path (str): The path to the file to analyze.

    Returns:
        dict: A dictionary indicating if timestomping is suspected, reasons, and the timestamps.
    """
    timestamps = get_file_timestamps(file_path)

    if timestamps is None:
        return {"error": "File not found", "file_path": file_path}
    if "error" in timestamps:
        return {"error": timestamps["error"], "file_path": file_path}

    is_timestomped = False
    reasons = []

    c_time = timestamps["creation_time"]
    m_time = timestamps["modification_time"]
    a_time = timestamps["access_time"]

    # Common timestomping indicators:
    # 1. Modification time is earlier than creation time (impossible normally)


    # 2. Access time is significantly older than modification/creation time (might indicate tampering or unusual access patterns)
    #    This is more heuristic and depends on system usage, so we'll make it a weak indicator.
    #    A significant difference could be, for example, more than a year.
    #    However, for a more robust detection, this would need context.
    # if (c_time - a_time).days > 365 or (m_time - a_time).days > 365:
    #     is_timestomped = True
    #     reasons.append(f"Access time ({a_time}) is significantly older than creation/modification time.")

    suspicion_score = 0.0

    # 3. All timestamps are identical (could be normal for new files, but suspicious for older files)
    if c_time == m_time == a_time:
        # This is often normal for newly created files that haven't been modified or accessed yet.
        # It becomes suspicious if the file has been around for a while.
        # For now, we'll flag it as a potential indicator if other anomalies are present.
        if not is_timestomped: # Only add if no other strong indicators
            reasons.append("All timestamps (creation, modification, access) are identical. This can be normal for new files, but might be suspicious for older files.")
            suspicion_score = max(suspicion_score, 0.3) # 30% risk for identical timestamps (weak indicator)

    # 1. Modification time is earlier than creation time (impossible normally)
    if m_time < c_time:
        is_timestomped = True
        reasons.append(f"Modification time ({m_time}) is earlier than creation time ({c_time}).")
        suspicion_score = 1.0 # 100% Critical: This is physically impossible in standard usage

    # 4. Nanosecond Anomaly (Authentic Heuristic)
    # Standard OS operations usually have random microseconds. 
    # Tools like 'timestomp' or 'touch' often set microseconds to 0 or round them.
    # We check if m_time OR c_time has exactly 0 microseconds.
    if c_time.microsecond == 0 or m_time.microsecond == 0:
         # Be careful, some filesystems (like FAT32) don't support high precision. 
         # But in a modern Linux/NTFS context, this is suspicious.
         reasons.append("Timestamps have exactly zero microseconds. This implies artificial modification (e.g. 'touch' command).")
         is_timestomped = True
         suspicion_score = max(suspicion_score, 0.7)

    return {
        "file_path": file_path,
        "is_timestomped": is_timestomped,
        "suspicion_score": suspicion_score,
        "reasons": reasons,
        "timestamps": {
            "creation_time": str(c_time),
            "modification_time": str(m_time),
            "access_time": str(a_time)
        }
    }

if __name__ == '__main__':
    # Example Usage
    test_file = "d:\Air University\Semester 5\DF Lab\project\project\backend\python\anti_forensics\test_timestomp_file.txt"

    # Create a dummy file
    with open(test_file, 'w') as f:
        f.write("This is a test file for timestomping detection.")

    print(f"Analyzing: {test_file}")
    result = detect_timestomping(test_file)
    print(result)

    # Simulate timestomping (this requires external tools or specific OS calls)
    # For demonstration, we'll manually set a modification time earlier than creation time
    # Note: os.utime can set mtime and atime, but ctime is harder to change without admin/special tools.
    # We'll simulate a scenario where mtime is older than ctime.
    # This is a conceptual example, as directly setting ctime in Python is not straightforward.

    # Let's create a file, then change its modification time to be older than its creation time.
    # This is often done with tools like 'touch -m -t' or specific APIs.
    # For Python, we can only easily manipulate mtime and atime.
    # To truly test the m_time < c_time scenario, you'd need to use a tool that can modify ctime.

    # For now, let's just demonstrate a file with identical timestamps (which is a weak indicator)
    # and a file that might have a suspicious access pattern.

    # Clean up
    if os.path.exists(test_file):
        os.remove(test_file)

    # Example of a file with a simulated timestomped modification time (conceptual)
    # This part is hard to simulate purely in Python without external tools or specific OS APIs
    # that allow setting ctime. The `os.utime` function only sets atime and mtime.
    # For a real test, you would use a forensic tool or a system call that can modify ctime.

    # Let's create a file and then try to make its mtime older than its ctime (conceptually).
    # This will likely not work as intended on most systems without special privileges/tools.
    # The primary detection `m_time < c_time` is the strongest indicator.

    # Example of a non-existent file
    print("\nChecking for timestomping on non_existent_file.txt")
    result_non_existent = detect_timestomping("non_existent_file.txt")
    print(result_non_existent)

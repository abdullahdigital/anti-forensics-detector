import os
import datetime
import platform



try:
    from ..common.ai_service import ai_service
except ImportError:
    import sys
    import os
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
    from python.common.ai_service import ai_service

# Assuming hash_utils.py is in the same directory and contains calculate_file_hash
from .hash_utils import calculate_file_hash

def check_log_integrity_by_hash(log_file_path, known_good_hash, hash_algorithm='sha256'):
    """
    Checks the integrity of a log file by comparing its current hash with a known good hash.

    Args:
        log_file_path (str): The path to the log file.
        known_good_hash (str): The expected hash of the log file.
        hash_algorithm (str): The hashing algorithm to use (e.g., 'md5', 'sha1', 'sha256').

    Returns:
        dict: A dictionary indicating if the integrity check passed and the current hash.
    """
    if not os.path.exists(log_file_path):
        return {"error": "Log file not found", "log_file_path": log_file_path}

    current_hash_result = calculate_file_hash(log_file_path, hash_algorithm)
    if "error" in current_hash_result:
        return {"error": f"Could not calculate hash: {current_hash_result['error']}", "log_file_path": log_file_path}

    current_hash = current_hash_result["hash_value"]
    integrity_compromised = (current_hash != known_good_hash)

    return {
        "log_file_path": log_file_path,
        "integrity_compromised": integrity_compromised,
        "current_hash": current_hash,
        "known_good_hash": known_good_hash,
        "hash_algorithm": hash_algorithm
    }

def check_log_timestamps(log_file_path):
    """
    Checks for suspicious timestamp anomalies in a log file.
    This is a basic check and might not detect sophisticated timestomping.

    Args:
        log_file_path (str): The path to the log file.

    Returns:
        dict: A dictionary indicating if timestamp anomalies are suspected and the timestamps.
    """
    if not os.path.exists(log_file_path):
        return {"error": "Log file not found", "log_file_path": log_file_path}

    stat_info = os.stat(log_file_path)
    current_time = datetime.datetime.now()

    c_time = datetime.datetime.fromtimestamp(stat_info.st_ctime)
    m_time = datetime.datetime.fromtimestamp(stat_info.st_mtime)
    a_time = datetime.datetime.fromtimestamp(stat_info.st_atime)

    suspicions = []
    if m_time > current_time:
        suspicions.append(f"Modification time ({m_time}) is in the future.")
    if c_time > current_time:
        suspicions.append(f"Creation time ({c_time}) is in the future.")
    if m_time < c_time:
        suspicions.append(f"Modification time ({m_time}) is earlier than creation time ({c_time}).")

    return {
        "log_file_path": log_file_path,
        "timestamp_anomalies_suspected": bool(suspicions),
        "reasons": suspicions,
        "timestamps": {
            "creation_time": str(c_time),
            "modification_time": str(m_time),
            "access_time": str(a_time)
        }
    }

def detect_null_injection(log_file_path):
    """
    Detects Null Byte Injection in log files.
    Authentic log files are text and should NOT contain null bytes (0x00).
    Attackers use null bytes to confuse log parsers or terminate strings early.
    """
    if not os.path.exists(log_file_path):
        return {"is_injection_suspected": False}
        
    try:
        # Read a chunk
        with open(log_file_path, 'rb') as f:
            chunk = f.read(8192) # Read 8KB
            
        if b'\x00' in chunk:
            # Check if it's UTF-16 (BOM check)
            if chunk.startswith(b'\xff\xfe') or chunk.startswith(b'\xfe\xff'):
                 # Valid unicode log, ignore
                 return {"is_injection_suspected": False}
                 
            # Valid ASCII/UTF-8 log should not have nulls
            count = chunk.count(b'\x00')
            return {
                "is_injection_suspected": True,
                "null_byte_count": count,
                "note": "Log file contains Null Bytes (0x00), which is abnormal for text logs and suggests binary injection."
            }
            
    except Exception:
        pass
        
    return {"is_injection_suspected": False}

async def detect_log_tampering_ai(log_file_path):
    """
    Uses Gemini AI to analyze log content for semantic anomalies/tampering.
    """
    if not os.path.exists(log_file_path):
         return {"is_ai_tampering_suspected": False}
         
    try:
        # Read the last 20 lines (tail)
        lines = []
        with open(log_file_path, 'r', errors='ignore') as f:
            # Simple tail implementation
            lines = f.readlines()[-20:]
        
        log_snippet = "".join(lines)
        if not log_snippet.strip():
             return {"is_ai_tampering_suspected": False, "note": "Log file empty or unreadable."}

        prompt = (
            "Analyze this log file snippet for signs of tampering, manual editing, or timestamp anomalies.\n"
            "Question: Are there any obvious signs of tampering (e.g. format changes, time jumps backwards, weird characters)? "
            "Reply with JSON: {\"suspicious\": boolean, \"confidence\": float 0.0-1.0, \"reason\": \"short explanation\"}"
        )
        
        response = await ai_service.analyze_text_async(prompt, text_content=log_snippet)
        
        if response:
             # Simple parsing of typical JSON response
            import json
            # Sanitize response to find JSON
            json_str = response.strip()
            if "```json" in json_str:
                json_str = json_str.split("```json")[1].split("```")[0]
            elif "```" in json_str:
                 json_str = json_str.split("```")[1].split("```")[0]
            
            data = json.loads(json_str)
            return {
                "is_ai_tampering_suspected": data.get("suspicious", False),
                "ai_confidence": data.get("confidence", 0.0),
                "ai_reason": data.get("reason", "AI detected anomaly.")
            }
            
    except Exception as e:
        return {"is_ai_tampering_suspected": False, "error": str(e)}

    return {"is_ai_tampering_suspected": False}



def check_windows_event_logs(log_name="Security", time_range_hours=24):
    """Method removed for Linux compatibility."""
    return {"status": "Skipped", "note": "Windows-specific functionality removed."}

async def detect_log_tampering(log_file_path, known_good_hash=None):
    """
    Detects potential log tampering by combining heuristic checks and a placeholder
    for AI-based analysis.

    Args:
        log_file_path (str): The path to the log file to analyze.
        known_good_hash (str, optional): A known good hash for integrity checking. Defaults to None.

    Returns:
        dict: A dictionary containing the log tampering detection results.
    """
    results = {"log_file_path": log_file_path}

    # Heuristic Check 1: Hash integrity
    if known_good_hash:
        hash_check_result = check_log_integrity_by_hash(log_file_path, known_good_hash)
        results["hash_integrity_check"] = hash_check_result
    else:
        results["hash_integrity_check"] = {"status": "Skipped", "note": "No known good hash provided."}

    # Heuristic Check 2: Timestamp anomalies
    timestamp_check_result = check_log_timestamps(log_file_path)
    results["timestamp_anomalies_check"] = timestamp_check_result

    # Authentic Heuristic: Null Injection
    injection_result = detect_null_injection(log_file_path)
    results["null_injection_check"] = injection_result

    # AI Analysis
    ai_tampering_result = await detect_log_tampering_ai(log_file_path)
    results["ai_tampering_detection"] = ai_tampering_result

    is_tampering_suspected = (
        (known_good_hash and hash_check_result.get("integrity_compromised", False)) or
        timestamp_check_result.get("timestamp_anomalies_suspected", False) or
        injection_result.get("is_injection_suspected", False) or
        ai_tampering_result.get("is_ai_tampering_suspected", False)
    )

    is_tampering_suspected = (
        (known_good_hash and hash_check_result.get("integrity_compromised", False)) or
        timestamp_check_result.get("timestamp_anomalies_suspected", False) or
        injection_result.get("is_injection_suspected", False)
    )

    suspicion_reasons = []

    if timestamp_check_result.get("timestamp_anomalies_suspected", False):
        suspicion_reasons.extend(timestamp_check_result.get("reasons", []))
        
    if known_good_hash and hash_check_result.get("integrity_compromised", False):
        suspicion_reasons.append(f"Hash mismatch! Expected {known_good_hash}, got {hash_check_result.get('current_hash')}")
        
    if injection_result.get("is_injection_suspected", False):
        suspicion_reasons.append(injection_result.get("note", "Null Byte Injection detected."))



    suspicion_score = 0.0
    if is_tampering_suspected:
        if timestamp_check_result.get("timestamp_anomalies_suspected", False):
            suspicion_score = max(suspicion_score, 0.8) # High confidence for timestamp anomalies
        if known_good_hash and hash_check_result.get("integrity_compromised", False):
            suspicion_score = 1.0 # Critical for broken hash

        if injection_result.get("is_injection_suspected", False):
            suspicion_score = max(suspicion_score, 1.0) # Critical for null injection
            
    if ai_tampering_result.get("is_ai_tampering_suspected", False):
        suspicion_reasons.append(f"[AI] {ai_tampering_result.get('ai_reason')}")
        suspicion_score = max(suspicion_score, ai_tampering_result.get("ai_confidence", 0.7))

    results["is_log_tampering_suspected"] = is_tampering_suspected
    results["suspicion_score"] = suspicion_score
    results["suspicion_reasons"] = suspicion_reasons
    return results

if __name__ == '__main__':
    # Example Usage
    # Create a dummy log file
    dummy_log_file = "d:\\Air University\\Semester 5\\DF Lab\\project\\project\\backend\\python\\anti_forensics\\dummy.log"
    with open(dummy_log_file, 'w') as f:
        f.write("2023-01-01 10:00:00 - INFO - User logged in\n")
        f.write("2023-01-01 10:01:00 - INFO - Action performed\n")

    # Calculate its initial hash
    initial_hash_result = calculate_file_hash(dummy_log_file, 'sha256')
    known_hash = initial_hash_result["hash_value"]
    print(f"Initial hash of {dummy_log_file}: {known_hash}")

    print(f"\nAnalyzing original log file: {dummy_log_file}")
    print(detect_log_tampering(dummy_log_file, known_good_hash=known_hash))

    # Simulate tampering: modify the log file
    with open(dummy_log_file, 'a') as f:
        f.write("2023-01-01 10:02:00 - ERROR - Unauthorized access detected\n")
    print(f"\nAnalyzing tampered log file: {dummy_log_file}")
    print(detect_log_tampering(dummy_log_file, known_good_hash=known_hash))

    # Simulate tampering: change timestamp (requires os.utime)
    future_timestamp = (datetime.datetime.now() + datetime.timedelta(days=365)).timestamp()
    os.utime(dummy_log_file, (future_timestamp, future_timestamp))
    print(f"\nAnalyzing log file with future timestamp: {dummy_log_file}")
    print(detect_log_tampering(dummy_log_file, known_good_hash=known_hash))

    os.remove(dummy_log_file)

    # Analyze a non-existent file
    print(f"\nAnalyzing non-existent file: non_existent.log")
    print(detect_log_tampering("d:\\Air University\\Semester 5\\DF Lab\\project\\project\\backend\\python\\anti_forensics\\non_existent.log"))

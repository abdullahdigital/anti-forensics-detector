import os

# Assuming file_utils.py is in the same directory and contains read_file_content
from .file_utils import read_file_content, get_file_size
try:
    from ..common.ai_service import ai_service
except ImportError:
    import sys
    import os
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
    from python.common.ai_service import ai_service

def detect_zero_fill(file_path, chunk_size=4096, threshold=0.9):
    """
    Detects if a significant portion of a file is filled with zeros.
    This can indicate a basic data wiping attempt.

    Args:
        file_path (str): The path to the file to analyze.
        chunk_size (int): The size of chunks to read from the file.
        threshold (float): The proportion of zero-filled chunks to consider it wiped.

    Returns:
        dict: A dictionary indicating if zero-fill wiping is suspected and the proportion of zeros.
    """
    if not os.path.exists(file_path):
        return {"error": "File not found", "file_path": file_path}

    total_chunks = 0
    zero_filled_chunks = 0
    file_size = get_file_size(file_path)

    if file_size == 0:
        return {"is_zero_fill_wiped": False, "zero_fill_proportion": 0.0, "file_path": file_path}

    for chunk in read_file_content(file_path, mode='rb', chunk_size=chunk_size):
        total_chunks += 1
        if all(byte == 0 for byte in chunk):
            zero_filled_chunks += 1

    zero_fill_proportion = zero_filled_chunks / total_chunks if total_chunks > 0 else 0.0
    is_zero_fill_wiped = zero_fill_proportion >= threshold

    return {
        "file_path": file_path,
        "is_zero_fill_wiped": is_zero_fill_wiped,
        "zero_fill_proportion": round(zero_fill_proportion, 4)
    }

def detect_pattern_fill(file_path, pattern=b'\xff', chunk_size=4096, threshold=0.9):
    """
    Detects if a significant portion of a file is filled with a specific byte pattern.
    Common patterns include 0xFF (all ones) or other specific sequences.

    Args:
        file_path (str): The path to the file to analyze.
        pattern (bytes): The byte pattern to look for (e.g., b'\xff' for all ones).
        chunk_size (int): The size of chunks to read from the file.
        threshold (float): The proportion of pattern-filled chunks to consider it wiped.

    Returns:
        dict: A dictionary indicating if pattern-fill wiping is suspected and the proportion.
    """
    if not os.path.exists(file_path):
        return {"error": "File not found", "file_path": file_path}

    total_chunks = 0
    pattern_filled_chunks = 0
    file_size = get_file_size(file_path)

    if file_size == 0:
        return {"is_pattern_fill_wiped": False, "pattern_fill_proportion": 0.0, "file_path": file_path}

    for chunk in read_file_content(file_path, mode='rb', chunk_size=chunk_size):
        total_chunks += 1
        if all(byte == pattern[0] for byte in chunk):
            pattern_filled_chunks += 1

    pattern_fill_proportion = pattern_filled_chunks / total_chunks if total_chunks > 0 else 0.0
    is_pattern_fill_wiped = pattern_fill_proportion >= threshold

    return {
        "file_path": file_path,
        "is_pattern_fill_wiped": is_pattern_fill_wiped,
        "pattern_fill_proportion": round(pattern_fill_proportion, 4),
        "pattern_searched": pattern.hex()
    }

def analyze_slack_space_placeholder(file_path):
    """
    Placeholder for analyzing slack space for remnants of wiped data.

    Analyzing slack space typically requires direct disk access and understanding
    of file system structures (e.g., NTFS, FAT32). This is a complex operation
    that often needs specialized libraries or kernel-level access.

    Args:
        file_path (str): The path to the file whose containing cluster's slack space might be analyzed.

    Returns:
        dict: A dictionary indicating the status of slack space analysis and notes.
    """
    if not os.path.exists(file_path):
        return {"error": "File not found", "file_path": file_path}

    return {
        "file_path": file_path,
        "slack_space_analysis_status": "Not Performed",
        "note": "Slack space analysis is a placeholder. Requires low-level file system access and specialized tools/libraries (e.g., pytsk, libewf) which are beyond the scope of a high-level Python script without elevated privileges."
    }

def detect_wiping_patterns(file_path):
    """
    Analyzes the byte frequency histogram of a file to detect efficient wiping.
    Real files have a distribution of bytes. Wiped files are dominated by specific bytes (00, FF, F6).
    """
    if not os.path.exists(file_path):
         return {"is_wiping_suspected": False}
    
    try:
        from collections import Counter
        
        # Read a sample (e.g. first 1MB) to be fast
        with open(file_path, 'rb') as f:
            data = f.read(1024 * 1024)
            
        if not data:
             return {"is_wiping_suspected": False}
             
        counts = Counter(data)
        total_bytes = len(data)
        
        # Check patterns
        zeros = counts.get(0, 0)
        ones = counts.get(255, 0) # 0xFF
        dod_pattern = counts.get(246, 0) # 0xF6 (common DoD wipe pattern)
        
        zero_ratio = zeros / total_bytes
        ones_ratio = ones / total_bytes
        dod_ratio = dod_pattern / total_bytes
        
        if zero_ratio > 0.95:
             # Already covered by detect_zero_fill, but this confirms it statistically
             return {"is_wiping_suspected": True, "type": "Zero Fill", "confidence": 1.0}
             
        if ones_ratio > 0.95:
             # Already covered by pattern fill
             return {"is_wiping_suspected": True, "type": "0xFF Fill", "confidence": 1.0}
             
        if dod_ratio > 0.95:
             return {"is_wiping_suspected": True, "type": "DoD Pattern (0xF6)", "confidence": 0.9}
             
        # Check for uniform distribution (random wiping) - harder, high entropy
        # But if we see > 90% of ONE byte value that isn't 00/FF, it's a single pass wipe
        most_common = counts.most_common(1)[0]
        if most_common[1] / total_bytes > 0.90:
             return {"is_wiping_suspected": True, "type": f"Single Byte Fill (0x{most_common[0]:02X})", "confidence": 0.9}

    except Exception as e:
        pass
        
    return {"is_wiping_suspected": False}

async def detect_data_wiping_ai(file_path, heuristic_results=None):
    """
    Uses Gemini AI to analyze heuristic results for data wiping patterns.
    """
    if not heuristic_results:
        return {"is_ai_wiping_suspected": False}
        
    prompt = (
        "Analyze these file attributes and heuristic wipe checks.\n"
        f"File: {os.path.basename(file_path)}\n"
        f"Zero Fill: {heuristic_results.get('zero_fill')}\n"
        f"Pattern Fill: {heuristic_results.get('pattern_fill')}\n"
        f"Histogram Analysis: {heuristic_results.get('histogram')}\n"
        "Question: Do these stats strongly indicate a deliberate data wiping/shredding tool was used? "
        "Reply with JSON: {\"suspicious\": boolean, \"confidence\": float 0.0-1.0, \"reason\": \"short explanation\"}"
    )

    response = await ai_service.analyze_text_async(prompt)
    if response:
        try:
             # Sanitize
            import json
            json_str = response.strip()
            if "```json" in json_str:
                json_str = json_str.split("```json")[1].split("```")[0]
            elif "```" in json_str:
                 json_str = json_str.split("```")[1].split("```")[0]
            
            data = json.loads(json_str)
            return {
                "is_ai_wiping_suspected": data.get("suspicious", False),
                "ai_confidence": data.get("confidence", 0.0),
                "ai_reason": data.get("reason", "AI detected anomaly.")
            }
        except Exception:
            pass
            
    return {"is_ai_wiping_suspected": False}

async def detect_data_wiping(file_path):
    """
    Detects potential data wiping attempts in a file by combining heuristic
    checks and a placeholder for AI-based analysis.

    Args:
        file_path (str): The path to the file to analyze.

    Returns:
        dict: A dictionary containing the data wiping detection results.
    """
    results = {"file_path": file_path}

    zero_fill_result = detect_zero_fill(file_path)
    results["zero_fill_detection"] = zero_fill_result

    pattern_fill_result = detect_pattern_fill(file_path, pattern=b'\xff')
    results["all_ones_pattern_detection"] = pattern_fill_result

    # Add other common patterns if needed, e.g., random data (harder to detect heuristically)

    slack_space_result = analyze_slack_space_placeholder(file_path)
    results["slack_space_analysis"] = slack_space_result

    # Authentic Heuristic Check
    histogram_result = detect_wiping_patterns(file_path)
    results["histogram_analysis"] = histogram_result

    # Gather results for AI
    ai_context = {
        "zero_fill": zero_fill_result,
        "pattern_fill": pattern_fill_result,
        "histogram": histogram_result
    }

    # AI Analysis (Hybrid)
    ai_wiping_result = await detect_data_wiping_ai(file_path, ai_context)
    results["ai_wiping_detection"] = ai_wiping_result
    
    is_wiping_suspected = (
        zero_fill_result.get("is_zero_fill_wiped", False) or
        pattern_fill_result.get("is_pattern_fill_wiped", False) or
        histogram_result.get("is_wiping_suspected", False)
    )

    results["is_data_wiping_suspected"] = is_wiping_suspected
    
    suspicion_reasons = []
    
    suspicion_score = 0.0
    if is_wiping_suspected:
         # Wiping evidence is usually high certainty
         suspicion_score = 1.0
         
         if histogram_result.get("is_wiping_suspected"):
             suspicion_reasons.append(f"Byte Histogram Analysis detected {histogram_result.get('type')} patterns.")
         if zero_fill_result.get("is_zero_fill_wiped"):
             suspicion_reasons.append("File is zero-filled (0x00).")
         if pattern_fill_result.get("is_pattern_fill_wiped"):
             suspicion_reasons.append("File is filled with repeating pattern.")
             
    if ai_wiping_result.get("is_ai_wiping_suspected", False):
        suspicion_reasons.append(f"[AI] {ai_wiping_result.get('ai_reason')}")
        # Only boost score if heuristics missed it or to reinforce
        if suspicion_score < 1.0:
            suspicion_score = max(suspicion_score, ai_wiping_result.get("ai_confidence", 0.7))

    results["suspicion_score"] = suspicion_score
    results["suspicion_reasons"] = suspicion_reasons
    
    return results

if __name__ == '__main__':
    # Example Usage
    # Create a dummy file for testing zero-fill
    dummy_zero_file = "d:\\Air University\\Semester 5\\DF Lab\\project\\project\\backend\\python\\anti_forensics\\zero_file.bin"
    with open(dummy_zero_file, 'wb') as f:
        f.write(b'\x00' * 1024)
    print(f"Analyzing zero-filled file: {dummy_zero_file}")
    print(detect_data_wiping(dummy_zero_file))
    os.remove(dummy_zero_file)

    # Create a dummy file for testing pattern-fill (all ones)
    dummy_ones_file = "d:\\Air University\\Semester 5\\DF Lab\\project\\project\\backend\\python\\anti_forensics\\ones_file.bin"
    with open(dummy_ones_file, 'wb') as f:
        f.write(b'\xff' * 1024)
    print(f"\nAnalyzing all-ones-filled file: {dummy_ones_file}")
    print(detect_data_wiping(dummy_ones_file))
    os.remove(dummy_ones_file)

    # Create a normal file
    dummy_normal_file = "d:\\Air University\\Semester 5\\DF Lab\\project\\project\\backend\\python\\anti_forensics\\normal_file.txt"
    with open(dummy_normal_file, 'w') as f:
        f.write("This is a normal file with some content.")
    print(f"\nAnalyzing normal file: {dummy_normal_file}")
    print(detect_data_wiping(dummy_normal_file))
    os.remove(dummy_normal_file)

    # Analyze a non-existent file
    print(f"\nAnalyzing non-existent file: non_existent.txt")
    print(detect_data_wiping("d:\\Air University\\Semester 5\\DF Lab\\project\\project\\backend\\python\\anti_forensics\\non_existent.txt"))


import os
import platform
import re
from datetime import datetime
import json
try:
    from ..common.ai_service import ai_service
except ImportError:
    import sys
    import os
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
    from python.common.ai_service import ai_service


def is_system_file(file_path):
    """
    Checks if a given file path points to a common system file or directory.
    This is a heuristic and can be expanded.
    """
    system_paths = [
        "C:\\Windows", "/bin", "/sbin", "/usr/bin", "/usr/sbin",
        "/etc", "/dev", "/proc", "/sys", "/lib", "/lib64",
        "Program Files", "Program Files (x86)", "Windows\\System32"
    ]
    file_path_lower = file_path.lower()
    for sp in system_paths:
        if sp.lower() in file_path_lower:
            return True
    return False

def load_magic_bytes():
    try:
        json_path = os.path.join(os.path.dirname(__file__), "magic_bytes.json")
        if os.path.exists(json_path):
            with open(json_path, 'r') as f:
                return json.load(f)
    except Exception as e:
        print(f"Error loading magic bytes: {e}")
    return {}

def detect_suspicious_extension_change(old_name, new_name):
    """
    Detects suspicious changes in file extensions and validates signatures.
    """
    old_ext = os.path.splitext(old_name)[1].lower().replace('.', '')
    new_ext = os.path.splitext(new_name)[1].lower().replace('.', '')

    # 1. Text-based extension change check
    if old_ext and new_ext and old_ext != new_ext:
        suspicious_extensions = ['exe', 'dll', 'bat', 'cmd', 'ps1', 'vbs', 'js', 'jar', 'sh', 'py']
        if old_ext not in suspicious_extensions and new_ext in suspicious_extensions:
            return True, f"Changed from .{old_ext} to suspicious executable extension .{new_ext}"

    # 2. Magic Byte Verification (Content Inspection)
    # Only applicable if new_name exists (it should, as we analyze current state)
    if os.path.exists(new_name) and os.path.isfile(new_name):
        magic_map = load_magic_bytes()
        # Invert map for easy lookup: extension -> signature
        sig_map = {v: k for k, v in magic_map.items()}
        
        target_sig = sig_map.get(new_ext)
        if target_sig:
            try:
                # Convert space-separated hex string to simple string
                target_hex = target_sig.replace(' ', '')
                
                with open(new_name, 'rb') as f:
                    # Read exact number of bytes needed
                    header_bytes = f.read(len(target_hex)//2)
                    header_hex = header_bytes.hex().upper()
                    
                if header_hex != target_hex:
                     return True, f"Extension Mismatch: File has .{new_ext} extension but header is {header_hex} (expected {target_hex})"
            except Exception as e:
                pass 

    return False, "No suspicious extension change"

def detect_hidden_file_rename(old_name, new_name):
    """
    Detects if a file is renamed to become a hidden file (e.g., adding a dot prefix on Unix-like systems).
    """
    old_basename = os.path.basename(old_name)
    new_basename = os.path.basename(new_name)

    if platform.system() != "Windows": # Unix-like systems
        if not old_basename.startswith('.') and new_basename.startswith('.'):
            return True, "File renamed to a hidden file (dot prefix added)"
    # On Windows, hidden attribute is set via file system API, not just name.
    # This would require integration with pywin32 or similar.
    return False, "No suspicious hidden file rename detected"

def detect_suspicious_character_rename(old_name, new_name):
    """
    Detects suspicious characters or patterns in new file names, often used for obfuscation.
    """
    # Look for multiple dots, unusual Unicode characters, or control characters
    if ".." in new_name or new_name.count('.') > 2:
        return True, "New name contains multiple dots or unusual dot patterns"
    if re.search(r'[^ -~]', new_name): # Non-ASCII printable characters
        return True, "New name contains non-ASCII printable characters"
    return False, "No suspicious character patterns"

import math
import collections

def calculate_shannon_entropy(string):
    """
    Calculates the Shannon entropy of a string.
    High entropy suggests randomness (e.g. encrypted or generated strings).
    Typical English text has entropy ~3.5-4.5. Random strings > 4.5.
    """
    if not string:
        return 0
    entropy = 0
    for x in set(string):
        p_x = float(string.count(x)) / len(string)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

# AI detection removed to ensure authentic results based only on heuristics.
async def detect_suspicious_rename_ai(old_file_path, new_file_path):
    """
    Uses Gemini AI to analyze the context of a file rename operation.
    """
    prompt = (
        f"Analyze this file rename operation for suspicious activity.\n"
        f"Old Path: {old_file_path}\n"
        f"New Path: {new_file_path}\n"
        f"OS: {platform.system()}\n"
        "Question: Is this rename suspicious (e.g., hiding a file, changing extension to executable, obfuscation)? "
        "Reply with JSON: {\"suspicious\": boolean, \"confidence\": float 0.0-1.0, \"reason\": \"short explanation\"}"
    )

    response = await ai_service.analyze_text_async(prompt)
    if response:
        try:
             # Sanitize response to find JSON
            json_str = response.strip()
            if "```json" in json_str:
                json_str = json_str.split("```json")[1].split("```")[0]
            elif "```" in json_str:
                 json_str = json_str.split("```")[1].split("```")[0]
            
            data = json.loads(json_str)
            return {
                "is_ai_suspicious": data.get("suspicious", False),
                "ai_confidence": data.get("confidence", 0.0),
                "ai_reason": data.get("reason", "AI detected anomaly.")
            }
        except Exception:
            pass
            
    return {"is_ai_suspicious": False}

async def detect_suspicious_rename(old_file_path, new_file_path):
    """
    Detects suspicious file renames by combining heuristic checks.

    Args:
        old_file_path (str): The original path of the file.
        new_file_path (str): The new path of the file after renaming.

    Returns:
        dict: A dictionary containing the suspicious rename detection results.
    """
    results = {
        "old_file_path": old_file_path,
        "new_file_path": new_file_path,
        "timestamp": datetime.now().isoformat()
    }

    is_suspicious = False
    suspicion_reasons = []

    # Heuristic Check 1: Rename of a known system file/path
    if is_system_file(old_file_path) or is_system_file(new_file_path):
        is_suspicious = True
        suspicion_reasons.append("Rename involves a known system file or path.")

    # Heuristic Check 2: Suspicious extension change
    ext_change_suspicious, ext_change_reason = detect_suspicious_extension_change(old_file_path, new_file_path)
    if ext_change_suspicious:
        is_suspicious = True
        suspicion_reasons.append(ext_change_reason)

    # Heuristic Check 3: Rename to hidden file
    hidden_rename_suspicious, hidden_rename_reason = detect_hidden_file_rename(old_file_path, new_file_path)
    if hidden_rename_suspicious:
        is_suspicious = True
        suspicion_reasons.append(hidden_rename_reason)

    # Heuristic Check 4: Suspicious characters in new name
    char_rename_suspicious, char_rename_reason = detect_suspicious_character_rename(old_file_path, new_file_path)
    if char_rename_suspicious:
        is_suspicious = True
        suspicion_reasons.append(char_rename_reason)
        
    new_basename = os.path.basename(new_file_path)
    # Patch: Strip UUIDs commonly added by upload systems (8-4-4-4-12 hex chars)
    # Example: 4ceb2956-3caa-41fe-aa81-de0383905785_malware.sh -> malware.sh
    uuid_pattern = r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}_?'
    name_clean = re.sub(uuid_pattern, '', new_basename, flags=re.IGNORECASE)
    
    name_only = os.path.splitext(name_clean)[0]
    # Only calculate for reasonably long names to avoid false positives on short names like "data"
    if len(name_only) > 5:
        entropy = calculate_shannon_entropy(name_only)
        # Threshold: 3.5 is a reasonable cutoff for random alphanumeric strings of this length
        if entropy > 3.5:
             is_suspicious = True
             suspicion_reasons.append(f"High entropy filename ({entropy:.2f}) indicates potential obfuscation.")
             results["entropy_score"] = entropy

    # Heuristic Check 6: Double Extension
    # Common malware tactic: document.pdf.exe
    if new_basename.count('.') >= 2:
        parts = new_basename.split('.')
        # Check if the second to last part is a common document extension
        # and limit this check to cases where the final extension is executable
        doc_exts = ['doc', 'docx', 'pdf', 'xls', 'xlsx', 'txt', 'rtf', 'ppt', 'pptx']
        exec_exts = ['exe', 'bat', 'ps1', 'vbs', 'scr', 'com', 'sh', 'elf']
        
        second_last = parts[-2].lower()
        last = parts[-1].lower()
        
        if second_last in doc_exts and last in exec_exts:
             is_suspicious = True
             suspicion_reasons.append(f"Double extension detected ({second_last}.{last}). Masquerading as document.")

    results["is_suspicious_rename"] = is_suspicious
    results["suspicion_reasons"] = suspicion_reasons

    suspicion_score = 0.0
    if is_suspicious:
        # Assign weights
        if ext_change_suspicious:
            suspicion_score = max(suspicion_score, 1.0) # Critical: Executable masquerading
        if hidden_rename_suspicious:
            suspicion_score = max(suspicion_score, 0.7) # High: Hiding files
        if char_rename_suspicious:
            suspicion_score = max(suspicion_score, 0.6) # Medium-High: Obfuscation
        if "Double extension" in str(suspicion_reasons):
             suspicion_score = max(suspicion_score, 0.9) # Very High
        if "High entropy" in str(suspicion_reasons):
             # Scale entropy score slightly, map 4.5-6.0 to 0.5-0.9
             ent_val = results.get("entropy_score", 4.5)
             score = min(0.9, (ent_val - 3.5) / 3.0) 
             suspicion_score = max(suspicion_score, max(0.5, score))

    # AI Analysis (Hybrid)
    # Trigger AI if heuristics found something OR just as a second opinion?
    # For efficiency, let's trigger it.
    ai_result = await detect_suspicious_rename_ai(old_file_path, new_file_path)
    results["ai_analysis"] = ai_result
    
    if ai_result.get("is_ai_suspicious", False):
        results["is_suspicious_rename"] = True
        suspicion_score = max(suspicion_score, ai_result.get("ai_confidence", 0.7))
        suspicion_reasons.append(f"[AI] {ai_result.get('ai_reason')}")

    results["suspicion_score"] = suspicion_score

    if not is_suspicious:
        results["note"] = "No suspicious rename patterns detected by heuristics."

    return results

if __name__ == "__main__":
    print("Running suspicious rename detector tests...")

    # Test cases
    # 1. Benign rename
    result1 = detect_suspicious_rename("document.txt", "report.txt")
    print(f"\nTest Case 1 (Benign): {result1}")

    # 2. Suspicious extension change (txt to exe)
    result2 = detect_suspicious_rename("image.jpg", "malware.exe")
    print(f"\nTest Case 2 (Suspicious Extension): {result2}")

    # 3. Rename to hidden file (Unix-like)
    if platform.system() != "Windows":
        result3 = detect_suspicious_rename("/home/user/file.txt", "/home/user/.hidden_file")
        print(f"\nTest Case 3 (Hidden File Rename): {result3}")
    else:
        print("\nTest Case 3 (Hidden File Rename): Skipped on Windows.")

    # 4. Rename involving system path
    result4 = detect_suspicious_rename("C:\\Users\\user\\temp.txt", "C:\\Windows\\System32\\drivers\\temp.dll")
    print(f"\nTest Case 4 (System Path Involvement): {result4}")

    # 5. Suspicious characters
    result5 = detect_suspicious_rename("normal.doc", "invoice..pdf")
    print(f"\nTest Case 5 (Suspicious Characters): {result5}")

    result6 = detect_suspicious_rename("report.pdf", "report\u200e.pdf") # Unicode control character
    print(f"\nTest Case 6 (Unicode Control Character): {result6}")

    # 6. AI-flagged (simulated)
    # To simulate AI flagging, we'd need to modify the dummy model or input
    # For now, the dummy model gives a low suspicion score unless "suspicious" is in the input.
    result7 = detect_suspicious_rename("legit.txt", "suspicious_activity.log")
    print(f"\nTest Case 7 (AI Flagged - simulated): {result7}")

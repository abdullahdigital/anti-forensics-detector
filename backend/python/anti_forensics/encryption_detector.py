import os
import math
from collections import Counter

# Try relative import, fallback for direct execution
try:
    from .file_utils import read_file_content, get_file_size
except ImportError:
    # Dummy mock for direct execution testing
    def read_file_content(path, mode='rb', chunk_size=4096):
        with open(path, mode) as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk: break
                yield chunk
    def get_file_size(path):
        return os.path.getsize(path)

def calculate_entropy(data):
    """
    Calculates the Shannon entropy of a byte string.
    High entropy can be an indicator of encryption or compression.
    """
    if not data:
        return 0.0

    byte_counts = Counter(data)
    entropy = 0.0
    total_bytes = len(data)

    for count in byte_counts.values():
        probability = count / total_bytes
        entropy -= probability * math.log2(probability)

    return entropy

def detect_high_entropy(file_path, chunk_size=4096, entropy_threshold=7.0):
    """
    Detects if a file exhibits high entropy, which can suggest encryption or compression.

    Args:
        file_path (str): The path to the file to analyze.
        chunk_size (int): The size of chunks to read from the file.
        entropy_threshold (float): The entropy value above which a chunk is considered high entropy.

    Returns:
        dict: A dictionary indicating if high entropy is detected and the average entropy.
    """
    if not os.path.exists(file_path):
        return {"error": "File not found", "file_path": file_path}

    total_entropy = 0.0
    num_chunks = 0
    high_entropy_chunks = 0

    try:
        for chunk in read_file_content(file_path, mode='rb', chunk_size=chunk_size):
            if not chunk:
                continue
            entropy = calculate_entropy(chunk)
            total_entropy += entropy
            num_chunks += 1
            if entropy >= entropy_threshold:
                high_entropy_chunks += 1
    except Exception as e:
        return {"error": str(e), "file_path": file_path}

    if num_chunks == 0:
        return {"is_high_entropy": False, "average_entropy": 0.0, "file_path": file_path}

    average_entropy = total_entropy / num_chunks
    is_high_entropy = (high_entropy_chunks / num_chunks) > 0.5 # More than half chunks are high entropy

    return {
        "file_path": file_path,
        "is_high_entropy": is_high_entropy,
        "average_entropy": round(average_entropy, 2),
        "high_entropy_chunk_proportion": round(high_entropy_chunks / num_chunks, 2) if num_chunks > 0 else 0.0
    }

# Dictionary of common magic numbers for encrypted file formats
# Each entry is a tuple: (format_name, magic_number_bytes)
MAGIC_NUMBERS = {
    "ZIP_ENCRYPTED": (b'\x50\x4B\x03\x04', 6, "PKZIP (encrypted)"), # PKZIP local file header, often used for encrypted zips
    "7Z_ENCRYPTED": (b'\x37\x7A\xBC\xAF\x27\x1C', 0, "7-Zip (encrypted)"), # 7-Zip signature
    "RAR_ENCRYPTED_5": (b'\x52\x61\x72\x21\x1A\x07\x01\x00', 0, "RAR v5.0 (encrypted)"), # RAR 5.0 signature
    "RAR_ENCRYPTED_4": (b'\x52\x61\x72\x21\x1A\x07\x00', 0, "RAR v4.x (encrypted)"), # RAR 4.x signature
    "GPG_ENCRYPTED": (b'\x85', 0, "GnuPG (encrypted)"), # GnuPG encrypted data packet
    "PDF_ENCRYPTED": (b'\x25\x50\x44\x46', 0, "PDF (encrypted)"), # PDF header, often contains encryption info later in file
    "OFFICE_ENCRYPTED": (b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1', 0, "Microsoft Office (encrypted)"), # OLE2 compound document format, used by older Office docs, can be encrypted
    "TRUECRYPT": (b'\x54\x52\x55\x45\x43\x52\x59\x50\x54', 0, "TrueCrypt/VeraCrypt volume"), # TrueCrypt/VeraCrypt header
    "LUKS": (b'\x4C\x55\x4B\x53\xBA\xBE', 0, "LUKS encrypted volume"), # Linux Unified Key Setup
    # Common Media Formats (High Entropy but Safe)
    "PNG": (b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A', 0, "PNG Image"),
    "JPG": (b'\xFF\xD8\xFF', 0, "JPEG Image"),
    "MP4": (b'\x00\x00\x00\x18\x66\x74\x79\x70', 4, "MP4 Video"), # Offset check needed? logic handles offset
    "MP3": (b'\x49\x44\x33', 0, "MP3 Audio (ID3)"),
}

def check_magic_numbers(file_path):
    """
    Checks a file's header against known magic numbers for encrypted file formats.

    Args:
        file_path (str): The path to the file to analyze.

    Returns:
        dict: A dictionary indicating if a known encrypted magic number is found.
    """
    if not os.path.exists(file_path):
        return {"error": "File not found", "file_path": file_path, "is_encrypted_format": False, "format_name": None}

    try:
        with open(file_path, 'rb') as f:
            # Determine max bytes to read
            max_read = 0
            for magic in MAGIC_NUMBERS.values():
                read_len = magic[1] + len(magic[0])
                if read_len > max_read:
                    max_read = read_len
            
            header = f.read(max_read)
            
            for magic_val, offset, display_name in MAGIC_NUMBERS.values():
                # Check bounds
                if len(header) >= offset + len(magic_val):
                    if header[offset:offset + len(magic_val)] == magic_val:
                        return {"is_encrypted_format": True, "format_name": display_name, "file_path": file_path}
    except Exception as e:
        return {"error": str(e), "file_path": file_path, "is_encrypted_format": False, "format_name": None}

    return {"is_encrypted_format": False, "format_name": None, "file_path": file_path}

def detect_encrypted_file_ai(file_path):
    """
    AI Detection removed to prioritize authentic heuristic results.
    """
    return {"is_ai_encryption_suspected": False}

def detect_encryption(file_path):
    """
    Detects potential encryption in a file by combining heuristic
    checks (like high entropy) and a placeholder for AI-based analysis.

    Args:
        file_path (str): The path to the file to analyze.

    Returns:
        dict: A dictionary containing the encryption detection results.
    """
    results = {"file_path": file_path}

    high_entropy_result = detect_high_entropy(file_path)
    results["high_entropy_detection"] = high_entropy_result

    magic_number_result = check_magic_numbers(file_path)
    results["header_check"] = magic_number_result

    ai_encryption_result = detect_encrypted_file_ai(file_path)
    results["ai_encryption_detection"] = ai_encryption_result

    is_encrypted_suspected = False
    
    # Logic Refinement:
    # High entropy is suspicious ONLY if:
    # 1. The file header is UNKNOWN (Potential Ransomware/Custom Encryption)
    # 2. The file header matches a known crypto volume (TrueCrypt/LUKS)
    # 3. AI flagged it.
    
    is_high_entropy = high_entropy_result.get("is_high_entropy", False)
    known_format = magic_number_result.get("is_encrypted_format", False)
    format_name = magic_number_result.get("format_name")
    
    if is_high_entropy:
        if known_format:
            # Matches a known format from our list (ZIP, PNG, TrueCrypt...)
            # Only flag as suspicious if it is explicitly a crypto volume
            suspicious_formats = ["TrueCrypt/VeraCrypt volume", "LUKS encrypted volume"]
            if format_name in suspicious_formats:
                is_encrypted_suspected = True
            else:
                # It is a harmless high-entropy format (PNG, ZIP, MP4)
                is_encrypted_suspected = False
        else:
             # High Entropy + Unknown Header = Suspicious (Ransomware-like)
             is_encrypted_suspected = True
             
    if ai_encryption_result.get("is_ai_encrypted_suspected", False):
        is_encrypted_suspected = True

    results["is_encrypted_suspected"] = is_encrypted_suspected
    
    suspicion_score = 0.0
    if is_encrypted_suspected:
         # High entropy is a strong indicator but can be compression
         suspicion_score = 0.7 
    
    results["suspicion_score"] = suspicion_score

    return results

if __name__ == '__main__':
    # Example Usage
    print("Testing encryption detector...")
    # Create a dummy low entropy file (text file)
    dummy_text_file = "low_entropy.txt"
    with open(dummy_text_file, 'w') as f:
        f.write("This is a simple text file with low entropy. It contains repetitive characters and common words.")
    print(f"Analyzing low entropy file: {dummy_text_file}")
    print(detect_encryption(dummy_text_file))
    if os.path.exists(dummy_text_file):
        os.remove(dummy_text_file)

    # Create a dummy high entropy file (random bytes)
    dummy_random_file = "high_entropy.bin"
    with open(dummy_random_file, 'wb') as f:
        f.write(os.urandom(4096)) # 4KB of random bytes
    print(f"\nAnalyzing high entropy file: {dummy_random_file}")
    print(detect_encryption(dummy_random_file))
    if os.path.exists(dummy_random_file):
        os.remove(dummy_random_file)
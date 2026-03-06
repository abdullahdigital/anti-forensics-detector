import os

class MasqueradeDetector:
    """
    Detects file masquerading (extension mismatch) using magic bytes verification.
    """
    
    # Common file signatures (Magic Bytes)
    SIGNATURES = {
        'exe': [b'MZ'], 
        'dll': [b'MZ'],
        'zip': [b'PK\x03\x04'],
        'jar': [b'PK\x03\x04'],
        'docx': [b'PK\x03\x04'],
        'xlsx': [b'PK\x03\x04'],
        'pptx': [b'PK\x03\x04'],
        'png': [b'\x89PNG\r\n\x1a\n'],
        'jpg': [b'\xff\xd8\xff'],
        'jpeg': [b'\xff\xd8\xff'],
        'gif': [b'GIF87a', b'GIF89a'],
        'pdf': [b'%PDF-'],
        'bmp': [b'BM'],
        'mp3': [b'ID3', b'\xff\xfb'],
        'mp4': [b'\x00\x00\x00\x18ftypmp42', b'\x00\x00\x00\x14ftypisom'], # Simplified
        'wav': [b'RIFF'], # Start with RIFF, check type later if needed
        'avi': [b'RIFF'],
        'py': [], # Script files are hard to detect by header alone definitively (shebangs vary)
        'sh': [b'#!'],
        'txt': [], # No header
    }

    # Text-based extensions for heuristic check
    TEXT_EXTENSIONS = ['txt', 'py', 'js', 'html', 'css', 'json', 'xml', 'md', 'log', 'ini', 'cfg', 'bat', 'ps1', 'sh']

    def detect_masquerading(self, file_path):
        """
        Analyzes a file to determine if its content matches its extension.
        
        Args:
            file_path (str): Path to the file.
            
        Returns:
            dict: Detection results.
        """
        if not os.path.exists(file_path):
            return {
                "file_path": file_path,
                "is_masqueraded": False,
                "error": "File not found"
            }
            
        filename = os.path.basename(file_path)
        _, ext = os.path.splitext(filename)
        ext = ext.lstrip('.').lower()
        
        # If no extension, difficult to determine "mismatch" without guessing type.
        if not ext:
             return {
                "file_path": file_path,
                "is_masqueraded": False,
                "note": "No extension to check against."
            }
            
        # 1. Byte Header Analysis
        signatures = self.SIGNATURES.get(ext)
        
        # If we don't know the signature for this extension, SKIP byte check (avoid false positives)
        # Exception: if it's a known text extension, we can check for binary content (high entropy/null bytes)
        if signatures is None or len(signatures) == 0:
            if ext in self.TEXT_EXTENSIONS:
                 return self._check_text_file_for_binary(file_path, ext)
            return {
                "file_path": file_path,
                "is_masqueraded": False,
                "note": f"Extension '{ext}' not in signature database."
            }

        try:
            with open(file_path, 'rb') as f:
                header = f.read(32) # Read enough for longest sig
                
            matched = False
            for sig in signatures:
                if header.startswith(sig):
                    matched = True
                    break
            
            if not matched:
                # Extension says X, but header is not X.
                # Let's try to identify what it IS for better reporting.
                actual_type = self._identify_type(header)
                
                # Special case: DOCX/JAR/APK are all ZIPs. 
                # If extension is DOCX and header is ZIP (PK..), it IS a match.
                # My dictionary handles this by mapping docx -> PK.., so matched should be True.
                
                # Special case 2: Scripts (.sh, .py) without shebangs are just Plain Text.
                # If actual_type is Plain Text and we expected a script/text file, it's valid.
                if actual_type == "Plain Text" and ext in self.TEXT_EXTENSIONS:
                     return {
                        "file_path": file_path,
                        "is_masqueraded": False,
                        "note": "Verified as safe Plain Text script."
                    }

                return {
                    "file_path": file_path,
                    "is_masqueraded": True,
                    "suspicion_score": 1.0,
                    "expected_type": ext,
                    "actual_type_detected": actual_type,
                    "reasons": [f"File has extension .{ext} but header suggests it is {actual_type or 'Unknown Binary'}."],
                    "header_hex": header[:8].hex().upper()
                }

        except Exception as e:
            return {
                "file_path": file_path,
                "is_masqueraded": False,
                "error": str(e)
            }
            
        return {
            "file_path": file_path,
            "is_masqueraded": False,
            "note": "Header matches extension."
        }

    def _check_text_file_for_binary(self, file_path, ext):
        """
        Heuristic: Text files shouldn't have many NULL bytes.
        """
        try:
            with open(file_path, 'rb') as f:
                chunk = f.read(1024)
                
            if b'\x00' in chunk:
                # Calculate null ratio
                null_count = chunk.count(b'\x00')
                if null_count > 10: # Threshold
                    # Check for MZ header just in case
                    actual_type = "Binary"
                    if chunk.startswith(b'MZ'):
                        actual_type = "Executable (EXE/DLL)"
                    elif chunk.startswith(b'PK'):
                        actual_type = "Archive (ZIP/Office)"
                        
                    return {
                        "file_path": file_path,
                        "is_masqueraded": True,
                        "suspicion_score": 0.9,
                        "expected_type": "Text",
                        "actual_type_detected": actual_type,
                        "reasons": [f"File has text extension .{ext} but contains significant binary data (NULL bytes)."]
                    }
        except:
             pass
             
        # Fix for User: Allowing Plain Text for script extensions
        # If the file is a script (.sh, .py, etc) and it is detected as Plain Text (no nulls), 
        # it is NOT a masquerade. The previous logic might have flagged it because it didn't match the Signature logic.
        return {
            "file_path": file_path,
            "is_masqueraded": False,
            "note": "Text-based file verified as safe."
        }

    def _identify_type(self, header):
        """
        Reverse lookup signature to find actual type.
        """
        for type_name, sigs in self.SIGNATURES.items():
            for sig in sigs:
                if header.startswith(sig):
                    return type_name.upper()
        
        # Heuristic for Plain Text
        try:
            # Check if majority of bytes are printable ASCII
            text_bytes = [b for b in header if 32 <= b <= 126 or b in (9, 10, 13)]
            if len(text_bytes) / len(header) > 0.8: # >80% printable
                return "Plain Text"
        except:
            pass
            
        return "Unknown"

# Standalone function for analyzer import
def detect_masquerading(file_path):
    detector = MasqueradeDetector()
    return detector.detect_masquerading(file_path)

import os
import datetime
from PIL import Image
from PIL.ExifTags import TAGS
try:
    from ..common.ai_service import ai_service
except ImportError:
    import sys
    import os
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
    from python.common.ai_service import ai_service

def get_image_exif(image_path):
    """
    Extracts EXIF data from an image file.
    """
    exif_data = {}
    try:
        with Image.open(image_path) as img:
            if hasattr(img, '_getexif'):
                info = img._getexif()
                if info:
                    for tag, value in info.items():
                        decoded = TAGS.get(tag, tag)
                        exif_data[decoded] = value
    except Exception as e:
        # Not all files are images, or may have corrupted EXIF
        pass
    return exif_data

async def detect_fake_metadata_ai(file_path, metadata=None):
    """
    Uses Gemini AI to analyze metadata consistency.
    """
    if not metadata:
        return {"is_ai_fake_metadata_suspected": False}
        
    # Convert metadata to string for prompt
    meta_str = str(metadata)
    if len(meta_str) > 2000:
        meta_str = meta_str[:2000] + "... (truncated)"
        
    prompt = (
        "Analyze these file metadata tags (EXIF/inferred).\n"
        "Question: Does this metadata suggest the file was edited, manipulated, or had its timestamps altered? "
        "Look for software tags (Photoshop, etc) or inconsistent dates. "
        "Reply with JSON: {\"suspicious\": boolean, \"confidence\": float 0.0-1.0, \"reason\": \"short explanation\"}"
    )

    response = await ai_service.analyze_text_async(prompt, text_content=meta_str)

    if response:
        try:
             # Sanitize response to find JSON
            import json
            json_str = response.strip()
            if "```json" in json_str:
                json_str = json_str.split("```json")[1].split("```")[0]
            elif "```" in json_str:
                 json_str = json_str.split("```")[1].split("```")[0]
            
            data = json.loads(json_str)
            return {
                "is_ai_fake_metadata_suspected": data.get("suspicious", False),
                "ai_confidence": data.get("confidence", 0.0),
                "ai_reason": data.get("reason", "AI detected anomaly.")
            }
        except Exception:
            pass
            
    return {
        "is_ai_fake_metadata_suspected": False
    }

async def detect_fake_metadata(file_path):
    """
    Detects potential fake or manipulated metadata in a file by combining heuristic
    Detects potential fake metadata by checking for inconsistencies.
    """
    suspicions = []
    suspicion_score = 0.0
    
    if not os.path.exists(file_path):
        return {"error": "File not found", "file_path": file_path, "is_fake_metadata": False, "reason": "File not found"}

    # Heuristic Check 1: Impossible timestamps (e.g., in the future)
    stat_info = os.stat(file_path)
    current_time = datetime.datetime.now()

    c_time = datetime.datetime.fromtimestamp(stat_info.st_ctime)
    m_time = datetime.datetime.fromtimestamp(stat_info.st_mtime)
    a_time = datetime.datetime.fromtimestamp(stat_info.st_atime)

    if c_time > current_time:
        suspicions.append(f"Creation time ({c_time}) is in the future.")
    if m_time > current_time:
        suspicions.append(f"Modification time ({m_time}) is in the future.")
    if a_time > current_time:
        suspicions.append(f"Access time ({a_time}) is in the future.")

    # Heuristic Check 2: Inconsistencies in EXIF data for image files
    exif_data = get_image_exif(file_path)
    if exif_data:
        date_original_str = exif_data.get('DateTimeOriginal')
        if date_original_str:
            try:
                date_original = datetime.datetime.strptime(date_original_str, '%Y:%m:%d %H:%M:%S')
                time_diff = abs((date_original - c_time).total_seconds())
                if time_diff > 24 * 3600: # If EXIF original date is very different from file creation date (e.g., more than a day)
                    suspicions.append(f"EXIF 'DateTimeOriginal' ({date_original}) differs significantly from file creation time ({c_time}).")
            except ValueError:
                suspicions.append(f"Invalid 'DateTimeOriginal' format in EXIF: {date_original_str}")

    # Heuristic Check 3: Software Signatures (Authentic Check)
    # Detects if editing software was used, which might indicate manipulation.
    known_editors = [
        "Photoshop", "GIMP", "Paint.NET", "Lightroom", 
        "Lavf", "HandBrake", "Premiere", "After Effects", 
        "ImageMagick", "Picasa", "Windows Photo Editor"
    ]
    
    if exif_data:
        software_tag = exif_data.get('Software')
        if software_tag:
             for editor in known_editors:
                 if editor.lower() in str(software_tag).lower():
                     suspicions.append(f"Metadata indicates file was processed by editing software: '{software_tag}'.")
                     
                     # Add risk for specific powerful editors
                     if "Photoshop" in str(software_tag) or "GIMP" in str(software_tag):
                         suspicion_score = max(suspicion_score, 0.6)
                     else:
                        suspicion_score = max(suspicion_score, 0.3)
                     break

                     break
    
    # AI Analysis (Hybrid)
    ai_detection_result = await detect_fake_metadata_ai(file_path, exif_data)

    if ai_detection_result.get("is_ai_fake_metadata_suspected", False):
        suspicions.append(f"[AI] {ai_detection_result.get('ai_reason')}")
        suspicion_score = max(suspicion_score, ai_detection_result.get("ai_confidence", 0.7))
    
    is_fake_metadata = bool(suspicions)
    
    if is_fake_metadata and suspicion_score == 0.0:
        suspicion_score = 0.5 # Default risk if suspicion exists but wasn't critical

    return {
        "file_path": file_path,
        "is_fake_metadata": is_fake_metadata,
        "suspicion_score": suspicion_score,
        "reasons": suspicions,
        "timestamps": {
            "creation_time": str(c_time),
            "modification_time": str(m_time),
            "access_time": str(a_time)
        },
        "exif_data": exif_data
    }

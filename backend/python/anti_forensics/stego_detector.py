import os
import numpy as np
from PIL import Image
from scipy.stats import entropy
from .file_utils import is_image_file
try:
    from ..common.ai_service import ai_service
except ImportError:
    import sys
    import os
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
    from python.common.ai_service import ai_service

def analyze_lsb_steganography(image_path, threshold=0.05):
    """
    Analyzes the Least Significant Bits (LSB) of an image for statistical anomalies
    that might indicate steganography. This is a basic heuristic.

    Args:
        image_path (str): The path to the image file.
        threshold (float): The variance threshold above which LSBs are considered suspicious.
                           A higher variance might indicate hidden data.

    Returns:
        dict: A dictionary containing the analysis results.
    """
    if not os.path.exists(image_path):
        return {"error": "Image file not found", "file_path": image_path}
    if not is_image_file(image_path):
        return {"error": "File is not a recognized image type", "file_path": image_path}

    try:
        img = Image.open(image_path)
        img = img.convert("RGB") # Ensure RGB format
        pixels = np.array(img)

        # Extract LSBs for each color channel
        lsb_red = (pixels[:, :, 0] & 1).flatten()
        lsb_green = (pixels[:, :, 1] & 1).flatten()
        lsb_blue = (pixels[:, :, 2] & 1).flatten()

        # Calculate variance of LSBs
        # A higher variance (closer to 0.25 for binary data) can indicate randomness
        # introduced by hidden data. For natural images, LSBs tend to be less random.
        variance_red = np.var(lsb_red)
        variance_green = np.var(lsb_green)
        variance_blue = np.var(lsb_blue)
        average_variance = (variance_red + variance_green + variance_blue) / 3

        is_stego_suspected = bool(average_variance > threshold)
        suspicion_score = 0.6 if is_stego_suspected else 0.0

        return {
            "file_path": image_path,
            "is_lsb_stego_suspected": is_stego_suspected,
            "suspicion_score": suspicion_score,
            "lsb_variance": {
                "red": float(round(variance_red, 4)),
                "green": float(round(variance_green, 4)),
                "blue": float(round(variance_blue, 4)),
                "average": float(round(average_variance, 4))
            },
            "threshold_used": threshold,
            "note": "LSB variance analysis is a basic heuristic. Advanced stego detection requires more sophisticated statistical methods or AI."
        }
    except Exception as e:
        return {"error": str(e), "file_path": image_path}

def detect_appended_data(file_path):
    """
    Detects data appended after the valid End Of File (EOF) marker.
    Common technique: 'cat image.jpg data.zip > stego.jpg'
    """
    if not os.path.exists(file_path): 
        return {"is_appended_data": False}
        
    file_size = os.path.getsize(file_path)
    
    try:
        with open(file_path, 'rb') as f:
            content = f.read()
            
        # JPEG EOF: FF D9
        # PNG EOF: IEND chunk (ends with AE 42 60 82)
        
        eof_offset = -1
        
        if content.startswith(b'\xff\xd8'): # JPEG
            # Find last FF D9
            eof_offset = content.rfind(b'\xff\xd9')
            if eof_offset != -1:
                eof_offset += 2 # Include marker
                
        elif content.startswith(b'\x89PNG'): # PNG
             # Find IEND chunk
             iend_marker = b'IEND'
             iend_pos = content.rfind(iend_marker)
             if iend_pos != -1:
                 # IEND chunk structure: Length (4) + IEND (4) + CRC (4)
                 # We found IEND, so we need to add 4 bytes for IEND + 4 bytes for CRC
                 eof_offset = iend_pos + 4 + 4
                 
        if eof_offset != -1 and eof_offset < file_size:
            extra_bytes = file_size - eof_offset
            if extra_bytes > 0:
                return {
                    "is_appended_data": True,
                    "file_path": file_path,
                    "eof_offset": eof_offset,
                    "actual_size": file_size,
                    "extra_bytes": extra_bytes,
                    "note": f"Found {extra_bytes} bytes of suspicious data appended after image EOF."
                }
                
    except Exception as e:
        pass
        
    return {"is_appended_data": False}

async def detect_steganography_ai(image_path, lsb_stats=None):
    """
    Uses Gemini AI to analyze LSB statistics and file attributes for steganography.
    """
    if not lsb_stats:
        return {"is_ai_stego_suspected": False, "note": "No LSB stats provided for AI analysis."}

    prompt = (
        "Analyze these LSB statistics for a potential steganography match.\n"
        f"File: {os.path.basename(image_path)}\n"
        f"LSB Variance: {lsb_stats.get('average', 0)}\n"
        f"Color Channel Variances: {lsb_stats}\n"
        "Question: Is it highly likely that this image contains hidden data based on high variance (near 0.25)? "
        "Reply with JSON: {\"suspicious\": boolean, \"confidence\": float 0.0-1.0, \"reason\": \"short explanation\"}"
    )

    response = await ai_service.analyze_text_async(prompt)
    
    if response:
        try:
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
                "is_ai_stego_suspected": data.get("suspicious", False),
                "ai_confidence": data.get("confidence", 0.0),
                "ai_reason": data.get("reason", "AI detected anomaly.")
            }
        except Exception as e:
            return {"is_ai_stego_suspected": False, "error": f"AI Parsing Error: {e}"}

    return {"is_ai_stego_suspected": False, "note": "AI service unavailable or no response."}

async def detect_steganography(file_path):
    """
    Combines LSB analysis and AI-based detection (placeholder) to detect steganography.

    Args:
        file_path (str): The path to the file to analyze.

    Returns:
        dict: A dictionary containing the combined steganography detection results.
    """
    if not is_image_file(file_path):
        return {
            "file_path": file_path,
            "is_steganography_suspected": False,
            "note": "File is not an image, steganography detection skipped."
        }


    lsb_results = analyze_lsb_steganography(file_path)
    appended_results = detect_appended_data(file_path)
    
    
    # AI Analysis (Hybrid Model)
    ai_results = {}
    if lsb_results.get("lsb_variance"):
         ai_results = await detect_steganography_ai(file_path, lsb_results["lsb_variance"])
    else:
         ai_results = {"is_ai_stego_suspected": False}

    is_steganography_suspected = lsb_results.get("is_lsb_stego_suspected", False) or \
                                 appended_results.get("is_appended_data", False)
                                 
    suspicion_reasons = []
    suspicion_score = 0.0
    if is_steganography_suspected:
        if appended_results.get("is_appended_data", False):
            suspicion_score = max(suspicion_score, 1.0) # Appended data is 100% anomaly
            suspicion_reasons.append(appended_results.get("note", "Suspicious appended data found."))
        if lsb_results.get("is_lsb_stego_suspected", False):
             suspicion_score = max(suspicion_score, 0.6)
             suspicion_reasons.append(lsb_results.get("note", "High LSB variance found."))
    
    # Add AI results if positive
    if ai_results.get("is_ai_stego_suspected", False):
        is_steganography_suspected = True
        suspicion_score = max(suspicion_score, ai_results.get("ai_confidence", 0.7))
        suspicion_reasons.append(f"[AI] {ai_results.get('ai_reason')}")

    return {
        "file_path": file_path,
        "is_steganography_suspected": is_steganography_suspected,
        "suspicion_score": suspicion_score,
        "suspicion_reasons": suspicion_reasons,
        "detection_methods": {
            "lsb_analysis": lsb_results,
            "appended_data": appended_results
        },
        "overall_note": "Combined results from LSB analysis and Authentic Appended Data checks."
    }

if __name__ == '__main__':
    # Example Usage
    # Create a dummy image for testing
    from PIL import Image, ImageDraw

    dummy_image_path = r"d:\Air University\Semester 5\DF Lab\project\project\backend\python\anti_forensics\dummy_clean_image.png"
    stego_image_path = r"d:\Air University\Semester 5\DF Lab\project\project\backend\python\anti_forensics\dummy_stego_image.png"

    # Create a simple clean image
    img = Image.new('RGB', (100, 100), color = 'red')
    d = ImageDraw.Draw(img)
    d.text((10,10), "Hello", fill=(255,255,0))
    img.save(dummy_image_path)

    print(f"Analyzing clean image: {dummy_image_path}")
    clean_result = detect_steganography(dummy_image_path)
    print(clean_result)

    # Simulate a steganographic image (very basic LSB modification for demonstration)
    # In a real scenario, you'd use a steganography tool to embed data.
    # This simple modification might not always trigger the LSB variance detector reliably
    # as it depends on the threshold and the nature of the modification.
    stego_img = Image.open(dummy_image_path)
    pixels = np.array(stego_img)
    # Modify some LSBs (e.g., change the last bit of some red pixels)
    for i in range(10):
        for j in range(10):
            pixels[i, j, 0] = pixels[i, j, 0] ^ 1 # Flip LSB of red channel
    Image.fromarray(pixels).save(stego_image_path)

    print(f"\nAnalyzing stego image: {stego_image_path}")
    stego_result = detect_steganography(stego_image_path)
    print(stego_result)

    # Example for a non-image file
    non_image_file = r"d:\Air University\Semester 5\DF Lab\project\project\backend\python\anti_forensics\test_non_image.txt"
    with open(non_image_file, 'w') as f:
        f.write("This is not an image.")
    print(f"\nAnalyzing non-image file: {non_image_file}")
    non_image_result = detect_steganography(non_image_file)
    print(non_image_result)

    # Clean up dummy files
    os.remove(dummy_image_path)
    os.remove(stego_image_path)
    os.remove(non_image_file)

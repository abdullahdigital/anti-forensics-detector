import os
import json
from flask import Blueprint, request, jsonify
from werkzeug.utils import secure_filename
from .ads_detector import ADSDetector

ads_bp = Blueprint('ads', __name__)

# Initialize detector
ads_detector = ADSDetector()

# Allowed file extensions
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'jpg', 'png', 'exe', 'zip'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@ads_bp.route("/detect", methods=["POST", "OPTIONS"])
def detect_ads_endpoint():
    """
    Detect Alternate Data Streams in a file or directory
    """
    if request.method == 'OPTIONS':
        return jsonify({}), 200
    
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "detail": "No JSON data provided"}), 400
    
    file_path = data.get("file_path")
    use_win32api = data.get("use_win32api", True)
    scan_directory = data.get("scan_directory", False)
    selected_detectors = data.get("selected_detectors", [])

    if not file_path:
        return jsonify({"success": False, "detail": "File path is required"}), 400

    try:
        # Re-initialize detector with potentially updated use_win32api setting
        detector = ADSDetector(use_win32api=use_win32api)
        results = detector.detect_ads_comprehensive(file_path, selected_detectors)

        if "error" in results:
            return jsonify({"success": False, "detail": results["error"]}), 404

        return jsonify({
            "success": True,
            "data": results,
            "message": "ADS detection completed"
        })

    except Exception as e:
        return jsonify({"success": False, "detail": str(e)}), 500

@ads_bp.route("/upload-and-detect", methods=["POST", "OPTIONS"])
def upload_and_detect():
    """
    Upload a file and detect ADS
    """
    if request.method == 'OPTIONS':
        return jsonify({}), 200
    
    if 'file' not in request.files:
        return jsonify({"success": False, "detail": "No file part in the request"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"success": False, "detail": "No selected file"}), 400

    if not allowed_file(file.filename):
        return jsonify({"success": False, "detail": f"File type not allowed. Allowed types: {', '.join(ALLOWED_EXTENSIONS)}"}), 400

    detectors_json = request.form.get('detectors', '[]')
    try:
        selected_detectors = json.loads(detectors_json)
    except json.JSONDecodeError:
        selected_detectors = []

    try:
        # Create temp directory
        temp_dir = "./temp_uploads"
        os.makedirs(temp_dir, exist_ok=True)
        
        # Secure the filename
        filename = secure_filename(file.filename)
        temp_path = os.path.join(temp_dir, filename)
        
        # Save uploaded file
        file.save(temp_path)

        # Detect ADS
        results = ads_detector.detect_ads_comprehensive(temp_path, selected_detectors)

        # Clean up temp file
        if os.path.exists(temp_path):
            os.remove(temp_path)
        
        # Clean up temp directory if empty
        if os.path.exists(temp_dir) and not os.listdir(temp_dir):
            os.rmdir(temp_dir)

        return jsonify({
            "success": True,
            "data": results,
            "filename": filename,
            "selected_detectors": selected_detectors
        })

    except Exception as e:
        # Clean up on error
        if 'temp_path' in locals() and os.path.exists(temp_path):
            os.remove(temp_path)
        return jsonify({"success": False, "detail": str(e)}), 500

@ads_bp.route("/test/create", methods=["GET"])
def create_test_ads():
    """
    Create a test file with ADS for demonstration
    """
    from .ads_detector import create_test_ads_file

    success, message = create_test_ads_file("test_ads_demo.txt")

    if success:
        return jsonify({
            "success": True,
            "message": message,
            "test_file": "test_ads_demo.txt"
        })
    else:
        return jsonify({"success": False, "detail": message}), 500

@ads_bp.route("/stats", methods=["GET"])
def get_ads_statistics():
    """
    Get statistics about ADS in a directory
    """
    directory = request.args.get("directory")
    if not directory:
        return jsonify({"success": False, "detail": "Directory parameter is required"}), 400

    try:
        detector = ADSDetector()
        results = detector.scan_directory_for_ads(directory)
        return jsonify({"success": True, "data": results})
    except Exception as e:
        return jsonify({"success": False, "detail": str(e)}), 500

# Health check endpoint
@ads_bp.route("/health", methods=["GET"])
def health_check():
    return jsonify({"status": "healthy", "service": "ADS Detector API"})
import os
import traceback
import json
from flask import Blueprint, request, jsonify
from werkzeug.utils import secure_filename
from .analyzer import AntiForensicsAnalyzer

analysis_bp = Blueprint('analysis', __name__)
UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Initialize analyzer
# Note: In a real production environment, you might want to handle this differently 
# to ensure thread safety or manage resources better, but for this 5th sem project 
# a global instance or per-request instance is likely fine.
# Given 'analyzer.py' holds state like caches, we should be careful. 
# A new instance per request ensures no stale state, but might be slower if initialization is heavy.
# Looking at analyzer.py, initialization is light (just dict setup), 
# but analyze_directory creates a USN journal handle.
# Let's instantiate per request to be safe and simple.

@analysis_bp.route("/file", methods=["POST", "OPTIONS"])
async def analyze_file_endpoint():
    """
    Analyze a single file for all anti-forensics techniques.
    """
    if request.method == 'OPTIONS':
        return jsonify({}), 200

    data = request.get_json()
    if not data:
        return jsonify({"success": False, "detail": "No JSON data provided"}), 400

    file_path = data.get("file_path")
    if not file_path:
        return jsonify({"success": False, "detail": "File path is required"}), 400

    if not os.path.exists(file_path):
         return jsonify({"success": False, "detail": f"File not found: {file_path}"}), 404

    try:
        analyzer = AntiForensicsAnalyzer()
        detectors = data.get("detectors") # List of detector names, or None
        results = await analyzer.analyze_file(file_path, selected_detectors=detectors)
        return jsonify({
            "success": True,
            "data": results,
            "message": "File analysis completed"
        })
    except Exception as e:
        return jsonify({"success": False, "detail": str(e), "traceback": traceback.format_exc()}), 500


@analysis_bp.route("/directory", methods=["POST", "OPTIONS"])
async def analyze_directory_endpoint():
    """
    Analyze a directory for all anti-forensics techniques.
    """
    if request.method == 'OPTIONS':
        return jsonify({}), 200

    data = request.get_json()
    if not data:
        return jsonify({"success": False, "detail": "No JSON data provided"}), 400

    directory_path = data.get("directory_path")
    if not directory_path:
        return jsonify({"success": False, "detail": "Directory path is required"}), 400

    if not os.path.exists(directory_path) or not os.path.isdir(directory_path):
         return jsonify({"success": False, "detail": f"Directory not found: {directory_path}"}), 404

    try:
        analyzer = AntiForensicsAnalyzer()
        detectors = data.get("detectors")
        report = await analyzer.analyze_directory(directory_path, selected_detectors=detectors)
        
        return jsonify({
            "success": True, 
            "data": report.report_data,
            "message": "Directory analysis completed"
        })
    except Exception as e:
        return jsonify({"success": False, "detail": str(e), "traceback": traceback.format_exc()}), 500

@analysis_bp.route("/upload", methods=["POST", "OPTIONS"])
async def analyze_upload_endpoint():
    """
    Handle file upload and run analysis.
    """
    if request.method == 'OPTIONS':
        return jsonify({}), 200

    if 'file' not in request.files:
        return jsonify({"success": False, "detail": "No file part in the request"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"success": False, "detail": "No file selected"}), 400

    if file:
        try:
            import uuid
            original_filename = secure_filename(file.filename)
            # Prepend UUID to avoid collisions
            filename = f"{uuid.uuid4()}_{original_filename}"
            file_path = os.path.join(UPLOAD_FOLDER, filename)
            file.save(file_path)
            
            detectors_json = request.form.get('detectors')
            detectors = json.loads(detectors_json) if detectors_json else None
            
            analyzer = AntiForensicsAnalyzer()
            results = await analyzer.analyze_file(file_path, selected_detectors=detectors)
            
            # Clean up
            if os.path.exists(file_path):
                os.remove(file_path)
                
            return jsonify({
                "success": True, 
                "data": results,
                "message": "File analysis completed"
            })
        except Exception as e:
            # Try to cleanup even on error
            if 'file_path' in locals() and os.path.exists(file_path):
                 os.remove(file_path)
            return jsonify({"success": False, "detail": str(e), "traceback": traceback.format_exc()}), 500

import os
import json
import asyncio

# Import all detector modules
from .ads_detector import detect_ads
from .masquerade_detector import detect_masquerading
from .timestomp_detector import detect_timestomping
from .stego_detector import detect_steganography
from .fake_metadata_detector import detect_fake_metadata
from .data_wiping_detector import detect_data_wiping
from .encryption_detector import detect_encryption
from .hidden_file_detector import detect_hidden_files
from .log_tampering_detector import detect_log_tampering
from .suspicious_rename_detector import detect_suspicious_rename
from .metadata_timeline import correlate_metadata_timeline
from .report_generator import ReportGenerator

from .anomaly_scorer import AnomalyScorer

class AntiForensicsAnalyzer:
    def __init__(self):
        self.detectors = {
            "masquerade_detection": detect_masquerading,
            "ads_detection": detect_ads, # Keeping it available but secondary
            "timestomping_detection": detect_timestomping,
            "steganography_detection": detect_steganography,
            "fake_metadata_detection": detect_fake_metadata,
            "data_wiping_detection": detect_data_wiping,
            "encryption_detection": detect_encryption,
            "hidden_file_detection": detect_hidden_files,
            "log_tampering_detection": detect_log_tampering,
            "suspicious_rename_detection": detect_suspicious_rename,
        }
        self.volume_path = r"\\.\C:"  # Default to C: drive, can be configured
        self.volume_handle = None
        self.last_usn = 0
        self.usn_journal_id = None
        self.rename_events_cache = {}
        self.frn_to_path_cache = {}
        self.anomaly_scorer = AnomalyScorer()
        self.whitelist = self._load_whitelist()

    def _load_whitelist(self):
        try:
            whitelist_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "whitelist.json")
            if os.path.exists(whitelist_path):
                with open(whitelist_path, 'r') as f:
                    return json.load(f)
        except Exception as e:
            print(f"Error loading whitelist: {e}")
        return {"exact_matches": [], "extensions": [], "directories": []}

    def _is_whitelisted(self, file_path):
        filename = os.path.basename(file_path)
        
        # Check exact matches
        if filename in self.whitelist.get("exact_matches", []):
            return True
            
        # Check extensions
        _, ext = os.path.splitext(filename)
        if ext.lower() in [e.lower() for e in self.whitelist.get("extensions", [])]:
            return True
            
        # Check directories
        for directory in self.whitelist.get("directories", []):
            if directory in file_path.split(os.sep):
                return True
                
        return False

    async def analyze_file(self, file_path, selected_detectors=None):
        """
        Analyzes a given file using specified (or all) anti-forensics detectors.
        Async version.

        Args:
            file_path (str): The path to the file to analyze.
            selected_detectors (list, optional): List of detector names to run. If None, runs all.

        Returns:
            dict: A dictionary containing the aggregated results from detectors.
        """
        if not os.path.exists(file_path):
            return {"error": "File not found", "file_path": file_path}

        # Whitelist Check
        if self._is_whitelisted(file_path):
            return {
                "file_path": file_path, 
                "whitelisted": True, 
                "reason": "File is in whitelist"
            }

        results = {"file_path": file_path}

        # Filter detectors if a list is provided
        active_detectors = self.detectors
        if selected_detectors and len(selected_detectors) > 0:
            active_detectors = {k: v for k, v in self.detectors.items() if k in selected_detectors}

        for detector_name, detector_func in active_detectors.items():
            try:
                # Special handling for suspicious_rename_detection which needs old and new path
                # For now, we'll assume the file_path is the 'new_file_path' and 'old_file_path' is unknown
                # This needs to be refined when integrating with a system that tracks renames
                if detector_name == "suspicious_rename_detection":
                    # On Linux without auditd/USN, we can't track renames easily. 
                    # Passing same path checks static masquerading only.
                    detection_result = detector_func(file_path, file_path)
                    
                    if asyncio.iscoroutine(detection_result):
                        detection_result = await detection_result

                else:
                    if asyncio.iscoroutinefunction(detector_func):
                         detection_result = await detector_func(file_path)
                    else:
                        detection_result = detector_func(file_path) # Sync detector

                results[detector_name] = detection_result
            except Exception as e:
                results[detector_name] = {"error": f"Error during {detector_name}: {str(e)}"}
        
        return results

    async def analyze_directory(self, directory_path, selected_detectors=None):
        """
        Analyzes all files in a given directory using specified (or all) anti-forensics detectors
        and generates a comprehensive report.

        Args:
            directory_path (str): The path to the directory to analyze.
            selected_detectors (list, optional): List of detector names to run.

        Returns:
            ReportGenerator: An instance of ReportGenerator containing the analysis results.
        """
        if not os.path.isdir(directory_path):
            return {"error": "Directory not found", "directory_path": directory_path}

        report_generator = ReportGenerator()

        # Determine drive letter from directory path
        drive_letter = os.path.splitdrive(os.path.abspath(directory_path))[0].rstrip(':')
        if not drive_letter:
            drive_letter = "C" # Default fallback
        self.volume_path = drive_letter

        # USN Journal reading removed (Windows only)
        # Rename detection will be limited to static checks on Linux
        self.rename_events_cache = {}

        for root, _, files in os.walk(directory_path):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                # For directory analysis, we don't have 'old_file_path' for rename detection
                # So, we'll pass the same path for both, effectively checking for self-rename (benign)
                raw_results = await self.analyze_file(file_path, selected_detectors)
                # Use AnomalyScorer to provide overall suspicion score.
                raw_results["overall_suspicion_score"] = await self.anomaly_scorer.score_anomalies(raw_results)
                report_generator.add_analysis_result(file_path, raw_results)
        return report_generator

async def main():
    # Example Usage
    analyzer = AntiForensicsAnalyzer()
    print("AntiForensicsAnalyzer initialized. Use the API to analyze files.")

if __name__ == '__main__':
    asyncio.run(main())

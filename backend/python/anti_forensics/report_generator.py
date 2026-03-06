import json
from datetime import datetime

class ReportGenerator:
    """
    Generates structured reports from anti-forensics detection results.
    """

    def __init__(self, tool_name="Anti-Forensics Analyzer"):
        self.tool_name = tool_name
        self.report_data = {
            "report_id": str(datetime.now().timestamp()),
            "tool_name": self.tool_name,
            "timestamp": datetime.now().isoformat(),
            "summary": {
                "total_files_analyzed": 0,
                "total_anomalies_detected": 0,
                "suspicious_files": []
            },
            "detailed_findings": []
        }

    def add_analysis_result(self, file_path, analysis_results):
        """
        Adds the analysis results for a single file to the report.

        Args:
            file_path (str): The path of the analyzed file.
            analysis_results (dict): The comprehensive results from the analyzer,
                                     including raw detection results and confidence scores.
        """
        self.report_data["summary"]["total_files_analyzed"] += 1

        file_summary = {
            "file_path": file_path,
            "overall_suspicion_score": analysis_results.get("overall_suspicion_score", 0),
            "anomalies_found": []
        }

        # Iterate through detection modules and extract anomalies
        for detector_name, detector_result in analysis_results.items():
            if detector_name in ["file_path", "overall_suspicion_score", "ai_confidence_score", "confidence_score", "anomaly_details"]:
                continue # Skip metadata fields

            is_suspicious_key = None
            reasons_key = None

            # Determine the keys for suspicion status and reasons based on detector type
            if "is_log_tampering_suspected" in detector_result:
                is_suspicious_key = "is_log_tampering_suspected"
                reasons_key = "suspicion_reasons" # For log tampering, reasons are in timestamp_anomalies_check or hash_integrity_check
            elif "is_suspicious_rename" in detector_result:
                is_suspicious_key = "is_suspicious_rename"
                reasons_key = "suspicion_reasons"
            elif "is_timestamp_anomaly_suspected" in detector_result:
                is_suspicious_key = "is_timestamp_anomaly_suspected"
                reasons_key = "reasons" # For metadata timeline
            elif "is_steganography_suspected" in detector_result:
                is_suspicious_key = "is_steganography_suspected"
                reasons_key = "reasons"
            elif "is_fake_metadata_suspected" in detector_result:
                is_suspicious_key = "is_fake_metadata_suspected"
                reasons_key = "reasons"
            elif "is_data_wiping_suspected" in detector_result:
                is_suspicious_key = "is_data_wiping_suspected"
                reasons_key = "reasons"
            elif "is_encryption_suspected" in detector_result:
                is_suspicious_key = "is_encryption_suspected"
                reasons_key = "reasons"
            elif "is_hidden_file_suspected" in detector_result:
                is_suspicious_key = "is_hidden_file_suspected"
                reasons_key = "reasons"
            elif "ads_detected" in detector_result:
                is_suspicious_key = "ads_detected"
                reasons_key = "ads_streams"
            elif "is_timestomping_suspected" in detector_result:
                is_suspicious_key = "is_timestomping_suspected"
                reasons_key = "reasons"

            if is_suspicious_key and detector_result.get(is_suspicious_key):
                self.report_data["summary"]["total_anomalies_detected"] += 1
                anomaly_details = {
                    "detector": detector_name,
                    "suspicion_score": detector_result.get("suspicion_score", "N/A"),
                    "details": detector_result
                }
                if reasons_key:
                    # Special handling for log tampering reasons which are nested
                    if detector_name == "log_tampering_detection":
                        log_reasons = []
                        if detector_result.get("hash_integrity_check", {}).get("integrity_compromised"):
                            log_reasons.append(detector_result["hash_integrity_check"].get("note", "Hash integrity compromised"))
                        if detector_result.get("timestamp_anomalies_check", {}).get("timestamp_anomalies_suspected"):
                            log_reasons.extend(detector_result["timestamp_anomalies_check"].get("reasons", []))
                        if detector_result.get("ai_tampering_detection", {}).get("is_ai_tampering_suspected"):
                            log_reasons.append("AI model flagged log tampering.")
                        anomaly_details["reasons"] = log_reasons if log_reasons else ["Log tampering suspected."]
                    elif detector_name == "ads_detection":
                        anomaly_details["reasons"] = [f"Detected ADS: {ads}" for ads in detector_result.get(reasons_key, [])]
                    else:
                        anomaly_details["reasons"] = detector_result.get(reasons_key, [f"{detector_name} suspected."])
                
                file_summary["anomalies_found"].append(anomaly_details)

        if file_summary["anomalies_found"]:
            self.report_data["summary"]["suspicious_files"].append({
                "file_path": file_path,
                "overall_suspicion_score": file_summary["overall_suspicion_score"],
                "anomalies_count": len(file_summary["anomalies_found"])
            })
            self.report_data["detailed_findings"].append(file_summary)

    def generate_json_report(self):
        """
        Generates the report in JSON format.

        Returns:
            str: A JSON string of the report.
        """
        return json.dumps(self.report_data, indent=4)

    def generate_human_readable_report(self):
        """
        Generates a human-readable text report.

        Returns:
            str: A formatted string of the report.
        """
        report_str = f"""====================================================
{self.tool_name} Report
====================================================
Report ID: {self.report_data['report_id']}
Timestamp: {self.report_data['timestamp']}

Summary:
  Total Files Analyzed: {self.report_data['summary']['total_files_analyzed']}
  Total Anomalies Detected: {self.report_data['summary']['total_anomalies_detected']}

Suspicious Files ({len(self.report_data['summary']['suspicious_files'])}):
"""
        if not self.report_data['summary']['suspicious_files']:
            report_str += "  No suspicious files found.\n"
        else:
            for sf in self.report_data['summary']['suspicious_files']:
                report_str += f"  - File: {sf['file_path']}\n    Overall Suspicion Score: {sf['overall_suspicion_score']:.2f}\n    Anomalies Count: {sf['anomalies_count']}\n"

        report_str += "\nDetailed Findings:\n"
        if not self.report_data['detailed_findings']:
            report_str += "  No detailed findings to display.\n"
        else:
            for df in self.report_data['detailed_findings']:
                report_str += f"""
----------------------------------------------------
File: {df['file_path']}
Overall Suspicion Score: {df['overall_suspicion_score']:.2f}
----------------------------------------------------
"""
                if not df['anomalies_found']:
                    report_str += "  No anomalies detected for this file.\n"
                else:
                    for anomaly in df['anomalies_found']:
                        report_str += f"  Detector: {anomaly['detector']}\n"
                        report_str += f"  Suspicion Score: {anomaly['suspicion_score']:.2f}\n"
                        if anomaly.get('reasons'):
                            report_str += "  Reasons:\n"
                            for reason in anomaly['reasons']:
                                report_str += f"    - {reason}\n"
                        report_str += f"  Details: {json.dumps(anomaly['details'], indent=4)}\n"
        report_str += "\n====================================================\n"
        return report_str

if __name__ == "__main__":
    print("Running ReportGenerator tests...")

    generator = ReportGenerator()

    # Simulate results from various detectors
    # Example 1: Log Tampering Detected
    log_tampering_result = {
        "file_path": "/var/log/syslog",
        "log_tampering_detection": {
            "is_log_tampering_suspected": True,
            "hash_integrity_check": {"status": "Compromised", "integrity_compromised": True, "note": "Hash mismatch."},
            "timestamp_anomalies_check": {"timestamp_anomalies_suspected": True, "reasons": ["Future timestamp detected."]},
            "ai_tampering_detection": {"is_ai_tampering_suspected": True, "model_prediction_score": 0.95},
            "suspicion_score": 0.9
        },
        "overall_suspicion_score": 0.9
    }
    generator.add_analysis_result("/var/log/syslog", log_tampering_result)

    # Example 2: Suspicious Rename Detected
    rename_result = {
        "file_path": "/usr/bin/ls",
        "suspicious_rename_detection": {
            "is_suspicious_rename": True,
            "suspicion_reasons": ["Rename involves a known system file or path.", "Changed from .txt to suspicious executable extension .exe"],
            "ai_detection": {"is_ai_suspicious": False, "model_prediction_score": 0.3},
            "suspicion_score": 0.7
        },
        "overall_suspicion_score": 0.7
    }
    generator.add_analysis_result("/usr/bin/ls", rename_result)

    # Example 3: Benign file
    benign_result = {
        "file_path": "/home/user/document.txt",
        "log_tampering_detection": {"is_log_tampering_suspected": False, "suspicion_score": 0.1},
        "suspicious_rename_detection": {"is_suspicious_rename": False, "suspicion_score": 0.05},
        "overall_suspicion_score": 0.08
    }
    generator.add_analysis_result("/home/user/document.txt", benign_result)

    # Example 4: Metadata Timeline Anomaly
    metadata_timeline_result = {
        "file_path": "/tmp/important_data.db",
        "metadata_timeline_detection": {
            "is_timestamp_anomaly_suspected": True,
            "heuristic_analysis": {"anomalies_detected": True, "reasons": ["Modification time is earlier than creation time."]},
            "ai_detection": {"is_ai_anomalous": True, "model_prediction_score": 0.85},
            "suspicion_score": 0.8
        },
        "overall_suspicion_score": 0.8
    }
    generator.add_analysis_result("/tmp/important_data.db", metadata_timeline_result)

    # Generate and print JSON report
    print("\n--- JSON Report ---")
    json_report = generator.generate_json_report()
    print(json_report)

    # Generate and print human-readable report
    print("\n--- Human-Readable Report ---")
    human_readable_report = generator.generate_human_readable_report()
    print(human_readable_report)

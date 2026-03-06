import json
try:
    from ..common.ai_service import ai_service
except ImportError:
    import sys
    import os
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
    from python.common.ai_service import ai_service

class AnomalyScorer:
    def __init__(self):
        # Define weights or rules for different types of anomalies
        # These can be adjusted based on forensic expertise or AI model output
        self.anomaly_weights = {
            "ads_detection": {"is_ads_present": 0.8},
            "timestomping_detection": {"is_timestomped": 0.9},
            "steganography_detection": {"is_stego_suspected": 0.95, "is_ai_stego_suspected": 0.98},
            "fake_metadata_detection": {"is_fake_metadata": 0.85, "is_ai_fake_metadata_suspected": 0.92},
            # Add weights for other detectors as they are implemented
        }

    async def _ai_scoring(self, analysis_results):
        """
        Uses Gemini AI to score the overall anomaly based on aggregated results.
        """
        # Prepare context
        context = json.dumps(analysis_results, indent=2, default=str)
        if len(context) > 4000:
             context = context[:4000] + "... (truncated)"
             
        prompt = (
            "You are a Digital Forensics Expert. Analyze this forensic report JSON.\n"
            "Task: Assign a suspicion score (0.0 to 10.0) where 10 is confirmed malware/attack.\n"
            "Context: The report covers steganography, data wiping, ADS, fake metadata, etc.\n"
            "Reply with JSON: {\"score\": float, \"reason\": \"summary of why\"}"
        )
        
        response = await ai_service.analyze_text_async(prompt, text_content=context)
        if response:
             try:
                 # Sanitize
                json_str = response.strip()
                if "```json" in json_str:
                    json_str = json_str.split("```json")[1].split("```")[0]
                elif "```" in json_str:
                     json_str = json_str.split("```")[1].split("```")[0]
                
                data = json.loads(json_str)
                score = float(data.get("score", 0.0))
                # Normalize AI score 0-10 to match heuristics component logic or just map to weight
                # Here we treat AI score as a standalone component that adds up to 1.0 (10/10 maps to 1.0)
                normalized_score = min(score / 10.0, 1.0)
                
                return {
                    "overall_ai_score": normalized_score,
                    "ai_confidence_note": data.get("reason", "AI assessed risk.")
                }
             except Exception:
                 pass
                 
        return {
            "overall_ai_score": 0.0, 
            "ai_confidence_note": "AI scoring unavailable."
        }

    async def assign_confidence_score(self, analysis_results):
        """
        Assigns a confidence score to the overall anti-forensics analysis results.

        Args:
            analysis_results (dict): The aggregated results from the AntiForensicsAnalyzer.

        Returns:
            dict: The analysis results with an added 'confidence_score' and 'anomaly_details'.
        """
        total_score = 0.0
        max_possible_score = 0.0
        anomaly_details = []

        # Heuristic-based scoring
        for detector_name, weights in self.anomaly_weights.items():
            if detector_name in analysis_results:
                detector_result = analysis_results[detector_name]
                # print(f"DEBUG: Scorer checking {detector_name}, type: {type(detector_result)}")
                if not isinstance(detector_result, dict):
                    print(f"ERROR: {detector_name} result is not a dict: {detector_result}")
                    continue
                for anomaly_key, weight in weights.items():
                    if anomaly_key in detector_result and detector_result[anomaly_key]:
                        total_score += weight
                        anomaly_details.append(f"{detector_name.replace('_', ' ').title()} suspected (Score: {weight})")
                    max_possible_score += weight # Sum up all possible weights

        # Integrate AI-based scoring
        ai_scores = await self._ai_scoring(analysis_results)
        if ai_scores.get("overall_ai_score", 0) > 0:
            total_score += ai_scores["overall_ai_score"]
            anomaly_details.append(f"AI-based overall score: {ai_scores['overall_ai_score']} (Note: {ai_scores['ai_confidence_note']})")
            max_possible_score += 1.0 # Assuming AI score contributes up to 1.0
        elif "ai_confidence_note" in ai_scores:
            anomaly_details.append(f"AI-based scoring note: {ai_scores['ai_confidence_note']}")

        # Normalize the score to be between 0 and 1 (or 0 and 100)
        confidence_score = (total_score / max_possible_score) * 100 if max_possible_score > 0 else 0

        analysis_results["confidence_score"] = round(confidence_score, 2)
        analysis_results["anomaly_details"] = anomaly_details
        return analysis_results

    async def score_anomalies(self, analysis_results):
        """
        Calculates and returns the overall suspicion score.
        Wraps assign_confidence_score for backward compatibility.
        """
        try:
            results = await self.assign_confidence_score(analysis_results)
            return results.get("confidence_score", 0.0)
        except Exception:
            return 0.0

if __name__ == '__main__':
    # Example Usage with dummy analysis results
    scorer = AnomalyScorer()

    # Scenario 1: No anomalies
    no_anomaly_results = {
        "file_path": "test_file_clean.txt",
        "ads_detection": {"is_ads_present": False},
        "timestomping_detection": {"is_timestomped": False},
        "steganography_detection": {"is_stego_suspected": False, "is_ai_stego_suspected": False},
        "fake_metadata_detection": {"is_fake_metadata": False, "is_ai_fake_metadata_suspected": False},
    }
    scored_no_anomaly = scorer.assign_confidence_score(no_anomaly_results)
    print("\n--- No Anomaly Scenario ---")
    print(json.dumps(scored_no_anomaly, indent=4))

    # Scenario 2: Some anomalies
    some_anomaly_results = {
        "file_path": "test_file_suspect.txt",
        "ads_detection": {"is_ads_present": True, "ads_count": 1},
        "timestomping_detection": {"is_timestomped": False},
        "steganography_detection": {"is_stego_suspected": True, "is_ai_stego_suspected": False},
        "fake_metadata_detection": {"is_fake_metadata": False, "is_ai_fake_metadata_suspected": True},
    }
    scored_some_anomaly = scorer.assign_confidence_score(some_anomaly_results)
    print("\n--- Some Anomaly Scenario ---")
    print(json.dumps(scored_some_anomaly, indent=4))

    # Scenario 3: All anomalies (for maximum score)
    all_anomaly_results = {
        "file_path": "test_file_highly_suspect.txt",
        "ads_detection": {"is_ads_present": True, "ads_count": 2},
        "timestomping_detection": {"is_timestomped": True, "reasons": ["Modification time earlier than creation time"]},
        "steganography_detection": {"is_stego_suspected": True, "is_ai_stego_suspected": True, "confidence": 0.8},
        "fake_metadata_detection": {"is_fake_metadata": True, "reasons": ["Future timestamp"], "is_ai_fake_metadata_suspected": True, "confidence": 0.7},
    }
    scored_all_anomaly = scorer.assign_confidence_score(all_anomaly_results)
    print("\n--- All Anomaly Scenario ---")
    print(json.dumps(scored_all_anomaly, indent=4))

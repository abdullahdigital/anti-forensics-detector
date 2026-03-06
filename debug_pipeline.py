
import os
import sys
import json
# Add backend to path
sys.path.append('/home/kali/Desktop/anti-forensics-linux/backend/python')

from anti_forensics.analyzer import AntiForensicsAnalyzer

def debug_pipeline():
    analyzer = AntiForensicsAnalyzer()
    
    files_to_check = [
        "/home/kali/Desktop/anti-forensics-linux/demo_evidence/corrupt.log"
    ]
    
    for fpath in files_to_check:
        print(f"\n--- Analyzing {os.path.basename(fpath)} ---")
        if not os.path.exists(fpath):
            print("File not found!")
            continue
            
        try:
            results = analyzer.analyze_file(fpath)
            print(json.dumps(results, indent=2))
        except Exception as e:
            print(f"CRASH: {e}")

if __name__ == "__main__":
    debug_pipeline()

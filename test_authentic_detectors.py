
import os
import sys
import unittest

# Add backend to path
sys.path.append('/home/kali/Desktop/anti-forensics-linux/backend/python')

from anti_forensics.stego_detector import detect_steganography
from anti_forensics.timestomp_detector import detect_timestomping
from anti_forensics.data_wiping_detector import detect_data_wiping
from anti_forensics.log_tampering_detector import detect_log_tampering

class TestAuthenticDetectors(unittest.TestCase):
    def setUp(self):
        self.evidence_dir = "/home/kali/Desktop/anti-forensics-linux/demo_evidence"
        
    def test_stego_appended_data(self):
        print("\nTesting Stego Appended Data...")
        path = os.path.join(self.evidence_dir, "stego_image.jpg")
        result = detect_steganography(path)
        self.assertTrue(result['is_steganography_suspected'])
        self.assertTrue(result['detection_methods']['appended_data']['is_appended_data'])
        print("PASS: Appended data detected.")
        
    def test_timestomping_nanosecond(self):
        print("\nTesting Timestomp Nanoseconds...")
        path = os.path.join(self.evidence_dir, "timestomped.txt")
        result = detect_timestomping(path)
        self.assertTrue(result['is_timestomped'])
        # Look for the specific reason string or just general flag
        # The logic adds a reason if microseconds are 0
        reasons = str(result['reasons'])
        self.assertIn("zero microseconds", reasons)
        print("PASS: Zero microseconds detected.")

    def test_wiping_histogram(self):
        print("\nTesting Wiping Histogram...")
        path = os.path.join(self.evidence_dir, "wiped_file.bin")
        result = detect_data_wiping(path)
        self.assertTrue(result['is_data_wiping_suspected'])
        self.assertTrue(result['histogram_analysis']['is_wiping_suspected'])
        self.assertEqual(result['histogram_analysis']['type'], "DoD Pattern (0xF6)")
        print("PASS: DoD 0xF6 pattern detected.")
        
    def test_log_null_injection(self):
        print("\nTesting Log Null Injection...")
        path = os.path.join(self.evidence_dir, "corrupt.log")
        result = detect_log_tampering(path)
        self.assertTrue(result['is_log_tampering_suspected'])
        self.assertTrue(result['null_injection_check']['is_injection_suspected'])
        self.assertTrue(len(result['suspicion_reasons']) > 0)
        print(f"PASS: Null injection detected with reason: {result['suspicion_reasons'][0]}")

if __name__ == '__main__':
    unittest.main()

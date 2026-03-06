import os
import time
import shutil

def generate_evidence():
    evidence_dir = "test_evidence"
    if os.path.exists(evidence_dir):
        shutil.rmtree(evidence_dir)
    os.makedirs(evidence_dir)
    print(f"Created directory: {os.path.abspath(evidence_dir)}")

    # 1. TIMESTOMPING (Critical for user request)
    # File created NOW, but modified in 2010.
    ts_file = os.path.join(evidence_dir, "timestomped.txt")
    with open(ts_file, "w") as f: f.write("This file is from the past.")
    # Backdate to 2010-01-01 12:00:00
    t = 1262347200.0
    os.utime(ts_file, (t, t))
    print(f"[+] Created Timestomped file: {ts_file} (Date: 2010)")

    # 2. DATA WIPING
    # Zero-filled file
    wipe_file = os.path.join(evidence_dir, "wiped_zeros.bin")
    with open(wipe_file, "wb") as f: f.write(b'\x00' * 1024 * 1024) # 1MB
    print(f"[+] Created Wiped file (Zero-Fill): {wipe_file}")

    # 3. ENCRYPTION (Ransomware simulation)
    # High entropy random data (no header)
    enc_file = os.path.join(evidence_dir, "ransomware_encrypted.data")
    with open(enc_file, "wb") as f: f.write(os.urandom(1024 * 100)) # 100KB
    print(f"[+] Created Encrypted file: {enc_file}")

    # 4. MASQUERADING
    # Shell script hiding as PDF
    # Note: We use a Fake Header to trick basic viewers, but our tool checks deeper mismatches
    masq_file = os.path.join(evidence_dir, "harmless_document.pdf")
    with open(masq_file, "w") as f: f.write("#!/bin/bash\necho 'I am a script'")
    print(f"[+] Created Masquerade file: {masq_file} (Script as PDF)")

    # 5. HIDDEN FILE (Linux)
    hidden_file = os.path.join(evidence_dir, ".hidden_config")
    with open(hidden_file, "w") as f: f.write("Hidden content")
    print(f"[+] Created Hidden file: {hidden_file}")

    print("\nSUCCESS: Evidence generated.")
    print(f"To test: Point the Anti-Forensics Tool to check the folder: '{os.path.abspath(evidence_dir)}'")

if __name__ == "__main__":
    generate_evidence()

import requests
import os
import json
import time
import subprocess
import sys

# Configuration
BASE_URL = "http://localhost:5000/api/analysis"
TEST_FILE = "backend_test_file.txt"
TEST_DIR = "backend_test_dir"

server_process = None

def start_server():
    print("Starting Flask server...")
    # Adjust path to main.py
    server_path = os.path.join(os.getcwd(), "backend", "python", "main.py")
    # Use unbuffered output to capture it immediately
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    process = subprocess.Popen([sys.executable, server_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    time.sleep(5) # Wait for server to start
    return process

def create_test_data():
    print("Creating test data...")
    with open(TEST_FILE, "w") as f:
        f.write("This is a test file for backend verification.")
    
    if not os.path.exists(TEST_DIR):
        os.makedirs(TEST_DIR)
        with open(os.path.join(TEST_DIR, "file1.txt"), "w") as f:
            f.write("Content 1")
        with open(os.path.join(TEST_DIR, "file2.txt"), "w") as f:
            f.write("Content 2")

def clean_up():
    print("Cleaning up...")
    if os.path.exists(TEST_FILE):
        os.remove(TEST_FILE)
    if os.path.exists(TEST_DIR):
        import shutil
        shutil.rmtree(TEST_DIR)

def print_server_logs():
    if server_process:
        print("--- SERVER LOGS ---")
        try:
            outs, errs = server_process.communicate(timeout=2)
            if outs: print("STDOUT:", outs.decode())
            if errs: print("STDERR:", errs.decode())
        except subprocess.TimeoutExpired:
            server_process.kill()
            outs, errs = server_process.communicate()
            if outs: print("STDOUT:", outs.decode())
            if errs: print("STDERR:", errs.decode())
        except Exception as e:
            print(f"Error reading logs: {e}")

def test_analyze_file():
    print("\nTesting /api/analysis/file...")
    abs_path = os.path.abspath(TEST_FILE)
    payload = {"file_path": abs_path}
    try:
        response = requests.post(f"{BASE_URL}/file", json=payload)
        if response.status_code == 200:
            print("SUCCESS: File analysis request successful.")
            data = response.json()
            if data.get("success") and "data" in data:
                print("Response data structure valid.")
            else:
                print("FAILURE: Invalid response structure.")
        else:
            print(f"FAILURE: Status code {response.status_code}")
            print(response.text)
    except Exception as e:
        print(f"FAILURE: Exception {e}")
        print_server_logs()

def test_analyze_directory():
    print("\nTesting /api/analysis/directory...")
    abs_path = os.path.abspath(TEST_DIR)
    payload = {"directory_path": abs_path}
    try:
        response = requests.post(f"{BASE_URL}/directory", json=payload)
        if response.status_code == 200:
            print("SUCCESS: Directory analysis request successful.")
            data = response.json()
            if data.get("success") and "data" in data:
                print("Response data structure valid.")
            else:
                print("FAILURE: Invalid response structure.")
        else:
            print(f"FAILURE: Status code {response.status_code}")
            print(response.text)
    except Exception as e:
        print(f"FAILURE: Exception {e}")
        print_server_logs()

if __name__ == "__main__":
    is_server_managed = False

    try:
        requests.get("http://localhost:5000/api/ads/health")
        print("Server appears to be running.")
    except:
        server_process = start_server()
        is_server_managed = True

    try:
        create_test_data()
        test_analyze_file()
        test_analyze_directory()
    finally:
        clean_up()
        if is_server_managed and server_process:
            print("Stopping server...")
            server_process.terminate()

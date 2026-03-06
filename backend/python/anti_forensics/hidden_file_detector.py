import os
import platform



def find_hidden_items_heuristic(path):
    """
    Finds potentially hidden files and directories within a given path using heuristic rules.

    Args:
        path (str): The directory path to search.

    Returns:
        list: A list of dictionaries, each describing a detected hidden item.
    """
    hidden_items = []

    if os.path.isfile(path):
        name = os.path.basename(path)
        # Check just this file
        if name.startswith('.'):
            return [{"type": "file", "name": name, "path": path, "reason": "Starts with '.' (Unix Hidden)"}]
        if '.' not in name and name != "":
             return [{"type": "file", "name": name, "path": path, "reason": "No file extension"}]
        # Windows check would go here if pywin32 was available
        return []

    if not os.path.isdir(path):
        return []

    for root, dirs, files in os.walk(path):
        for name in dirs:
            full_path = os.path.join(root, name)
            # Unix-like hidden directories
            if name.startswith('.'):
                hidden_items.append({"type": "directory", "name": name, "path": full_path, "reason": "Starts with '.'"})


        for name in files:
            full_path = os.path.join(root, name)
            # Unix-like hidden files
            if name.startswith('.'):
                hidden_items.append({"type": "file", "name": name, "path": full_path, "reason": "Starts with '.'"})
            
            # Files with no extension (can be suspicious)
            if '.' not in name and name != "":
                hidden_items.append({"type": "file", "name": name, "path": full_path, "reason": "No file extension"})



    return hidden_items

    return hidden_items

def check_windows_attributes(file_path):
    """Function removed for Linux compatibility."""
    return {"is_hidden": False, "is_system": False}

def detect_hidden_files_ai(file_path):
    """
    AI Detection removed to prioritize authentic heuristic results.
    """
    return {"is_ai_hidden_suspected": False}

def detect_hidden_files(path):
    """
    Detects potentially hidden files and directories by combining heuristic
    checks and a placeholder for AI-based analysis.

    Args:
        path (str): The directory path to search.

    Returns:
        dict: A dictionary containing the hidden file detection results.
    """
    results = {"path": path}

    heuristic_hidden_items = find_hidden_items_heuristic(path)
    results["heuristic_detection"] = {
        "hidden_items": heuristic_hidden_items,
        "is_hidden_suspected": bool(heuristic_hidden_items)
    }

    ai_detection_result = detect_hidden_files_ai(path)
    results["ai_detection"] = ai_detection_result

    is_overall_hidden_suspected = (
        results["heuristic_detection"]["is_hidden_suspected"] or
        ai_detection_result.get("is_ai_hidden_suspected", False)
    )

    results["is_hidden_files_suspected"] = is_overall_hidden_suspected

    return results

if __name__ == '__main__':
    # Example Usage
    test_dir = "d:\\Air University\\Semester 5\\DF Lab\\project\\project\\backend\\python\\anti_forensics\\test_hidden_files"
    os.makedirs(test_dir, exist_ok=True)

    # Create some dummy hidden files/dirs
    with open(os.path.join(test_dir, ".hidden_file.txt"), 'w') as f: f.write("hidden content")
    os.makedirs(os.path.join(test_dir, ".hidden_dir"), exist_ok=True)
    with open(os.path.join(test_dir, "no_extension_file"), 'w') as f: f.write("content")
    with open(os.path.join(test_dir, "normal_file.txt"), 'w') as f: f.write("normal content")

    print(f"Searching for hidden files in: {test_dir}")
    results = detect_hidden_files(test_dir)
    print(results)

    # Clean up
    os.remove(os.path.join(test_dir, ".hidden_file.txt"))
    os.rmdir(os.path.join(test_dir, ".hidden_dir"))
    os.remove(os.path.join(test_dir, "no_extension_file"))
    os.remove(os.path.join(test_dir, "normal_file.txt"))
    os.rmdir(test_dir)

    # Test with a non-existent directory
    print(f"\nSearching in non-existent directory: non_existent_dir")
    print(detect_hidden_files("d:\\Air University\\Semester 5\\DF Lab\\project\\project\\backend\\python\\anti_forensics\\non_existent_dir"))

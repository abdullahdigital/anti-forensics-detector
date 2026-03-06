import hashlib
import os

def calculate_file_hash(file_path, hash_algorithm, chunk_size=4096):
    """
    Calculates the hash of a file using the specified algorithm.

    Args:
        file_path (str): The path to the file.
        hash_algorithm (str): The hashing algorithm to use (e.g., 'md5', 'sha1', 'sha256').
        chunk_size (int): The size of chunks to read from the file.

    Returns:
        str: The hexadecimal representation of the file's hash.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If an unsupported hash algorithm is provided.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    hasher = None
    if hash_algorithm.lower() == 'md5':
        hasher = hashlib.md5()
    elif hash_algorithm.lower() == 'sha1':
        hasher = hashlib.sha1()
    elif hash_algorithm.lower() == 'sha256':
        hasher = hashlib.sha256()
    else:
        raise ValueError(f"Unsupported hash algorithm: {hash_algorithm}")

    with open(file_path, 'rb') as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            hasher.update(chunk)

    return hasher.hexdigest()

def calculate_md5(file_path, chunk_size=4096):
    """
    Calculates the MD5 hash of a file.
    """
    return calculate_file_hash(file_path, 'md5', chunk_size)

def calculate_sha1(file_path, chunk_size=4096):
    """
    Calculates the SHA1 hash of a file.
    """
    return calculate_file_hash(file_path, 'sha1', chunk_size)

def calculate_sha256(file_path, chunk_size=4096):
    """
    Calculates the SHA256 hash of a file.
    """
    return calculate_file_hash(file_path, 'sha256', chunk_size)

if __name__ == '__main__':
    # Example Usage
    dummy_file_path = "d:\Air University\Semester 5\DF Lab\project\project\backend\python\anti_forensics\dummy_hash_file.txt"
    with open(dummy_file_path, 'w') as f:
        f.write("This is a test file for hashing.\n")
        f.write("It contains some sample data.\n")

    print(f"Analyzing: {dummy_file_path}")
    try:
        md5_hash = calculate_md5(dummy_file_path)
        sha1_hash = calculate_sha1(dummy_file_path)
        sha256_hash = calculate_sha256(dummy_file_path)

        print(f"MD5: {md5_hash}")
        print(f"SHA1: {sha1_hash}")
        print(f"SHA256: {sha256_hash}")

        # Verify integrity (simple example)
        if calculate_md5(dummy_file_path) == md5_hash:
            print("MD5 hash matches (integrity verified).")
        else:
            print("MD5 hash mismatch (integrity compromised).")

    except FileNotFoundError as e:
        print(e)
    except ValueError as e:
        print(e)
    finally:
        if os.path.exists(dummy_file_path):
            os.remove(dummy_file_path)

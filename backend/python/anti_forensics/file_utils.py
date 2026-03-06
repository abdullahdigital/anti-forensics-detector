import os
import hashlib
import binascii

def read_file_content(file_path, mode='rb', chunk_size=4096):
    """
    Reads the content of a file in chunks.

    Args:
        file_path (str): The path to the file.
        mode (str): The mode to open the file (e.g., 'rb' for binary, 'r' for text).
        chunk_size (int): The size of each chunk to read.

    Yields:
        bytes or str: Chunks of the file content.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    if not os.path.isfile(file_path):
        raise IsADirectoryError(f"Path is a directory, not a file: {file_path}")

    with open(file_path, mode) as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            yield chunk

def get_file_size(file_path):
    """
    Returns the size of a file in bytes.

    Args:
        file_path (str): The path to the file.

    Returns:
        int: The size of the file in bytes.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    return os.path.getsize(file_path)

def create_temp_file(content, suffix="", directory=None):
    """
    Creates a temporary file with the given content.

    Args:
        content (bytes or str): The content to write to the temporary file.
        suffix (str): The suffix for the temporary file name (e.g., '.tmp', '.bin').
        directory (str, optional): The directory where the temporary file should be created.
                                   Defaults to the system's default temporary directory.

    Returns:
        str: The path to the created temporary file.
    """
    import tempfile
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix, dir=directory, mode='wb' if isinstance(content, bytes) else 'w') as temp_f:
        temp_f.write(content)
    return temp_f.name

def delete_file(file_path):
    """
    Deletes a file.

    Args:
        file_path (str): The path to the file to delete.
    """
    if os.path.exists(file_path):
        os.remove(file_path)

def get_hex_dump(data, length=16, sep=' '):
    """
    Returns a hexadecimal dump of binary data.

    Args:
        data (bytes): The binary data to dump.
        length (int): The number of bytes per line.
        sep (str): Separator between hex bytes.

    Returns:
        str: The hexadecimal dump.
    """
    result = []
    for i in range(0, len(data), length):
        chunk = data[i:i+length]
        hex_part = binascii.hexlify(chunk).decode('ascii')
        hex_formatted = sep.join([hex_part[j:j+2] for j in range(0, len(hex_part), 2)])
        ascii_part = ''.join([chr(b) if 32 <= b < 127 else '.' for b in chunk])
        result.append(f"{i:08x}: {hex_formatted:<{length*3-1}} {ascii_part}")
    return "\n".join(result)

def get_file_extension(file_path):
    """
    Returns the extension of a file.

    Args:
        file_path (str): The path to the file.

    Returns:
        str: The file extension (e.g., '.txt', '.jpg'), or an empty string if no extension.
    """
    return os.path.splitext(file_path)[1]

def get_file_name(file_path, with_extension=True):
    """
    Returns the file name from a path.

    Args:
        file_path (str): The path to the file.
        with_extension (bool): Whether to include the file extension.

    Returns:
        str: The file name.
    """
    if with_extension:
        return os.path.basename(file_path)
    else:
        return os.path.splitext(os.path.basename(file_path))[0]

def is_windows_os():
    """
    Checks if the current operating system is Windows.
    """
    return os.name == 'nt'

def is_image_file(file_path):
    """
    Checks if a file is a common image file type based on its extension.
    """
    image_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.webp']
    ext = get_file_extension(file_path).lower()
    return ext in image_extensions

def is_executable_file(file_path):
    """
    Checks if a file is a common executable file type based on its extension.
    """
    executable_extensions = ['.exe', '.dll', '.sys', '.com', '.bat', '.sh', '.bin', '.elf', '.out']
    ext = get_file_extension(file_path).lower()
    return ext in executable_extensions

def is_document_file(file_path):
    """
    Checks if a file is a common document file type based on its extension.
    """
    document_extensions = ['.doc', '.docx', '.pdf', '.txt', '.rtf', '.odt', '.xls', '.xlsx', '.ppt', '.pptx']
    ext = get_file_extension(file_path).lower()
    return ext in document_extensions

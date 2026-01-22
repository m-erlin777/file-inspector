# reader.py

"""
DOCSTRING

Provides safe, minimal binary file access for reading specific byte ranges from a file.
Narrow in scope, no detection logic.
"""

from typing import Optional
from pathlib import Path

class FileReadError(Exception):
    
    # Raised when a file cannot be read safely.

    pass

def read_bytes(
        file_path: Path,
        offset: int,
        length: int
) -> Optional[bytes]:
    
    """
    Docstring for read_bytes
    
    :param file_path: Path to file being inspected
    :param offset: Byte offset from which to begin reading
    :param length: Number of bytes to read
    :return: Bytes read from file; None if impossible
    """

    if not file_path.exists():
        raise FileReadError(f"File does not exist: {file_path}")
    
    if offset < 0 or length <= 0:
        raise FileReadError("Offset must be >= 0 and length must be > 0")
    
    try:
        file_size = file_path.stat().st_size

        if offset >= file_size:
            return None
        
        with file_path.open("rb") as f:
            f.seek(offset)
            data = f.read(length)

            if not data:
                return None
            
            return data
        
    except OSError as e:
        raise FileReadError(f"Error reading file {file_path}: {e}")
